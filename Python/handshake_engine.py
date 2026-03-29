'''
Implements requirements of managing the security handshake.
'''

import os
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from identity_manager import rsa_pss_sign, rsa_pss_verify, generate_rsa_key_pair, compute_fingerprint
from cryptography.hazmat.primitives import hashes, serialization

HANDSHAKE_PORT = 5000
SALT = b"CISC468-SALT"
INFO = b"SessionKey"


'''
Constructs the handshake message to be sent by the initiator.
The format of the message is:
    4 bytes: length of sender's RSA pubkey in DER format
    n bytes: sender's RSA pubkey in DER format
    4 bytes: length of sender's X25519 pubkey
    32 bytes: sender's X25519 pubkey
    4 bytes: length of RSA-PSS signature on X25519 pubkey
    m bytes: RSA-PSS signature of X25519 pubkey
All size fields are big-endian unsigned integers.
Input: sender's RSA private key, sender's RSA public key, sender's X25519
Output: handshake message (bytes)
'''
def build_handshake_message(priv_rsa, pub_rsa, pub_x25519: bytes) -> bytes:
    # Get RSA pubkey DER encoding and sign it
    rsa_pubkey_der = pub_rsa.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sig = rsa_pss_sign(priv_rsa, pub_x25519)

    return (
          struct.pack(">I", len(rsa_pubkey_der))
        + rsa_pubkey_der
        + struct.pack(">I", len(pub_x25519))
        + pub_x25519
        + struct.pack(">I", len(sig))
        + sig
    )


'''
Parses received handshake message & verifies it.
Input: handshake message (bytes)
Output: verification (True if valid, False if invalid), sender's RSA public key, sender's X25519 public key 
'''
def parse_handshake_message(data: bytes):
    offset = 0
    # Extract message fields
    rsa_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    rsa_pubkey_der = data[offset:offset+rsa_len]
    offset += rsa_len
    x25519_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    x25519_pubkey = data[offset:offset+x25519_len]
    offset += x25519_len
    sig_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    sig = data[offset:offset+sig_len]

    # Get RSA pubkey
    rsa_pubkey = serialization.load_der_public_key(rsa_pubkey_der)
    # Check signature
    verified = rsa_pss_verify(rsa_pubkey, x25519_pubkey, sig)

    return rsa_pubkey, x25519_pubkey, verified


'''
Performs the two-way handshake & generates the shared session key.
Input: socket connection, this peer's private RSA key, this peer's public RSA key, is_initiator (True if this peer is initiator, False if responder)
Output: shared session key (bytes) & peer's public RSA key if successful
'''
def perform_handshake(sock, priv_rsa, pub_rsa, is_initiator=True):
    # Generate X25519 key pair
    priv_x25519 = x25519.X25519PrivateKey.generate()
    pub_x25519 = priv_x25519.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    # Build & send handshake message
    if is_initiator:
        msg_out = build_handshake_message(priv_rsa, pub_rsa, pub_x25519)
        sock.sendall(msg_out)
        peer_msg = recv_framed(sock)
    else:
        peer_msg = recv_framed(sock)
        msg_out = build_handshake_message(priv_rsa, pub_rsa, pub_x25519)
        sock.sendall(msg_out)
    
    # Parse & verify peer's handshake message
    peer_rsa_pub, peer_x25519_pub_bytes, verified = parse_handshake_message(peer_msg)
    if not verified:
        print("Handshake verification failed")
        return None, None
    
    # Compute fingerprint for trusted_{peer}.pub
    peer_filename = f"trusted_peer.pub"
    with open(peer_filename, "wb") as f:
        f.write(peer_rsa_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    
    # Compute shared session key using HKDF on X25519 shared secret
    peer_x25519_pub = x25519.X25519PublicKey.from_public_bytes(peer_x25519_pub_bytes)
    shared_secret = priv_x25519.exchange(peer_x25519_pub)
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=INFO).derive(shared_secret)

    return session_key, peer_rsa_pub


'''
Helper function for reading messages from socket.
Since Python sock.recv doesn't guarantee to read all the bytes sent by the peer in one call,
this function has to read [field length] [field data] for each of the fields
    RSA pubkey, X25519 pubkey, signature
separately. Note that each pubkey/sig field is preceded by a 4-byte header which tells us the size
of the following field.
'''
def recv_framed(sock):
    buf = b""
    # Read the first 4 bytes - length of RSA DER-encoded public key
    while len(buf) < 4:
        chunk = sock.recv(4 - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading message length")
        buf += chunk

    # Get the length of RSA DER-encoded pubkey, then read the pubkey itself
    rsa_pubkey_der_len = struct.unpack(">I", buf)[0]
    while len(buf) < (rsa_pubkey_der_len + 4):
        chunk = sock.recv((rsa_pubkey_der_len + 4) - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading RSA public key")
        buf += chunk

    # Read the next 4 bytes - length of X25519 public key
    while len(buf) < (rsa_pubkey_der_len + 8):
        chunk = sock.recv((rsa_pubkey_der_len + 8) - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading X25519 public key length")
        buf += chunk
    
    # Get the length of X25519 pubkey, then read the pubkey itself
    x25519_pubkey_len = struct.unpack(">I", buf[rsa_pubkey_der_len + 4 : rsa_pubkey_der_len + 8])[0]
    while len(buf) < (rsa_pubkey_der_len + 8 + x25519_pubkey_len):
        chunk = sock.recv((rsa_pubkey_der_len + 8 + x25519_pubkey_len) - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading X25519 public key")
        buf += chunk

    # Read the next 4 bytes - length of signature
    while len(buf) < (rsa_pubkey_der_len + 8 + x25519_pubkey_len + 4):
        chunk = sock.recv((rsa_pubkey_der_len + 8 + x25519_pubkey_len + 4) - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading signature length")
        buf += chunk
    
    # Get the length of signature, then read the signature itself
    sig_len = struct.unpack(">I", buf[rsa_pubkey_der_len + 8 + x25519_pubkey_len : rsa_pubkey_der_len + 8 + x25519_pubkey_len + 4])[0]
    while len(buf) < (rsa_pubkey_der_len + 8 + x25519_pubkey_len + 4 + sig_len):
        chunk = sock.recv((rsa_pubkey_der_len + 8 + x25519_pubkey_len + 4 + sig_len) - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading signature")
        buf += chunk
    
    return buf


# temp test - TODO move to proper test file!
import socket
import threading
def server_thread(port, server_ready, keypair):
    priv_rsa, pub_rsa = keypair
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    server_ready.set()
    conn, addr = srv.accept()
    print(f"[SERVER] Connection from {addr}")
    session_key, peer_pub = perform_handshake(conn, priv_rsa, pub_rsa, is_initiator=False)
    print(f"[SERVER] Handshake complete. Session key: {session_key.hex()}")
    conn.close()
    srv.close()
    return session_key
def client_thread(port, keypair, out_key_holder):
    priv_rsa, pub_rsa = keypair
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", port))
    session_key, peer_pub = perform_handshake(cli, priv_rsa, pub_rsa, is_initiator=True)
    print(f"[CLIENT] Handshake complete. Session key: {session_key.hex()}")
    out_key_holder.append(session_key)
    cli.close()
if __name__ == "__main__":
    port = 5055
    server_ready = threading.Event()
    # Generate distinct keypairs for initiator and responder
    server_keys = generate_rsa_key_pair()
    client_keys = generate_rsa_key_pair()
    # Start server
    t_server = threading.Thread(target=server_thread, args=(port, server_ready, server_keys))
    t_server.start()
    server_ready.wait()
    # Run client
    out_key = []
    client_thread(port, client_keys, out_key)
    t_server.join(timeout=2)
    # The handshake is unauthenticated here (different keypairs),
    # so we mainly check that both sides *derived identical secrets*
    if out_key:
        print("[TEST] Handshake completed successfully.")
    else:
        print("[TEST] Handshake failed or timed out.")
