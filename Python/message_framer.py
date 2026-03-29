'''
Module to wrap messages with AES-GCM encryption.
Applies only after handshake is complete.
'''

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

'''
Encrypts a plaintext message using AES-GCM with the HKDF session key derived in the handshake.
The message format is
    1 byte: message type (enum)
    4 bytes: length of ciphertext field; excludes nonce/auth tag (big-endian unsigned int)
    12 bytes: nonce
    variable bytes: ciphertext
    16 bytes: 128-bit GCM authentication tag
Input: session key (bytes), message type (int), plaintext message (bytes)
Output: framed message (bytes)
'''
def aesgcm_encrypt_message(session_key: bytes, msg_type: int, plaintext: bytes) -> bytes:
    # Generate a random 12-byte nonce and the AES GCM object
    nonce = os.urandom(12)
    aesgcm = AESGCM(session_key)
    # Encrypt the plaintext
    ciphertext_and_auth = aesgcm.encrypt(nonce, plaintext, None)
    payload_len = len(ciphertext_and_auth) - 16  # payload_len is ciphertext only
    ciphertext = ciphertext_and_auth[:-16]
    auth_tag = ciphertext_and_auth[-16:]

    return (
        struct.pack(">B", msg_type)
        + struct.pack(">I", payload_len)
        + nonce
        + ciphertext
        + auth_tag
    )


'''
Reads exactly n bytes from a socket, blocking until all bytes are received.
Input: socket, number of bytes to read
Output: bytes
'''
def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed before all bytes received")
        buf.extend(chunk)
    return bytes(buf)


'''
Reads and decrypts one framed message from a socket.
Reads the header to determine the full message length before reading the rest.
Input: socket, session key (bytes)
Output: message type (int), plaintext message (bytes)
'''
def recv_message(sock, session_key: bytes):
    # Header: 1 byte type + 4 bytes payload length
    header = recv_exact(sock, 5)
    msg_type = header[0]
    payload_len = struct.unpack(">I", header[1:5])[0]

    # Read nonce (12 bytes) + ciphertext (payload_len bytes) + auth tag (16 bytes)
    rest = recv_exact(sock, 12 + payload_len + 16)
    nonce = rest[:12]
    ciphertext = rest[12 : 12 + payload_len]
    tag = rest[12 + payload_len :]

    aesgcm = AESGCM(session_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        return msg_type, plaintext
    except Exception as e:
        print(f"AES-GCM decryption failed: {e}")
        return None, None


'''
Decrypts an AES-GCM framed message using the HKDF session key derived in the handshake.
Input: session key (bytes), framed message (bytes)
Output: message type (enum), plaintext message (bytes)
'''
def aesgcm_decrypt_message(session_key: bytes, framed_msg: bytes):
    # Unpack message fields
    msg_type = framed_msg[0]
    payload_len = struct.unpack(">I", framed_msg[1:5])[0]
    nonce = framed_msg[5:17]
    ciphertext = framed_msg[17 : 17+payload_len]
    tag = framed_msg[17+payload_len : 17+payload_len+16]

    # Try decrypting the message
    aesgcm = AESGCM(session_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        return msg_type, plaintext
    except Exception as e:
        print(f"AES-GCM decryption failed: {e}")
        return None, None
    

# temp tests: TODO place in proper test file
if __name__ == "__main__":
    key = os.urandom(32)
    msg_type = 0x04
    payload = b"hello world, gcm test"
    frame = aesgcm_encrypt_message(key, msg_type, payload)
    msg_type, plain = aesgcm_decrypt_message(key, frame)
    print("[TEST] Type:", hex(msg_type))
    print("[TEST] Decrypted:", plain)
    print("[TEST] Decryption successful:", plain == payload)
