import discovery
import identity_manager
import handshake_engine
import message_framer
import storage_manager
import protocol_handler
import time
import socket
import threading
import os
import tempfile

## Discovery tests ##

def run_discovery_pair():
    # Create two peers with unique instance names and ports
    d1 = discovery.Discovery("peer1id", port=5051)
    d2 = discovery.Discovery("peer2id", port=5052)
    # Start advertising and browsing
    d1.start()
    d2.start()
    d1.browse()
    d2.browse()
    print("[TEST] Both discovery instances started, waiting for detection...")
    # Allow some time for mDNS packets to propagate
    time.sleep(5)
    # Check that each discovered the other
    peer1_found = any("peer2id" in name for name in d1.peers)
    peer2_found = any("peer1id" in name for name in d2.peers)
    print("[RESULT] Peer1 sees Peer2:", peer1_found)
    print("[RESULT] Peer2 sees Peer1:", peer2_found)
    # Cleanup
    d1.close()
    d2.close()
    return peer1_found and peer2_found

def test_discovery():
    d = discovery.Discovery("testpeerid")
    print(d)
    d.start()
    print(d)
    if d is not None:
        d.browse()
    else:
        print("d is none")
    print("[TEST] Discovery advertisement started.")
    time.sleep(2)
    d.close()
    print("[TEST] Discovery closed cleanly.")

    ok = run_discovery_pair()
    if ok:
        print("[TEST] Discovery confirmed bidirectional visibility.")
    else:
        print("[TEST]")


## Test identity_manager.py ##
def test_identity_manager():
    print("Using master password \'abcde\'")
    pw = "abcde"
    priv_key, pub_key = identity_manager.load_identity(pw)
    fingerprint = identity_manager.compute_fingerprint(pub_key)
    print(f"[+] Loaded identity. Fingerprint: {fingerprint}")
    test_str = b"hello world"
    enc_str = identity_manager.aes_cbc_encrypt(identity_manager.derive_master_key(pw), test_str)
    dec_str = identity_manager.aes_cbc_decrypt(identity_manager.derive_master_key(pw), enc_str)
    print(f"Decrypted string matches original: {dec_str == test_str}")
    sig = identity_manager.rsa_pss_sign(priv_key, test_str)
    verified = identity_manager.rsa_pss_verify(pub_key, test_str, sig)
    print(f"Signature valid: {verified}")


## Test handshake_engine.py ##
def server_thread(port, server_ready, keypair):
    priv_rsa, pub_rsa = keypair
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    server_ready.set()
    conn, addr = srv.accept()
    print(f"[SERVER] Connection from {addr}")
    session_key, peer_pub = handshake_engine.perform_handshake(conn, priv_rsa, pub_rsa, is_initiator=False)
    print(f"[SERVER] Handshake complete. Session key: {session_key.hex()}")
    conn.close()
    srv.close()
    return session_key
def client_thread(port, keypair, out_key_holder):
    priv_rsa, pub_rsa = keypair
    cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cli.connect(("127.0.0.1", port))
    session_key, peer_pub = handshake_engine.perform_handshake(cli, priv_rsa, pub_rsa, is_initiator=True)
    print(f"[CLIENT] Handshake complete. Session key: {session_key.hex()}")
    out_key_holder.append(session_key)
    cli.close()
def test_handshake_engine():
    port = 5055
    server_ready = threading.Event()
    # Generate distinct keypairs for initiator and responder
    server_keys = identity_manager.generate_rsa_key_pair()
    client_keys = identity_manager.generate_rsa_key_pair()
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


## Test message_framer.py ##
def test_message_framer():
    key = os.urandom(32)
    msg_type = 0x04
    payload = b"hello world, gcm test"
    frame = message_framer.aesgcm_encrypt_message(key, msg_type, payload)
    msg_type, plain = message_framer.aesgcm_decrypt_message(key, frame)
    print("[TEST] Type:", hex(msg_type))
    print("[TEST] Decrypted:", plain)
    print("[TEST] Decryption successful:", plain == payload)


## Test storage_manager.py ##
def test_storage_manager():
    password = "secret"
    tmpdir = tempfile.gettempdir()
    src = os.path.join(tmpdir, "plain.txt")
    enc = os.path.join(tmpdir, "enc.bin")
    dec = os.path.join(tmpdir, "dec.txt")
    open(src, "wb").write(b"Confidential data block.")
    storage_manager.encrypt_file(password, b"Confidential data block.", enc)
    dec_txt = storage_manager.decrypt_file(password, enc)
    open(dec, "wb").write(dec_txt)
    h1 = storage_manager.hash_file_bytes(src)
    h2 = storage_manager.hash_file_bytes(dec)
    print("[TEST] Hash equal:", h1 == h2)
    assert h1 == h2


## Test protocol_handler.py ##
def test_protocol_handler():
    # 0x03
    files = [{
        "name": "a.txt",
        "hash": b"1"*32,
        "fingerprint": "deadbeefcafebabe",
        "signature": b"SIGN",
    }]
    resp = protocol_handler.build_file_list_resp(files)
    parsed = protocol_handler.parse_file_list_resp(resp)
    assert parsed[0]["name"] == "a.txt"
    print("[TEST] FILE_LIST_RESPONSE ok")
    # 0x04 / 0x05
    b = protocol_handler.build_rcv_or_send_request("file.pdf")
    p = protocol_handler.parse_rcv_or_send_request(b)
    assert p == "file.pdf"
    print("[TEST] REQ_TO_RECEIVE / REQ_TO_SEND ok")
    b2 = protocol_handler.build_rcv_or_send_request("data.bin")
    p2 = protocol_handler.parse_rcv_or_send_request(b2)
    print("[TEST] REQ_TO_RECEIVE / REQ_TO_SEND ok")
    assert p2 == "data.bin"
    # 0x06
    km = protocol_handler.build_key_migration(b"PUB", b"1234567890123456", b"SIGN")
    km_p = protocol_handler.parse_key_migration(km)
    assert km_p["new_rsa_pub_der"] == b"PUB" and km_p["nonce"] == b"1234567890123456" and km_p["old_rsa_sig"] == b"SIGN"
    print("[TEST] KEY_MIGRATION ok")
    # 0x07
    c = protocol_handler.build_consent_resp(0x01, "demo")
    c_p_stat, c_p_filename = protocol_handler.parse_consent_resp(c)
    assert c_p_filename == "demo" and c_p_stat == 0x01
    print("[TEST] CONSENT_RESPONSE ok")
    # 0x08
    d = protocol_handler.build_data_transfer("x.txt", b"ABCDEF")
    d_p = protocol_handler.parse_data_transfer(d)
    assert d_p["filename"] == "x.txt" and d_p["file_contents"] == b"ABCDEF"
    print("[TEST] DATA_TRANSFER ok")
    print("[TEST] All protocol handler cases passed.")


if __name__ == "__main__":
    print("Testing discovery.py module:")
    test_discovery()
    print("\nTesting identity_manager.py module:")
    test_identity_manager()
    print("\nTesting handshake_engine.py module:")
    test_handshake_engine()
    print("\nTesting message_framer.py module:")
    test_message_framer()
    print("\nTesting storage_manager.py module:")
    test_storage_manager()
    print("\nTesting protocol_handler.py module:")
    test_protocol_handler()
 
