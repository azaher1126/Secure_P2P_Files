'''
CLI P2P client implementation for all message types
'''

import os
import socket
import threading
from cryptography.hazmat.primitives import serialization
from identity_manager import load_identity, save_identity, compute_fingerprint, rsa_pss_sign, rsa_pss_verify, generate_rsa_key_pair
from handshake_engine import perform_handshake
from message_framer import aesgcm_encrypt_message, aesgcm_decrypt_message
from protocol_handler import (
    build_file_list_resp, parse_file_list_resp,
    build_rcv_or_send_request, parse_rcv_or_send_request,
    build_key_migration, parse_key_migration,
    build_consent_resp, parse_consent_resp,
    build_data_transfer, parse_data_transfer
)
from discovery import Discovery
from storage_manager import encrypt_file, decrypt_file, hash_file_bytes

DATA_PATH = "shared_files"
os.makedirs(DATA_PATH, exist_ok=True)


'''
Receives & handles incoming messages in background during an established session with a peer.
Input: socket connection to peer, session key, this peer's RSA private key, this peer's RSA public key, this peer's password
Output: None (runs session loop until connection is closed)
'''
def recv_loop(sock, session_key, priv_rsa, pub_rsa, password):
    while True:
        try:
            frame = sock.recv(4096)
            if not frame:
                break

            # Get message type and payload in plaintext
            msg_type, plaintext = aesgcm_decrypt_message(session_key, frame)
        
        except Exception as e:
            print("[!] Receive loop error:", e)
            break

        # Handle incoming message based on type
        # GET_FILE_LIST
        if msg_type == 0x02:
            print("[REQ] Peer requested file list")

            files = []
            for filename in os.listdir(DATA_PATH):
                filepath = os.path.join(DATA_PATH, filename)
                if not os.path.isfile(filepath):
                    continue

                # This is a file, get the metadata
                h = hash_file_bytes(filepath)
                fingerprint = compute_fingerprint(pub_rsa)
                sig = rsa_pss_sign(priv_rsa, filename.encode("utf-8") + h)
                files.append({
                    "name": filename,
                    "hash": h,
                    "fingerprint": fingerprint,
                    "signature": sig,
                })

            # Build the response message payload
            payload = build_file_list_resp(files)
            # Encrypt and send the response
            frame_out = aesgcm_encrypt_message(session_key, 0x03, payload)
            sock.sendall(frame_out)

        # FILE_LIST_RESPONSE
        elif msg_type == 0x03:
            print("[RESP] Received file list response from peer:")
            files = parse_file_list_resp(plaintext)
            for f in files:
                print(f"  - {f['name']} (hash: {f['hash'].hex()}, owner: {f['fingerprint']}, signature: {f['signature'].hex()})")

        # REQ_TO_RECEIVE
        elif msg_type == 0x04:
            filename = parse_rcv_or_send_request(plaintext)
            print("[REQ] Peer requests to download file", filename)
            
            # Get the user's consent
            consent = input("Accept request? (y/n): ").strip().lower().startswith("y")
            if consent:
                filepath = os.path.join(DATA_PATH, filename)
                if not os.path.isfile(filepath): # file not found, send deny consent response
                    print("[!] Requested file not found")
                    continue

                print("[RESP] Sending file...")
                # Send the file
                file_plaintext = decrypt_file(password, filepath)
                data_transfer = build_data_transfer(filename, file_plaintext)
                frame_out = aesgcm_encrypt_message(session_key, 0x08, data_transfer)
                sock.sendall(frame_out)
                print("[RESP] File sent successfully")

        # REQ_TO_SEND
        elif msg_type == 0x05:
            filename = parse_rcv_or_send_request(plaintext)
            print("[REQ] Peer wants to upload ", filename)

            # Get consent
            consent = input("Accept? (y/n): ").lower().startswith("y")
            if consent:
                status = 0x01 # accept
            else:
                status = 0x02 # deny
            
            # Respond to peer
            consent_resp = build_consent_resp(status, filename)
            frame_out = aesgcm_encrypt_message(session_key, 0x07, consent_resp)
            sock.sendall(frame_out)

        # KEY_MIGRATION
        elif msg_type == 0x06:
            print("[INFO] Received key migration notice")

            # Get the new key & info
            new_key = parse_key_migration(plaintext)
            new_der = new_key["new_rsa_pub_der"]
            nonce = new_key["nonce"]
            sig = new_key["old_rsa_sig"]

            # Verify new key with old signature
            with open("trusted_peer.pub", "rb") as f:
                old_peer_rsa_pub = f.read()
            if rsa_pss_verify(old_peer_rsa_pub, new_der + nonce, sig):
                print("[*] Key migration verified")
                # Update stored pubkey for peer
                with open("trusted_peer.pub", "wb") as f:
                    f.write(new_der)

                print("[*] Peer public key updated, closing session")
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception as e:
                    print("[!] Failed to shut down session, exception", e)
                sock.close()
                break

        # CONSENT_RESPONSE
        elif msg_type == 0x07:
            status, filename = parse_consent_resp(plaintext)
            print(f"[RESP] Received consent {status} for {filename}")
            
            if status == 0x01: # accept
                filepath = os.path.join(DATA_PATH, filename)
                if os.path.isfile(filepath):
                    # Send the file
                    file_plaintext = decrypt_file(password, filepath)
                    data_transfer = build_data_transfer(filename, file_plaintext)
                    frame_out = aesgcm_encrypt_message(session_key, 0x08, data_transfer)
                    sock.sendall(frame_out)
                    print("[RESP] File sent successfully")

        # DATA_TRANSFER
        elif msg_type == 0x08:
            file_data = parse_data_transfer(plaintext)
            filename = file_data["filename"]
            file_contents = file_data["file_contents"]
            print("[INFO] Received file transfer for file", filename)

            # Encrypt file contents and store
            filepath = os.path.join(DATA_PATH, filename)
            encrypt_file(password, file_contents, filepath)
    
    print("[*] Receive loop closed")


'''
Interactive session for user.
Input: socket connection to peer, session key, this peer's priv RSA key, this peer's pub RSA key, this peer's password
Output: None (runs loop until connection closed)
'''
def interactive_cli(sock, session_key, priv_rsa, pub_rsa, password):
    while True:
        try:
            print("Options:")
            print(" - request peer file list  [list]")
            print(" - request to receive file [get <filename>]")
            print(" - request to send a file  [send <filename>]")
            print(" - key migration notice    [migrate]")
            print(" - exit                    [exit]")
            cmd = input("Enter cmd [list/get/send/migrate/exit]: ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue

        # Otherwise parse the command
        parts = cmd.split()
        op = parts[0] # operation requested

        if op == "list":
            frame_out = aesgcm_encrypt_message(session_key, 0x02, b"")
            sock.sendall(frame_out)
            print("[RESP] Requested file list from peer")

        elif op == "get":
            if len(parts) != 2:
                print("Usage: get <filename>")
                continue
            
            rcv_req = build_rcv_or_send_request(parts[1])
            frame_out = aesgcm_encrypt_message(session_key, 0x04, rcv_req)
            sock.sendall(frame_out)
            print(f"[RESP] Requested file {parts[1]} from peer")

        elif op == "send":
            if len(parts) != 2:
                print("Usage: send <filename>")
                continue

            filename = parts[1]
            filepath = os.path.join(DATA_PATH, filename)
            if os.path.isfile(filepath):
                send_req = build_rcv_or_send_request(parts[1])
                frame_out = aesgcm_encrypt_message(session_key, 0x05, send_req)
                sock.sendall(frame_out)
                print(f"[RESP] Requested to send file {parts[1]} to peer")
            else:
                print(f"[ERR] No file {filename} in shared_files/")

        elif op == "migrate":
            print("[*] Starting key migration procedure...")

            # Generate new RSA keys
            new_priv, new_pub = generate_rsa_key_pair()
            # Save identity
            save_identity(new_priv, new_pub, password)

            # Generate other fields for key migration message
            new_pub_der = new_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            nonce = os.urandom(16)

            # Sign just the new DER-encoded key and nonce
            payload_to_sign = new_pub_der + nonce
            old_sig = rsa_pss_sign(priv_rsa, payload_to_sign)

            # Build the key migration message
            key_migration_req = build_key_migration(new_pub_der, nonce, old_sig)
            frame_out = aesgcm_encrypt_message(session_key, 0x06, key_migration_req)
            sock.sendall(frame_out)

            print("[*] Sent KEY_MIGRATION notice to peer and updated keys. Future sessions will use new key.")
            # Shut down the connection
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                print("[ERR] Failed to shut down socket, exception", e)
            sock.close()
            break

        elif op == "exit":
            print("[*] Closing session...")
            break

        else:
            print("[ERR] Invalid command.")
    
    try:
        sock.close()
    except Exception as e:
        print("Failed to close socket with exception", e)


'''
Handles incoming connection from peer.
'''
def handle_peer_connection(conn, addr, priv_rsa, pub_rsa, password):
    print(f"[+] Inbound connection from {addr}")
    try:
        session_key, peer_rsa_pub = perform_handshake(conn, priv_rsa, pub_rsa, is_initiator=False)
    except Exception as e: # give up
        print("[!] Handshake failed:", e)
        conn.close()
        return
    
    print(f"[*] Started secure session with {addr}")

    threading.Thread(
        target=recv_loop, args=(conn, session_key, priv_rsa, pub_rsa, password), daemon=True
    ).start()
    interactive_cli(conn, session_key, priv_rsa, pub_rsa, password)

'''
Handles outbound connection to peer.
'''
def connect_to_peer(ip, priv_rsa, pub_rsa, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Try to establish connection
    try:
        s.connect((ip, 5000))
    except Exception as e:
        print("[!] Connection failed:", e)
        return
    
    # Try to perform handshake
    try:
        session_key, peer_rsa_pub = perform_handshake(s, priv_rsa, pub_rsa, is_initiator=True)
    except Exception as e: # give up
        print("[!] Handshake failed:", e)
        s.close()
        return
    
    # Successful connection & handshake
    print("[*] Secure session established with ", ip)
    threading.Thread(
        target=recv_loop, args=(s, session_key, priv_rsa, pub_rsa, password), daemon=True
    ).start()
    interactive_cli(s, session_key, priv_rsa, pub_rsa, password)


'''
Listener for inbound peer connections.
'''
def start_server(priv_rsa, pub_rsa, password):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", 5000))
    srv.listen()
    print("[*] Listening on TCP/5000...")

    # Accept connections
    while True:
        conn, addr = srv.accept()
        threading.Thread(
            target=handle_peer_connection, args=(conn, addr, priv_rsa, pub_rsa, password), daemon=True
        ).start()


if __name__ == "__main__":
    # Setup
    print("Welcome to the Secure P2P File-Sharing Application.")
    password = input("Enter a master password: ").strip()
    priv_rsa, pub_rsa = load_identity(password)
    fingerprint = compute_fingerprint(pub_rsa)
    print("[+] Your peer ID:", fingerprint)

    # Discover peers
    disc = Discovery(fingerprint)
    disc.start()
    # Advertise & listen for peer connections in background
    threading.Thread(target=disc.browse, daemon=True).start()
    threading.Thread(target=start_server, args=(priv_rsa, pub_rsa, password), daemon=True).start()

    while True:
        cmd = input("Enter a choice [peers/connect/exit]: ").strip()
        if cmd == "peers":
            for (name, data) in disc.peers.items():
                ip = data[1]
                port = data[2]
                print(f"{name}@{ip}:{port}")

        elif cmd.startswith("connect"):
            parts = cmd.split()
            if len(parts) != 2:
                print("Usage: connect <peer-ip>")
                continue
            # Connect to peer
            connect_to_peer(parts[1], priv_rsa, pub_rsa, password)

        elif cmd == "exit":
            print("Bye!")
            break
        else:
            print("Invalid command.")
