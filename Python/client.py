'''
CLI P2P client implementation for all message types
'''

import os
import socket
import threading
import hashlib
from queue import Queue
from cryptography.hazmat.primitives import serialization
from identity_manager import load_identity, save_identity, compute_fingerprint, rsa_pss_sign, rsa_pss_verify, generate_rsa_key_pair
from handshake_engine import perform_handshake
from message_framer import aesgcm_encrypt_message, aesgcm_decrypt_message, recv_message
from protocol_handler import (
    build_file_list_resp, parse_file_list_resp,
    build_rcv_or_send_request, parse_rcv_or_send_request,
    build_key_migration, parse_key_migration,
    build_consent_resp, parse_consent_resp,
    build_data_transfer, parse_data_transfer
)
from discovery import Discovery
from storage_manager import encrypt_file, decrypt_file, hash_file_bytes, encrypt_plaintext_file_on_bootup

DATA_PATH = "shared_files"
os.makedirs(DATA_PATH, exist_ok=True)


'''
Receives & handles incoming messages in background during an established session with a peer.
Input: socket connection to peer, session key, this peer's RSA private key, this peer's RSA public key, this peer's password
Output: None (runs session loop until connection is closed)
'''
def recv_loop(sock, session_key, priv_rsa, pub_rsa, password, ui_queue, input_queue):
    while True:
        try:
            msg_type, plaintext = recv_message(sock, session_key)
            if msg_type is None:
                break
        except Exception as e:
            print("[!] Receive loop error:", e)
            break

        # Handle incoming message based on type
        # GET_FILE_LIST
        if msg_type == 0x02:
            ui_queue.put("[REQ] Peer requested file list")

            files = []
            for filename in os.listdir(DATA_PATH):
                filepath = os.path.join(DATA_PATH, filename)
                if not os.path.isfile(filepath):
                    continue

                # Handle encrypted files (_enc suffix) - derive original name and plaintext hash
                if filename.endswith("_enc") or "_enc." in filename:
                    # Derive original filename (e.g., "doc_enc.txt" -> "doc.txt")
                    # The bootup encryption inserts "_enc" before the extension
                    # e.g., "document.txt" -> "document_enc.txt"
                    if "_enc." in filename:
                        parts = filename.rsplit("_enc.", 1)
                        original_name = parts[0] + "." + parts[1]
                    else:
                        # File ends with "_enc" but no extension
                        original_name = filename[:-4]  # Remove "_enc" suffix
                    
                    # Decrypt file to get plaintext for hashing/signing
                    try:
                        file_plaintext = decrypt_file(password, filepath)
                    except Exception as e:
                        ui_queue.put(f"[!] Failed to decrypt {filename}: {e}")
                        continue
                    
                    # Hash the PLAINTEXT (not ciphertext) per protocol spec
                    h = hashlib.sha256(file_plaintext).digest()
                    
                    # Use original filename in the list
                    display_name = original_name
                else:
                    # Plaintext file (shouldn't normally happen after bootup)
                    h = hash_file_bytes(filepath)
                    display_name = filename
                
                fingerprint = compute_fingerprint(pub_rsa)
                # Sign over (filename + hash)
                sig = rsa_pss_sign(priv_rsa, display_name.encode("utf-8") + h)
                files.append({
                    "name": display_name,
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
            ui_queue.put("[RESP] Received file list response from peer:")
            files = parse_file_list_resp(plaintext)
            for f in files:
                ui_queue.put(f"  - {f['name']} (hash: {f['hash'].hex()}, owner: {f['fingerprint']}, signature: {f['signature'].hex()})")
            # Save list of files and hashes for reference during data transfer
            # store in form [filename],[filehash]
            with open("peer_files.txt", "wb") as peer_files:
                for f in files:
                    fname = f['name'].encode('utf-8')
                    fhash = f['hash']
                    peer_files.write(fname + ",".encode("utf-8") + fhash + "\n".encode("utf-8"))

        # REQ_TO_RECEIVE
        elif msg_type == 0x04:
            filename = parse_rcv_or_send_request(plaintext)
            ui_queue.put(f"[REQ] Peer requests to download file {filename}, accept?")
            
            # Get the user's consent
            try:
                consent = input_queue.get(timeout=30)
            except:
                ui_queue.put("[!] No response, denying request")
                consent = False
            
            # Determine status and check file existence
            # Try the filename as-is first (for plaintext files)
            filepath = os.path.join(DATA_PATH, filename)
            file_exists = os.path.isfile(filepath)
            
            # If not found, try looking for encrypted version (filename_enc.ext)
            if not file_exists and "." in filename:
                # Insert "_enc" before the extension
                parts = filename.rsplit(".", 1)
                enc_filename = parts[0] + "_enc." + parts[1]
                enc_filepath = os.path.join(DATA_PATH, enc_filename)
                if os.path.isfile(enc_filepath):
                    filepath = enc_filepath
                    file_exists = True
            elif not file_exists and filename.endswith("_enc") is False:
                # Try appending "_enc" suffix
                enc_filepath = os.path.join(DATA_PATH, filename + "_enc")
                if os.path.isfile(enc_filepath):
                    filepath = enc_filepath
                    file_exists = True
            
            if consent and file_exists:
                status = 0x01  # accept
            else:
                status = 0x02  # deny
                if consent and not file_exists:
                    ui_queue.put("[!] Requested file not found")
            
            # Send CONSENT_RESPONSE first
            consent_resp = build_consent_resp(status, filename)
            frame_out = aesgcm_encrypt_message(session_key, 0x07, consent_resp)
            sock.sendall(frame_out)
            
            # Only send file if accepted
            if status == 0x01:  # accept
                ui_queue.put("[RESP] Sending file...")
                # Send the file
                file_plaintext = decrypt_file(password, filepath)
                data_transfer = build_data_transfer(filename, file_plaintext)
                frame_out = aesgcm_encrypt_message(session_key, 0x08, data_transfer)
                sock.sendall(frame_out)
                ui_queue.put("[RESP] File sent successfully")

        # REQ_TO_SEND
        elif msg_type == 0x05:
            filename = parse_rcv_or_send_request(plaintext)
            ui_queue.put(f"[REQ] Peer wants to upload {filename}, accept?")

            # Get consent
            try:
                consent = input_queue.get(timeout=30)
            except:
                ui_queue.put("[!] No response, denying request")
                consent = False
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
            ui_queue.put("[INFO] Received key migration notice")

            # Get the new key & info
            new_key = parse_key_migration(plaintext)
            new_der = new_key["new_rsa_pub_der"]
            nonce = new_key["nonce"]
            sig = new_key["old_rsa_sig"]

            # Verify new key with old signature
            with open("trusted_peer.pub", "rb") as f:
                old_peer_rsa_pub = f.read()
            if rsa_pss_verify(serialization.load_der_public_key(old_peer_rsa_pub), new_der + nonce, sig):
                ui_queue.put("[*] Key migration verified")
                # Update stored pubkey for peer
                with open("trusted_peer.pub", "wb") as f:
                    f.write(new_der)

                ui_queue.put("[*] Peer public key updated, closing session")
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except Exception as e:
                    print("[!] Failed to shut down session, exception", e)
                sock.close()
                break

        # CONSENT_RESPONSE
        elif msg_type == 0x07:
            status, filename = parse_consent_resp(plaintext)
            ui_queue.put(f"[RESP] Received consent {status} for {filename}")
            
            if status == 0x01: # accept
                filepath = os.path.join(DATA_PATH, filename)
                if os.path.isfile(filepath):
                    # Send the file
                    file_plaintext = decrypt_file(password, filepath)
                    data_transfer = build_data_transfer(filename, file_plaintext)
                    frame_out = aesgcm_encrypt_message(session_key, 0x08, data_transfer)
                    sock.sendall(frame_out)
                    ui_queue.put("[RESP] File sent successfully")
                elif not "_enc" in filename:
                    # Try version with _enc at end of filename
                    fname_parts = filename.split(".")
                    filepath = os.path.join(DATA_PATH, fname_parts[0] + "_enc." + fname_parts[1])
                    if os.path.isfile(filepath):
                        # Send the file
                        file_plaintext = decrypt_file(password, filepath)
                        data_transfer = build_data_transfer(filename, file_plaintext)
                        frame_out = aesgcm_encrypt_message(session_key, 0x08, data_transfer)
                        sock.sendall(frame_out)
                        ui_queue.put("[RESP] File sent successfully")
                    else:
                        print("no filepath", filepath)

        # DATA_TRANSFER
        elif msg_type == 0x08:
            file_data = parse_data_transfer(plaintext)
            filename = file_data["filename"]
            file_contents = file_data["file_contents"]
            ui_queue.put(f"[INFO] Received file transfer for file {filename}")

            # Verify the hash
            filehash = hashlib.sha256(file_contents).digest()
            fname_len = len(filename)
            verified = False
            with open("peer_files.txt", "rb") as f:
                for line in f:
                    fileinfo = line.strip()
                    if (fileinfo[:fname_len]).decode("utf-8") == filename:
                        print("saved hash:", fileinfo[fname_len + 1 :].hex())
                        print("received hash:", filehash.hex())
                        # check if the hash matches
                        if fileinfo[fname_len + 1 :] == filehash:
                            verified = True
                            break
                        # else verified remains False
                        break

            # Encrypt file contents and store only if file hash was verified
            if verified:
                ui_queue.put(f"Hash verified for file {filename}, storing now")
                # Store new encrypted files with _enc in the name
                if not "_enc" in filename:
                    fname_parts = filename.split(".")
                    fname_enc = fname_parts[0] + "_enc." + fname_parts[1]
                else:
                    fname_enc = filename
                filepath = os.path.join(DATA_PATH, fname_enc)
                encrypt_file(password, file_contents, filepath)
            else:
                ui_queue.put(f"Hash verification failed for file {filename}, not storing")
    
    print("[*] Receive loop closed")


'''
Interactive session for user.
Input: socket connection to peer, session key, this peer's priv RSA key, this peer's pub RSA key, this peer's password
Output: None (runs loop until connection closed)
'''
def interactive_cli(sock, session_key, priv_rsa, pub_rsa, password, ui_queue, input_queue):
    while True:
        pending_prompt = None
        while not ui_queue.empty():
            msg = ui_queue.get()
            print(msg)
            if "accept?" in msg:
                pending_prompt = msg
            # If waiting for user input
            if pending_prompt:
                ans = input("(y/n): ").strip().lower().startswith("y")
                input_queue.put(ans)
                pending_prompt = None
                continue
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

            if "_enc" in parts[1]:
                fname_parts = parts[1].split(".")
                filename = (fname_parts[0])[:-4] + "." + fname_parts[1]
            else:
                filename = parts[1]
            filepath = os.path.join(DATA_PATH, parts[1])
            if os.path.isfile(filepath):
                send_req = build_rcv_or_send_request(filename)
                frame_out = aesgcm_encrypt_message(session_key, 0x05, send_req)
                sock.sendall(frame_out)
                print(f"[RESP] Requested to send file {parts[1]} to peer")
            else:
                print(f"[ERR] No file {parts[1]} in shared_files/")

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

    ui_queue = Queue()
    input_queue = Queue()
    threading.Thread(
        target=recv_loop, args=(conn, session_key, priv_rsa, pub_rsa, password, ui_queue, input_queue), daemon=True
    ).start()
    interactive_cli(conn, session_key, priv_rsa, pub_rsa, password, ui_queue, input_queue)

'''
Handles outbound connection to peer.
'''
def connect_to_peer(ip, port, priv_rsa, pub_rsa, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Try to establish connection
    try:
        s.connect((ip, port))
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
    ui_queue = Queue()
    input_queue = Queue()
    threading.Thread(
        target=recv_loop, args=(s, session_key, priv_rsa, pub_rsa, password, ui_queue, input_queue), daemon=True
    ).start()
    interactive_cli(s, session_key, priv_rsa, pub_rsa, password, ui_queue, input_queue)


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

    # Encrypt all files in shared_files/ on bootup
    for filename in os.listdir(DATA_PATH):
        filepath = os.path.join(DATA_PATH, filename)
        print(filepath)
        if not "_enc" in filepath:
            filename_parts = filename.split(".")
            enc_fname = filename_parts[0] + "_enc." + filename_parts[1]
            enc_fpath = os.path.join(DATA_PATH, enc_fname)
            print(enc_fpath)
            encrypt_plaintext_file_on_bootup(password, filepath, enc_fpath)
            os.remove(filepath)
        print(os.listdir(DATA_PATH))

    # Discover peers
    disc = Discovery(fingerprint, port=5000)
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
            if len(parts) != 3:
                print("Usage: connect <peer-ip> <peer-port>")
                continue
            # Connect to peer
            connect_to_peer(parts[1], int(parts[2]), priv_rsa, pub_rsa, password)

        elif cmd == "exit":
            print("Bye!")
            break
        else:
            print("Invalid command.")
