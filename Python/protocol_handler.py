'''
Implements handling for all supported message types after handshake complete.
Message catalogue:
    0x02 - GET_FILE_LIST      (request for peer's file list)
                Note: there is no implementation for this message type, as it is indicated only by the message type
    0x03 - FILE_LIST_RESPONSE (response to GET_FILE_LIST with file list)
    0x04 - REQ_TO_RECEIVE     (request to receive named file from peer)
    0x05 - REQ_TO_SEND        (request to send named file to peer)
    0x06 - KEY_MIGRATION      (notify peer of new long-term public key)
    0x07 - CONSENT_RESPONSE   (either accept or deny 0x04 or 0x05 request)
    0x08 - DATA_TRANSFER      (transfer complete file, no chunking)
'''

import struct

'''
Builds response for 0x03 - FILE_LIST_RESPONSE.
The message format is:
    4 bytes  - number of files (big-endian unsigned int)
  the following fields are repeated for each file in the list:
    4 bytes  - length of filename string (big-endian unsigned int)
    n bytes  - filename string (UTF-8 encoded, no null terminator)
    4 bytes  - length of file hash (big-endian unsigned int, should be 32 bytes for SHA-256)
    32 bytes - SHA-256 hash of plaintext file contents
    4 bytes  - length of owner's fingerprint (big-endian unsigned int)
    m bytes  - owner's fingerprint (hex string)
    4 bytes  - length of RSA-PSS signature on concatenation of filename + hash (big-endian unsigned int)
    k bytes  - RSA-PSS signature of filename + hash
Input: list of files (each file is a dict with keys "name" (str), "hash" (bytes), "fingerprint" (str), "signature" (bytes))
Output: raw unframed message (bytes)
'''
def build_file_list_resp(files: list) -> bytes:
    # Number of files
    resp = struct.pack(">I", len(files))

    # For each file
    for f in files:
        name_bytes = f["name"].encode("utf-8")
        hash_bytes = f["hash"]
        fingerprint_bytes = f["fingerprint"].encode("utf-8")
        sig_bytes = f["signature"]

        resp += (
              struct.pack(">I", len(name_bytes))
            + name_bytes
            + struct.pack(">I", 32) # length of hash is always 32
            + hash_bytes
            + struct.pack(">I", len(fingerprint_bytes))
            + fingerprint_bytes
            + struct.pack(">I", len(sig_bytes))
            + sig_bytes
        )

    return resp


'''
Parses 0x03 - FILE_LIST_RESPONSE message.
Input: raw unframed message (bytes)
Output: list of files (each file is a dict with keys "name" (str), "hash" (bytes), "fingerprint" (str), "signature" (bytes))
'''
def parse_file_list_resp(data: bytes) -> list:
    offset = 0
    files = []
    num_files = struct.unpack(">I", data[offset:offset+4])[0] # number of files in the list
    offset += 4

    # Process each file entry
    for f in range(num_files):
        # Filename
        name_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        name = data[offset:offset+name_len].decode("utf-8")
        offset += name_len

        # File hash
        hash_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        file_hash = data[offset:offset+hash_len]
        offset += hash_len

        # Fingerprint
        fingerprint_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        fingerprint = data[offset:offset+fingerprint_len].decode("utf-8")
        offset += fingerprint_len

        # Signature
        sig_len = struct.unpack(">I", data[offset:offset+4])[0]
        offset += 4
        signature = data[offset:offset+sig_len]
        offset += sig_len

        # Append file info to list
        files.append({
            "name": name,
            "hash": file_hash,
            "fingerprint": fingerprint,
            "signature": signature
        })

    return files


'''
Build & parse 0x04 or 0x05 - REQ_TO_RECEIVE or REQ_TO_SEND messages.
The message format is:
    4 bytes - length of filename string (big-endian unsigned int)
    n bytes - filename string (UTF-8 encoded, no null terminator)
Input: filename (str)
Output: raw unframed message (bytes)
'''
def build_rcv_or_send_request(filename: str) -> bytes:
    name_bytes = filename.encode("utf-8")
    return struct.pack(">I", len(name_bytes)) + name_bytes

def parse_rcv_or_send_request(data: bytes) -> str:
    name_len = struct.unpack(">I", data[0:4])[0]
    filename = data[4:4+name_len].decode("utf-8")
    return filename


'''
Build 0x06 - KEY_MIGRATION message.
The message format is:
    4 bytes  - length of new RSA pubkey in DER format (big-endian unsigned int)
    n bytes  - new RSA pubkey in DER format
    4 bytes  - length of nonce (should be 16 bytes)
    16 bytes - 16-byte nonce
    4 bytes  - length of RSA-PSS signature on concatenation of new pubkey + nonce (big-endian unsigned int)
    m bytes  - RSA-PSS signature of new pubkey + nonce using old RSA privkey
Input: new RSA public key (bytes in DER format), nonce (bytes), signature (bytes)
Output: raw unframed message (bytes)
'''
def build_key_migration(new_rsa_pub: bytes, nonce: bytes, sig: bytes) -> bytes:
    return (
          struct.pack(">I", len(new_rsa_pub))
        + new_rsa_pub
        + struct.pack(">I", 16) # nonce is 16 bytes
        + nonce
        + struct.pack(">I", len(sig))
        + sig
    )

'''
Parses 0x06 - KEY_MIGRATION message.
The message format is the same as above.
Input: raw unframed message (bytes)
Output: dict with keys "new_rsa_pub_der" (bytes), "nonce" (bytes), "old_rsa_sig" (bytes)
'''
def parse_key_migration(data: bytes):
    offset = 0
    
    # New RSA pubkey
    rsa_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    new_rsa_pub = data[offset:offset+rsa_len]
    offset += rsa_len

    # Nonce
    nonce_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    nonce = data[offset:offset+nonce_len]
    offset += nonce_len

    # Signature
    sig_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    sig = data[offset:offset+sig_len]

    return {"new_rsa_pub_der": new_rsa_pub, "nonce": nonce, "old_rsa_sig": sig}


'''
Build & parse 0x07 - CONSENT_RESPONSE message. Sent in response to a 0x04 or 0x05 request.
The message format is:
    1 byte  - status (0x01 for accept, 0x02 for deny)
    4 bytes - length of filename
    n bytes - filename string (UTF-8 encoded, no null terminator)
Input: status (int), filename (str)
Output: raw unframed message (bytes)
'''
def build_consent_resp(status: int, filename: str) -> bytes:
    name_bytes = filename.encode("utf-8")
    return struct.pack(">B", status) + struct.pack(">I", len(name_bytes)) + name_bytes

def parse_consent_resp(data: bytes):
    status = data[0]
    name_len = struct.unpack(">I", data[1:5])[0]
    filename = data[5:5+name_len].decode("utf-8")

    return status, filename


'''
Build 0x08 - DATA_TRANSFER message.
The message format is:
    4 bytes - length of filename string
    n bytes - filename string (UTF-8 encoded, no null terminator)
    8 bytes - length of binary file contents in bytes (big-endian unsigned int)
    m bytes - binary file contents (plaintext)
Input: filename (str), file contents (bytes)
Output: raw unframed message (bytes)
'''
def build_data_transfer(filename: str, file_contents: bytes) -> bytes:
    name_bytes = filename.encode("utf-8")
    return (
          struct.pack(">I", len(name_bytes))
        + name_bytes
        + struct.pack(">Q", len(file_contents)) # 8 bytes for file size
        + file_contents
    )

'''
Parses 0x08 - DATA_TRANSFER message.
The message format is the same as above.
Input: raw unframed message (bytes)
Output: dict with keys "filename" (str), "file_contents" (bytes)
'''
def parse_data_transfer(data: bytes):
    offset = 0

    # Filename
    name_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    filename = data[offset:offset+name_len].decode("utf-8")
    offset += name_len

    # File contents
    file_size = struct.unpack(">Q", data[offset:offset+8])[0]
    offset += 8
    file_contents = data[offset:offset+file_size]

    return {"filename": filename, "file_contents": file_contents}


# temp tests: TODO place in proper test file
if __name__ == "__main__":
    # 0x03
    files = [{
        "name": "a.txt",
        "hash": b"1"*32,
        "fingerprint": "deadbeefcafebabe",
        "signature": b"SIGN",
    }]
    resp = build_file_list_resp(files)
    parsed = parse_file_list_resp(resp)
    assert parsed[0]["name"] == "a.txt"
    print("[TEST] FILE_LIST_RESPONSE ok")
    # 0x04 / 0x05
    b = build_rcv_or_send_request("file.pdf")
    p = parse_rcv_or_send_request(b)
    assert p == "file.pdf"
    print("[TEST] REQ_TO_RECEIVE / REQ_TO_SEND ok")
    b2 = build_rcv_or_send_request("data.bin")
    p2 = parse_rcv_or_send_request(b2)
    print("[TEST] REQ_TO_RECEIVE / REQ_TO_SEND ok")
    assert p2 == "data.bin"
    # 0x06
    km = build_key_migration(b"PUB", b"1234567890123456", b"SIGN")
    km_p = parse_key_migration(km)
    assert km_p["new_rsa_pub_der"] == b"PUB" and km_p["nonce"] == b"1234567890123456" and km_p["old_rsa_sig"] == b"SIGN"
    print("[TEST] KEY_MIGRATION ok")
    # 0x07
    c = build_consent_resp(0x01, "demo")
    c_p_stat, c_p_filename = parse_consent_resp(c)
    assert c_p_filename == "demo" and c_p_stat == 0x01
    print("[TEST] CONSENT_RESPONSE ok")
    # 0x08
    d = build_data_transfer("x.txt", b"ABCDEF")
    d_p = parse_data_transfer(d)
    assert d_p["filename"] == "x.txt" and d_p["file_contents"] == b"ABCDEF"
    print("[TEST] DATA_TRANSFER ok")
    print("[TEST] All protocol handler cases passed.")
