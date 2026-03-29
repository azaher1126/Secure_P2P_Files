'''
Manages storage of files & their encryption/decryption.
'''

import os
import hashlib
from identity_manager import derive_master_key, aes_cbc_encrypt, aes_cbc_decrypt

'''
Encrypts a file using AES-CBC with the master key derived from the user's password.
Input: user password, plaintext file path, ciphertext file path
Output: None (saves encrypted file to disk)
'''
def encrypt_file(password: str, plaintext: bytes, ciphertext_path: str):
    # Get the AES key
    key = derive_master_key(password)
    # Encrypt plaintext
    ciphertext = aes_cbc_encrypt(key, plaintext)

    # Write ciphertext to file
    open(ciphertext_path, "wb").write(ciphertext)
    return


'''
Decrypts a file using AES-CBC with the master key derived from the user's password.
Input: user password, ciphertext file path, plaintext file path
Output: plaintext file contents (bytes)
'''
def decrypt_file(password: str, ciphertext_path: str):
    # Get the AES key
    key = derive_master_key(password)
    # Read and decrypt ciphertext file
    with open(ciphertext_path, "rb") as f:
        ciphertext = f.read()
    plaintext = aes_cbc_decrypt(key, ciphertext)

    return plaintext


'''
Computes SHA-256 hash of file contents.
Input: filepath
Output: bytes of hash digest
'''
def hash_file_bytes(filepath: str) -> bytes:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


# temp test: TODO move to proper test file
import tempfile
if __name__ == "__main__":
    password = "secret"
    tmpdir = tempfile.gettempdir()
    src = os.path.join(tmpdir, "plain.txt")
    enc = os.path.join(tmpdir, "enc.bin")
    dec = os.path.join(tmpdir, "dec.txt")
    open(src, "wb").write(b"Confidential data block.")
    encrypt_file(password, src, enc)
    decrypt_file(password, enc, dec)
    h1 = hash_file_bytes(src)
    h2 = hash_file_bytes(dec)
    print("[TEST] Hash equal:", h1 == h2)
    assert h1 == h2
