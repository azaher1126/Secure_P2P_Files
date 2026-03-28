'''
Implements requirements of managing identity (master key, encryption, decryption, RSA key generation, sign/verification, etc.)
'''

import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Store identity-related files in "data" directory
DATA_DIR = "data"
PUBKEY_FILE = os.path.join(DATA_DIR, "identity.pub")
PRIVKEY_FILE = os.path.join(DATA_DIR, "identity.key")
SALT_FILE = os.path.join(DATA_DIR, "local.salt")

'''
Checks if "data" subdirectory exists; if not, create it.
'''
def check_exists_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)


'''
Derive master AES key from PBKDF2-HMAC-SHA256 with user's input password.
Input: user's password (str)
Output: master key (32 bytes)
'''
def derive_master_key(password: str) -> bytes:
    check_exists_data_dir()
    # Check if salt file exists & create one if necessary
    if os.path.exists(SALT_FILE):
        salt = open(SALT_FILE, "rb").read()
    else:
        salt = os.urandom(16)
        open(SALT_FILE, "wb").write(salt)
    
    # Generate master key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
        backend=default_backend()
    )
    master_key = kdf.derive(password.encode("utf-8"))
    return master_key


'''
Generate RSA public-private key pair.
'''
def generate_rsa_key_pair():
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()
    return priv_key, pub_key


'''
Saves RSA public-private key pair to files. Uses the master key to encrypt the private key.
Input: private key, public key, user's password
Output: None (saves files to disk)
'''
def save_identity(priv_key, pub_key, password: str):
    check_exists_data_dir()
    
    # Get master key
    master_key = derive_master_key(password)

    # Serialize keys
    priv_bytes = priv_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_bytes = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Encrypt private key with master key using AES CBC
    enc_priv = aes_cbc_encrypt(master_key, priv_bytes)

    # Write to files
    open(PRIVKEY_FILE, "wb").write(enc_priv)
    open(PUBKEY_FILE, "wb").write(pub_bytes)
    return


'''
Load RSA identity from files.
Input: user's password
Output: RSA private key, public key
'''
def load_identity(password: str):
    # Get master key
    master_key = derive_master_key(password)
    if not os.path.exists(PRIVKEY_FILE) or not os.path.exists(PUBKEY_FILE):
        print("No identity found, generating one now...")
        priv_key, pub_key = generate_rsa_key_pair()
        save_identity(priv_key, pub_key, password)
    else:
        # Load and decrypt private key
        enc_priv = open(PRIVKEY_FILE, "rb").read()
        priv_bytes = aes_cbc_decrypt(master_key, enc_priv)
        priv_key = serialization.load_der_private_key(priv_bytes, password=None)

        # Load public key
        pub_bytes = open(PUBKEY_FILE, "rb").read()
        pub_key = serialization.load_der_public_key(pub_bytes)
    return priv_key, pub_key

'''
Computes peer ID fingerprint as 8-byte truncated SHA-256 hash of public key.
Input: RSA public key
Output: peer ID (8 bytes as 16-character hex string)
'''
def compute_fingerprint(pub_key) -> str:
    # Get the DER encoding of the public key
    der = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Hash and get the first 8 bytes
    hash_digest = hashlib.sha256(der).digest()[:8]
    return hash_digest.hex()


'''
Sign a message using RSA-PSS with hash SHA-256, MGF MGF1 with SHA-256, & salt length 32 bytes.
Input: RSA private key, message (bytes)
Output: signature (bytes)
'''
def rsa_pss_sign(priv_key, data: bytes) -> bytes:
    return priv_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256()
    )


'''
Verify a signature using RSA-PSS with hash SHA-256, MGF MGF1 with SHA-256, & salt length 32 bytes.
Input: RSA public key, message (bytes), signature (bytes)
Output: True if valid, False if invalid
'''
def rsa_pss_verify(pub_key, data: bytes, signature: bytes) -> bool:
    try:
        pub_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verfication failed: {e}")
        return False


'''
Wrapper for AES CBC encryption. CBC encryption is done with padding according to PKCS7, where
    if N bytes of padding are required to make the plaintext a multiple of the block size, 
    then N bytes of value N are appended to the plaintext.
Input: master key (bytes), plaintext (bytes)
Output: ciphertext (bytes)
'''
def aes_cbc_encrypt(master_key: bytes, plaintext: bytes) -> bytes:
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    # Get the padding length needed & pad the plaintext
    pad_len = 16 - (len(plaintext) % 16)
    padded_text = plaintext + bytes([pad_len] * pad_len)

    # Encrypt
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    ciphertext = cipher.encryptor().update(padded_text) + cipher.encryptor().finalize()

    # Send IV + ciphertext together
    return iv + ciphertext


'''
Wrapper for AES CBC decryption.
Input: master key (bytes), ciphertext (bytes)
Output: plaintext (bytes)
'''
def aes_cbc_decrypt(master_key: bytes, ciphertext: bytes) -> bytes:
    # Extract IV from ciphertext
    iv = ciphertext[:16]
    real_ciphertext = ciphertext[16:]

    # Decrypt
    cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv), backend=default_backend())
    plaintext = cipher.decryptor().update(real_ciphertext) + cipher.decryptor().finalize()
    pad_len = plaintext[-1]
    
    return plaintext[:-pad_len]


# temp unit test, TODO place in proper test file
if __name__ == "__main__":
    pw = input("Enter master password: ")
    priv_key, pub_key = load_identity(pw)
    fingerprint = compute_fingerprint(pub_key)
    print(f"[+] Loaded identity. Fingerprint: {fingerprint}")
    test_str = b"hello world"
    enc_str = aes_cbc_encrypt(derive_master_key(pw), test_str)
    dec_str = aes_cbc_decrypt(derive_master_key(pw), enc_str)
    print(f"Decrypted string matches original: {dec_str == test_str}")
    sig = rsa_pss_sign(priv_key, test_str)
    verified = rsa_pss_verify(pub_key, test_str, sig)
    print(f"Signature valid: {verified}")
