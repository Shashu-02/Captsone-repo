from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import ecdsa
import hashlib
import os

def encrypt_and_sign(file_data: bytes, aes_key: bytes):
    """Encrypts data with AES-256 and signs it with SECP256K1."""
    # 1. Encrypt with AES-CBC
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
    
    encrypted_hex = encrypted_data.hex()
    iv_hex = iv.hex()
    
    # 2. Sign with SECP256K1 Private Key (Assuming saved as private_key.pem)
    with open("private_key.pem", "rb") as f:
        sk = ecdsa.SigningKey.from_pem(f.read())
        
    signature = sk.sign(encrypted_data, hashfunc=hashlib.sha256)
    signature_hex = signature.hex()
    
    return encrypted_hex, iv_hex, signature_hex


def decrypt_and_verify(encrypted_hex: str, iv_hex: str, signature_hex: str, aes_key: bytes):
    """Verifies the SECP256K1 signature and decrypts the AES-256 data."""
    encrypted_data = bytes.fromhex(encrypted_hex)
    iv = bytes.fromhex(iv_hex)
    signature = bytes.fromhex(signature_hex)
    
    # 1. Verify Signature using Public Key
    with open("public_key.pem", "rb") as f:
        vk = ecdsa.VerifyingKey.from_pem(f.read())
        
    try:
        vk.verify(signature, encrypted_data, hashfunc=hashlib.sha256)
    except ecdsa.BadSignatureError:
        return None # Signature failed
        
    # 2. Decrypt with AES-CBC
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    
    return decrypted_data