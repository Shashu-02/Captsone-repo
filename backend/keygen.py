import os
import ecdsa

def generate_secp256k1_keys():
    """Generates SECP256K1 private and public keys and saves them locally."""
    # Generate the private signing key
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    
    # Generate the public verifying key
    vk = sk.get_verifying_key()
    
    # Save the private key to a local file
    with open("private_key.pem", "wb") as f:
        f.write(sk.to_pem())
        
    # Save the public key to a local file
    with open("public_key.pem", "wb") as f:
        f.write(vk.to_pem())

def generate_aes_key():
    """Generates a 256-bit (32-byte) AES key and saves it to a local file."""
    # Generate 32 random bytes for AES-256
    aes_key = os.urandom(32)
    
    # Save it locally so the Receiver tab can access it later
    with open("aes_key.bin", "wb") as f:
        f.write(aes_key)
        
    return aes_key