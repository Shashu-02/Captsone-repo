import os

import ecdsa
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


def derive_ecdh_shared_key(private_key_path, peer_public_pem):
    """Derive a 256-bit AES key from local private + peer public key."""
    with open(private_key_path, "rb") as f:
        local_private = ecdsa.SigningKey.from_pem(f.read())

    if local_private.curve != ecdsa.SECP256k1:
        raise ValueError("Unexpected local key curve.")

    if isinstance(peer_public_pem, str):
        peer_public_pem = peer_public_pem.encode("utf-8")

    peer_public = ecdsa.VerifyingKey.from_pem(peer_public_pem)

    if peer_public.curve != ecdsa.SECP256k1:
        raise ValueError("Unexpected peer key curve.")

    shared_point = local_private.privkey.secret_multiplier * peer_public.pubkey.point
    shared_secret = shared_point.x().to_bytes(32, "big")

    return HKDF(
        master=shared_secret,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        context=b"secure-off-chain-storage/v1",
    )


def encrypt_gcm(file_data: bytes, aes_key: bytes) -> dict:
    if len(aes_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)

    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
    }


def decrypt_gcm(package: dict, aes_key: bytes) -> bytes:
    if len(aes_key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")

    cipher = AES.new(
        aes_key,
        AES.MODE_GCM,
        nonce=bytes.fromhex(package["nonce"]),
    )
    return cipher.decrypt_and_verify(
        bytes.fromhex(package["ciphertext"]),
        bytes.fromhex(package["tag"]),
    )
