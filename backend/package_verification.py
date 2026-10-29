"""Shared, fail-closed verification helpers for transfer packages."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import ecdsa

from trusted_keys import is_trusted


def canonical_package_fields(package: dict) -> bytes:
    if "recipient_keys" in package:
        names = (
            "version", "algorithm", "transfer_id", "ciphertext", "nonce",
            "tag", "recipient_keys", "sender_ecdh_public",
        )
    else:
        names = (
            "version", "algorithm", "transfer_id", "ciphertext", "nonce",
            "tag", "recipient_ecdh_fingerprint", "sender_ecdh_public",
        )
    missing = [name for name in names if name not in package]
    if missing:
        raise ValueError(f"Package is missing signed fields: {', '.join(missing)}")
    fields = {name: package[name] for name in names}
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_sender_signature(
    package: dict,
    username: str,
    trusted_store: Path | None = None,
) -> bool:
    """Return False unless public key is trusted and signature is valid."""
    try:
        public_pem = package["sender_signing_public"]
        signature = bytes.fromhex(package["signature"])
        if trusted_store is None:
            trusted = is_trusted(username, public_pem)
        else:
            trusted = is_trusted(username, public_pem, trusted_store)
        if not trusted:
            return False
        vk = ecdsa.VerifyingKey.from_pem(public_pem.encode("utf-8") if isinstance(public_pem, str) else public_pem)
        canonical = canonical_package_fields(package)
        return vk.verify(signature, canonical, hashfunc=hashlib.sha256)
    except (KeyError, ValueError, TypeError, ecdsa.BadSignatureError):
        return False
