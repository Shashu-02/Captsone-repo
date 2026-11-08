"""Central trusted-sender registry backed by the authentication SQLite database.

The legacy JSON path is retained only for one-time migration and explicit
backward-compatible test calls. Production verification uses SQLite.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

try:
    from . import auth_manager
except ImportError:
    import auth_manager

TRUST_STORE = Path(os.environ.get(
    "CAPSTONE_TRUST_STORE",
    str(Path(__file__).resolve().parent / "keys" / "trusted_sender_signing_keys.json"),
))


def fingerprint(public_key_pem: bytes | str) -> str:
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    return hashlib.sha256(raw.strip()).hexdigest()


def validate_signing_public_key(public_key_pem: bytes | str) -> tuple[str, str]:
    raw = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
    try:
        key = serialization.load_pem_public_key(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("The uploaded file is not a valid PEM public key.") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("The sender signing key must be an elliptic-curve public key.")
    if key.curve.name != "secp256k1":
        raise ValueError(f"Expected a SECP256K1 signing key; received {key.curve.name}.")
    return raw.decode("utf-8"), fingerprint(raw)


def load_trusted_keys(path: Path | None = None) -> dict[str, dict[str, str]]:
    """Return registry entries; default source is the central SQLite database."""
    if path is not None:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Trusted-key store must be a JSON object.")
        return data
    auth_manager.initialize()
    with auth_manager._connect() as con:
        rows = con.execute(
            "SELECT username,public_key_pem,fingerprint FROM trusted_sender_keys"
        ).fetchall()
    return {r["username"]: {"public_key_pem": r["public_key_pem"],
                            "fingerprint": r["fingerprint"]} for r in rows}


def is_trusted(username: str, public_key_pem: bytes | str, path: Path | None = None) -> bool:
    fp = fingerprint(public_key_pem)
    if path is not None:
        entry = load_trusted_keys(path).get(username)
        return bool(isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str)
                    and hmac.compare_digest(fp, entry["fingerprint"]))
    return auth_manager.is_trusted_sender_key(username, fp)


def provision_trusted_key(username: str, public_key_pem: bytes | str, *,
                          administrator_confirmed: bool, admin_username: str = "legacy-admin",
                          path: Path | None = None) -> str:
    """Compatibility helper; production callers should use the authenticated Admin API."""
    if not administrator_confirmed:
        raise PermissionError("A trusted administrator must verify the sender public key out-of-band.")
    if path is not None:
        raise ValueError("Direct JSON trust-store writes are disabled; use the Admin API.")
    pem, fp = validate_signing_public_key(public_key_pem)
    auth_manager.register_trusted_sender_key(username, pem, fp, admin_username)
    return fp
