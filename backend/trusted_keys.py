"""Explicit local trust store for sender signing public keys.

Trust-on-first-use is deliberately NOT performed here. An administrator must
provision a sender's public key through a trusted channel. The file is local
runtime state and must not be committed to Git.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

TRUST_STORE = Path(
    os.environ.get(
        "CAPSTONE_TRUST_STORE",
        str(Path(__file__).resolve().parent / "keys" / "trusted_sender_signing_keys.json"),
    )
)


def fingerprint(public_key_pem: bytes | str) -> str:
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    # Canonical fingerprint of the PEM bytes as provisioned.
    return hashlib.sha256(public_key_pem.strip()).hexdigest()


def load_trusted_keys(path: Path = TRUST_STORE) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Trusted-key store must be a JSON object.")
    return data


def is_trusted(username: str, public_key_pem: bytes | str, path: Path = TRUST_STORE) -> bool:
    entries = load_trusted_keys(path)
    entry = entries.get(username)
    if not isinstance(entry, dict) or not isinstance(entry.get("fingerprint"), str):
        return False
    return fingerprint(public_key_pem) == entry["fingerprint"]


def provision_trusted_key(
    username: str,
    public_key_pem: bytes | str,
    *,
    administrator_confirmed: bool,
    path: Path = TRUST_STORE,
) -> str:
    """Provision a key only after an administrator independently verifies it.

    This helper intentionally requires an explicit confirmation flag. It does
    not establish the identity of the person supplying the key by itself.
    """
    if not administrator_confirmed:
        raise PermissionError(
            "A trusted administrator must verify the sender public key out-of-band."
        )
    if not username or not username.strip():
        raise ValueError("username is required")
    if isinstance(public_key_pem, bytes):
        pem_text = public_key_pem.decode("utf-8")
    else:
        pem_text = public_key_pem
    fp = fingerprint(pem_text)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    current = load_trusted_keys(path)
    current[username] = {"fingerprint": fp, "public_key_pem": pem_text}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return fp
