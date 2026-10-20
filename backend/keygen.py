import os
from pathlib import Path

import ecdsa

KEY_DIR = Path(__file__).resolve().parent / "keys"


def generate_identity(role: str):
    """Generate a SECP256K1 identity for ECDH and signing."""
    if role not in {"sender", "recipient"}:
        raise ValueError("Role must be sender or recipient.")

    KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_path = KEY_DIR / f"{role}_private.pem"
    public_path = KEY_DIR / f"{role}_public.pem"

    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()

    # Restrict access to the private key file.
    fd = os.open(
        private_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(fd, "wb") as f:
        f.write(sk.to_pem())

    public_path.write_bytes(vk.to_pem())
    public_path.chmod(0o644)

    return private_path, public_path
