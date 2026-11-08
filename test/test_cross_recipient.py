#!/usr/bin/env python3
"""Read-only AES-GCM recipient-envelope isolation test for the capstone project."""

import argparse
import hashlib
import json
from pathlib import Path

import ecdsa
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


def fingerprint(public_key_path):
    vk = ecdsa.VerifyingKey.from_pem(public_key_path.read_bytes())
    if vk.curve != ecdsa.SECP256k1:
        raise ValueError(f"Unsupported public-key curve: {public_key_path}")
    return hashlib.sha256(vk.to_pem()).hexdigest()


def unwrap(private_key_path, sender_public_pem, envelope):
    sk = ecdsa.SigningKey.from_pem(private_key_path.read_bytes())
    vk = ecdsa.VerifyingKey.from_pem(sender_public_pem.encode("utf-8"))
    if sk.curve != ecdsa.SECP256k1 or vk.curve != ecdsa.SECP256k1:
        raise ValueError("Only SECP256K1 keys are supported")
    shared_point = sk.privkey.secret_multiplier * vk.pubkey.point
    secret = shared_point.x().to_bytes(32, "big")
    key = HKDF(
        master=secret,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        context=b"secure-off-chain-storage/v1",
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(envelope["wrap_nonce"]))
    return cipher.decrypt_and_verify(
        bytes.fromhex(envelope["wrapped_key"]), bytes.fromhex(envelope["wrap_tag"])
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="Downloaded IPFS JSON package")
    parser.add_argument("--keys", type=Path, default=Path("receiver/keys"))
    args = parser.parse_args()
    package = json.loads(args.package.expanduser().read_text(encoding="utf-8"))
    envelopes = package.get("recipient_keys")
    if not isinstance(envelopes, list) or len(envelopes) < 2:
        parser.error("Package must contain at least two recipient envelopes")
    sender_public = package.get("sender_ecdh_public")
    if not isinstance(sender_public, str) or not sender_public.strip():
        parser.error("Package lacks sender_ecdh_public")

    identities = {}
    for directory in sorted(args.keys.iterdir()):
        if not directory.is_dir():
            continue
        pub = directory / "recipient_ecdh_public.pem"
        priv = directory / "recipient_ecdh_private.pem"
        if pub.is_file() and priv.is_file():
            identities[directory.name] = (fingerprint(pub), priv)

    print("Transfer:", package.get("transfer_id", "unknown"))
    print("Package envelopes:", len(envelopes))
    print("Local identities:", ", ".join(identities) or "none")
    matched = {}
    for idx, envelope in enumerate(envelopes, start=1):
        fp = envelope.get("fingerprint")
        names = [name for name, (local_fp, _) in identities.items() if local_fp == fp]
        print(
            f"Envelope {idx}: {str(fp)[:16]}... => {', '.join(names) if names else 'NO LOCAL KEY MATCH'}"
        )
        if len(names) == 1:
            matched[idx] = (names[0], envelope)

    if len(matched) != len(envelopes):
        print("\nINCOMPLETE: Some envelopes do not match a unique local identity.")
        print(
            "Use the package generated for the current receiver keys, or locate the correct keys."
        )
        return 2

    passed = 0
    failed = 0
    for identity_idx, (name, _) in matched.items():
        priv = identities[name][1]
        for envelope_idx, (_, envelope) in matched.items():
            expected_success = identity_idx == envelope_idx
            try:
                aes_key = unwrap(priv, sender_public, envelope)
                actual_success = len(aes_key) == 32
                reason = (
                    "unwrapped 32-byte AES key"
                    if actual_success
                    else "unexpected AES key length"
                )
            except (ValueError, KeyError) as exc:
                actual_success = False
                reason = type(exc).__name__
            ok = actual_success == expected_success
            passed += int(ok)
            failed += int(not ok)
            label = "OWN ENVELOPE" if expected_success else "CROSS ENVELOPE"
            print(
                f"{'PASS' if ok else 'FAIL'} | {name} | {label} {envelope_idx} | {reason}"
            )

    print(f"\nResult: {passed} passed, {failed} failed")
    print(
        "This checks AES key-envelope isolation only; it does not re-test API authorization or signatures."
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
