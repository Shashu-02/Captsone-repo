#!/usr/bin/env python3
"""Offline adversarial security tests for the Secure Storage capstone.

Run from the repository root:
    source .venv/bin/activate
    python tests/test_adversarial_security.py

The suite creates temporary cryptographic identities, a temporary trust store,
and a temporary replay database. It does not contact IPFS/Hardhat or modify
project keys, the production trust store, or the production audit database.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import ecdsa
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend import audit_manager
from backend.package_verification import (
    canonical_package_fields,
    verify_sender_signature,
)

CONTEXT = b"secure-off-chain-storage/v1"
SENDER_NAME = "AdversarialTestSender"


def derive_wrap_key(
    private_key: ecdsa.SigningKey, peer_public: ecdsa.VerifyingKey
) -> bytes:
    if private_key.curve != ecdsa.SECP256k1 or peer_public.curve != ecdsa.SECP256k1:
        raise ValueError("Only SECP256K1 keys are accepted.")
    point = private_key.privkey.secret_multiplier * peer_public.pubkey.point
    secret = point.x().to_bytes(32, "big")
    return HKDF(
        master=secret,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        context=CONTEXT,
    )


def public_fingerprint(public_key: ecdsa.VerifyingKey) -> str:
    return hashlib.sha256(public_key.to_pem()).hexdigest()


def encrypt_payload(data: bytes, key: bytes):
    nonce = __import__("os").urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext.hex(), nonce.hex(), tag.hex()


def make_package(
    sender_ecdh: ecdsa.SigningKey,
    sender_sign: ecdsa.SigningKey,
    recipients: list[tuple[str, ecdsa.VerifyingKey]],
    plaintext: bytes,
) -> tuple[dict, bytes]:
    aes_key = __import__("os").urandom(32)
    ciphertext, nonce, tag = encrypt_payload(plaintext, aes_key)
    envelopes = []
    for _name, recipient_public in recipients:
        wrap_key = derive_wrap_key(sender_ecdh, recipient_public)
        wrap_nonce = __import__("os").urandom(12)
        cipher = AES.new(wrap_key, AES.MODE_GCM, nonce=wrap_nonce)
        wrapped_key, wrap_tag = cipher.encrypt_and_digest(aes_key)
        envelopes.append(
            {
                "fingerprint": public_fingerprint(recipient_public),
                "wrapped_key": wrapped_key.hex(),
                "wrap_nonce": wrap_nonce.hex(),
                "wrap_tag": wrap_tag.hex(),
            }
        )

    package = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "transfer_id": "adversarial-" + __import__("uuid").uuid4().hex,
        "sender_username": SENDER_NAME,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag,
        "recipient_keys": envelopes,
        "sender_ecdh_public": sender_ecdh.get_verifying_key().to_pem().decode("utf-8"),
        "original_filename": "adversarial-test.txt",
    }
    signature = sender_sign.sign(
        canonical_package_fields(package), hashfunc=hashlib.sha256
    )
    package["signature"] = signature.hex()
    package["sender_signing_public"] = (
        sender_sign.get_verifying_key().to_pem().decode("utf-8")
    )
    return package, aes_key


class AdversarialSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="capstone-adversarial-")
        self.temp_path = Path(self.temp.name)
        self.trust_store = self.temp_path / "trusted_senders.json"
        self.replay_db = self.temp_path / "audit_replay.sqlite3"

        self.sender_ecdh = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.sender_sign = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.recipient_a = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.recipient_b = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.outsider = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

        self.plaintext = b"Confidential capstone adversarial test payload."
        self.package, self.aes_key = make_package(
            self.sender_ecdh,
            self.sender_sign,
            [
                ("RecipientA", self.recipient_a.get_verifying_key()),
                ("RecipientB", self.recipient_b.get_verifying_key()),
            ],
            self.plaintext,
        )
        # Build an isolated test fixture directly. Production trust-store writes
        # are intentionally disabled; this temporary file is only consumed by
        # verify_sender_signature(trusted_store=...) and never touches Admin API
        # state or the real trusted-sender registry.
        sender_public_pem = (
            self.sender_sign.get_verifying_key().to_pem().decode("utf-8")
        )
        sender_fingerprint = hashlib.sha256(
            sender_public_pem.encode("utf-8").strip()
        ).hexdigest()
        self.trust_store.write_text(
            json.dumps(
                {
                    SENDER_NAME: {
                        "fingerprint": sender_fingerprint,
                        "public_key_pem": sender_public_pem,
                    }
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def verify(self, package):
        return verify_sender_signature(
            package, SENDER_NAME, trusted_store=self.trust_store
        )

    def envelope_for(self, package, public_key):
        fp = public_fingerprint(public_key)
        return next(
            (
                entry
                for entry in package["recipient_keys"]
                if entry.get("fingerprint") == fp
            ),
            None,
        )

    def unwrap(self, recipient_private, envelope):
        sender_public = ecdsa.VerifyingKey.from_pem(
            self.package["sender_ecdh_public"].encode("utf-8")
        )
        wrap_key = derive_wrap_key(recipient_private, sender_public)
        cipher = AES.new(
            wrap_key,
            AES.MODE_GCM,
            nonce=bytes.fromhex(envelope["wrap_nonce"]),
        )
        return cipher.decrypt_and_verify(
            bytes.fromhex(envelope["wrapped_key"]),
            bytes.fromhex(envelope["wrap_tag"]),
        )

    def test_01_ciphertext_tampering_is_detected(self):
        self.assertTrue(
            self.verify(self.package), "positive control: original signature"
        )
        tampered = json.loads(json.dumps(self.package))
        raw = bytearray.fromhex(tampered["ciphertext"])
        raw[0] ^= 0x01
        tampered["ciphertext"] = raw.hex()
        self.assertFalse(
            self.verify(tampered), "modified ciphertext must invalidate signature"
        )

        # Also verify AES-GCM rejects altered ciphertext even if the caller
        # reaches the payload-authentication layer.
        cipher = AES.new(
            self.aes_key, AES.MODE_GCM, nonce=bytes.fromhex(self.package["nonce"])
        )
        with self.assertRaises(ValueError):
            cipher.decrypt_and_verify(bytes(raw), bytes.fromhex(self.package["tag"]))

    def test_02_invalid_signature_is_rejected(self):
        self.assertTrue(self.verify(self.package), "positive control: valid signature")
        tampered = json.loads(json.dumps(self.package))
        signature = bytearray.fromhex(tampered["signature"])
        signature[0] ^= 0x01
        tampered["signature"] = signature.hex()
        self.assertFalse(self.verify(tampered))

    def test_03_wrong_recipient_cannot_unwrap_another_envelope(self):
        envelope_a = self.envelope_for(
            self.package, self.recipient_a.get_verifying_key()
        )
        self.assertIsNotNone(envelope_a)
        outsider_fp = public_fingerprint(self.outsider.get_verifying_key())
        self.assertNotIn(
            outsider_fp,
            [item["fingerprint"] for item in self.package["recipient_keys"]],
        )
        with self.assertRaises(ValueError):
            self.unwrap(self.outsider, envelope_a)

    def test_04_replay_is_rejected_per_recipient_without_touching_real_db(self):
        original_db = audit_manager.DB_PATH
        audit_manager.DB_PATH = self.replay_db
        try:
            transfer_id = self.package["transfer_id"]
            fp_a = public_fingerprint(self.recipient_a.get_verifying_key())
            fp_b = public_fingerprint(self.recipient_b.get_verifying_key())

            self.assertFalse(audit_manager.transfer_was_consumed(transfer_id, fp_a))
            self.assertTrue(
                audit_manager.mark_transfer_consumed(transfer_id, "test-cid", fp_a)
            )
            self.assertTrue(audit_manager.transfer_was_consumed(transfer_id, fp_a))
            self.assertFalse(
                audit_manager.mark_transfer_consumed(transfer_id, "test-cid", fp_a),
                "second consumption by same recipient must fail",
            )

            # Multi-recipient semantics: another authorized recipient may
            # consume this same transfer once under its own fingerprint.
            self.assertFalse(audit_manager.transfer_was_consumed(transfer_id, fp_b))
            self.assertTrue(
                audit_manager.mark_transfer_consumed(transfer_id, "test-cid", fp_b)
            )
            self.assertFalse(
                audit_manager.mark_transfer_consumed(transfer_id, "test-cid", fp_b)
            )
        finally:
            audit_manager.DB_PATH = original_db

    def test_05_untrusted_sender_key_is_rejected(self):
        attacker_sign = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        forged, _ = make_package(
            self.sender_ecdh,
            attacker_sign,
            [
                ("RecipientA", self.recipient_a.get_verifying_key()),
                ("RecipientB", self.recipient_b.get_verifying_key()),
            ],
            self.plaintext,
        )
        # The attacker has a mathematically valid signature, but the signing
        # key is not the administrator-provisioned key for SENDER_NAME.
        self.assertFalse(self.verify(forged))

    def test_06_valid_recipients_can_unwrap_their_own_envelopes(self):
        envelope_a = self.envelope_for(
            self.package, self.recipient_a.get_verifying_key()
        )
        envelope_b = self.envelope_for(
            self.package, self.recipient_b.get_verifying_key()
        )
        self.assertEqual(self.unwrap(self.recipient_a, envelope_a), self.aes_key)
        self.assertEqual(self.unwrap(self.recipient_b, envelope_b), self.aes_key)

    def test_07_recipient_metadata_tampering_invalidates_signature(self):
        tampered = json.loads(json.dumps(self.package))
        tampered["recipient_keys"][0]["fingerprint"] = "0" * 64
        self.assertFalse(self.verify(tampered))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(AdversarialSecurityTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
