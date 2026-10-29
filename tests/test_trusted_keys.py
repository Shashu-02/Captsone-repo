import json

import ecdsa
import pytest

from backend.trusted_keys import fingerprint, is_trusted, provision_trusted_key


def make_public_pem():
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    return sk.get_verifying_key().to_pem()


def test_unprovisioned_key_is_not_trusted(tmp_path):
    key = make_public_pem()
    assert not is_trusted("alice", key, tmp_path / "trust.json")


def test_provisioned_key_is_trusted(tmp_path):
    path = tmp_path / "trust.json"
    key = make_public_pem()
    provision_trusted_key("alice", key, administrator_confirmed=True, path=path)
    assert is_trusted("alice", key, path)


def test_different_key_is_not_trusted(tmp_path):
    path = tmp_path / "trust.json"
    trusted = make_public_pem()
    attacker = make_public_pem()
    provision_trusted_key("alice", trusted, administrator_confirmed=True, path=path)
    assert not is_trusted("alice", attacker, path)


def test_requires_admin_confirmation(tmp_path):
    with pytest.raises(PermissionError):
        provision_trusted_key(
            "alice", make_public_pem(),
            administrator_confirmed=False,
            path=tmp_path / "trust.json",
        )
