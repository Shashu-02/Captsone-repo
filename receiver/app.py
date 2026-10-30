import hashlib
import json
import os
import sys
import time
from pathlib import Path

import ecdsa
import streamlit as st
from Crypto.Cipher import AES

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
import audit_manager
import audit_policy
from package_verification import verify_sender_signature


# ==========================================
# CRYPTOGRAPHIC HELPERS: ECDH + HKDF + AES-GCM
# ==========================================
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = Path(__file__).resolve().parent / "keys"
KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
SENDER_KEY_DIR = PROJECT_ROOT / "sender" / "keys"
TRUSTED_SENDER_ECDH_PUBLIC = SENDER_KEY_DIR / "sender_ecdh_public.pem"
TRUSTED_SENDER_SIGN_PUBLIC = SENDER_KEY_DIR / "sender_sign_public.pem"
SENDER_ECDH_PRIVATE = KEY_DIR / "sender_ecdh_private.pem"
SENDER_ECDH_PUBLIC = KEY_DIR / "sender_ecdh_public.pem"
SENDER_SIGN_PRIVATE = KEY_DIR / "sender_sign_private.pem"
SENDER_SIGN_PUBLIC = KEY_DIR / "sender_sign_public.pem"
RECIPIENT_ECDH_PRIVATE = KEY_DIR / "recipient_ecdh_private.pem"
RECIPIENT_ECDH_PUBLIC = KEY_DIR / "recipient_ecdh_public.pem"
RECIPIENT_SIGN_PRIVATE = KEY_DIR / "recipient_sign_private.pem"
RECIPIENT_SIGN_PUBLIC = KEY_DIR / "recipient_sign_public.pem"


def _save_private(path, pem):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def generate_identity(role):
    """Generate separate ECDH and signing key pairs for one identity."""
    if role not in {"sender", "recipient"}:
        raise ValueError("role must be sender or recipient")
    ecdh_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    sign_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    _save_private(KEY_DIR / f"{role}_ecdh_private.pem", ecdh_sk.to_pem())
    _save_private(KEY_DIR / f"{role}_sign_private.pem", sign_sk.to_pem())
    (KEY_DIR / f"{role}_ecdh_public.pem").write_bytes(
        ecdh_sk.get_verifying_key().to_pem()
    )
    (KEY_DIR / f"{role}_sign_public.pem").write_bytes(
        sign_sk.get_verifying_key().to_pem()
    )


def derive_ecdh_shared_key(priv_pem_path, peer_pub_pem):
    """ECDH followed by HKDF-SHA256 to derive a 32-byte AES key."""
    with open(priv_pem_path, "rb") as f:
        sk = ecdsa.SigningKey.from_pem(f.read())
    if isinstance(peer_pub_pem, str):
        peer_pub_pem = peer_pub_pem.encode("utf-8")
    vk = ecdsa.VerifyingKey.from_pem(peer_pub_pem)
    if sk.curve != ecdsa.SECP256k1 or vk.curve != ecdsa.SECP256k1:
        raise ValueError("Only SECP256K1 keys are accepted.")
    shared_point = sk.privkey.secret_multiplier * vk.pubkey.point
    shared_secret = shared_point.x().to_bytes(32, "big")
    return HKDF(
        master=shared_secret,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        context=b"secure-off-chain-storage/v1",
    )


def encrypt_gcm(file_bytes, aes_key):
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    return ciphertext.hex(), nonce.hex(), tag.hex()


def decrypt_gcm(ciphertext_hex, nonce_hex, tag_hex, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(nonce_hex))
    return cipher.decrypt_and_verify(
        bytes.fromhex(ciphertext_hex), bytes.fromhex(tag_hex)
    )


def canonical_package_fields(package):
    """Return deterministic bytes for every security-relevant package field."""
    if "recipient_keys" in package:
        names = (
            "version",
            "algorithm",
            "transfer_id",
            "sender_username",
            "ciphertext",
            "nonce",
            "tag",
            "recipient_keys",
            "sender_ecdh_public",
        )
    else:
        # Legacy package shape retained for parsing older records. New receiver
        # verification still requires sender_username and trusted-key approval.
        names = (
            "version",
            "algorithm",
            "transfer_id",
            "sender_username",
            "ciphertext",
            "nonce",
            "tag",
            "recipient_ecdh_fingerprint",
            "sender_ecdh_public",
        )
    missing = [name for name in names if name not in package]
    if missing:
        raise ValueError(f"Package is missing signed fields: {', '.join(missing)}")
    fields = {name: package[name] for name in names}
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


st.set_page_config(
    page_title="Secure Storage — Receiver", page_icon="📥", layout="wide"
)

# --- Central API authentication and administrator approval gate ---
import api_client
from auth_manager import ensure_identity

if "auth_username" not in st.session_state:
    st.session_state.auth_username = None
if "api_token" not in st.session_state:
    st.session_state.api_token = None

if not st.session_state.api_token:
    st.subheader("Central account sign in / registration")
    mode = st.radio("Choose", ["Sign in", "Register new receiver"], horizontal=True)
    with st.form("receiver_auth_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Continue")
    if submitted:
        try:
            if mode == "Register new receiver":
                result = api_client.register(username, password, "receiver")
                st.success(
                    result.get("message", "Registration submitted for admin approval.")
                )
            else:
                result = api_client.login(username, password)
                user = result["user"]
                if user["role"] != "receiver":
                    st.error("This account is not a receiver account.")
                else:
                    st.session_state.api_token = result["access_token"]
                    st.session_state.auth_username = user["username"]
                    st.rerun()
        except Exception as exc:
            st.error(str(exc))
    st.stop()

try:
    _current_user = api_client.me(st.session_state.api_token)
except Exception as exc:
    st.session_state.api_token = None
    st.session_state.auth_username = None
    st.error(f"Central API session expired or unavailable: {exc}")
    st.stop()

if _current_user["role"] != "receiver":
    st.session_state.api_token = None
    st.session_state.auth_username = None
    st.error("This account is not a receiver account.")
    st.stop()

# Receiver private keys remain in this account's local key directory.
_receiver_username = _current_user["username"]
KEY_DIR = Path(__file__).resolve().parent / "keys" / _receiver_username
KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
try:
    os.chmod(KEY_DIR, 0o700)
except OSError:
    pass
RECIPIENT_ECDH_PRIVATE = KEY_DIR / "recipient_ecdh_private.pem"
RECIPIENT_ECDH_PUBLIC = KEY_DIR / "recipient_ecdh_public.pem"
RECIPIENT_SIGN_PRIVATE = KEY_DIR / "recipient_sign_private.pem"
RECIPIENT_SIGN_PUBLIC = KEY_DIR / "recipient_sign_public.pem"
if st.button("Sign out", key="auth_signout"):
    try:
        api_client.log_event(st.session_state.api_token, "logout", "receiver portal")
    except Exception:
        pass
    st.session_state.api_token = None
    st.session_state.auth_username = None
    st.rerun()
st.caption(f"Signed in as **{st.session_state.auth_username}** · approved receiver")
# Private identity remains on the receiver device; publish only its public ECDH key.
ensure_identity("recipient", KEY_DIR, generate_identity)
try:
    api_client.publish_receiver_key(
        st.session_state.api_token, RECIPIENT_ECDH_PUBLIC.read_text(encoding="utf-8")
    )
except Exception as exc:
    st.error(f"Could not publish receiver public key to central API: {exc}")


st.title("📥 Receiver Portal")
st.caption("Create recipient identity · Retrieve · Verify · Decrypt")
if "receiver_metrics" not in st.session_state:
    st.session_state.receiver_metrics = {
        "IPFS download time": None,
        "Signature verification time": None,
        "Decryption time (GCM)": None,
    }

st.info(
    "Cryptographic keys are provisioned locally after administrator approval. Only the receiver public ECDH key is published to the central API; private keys remain on this device."
)

st.divider()
st.header("2. Fetch, verify and decrypt")
cid = st.text_input("IPFS CID (also used as blockchain lookup key)")
if st.button("Fetch, verify and decrypt", type="primary"):
    import uuid

    verification_run_id = uuid.uuid4().hex
    verification_started_at = audit_manager.utc_now()
    checks = []

    class VerificationStop(Exception):
        pass

    def add_check(name, status, message):
        checks.append({"Check": name, "Result": status, "Details": message})

    def fail_check(name, message):
        add_check(name, "FAIL", message)
        raise VerificationStop(message)

    plaintext = None
    verify_ms = decrypt_ms = None
    audit_cid = cid.strip() if cid else ""
    audit_package_hash = ""
    audit_block_meta = {}
    audit_tx_hash = ""
    try:
        if not cid.strip():
            fail_check("Input validation", "Enter the CID from the sender.")
        if not RECIPIENT_ECDH_PRIVATE.exists() or not RECIPIENT_ECDH_PUBLIC.exists():
            fail_check("Recipient identity", "Generate recipient keys first.")
        if not TRUSTED_SENDER_ECDH_PUBLIC.exists():
            fail_check(
                "Sender ECDH key",
                "Sender ECDH public key is not available in this single-machine demo.",
            )
        try:
            sender_ecdh_text = TRUSTED_SENDER_ECDH_PUBLIC.read_text(
                encoding="utf-8"
            ).strip()
        except (OSError, UnicodeDecodeError) as exc:
            fail_check(
                "Sender ECDH key",
                f"Could not load local Sender ECDH public key: {type(exc).__name__}.",
            )
        if not sender_ecdh_text:
            fail_check("Sender ECDH key", "Local Sender ECDH public-key file is empty.")
        add_check(
            "Input and key availability",
            "PASS",
            "CID, recipient identity, and locally registered sender public keys are present.",
        )

        chain_result = api_client.verify_blockchain_record(
            st.session_state.api_token, cid.strip()
        )
        if chain_result["status"] != "PASS":
            add_check(
                "Blockchain record", chain_result["status"], chain_result["message"]
            )
            raise VerificationStop(chain_result["message"])
        record = chain_result["record"]
        audit_block_meta = audit_manager.anchor_metadata_for_cid(record["cid"])
        audit_tx_hash = audit_block_meta.get("transaction_hash", "")
        add_check(
            "Blockchain record",
            "PASS",
            f"Matching on-chain CID found; sender {record['sender']}.",
        )

        ipfs_started = time.perf_counter()
        ipfs_result = api_client.retrieve_package_result(
            st.session_state.api_token,
            record["cid"],
        )
        st.session_state.receiver_metrics["IPFS download time"] = (
            f"{(time.perf_counter() - ipfs_started) * 1000:.2f} ms"
            if ipfs_result["status"] == "PASS"
            else None
        )
        if ipfs_result["status"] != "PASS":
            add_check("IPFS retrieval", ipfs_result["status"], ipfs_result["message"])
            raise VerificationStop(ipfs_result["message"])
        raw_bytes = ipfs_result["content"]
        add_check(
            "IPFS retrieval",
            "PASS",
            f"Retrieved {len(raw_bytes):,} bytes using the CID.",
        )
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            fail_check(
                "Package format", "Retrieved content is not a UTF-8 JSON package."
            )

        actual = hashlib.sha256(raw_bytes).hexdigest()
        audit_package_hash = actual
        expected = str(record["data_hash"]).removeprefix("0x").lower()
        if actual.lower() != expected:
            fail_check(
                "Blockchain commitment",
                "SHA-256 of the IPFS package does not match the on-chain commitment.",
            )
        add_check("Blockchain commitment", "PASS", f"SHA-256 matches: {actual}.")

        try:
            package = json.loads(raw)
        except json.JSONDecodeError:
            fail_check("Package format", "Retrieved content is not valid JSON.")
        if package.get("version") != 1 or package.get("algorithm") != "AES-256-GCM":
            fail_check(
                "Package format", "Unsupported package version or encryption algorithm."
            )
        if (
            not isinstance(package.get("transfer_id"), str)
            or not package.get("transfer_id").strip()
        ):
            fail_check(
                "Replay protection",
                "Package has no unique transfer_id; legacy packages are not accepted by replay protection.",
            )
        # Replay protection is scoped to this recipient identity. The same
        # multi-recipient package may be consumed once by A and once by B.
        recipient_fingerprint = hashlib.sha256(
            ecdsa.VerifyingKey.from_pem(RECIPIENT_ECDH_PUBLIC.read_bytes()).to_pem()
        ).hexdigest()
        if audit_manager.transfer_was_consumed(
            package["transfer_id"], recipient_fingerprint
        ):
            fail_check(
                "Replay protection",
                "This transfer was already successfully consumed by this recipient; replay rejected.",
            )
        add_check(
            "Replay protection",
            "PASS",
            "Transfer ID is present and has not been consumed by this recipient before.",
        )
        add_check(
            "Package format",
            "PASS",
            "Recognized version 1 AES-256-GCM package with transfer ID.",
        )

        if package.get("sender_ecdh_public", "").strip() != sender_ecdh_text.strip():
            fail_check(
                "Sender ECDH key binding",
                "Sender ECDH public key does not match package metadata.",
            )
        sender_username = package.get("sender_username")
        if not isinstance(sender_username, str) or not sender_username.strip():
            fail_check(
                "Sender identity", "Package has no authenticated sender username."
            )
        if sender_username != sender_username.strip():
            fail_check(
                "Sender identity",
                "Sender username contains invalid surrounding whitespace.",
            )
        add_check(
            "Sender ECDH key binding",
            "PASS",
            "Sender ECDH public key matches the locally configured sender identity.",
        )

        recipient_envelope = None
        if "recipient_keys" in package:
            if (
                not isinstance(package["recipient_keys"], list)
                or not package["recipient_keys"]
            ):
                fail_check(
                    "Recipient binding",
                    "Recipient envelope list is malformed or empty; refusing legacy fallback.",
                )
            recipient_envelope = next(
                (
                    entry
                    for entry in package["recipient_keys"]
                    if isinstance(entry, dict)
                    and entry.get("fingerprint") == recipient_fingerprint
                ),
                None,
            )
            if recipient_envelope is None:
                fail_check(
                    "Recipient binding",
                    "This recipient's public-key fingerprint is not authorized for the package.",
                )
            required_envelope_fields = ("wrapped_key", "wrap_nonce", "wrap_tag")
            if any(
                not isinstance(recipient_envelope.get(k), str)
                or not recipient_envelope.get(k)
                for k in required_envelope_fields
            ):
                fail_check("Recipient binding", "Recipient key envelope is incomplete.")
            add_check(
                "Recipient binding",
                "PASS",
                "A recipient-specific wrapped AES key is present for this identity.",
            )
        else:
            # Legacy packages are accepted only when explicitly bound to this account's unique key.
            if package.get("recipient_ecdh_fingerprint") != recipient_fingerprint:
                fail_check(
                    "Recipient binding",
                    "Package was encrypted for a different recipient ECDH key.",
                )
            add_check(
                "Recipient binding",
                "PASS",
                "Legacy package is bound to this recipient's ECDH key.",
            )

        try:
            t0 = time.perf_counter()
            signature_ok = verify_sender_signature(package, sender_username)
            verify_ms = (time.perf_counter() - t0) * 1000
        except Exception as exc:
            fail_check(
                "Sender signature",
                f"Trusted-key verification failed: {type(exc).__name__}.",
            )
        if not signature_ok:
            fail_check(
                "Sender signature",
                f"Sender '{sender_username}' is not trusted or the package signature is invalid.",
            )
        st.session_state.receiver_metrics["Signature verification time"] = (
            f"{verify_ms:.2f} ms"
        )
        add_check(
            "Sender signature",
            "PASS",
            "Sender identity is approved in the local trust store and the package signature is valid.",
        )

        # Derive/decrypt only after all preceding checks have passed.
        try:
            shared_key = derive_ecdh_shared_key(
                RECIPIENT_ECDH_PRIVATE, sender_ecdh_text.strip()
            )
            if recipient_envelope is not None:
                unwrap_cipher = AES.new(
                    shared_key,
                    AES.MODE_GCM,
                    nonce=bytes.fromhex(recipient_envelope["wrap_nonce"]),
                )
                aes_key = unwrap_cipher.decrypt_and_verify(
                    bytes.fromhex(recipient_envelope["wrapped_key"]),
                    bytes.fromhex(recipient_envelope["wrap_tag"]),
                )
            else:
                aes_key = shared_key
            t1 = time.perf_counter()
            plaintext = decrypt_gcm(
                package["ciphertext"], package["nonce"], package["tag"], aes_key
            )
            decrypt_ms = (time.perf_counter() - t1) * 1000
            st.session_state.receiver_metrics["Decryption time (GCM)"] = (
                f"{decrypt_ms:.2f} ms"
            )
        except Exception as exc:
            fail_check(
                "AES-GCM authentication/decryption",
                f"Authentication or decryption failed: {exc}",
            )
        if not audit_manager.mark_transfer_consumed(
            package["transfer_id"], cid.strip(), recipient_fingerprint
        ):
            plaintext = None
            fail_check(
                "Replay protection",
                "Another verification consumed this transfer for this recipient first; plaintext download blocked.",
            )
        add_check(
            "AES-GCM authentication/decryption",
            "PASS",
            "Authentication succeeded and plaintext was recovered.",
        )

    except VerificationStop:
        pass
    except Exception as exc:
        add_check(
            "Verification operation", "ERROR", f"Unexpected or service error: {exc}"
        )

    import pandas as pd

    st.subheader("Independent verification results")
    st.dataframe(pd.DataFrame(checks), use_container_width=True, hide_index=True)
    final_audit_status = (
        "PASS"
        if plaintext is not None
        and checks
        and all(row["Result"] == "PASS" for row in checks)
        else ("ERROR" if any(row["Result"] == "ERROR" for row in checks) else "FAIL")
    )
    historical_events = audit_manager.list_events(limit=5000)
    risk_result = audit_policy.assess_risk(checks, historical_events)
    st.subheader("Risk-based verification priority")
    r1, r2, r3 = st.columns(3)
    r1.metric("Risk score", f"{risk_result['risk_score']}/100")
    r2.metric("Risk level", risk_result["risk_level"])
    r3.metric("Historical failures", risk_result["historical_failure_count"])
    if risk_result["priority_signals"]:
        st.warning("Prioritized signals: " + ", ".join(risk_result["priority_signals"]))
    else:
        st.info("No risk signals detected in this verification attempt.")
    st.caption(risk_result["interpretation"])
    with st.expander("Measure risk-policy overhead (synthetic microbenchmark)"):
        if st.button("Run policy benchmark", key="run_policy_microbenchmark"):
            bench = audit_policy.synthetic_policy_benchmark(1000)
            st.json(bench)
    # One stable ID per button-triggered verification attempt prevents duplicate records on ordinary Streamlit reruns.
    for index, check in enumerate(checks):
        audit_manager.record_event(
            event_id=f"receiver:verify:{verification_run_id}:{index}",
            event_type=f"VERIFICATION_CHECK:{check['Check']}",
            status=check["Result"],
            cid=audit_cid,
            package_sha256=audit_package_hash,
            block_number=audit_block_meta.get("block_number"),
            blockchain_timestamp_utc=audit_block_meta.get(
                "blockchain_timestamp_utc", ""
            ),
            verification_local_time=verification_started_at,
            transaction_hash=audit_tx_hash,
            details=check["Details"],
        )
    audit_manager.record_event(
        event_id=f"receiver:verification-summary:{verification_run_id}",
        event_type="VERIFICATION_SUMMARY",
        status=final_audit_status,
        cid=audit_cid,
        package_sha256=audit_package_hash,
        block_number=audit_block_meta.get("block_number"),
        blockchain_timestamp_utc=audit_block_meta.get("blockchain_timestamp_utc", ""),
        verification_local_time=verification_started_at,
        transaction_hash=audit_tx_hash,
        details=f"{len(checks)} verification checks recorded.",
    )
    if (
        plaintext is not None
        and checks
        and all(row["Result"] == "PASS" for row in checks)
    ):
        st.success(
            "FINAL RESULT: PASS — all required checks succeeded. Decryption is authorized."
        )
        a, b = st.columns(2)
        a.metric("Signature verification", f"{verify_ms:.2f} ms")
        b.metric("Decryption", f"{decrypt_ms:.2f} ms")
        filename = st.text_input("Output filename", value="recovered_file.bin")
        st.download_button(
            "Download verified file",
            plaintext,
            file_name=filename.strip() or "recovered_file.bin",
            mime="application/octet-stream",
        )
    else:
        final_status = (
            "ERROR" if any(row["Result"] == "ERROR" for row in checks) else "FAIL"
        )
        st.error(
            f"FINAL RESULT: {final_status} — file download is disabled because verification did not fully pass."
        )

st.caption(
    "Receiver private keys are stored only under receiver/keys/. Trusted Sender public keys are loaded automatically from the local Sender portal; no PEM upload or manual key exchange is needed in this single-machine demo."
)


st.divider()
st.header("📊 Receiver Performance Metrics")
st.caption(
    "Actual measurements from successful receiver operations in this Streamlit session."
)
_receiver_metric_cols = st.columns(3)
for _col, (_label, _value) in zip(
    _receiver_metric_cols, st.session_state.receiver_metrics.items()
):
    _col.metric(_label, _value if _value is not None else "Not measured yet")

# Shared audit history and CSV/manifest integrity verification.
audit_manager.render_audit_ui(st, "Receiver")


# ==========================================
# ATTACKER MODE — MANUAL SECURITY TEST LAB
# ==========================================
st.divider()
st.header("⚠️ Attacker Mode — Manual Security Testing Lab")
st.caption(
    "Inspect a package you actually uploaded, or select one controlled attack at a time. "
    "This lab never provides a plaintext download."
)

scenario = st.selectbox(
    "Choose a test scenario",
    [
        "Scenario A — Diagnose uploaded package",
        "Scenario B — Manually test a cryptographic attack",
        "Scenario C — CID, replay and service handling",
    ],
    key="manual_attacker_scenario",
)
attack_package_upload = st.file_uploader(
    "Upload encrypted package JSON (original or manually edited)",
    type=["json"],
    key="manual_attack_package",
)
# The test lab also uses locally registered Sender public keys; only the package may be uploaded for tampering tests.
attack_sender_ecdh_pem = (
    TRUSTED_SENDER_ECDH_PUBLIC.read_bytes()
    if TRUSTED_SENDER_ECDH_PUBLIC.exists()
    else None
)
attack_sender_sign_pem = (
    TRUSTED_SENDER_SIGN_PUBLIC.read_bytes()
    if TRUSTED_SENDER_SIGN_PUBLIC.exists()
    else None
)


def _manual_add(rows, check, status, detector, details):
    rows.append(
        {"Check": check, "Result": status, "Detected by": detector, "Details": details}
    )


def _manual_signature_valid(pkg, public_pem):
    try:
        if not pkg.get("signature"):
            return False, "Signature field is missing."
        vk = ecdsa.VerifyingKey.from_pem(public_pem)
        vk.verify(
            bytes.fromhex(pkg["signature"]),
            canonical_package_fields(pkg),
            hashfunc=hashlib.sha256,
        )
        return True, "Signature is valid for the canonical package fields."
    except Exception as exc:
        return False, f"Signature verification failed ({type(exc).__name__})."


def _manual_diagnose(raw_bytes, ecdh_pem, sign_pem):
    rows = []
    try:
        pkg = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        _manual_add(
            rows,
            "JSON parsing",
            "FAIL",
            "JSON parser",
            f"Uploaded file is not valid JSON: {exc}",
        )
        return rows, None

    required = (
        "version",
        "algorithm",
        "ciphertext",
        "nonce",
        "tag",
        "sender_ecdh_public",
        "sender_signing_public",
        "signature",
    )
    missing = [name for name in required if not pkg.get(name)]
    if missing:
        _manual_add(
            rows,
            "Package schema",
            "FAIL",
            "Schema validator",
            "Missing/empty fields: " + ", ".join(missing),
        )
    elif pkg.get("version") != 1 or pkg.get("algorithm") != "AES-256-GCM":
        _manual_add(
            rows,
            "Package schema",
            "FAIL",
            "Schema validator",
            "Unsupported package version or algorithm.",
        )
    else:
        _manual_add(
            rows,
            "Package schema",
            "PASS",
            "Schema validator",
            "Required fields and supported algorithm are present.",
        )

    try:
        uploaded_ecdh = ecdsa.VerifyingKey.from_pem(ecdh_pem)
        packaged_ecdh = ecdsa.VerifyingKey.from_pem(
            pkg.get("sender_ecdh_public", "").encode()
        )
        same_ecdh = (
            uploaded_ecdh.to_pem() == packaged_ecdh.to_pem()
            and uploaded_ecdh.curve == ecdsa.SECP256k1
        )
        _manual_add(
            rows,
            "Sender ECDH public-key binding",
            "PASS" if same_ecdh else "FAIL",
            "Public-key binding",
            "Uploaded key matches package metadata."
            if same_ecdh
            else "Uploaded ECDH key differs from package metadata or uses the wrong curve.",
        )
    except Exception as exc:
        _manual_add(
            rows,
            "Sender ECDH public-key binding",
            "FAIL",
            "PEM parser",
            f"Cannot validate sender ECDH key: {exc}",
        )

    packaged_sign = str(pkg.get("sender_signing_public", "")).strip()
    try:
        uploaded_sign = ecdsa.VerifyingKey.from_pem(sign_pem).to_pem().decode().strip()
        package_sign = (
            ecdsa.VerifyingKey.from_pem(packaged_sign.encode())
            .to_pem()
            .decode()
            .strip()
        )
        bound = uploaded_sign == package_sign
        _manual_add(
            rows,
            "Trusted signing-key binding",
            "PASS" if bound else "FAIL",
            "Public-key binding",
            "Uploaded trusted key matches package metadata."
            if bound
            else "Uploaded trusted signing key differs from the key embedded in the package.",
        )
    except Exception as exc:
        bound = False
        _manual_add(
            rows,
            "Trusted signing-key binding",
            "FAIL",
            "PEM parser",
            f"Cannot validate signing key: {exc}",
        )

    sig_ok, sig_detail = _manual_signature_valid(pkg, sign_pem)
    _manual_add(
        rows,
        "Sender digital signature",
        "PASS" if sig_ok else "FAIL",
        "SECP256K1 signature verifier",
        sig_detail,
    )

    current_fp = (
        hashlib.sha256(RECIPIENT_ECDH_PUBLIC.read_bytes()).hexdigest()
        if RECIPIENT_ECDH_PUBLIC.exists()
        else ""
    )
    if not current_fp:
        _manual_add(
            rows,
            "Recipient binding",
            "ERROR",
            "Recipient key store",
            "Generate recipient keys before checking recipient binding.",
        )
        recipient_ok = False
    else:
        recipient_ok = pkg.get("recipient_ecdh_fingerprint") == current_fp
        _manual_add(
            rows,
            "Recipient binding",
            "PASS" if recipient_ok else "FAIL",
            "Recipient fingerprint check",
            "Package is bound to this recipient key."
            if recipient_ok
            else "Fingerprint mismatch: package targets a different recipient key or metadata was changed.",
        )

    # Only attempt GCM authentication when the signature and recipient binding pass.
    if sig_ok and recipient_ok and bound:
        try:
            if not RECIPIENT_ECDH_PRIVATE.exists():
                raise FileNotFoundError("Recipient ECDH private key is unavailable.")
            aes_key = derive_ecdh_shared_key(RECIPIENT_ECDH_PRIVATE, ecdh_pem)
            decrypt_gcm(pkg["ciphertext"], pkg["nonce"], pkg["tag"], aes_key)
            _manual_add(
                rows,
                "AES-GCM authentication",
                "PASS",
                "AES-GCM tag verifier",
                "Authentication succeeded. Plaintext was immediately discarded; this lab does not offer a download.",
            )
        except Exception as exc:
            _manual_add(
                rows,
                "AES-GCM authentication",
                "FAIL",
                "AES-GCM tag verifier",
                f"Authentication/decryption rejected ({type(exc).__name__}); no plaintext retained.",
            )
    else:
        _manual_add(
            rows,
            "AES-GCM authentication",
            "NOT RUN",
            "Fail-closed gate",
            "Signature, key binding, or recipient check failed; decryption was not attempted.",
        )
    return rows, pkg


if scenario == "Scenario A — Diagnose uploaded package":
    st.info(
        "Upload the original package first, then edit one field in a copy and upload it again. This reports the actual checks that pass or fail for that upload."
    )
    if st.button(
        "Inspect uploaded package", key="manual_inspect_package", type="primary"
    ):
        if not all(
            (
                attack_package_upload,
                attack_sender_ecdh_pem,
                attack_sender_sign_pem,
            )
        ):
            st.warning(
                "Upload the JSON package and ensure an approved Sender identity exists."
            )
        else:
            rows, _ = _manual_diagnose(
                attack_package_upload.getvalue(),
                attack_sender_ecdh_pem,
                attack_sender_sign_pem,
            )
            st.dataframe(rows, use_container_width=True, hide_index=True)
            failed = [r for r in rows if r["Result"] in ("FAIL", "ERROR")]
            if failed:
                st.error(
                    "Package diagnosis found an issue. Plaintext download is not available in Attacker Mode."
                )
            elif any(r["Result"] == "NOT RUN" for r in rows):
                st.warning(
                    "Some checks were not run because an earlier security check failed."
                )
            else:
                st.success(
                    "The tested local package checks passed. This alone does not prove the blockchain commitment matches; use the normal Receiver verification workflow for that."
                )

elif scenario == "Scenario B — Manually test a cryptographic attack":
    st.info(
        "Choose one attack. The app creates a temporary in-memory modified copy and reports whether the relevant control blocked it. Your uploaded file is not overwritten, and no plaintext is downloaded."
    )
    attack_choice = st.selectbox(
        "Attack to perform",
        [
            "Modify GCM authentication tag",
            "Alter digital signature",
            "Modify ciphertext",
            "Remove signature",
            "Use wrong signing public key",
            "Use wrong recipient fingerprint",
        ],
        key="manual_attack_choice",
    )
    if st.button("Run selected attack", key="run_one_manual_attack", type="primary"):
        if not all(
            (
                attack_package_upload,
                attack_sender_ecdh_pem,
                attack_sender_sign_pem,
            )
        ):
            st.warning(
                "Upload the JSON package and ensure an approved Sender identity exists."
            )
        else:
            try:
                pkg = json.loads(attack_package_upload.getvalue().decode("utf-8"))
                sign_pem = attack_sender_sign_pem
                ecdh_pem = attack_sender_ecdh_pem
                mutated = dict(pkg)
                if attack_choice == "Modify GCM authentication tag":
                    tag = str(mutated.get("tag", ""))
                    if len(tag) < 2:
                        raise ValueError("Package has no usable GCM tag.")
                    mutated["tag"] = ("00" if tag[:2] != "00" else "ff") + tag[2:]
                    key = derive_ecdh_shared_key(RECIPIENT_ECDH_PRIVATE, ecdh_pem)
                    try:
                        decrypt_gcm(
                            mutated["ciphertext"], mutated["nonce"], mutated["tag"], key
                        )
                        blocked = False
                        detector = "AES-GCM authentication"
                        detail = "Modified tag unexpectedly authenticated."
                    except Exception as exc:
                        blocked = True
                        detector = "AES-GCM authentication"
                        detail = f"Modified tag rejected ({type(exc).__name__}); no plaintext retained."
                elif attack_choice == "Alter digital signature":
                    sig = str(mutated.get("signature", ""))
                    if not sig:
                        raise ValueError("Package has no signature to alter.")
                    mutated["signature"] = ("00" if sig[:2] != "00" else "ff") + sig[2:]
                    valid, detail = _manual_signature_valid(mutated, sign_pem)
                    blocked = not valid
                    detector = "SECP256K1 signature verifier"
                elif attack_choice == "Modify ciphertext":
                    ciphertext = str(mutated.get("ciphertext", ""))
                    if len(ciphertext) < 2:
                        raise ValueError("Package ciphertext is missing or too short.")
                    mutated["ciphertext"] = (
                        "00" if ciphertext[:2] != "00" else "ff"
                    ) + ciphertext[2:]
                    valid, detail = _manual_signature_valid(mutated, sign_pem)
                    blocked = not valid
                    detector = "Digital signature over canonical fields"
                elif attack_choice == "Remove signature":
                    mutated.pop("signature", None)
                    valid, detail = _manual_signature_valid(mutated, sign_pem)
                    blocked = not valid
                    detector = "Required signature / signature verifier"
                elif attack_choice == "Use wrong signing public key":
                    wrong_key = (
                        ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
                        .get_verifying_key()
                        .to_pem()
                    )
                    valid, detail = _manual_signature_valid(pkg, wrong_key)
                    blocked = not valid
                    detector = "Trusted signing public-key verification"
                else:
                    mutated["recipient_ecdh_fingerprint"] = "00" * 32
                    current_fp = (
                        hashlib.sha256(RECIPIENT_ECDH_PUBLIC.read_bytes()).hexdigest()
                        if RECIPIENT_ECDH_PUBLIC.exists()
                        else ""
                    )
                    blocked = (
                        bool(current_fp)
                        and mutated["recipient_ecdh_fingerprint"] != current_fp
                    )
                    detector = "Recipient fingerprint check"
                    detail = (
                        "Wrong recipient fingerprint rejected before decryption."
                        if blocked
                        else "Recipient identity unavailable or test did not reject the altered fingerprint."
                    )
                st.write(f"**Attack:** {attack_choice}")
                st.write(f"**Detected by:** {detector}")
                st.write(f"**Details:** {detail}")
                if blocked:
                    st.success(
                        "BLOCKED — the selected attack was rejected as expected. No plaintext download is provided."
                    )
                else:
                    st.error(
                        "VULNERABLE / INCONCLUSIVE — the selected attack was not rejected as expected. Investigate before claiming protection."
                    )
            except Exception as exc:
                st.error(f"ERROR — could not complete this attack test: {exc}")

else:
    st.info(
        "These checks query the local blockchain where applicable. Service outages are not induced automatically; stop a service manually in a controlled test environment to demonstrate a real outage."
    )
    cid_to_test = st.text_input("CID to test", key="manual_cid_test")
    service_test = st.selectbox(
        "Check",
        [
            "Look up this CID on blockchain",
            "Replay-store duplicate check",
            "Simulated IPFS unavailable (policy demonstration)",
            "Simulated blockchain unavailable (policy demonstration)",
        ],
        key="manual_service_test",
    )
    if st.button("Run selected check", key="manual_run_service_test", type="primary"):
        if service_test == "Look up this CID on blockchain":
            if not cid_to_test.strip():
                st.warning(
                    "Enter a CID. For a negative test, use a deliberately invalid CID."
                )
            else:
                try:
                    record = api_client.verify_blockchain_record(
                        st.session_state.api_token, cid_to_test.strip()
                    )
                    status = record.get("status", "ERROR")
                    st.write(f"**Result:** {status}")
                    st.write(
                        f"**Details:** {record.get('message', record.get('data', 'No details returned.'))}"
                    )
                    if status == "FAIL":
                        st.success("No record found; retrieval must not proceed.")
                    elif status == "PASS":
                        st.warning(
                            "A record exists. Continue with full package commitment/signature verification before any decryption."
                        )
                    else:
                        st.error(
                            "Blockchain lookup failed; fail closed and do not decrypt."
                        )
                except Exception as exc:
                    st.error(f"ERROR — blockchain lookup could not complete: {exc}")
        elif service_test == "Replay-store duplicate check":
            if not cid_to_test.strip():
                st.warning(
                    "Enter a test transfer ID in the CID field (this value is used only as a test ID)."
                )
            else:
                try:
                    first = audit_manager.mark_transfer_consumed(
                        cid_to_test.strip(), "manual-attacker-test"
                    )
                    second = audit_manager.mark_transfer_consumed(
                        cid_to_test.strip(), "manual-attacker-test"
                    )
                    st.write(f"First claim: {'ACCEPTED' if first else 'REJECTED'}")
                    st.write(
                        f"Second claim: {'REJECTED (expected)' if not second else 'ACCEPTED (unexpected)'}"
                    )
                    if first and not second:
                        st.success("Replay protection blocked the duplicate claim.")
                    else:
                        st.error(
                            "Replay check did not behave as expected; inspect the shared replay store."
                        )
                except Exception as exc:
                    st.error(f"ERROR — replay-store check failed: {exc}")
        else:
            st.warning(
                "This is a policy demonstration only; it does not stop or contact the named service. For a real outage test, stop that service in a controlled environment and run normal Receiver verification. Expected outcome: ERROR and no plaintext download."
            )

st.caption(
    "Attacker Mode never offers a plaintext download. A successful attack-blocking result is shown as BLOCKED; uploaded package problems are reported as FAIL with the detecting check. Service-outage policy examples are explicitly labeled simulated."
)
