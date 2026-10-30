import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

import ecdsa
import streamlit as st
from Crypto.Cipher import AES

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
import audit_manager


# ==========================================
# CRYPTOGRAPHIC HELPERS: ECDH + HKDF + AES-GCM
# ==========================================
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = Path(__file__).resolve().parent / "keys"
KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
RECEIVER_KEY_DIR = PROJECT_ROOT / "receiver" / "keys"
RECEIVER_ECDH_PUBLIC = RECEIVER_KEY_DIR / "recipient_ecdh_public.pem"
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


st.set_page_config(page_title="Secure Storage — Sender", page_icon="📤", layout="wide")

# --- Central API authentication and administrator approval gate ---
import api_client
from auth_manager import ensure_identity

if "auth_username" not in st.session_state:
    st.session_state.auth_username = None
if "api_token" not in st.session_state:
    st.session_state.api_token = None

if not st.session_state.api_token:
    st.subheader("Central account sign in / registration")
    mode = st.radio("Choose", ["Sign in", "Register new sender"], horizontal=True)
    with st.form("sender_auth_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Continue")
    if submitted:
        try:
            if mode == "Register new sender":
                result = api_client.register(username, password, "sender")
                st.success(
                    result.get("message", "Registration submitted for admin approval.")
                )
            else:
                result = api_client.login(username, password)
                user = result["user"]
                if user["role"] != "sender":
                    st.error("This account is not a sender account.")
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

if _current_user["role"] != "sender":
    st.session_state.api_token = None
    st.session_state.auth_username = None
    st.error("This account is not a sender account.")
    st.stop()

if st.button("Sign out", key="auth_signout"):
    try:
        api_client.log_event(st.session_state.api_token, "logout", "sender portal")
    except Exception:
        pass
    st.session_state.api_token = None
    st.session_state.auth_username = None
    st.rerun()
st.caption(f"Signed in as **{st.session_state.auth_username}** · approved sender")
# Private signing and ECDH keys remain on this sender device.
ensure_identity("sender", KEY_DIR, generate_identity)


st.title("📤 Sender Portal")
st.caption(
    "Encrypt for recipient · Sign · Store encrypted package on IPFS · Anchor its hash on Ethereum"
)
st.info(
    "Choose approved recipients from the dropdown. Receiver public keys are discovered automatically; private keys never leave their owner’s device."
)

if "payload_to_store" not in st.session_state:
    st.session_state.payload_to_store = None
if "last_cid" not in st.session_state:
    st.session_state.last_cid = ""
if "last_hash" not in st.session_state:
    st.session_state.last_hash = ""
if "last_tx" not in st.session_state:
    st.session_state.last_tx = ""
if "last_filename" not in st.session_state:
    st.session_state.last_filename = "encrypted_package.json"
if "sender_metrics" not in st.session_state:
    st.session_state.sender_metrics = {
        "Original file size": None,
        "Encrypted payload size": None,
        "IPFS package size": None,
        "Encryption time (GCM)": None,
        "SECP256K1 signing time": None,
        "IPFS upload time": None,
        "Blockchain confirmation time": None,
        "Gas used per anchor": None,
        "Blockchain transaction cost (ETH)": None,
    }

st.info(
    "Cryptographic keys are provisioned automatically after administrator approval and are not replaced on login."
)

if SENDER_ECDH_PUBLIC.exists() and SENDER_SIGN_PUBLIC.exists():
    st.success(
        "Sender identity is ready. Public keys are registered locally; no key export is required."
    )
else:
    st.warning(
        "Sender identity is not available. Sign in after administrator approval to provision keys."
    )

st.divider()
st.header("2. Encrypt and sign a file")
# Discover approved recipients through the central API.
try:
    recipient_registry = api_client.list_receivers(st.session_state.api_token)
except Exception as exc:
    recipient_registry = []
    st.error(f"Could not load approved receivers from central API: {exc}")
recipient_by_label = {
    f"{row['username']} · {row['fingerprint'][:10]}": row for row in recipient_registry
}
if not recipient_by_label:
    st.warning(
        "No approved Receiver public keys are registered yet. Open each approved Receiver portal once so it can publish its public key."
    )
selected_recipient_labels = st.multiselect(
    "Select recipient(s)",
    options=list(recipient_by_label.keys()),
    default=[],
    help="Choose one receiver for private delivery or multiple receivers for group delivery. Only approved receivers with registered public keys appear here.",
    key="selected_recipients",
)
recipient_public_keys = []
for label in selected_recipient_labels:
    row = recipient_by_label[label]
    recipient_public_keys.append(
        (row["username"], row["ecdh_public_pem"].encode("utf-8"))
    )
if recipient_public_keys:
    st.caption(
        f"Selected {len(recipient_public_keys)} recipient(s): "
        + ", ".join(label.split(" · ")[0] for label in selected_recipient_labels)
    )
uploaded_file = st.file_uploader(
    "Choose a file to secure",
    type=["txt", "csv", "json", "pdf", "png", "jpg", "jpeg", "bin"],
    key="sender_file_upload",
)
if st.button("Encrypt for recipient and sign", type="primary"):
    try:
        if not all(
            p.exists()
            for p in [
                SENDER_ECDH_PRIVATE,
                SENDER_ECDH_PUBLIC,
                SENDER_SIGN_PRIVATE,
                SENDER_SIGN_PUBLIC,
            ]
        ):
            raise ValueError("Generate sender keys first.")
        if not recipient_public_keys:
            raise ValueError(
                "Select at least one approved recipient from the dropdown before encrypting."
            )
        if uploaded_file is None:
            raise ValueError("Choose a file first.")
        file_bytes = uploaded_file.getvalue()
        t0 = time.perf_counter()
        # Encrypt the file once with a fresh random AES-256 key.
        aes_key = os.urandom(32)
        ciphertext, nonce, tag = encrypt_gcm(file_bytes, aes_key)
        recipient_envelopes = []
        for recipient_label, recipient_pub in recipient_public_keys:
            recipient_vk = ecdsa.VerifyingKey.from_pem(recipient_pub)
            if recipient_vk.curve != ecdsa.SECP256k1:
                raise ValueError(
                    f"Recipient '{recipient_label}' key must use SECP256K1."
                )
            wrap_key = derive_ecdh_shared_key(SENDER_ECDH_PRIVATE, recipient_pub)
            wrap_nonce = os.urandom(12)
            wrap_cipher = AES.new(wrap_key, AES.MODE_GCM, nonce=wrap_nonce)
            wrapped_aes_key, wrap_tag = wrap_cipher.encrypt_and_digest(aes_key)
            recipient_envelopes.append(
                {
                    "fingerprint": hashlib.sha256(recipient_vk.to_pem()).hexdigest(),
                    "wrapped_key": wrapped_aes_key.hex(),
                    "wrap_nonce": wrap_nonce.hex(),
                    "wrap_tag": wrap_tag.hex(),
                }
            )
        encryption_ms = (time.perf_counter() - t0) * 1000
        package = {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "transfer_id": uuid.uuid4().hex,
            "sender_username": st.session_state.auth_username,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "recipient_keys": recipient_envelopes,
            "sender_ecdh_public": SENDER_ECDH_PUBLIC.read_text(),
        }
        canonical = canonical_package_fields(package)
        signing_key = ecdsa.SigningKey.from_pem(SENDER_SIGN_PRIVATE.read_bytes())
        t1 = time.perf_counter()
        signature = signing_key.sign(canonical, hashfunc=hashlib.sha256)
        signing_ms = (time.perf_counter() - t1) * 1000
        st.session_state.sender_metrics.update(
            {
                "Original file size": f"{len(file_bytes):,} bytes",
                "Encrypted payload size": f"{len(bytes.fromhex(ciphertext)):,} bytes",
                "Encryption time (GCM)": f"{encryption_ms:.2f} ms",
                "SECP256K1 signing time": f"{signing_ms:.2f} ms",
            }
        )
        package["signature"] = signature.hex()
        package["sender_signing_public"] = SENDER_SIGN_PUBLIC.read_text()
        st.session_state.payload_to_store = json.dumps(
            package, sort_keys=True, separators=(",", ":")
        )
        st.session_state.last_filename = uploaded_file.name
        st.session_state.sender_metrics["IPFS package size"] = (
            f"{len(st.session_state.payload_to_store.encode('utf-8')):,} bytes"
        )
        st.session_state.last_cid = st.session_state.last_hash = (
            st.session_state.last_tx
        ) = ""
        st.success(
            f"File encrypted once with AES-256-GCM and signed for {len(recipient_envelopes)} recipient(s)."
        )
        package_digest = hashlib.sha256(
            st.session_state.payload_to_store.encode("utf-8")
        ).hexdigest()
        audit_manager.record_event(
            event_id=f"sender:encrypt:{package_digest}",
            event_type="ENCRYPT_AND_SIGN",
            status="PASS",
            package_sha256=package_digest,
            details=f"Encrypted and signed uploaded file name={uploaded_file.name!r}; plaintext is not stored in audit log.",
        )
        a, b, c = st.columns(3)
        a.metric("Original size", f"{len(file_bytes):,} bytes")
        b.metric("Ciphertext", f"{len(bytes.fromhex(ciphertext)):,} bytes")
        c.metric("Encrypt / sign", f"{encryption_ms:.2f} / {signing_ms:.2f} ms")
    except Exception as e:
        st.error(f"Encryption failed: {e}")

st.markdown(
    "**View IPFS node in the official Web UI:** "
    "[Open IPFS Web UI](http://127.0.0.1:5001/webui)"
)
st.caption(
    "This opens your local Kubo IPFS interface in a new browser tab. Start the IPFS daemon first."
)

if st.session_state.payload_to_store:
    st.download_button(
        "Download encrypted package backup",
        st.session_state.payload_to_store.encode(),
        file_name="encrypted_package.json",
        mime="application/json",
    )
    st.header("3. Upload to IPFS")
    if st.button("Upload encrypted package to IPFS"):
        try:
            ipfs_started = time.perf_counter()
            st.session_state.last_cid = api_client.upload_package(
                st.session_state.api_token,
                st.session_state.payload_to_store,
                [username for username, _public_key in recipient_public_keys],
            )
            st.session_state.sender_metrics["IPFS upload time"] = (
                f"{(time.perf_counter() - ipfs_started) * 1000:.2f} ms"
            )
            st.session_state.last_hash = hashlib.sha256(
                st.session_state.payload_to_store.encode()
            ).hexdigest()
            audit_manager.record_event(
                event_id=f"sender:ipfs:{st.session_state.last_cid}:{st.session_state.last_hash}",
                event_type="IPFS_UPLOAD",
                status="PASS",
                cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash,
                details="Encrypted package uploaded to IPFS.",
            )
            st.success("Encrypted package uploaded to IPFS.")
        except Exception as e:
            audit_manager.record_event(
                event_id=f"sender:ipfs-error:{hashlib.sha256((str(st.session_state.last_cid) + str(e)).encode()).hexdigest()}",
                event_type="IPFS_UPLOAD",
                status="ERROR",
                cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash,
                details=str(e),
            )
            st.error(f"IPFS upload failed: {e}")

if st.session_state.last_cid:
    st.markdown("**IPFS CID**")
    st.code(st.session_state.last_cid)
    st.markdown("**Package SHA-256**")
    st.code(st.session_state.last_hash)
    details = {
        "cid": st.session_state.last_cid,
        "package_sha256": st.session_state.last_hash,
        "filename": st.session_state.last_filename,
        "sender_ecdh_public": SENDER_ECDH_PUBLIC.read_text(),
        "sender_signing_public": SENDER_SIGN_PUBLIC.read_text(),
    }
    st.download_button(
        "Download transfer details",
        json.dumps(details, indent=2).encode(),
        file_name="transfer_details.json",
        mime="application/json",
    )
    st.header("4. Anchor on blockchain")
    if st.button("Record CID and hash on blockchain"):
        try:
            anchor_started = time.perf_counter()
            result = api_client.anchor_blockchain_record(
                st.session_state.api_token,
                st.session_state.last_cid,
                st.session_state.last_hash,
            )
            if result.get("status") != "PASS":
                raise RuntimeError(result.get("message", "Blockchain anchoring failed."))

            st.session_state.last_tx = result["transaction_hash"]
            st.session_state.sender_metrics["Blockchain confirmation time"] = (
                f"{(time.perf_counter() - anchor_started) * 1000:.2f} ms"
            )
            st.session_state.sender_metrics["Gas used per anchor"] = str(
                result.get("gas_used") or "Unavailable"
            )
            cost_eth = result.get("cost_eth")
            st.session_state.sender_metrics["Blockchain transaction cost (ETH)"] = (
                f"{cost_eth:.8f} ETH" if cost_eth is not None else "Unavailable"
            )

            audit_manager.record_event(
                event_id=f"sender:anchor:{st.session_state.last_tx}",
                event_type="BLOCKCHAIN_ANCHOR",
                status="PASS",
                cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash,
                block_number=result.get("block_number"),
                blockchain_timestamp_utc=result.get("blockchain_timestamp_utc", ""),
                transaction_hash=st.session_state.last_tx,
                details="CID and package SHA-256 commitment anchored through the central blockchain API.",
            )
            st.success("CID and hash anchored on the central blockchain.")
            g1, g2 = st.columns(2)
            g1.metric("Anchor gas used", str(result.get("gas_used") or "Unavailable"))
            g2.metric(
                "Estimated transaction cost (ETH)",
                f"{cost_eth:.8f}" if cost_eth is not None else "Unavailable",
            )
        except Exception as e:
            audit_manager.record_event(
                event_id=f"sender:anchor-error:{st.session_state.last_cid}:{st.session_state.last_hash}",
                event_type="BLOCKCHAIN_ANCHOR",
                status="ERROR",
                cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash,
                details=str(e),
            )
            st.error(f"Blockchain anchoring failed: {e}")
    if st.session_state.last_tx:
        st.code(st.session_state.last_tx)

st.divider()
st.header("📊 Sender Performance Metrics")
st.caption(
    "Actual measurements from sender operations in this Streamlit session. Unperformed operations remain 'Not measured yet'."
)
_sender_metric_items = list(st.session_state.sender_metrics.items())
for _row_start in range(0, len(_sender_metric_items), 3):
    _cols = st.columns(3)
    for _col, (_label, _value) in zip(
        _cols, _sender_metric_items[_row_start : _row_start + 3]
    ):
        _col.metric(_label, _value if _value is not None else "Not measured yet")

st.caption(
    "Sender private keys are stored only under sender/keys/. Do not commit keys/ folders to Git."
)


audit_manager.render_audit_ui(st, "Sender")
