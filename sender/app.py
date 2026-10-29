import glob
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
from web3 import Web3

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
import blockchain_manager
import ipfs_manager
import audit_manager


# ==========================================
# AUTOMATIC SMART CONTRACT DEPLOYER
# ==========================================
def get_or_deploy_contract():
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    if not w3.is_connected():
        raise RuntimeError(
            "Hardhat RPC is unavailable at http://127.0.0.1:8545. Start npx hardhat node first."
        )

    addr_file = str(
        Path(__file__).resolve().parents[1] / "blockchain" / "contract_address.txt"
    )
    if os.path.exists(addr_file):
        with open(addr_file, "r") as f:
            saved_addr = f.read().strip()
        try:
            if w3.eth.get_code(Web3.to_checksum_address(saved_addr)) not in (
                b"",
                b"\x00",
            ):
                return saved_addr
        except Exception:
            pass

    artifacts_root = Path(__file__).resolve().parents[1] / "blockchain"
    files = glob.glob(
        str(artifacts_root / "artifacts/contracts/**/DataStorage.json"), recursive=True
    )
    files = [f for f in files if not f.endswith(".dbg.json")]
    if not files:
        raise FileNotFoundError(
            "Compiled contract artifact not found. Install Hardhat and run npx hardhat compile in the blockchain folder."
        )

    with open(files[0], "r") as f:
        data = json.load(f)

    w3.eth.default_account = w3.eth.accounts[0]
    Contract = w3.eth.contract(abi=data["abi"], bytecode=data["bytecode"])
    tx_hash = Contract.constructor().transact()
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    new_addr = receipt.contractAddress
    with open(addr_file, "w") as f:
        f.write(new_addr)

    return new_addr



MINIMAL_ABI = [
    {
        "inputs": [
            {"internalType": "string", "name": "_cid", "type": "string"},
            {"internalType": "string", "name": "_dataHash", "type": "string"},
        ],
        "name": "storeRecord",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "string", "name": "", "type": "string"}],
        "name": "records",
        "outputs": [
            {"internalType": "string", "name": "cid", "type": "string"},
            {"internalType": "string", "name": "dataHash", "type": "string"},
            {"internalType": "address", "name": "sender", "type": "address"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

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
    fields = {
        k: package[k]
        for k in (
            "version",
            "algorithm",
            "transfer_id",
            "ciphertext",
            "nonce",
            "tag",
            "recipient_ecdh_fingerprint",
            "sender_ecdh_public",
        )
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


st.set_page_config(page_title="Secure Storage — Sender", page_icon="📤", layout="wide")

# --- Authentication and administrator approval gate ---
from auth_manager import (authenticate, register_user, get_user, ensure_identity, log_event)

if "auth_username" not in st.session_state:
    st.session_state.auth_username = None
if not st.session_state.auth_username:
    st.subheader("Client sign in / registration")
    mode = st.radio("Choose", ["Sign in", "Register new sender"], horizontal=True)
    with st.form("sender_auth_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Continue")
    if submitted:
        try:
            if mode == "Register new sender":
                register_user(username, password, "sender")
                st.success("Registration submitted. An administrator must approve your account before access is enabled.")
            else:
                user = authenticate(username, password)
                if not user:
                    st.error("Invalid username or password.")
                elif user["role"] != "sender":
                    st.error("This account is not a sender account.")
                elif user["status"] != "approved":
                    st.warning(f"Account status: {user['status']}. Please wait for administrator approval.")
                else:
                    st.session_state.auth_username = user["username"]
                    st.rerun()
        except Exception as exc:
            st.error(str(exc))
    st.stop()

_current_user = get_user(st.session_state.auth_username)
if not _current_user or _current_user["role"] != "sender" or _current_user["status"] != "approved":
    st.session_state.auth_username = None
    st.error("This account is not approved. Please sign in again after administrator approval.")
    st.stop()
if st.button("Sign out", key="auth_signout"):
    log_event(st.session_state.auth_username, "logout", "sender portal")
    st.session_state.auth_username = None
    st.rerun()
st.caption(f"Signed in as **{st.session_state.auth_username}** · approved sender")
# Auto-provision keys once after approval. Existing keys are never overwritten automatically.
ensure_identity("sender", KEY_DIR, generate_identity)


st.title("📤 Sender Portal")
st.caption(
    "Encrypt for recipient · Sign · Store encrypted package on IPFS · Anchor its hash on Ethereum"
)
st.info(
    "Generate sender keys here. Import only the receiver's public ECDH key; never request or share the receiver's private key."
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
        "Original file size": None, "Encrypted payload size": None,
        "IPFS package size": None, "Encryption time (GCM)": None,
        "SECP256K1 signing time": None, "IPFS upload time": None,
        "Blockchain confirmation time": None, "Gas used per anchor": None,
        "Blockchain transaction cost (ETH)": None,
    }

st.info("Cryptographic keys are provisioned automatically after administrator approval and are not replaced on login.")

if SENDER_ECDH_PUBLIC.exists() and SENDER_SIGN_PUBLIC.exists():
    st.success("Sender identity is ready. Public keys are registered locally; no key export is required.")
else:
    st.warning("Sender identity is not available. Sign in after administrator approval to provision keys.")

st.divider()
st.header("2. Encrypt and sign a file")
# Single-machine demo: automatically load the approved Receiver portal's public key.
recipient_pub = None
if RECEIVER_ECDH_PUBLIC.exists():
    recipient_pub = RECEIVER_ECDH_PUBLIC.read_bytes()
    st.success("Receiver public key detected automatically. No PEM upload required.")
else:
    st.warning("Receiver identity is not available yet. Sign in to an approved Receiver account first.")
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
        if recipient_pub is None:
            raise ValueError("Receiver public key is missing. Approve and sign in to the Receiver portal first.")
        if uploaded_file is None:
            raise ValueError("Choose a file first.")
        recipient_vk = ecdsa.VerifyingKey.from_pem(recipient_pub)
        if recipient_vk.curve != ecdsa.SECP256k1:
            raise ValueError("Recipient key must use SECP256K1.")
        file_bytes = uploaded_file.getvalue()
        t0 = time.perf_counter()
        aes_key = derive_ecdh_shared_key(SENDER_ECDH_PRIVATE, recipient_pub)
        ciphertext, nonce, tag = encrypt_gcm(file_bytes, aes_key)
        encryption_ms = (time.perf_counter() - t0) * 1000
        package = {
            "version": 1,
            "algorithm": "AES-256-GCM",
            "transfer_id": uuid.uuid4().hex,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "recipient_ecdh_fingerprint": hashlib.sha256(recipient_pub).hexdigest(),
            "sender_ecdh_public": SENDER_ECDH_PUBLIC.read_text(),
        }
        canonical = canonical_package_fields(package)
        signing_key = ecdsa.SigningKey.from_pem(SENDER_SIGN_PRIVATE.read_bytes())
        t1 = time.perf_counter()
        signature = signing_key.sign(canonical, hashfunc=hashlib.sha256)
        signing_ms = (time.perf_counter() - t1) * 1000
        st.session_state.sender_metrics.update({
            "Original file size": f"{len(file_bytes):,} bytes",
            "Encrypted payload size": f"{len(bytes.fromhex(ciphertext)):,} bytes",
            "Encryption time (GCM)": f"{encryption_ms:.2f} ms",
            "SECP256K1 signing time": f"{signing_ms:.2f} ms",
        })
        package["signature"] = signature.hex()
        package["sender_signing_public"] = SENDER_SIGN_PUBLIC.read_text()
        st.session_state.payload_to_store = json.dumps(
            package, sort_keys=True, separators=(",", ":")
        )
        st.session_state.last_filename = uploaded_file.name
        st.session_state.sender_metrics["IPFS package size"] = f"{len(st.session_state.payload_to_store.encode('utf-8')):,} bytes"
        st.session_state.last_cid = st.session_state.last_hash = (
            st.session_state.last_tx
        ) = ""
        st.success("File encrypted with AES-256-GCM and digitally signed.")
        package_digest = hashlib.sha256(st.session_state.payload_to_store.encode("utf-8")).hexdigest()
        audit_manager.record_event(
            event_id=f"sender:encrypt:{package_digest}", event_type="ENCRYPT_AND_SIGN",
            status="PASS", package_sha256=package_digest,
            details=f"Encrypted and signed uploaded file name={uploaded_file.name!r}; plaintext is not stored in audit log.")
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
st.caption("This opens your local Kubo IPFS interface in a new browser tab. Start the IPFS daemon first.")

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
            st.session_state.last_cid = ipfs_manager.upload_data(
                st.session_state.payload_to_store
            )
            st.session_state.sender_metrics["IPFS upload time"] = f"{(time.perf_counter() - ipfs_started) * 1000:.2f} ms"
            st.session_state.last_hash = hashlib.sha256(
                st.session_state.payload_to_store.encode()
            ).hexdigest()
            audit_manager.record_event(
                event_id=f"sender:ipfs:{st.session_state.last_cid}:{st.session_state.last_hash}",
                event_type="IPFS_UPLOAD", status="PASS", cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash, details="Encrypted package uploaded to IPFS.")
            st.success("Encrypted package uploaded to IPFS.")
        except Exception as e:
            audit_manager.record_event(
                event_id=f"sender:ipfs-error:{hashlib.sha256((str(st.session_state.last_cid)+str(e)).encode()).hexdigest()}",
                event_type="IPFS_UPLOAD", status="ERROR", cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash, details=str(e))
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
            address = get_or_deploy_contract()
            anchor_started = time.perf_counter()
            receipt = blockchain_manager.store_record(
                cid=st.session_state.last_cid,
                data_hash=st.session_state.last_hash,
                contract_address=address,
                abi=MINIMAL_ABI,
            )
            tx = receipt.get("transactionHash", receipt.get("transaction_hash", ""))
            if hasattr(tx, "hex"):
                tx = tx.hex()
            st.session_state.last_tx = str(tx)
            st.session_state.sender_metrics["Blockchain confirmation time"] = f"{(time.perf_counter() - anchor_started) * 1000:.2f} ms"
            meta = blockchain_manager.get_receipt_metadata(receipt)
            gas_metrics = blockchain_manager.transaction_cost_metrics(receipt)
            st.session_state.sender_metrics["Gas used per anchor"] = str(gas_metrics.get("gas_used") or "Unavailable")
            st.session_state.sender_metrics["Blockchain transaction cost (ETH)"] = (f"{gas_metrics['cost_eth']:.8f} ETH" if gas_metrics.get("cost_eth") is not None else "Unavailable")
            audit_manager.record_event(
                event_id=f"sender:anchor:{st.session_state.last_tx or st.session_state.last_cid}",
                event_type="BLOCKCHAIN_ANCHOR", status="PASS", cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash, block_number=meta.get("block_number"),
                blockchain_timestamp_utc=meta.get("blockchain_timestamp_utc", ""),
                transaction_hash=st.session_state.last_tx,
                details="CID and package SHA-256 commitment anchored on chain." + (f" Block metadata note: {meta['metadata_error']}" if meta.get("metadata_error") else ""))
            st.success("CID and hash anchored on the local blockchain.")
            g1, g2 = st.columns(2)
            g1.metric("Anchor gas used", str(gas_metrics.get("gas_used") or "Unavailable"))
            g2.metric("Estimated transaction cost (ETH)", f"{gas_metrics['cost_eth']:.8f}" if gas_metrics.get("cost_eth") is not None else "Unavailable")
        except Exception as e:
            audit_manager.record_event(
                event_id=f"sender:anchor-error:{st.session_state.last_cid}:{st.session_state.last_hash}",
                event_type="BLOCKCHAIN_ANCHOR", status="ERROR", cid=st.session_state.last_cid,
                package_sha256=st.session_state.last_hash, details=str(e))
            st.error(f"Blockchain anchoring failed: {e}")
    if st.session_state.last_tx:
        st.code(st.session_state.last_tx)

st.divider()
st.header("📊 Sender Performance Metrics")
st.caption("Actual measurements from sender operations in this Streamlit session. Unperformed operations remain 'Not measured yet'.")
_sender_metric_items = list(st.session_state.sender_metrics.items())
for _row_start in range(0, len(_sender_metric_items), 3):
    _cols = st.columns(3)
    for _col, (_label, _value) in zip(_cols, _sender_metric_items[_row_start:_row_start + 3]):
        _col.metric(_label, _value if _value is not None else "Not measured yet")

st.caption(
    "Sender private keys are stored only under sender/keys/. Do not commit keys/ folders to Git."
)


audit_manager.render_audit_ui(st, "Sender")
