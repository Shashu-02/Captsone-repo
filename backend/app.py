import glob
import hashlib
import json
import os
import time

import blockchain_manager
import ecdsa
import ipfs_manager
import pandas as pd
import streamlit as st
from Crypto.Cipher import AES
from web3 import Web3

# ==========================================
# PAGE CONFIGURATION & SETUP
# ==========================================
st.set_page_config(page_title="Secure Off-Chain Storage Framework", layout="wide")

st.title("🛡️ Secure Off-Chain Storage Framework")
st.write("Privacy-Preserving Data Sharing Using AES-256-GCM, ECDH, and IPFS")
st.caption(
    "AES-256-GCM | ECDH Key Derivation | SECP256K1 Digital Signatures | IPFS | Ethereum Smart Contract"
)
st.markdown("---")


# ==========================================
# AUTOMATIC SMART CONTRACT DEPLOYER
# ==========================================
def get_or_deploy_contract():
    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
    if not w3.is_connected():
        return None

    addr_file = "contract_address.txt"
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

    files = glob.glob("../blockchain/**/artifacts/contracts/**/*.json", recursive=True)
    files = [f for f in files if not f.endswith(".dbg.json")]
    if not files:
        st.error(
            "Compiled contract artifact not found! Run 'npx hardhat compile' once in your blockchain folder."
        )
        return None

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


CONTRACT_ADDRESS = get_or_deploy_contract()

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

KEY_DIR = Path(__file__).resolve().parent / "keys"
KEY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
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
            "ciphertext",
            "nonce",
            "tag",
            "recipient_ecdh_fingerprint",
            "sender_ecdh_public",
        )
    }
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ==========================================
# SESSION STATE INITIALIZATION
# ==========================================
metrics_keys = [
    "orig_size",
    "enc_size",
    "ipfs_size",
    "enc_time",
    "sign_time",
    "ipfs_up_time",
    "block_time",
    "gas_used",
    "ipfs_down_time",
    "verify_time",
    "dec_time",
    "last_cid",
    "last_hash",
    "last_tx",
    "last_enc_hex",
    "last_sig_hex",
    "last_nonce",
    "last_tag",
]
for key in metrics_keys:
    if key not in st.session_state:
        st.session_state[key] = "Not measured yet"

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "wrong_pub_pem" not in st.session_state:
    fake_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    st.session_state.wrong_pub_pem = (
        fake_sk.get_verifying_key().to_pem().decode("utf-8")
    )


def format_val(val, unit=""):
    if val == "Not measured yet":
        return val
    if isinstance(val, (int, float)):
        if unit == "bytes":
            return f"{int(val):,} {unit}"
        if unit == "ms":
            return f"{val:.2f} {unit}"
        if unit == "%":
            return f"{val:.2f}{unit}"
        if unit == "gas":
            return f"{int(val):,} gas"
        return f"{val:,}"
    return str(val)


# ==========================================
# TABS SETUP
# ==========================================
tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📤 Sender (Encrypt & Upload)",
        "📥 Receiver (Retrieve & Verify)",
        "⚠️ Attacker Mode (Security Tests)",
        "📊 Metrics & Audit Log",
    ]
)

# ==========================================
# TAB 1: SENDER — RECIPIENT-BASED ENCRYPTION
# ==========================================
with tab1:
    st.header("1. Sender and Recipient Identities")
    st.warning(
        "Prototype: sender and recipient identities are generated locally. In a real deployment, import the recipient public key and verify its fingerprint through a trusted channel."
    )

    if st.button("Generate Sender Identity"):
        try:
            generate_identity("sender")
            st.success("Sender ECDH and signing keys generated.")
        except Exception as e:
            st.error(f"Sender key generation failed: {e}")

    st.markdown("**Import the recipient's ECDH public key**")
    st.caption(
        "On the receiver side, generate/export the recipient public key first. Import that PEM here. Never upload or share the recipient private key."
    )
    recipient_public_upload = st.file_uploader(
        "Recipient ECDH public key (.pem)",
        type=["pem", "txt"],
        key="recipient_ecdh_public_upload",
    )

    if SENDER_ECDH_PUBLIC.exists():
        sender_ecdh_pub = SENDER_ECDH_PUBLIC.read_text()
        st.markdown("**Sender ECDH public key (shareable)**")
        st.code(sender_ecdh_pub, language="text")
        st.download_button(
            "Export Sender ECDH Public Key",
            sender_ecdh_pub,
            file_name="sender_ecdh_public.pem",
            key="export_sender_ecdh",
        )
    if SENDER_SIGN_PUBLIC.exists():
        sender_sign_pub = SENDER_SIGN_PUBLIC.read_text()
        st.markdown("**Sender signing public key (shareable)**")
        st.code(sender_sign_pub, language="text")
        st.download_button(
            "Export Sender Signing Public Key",
            sender_sign_pub,
            file_name="sender_sign_public.pem",
            key="export_sender_sign",
        )

    st.caption(
        "Sender private keys are stored locally under backend/keys/ with restrictive file permissions and are never displayed."
    )
    st.markdown("---")
    st.header("2. Encrypt and Sign Dataset")
    uploaded_file = st.file_uploader(
        "Upload a CSV, TXT, or JSON file",
        type=["txt", "csv", "json"],
        key="sender_upload",
    )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        st.success(f"File loaded: {uploaded_file.name} ({len(file_bytes):,} bytes)")
        if st.button("Encrypt for Recipient and Sign", key="encrypt_for_recipient"):
            try:
                required = [
                    SENDER_ECDH_PRIVATE,
                    SENDER_ECDH_PUBLIC,
                    SENDER_SIGN_PRIVATE,
                    SENDER_SIGN_PUBLIC,
                ]
                if not all(p.exists() for p in required):
                    raise ValueError("Generate the Sender identity first.")
                if recipient_public_upload is None:
                    raise ValueError(
                        "Import the recipient's ECDH public PEM exported from the Receiver tab."
                    )

                recipient_pub_bytes = recipient_public_upload.getvalue()
                # Validate that the uploaded key is a valid SECP256K1 public key before use.
                recipient_vk = ecdsa.VerifyingKey.from_pem(recipient_pub_bytes)
                if recipient_vk.curve != ecdsa.SECP256k1:
                    raise ValueError("Recipient key must use SECP256K1.")
                aes_key = derive_ecdh_shared_key(
                    SENDER_ECDH_PRIVATE, recipient_pub_bytes
                )
                t0 = time.perf_counter()
                ciphertext_hex, nonce_hex, tag_hex = encrypt_gcm(file_bytes, aes_key)
                enc_ms = (time.perf_counter() - t0) * 1000

                recipient_fingerprint = hashlib.sha256(recipient_pub_bytes).hexdigest()
                package = {
                    "version": 1,
                    "algorithm": "AES-256-GCM",
                    "ciphertext": ciphertext_hex,
                    "nonce": nonce_hex,
                    "tag": tag_hex,
                    "recipient_ecdh_fingerprint": recipient_fingerprint,
                    "sender_ecdh_public": SENDER_ECDH_PUBLIC.read_text(),
                }
                canonical = canonical_package_fields(package)
                with open(SENDER_SIGN_PRIVATE, "rb") as f:
                    signing_key = ecdsa.SigningKey.from_pem(f.read())
                t1 = time.perf_counter()
                signature = signing_key.sign(canonical, hashfunc=hashlib.sha256)
                sign_ms = (time.perf_counter() - t1) * 1000
                package["signature"] = signature.hex()
                package["sender_signing_public"] = SENDER_SIGN_PUBLIC.read_text()
                package_text = json.dumps(
                    package, sort_keys=True, separators=(",", ":")
                )

                st.session_state.orig_size = len(file_bytes)
                st.session_state.enc_size = len(bytes.fromhex(ciphertext_hex))
                st.session_state.enc_time = enc_ms
                st.session_state.sign_time = sign_ms
                st.session_state.last_enc_hex = ciphertext_hex
                st.session_state.last_sig_hex = signature.hex()
                st.session_state.last_nonce = nonce_hex
                st.session_state.last_tag = tag_hex
                st.session_state.payload_to_store = package_text
                st.session_state.ipfs_size = len(package_text.encode("utf-8"))
                st.session_state.last_cid = "Not measured yet"
                st.session_state.last_hash = "Not measured yet"
                st.session_state.last_tx = "Not measured yet"
                st.session_state.block_time = "Not measured yet"
                st.session_state.gas_used = "Not measured yet"
                st.success(
                    "Encrypted for recipient with AES-256-GCM and signed separately."
                )
            except Exception as e:
                st.error(f"Encryption failed: {e}")

    if st.session_state.last_enc_hex != "Not measured yet":
        st.markdown("---")
        st.subheader("Secured Output")
        st.code(st.session_state.last_enc_hex[:200] + "...", language="text")
        col1, col2 = st.columns(2)
        col1.metric(
            "Original File Size", format_val(st.session_state.orig_size, "bytes")
        )
        col2.metric(
            "Encrypted Payload Size", format_val(st.session_state.enc_size, "bytes")
        )
        st.markdown("**Digital signature (hex preview)**")
        st.code(st.session_state.last_sig_hex[:120] + "...", language="text")

        st.markdown("---")
        st.header("3. IPFS Off-Chain Storage")
        if st.button("Upload to IPFS", key="upload_to_ipfs"):
            try:
                start_ipfs = time.perf_counter()
                cid = ipfs_manager.upload_data(st.session_state.payload_to_store)
                st.session_state.ipfs_up_time = (
                    time.perf_counter() - start_ipfs
                ) * 1000
                st.session_state.last_cid = cid
                st.success("Encrypted package uploaded to IPFS.")
            except Exception as e:
                st.error(f"IPFS upload failed: {e}")

        if st.session_state.last_cid != "Not measured yet":
            st.markdown("**IPFS CID**")
            st.code(st.session_state.last_cid)
            st.markdown("[Open IPFS WebUI](http://127.0.0.1:5001/webui)")
            if st.button("Record on Blockchain", key="record_on_chain"):
                try:
                    current_contract = get_or_deploy_contract()
                    if not current_contract:
                        raise RuntimeError(
                            "Cannot connect to Hardhat node or deploy contract."
                        )
                    data_hash = hashlib.sha256(
                        st.session_state.payload_to_store.encode("utf-8")
                    ).hexdigest()
                    st.session_state.last_hash = data_hash
                    start_blockchain = time.perf_counter()
                    receipt = blockchain_manager.store_record(
                        cid=st.session_state.last_cid,
                        data_hash=data_hash,
                        contract_address=current_contract,
                        abi=MINIMAL_ABI,
                    )
                    st.session_state.block_time = (
                        time.perf_counter() - start_blockchain
                    ) * 1000
                    st.session_state.gas_used = receipt["gasUsed"]
                    st.session_state.last_tx = receipt["transactionHash"].hex()
                    st.session_state.audit_log.append(
                        {
                            "Filename": uploaded_file.name,
                            "IPFS CID": st.session_state.last_cid,
                            "Tx Hash": st.session_state.last_tx,
                            "Gas Used": st.session_state.gas_used,
                            "Timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )
                    st.success("Blockchain record created and added to audit log.")
                except Exception as e:
                    st.error(f"Blockchain recording failed: {e}")
            if st.session_state.last_tx != "Not measured yet":
                st.markdown("**Transaction hash**")
                st.code(st.session_state.last_tx)

# ==========================================
# TAB 2: RECEIVER — VERIFY AND DECRYPT
# ==========================================
with tab2:
    st.header("4. Receiver Identity")
    st.info(
        "Generate the recipient identity on the receiver side. Keep the ECDH private key on the receiver machine; export/share only the public PEM with the sender."
    )
    if st.button(
        "Generate Recipient Identity", key="generate_recipient_identity_receiver"
    ):
        try:
            generate_identity("recipient")
            st.success(
                "Recipient ECDH and signing key pairs generated. Private keys remain in backend/keys/."
            )
        except Exception as e:
            st.error(f"Recipient key generation failed: {e}")
    if RECIPIENT_ECDH_PUBLIC.exists():
        recipient_ecdh_pub = RECIPIENT_ECDH_PUBLIC.read_bytes()
        st.markdown("**Recipient ECDH public key (shareable)**")
        st.code(recipient_ecdh_pub.decode("utf-8"), language="text")
        st.download_button(
            "Export Recipient ECDH Public Key",
            recipient_ecdh_pub,
            file_name="recipient_ecdh_public.pem",
            key="export_recipient_ecdh_receiver",
        )
    else:
        st.warning(
            "Generate the recipient identity to create the public key for the sender."
        )

    st.markdown("---")
    st.header("5. Receiver: Fetch, Verify and Decrypt")
    st.info(
        "The receiver checks the blockchain commitment, verifies the sender signature using a trusted signing public key, derives the recipient key with ECDH + HKDF-SHA256, then authenticates/decrypts with AES-GCM."
    )
    fetch_id = st.text_input(
        "Blockchain Record ID / IPFS CID", key="receiver_record_id"
    )
    sender_sign_pub_input = st.text_area(
        "Trusted sender signing public key (PEM)",
        key="trusted_sender_sign_pub",
        height=140,
    )
    sender_ecdh_pub_input = st.text_area(
        "Sender ECDH public key (PEM)", key="trusted_sender_ecdh_pub", height=140
    )

    if st.button("Fetch, Verify and Decrypt", key="receiver_verify_decrypt"):
        try:
            if not fetch_id.strip():
                raise ValueError("Enter the CID used as the blockchain record key.")
            if (
                not RECIPIENT_ECDH_PRIVATE.exists()
                or not RECIPIENT_ECDH_PUBLIC.exists()
            ):
                raise ValueError(
                    "Recipient identity is unavailable. Generate/import the recipient identity on this machine."
                )
            if not sender_sign_pub_input.strip() or not sender_ecdh_pub_input.strip():
                raise ValueError("Provide trusted sender signing and ECDH public keys.")
            current_contract = get_or_deploy_contract()
            if not current_contract:
                raise RuntimeError("Cannot connect to the blockchain contract.")
            record = blockchain_manager.verify_record(
                cid=fetch_id.strip(), contract_address=current_contract, abi=MINIMAL_ABI
            )
            if not record:
                raise ValueError("Record not found on blockchain.")

            start_ipfs = time.perf_counter()
            raw_ipfs_data = ipfs_manager.retrieve_file(record["cid"])
            st.session_state.ipfs_down_time = (time.perf_counter() - start_ipfs) * 1000
            downloaded_hash = hashlib.sha256(raw_ipfs_data.encode("utf-8")).hexdigest()
            if (
                downloaded_hash.lower()
                != record["data_hash"].removeprefix("0x").lower()
            ):
                raise ValueError("Package hash mismatch against blockchain anchor.")
            package = json.loads(raw_ipfs_data)
            if package.get("version") != 1 or package.get("algorithm") != "AES-256-GCM":
                raise ValueError("Unsupported package version or encryption algorithm.")
            if (
                package.get("sender_ecdh_public", "").strip()
                != sender_ecdh_pub_input.strip()
            ):
                raise ValueError("Sender ECDH public key does not match the package.")
            recipient_pub = RECIPIENT_ECDH_PUBLIC.read_bytes()
            recipient_fingerprint = hashlib.sha256(recipient_pub).hexdigest()
            if package.get("recipient_ecdh_fingerprint") != recipient_fingerprint:
                raise ValueError(
                    "This package was not addressed to this recipient key."
                )

            canonical = canonical_package_fields(package)
            t0 = time.perf_counter()
            sender_vk = ecdsa.VerifyingKey.from_pem(
                sender_sign_pub_input.encode("utf-8")
            )
            sender_vk.verify(
                bytes.fromhex(package["signature"]), canonical, hashfunc=hashlib.sha256
            )
            st.session_state.verify_time = (time.perf_counter() - t0) * 1000

            aes_key = derive_ecdh_shared_key(
                RECIPIENT_ECDH_PRIVATE, sender_ecdh_pub_input
            )
            t1 = time.perf_counter()
            plaintext = decrypt_gcm(
                package["ciphertext"], package["nonce"], package["tag"], aes_key
            )
            st.session_state.dec_time = (time.perf_counter() - t1) * 1000
            st.success(
                "Blockchain hash, sender signature, recipient binding, and AES-GCM authentication all passed."
            )
            out_filename = st.text_input(
                "Output filename",
                value="recovered_file.bin",
                key="receiver_output_filename",
            )
            st.download_button(
                "Download Verified File",
                data=plaintext,
                file_name=out_filename.strip() or "recovered_file.bin",
                mime="application/octet-stream",
            )
        except Exception as e:
            st.error(f"Retrieval / verification failed: {e}")

# ==========================================
# TAB 3: ATTACKER SIMULATION (JSON PACKAGE)
# ==========================================
with tab3:
    st.header("6. Security & Tamper Testing")
    attack_type = st.selectbox(
        "Select Attack Scenario",
        [
            "Scenario A: Modify Encrypted Data",
            "Scenario B: Remove Signature",
            "Scenario C: Verify with Wrong Public Key",
        ],
        key="attacker_scenario",
    )
    default_record_id = (
        st.session_state.last_cid
        if st.session_state.last_cid != "Not measured yet"
        else ""
    )
    attack_cid = st.text_input(
        "Blockchain Record ID / CID", value=default_record_id, key="attack_cid"
    )
    wrong_pub_input = ""
    if attack_type == "Scenario C: Verify with Wrong Public Key":
        wrong_pub_input = st.text_area(
            "Wrong SECP256K1 signing public key (PEM)",
            value=st.session_state.wrong_pub_pem,
            height=120,
        )

    if st.button("Run Attack Simulator", key="run_attack_simulator"):
        try:
            if not attack_cid.strip():
                raise ValueError("Enter the CID used as the blockchain record key.")
            current_contract = get_or_deploy_contract()
            if not current_contract:
                raise RuntimeError("Cannot connect to the blockchain contract.")
            record = blockchain_manager.verify_record(
                attack_cid.strip(), current_contract, MINIMAL_ABI
            )
            if not record:
                raise ValueError("No blockchain record found.")
            raw = ipfs_manager.retrieve_file(record["cid"])
            original_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            expected_hash = str(record["data_hash"]).removeprefix("0x").lower()
            if original_hash.lower() != expected_hash:
                raise ValueError(
                    "Original package hash mismatch; refusing to simulate on untrusted data."
                )
            package = json.loads(raw)
            if attack_type == "Scenario A: Modify Encrypted Data":
                payload = package.get("ciphertext", "")
                package["ciphertext"] = (
                    ("deadbeef" + payload[8:]) if len(payload) >= 8 else "deadbeef"
                )
            elif attack_type == "Scenario B: Remove Signature":
                package["signature"] = ""
            else:
                if not wrong_pub_input.strip():
                    raise ValueError("Provide a wrong public key.")
                vk = ecdsa.VerifyingKey.from_pem(wrong_pub_input.encode("utf-8"))
                vk.verify(
                    bytes.fromhex(package["signature"]),
                    canonical_package_fields(package),
                    hashfunc=hashlib.sha256,
                )
                st.error("The supplied key unexpectedly verified the signature.")
                st.stop()
            tampered = json.dumps(
                package, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            tampered_hash = hashlib.sha256(tampered).hexdigest()
            if tampered_hash != expected_hash:
                st.error(
                    "ATTACK DETECTED: tampered package no longer matches the blockchain commitment."
                )
                st.success("The altered package was rejected before decryption.")
            else:
                st.error(
                    "Unexpected result: altered package hash matches blockchain commitment."
                )
        except Exception as e:
            st.error(f"Attack rejected / simulation error: {e}")

# ==========================================
# TAB 4: METRICS & AUDIT LOG
# ==========================================
with tab4:
    st.header("📊 Performance Metrics")
    st.caption("Measurements captured from actual operations in this session.")

    r1_col1, r1_col2, r1_col3 = st.columns(3)
    r1_col1.metric(
        "Original file size", format_val(st.session_state.orig_size, "bytes")
    )
    r1_col2.metric(
        "Encrypted payload size", format_val(st.session_state.enc_size, "bytes")
    )
    r1_col3.metric("IPFS package size", format_val(st.session_state.ipfs_size, "bytes"))

    r2_col1, r2_col2, r2_col3 = st.columns(3)
    r2_col1.metric("Encryption time (GCM)", format_val(st.session_state.enc_time, "ms"))
    r2_col2.metric(
        "SECP256K1 signing time", format_val(st.session_state.sign_time, "ms")
    )
    r2_col3.metric("IPFS upload time", format_val(st.session_state.ipfs_up_time, "ms"))

    r3_col1, r3_col2, r3_col3 = st.columns(3)
    r3_col1.metric(
        "Blockchain confirmation time", format_val(st.session_state.block_time, "ms")
    )
    r3_col2.metric("Gas used per anchor", format_val(st.session_state.gas_used, "gas"))
    r3_col3.metric(
        "IPFS download time", format_val(st.session_state.ipfs_down_time, "ms")
    )

    r4_col1, r4_col2, r4_col3 = st.columns(3)
    r4_col1.metric(
        "Signature verification time", format_val(st.session_state.verify_time, "ms")
    )
    r4_col2.metric("Decryption time (GCM)", format_val(st.session_state.dec_time, "ms"))

    st.markdown("---")
    st.subheader("📋 Live Blockchain Audit Log")
    if len(st.session_state.audit_log) > 0:
        df_audit = pd.DataFrame(st.session_state.audit_log)
        st.dataframe(df_audit, use_container_width=True)

        csv_data = df_audit.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Audit Report (CSV)",
            data=csv_data,
            file_name="blockchain_audit_report.csv",
            mime="text/csv",
        )
    else:
        st.info(
            "No records anchored on the blockchain yet in this session. Complete a sender workflow to populate the audit log."
        )

    st.markdown("---")
    st.subheader("Storage Overhead")
    if (
        st.session_state.orig_size != "Not measured yet"
        and st.session_state.ipfs_size != "Not measured yet"
    ):
        overhead_pct = (
            (st.session_state.ipfs_size - st.session_state.orig_size)
            / st.session_state.orig_size
        ) * 100
        st.write(f"Original file: **{st.session_state.orig_size:,} bytes**")
        st.write(f"IPFS package: **{st.session_state.ipfs_size:,} bytes**")
        st.metric("Package size overhead", f"{overhead_pct:.2f}%")
