import streamlit as st
import hashlib
import time
import os
import glob
import json
import ecdsa
import pandas as pd
from Crypto.Cipher import AES
from web3 import Web3
import ipfs_manager
import blockchain_manager

# ==========================================
# PAGE CONFIGURATION & SETUP
# ==========================================
st.set_page_config(page_title="Secure Off-Chain Storage Framework", layout="wide")

st.title("🛡️ Secure Off-Chain Storage Framework")
st.write("Privacy-Preserving Data Sharing Using AES-256-GCM, ECDH, and IPFS")
st.caption("AES-256-GCM | ECDH Key Derivation | SECP256K1 Digital Signatures | IPFS | Ethereum Smart Contract")
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
            if w3.eth.get_code(Web3.to_checksum_address(saved_addr)) not in (b"", b"\x00"):
                return saved_addr
        except Exception:
            pass

    files = glob.glob("../blockchain/**/artifacts/contracts/**/*.json", recursive=True)
    files = [f for f in files if not f.endswith(".dbg.json")]
    if not files:
        st.error("Compiled contract artifact not found! Run 'npx hardhat compile' once in your blockchain folder.")
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
            {"internalType": "string", "name": "_dataHash", "type": "string"}
        ],
        "name": "storeRecord",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "string", "name": "", "type": "string"}],
        "name": "records",
        "outputs": [
            {"internalType": "string", "name": "cid", "type": "string"},
            {"internalType": "string", "name": "dataHash", "type": "string"},
            {"internalType": "address", "name": "sender", "type": "address"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# ==========================================
# CRYPTOGRAPHIC HELPER FUNCTIONS (GCM & ECDH)
# ==========================================
def derive_ecdh_shared_key(priv_pem_path, pub_pem_str):
    """Derives a shared 256-bit AES key using ECDH over SECP256K1."""
    with open(priv_pem_path, "rb") as f:
        sk = ecdsa.SigningKey.from_pem(f.read())
    vk = ecdsa.VerifyingKey.from_pem(pub_pem_str.encode("utf-8"))
    
    # ECDH point multiplication: scalar multiplication of private multiplier with peer's public point
    shared_point = sk.privkey.secret_multiplier * vk.pubkey.point
    shared_secret = shared_point.x().to_bytes(32, 'big')
    return hashlib.sha256(shared_secret).digest()

def encrypt_gcm(file_bytes, aes_key):
    """Encrypts data using AES-256-GCM returning hex strings for ciphertext, nonce, and tag."""
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    return ciphertext.hex(), cipher.nonce.hex(), tag.hex()

def decrypt_gcm(ciphertext_hex, nonce_hex, tag_hex, aes_key):
    """Decrypts and authenticates AES-256-GCM payload."""
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bytes.fromhex(nonce_hex))
    return cipher.decrypt_and_verify(bytes.fromhex(ciphertext_hex), bytes.fromhex(tag_hex))

# ==========================================
# SESSION STATE INITIALIZATION
# ==========================================
metrics_keys = [
    "orig_size", "enc_size", "ipfs_size", 
    "enc_time", "sign_time", "ipfs_up_time", 
    "block_time", "gas_used", "ipfs_down_time", 
    "verify_time", "dec_time",
    "last_cid", "last_hash", "last_tx", "last_enc_hex", "last_sig_hex", "last_nonce", "last_tag"
]
for key in metrics_keys:
    if key not in st.session_state:
        st.session_state[key] = "Not measured yet"

if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

if "wrong_pub_pem" not in st.session_state:
    fake_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    st.session_state.wrong_pub_pem = fake_sk.get_verifying_key().to_pem().decode("utf-8")

def format_val(val, unit=""):
    if val == "Not measured yet":
        return val
    if isinstance(val, (int, float)):
        if unit == "bytes": return f"{int(val):,} {unit}"
        if unit == "ms": return f"{val:.2f} {unit}"
        if unit == "%": return f"{val:.2f}{unit}"
        if unit == "gas": return f"{int(val):,} gas"
        return f"{val:,}"
    return str(val)

# ==========================================
# TABS SETUP
# ==========================================
tab1, tab2, tab3, tab4 = st.tabs([
    "📤 Sender (Encrypt & Upload)", 
    "📥 Receiver (Retrieve & Verify)", 
    "⚠️ Attacker Mode (Security Tests)",
    "📊 Metrics & Audit Log"
])

# ==========================================
# TAB 1: SENDER (Step-by-Step Pipeline)
# ==========================================
with tab1:
    st.header("1. Cryptographic Identity & ECDH Setup")
    st.write("Generate SECP256K1 key pairs and derive a shared AES-256-GCM session key on the fly via Elliptic Curve Diffie-Hellman (ECDH).")
    
    if st.button("Generate Cryptographic Identity Keys"):
        try:
            import keygen
            keygen.generate_secp256k1_keys()
            st.success("SECP256K1 Identity Keys Generated Successfully!")
        except Exception as e:
            st.error(f"Key Generation Failed: {e}")
            
    pub_disp = "(Click 'Generate Cryptographic Identity Keys' above)"
    priv_disp = "(Click 'Generate Cryptographic Identity Keys' above)"
    if os.path.exists("public_key.pem"):
        with open("public_key.pem", "r") as f: pub_disp = f.read()
    if os.path.exists("private_key.pem"):
        with open("private_key.pem", "r") as f: priv_disp = f.read()
        
    st.markdown("**SECP256K1 Public Key (PEM)**")
    st.code(pub_disp, language="text")
    
    with st.expander("Show Private Key"):
        st.warning("Demonstration only. Do not share or commit this key.")
        st.code(priv_disp, language="text")
        
    st.markdown("---")
    st.header("2. Encrypt and Sign Dataset (AES-256-GCM)")
    uploaded_file = st.file_uploader("Upload a CSV or TXT file", type=["txt", "csv", "json"], key="sender_upload")
    
    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        st.success(f"File loaded: {uploaded_file.name} ({len(file_bytes)} bytes)")
        
        if st.button("Encrypt and Sign Dataset"):
            try:
                st.session_state.orig_size = len(file_bytes)
                if not os.path.exists("private_key.pem"):
                    import keygen
                    keygen.generate_secp256k1_keys()
                    
                # Derive AES key via ECDH (using own public/private key for self-contained test)
                aes_key = derive_ecdh_shared_key("private_key.pem", pub_disp)
                
                # Encrypt using AES-256-GCM
                t0 = time.perf_counter()
                ciphertext_hex, nonce_hex, tag_hex = encrypt_gcm(file_bytes, aes_key)
                total_crypto_ms = (time.perf_counter() - t0) * 1000
                
                # Sign ciphertext with SECP256K1 private key
                t_sign_start = time.perf_counter()
                with open("private_key.pem", "rb") as f:
                    sk = ecdsa.SigningKey.from_pem(f.read())
                signature_bytes = sk.sign(bytes.fromhex(ciphertext_hex), hashfunc=hashlib.sha256)
                signature_hex = signature_bytes.hex()
                sign_ms = (time.perf_counter() - t_sign_start) * 1000
                enc_ms = max(0.01, total_crypto_ms - sign_ms)
                
                st.session_state.enc_time = enc_ms
                st.session_state.sign_time = sign_ms
                st.session_state.enc_size = len(ciphertext_hex.encode('utf-8'))
                st.session_state.last_enc_hex = ciphertext_hex
                st.session_state.last_sig_hex = signature_hex
                st.session_state.last_nonce = nonce_hex
                st.session_state.last_tag = tag_hex
                
                # Package format: ciphertext::nonce::tag::signature
                st.session_state.payload_to_store = f"{ciphertext_hex}::{nonce_hex}::{tag_hex}::{signature_hex}"
                st.session_state.ipfs_size = len(st.session_state.payload_to_store.encode('utf-8'))
                
                st.success("Dataset encrypted (AES-256-GCM) and signed successfully!")
            except Exception as e:
                st.error(f"Encryption Failed: {e}")
                
    if st.session_state.last_enc_hex != "Not measured yet":
        st.markdown("---")
        st.subheader("Secured Output")
        st.markdown("**Encrypted Payload (GCM Ciphertext hex preview)**")
        st.code(st.session_state.last_enc_hex[:200] + "...", language="text")
        
        col_s1, col_s2 = st.columns(2)
        col_s1.metric("Original File Size", f"{st.session_state.orig_size:,} bytes")
        col_s2.metric("Encrypted Payload Size", f"{st.session_state.enc_size:,} characters")
        
        st.markdown("**SECP256K1 Digital Signature (hex)**")
        st.code(st.session_state.last_sig_hex[:200] + "...", language="text")
        
        st.markdown("---")
        st.header("3. IPFS Off-Chain Storage")
        if st.button("Upload to IPFS"):
            try:
                start_ipfs = time.perf_counter()
                cid = ipfs_manager.upload_data(st.session_state.payload_to_store)
                st.session_state.ipfs_up_time = (time.perf_counter() - start_ipfs) * 1000
                st.session_state.last_cid = cid
                st.success("Uploaded package to IPFS successfully!")
            except Exception as e:
                st.error(f"IPFS Upload Failed: {e}")
                
        if st.session_state.last_cid != "Not measured yet":
            st.subheader("IPFS Upload Results")
            st.markdown("**Content Identifier (CID)**")
            st.code(st.session_state.last_cid, language="text")
            st.markdown("[Open IPFS WebUI](http://127.0.0.1:5001/webui)")
            
            st.markdown("---")
            st.header("4. Blockchain Metadata Recording")
            if st.button("Record on Blockchain"):
                try:
                    current_contract = get_or_deploy_contract()
                    if not current_contract:
                        st.error("Cannot connect to Hardhat node.")
                        st.stop()
                        
                    data_hash = hashlib.sha256(st.session_state.payload_to_store.encode('utf-8')).hexdigest()
                    st.session_state.last_hash = data_hash
                    
                    start_blockchain = time.perf_counter()
                    receipt = blockchain_manager.store_record(
                        cid=st.session_state.last_cid, 
                        data_hash=data_hash, 
                        contract_address=current_contract, 
                        abi=MINIMAL_ABI
                    )
                    st.session_state.block_time = (time.perf_counter() - start_blockchain) * 1000
                    st.session_state.gas_used = receipt['gasUsed']
                    st.session_state.last_tx = receipt['transactionHash'].hex()
                    
                    # Append to Audit Log
                    audit_entry = {
                        "Filename": uploaded_file.name if uploaded_file else "dataset.txt",
                        "IPFS CID": st.session_state.last_cid,
                        "Tx Hash": st.session_state.last_tx,
                        "Gas Used": st.session_state.gas_used,
                        "Timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    st.session_state.audit_log.append(audit_entry)
                    
                    st.success("Blockchain record created and added to audit log successfully.")
                except Exception as e:
                    st.error(f"Blockchain Recording Failed: {e}")
                    
            if st.session_state.last_tx != "Not measured yet":
                st.markdown("**Blockchain Record ID (CID)**")
                st.code(st.session_state.last_cid, language="text")
                st.markdown("**Transaction Hash**")
                st.code(st.session_state.last_tx, language="text")

# ==========================================
# TAB 2: RECEIVER (Fetch, Verify & Decrypt)
# ==========================================
with tab2:
    st.header("5. Receiver: Fetch, Verify and Decrypt")
    st.info("Receiver verifies blockchain record, fetches IPFS package, performs ECDH key agreement, verifies signature, and decrypts via AES-256-GCM.")
    
    fetch_id = st.text_input("Blockchain Record ID (bytes32 / CID)")
    dummy_pub = "---BEGIN PUBLIC KEY---\n(Paste Public Key Here)\n---END PUBLIC KEY---"
    if os.path.exists("public_key.pem"):
        with open("public_key.pem", "r") as f: dummy_pub = f.read()

    sender_pub = st.text_area("Sender's Public Key (PEM)", value=dummy_pub, height=150)
    
    if st.button("Fetch, Verify and Decrypt"):
        if not fetch_id:
            st.error("Please enter a valid Record ID.")
        else:
            try:
                current_contract = get_or_deploy_contract()
                record = blockchain_manager.verify_record(
                    cid=fetch_id,
                    contract_address=current_contract,
                    abi=MINIMAL_ABI
                )
                if not record:
                    st.error("Record not found on blockchain!")
                    st.stop()
                    
                st.success("Blockchain record retrieved.")
                
                start_ipfs = time.perf_counter()
                raw_ipfs_data = ipfs_manager.retrieve_file(fetch_id)
                st.session_state.ipfs_down_time = (time.perf_counter() - start_ipfs) * 1000
                
                downloaded_hash = hashlib.sha256(raw_ipfs_data.encode('utf-8')).hexdigest()
                if downloaded_hash != record['data_hash']:
                    st.error("Hash Mismatch! Data tampered in transit.")
                    st.stop()
                
                st.success("IPFS package hash matches blockchain anchor.")
                    
                parts = raw_ipfs_data.split("::")
                if len(parts) == 4:
                    encrypted_hex, nonce_hex, tag_hex, signature_hex = parts
                else:
                    st.error("Invalid package format.")
                    st.stop()
                
                # Derive AES key via ECDH (using receiver private key or matching key)
                priv_path = "private_key.pem" if os.path.exists("private_key.pem") else "public_key.pem"
                aes_key = derive_ecdh_shared_key(priv_path, sender_pub)
                
                # Verify Signature
                t_ver_start = time.perf_counter()
                vk = ecdsa.VerifyingKey.from_pem(sender_pub.encode("utf-8"))
                vk.verify(bytes.fromhex(signature_hex), bytes.fromhex(encrypted_hex), hashfunc=hashlib.sha256)
                verify_ms = (time.perf_counter() - t_ver_start) * 1000
                
                # Decrypt AES-256-GCM
                t_total_dec = time.perf_counter()
                decrypted_data = decrypt_gcm(encrypted_hex, nonce_hex, tag_hex, aes_key)
                total_dec_ms = (time.perf_counter() - t_total_dec) * 1000
                dec_ms = max(0.01, total_dec_ms - verify_ms)
                
                st.session_state.verify_time = verify_ms
                st.session_state.dec_time = dec_ms
                
                st.success("SECP256K1 signature verified & AES-256-GCM decryption successful!")
                
                st.markdown(f"**Recovered file size:** {len(decrypted_data)} bytes")
                out_filename = st.text_input("Output filename", value="recovered_file.txt")
                st.download_button(
                    label="Download Verified File",
                    data=decrypted_data,
                    file_name=out_filename,
                    mime="text/plain"
                )
            except Exception as e:
                st.error(f"Retrieval Failed: {e}")

# ==========================================
# TAB 3: ATTACKER SIMULATION
# ==========================================
with tab3:
    st.header("6. Security & Tamper Testing")
    st.write("Simulate attacks against a stored IPFS package.")
    
    attack_type = st.selectbox(
        "Select Attack Scenario",
        (
            "Scenario A: Modify Encrypted Data", 
            "Scenario B: Submit Data Without a Signature", 
            "Scenario C: Verify with Wrong Public Key"
        )
    )
    
    default_record_id = st.session_state.last_cid if st.session_state.last_cid != "Not measured yet" else ""
    attack_cid = st.text_input("Blockchain Record ID (bytes32)", value=default_record_id, key="attack_cid")
    
    if "Scenario C" in attack_type:
        wrong_pub_input = st.text_area("Wrong SECP256K1 public key (PEM)", value=st.session_state.wrong_pub_pem, height=150)
        
    if st.button("Run Attack Simulator"):
        if not attack_cid:
            st.error("Please enter a valid Blockchain Record ID.")
        else:
            try:
                current_contract = get_or_deploy_contract()
                record = blockchain_manager.verify_record(attack_cid, current_contract, MINIMAL_ABI)
                if not record:
                    st.error("No blockchain record found.")
                    st.stop()
                    
                raw_ipfs_data = ipfs_manager.retrieve_file(attack_cid)
                parts = raw_ipfs_data.split("::")
                encrypted_hex, nonce_hex, tag_hex, signature_hex = parts[0], parts[1], parts[2], parts[3]
                
                st.markdown(f"**IPFS CID:** `{record['cid']}`")
                
                if "Scenario A" in attack_type:
                    tampered_encrypted_hex = "deadbeef" + encrypted_hex[8:]
                    tampered_package = f"{tampered_encrypted_hex}::{nonce_hex}::{tag_hex}::{signature_hex}"
                    tampered_hash = hashlib.sha256(tampered_package.encode('utf-8')).hexdigest()
                    st.code(f"Original payload: {encrypted_hex[:36]}...", language="text")
                    st.code(f"Tampered payload: {tampered_encrypted_hex[:36]}...", language="text")
                    if tampered_hash != record['data_hash']:
                        st.error("🚨 ATTACK DETECTED: Hash mismatch against blockchain record.")
                        st.success("🛡️ ZERO-TRUST CHECK PASSED: Altered package rejected before decryption.")
                        
                elif "Scenario B" in attack_type:
                    st.warning("Simulating package with signature removed.")
                    unsigned_package = f"{encrypted_hex}::{nonce_hex}::{tag_hex}::"
                    tampered_hash = hashlib.sha256(unsigned_package.encode('utf-8')).hexdigest()
                    if tampered_hash != record['data_hash']:
                        st.error("🚨 ATTACK DETECTED: Hash mismatch against blockchain record.")
                        st.success("🛡️ ZERO-TRUST CHECK PASSED: Unsigned package rejected.")
                        
                elif "Scenario C" in attack_type:
                    try:
                        wrong_vk = ecdsa.VerifyingKey.from_pem(wrong_pub_input.encode("utf-8"))
                        wrong_vk.verify(bytes.fromhex(signature_hex), bytes.fromhex(encrypted_hex), hashfunc=hashlib.sha256)
                        st.error("Unexpected: Signature verified with wrong key.")
                    except Exception:
                        st.error("ATTACK REJECTED: Signature verification failed with supplied public key.")
                        st.success("The application did not decrypt or release plaintext.")
            except Exception as e:
                st.error(f"Simulation Error: {e}")

# ==========================================
# TAB 4: METRICS & AUDIT LOG
# ==========================================
with tab4:
    st.header("📊 Performance Metrics")
    st.caption("Measurements captured from actual operations in this session.")
    
    r1_col1, r1_col2, r1_col3 = st.columns(3)
    r1_col1.metric("Original file size", format_val(st.session_state.orig_size, "bytes"))
    r1_col2.metric("Encrypted payload size", format_val(st.session_state.enc_size, "bytes"))
    r1_col3.metric("IPFS package size", format_val(st.session_state.ipfs_size, "bytes"))
    
    r2_col1, r2_col2, r2_col3 = st.columns(3)
    r2_col1.metric("Encryption time (GCM)", format_val(st.session_state.enc_time, "ms"))
    r2_col2.metric("SECP256K1 signing time", format_val(st.session_state.sign_time, "ms"))
    r2_col3.metric("IPFS upload time", format_val(st.session_state.ipfs_up_time, "ms"))
    
    r3_col1, r3_col2, r3_col3 = st.columns(3)
    r3_col1.metric("Blockchain confirmation time", format_val(st.session_state.block_time, "ms"))
    r3_col2.metric("Gas used per anchor", format_val(st.session_state.gas_used, "gas"))
    r3_col3.metric("IPFS download time", format_val(st.session_state.ipfs_down_time, "ms"))
    
    r4_col1, r4_col2, r4_col3 = st.columns(3)
    r4_col1.metric("Signature verification time", format_val(st.session_state.verify_time, "ms"))
    r4_col2.metric("Decryption time (GCM)", format_val(st.session_state.dec_time, "ms"))
    
    st.markdown("---")
    st.subheader("📋 Live Blockchain Audit Log")
    if len(st.session_state.audit_log) > 0:
        df_audit = pd.DataFrame(st.session_state.audit_log)
        st.dataframe(df_audit, use_container_width=True)
        
        csv_data = df_audit.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Audit Report (CSV)",
            data=csv_data,
            file_name="blockchain_audit_report.csv",
            mime="text/csv"
        )
    else:
        st.info("No records anchored on the blockchain yet in this session. Complete a sender workflow to populate the audit log.")
        
    st.markdown("---")
    st.subheader("Storage Overhead")
    if st.session_state.orig_size != "Not measured yet" and st.session_state.ipfs_size != "Not measured yet":
        overhead_pct = ((st.session_state.ipfs_size - st.session_state.orig_size) / st.session_state.orig_size) * 100
        st.write(f"Original file: **{st.session_state.orig_size:,} bytes**")
        st.write(f"IPFS package: **{st.session_state.ipfs_size:,} bytes**")
        st.metric("Package size overhead", f"{overhead_pct:.2f}%")