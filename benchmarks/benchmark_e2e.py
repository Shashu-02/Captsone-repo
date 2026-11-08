#!/usr/bin/env python3
"""Service-layer end-to-end benchmark: encrypt/sign -> IPFS -> chain -> retrieve/verify/decrypt.

Uses fresh ephemeral test identities and does not touch production private keys,
accounts, trust registry, audit DB, or application data. Calls local IPFS and the
local Hardhat contract directly; it intentionally excludes FastAPI auth/API and
Streamlit browser overhead.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os,statistics,sys,time,uuid
from pathlib import Path
import ecdsa
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from web3 import Web3

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.ipfs_manager import upload_data,retrieve_file_bytes
from backend.package_verification import canonical_package_fields,verify_sender_signature
from backend.trusted_keys import fingerprint

ARTIFACT=ROOT/"blockchain"/"artifacts"/"contracts"/"DataStorage.sol"/"DataStorage.json"
ADDRESS_FILE=ROOT/"backend"/"contract_address.txt"

def derive(sk,vk):
    shared=(sk.privkey.secret_multiplier*vk.pubkey.point).x().to_bytes(32,"big")
    return HKDF(master=shared,key_len=32,salt=None,hashmod=SHA256,context=b"secure-off-chain-storage/v1")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repeats",type=int,default=3)
    ap.add_argument("--sizes",default="1,5,10",help="MiB; stay below the configured API upload cap if later testing via API")
    args=ap.parse_args()
    if args.repeats<2:ap.error("--repeats must be >= 2")
    if not ARTIFACT.is_file() or not ADDRESS_FILE.is_file():
        raise SystemExit("Contract artifact/address missing. Compile and deploy the local DataStorage contract first.")
    w3=Web3(Web3.HTTPProvider("http://127.0.0.1:8545",request_kwargs={"timeout":30}))
    if not w3.is_connected() or w3.eth.chain_id!=31337:
        raise SystemExit("Local Hardhat RPC on chain 31337 is required.")
    art=json.loads(ARTIFACT.read_text())
    contract=w3.eth.contract(address=Web3.to_checksum_address(ADDRESS_FILE.read_text().strip()),abi=art["abi"])
    sender_account=w3.eth.accounts[0]
    sender_ecdh=ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    sender_sign=ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    receiver_ecdh=ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    receiver_fp=hashlib.sha256(receiver_ecdh.get_verifying_key().to_pem()).hexdigest()
    sender_pub_pem=sender_sign.get_verifying_key().to_pem().decode()
    # Temporary trust-store file used only by this script.
    import tempfile
    td=tempfile.TemporaryDirectory(prefix="capstone-e2e-trust-")
    trust_path=Path(td.name)/"trusted.json"
    trust_path.write_text(json.dumps({"BENCH_SENDER":{"fingerprint":fingerprint(sender_pub_pem),"public_key_pem":sender_pub_pem}}))
    rows=[]
    try:
        for mib in map(int,args.sizes.split(",")):
            totals=[]; encs=[]; signs=[]; uploads=[]; anchors=[]; downloads=[]; verifies=[]; decrypts=[]
            for n in range(args.repeats):
                plaintext=os.urandom(mib*1024*1024)
                aes_key=os.urandom(32)
                t=time.perf_counter()
                nonce=os.urandom(12); cipher=AES.new(aes_key,AES.MODE_GCM,nonce=nonce)
                ciphertext,tag=cipher.encrypt_and_digest(plaintext)
                wrap_key=derive(sender_ecdh,receiver_ecdh.get_verifying_key())
                wrap_nonce=os.urandom(12); wc=AES.new(wrap_key,AES.MODE_GCM,nonce=wrap_nonce)
                wrapped,wrap_tag=wc.encrypt_and_digest(aes_key)
                encs.append((time.perf_counter()-t)*1000)
                package={"version":1,"algorithm":"AES-256-GCM","transfer_id":uuid.uuid4().hex,
                    "sender_username":"BENCH_SENDER","ciphertext":ciphertext.hex(),"nonce":nonce.hex(),"tag":tag.hex(),
                    "recipient_keys":[{"fingerprint":receiver_fp,"wrapped_key":wrapped.hex(),"wrap_nonce":wrap_nonce.hex(),"wrap_tag":wrap_tag.hex()}],
                    "sender_ecdh_public":sender_ecdh.get_verifying_key().to_pem().decode(),
                    "original_filename":f"benchmark-{mib}MiB.bin"}
                t=time.perf_counter()
                signature=sender_sign.sign(canonical_package_fields(package),hashfunc=hashlib.sha256)
                signs.append((time.perf_counter()-t)*1000)
                package["signature"]=signature.hex();package["sender_signing_public"]=sender_pub_pem
                serialized=json.dumps(package,sort_keys=True,separators=(",",":"))
                digest=hashlib.sha256(serialized.encode()).hexdigest()
                t=time.perf_counter();cid=upload_data(serialized);uploads.append((time.perf_counter()-t)*1000)
                t=time.perf_counter()
                tx=contract.functions.storeRecord(cid,digest).transact({"from":sender_account})
                receipt=w3.eth.wait_for_transaction_receipt(tx,timeout=60)
                anchors.append((time.perf_counter()-t)*1000)
                if receipt.status!=1:raise RuntimeError("Blockchain anchor transaction failed")
                t=time.perf_counter();downloaded=retrieve_file_bytes(cid);downloads.append((time.perf_counter()-t)*1000)
                if hashlib.sha256(downloaded).hexdigest()!=hashlib.sha256(serialized.encode()).hexdigest():
                    raise RuntimeError("Retrieved package digest mismatch")
                loaded=json.loads(downloaded.decode())
                t=time.perf_counter()
                if not verify_sender_signature(loaded,"BENCH_SENDER",trust_path):
                    raise RuntimeError("Sender signature verification failed")
                record=contract.functions.records(cid).call()
                if record[0]!=cid or record[1]!=digest:raise RuntimeError("Blockchain commitment verification failed")
                verifies.append((time.perf_counter()-t)*1000)
                t=time.perf_counter()
                env=next(x for x in loaded["recipient_keys"] if x["fingerprint"]==receiver_fp)
                wc=AES.new(derive(receiver_ecdh,sender_ecdh.get_verifying_key()),AES.MODE_GCM,nonce=bytes.fromhex(env["wrap_nonce"]))
                recovered_key=wc.decrypt_and_verify(bytes.fromhex(env["wrapped_key"]),bytes.fromhex(env["wrap_tag"]))
                dc=AES.new(recovered_key,AES.MODE_GCM,nonce=bytes.fromhex(loaded["nonce"]))
                recovered=dc.decrypt_and_verify(bytes.fromhex(loaded["ciphertext"]),bytes.fromhex(loaded["tag"]))
                decrypts.append((time.perf_counter()-t)*1000)
                if recovered!=plaintext:raise RuntimeError("Recovered plaintext differs from original")
                totals.append(sum([encs[-1],signs[-1],uploads[-1],anchors[-1],downloads[-1],verifies[-1],decrypts[-1]]))
                print(f"{mib} MiB run {n+1}/{args.repeats}: total {totals[-1]:.2f} ms | integrity PASS")
            rows.append({"file_size_mib":mib,"repeats":args.repeats,
                "encrypt_and_wrap_mean_ms":statistics.mean(encs),"sign_mean_ms":statistics.mean(signs),
                "ipfs_upload_mean_ms":statistics.mean(uploads),"blockchain_anchor_mean_ms":statistics.mean(anchors),
                "ipfs_retrieve_mean_ms":statistics.mean(downloads),"signature_and_chain_verify_mean_ms":statistics.mean(verifies),
                "unwrap_and_decrypt_mean_ms":statistics.mean(decrypts),"pipeline_sum_mean_ms":statistics.mean(totals),
                "end_to_end_throughput_mib_s":mib/(statistics.mean(totals)/1000),"integrity":"PASS"})
    finally:
        td.cleanup()
    out=ROOT/"benchmarks"/"results"/"e2e.csv";out.parent.mkdir(parents=True,exist_ok=True)
    with out.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print(f"\nSaved: {out}")
    print("Scope: crypto + local IPFS + local Hardhat contract. FastAPI auth/routes and Streamlit UI are excluded.")

if __name__=="__main__":main()
