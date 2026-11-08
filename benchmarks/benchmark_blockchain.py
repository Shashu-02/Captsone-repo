#!/usr/bin/env python3
"""Measure deployed DataStorage writes, gas, and read latency on local Hardhat."""
from __future__ import annotations
import argparse,csv,json,statistics,sys,time,uuid
from pathlib import Path
from web3 import Web3

ROOT=Path(__file__).resolve().parents[1]
ARTIFACT=ROOT/"blockchain"/"artifacts"/"contracts"/"DataStorage.sol"/"DataStorage.json"
ADDRESS_FILE=ROOT/"backend"/"contract_address.txt"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repeats",type=int,default=10)
    args=ap.parse_args()
    if args.repeats<2: ap.error("--repeats must be >= 2")
    if not ARTIFACT.is_file(): raise SystemExit(f"Missing compiled artifact: {ARTIFACT}\nRun: cd blockchain && npx hardhat compile")
    if not ADDRESS_FILE.is_file(): raise SystemExit(f"Missing contract address file: {ADDRESS_FILE}")
    address=ADDRESS_FILE.read_text().strip()
    artifact=json.loads(ARTIFACT.read_text())
    w3=Web3(Web3.HTTPProvider("http://127.0.0.1:8545",request_kwargs={"timeout":30}))
    if not w3.is_connected(): raise SystemExit("Hardhat RPC unavailable. Start `cd blockchain && npx hardhat node`.")
    if w3.eth.chain_id!=31337: raise SystemExit(f"Expected local chain 31337, got {w3.eth.chain_id}; refusing to benchmark another network.")
    contract=w3.eth.contract(address=Web3.to_checksum_address(address),abi=artifact["abi"])
    sender=w3.eth.accounts[0]
    writes=[]; reads=[]; gas=[]; costs=[]
    for i in range(args.repeats):
        cid="bench-"+uuid.uuid4().hex
        commitment=__import__("hashlib").sha256(uuid.uuid4().bytes).hexdigest()
        t=time.perf_counter()
        tx_hash=contract.functions.storeRecord(cid,commitment).transact({"from":sender})
        receipt=w3.eth.wait_for_transaction_receipt(tx_hash,timeout=60)
        writes.append((time.perf_counter()-t)*1000)
        if receipt.status!=1: raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
        gas.append(int(receipt.gasUsed))
        tx=w3.eth.get_transaction(tx_hash)
        effective=int(getattr(receipt,"effectiveGasPrice",None) or tx["gasPrice"])
        costs.append(gas[-1]*effective)
        t=time.perf_counter()
        record=contract.functions.records(cid).call()
        reads.append((time.perf_counter()-t)*1000)
        if record[0]!=cid or record[1]!=commitment: raise RuntimeError("On-chain read-back mismatch")
        print(f"{i+1}/{args.repeats} | write {writes[-1]:.2f} ms | gas {gas[-1]} | read {reads[-1]:.2f} ms")
    out=ROOT/"benchmarks"/"results"/"blockchain.csv";out.parent.mkdir(parents=True,exist_ok=True)
    row={"network":"Hardhat local chain 31337","contract":address,"repeats":args.repeats,
         "write_mean_ms":statistics.mean(writes),"write_median_ms":statistics.median(writes),
         "read_mean_ms":statistics.mean(reads),"read_median_ms":statistics.median(reads),
         "gas_mean":statistics.mean(gas),"gas_min":min(gas),"gas_max":max(gas),
         "transaction_cost_mean_wei":statistics.mean(costs),"readback_check":"PASS"}
    with out.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(row));w.writeheader();w.writerow(row)
    print(f"\nSaved: {out}\nMean gas: {statistics.mean(gas):.0f}; mean write: {statistics.mean(writes):.2f} ms")

if __name__=="__main__":main()
