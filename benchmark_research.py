"""Repeatable local benchmark for the risk-policy contribution.

Run from the project root with its virtual environment active:
    python benchmark_research.py --iterations 5000
This measures synthetic policy-classification latency/detection rate. Gas values are
reported only when supplied a real transaction receipt JSON captured from Hardhat.
It does not claim synthetic results represent real-world attack detection.
"""
import argparse, json, statistics, time
from pathlib import Path
from backend import audit_policy

CASES = [
    ("valid", "Package format", "PASS", "valid package"),
    ("invalid_signature", "Sender signature", "FAIL", "signature verification failed"),
    ("commitment_change", "Blockchain commitment", "FAIL", "SHA-256 mismatch"),
    ("wrong_recipient", "Recipient binding", "FAIL", "different recipient key"),
    ("ipfs_down", "IPFS retrieval", "ERROR", "IPFS unavailable"),
    ("chain_down", "Blockchain record", "ERROR", "blockchain unavailable"),
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--receipt-json", type=Path, help="Optional JSON with gasUsed and effectiveGasPrice from a real receipt")
    args = parser.parse_args()
    if args.iterations < 1: parser.error("--iterations must be >= 1")
    rows=[]; baseline_detected=0; risk_detected=0; base_times=[]; risk_times=[]
    for name, event_type, status, details in CASES:
        # Baseline is the current fail-closed verification outcome: all explicit FAIL/ERRORs detected.
        expected_attack = name != "valid"
        start=time.perf_counter()
        for _ in range(args.iterations):
            baseline = status in {"FAIL", "ERROR"}
        base_ms=(time.perf_counter()-start)*1000
        start=time.perf_counter()
        for _ in range(args.iterations):
            signals=audit_policy.classify_event(event_type, status, details)
            risk_detected += int(expected_attack and bool(signals))
        risk_ms=(time.perf_counter()-start)*1000
        baseline_detected += int(expected_attack and (status in {"FAIL","ERROR"}))
        rows.append({"case":name,"expected_attack":expected_attack,"baseline_detected":bool(status in {"FAIL","ERROR"}),"risk_signals":audit_policy.classify_event(event_type,status,details),"baseline_loop_ms":round(base_ms,4),"risk_policy_loop_ms":round(risk_ms,4),"risk_policy_mean_us":round(risk_ms*1000/args.iterations,4)})
    attacks=sum(1 for c in CASES if c[0] != "valid")
    result={"scope":"Synthetic benchmark only; not real-world validation", "iterations_per_case":args.iterations,
            "attack_cases":attacks,"baseline_detection_rate":baseline_detected/attacks,
            "risk_policy_detection_rate":risk_detected/(attacks*args.iterations),"cases":rows,
            "gas_cost":"Not measured: this benchmark performs no blockchain transactions."}
    if args.receipt_json and args.receipt_json.exists():
        receipt=json.loads(args.receipt_json.read_text())
        gas_used=int(receipt["gasUsed"])
        gas_price=int(receipt.get("effectiveGasPrice", receipt.get("gasPrice",0)))
        result["real_receipt_gas"]={"gas_used":gas_used,"gas_price_wei":gas_price,"cost_eth":gas_used*gas_price/10**18}
    print(json.dumps(result,indent=2))
if __name__ == "__main__": main()
