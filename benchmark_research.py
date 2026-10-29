"""Synthetic microbenchmark for the audit-risk triage policy (not crypto performance).

Run from the repository root: python benchmark_research.py --iterations 10000
Outputs JSON to stdout. Results are policy classification timings only; they do not
measure end-to-end transfer latency, real attack detection, IPFS, or gas.
"""
import argparse
import json
import time
from backend import audit_policy

CASES = [
    ("valid", "Package format", "PASS", "valid package", False),
    ("invalid_signature", "Sender signature", "FAIL", "signature verification failed", True),
    ("commitment_change", "Blockchain commitment", "FAIL", "SHA-256 mismatch", True),
    ("wrong_recipient", "Recipient binding", "FAIL", "different recipient key", True),
    ("ipfs_down", "IPFS retrieval", "ERROR", "IPFS unavailable", True),
    ("chain_down", "Blockchain record", "ERROR", "blockchain unavailable", True),
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be >= 1")
    rows = []
    detected = 0
    attack_count = sum(int(case[4]) for case in CASES)
    for name, event_type, status, details, is_attack in CASES:
        start = time.perf_counter()
        signals = []
        for _ in range(args.iterations):
            signals = audit_policy.classify_event(event_type, status, details)
        elapsed_ms = (time.perf_counter() - start) * 1000
        detected_case = bool(is_attack and signals)
        detected += int(detected_case)
        rows.append({"case": name, "expected_attack": is_attack,
                     "risk_signals": signals, "detected_by_policy": detected_case,
                     "iterations": args.iterations, "total_ms": round(elapsed_ms, 4),
                     "mean_us": round(elapsed_ms * 1000 / args.iterations, 4)})
    print(json.dumps({"scope": "Synthetic policy-classification microbenchmark only",
        "iterations_per_case": args.iterations, "attack_cases": attack_count,
        "policy_signal_rate_on_synthetic_cases": detected / attack_count,
        "warning": "This is not a real-world detection rate and does not benchmark cryptography, IPFS, blockchain, or end-to-end transfer.",
        "cases": rows}, indent=2))
if __name__ == "__main__":
    main()
