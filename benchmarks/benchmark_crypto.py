#!/usr/bin/env python3
"""AES-256-GCM benchmark using the project's backend.crypto_engine helpers."""
from __future__ import annotations
import argparse, csv, os, platform, statistics, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.crypto_engine import encrypt_gcm, decrypt_gcm

SIZES = [1, 5, 10, 25]  # MiB
REPEATS = 10
WARMUPS = 1

def percentile(values, p):
    values = sorted(values)
    if len(values) == 1: return values[0]
    pos = (len(values) - 1) * p / 100
    lo, hi = int(pos), min(int(pos) + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (pos - lo)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=REPEATS)
    ap.add_argument("--sizes", default="1,5,10,25", help="Comma-separated sizes in MiB")
    args = ap.parse_args()
    if args.repeats < 2: ap.error("--repeats must be >= 2")
    out = ROOT / "benchmarks" / "results" / "crypto.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for mib in map(int, args.sizes.split(",")):
        data, key = os.urandom(mib * 1024 * 1024), os.urandom(32)
        enc, dec = [], []
        for i in range(args.repeats + WARMUPS):
            t = time.perf_counter()
            package = encrypt_gcm(data, key)
            enc_ms = (time.perf_counter() - t) * 1000
            t = time.perf_counter()
            recovered = decrypt_gcm(package, key)
            dec_ms = (time.perf_counter() - t) * 1000
            if recovered != data: raise RuntimeError("Decrypted bytes differ from input")
            if i >= WARMUPS: enc.append(enc_ms); dec.append(dec_ms)
        mb = len(data) / (1024 * 1024)
        rows.append({
            "file_size_mib": mib, "repeats": args.repeats,
            "encrypt_mean_ms": statistics.mean(enc), "encrypt_median_ms": statistics.median(enc),
            "encrypt_p95_ms": percentile(enc,95), "encrypt_p99_ms": percentile(enc,99),
            "decrypt_mean_ms": statistics.mean(dec), "decrypt_median_ms": statistics.median(dec),
            "decrypt_p95_ms": percentile(dec,95), "decrypt_p99_ms": percentile(dec,99),
            "encrypt_throughput_mib_s": mb / (statistics.mean(enc)/1000),
            "decrypt_throughput_mib_s": mb / (statistics.mean(dec)/1000),
            "integrity_check": "PASS"
        })
        print(f"{mib} MiB | enc {statistics.mean(enc):.2f} ms | dec {statistics.mean(dec):.2f} ms | integrity PASS")
    with out.open("w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(f"\nSaved: {out}")

if __name__ == "__main__": main()
