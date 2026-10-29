"""Benchmark experiment matrix and CSV schema for the paper.

This script creates a repeatable run plan, not fabricated performance results.
Run it to generate benchmark_plan.csv; populate observed metrics only after
running the actual application under the recorded conditions.
"""
import csv
from pathlib import Path

FILE_SIZES_BYTES = [1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024]
RECIPIENT_COUNTS = [1, 2, 5, 10]
TRIALS = 30

FIELDS = [
    "trial_id", "timestamp_utc", "git_commit", "os", "cpu", "ram_gb",
    "python_version", "file_size_bytes", "recipient_count", "operation",
    "elapsed_ms", "throughput_mib_s", "package_size_bytes", "storage_overhead_pct",
    "gas_used", "gas_price_wei", "tx_cost_native", "outcome", "notes",
]


def main(output="benchmark_plan.csv"):
    rows = []
    for size in FILE_SIZES_BYTES:
        for recipients in RECIPIENT_COUNTS:
            for operation in (
                "encrypt", "sign", "ipfs_upload", "anchor", "ipfs_download",
                "signature_verify", "hash_verify", "decrypt", "end_to_end",
            ):
                for trial in range(1, TRIALS + 1):
                    row = {field: "" for field in FIELDS}
                    row.update({
                        "trial_id": f"{size}-{recipients}-{operation}-{trial}",
                        "file_size_bytes": size,
                        "recipient_count": recipients,
                        "operation": operation,
                        "notes": "Plan row only; fill with measured values after execution.",
                    })
                    rows.append(row)
    with Path(output).open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} planned trials to {output}; no measurements were invented.")


if __name__ == "__main__":
    main()
