#!/usr/bin/env python3
"""Evaluate backend.audit_policy against a deterministic labelled scenario set.

Run from the repository root:
    python benchmarks/evaluate_risk.py

This is a synthetic policy evaluation, not a production traffic measurement.
It writes per-scenario predictions and aggregate metrics under benchmarks/results/.
"""

from __future__ import annotations

import csv
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.audit_policy import assess_risk  # noqa: E402

RESULTS = ROOT / "benchmarks" / "results"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
DEFAULT_THRESHOLD = 25  # MEDIUM or HIGH risk


def event(event_type: str, status: str, details: str = "") -> dict:
    return {"event_type": event_type, "status": status, "details": details}


def history(count: int, age_minutes: int = 0) -> list[dict]:
    timestamp = (NOW - timedelta(minutes=age_minutes)).isoformat()
    return [
        {
            "event_type": "verification",
            "verification_status": "FAIL",
            "local_recorded_at": timestamp,
        }
        for _ in range(count)
    ]


def build_dataset() -> list[dict]:
    """Balanced labelled cases: attacks are positive; normal/degraded operations negative."""
    cases = [
        (
            "attack_signature_invalid",
            1,
            [event("Sender signature", "FAIL", "Signature verification failed")],
            [],
        ),
        (
            "attack_commitment_changed",
            1,
            [event("Blockchain commitment", "FAIL", "SHA-256 mismatch")],
            [],
        ),
        (
            "attack_missing_blockchain_record",
            1,
            [event("Blockchain verification", "FAIL", "No matching on-chain record")],
            [],
        ),
        (
            "attack_wrong_recipient",
            1,
            [event("Recipient binding", "FAIL", "Different recipient key")],
            [],
        ),
        (
            "attack_replay",
            1,
            [event("Replay protection", "FAIL", "Replay detected for transfer")],
            [],
        ),
        (
            "attack_repeated_failures",
            1,
            [event("Package verification", "FAIL", "Verification failed")],
            history(4),
        ),
        (
            "attack_mixed_signals",
            1,
            [
                event("Sender signature", "FAIL", "Signature verification failed"),
                event("Blockchain commitment", "FAIL", "SHA-256 mismatch"),
            ],
            [],
        ),
        (
            "normal_successful_transfer",
            0,
            [
                event("Sender signature", "PASS", "Signature verified"),
                event("Blockchain verification", "PASS", "Record verified"),
                event("Recipient binding", "PASS", "Recipient key matched"),
            ],
            [],
        ),
        (
            "normal_successful_transfer_2",
            0,
            [event("Package verification", "PASS", "All checks passed")],
            [],
        ),
        (
            "normal_successful_transfer_3",
            0,
            [event("IPFS retrieval", "PASS", "Package retrieved")],
            [],
        ),
        ("normal_no_events", 0, [], []),
        (
            "benign_ipfs_outage",
            0,
            [event("IPFS retrieval", "ERROR", "IPFS unavailable")],
            [],
        ),
        (
            "benign_blockchain_outage",
            0,
            [event("Blockchain connection", "ERROR", "Blockchain unavailable")],
            [],
        ),
        (
            "benign_generic_verification_error",
            0,
            [event("Package check", "ERROR", "Temporary local parsing issue")],
            [],
        ),
        (
            "benign_multiple_infrastructure_outages",
            0,
            [
                event("IPFS retrieval", "ERROR", "IPFS unavailable"),
                event("Blockchain connection", "ERROR", "Blockchain unavailable"),
            ],
            [],
        ),
    ]
    return [
        {
            "scenario": name,
            "label": label,
            "current_events": current,
            "historical_events": old,
        }
        for name, label, current, old in cases
    ]


def confusion(rows: list[dict], threshold: int) -> dict:
    tp = fp = tn = fn = 0
    for row in rows:
        predicted = int(row["risk_score"] >= threshold)
        actual = int(row["label"])
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif not actual and not predicted:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(rows) if rows else 0.0
    return {
        "threshold": threshold,
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": precision,
        "recall_detection_rate": recall,
        "specificity": specificity,
        "false_positive_rate": fpr,
        "f1_score": f1,
        "accuracy": accuracy,
        "total_cases": len(rows),
    }


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    evaluated = []
    for case in build_dataset():
        result = assess_risk(
            case["current_events"],
            case["historical_events"],
            now=NOW,
        )
        evaluated.append(
            {
                "scenario": case["scenario"],
                "label": case["label"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "predicted_risky_at_25": int(result["risk_score"] >= DEFAULT_THRESHOLD),
                "priority_signals": ";".join(result["priority_signals"]),
                "historical_failure_count": result["historical_failure_count"],
            }
        )

    csv_path = RESULTS / "risk_evaluation.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(evaluated[0]))
        writer.writeheader()
        writer.writerows(evaluated)

    metrics = [confusion(evaluated, threshold) for threshold in (25, 50)]
    report_path = RESULTS / "risk_evaluation_summary.md"
    lines = [
        "# Security Risk Evaluation",
        "",
        f"- Dataset: {len(evaluated)} deterministic labelled synthetic scenarios",
        "- Positive label: malicious or security-compromise scenario",
        "- Negative label: legitimate operation or benign infrastructure/operational issue",
        "- Policy: `backend.audit_policy.assess_risk()`",
        "- Alert rule at threshold 25: MEDIUM or HIGH risk",
        "- Threshold 50: HIGH risk only",
        "- Fixed evaluation clock: 2026-11-08T12:00:00+00:00",
        "",
        "## Metrics",
        "",
        "| Threshold | TP | FP | TN | FN | Detection rate / Recall | False-positive rate | Precision | F1 | Accuracy |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for m in metrics:
        lines.append(
            f"| {m['threshold']} | {m['true_positive']} | {m['false_positive']} | "
            f"{m['true_negative']} | {m['false_negative']} | "
            f"{m['recall_detection_rate']:.3f} | {m['false_positive_rate']:.3f} | "
            f"{m['precision']:.3f} | {m['f1_score']:.3f} | {m['accuracy']:.3f} |"
        )
    lines += [
        "",
        "## Confusion-matrix definitions",
        "",
        "- TP: malicious scenario correctly flagged.",
        "- FP: benign scenario incorrectly flagged.",
        "- TN: benign scenario correctly left below the alert threshold.",
        "- FN: malicious scenario missed by the alert threshold.",
        "",
        "## Scenario results",
        "",
        "| Scenario | Actual | Score | Level | Signals |",
        "|---|---:|---:|---|---|",
    ]
    for row in evaluated:
        lines.append(
            f"| {row['scenario']} | {row['label']} | {row['risk_score']} | "
            f"{row['risk_level']} | {row['priority_signals'] or 'none'} |"
        )
    lines += [
        "",
        "## Limitations",
        "",
        "This is a deterministic synthetic policy evaluation, not a measurement of real attackers "
        "or production traffic. Results depend on the hand-labelled scenario mix and selected "
        "thresholds. The benign multi-service outage case intentionally checks whether operational "
        "availability errors can be mistaken for malicious activity. Increase and diversify the "
        "labelled dataset before making claims about real-world detection performance. "
        "Cryptographic verification must remain mandatory regardless of this triage score.",
        "",
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Scenarios evaluated: {len(evaluated)}")
    for m in metrics:
        print(
            f"Threshold {m['threshold']}: TP={m['true_positive']} FP={m['false_positive']} "
            f"TN={m['true_negative']} FN={m['false_negative']} "
            f"Recall={m['recall_detection_rate']:.3f} FPR={m['false_positive_rate']:.3f} "
            f"Precision={m['precision']:.3f} F1={m['f1_score']:.3f}"
        )
    print(f"CSV: {csv_path.relative_to(ROOT)}")
    print(f"Report: {report_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
