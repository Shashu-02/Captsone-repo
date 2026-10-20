"""Risk-based prioritization for secure-storage verification events.

This policy prioritizes investigation; it never substitutes for cryptographic checks.
"""
from __future__ import annotations
from collections import Counter

WEIGHTS = {
    "signature_invalid": 50,
    "commitment_changed": 45,
    "blockchain_record_missing": 35,
    "recipient_key_mismatch": 30,
    "replay_detected": 30,
    "ipfs_unavailable": 15,
    "blockchain_unavailable": 15,
    "verification_failure": 10,
}


def classify_event(event_type: str, status: str, details: str = "") -> list[str]:
    """Map a verification/audit event to risk signals based on explicit indicators."""
    text = f"{event_type} {details}".lower()
    signals = []
    if "signature" in text and status.upper() in {"FAIL", "ERROR"}:
        signals.append("signature_invalid")
    if any(x in text for x in ("commitment", "hash mismatch", "sha-256")) and status.upper() == "FAIL":
        signals.append("commitment_changed")
    if any(x in text for x in ("recipient binding", "recipient key", "different recipient")) and status.upper() == "FAIL":
        signals.append("recipient_key_mismatch")
    if "replay" in text and status.upper() == "FAIL":
        signals.append("replay_detected")
    if "blockchain" in text and status.upper() == "ERROR":
        signals.append("blockchain_unavailable")
    if "ipfs" in text and status.upper() == "ERROR":
        signals.append("ipfs_unavailable")
    if any(x in text for x in ("no matching on-chain", "record missing", "invalid cid")) and status.upper() == "FAIL":
        signals.append("blockchain_record_missing")
    if status.upper() in {"FAIL", "ERROR"} and not signals:
        signals.append("verification_failure")
    return signals


def assess_risk(current_events: list[dict], historical_events: list[dict] | None = None) -> dict:
    """Return score, level, prioritized signals, and explanation.

    Repeated failures increase risk. This is an explainable triage score, not a probability.
    """
    historical_events = historical_events or []
    signals = []
    for event in current_events:
        signals.extend(classify_event(event.get("event_type", event.get("Check", "")),
                                      event.get("status", event.get("Result", "")),
                                      event.get("details", event.get("Details", ""))))
    history_failures = [e for e in historical_events if str(e.get("verification_status", "")).upper() in {"FAIL", "ERROR"}]
    counts = Counter(signals)
    repeated = len(history_failures) >= 3
    score = min(100, sum(WEIGHTS.get(s, 0) for s in set(signals)) + min(30, max(0, len(history_failures)-1)*5))
    if repeated:
        score = min(100, score + 15)
        signals.append("repeated_failures")
    level = "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    priority = sorted(set(signals), key=lambda s: WEIGHTS.get(s, 20), reverse=True)
    return {"risk_score": score, "risk_level": level, "priority_signals": priority,
            "historical_failure_count": len(history_failures), "repeated_failures": repeated,
            "interpretation": "Triage score only; all required cryptographic checks remain mandatory."}


def synthetic_policy_benchmark(iterations: int = 1000) -> dict:
    """Microbenchmark policy classification only; not a full-chain detection benchmark."""
    import time
    samples = [
        {"event_type": "Sender signature", "status": "FAIL", "details": "Signature verification failed"},
        {"event_type": "Blockchain commitment", "status": "FAIL", "details": "SHA-256 mismatch"},
        {"event_type": "IPFS retrieval", "status": "ERROR", "details": "IPFS unavailable"},
        {"event_type": "Recipient binding", "status": "FAIL", "details": "different recipient key"},
    ]
    start = time.perf_counter()
    detected = 0
    for i in range(iterations):
        sample = samples[i % len(samples)]
        detected += bool(classify_event(sample["event_type"], sample["status"], sample["details"]))
    elapsed_ms = (time.perf_counter() - start) * 1000
    return {"iterations": iterations, "synthetic_signals_detected": detected,
            "synthetic_detection_rate": detected / iterations if iterations else 0,
            "total_policy_time_ms": elapsed_ms,
            "mean_policy_time_ms": elapsed_ms / iterations if iterations else 0,
            "scope": "Synthetic policy-classification microbenchmark only; not measured end-to-end attack detection."}
