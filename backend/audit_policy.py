"""24-hour rolling risk policy with exponential decay for historical failures.

This is a triage mechanism only. It never replaces or bypasses mandatory
cryptographic verification.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math
import time

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

HISTORY_WINDOW_HOURS = 24
HISTORY_HALF_LIFE_HOURS = 12
HISTORICAL_FAILURE_WEIGHT = 5
MAX_HISTORICAL_PENALTY = 30
REPEATED_FAILURE_THRESHOLD = 2.5
REPEATED_FAILURE_PENALTY = 15


def _parse_utc_timestamp(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def classify_event(event_type: str, status: str, details: str = "") -> list[str]:
    """Map a verification/audit event to risk signals."""
    text = f"{event_type} {details}".lower()
    status_text = str(status).upper()
    signals = []

    if "signature" in text and status_text in {"FAIL", "ERROR"}:
        signals.append("signature_invalid")
    if any(x in text for x in ("commitment", "hash mismatch", "sha-256")) and status_text == "FAIL":
        signals.append("commitment_changed")
    if any(x in text for x in ("recipient binding", "recipient key", "different recipient")) and status_text == "FAIL":
        signals.append("recipient_key_mismatch")
    if "replay" in text and status_text == "FAIL":
        signals.append("replay_detected")
    if "blockchain" in text and status_text == "ERROR":
        signals.append("blockchain_unavailable")
    if "ipfs" in text and status_text == "ERROR":
        signals.append("ipfs_unavailable")
    if any(x in text for x in ("no matching on-chain", "record missing", "invalid cid")) and status_text == "FAIL":
        signals.append("blockchain_record_missing")
    if status_text in {"FAIL", "ERROR"} and not signals:
        signals.append("verification_failure")
    return signals


def _historical_failure_weight(event: dict, now: datetime) -> float:
    """Weight an event inside the 24-hour window; newer failures weigh more."""
    timestamp = _parse_utc_timestamp(
        event.get("local_recorded_at") or event.get("verification_local_time")
    )
    if timestamp is None:
        return 0.0
    age_hours = (now - timestamp).total_seconds() / 3600.0
    if age_hours < 0 or age_hours > HISTORY_WINDOW_HOURS:
        return 0.0
    return math.pow(0.5, age_hours / HISTORY_HALF_LIFE_HOURS)


def assess_risk(
    current_events: list[dict],
    historical_events: list[dict] | None = None,
    *,
    now: datetime | None = None,
) -> dict:
    """Calculate an explainable risk score from current signals and recent history.

    Historical FAIL/ERROR events are limited to 24 hours and decay with a
    12-hour half-life. `now` is injectable for deterministic tests.
    """
    historical_events = historical_events or []
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    current_time = current_time.astimezone(timezone.utc)

    signals = []
    for event in current_events:
        signals.extend(
            classify_event(
                event.get("event_type", event.get("Check", "")),
                event.get("status", event.get("Result", "")),
                event.get("details", event.get("Details", "")),
            )
        )

    failures = [
        event for event in historical_events
        if str(event.get("verification_status", event.get("status", ""))).upper()
        in {"FAIL", "ERROR"}
    ]
    weighted_failures = sum(
        _historical_failure_weight(event, current_time) for event in failures
    )
    in_window_count = sum(
        1 for event in failures
        if _historical_failure_weight(event, current_time) > 0
    )

    current_signal_score = sum(WEIGHTS.get(s, 0) for s in set(signals))
    historical_penalty = min(
        MAX_HISTORICAL_PENALTY,
        max(0.0, weighted_failures - 1.0) * HISTORICAL_FAILURE_WEIGHT,
    )
    repeated = weighted_failures >= REPEATED_FAILURE_THRESHOLD
    repeated_penalty = REPEATED_FAILURE_PENALTY if repeated else 0

    score = min(100, int(round(
        current_signal_score + historical_penalty + repeated_penalty
    )))
    if repeated:
        signals.append("repeated_failures")

    level = "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    priority = sorted(
        set(signals), key=lambda signal: WEIGHTS.get(signal, 20), reverse=True
    )
    return {
        "risk_score": score,
        "risk_level": level,
        "priority_signals": priority,
        "historical_failure_count": in_window_count,
        "weighted_historical_failures": round(weighted_failures, 3),
        "historical_penalty": int(round(historical_penalty)),
        "repeated_failures": repeated,
        "history_window_hours": HISTORY_WINDOW_HOURS,
        "history_half_life_hours": HISTORY_HALF_LIFE_HOURS,
        "interpretation": (
            "Triage score only. Historical FAIL/ERROR events are counted within "
            "a 24-hour rolling window and decay with a 12-hour half-life. All "
            "required cryptographic checks remain mandatory regardless of score."
        ),
    }


def synthetic_policy_benchmark(iterations: int = 1000) -> dict:
    """Benchmark signal classification only, not full-chain attack detection."""
    if iterations < 0:
        raise ValueError("iterations must be non-negative")
    samples = [
        {"event_type": "Sender signature", "status": "FAIL", "details": "Signature verification failed"},
        {"event_type": "Blockchain commitment", "status": "FAIL", "details": "SHA-256 mismatch"},
        {"event_type": "IPFS retrieval", "status": "ERROR", "details": "IPFS unavailable"},
        {"event_type": "Recipient binding", "status": "FAIL", "details": "different recipient key"},
    ]
    start = time.perf_counter()
    detected = 0
    for index in range(iterations):
        sample = samples[index % len(samples)]
        detected += bool(classify_event(sample["event_type"], sample["status"], sample["details"]))
    elapsed_ms = (time.perf_counter() - start) * 1000
    return {
        "iterations": iterations,
        "synthetic_signals_detected": detected,
        "synthetic_detection_rate": detected / iterations if iterations else 0,
        "total_policy_time_ms": elapsed_ms,
        "mean_policy_time_ms": elapsed_ms / iterations if iterations else 0,
        "scope": "Synthetic policy-classification microbenchmark only; not measured end-to-end attack detection.",
    }
