# Security Risk Evaluation

- Dataset: 15 deterministic labelled synthetic scenarios
- Positive label: malicious or security-compromise scenario
- Negative label: legitimate operation or benign infrastructure/operational issue
- Policy: `backend.audit_policy.assess_risk()`
- Alert rule at threshold 25: MEDIUM or HIGH risk
- Threshold 50: HIGH risk only
- Fixed evaluation clock: 2026-11-08T12:00:00+00:00

## Metrics

| Threshold | TP | FP | TN | FN | Detection rate / Recall | False-positive rate | Precision | F1 | Accuracy |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 25 | 7 | 0 | 8 | 0 | 1.000 | 0.000 | 1.000 | 1.000 | 1.000 |
| 50 | 2 | 0 | 8 | 5 | 0.286 | 0.000 | 1.000 | 0.444 | 0.667 |

## Confusion-matrix definitions

- TP: malicious scenario correctly flagged.
- FP: benign scenario incorrectly flagged.
- TN: benign scenario correctly left below the alert threshold.
- FN: malicious scenario missed by the alert threshold.

## Scenario results

| Scenario | Actual | Score | Level | Signals |
|---|---:|---:|---|---|
| attack_signature_invalid | 1 | 50 | HIGH | signature_invalid |
| attack_commitment_changed | 1 | 45 | MEDIUM | commitment_changed |
| attack_missing_blockchain_record | 1 | 35 | MEDIUM | blockchain_record_missing |
| attack_wrong_recipient | 1 | 30 | MEDIUM | recipient_key_mismatch |
| attack_replay | 1 | 30 | MEDIUM | replay_detected |
| attack_repeated_failures | 1 | 40 | MEDIUM | repeated_failures;verification_failure |
| attack_mixed_signals | 1 | 95 | HIGH | signature_invalid;commitment_changed |
| normal_successful_transfer | 0 | 0 | LOW | none |
| normal_successful_transfer_2 | 0 | 0 | LOW | none |
| normal_successful_transfer_3 | 0 | 0 | LOW | none |
| normal_no_events | 0 | 0 | LOW | none |
| benign_ipfs_outage | 0 | 0 | LOW | none |
| benign_blockchain_outage | 0 | 0 | LOW | none |
| benign_generic_verification_error | 0 | 10 | LOW | verification_failure |
| benign_multiple_infrastructure_outages | 0 | 0 | LOW | none |

## Limitations

This is a deterministic synthetic policy evaluation, not a measurement of real attackers or production traffic. Results depend on the hand-labelled scenario mix and selected thresholds. The benign multi-service outage case intentionally checks whether operational availability errors can be mistaken for malicious activity. Increase and diversify the labelled dataset before making claims about real-world detection performance. Cryptographic verification must remain mandatory regardless of this triage score.
