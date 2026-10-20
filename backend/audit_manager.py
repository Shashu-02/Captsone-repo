"""Shared, persistent audit log for the split Sender and Receiver apps.

CSV reports are integrity-checkable against a separately exported JSON manifest.
The manifest hash is not a digital signature; keep the manifest in a trusted location.
"""
from __future__ import annotations
import csv, hashlib, io, json, sqlite3
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "backend" / "audit_log.sqlite3"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
FIELDS = ["event_id", "event_type", "verification_status", "cid", "package_sha256",
          "block_number", "blockchain_timestamp_utc", "local_recorded_at",
          "verification_local_time", "transaction_hash", "details"]

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""CREATE TABLE IF NOT EXISTS audit_events (
        event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
        verification_status TEXT NOT NULL, cid TEXT NOT NULL DEFAULT '',
        package_sha256 TEXT NOT NULL DEFAULT '', block_number INTEGER,
        blockchain_timestamp_utc TEXT NOT NULL DEFAULT '', local_recorded_at TEXT NOT NULL,
        verification_local_time TEXT NOT NULL DEFAULT '', transaction_hash TEXT NOT NULL DEFAULT '',
        details TEXT NOT NULL DEFAULT '')""")
    con.execute("""CREATE TABLE IF NOT EXISTS consumed_transfers (
        transfer_id TEXT PRIMARY KEY, cid TEXT NOT NULL DEFAULT '', consumed_at_utc TEXT NOT NULL
    )""")
    con.commit()
    return con

def record_event(*, event_id, event_type, status, cid="", package_sha256="", block_number=None,
                 blockchain_timestamp_utc="", verification_local_time="", transaction_hash="", details=""):
    """Insert once per event_id. Returns False if the event was already recorded."""
    con = _connect()
    try:
        cur = con.execute("""INSERT OR IGNORE INTO audit_events
            (event_id,event_type,verification_status,cid,package_sha256,block_number,
             blockchain_timestamp_utc,local_recorded_at,verification_local_time,transaction_hash,details)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (str(event_id), str(event_type), str(status), str(cid or ""), str(package_sha256 or ""),
             int(block_number) if block_number is not None else None, str(blockchain_timestamp_utc or ""),
             utc_now(), str(verification_local_time or ""), str(transaction_hash or ""), str(details or "")))
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()

def list_events(limit=5000):
    con = _connect()
    try:
        rows = con.execute("SELECT * FROM audit_events ORDER BY local_recorded_at DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()

def anchor_metadata_for_cid(cid):
    """Return block metadata previously captured from the anchoring receipt, if available."""
    con = _connect()
    try:
        row = con.execute("""SELECT block_number,blockchain_timestamp_utc,transaction_hash
            FROM audit_events WHERE cid=? AND event_type='BLOCKCHAIN_ANCHOR' AND verification_status='PASS'
            ORDER BY local_recorded_at DESC LIMIT 1""", (str(cid),)).fetchone()
        return dict(row) if row else {}
    finally:
        con.close()

def export_csv_bytes():
    rows = list(reversed(list_events()))
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")

def build_manifest(csv_bytes):
    return {"format": "secure-storage-audit-report-v1", "sha256": hashlib.sha256(csv_bytes).hexdigest(),
            "bytes": len(csv_bytes), "created_at_utc": utc_now(),
            "note": "Integrity checksum only, not a digital signature or proof of author identity."}

def verify_report(csv_bytes, manifest_bytes):
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        if manifest.get("format") != "secure-storage-audit-report-v1":
            return {"status":"FAIL", "message":"Unsupported or invalid manifest format."}
        actual = hashlib.sha256(csv_bytes).hexdigest()
        if actual != manifest.get("sha256") or len(csv_bytes) != int(manifest.get("bytes", -1)):
            return {"status":"FAIL", "message":"CSV checksum or byte length does not match the manifest.", "actual_sha256":actual}
        # Ensure the report itself is readable CSV with the expected columns.
        header = next(csv.reader(io.StringIO(csv_bytes.decode("utf-8"))), [])
        if header != FIELDS:
            return {"status":"FAIL", "message":"CSV columns do not match the expected audit schema."}
        return {"status":"PASS", "message":"CSV matches the supplied manifest checksum and schema.", "actual_sha256":actual}
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, StopIteration) as exc:
        return {"status":"ERROR", "message":f"Could not verify report: {exc}"}

def transfer_was_consumed(transfer_id: str) -> bool:
    """Return True when this unique transfer ID has already been successfully consumed."""
    if not transfer_id:
        return False
    con = _connect()
    try:
        row = con.execute("SELECT 1 FROM consumed_transfers WHERE transfer_id=?", (str(transfer_id),)).fetchone()
        return row is not None
    finally:
        con.close()

def mark_transfer_consumed(transfer_id: str, cid: str = "") -> bool:
    """Atomically mark a transfer as consumed once; False means it was already used."""
    if not transfer_id:
        raise ValueError("transfer_id is required")
    con = _connect()
    try:
        cur = con.execute("INSERT OR IGNORE INTO consumed_transfers (transfer_id,cid,consumed_at_utc) VALUES (?,?,?)",
                          (str(transfer_id), str(cid or ""), utc_now()))
        con.commit()
        return cur.rowcount == 1
    finally:
        con.close()

def render_audit_ui(st, app_label):
    import pandas as pd
    st.divider()
    st.header("Audit log and report verification")
    rows = list_events()
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No audit events recorded yet. Sender and Receiver events will appear here once actions are performed.")
    csv_bytes = export_csv_bytes()
    manifest_bytes = json.dumps(build_manifest(csv_bytes), indent=2).encode("utf-8")
    c1, c2 = st.columns(2)
    c1.download_button("Download audit CSV", csv_bytes, file_name=f"{app_label.lower()}_audit.csv", mime="text/csv")
    c2.download_button("Download report manifest", manifest_bytes, file_name=f"{app_label.lower()}_audit_manifest.json", mime="application/json")
    st.subheader("Verify an exported audit report")
    csv_upload = st.file_uploader("Upload audit CSV", type=["csv"], key=f"{app_label}_audit_csv_verify")
    manifest_upload = st.file_uploader("Upload matching JSON manifest", type=["json"], key=f"{app_label}_audit_manifest_verify")
    if st.button("Verify audit report", key=f"{app_label}_verify_audit_report"):
        if csv_upload is None or manifest_upload is None:
            st.warning("Upload both the CSV and its matching JSON manifest.")
        else:
            result = verify_report(csv_upload.getvalue(), manifest_upload.getvalue())
            if result["status"] == "PASS": st.success(f"PASS — {result['message']} SHA-256: {result.get('actual_sha256','')}")
            elif result["status"] == "FAIL": st.error(f"FAIL — {result['message']}")
            else: st.warning(f"ERROR — {result['message']}")
            st.caption("A checksum detects changes only when the matching manifest is trusted. It is not a digital signature.")
