"""IPFS upload/retrieval helpers with explicit result reporting."""

import requests

IPFS_API = "http://127.0.0.1:5001"
REQUEST_TIMEOUT = (5, 30)


def upload_data(payload: str) -> str:
    """Upload a string payload and return its CID."""
    try:
        response = requests.post(
            f"{IPFS_API}/api/v0/add",
            files={"file": ("secure_payload.txt", payload.encode("utf-8"))},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        cid = data.get("Hash")
        if not cid:
            raise RuntimeError("IPFS response did not contain a CID.")
        return cid
    except requests.RequestException as exc:
        raise RuntimeError(f"IPFS upload failed: {exc}") from exc


def retrieve_file_bytes(cid: str) -> bytes:
    """Retrieve exact bytes for a CID. Do not decode before hashing."""
    if not cid or not cid.strip():
        raise ValueError("CID is required.")
    try:
        response = requests.post(
            f"{IPFS_API}/api/v0/cat",
            params={"arg": cid.strip()},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.content
    except requests.RequestException as exc:
        raise RuntimeError(f"IPFS retrieval failed for CID {cid!r}: {exc}") from exc


def retrieve_file(cid: str) -> str:
    """Compatibility wrapper for existing text-package callers."""
    return retrieve_file_bytes(cid).decode("utf-8")


def retrieve_file_result(cid: str):
    """Return explicit PASS/FAIL/ERROR for CID retrieval."""
    try:
        content = retrieve_file_bytes(cid)
        if not content:
            return {"status": "FAIL", "message": "IPFS returned an empty package."}
        return {
            "status": "PASS",
            "message": "Package retrieved from IPFS.",
            "content": content,
        }
    except ValueError as exc:
        return {"status": "FAIL", "message": str(exc)}
    except Exception as exc:
        return {"status": "ERROR", "message": str(exc)}
