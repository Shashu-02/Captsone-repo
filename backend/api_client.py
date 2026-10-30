"""HTTP client for Streamlit apps connecting to the central FastAPI server."""

import base64
import os

import requests

API_BASE_URL = os.environ.get(
    "CAPSTONE_API_URL",
    "http://127.0.0.1:8000",
).rstrip("/")

TIMEOUT_SECONDS = 12


class APIError(RuntimeError):
    pass


def request(method, path, token=None, **kwargs):
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        response = requests.request(
            method,
            API_BASE_URL + path,
            headers=headers,
            timeout=TIMEOUT_SECONDS,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise APIError(
            f"Cannot reach central API at {API_BASE_URL}. "
            "Check server and CAPSTONE_API_URL."
        ) from exc

    try:
        payload = response.json()
    except ValueError:
        payload = {"detail": response.text or f"HTTP {response.status_code}"}

    if not response.ok:
        raise APIError(str(payload.get("detail", payload)))

    return payload


def register(username, password, role):
    return request(
        "POST",
        "/api/register",
        json={
            "username": username,
            "password": password,
            "role": role,
        },
    )


def login(username, password):
    return request(
        "POST",
        "/api/login",
        json={
            "username": username,
            "password": password,
        },
    )


def me(token):
    return request("GET", "/api/me", token=token)


def list_receivers(token):
    return request("GET", "/api/peers/receivers", token=token)


def publish_receiver_key(token, public_pem):
    return request(
        "POST",
        "/api/peers/public-key",
        token=token,
        json={"ecdh_public_pem": public_pem},
    )


def admin_peers(token):
    return request("GET", "/api/admin/peers", token=token)


def review_peer(token, username, status):
    return request(
        "POST",
        f"/api/admin/peers/{username}/review",
        token=token,
        json={"status": status},
    )


def admin_events(token):
    return request("GET", "/api/admin/events", token=token)


def log_event(token, action, details=""):
    return request(
        "POST",
        "/api/events",
        token=token,
        json={
            "action": action,
            "details": details,
        },
    )


def upload_package(token, payload, recipients):
    """Upload an encrypted package through the central API."""

    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise TypeError("payload must be str or bytes")

    result = request(
        "POST",
        "/api/ipfs/upload",
        token=token,
        json={"payload_b64": base64.b64encode(payload_bytes).decode("ascii"), "recipients": list(recipients)},
    )

    return result["cid"]


def retrieve_package_result(token, cid):
    """Retrieve an encrypted package through the central API."""

    try:
        result = request(
            "GET",
            f"/api/ipfs/{cid}",
            token=token,
        )

        content = base64.b64decode(
            result["content_b64"],
            validate=True,
        )

        if not content:
            return {
                "status": "FAIL",
                "message": "IPFS returned an empty package.",
            }

        return {
            "status": "PASS",
            "message": "Package retrieved through central API.",
            "content": content,
        }

    except Exception as exc:
        return {
            "status": "ERROR",
            "message": str(exc),
        }


def anchor_blockchain_record(token, cid, data_hash):
    """Anchor a CID and SHA-256 hash through the central API."""
    return request(
        "POST",
        "/api/blockchain/anchor",
        token=token,
        json={
            "cid": cid,
            "data_hash": data_hash,
        },
    )


def verify_blockchain_record(token, cid):
    """Verify a CID against the central blockchain."""
    return request(
        "POST",
        "/api/blockchain/verify",
        token=token,
        json={"cid": cid},
    )
