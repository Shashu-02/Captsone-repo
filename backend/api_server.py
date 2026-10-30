"""LAN Admin API for the Secure Storage capstone.

Run from the project root:
  export CAPSTONE_API_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
  python -m uvicorn backend.api_server:app --host 0.0.0.0 --port 8000

This initial API uses the existing backend/auth_manager.py SQLite database.
For LAN development only: configure HTTPS before using over untrusted networks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from . import auth_manager, blockchain_manager, ipfs_manager

app = FastAPI(
    title="Secure Storage Admin API",
    version="0.1.0",
    description="Central registration, authentication and peer-key registry.",
)

TOKEN_TTL_SECONDS = 8 * 60 * 60


def _secret() -> bytes:
    value = os.environ.get("CAPSTONE_API_SECRET", "")
    if len(value) < 32:
        raise RuntimeError(
            "Set CAPSTONE_API_SECRET to a random secret of at least 32 characters."
        )
    return value.encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _issue_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    encoded = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64(
        hmac.new(_secret(), encoded.encode("ascii"), hashlib.sha256).digest()
    )
    return f"{encoded}.{signature}"


def _current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required.")
    token = authorization[7:].strip()
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected = _b64(
            hmac.new(_secret(), encoded.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected):
            raise ValueError("bad signature")
        payload = json.loads(_unb64(encoded))
        if int(payload["exp"]) < int(time.time()):
            raise ValueError("expired")
        username = str(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    user = auth_manager.get_user(username)
    if not user or user["status"] != "approved":
        raise HTTPException(
            status_code=403, detail="Account is not approved or was revoked."
        )
    return user


def _require_admin(user: dict[str, Any] = Depends(_current_user)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required.")
    return user


class Registration(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=10, max_length=256)
    role: str


class Login(BaseModel):
    username: str
    password: str


class PublicKeyPublication(BaseModel):
    ecdh_public_pem: str = Field(min_length=1, max_length=16000)


class ReviewRequest(BaseModel):
    status: str


class EventRequest(BaseModel):
    action: str = Field(min_length=1, max_length=100)
    details: str = Field(default="", max_length=500)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "secure-storage-admin-api"}


@app.post("/api/register", status_code=status.HTTP_201_CREATED)
def register(data: Registration) -> dict[str, str]:
    try:
        auth_manager.register_user(data.username, data.password, data.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "message": "Registration submitted. Administrator approval is required.",
        "status": "pending",
    }


@app.post("/api/login")
def login(data: Login) -> dict[str, Any]:
    user = auth_manager.authenticate(data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if user["status"] != "approved":
        raise HTTPException(
            status_code=403,
            detail=f"Account status: {user['status']}. Administrator approval is required.",
        )
    return {
        "access_token": _issue_token(user["username"]),
        "token_type": "bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "user": {
            "username": user["username"],
            "role": user["role"],
            "status": user["status"],
        },
    }


@app.get("/api/me")
def me(user: dict[str, Any] = Depends(_current_user)) -> dict[str, Any]:
    return user


@app.get("/api/peers/receivers")
def approved_receivers(
    user: dict[str, Any] = Depends(_current_user),
) -> list[dict[str, str]]:
    if user["role"] != "sender":
        raise HTTPException(
            status_code=403, detail="Only approved senders can list receivers."
        )
    return auth_manager.list_approved_receiver_public_keys()


@app.post("/api/peers/public-key")
def publish_receiver_key(
    data: PublicKeyPublication,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, str]:
    if user["role"] != "receiver":
        raise HTTPException(
            status_code=403, detail="Only receiver accounts can publish this key."
        )
    try:
        auth_manager.publish_receiver_public_key(user["username"], data.ecdh_public_pem)
        fingerprint = hashlib.sha256(data.ecdh_public_pem.encode("utf-8")).hexdigest()
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return {"message": "Receiver public key published.", "fingerprint": fingerprint}


@app.get("/api/admin/peers")
def admin_peers(
    admin: dict[str, Any] = Depends(_require_admin),
) -> list[dict[str, Any]]:
    return auth_manager.list_users()


@app.post("/api/admin/peers/{username}/review")
def review_peer(
    username: str,
    data: ReviewRequest,
    admin: dict[str, Any] = Depends(_require_admin),
) -> dict[str, str]:
    if data.status not in {"approved", "rejected", "revoked"}:
        raise HTTPException(status_code=400, detail="Invalid review status.")
    try:
        auth_manager.review_user(username, data.status, admin["username"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"username": username, "status": data.status}


@app.post("/api/events", status_code=status.HTTP_201_CREATED)
def create_event(
    data: EventRequest, user: dict[str, Any] = Depends(_current_user)
) -> dict[str, str]:
    auth_manager.log_event(user["username"], data.action, data.details)
    return {"message": "Event recorded."}


@app.get("/api/admin/events")
def admin_events(
    admin: dict[str, Any] = Depends(_require_admin),
) -> list[dict[str, Any]]:
    return auth_manager.list_events()


# ==========================================
# CENTRAL IPFS API
# ==========================================


class IPFSUploadRequest(BaseModel):
    payload_b64: str = Field(min_length=1)
    recipients: list[str] = Field(min_length=1, max_length=100)


@app.post("/api/ipfs/upload")
def upload_to_ipfs(
    data: IPFSUploadRequest,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, str]:
    if user["role"] != "sender":
        raise HTTPException(status_code=403, detail="Only approved senders can upload packages.")
    max_bytes = int(os.environ.get("CAPSTONE_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))
    try:
        payload = base64.b64decode(data.payload_b64, validate=True)
        if not payload:
            raise ValueError("Empty package.")
        if len(payload) > max_bytes:
            raise HTTPException(status_code=413, detail=f"Package exceeds {max_bytes} byte upload limit.")
        cid = ipfs_manager.upload_data(payload.decode("utf-8"))
        auth_manager.register_package_access(cid, user["username"], data.recipients)
        return {"cid": cid, "status": "PASS"}
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"IPFS upload failed: {exc}")


@app.get("/api/ipfs/{cid}")
def retrieve_from_ipfs(
    cid: str,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, str]:
    if user["role"] != "receiver":
        raise HTTPException(status_code=403, detail="Only approved receivers can retrieve packages.")
    if not auth_manager.can_access_package(cid, user["username"]):
        raise HTTPException(status_code=404, detail="Package not found or this receiver is not authorized.")
    try:
        content = ipfs_manager.retrieve_file_bytes(cid)
        return {"status": "PASS", "content_b64": base64.b64encode(content).decode("ascii")}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"IPFS retrieval failed: {exc}")


# ==========================================
# CENTRAL BLOCKCHAIN API
# ==========================================


class BlockchainAnchorRequest(BaseModel):
    cid: str = Field(min_length=1, max_length=256)
    data_hash: str = Field(min_length=64, max_length=64)


class BlockchainVerifyRequest(BaseModel):
    cid: str = Field(min_length=1, max_length=256)


def _load_contract_config():
    """Load the deployed contract address and ABI on the central server."""
    project_root = Path(__file__).resolve().parents[1]

    address_file = project_root / "blockchain" / "contract_address.txt"
    artifact_file = (
        project_root
        / "blockchain"
        / "artifacts"
        / "contracts"
        / "DataStorage.sol"
        / "DataStorage.json"
    )

    if not address_file.is_file():
        raise RuntimeError("Contract address file is missing.")

    if not artifact_file.is_file():
        raise RuntimeError("Compiled DataStorage contract artifact is missing.")

    address = address_file.read_text(encoding="utf-8").strip()

    if not blockchain_manager.w3.is_connected():
        raise ConnectionError("Central Hardhat node is unavailable.")

    checksum_address = blockchain_manager.w3.to_checksum_address(address)

    if not blockchain_manager.w3.eth.get_code(checksum_address):
        raise RuntimeError(
            "No contract bytecode found at the configured address. "
            "Check the Hardhat node and contract deployment."
        )

    artifact = json.loads(artifact_file.read_text(encoding="utf-8"))

    return checksum_address, artifact["abi"]


@app.post("/api/blockchain/anchor")
def anchor_blockchain_record(
    data: BlockchainAnchorRequest,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:

    if user["role"] != "sender":
        raise HTTPException(
            status_code=403,
            detail="Only approved senders can anchor blockchain records.",
        )

    if not all(c in "0123456789abcdefABCDEF" for c in data.data_hash):
        raise HTTPException(
            status_code=400,
            detail="data_hash must be a 64-character SHA-256 hexadecimal value.",
        )

    try:
        address, abi = _load_contract_config()

        receipt = blockchain_manager.store_record(
            cid=data.cid,
            data_hash=data.data_hash.lower(),
            contract_address=address,
            abi=abi,
        )

        receipt_status = int(receipt["status"])

        if receipt_status != 1:
            raise RuntimeError("Blockchain transaction was not successful.")

        tx_hash = receipt["transactionHash"].hex()
        metadata = blockchain_manager.get_receipt_metadata(receipt)
        gas = blockchain_manager.transaction_cost_metrics(receipt)

        return {
            "status": "PASS",
            "message": "Blockchain record successfully anchored.",
            "cid": data.cid,
            "data_hash": data.data_hash.lower(),
            "transaction_hash": tx_hash,
            "block_number": metadata.get("block_number"),
            "blockchain_timestamp_utc": metadata.get("blockchain_timestamp_utc", ""),
            "gas_used": gas.get("gas_used"),
            "cost_eth": gas.get("cost_eth"),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Blockchain anchoring failed: {exc}",
        )


@app.post("/api/blockchain/verify")
def verify_blockchain_record(
    data: BlockchainVerifyRequest,
    user: dict[str, Any] = Depends(_current_user),
) -> dict[str, Any]:

    if user["role"] != "receiver":
        raise HTTPException(
            status_code=403,
            detail="Only approved receivers can verify blockchain records.",
        )

    try:
        address, abi = _load_contract_config()

        result = blockchain_manager.verify_record_result(
            cid=data.cid,
            contract_address=address,
            abi=abi,
        )

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Blockchain verification service failed: {exc}",
        )
