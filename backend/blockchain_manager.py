"""Blockchain storage and independent verification helpers.

Existing store_record()/verify_record() interfaces are retained for compatibility.
Verification helpers return explicit PASS, FAIL, or ERROR statuses.
"""
from web3 import Web3

RPC_URL = "http://127.0.0.1:8545"
w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 10}))


def _result(status, message, **details):
    return {"status": status, "message": message, **details}


def store_record(cid: str, data_hash: str, contract_address: str, abi: list):
    """Anchor a CID and SHA-256 commitment on the configured contract."""
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to Hardhat node at {RPC_URL}.")
    if not cid or not data_hash:
        raise ValueError("CID and data_hash are required.")
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address), abi=abi
    )
    sender_account = w3.eth.accounts[0]
    tx_hash = contract.functions.storeRecord(cid, data_hash).transact(
        {"from": sender_account}
    )
    return w3.eth.wait_for_transaction_receipt(tx_hash)


def verify_record(cid: str, contract_address: str, abi: list):
    """Return the actual on-chain record, or None if no record exists."""
    if not w3.is_connected():
        raise ConnectionError(f"Cannot connect to Hardhat node at {RPC_URL}.")
    if not cid:
        raise ValueError("CID is required.")
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address), abi=abi
    )
    record = contract.functions.records(cid).call()
    # Expected mapping tuple: (cid, dataHash, sender, timestamp)
    if len(record) < 4 or int(record[3]) == 0 or not record[0]:
        return None
    # Confirm the record stored under this mapping key reports the same CID.
    if record[0] != cid:
        return None
    return {
        "cid": record[0],
        "data_hash": record[1],
        "sender": record[2],
        "timestamp": int(record[3]),
    }


def verify_record_result(cid: str, contract_address: str, abi: list):
    """Explicitly distinguish a missing/mismatched record from service errors."""
    try:
        record = verify_record(cid, contract_address, abi)
        if record is None:
            return _result("FAIL", "No matching on-chain record exists for this CID.")
        if record["cid"] != cid:
            return _result("FAIL", "On-chain CID does not match the requested CID.")
        if not record.get("data_hash"):
            return _result("FAIL", "On-chain commitment hash is empty.")
        return _result("PASS", "Matching on-chain record found.", record=record)
    except (ConnectionError, TimeoutError) as exc:
        return _result("ERROR", str(exc))
    except Exception as exc:
        return _result("ERROR", f"Blockchain verification error: {exc}")


def get_receipt_metadata(receipt):
    """Extract mined block number and canonical block timestamp from a tx receipt."""
    try:
        block_number = int(receipt["blockNumber"] if isinstance(receipt, dict) else receipt.blockNumber)
        block = w3.eth.get_block(block_number)
        timestamp = int(block["timestamp"] if isinstance(block, dict) else block.timestamp)
        from datetime import datetime, timezone
        return {"block_number": block_number,
                "blockchain_timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")}
    except Exception as exc:
        return {"block_number": None, "blockchain_timestamp_utc": "", "metadata_error": str(exc)}


def transaction_cost_metrics(receipt):
    """Return measured gas usage/cost from a mined transaction receipt when available."""
    try:
        gas_used = int(receipt["gasUsed"] if isinstance(receipt, dict) else receipt.gasUsed)
        tx_hash = receipt.get("transactionHash") if isinstance(receipt, dict) else getattr(receipt, "transactionHash", None)
        gas_price = None
        if tx_hash is not None:
            tx = w3.eth.get_transaction(tx_hash)
            gas_price = int(tx.get("effectiveGasPrice", tx.get("gasPrice", 0)) if isinstance(tx, dict) else getattr(tx, "effectiveGasPrice", getattr(tx, "gasPrice", 0)))
        return {"gas_used": gas_used, "gas_price_wei": gas_price,
                "cost_wei": gas_used * gas_price if gas_price is not None else None,
                "cost_eth": (gas_used * gas_price / 10**18) if gas_price is not None else None}
    except Exception as exc:
        return {"gas_used": None, "gas_price_wei": None, "cost_wei": None,
                "cost_eth": None, "error": str(exc)}

def verify_record_with_risk(cid: str, contract_address: str, abi: list, historical_events=None):
    """Combine independent on-chain lookup with risk triage; never weakens verification."""
    from audit_policy import assess_risk
    result = verify_record_result(cid, contract_address, abi)
    current = [{"event_type": "Blockchain record", "status": result["status"], "details": result["message"]}]
    risk = assess_risk(current, historical_events or [])
    return {**result, "risk": risk}
