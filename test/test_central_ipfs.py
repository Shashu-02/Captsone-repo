import base64
import getpass
import hashlib

import requests

API = "http://127.0.0.1:8000"


def login(username):
    password = getpass.getpass(f"Password for {username}: ")

    response = requests.post(
        f"{API}/api/login",
        json={"username": username, "password": password},
        timeout=15,
    )
    response.raise_for_status()

    data = response.json()
    print(f"[PASS] {username} authenticated")
    return data["access_token"]


def main():
    sender_token = login("Sender")
    receiver_token = login("Rec")

    original = (
        b"CAPSTONE CENTRAL IPFS INTEGRATION TEST\n"
        b"AES-256-GCM encrypted package simulation.\n"
    )

    print("\nOriginal SHA256:", hashlib.sha256(original).hexdigest())

    # Upload as Sender
    upload_response = requests.post(
        f"{API}/api/ipfs/upload",
        headers={"Authorization": f"Bearer {sender_token}"},
        json={"payload_b64": base64.b64encode(original).decode("ascii"), "recipients": ["Rec"]},
        timeout=30,
    )
    upload_response.raise_for_status()

    cid = upload_response.json()["cid"]
    print("\n[PASS] Package uploaded through central API")
    print("CID:", cid)

    # Retrieve as Receiver
    retrieve_response = requests.get(
        f"{API}/api/ipfs/{cid}",
        headers={"Authorization": f"Bearer {receiver_token}"},
        timeout=30,
    )
    retrieve_response.raise_for_status()

    retrieved = base64.b64decode(
        retrieve_response.json()["content_b64"],
        validate=True,
    )

    print("\nRetrieved SHA256:", hashlib.sha256(retrieved).hexdigest())

    if retrieved != original:
        raise RuntimeError("Integrity verification FAILED")

    print("\n[PASS] Retrieved content matches original")
    print("[PASS] Central API → IPFS → Central API test completed")


if __name__ == "__main__":
    main()
