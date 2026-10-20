import requests

def upload_data(payload: str) -> str:
    """Uploads data to the local IPFS daemon and returns the CID."""
    files = {
        'file': ('secure_payload.txt', payload)
    }
    
    # Call the local IPFS API 'add' endpoint
    response = requests.post('http://127.0.0.1:5001/api/v0/add', files=files)
    
    if response.status_code == 200:
        # IPFS returns a JSON object containing the 'Hash' (CID)
        return response.json()['Hash']
    else:
        raise Exception(f"Failed to upload to IPFS. Status: {response.status_code}")

def retrieve_file(cid: str) -> str:
    """Downloads the file from the local IPFS daemon."""
    params = {'arg': cid}
    
    # Use the local IPFS API 'cat' endpoint to read the file
    response = requests.post('http://127.0.0.1:5001/api/v0/cat', params=params)
    
    if response.status_code == 200:
        return response.text
    else:
        raise Exception(f"Failed to retrieve file from IPFS. Status: {response.status_code}")