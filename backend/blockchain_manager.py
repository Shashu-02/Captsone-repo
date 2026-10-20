from web3 import Web3

# Connect to the local Hardhat Ethereum node
w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

def store_record(cid: str, data_hash: str, contract_address: str, abi: list):
    """Anchors the IPFS CID and Data Hash to the Ethereum smart contract."""
    if not w3.is_connected():
        raise Exception("Cannot connect to Hardhat node. Is it running?")
        
    contract = w3.eth.contract(address=contract_address, abi=abi)
    
    # Use the first default Hardhat account as the sender
    sender_account = w3.eth.accounts[0]
    
    # Execute the storeRecord smart contract function
    tx_hash = contract.functions.storeRecord(cid, data_hash).transact({'from': sender_account})
    
    # Wait for the block to be mined and return the receipt for gas metrics
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

def verify_record(cid: str, contract_address: str, abi: list):
    """Queries the blockchain to verify if a CID exists and returns its original hash."""
    if not w3.is_connected():
        raise Exception("Cannot connect to Hardhat node. Is it running?")
        
    contract = w3.eth.contract(address=contract_address, abi=abi)
    
    # Call the records mapping on the smart contract
    record = contract.functions.records(cid).call()
    
    # record is a tuple: (cid, dataHash, sender, timestamp)
    # If the timestamp is 0, the record was never stored
    if record[3] == 0:
        return None
        
    return {
        "cid": record[0],
        "data_hash": record[1],
        "sender": record[2],
        "timestamp": record[3]
    }