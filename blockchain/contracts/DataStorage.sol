// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Write-once integrity anchor for encrypted off-chain packages
/// @notice Stores only a CID and SHA-256 commitment; never store plaintext or keys here.
contract DataStorage {
    struct Record {
        string cid;
        string dataHash;
        address sender;
        uint256 timestamp;
    }

    mapping(string => Record) public records;
    event RecordStored(string cid, string dataHash, address sender, uint256 timestamp);

    error EmptyCID();
    error InvalidHash();
    error CIDAlreadyAnchored(string cid);

    function storeRecord(string memory _cid, string memory _dataHash) public {
        if (bytes(_cid).length == 0) revert EmptyCID();
        if (bytes(_dataHash).length != 64 || !_isHex(_dataHash)) revert InvalidHash();
        if (bytes(records[_cid].cid).length != 0) revert CIDAlreadyAnchored(_cid);

        records[_cid] = Record({
            cid: _cid,
            dataHash: _dataHash,
            sender: msg.sender,
            timestamp: block.timestamp
        });
        emit RecordStored(_cid, _dataHash, msg.sender, block.timestamp);
    }

    function _isHex(string memory value) private pure returns (bool) {
        bytes memory b = bytes(value);
        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            bool digit = c >= 0x30 && c <= 0x39;
            bool lower = c >= 0x61 && c <= 0x66;
            bool upper = c >= 0x41 && c <= 0x46;
            if (!(digit || lower || upper)) return false;
        }
        return true;
    }
}
