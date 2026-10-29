// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title DataStorage
/// @notice Write-once CID-to-package-hash commitments for auditability.
/// @dev A CID cannot be re-anchored with a different hash. Deploy a new
/// contract when migrating from the previous mutable-record implementation.
contract DataStorage {
    struct Record {
        string cid;
        string dataHash;
        address sender;
        uint256 timestamp;
    }

    mapping(string => Record) public records;
    event RecordStored(
        string cid,
        string dataHash,
        address indexed sender,
        uint256 timestamp
    );

    function storeRecord(string calldata _cid, string calldata _dataHash) external {
        require(bytes(_cid).length > 0, "CID required");
        require(_isSha256Hex(_dataHash), "Expected 64 hex chars");
        require(bytes(records[_cid].cid).length == 0, "CID already anchored");

        records[_cid] = Record({
            cid: _cid,
            dataHash: _dataHash,
            sender: msg.sender,
            timestamp: block.timestamp
        });

        emit RecordStored(_cid, _dataHash, msg.sender, block.timestamp);
    }

    function _isSha256Hex(string calldata value) private pure returns (bool) {
        bytes calldata data = bytes(value);
        if (data.length != 64) return false;
        for (uint256 i = 0; i < data.length; i++) {
            bytes1 c = data[i];
            bool digit = c >= 0x30 && c <= 0x39;
            bool lower = c >= 0x61 && c <= 0x66;
            bool upper = c >= 0x41 && c <= 0x46;
            if (!(digit || lower || upper)) return false;
        }
        return true;
    }
}
