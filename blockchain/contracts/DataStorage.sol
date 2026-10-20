// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract DataStorage {
    struct Record {
        string cid;
        string dataHash;
        address sender;
        uint256 timestamp;
    }

    mapping(string => Record) public records;
    event RecordStored(string cid, string dataHash, address sender, uint256 timestamp);

    function storeRecord(string memory _cid, string memory _dataHash) public {
        records[_cid] = Record({
            cid: _cid,
            dataHash: _dataHash,
            sender: msg.sender,
            timestamp: block.timestamp
        });
        emit RecordStored(_cid, _dataHash, msg.sender, block.timestamp);
    }
}