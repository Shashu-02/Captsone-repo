# Smart-contract test cases to implement in Hardhat

These are the required behaviors for `DataStorage.sol`; implement them in your project's existing Hardhat test framework.

1. A valid CID plus 64 hexadecimal characters stores the record.
2. An empty CID reverts.
3. A hash shorter or longer than 64 characters reverts.
4. A 64-character non-hex string reverts.
5. A second write for the same CID reverts, even if the second caller is different.
6. A different CID can be anchored successfully.
7. After a failed overwrite, the original hash, sender, and timestamp remain unchanged.

Important: the new contract requires a fresh deployment; changing Solidity source does not modify an already deployed contract.
