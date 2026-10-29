import { expect } from "chai";
import { network } from "hardhat";

const { ethers } = await network.create();

describe("DataStorage write-once integrity anchor", function () {
  async function deploy() {
    return await ethers.deployContract("DataStorage");
  }
  const hash = "a".repeat(64);

  it("stores the commitment, sender, and timestamp", async function () {
    const contract = await deploy();
    const [sender] = await ethers.getSigners();
    await expect(contract.storeRecord("bafy-test-cid", hash))
      .to.emit(contract, "RecordStored");
    const record = await contract.records("bafy-test-cid");
    expect(record.cid).to.equal("bafy-test-cid");
    expect(record.dataHash).to.equal(hash);
    expect(record.sender).to.equal(sender.address);
    expect(record.timestamp).to.be.greaterThan(0n);
  });

  it("rejects empty CIDs and malformed SHA-256 commitments", async function () {
    const contract = await deploy();
    await expect(contract.storeRecord("", hash)).to.be.revertedWithCustomError(contract, "EmptyCID");
    await expect(contract.storeRecord("cid-1", "not-a-hash")).to.be.revertedWithCustomError(contract, "InvalidHash");
    await expect(contract.storeRecord("cid-2", "g".repeat(64))).to.be.revertedWithCustomError(contract, "InvalidHash");
  });

  it("rejects overwriting an existing CID", async function () {
    const contract = await deploy();
    await contract.storeRecord("same-cid", hash);
    await expect(contract.storeRecord("same-cid", "b".repeat(64)))
      .to.be.revertedWithCustomError(contract, "CIDAlreadyAnchored").withArgs("same-cid");
  });

  it("allows independent CIDs", async function () {
    const contract = await deploy();
    await contract.storeRecord("cid-a", hash);
    await contract.storeRecord("cid-b", "b".repeat(64));
    expect((await contract.records("cid-a")).dataHash).to.equal(hash);
    expect((await contract.records("cid-b")).dataHash).to.equal("b".repeat(64));
  });
});
