import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const DataStorageModule = buildModule("DataStorageModule", (m) => {
  const dataStorage = m.contract("DataStorage");
  return { dataStorage };
});

export default DataStorageModule;