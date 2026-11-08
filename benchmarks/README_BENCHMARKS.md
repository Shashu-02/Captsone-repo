# Reproducible benchmark instructions

## What these tests do

1. `benchmark_crypto.py`: times the project's actual AES-256-GCM encrypt/decrypt helpers.
2. `benchmark_storage.py`: compares local disk and local Kubo IPFS using identical base64 payload bytes. It verifies SHA-256 after each read.
3. `benchmark_blockchain.py`: measures writes, reads, gas and transaction cost against the deployed DataStorage contract on local Hardhat chain 31337. Each write uses a unique CID because the contract is write-once.
4. `benchmark_e2e.py`: measures a service-layer transfer pipeline using the project's crypto format, signature verification helper, IPFS helper and deployed contract. It uses temporary test identities/trust data and does not touch production keys, accounts, trust registry or audit DB.

**Scope limitation:** the E2E script directly calls the local crypto/IPFS/blockchain service components. It does not benchmark FastAPI authentication/routes or Streamlit browser/UI overhead. Report it as a service-layer pipeline benchmark, not a full browser/API user journey.

## Requirements

Run from the project root. Use the same Python environment and same running services for all experiments.

```bash
python -m pip install pycryptodome ecdsa requests web3
```

If your project already has a working environment, prefer its installed requirements rather than changing dependency versions. These scripts use only Python standard library plus dependencies already used by the project.

## Create folder / copy files

Put the files in this layout:

```text
Captsone-repo/
  benchmarks/
    benchmark_crypto.py
    benchmark_storage.py
    benchmark_blockchain.py
    benchmark_e2e.py
    generate_report.py
    README_BENCHMARKS.md
    results/
```

Create the results folder if needed:

```bash
mkdir -p benchmarks/results
```

## Record environment before running

From the project root:

```bash
{
  date -Is
  uname -a
  python --version
  python -m pip freeze
  (cd blockchain && npx hardhat --version)
  lscpu | grep -E 'Model name|CPU\\(s\\)' | head
  free -h
} > benchmarks/results/system_info.txt
```

Do not publish private keys, `.runtime`, database files, passwords, API secrets, or account tokens.

## Start services

Terminal 1 — local IPFS Kubo daemon, if not already running:

```bash
ipfs daemon
```

Terminal 2 — local Hardhat node:

```bash
cd blockchain
npx hardhat node
```

Keep both terminals running. Do not reset the Hardhat chain between the blockchain and E2E tests.

Check Kubo:

```bash
curl -s -X POST http://127.0.0.1:5001/api/v0/version
```

Check Hardhat:

```bash
curl -s http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

Expected chain ID is `0x7a69` (31337).

## Compile and deploy contract (only if needed)

From project root:

```bash
cd blockchain
npx hardhat compile
npx hardhat ignition deploy ignition/modules/DataStorage.ts
```

Use the same local node. If the contract is already deployed and its address matches `backend/contract_address.txt`, do not redeploy. Verify the compiled artifact exists at:

`blockchain/artifacts/contracts/DataStorage.sol/DataStorage.json`

The address used by scripts is read from `backend/contract_address.txt`. Verify it is the contract deployed on the currently running node. A freshly restarted Hardhat node has a fresh chain state; an old address may have no code on it.

## Run tests (from project root)

Activate the Python environment you actually use. `.venv` is optional; if it does not exist, do not try to source it.

```bash
python -m benchmarks.benchmark_crypto --repeats 10
python -m benchmarks.benchmark_storage --repeats 5
python -m benchmarks.benchmark_blockchain --repeats 10
python -m benchmarks.benchmark_e2e --repeats 3
python -m benchmarks.generate_report
```

For shorter smoke tests first:

```bash
python -m benchmarks.benchmark_crypto --repeats 2 --sizes 1
python -m benchmarks.benchmark_storage --repeats 2 --sizes 1
python -m benchmarks.benchmark_blockchain --repeats 2
python -m benchmarks.benchmark_e2e --repeats 2 --sizes 1
```

After smoke tests pass, run the full commands above. Storage and E2E use local services and will add test objects/records to local IPFS and the local Hardhat chain. They do not delete existing data.

## Outputs

Each script writes a CSV under `benchmarks/results/`:
- `crypto.csv`
- `storage.csv`
- `blockchain.csv`
- `e2e.csv`

The environment is recorded in `system_info.txt`. `benchmark_summary.md` is generated from CSVs that exist.

## Reproducibility rules

- Do not run heavy downloads, builds, games, or other benchmarks concurrently.
- Keep power mode and service configuration consistent.
- Record whether IPFS is local and whether Hardhat is local.
- Use the same file sizes and repeat counts when comparing runs.
- Do not compare results collected on different hardware or under different load without stating that.
- Preserve raw CSV files; do not edit measured values manually.
- Run each experiment at least twice on separate sessions if time permits.
- The first run is a smoke test; use the full repeat count for reportable results.
- These are local-development benchmarks, not public-network Ethereum cost estimates.
