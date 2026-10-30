#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

API_HOST="${CAPSTONE_API_HOST:-0.0.0.0}"
API_PORT="${CAPSTONE_API_PORT:-8000}"
SENDER_PORT="${CAPSTONE_SENDER_PORT:-8501}"
RECEIVER_PORT="${CAPSTONE_RECEIVER_PORT:-8502}"
ADMIN_PORT="${CAPSTONE_ADMIN_PORT:-8503}"
RPC_URL="${HARDHAT_RPC_URL:-http://127.0.0.1:8545}"
IPFS_API_URL="${IPFS_API_URL:-http://127.0.0.1:5001}"

export HARDHAT_RPC_URL="$RPC_URL"

mkdir -p .runtime/logs .runtime/pids

# Python virtual environment
if [[ ! -d .venv ]]; then
    echo "Missing .venv. Create it with: python -m venv .venv"
    exit 1
fi

source .venv/bin/activate

# Prerequisites
command -v node >/dev/null || {
    echo "Node.js is required."
    exit 1
}
command -v npm >/dev/null || {
    echo "npm is required."
    exit 1
}
command -v ipfs >/dev/null || {
    echo "IPFS Kubo is required."
    exit 1
}
command -v curl >/dev/null || {
    echo "curl is required."
    exit 1
}

# Install blockchain dependencies if missing
if [[ ! -d blockchain/node_modules ]]; then
    echo "Installing blockchain dependencies..."
    (cd blockchain && npm install)
fi

# Persistent API secret
if [[ -z "${CAPSTONE_API_SECRET:-}" ]]; then
    if [[ -f .runtime/api_secret ]]; then
        export CAPSTONE_API_SECRET="$(cat .runtime/api_secret)"
    else
        umask 077
        python - <<'PY' >.runtime/api_secret
import secrets
print(secrets.token_urlsafe(48))
PY
        export CAPSTONE_API_SECRET="$(cat .runtime/api_secret)"
    fi
fi

# Background process manager
start_bg() {
    local name="$1"
    shift

    local pidfile=".runtime/pids/${name}.pid"
    local logfile=".runtime/logs/${name}.log"

    if [[ -f "$pidfile" ]]; then
        local old_pid
        old_pid="$(cat "$pidfile")"

        if kill -0 "$old_pid" 2>/dev/null; then
            echo "$name already running (PID $old_pid)"
            return
        fi

        rm -f "$pidfile"
    fi

    nohup "$@" >"$logfile" 2>&1 &
    echo $! >"$pidfile"

    echo "Started $name (PID $!)"
}

# Check Hardhat RPC
rpc_ready() {
    curl -fsS -X POST "$RPC_URL" \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
        2>/dev/null | grep -q '"result"'
}

# Check IPFS
ipfs_ready() {
    curl -fsS -X POST "$IPFS_API_URL/api/v0/id" \
        >/dev/null 2>&1
}

# Start Hardhat if needed
if ! rpc_ready; then
    echo "Starting Hardhat node..."

    start_bg hardhat bash -lc \
        "cd '$ROOT/blockchain' && npx hardhat node"

    ready=0

    for ((i = 1; i <= 40; i++)); do
        if rpc_ready; then
            ready=1
            break
        fi
        sleep 1
    done

    if [[ "$ready" -ne 1 ]]; then
        echo "Hardhat RPC failed to start."
        echo "Check .runtime/logs/hardhat.log"
        exit 1
    fi
else
    echo "Hardhat RPC already available."
fi

# Start IPFS if needed
if ! ipfs_ready; then
    echo "Starting IPFS daemon..."

    start_bg ipfs ipfs daemon

    ready=0

    for ((i = 1; i <= 40; i++)); do
        if ipfs_ready; then
            ready=1
            break
        fi
        sleep 1
    done

    if [[ "$ready" -ne 1 ]]; then
        echo "IPFS failed to start."
        echo "Check .runtime/logs/ipfs.log"
        exit 1
    fi
else
    echo "IPFS API already available."
fi

# Verify contract bytecode using Python JSON-RPC.
# No Foundry or cast installation required.
check_contract() {
    local address="$1"

    python - "$address" "$RPC_URL" <<'PY'
import json
import sys
import urllib.request

address, rpc = sys.argv[1], sys.argv[2]

payload = json.dumps({
    "jsonrpc": "2.0",
    "method": "eth_getCode",
    "params": [address, "latest"],
    "id": 1
}).encode()

request = urllib.request.Request(
    rpc,
    payload,
    {"Content-Type": "application/json"}
)

try:
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.load(response)

    code = result.get("result", "0x")
    if not code or code == "0x":
        sys.exit(1)

    print("Contract bytecode verified.")
except Exception as error:
    print("Contract verification failed:", error)
    sys.exit(1)
PY
}

# Compile and deploy only when required.
(
    cd blockchain

    echo "Compiling Solidity contracts..."
    npx hardhat compile

    ADDRESS_FILE="contract_address.txt"
    ADDRESS=""

    if [[ -f "$ADDRESS_FILE" ]]; then
        ADDRESS="$(tr -d '[:space:]' <"$ADDRESS_FILE")"
    fi

    if [[ -n "$ADDRESS" ]] && check_contract "$ADDRESS"; then
        echo "Existing DataStorage contract is valid."
        echo "Reusing: $ADDRESS"

    else
        echo "No valid deployed contract found."
        echo "Deploying DataStorage..."

        # Only reset Ignition deployment records for the local chain.
        rm -rf ignition/deployments/chain-31337

        npx hardhat ignition deploy \
            ignition/modules/DataStorage.ts \
            --network localhost

        DEPLOYED="ignition/deployments/chain-31337/deployed_addresses.json"

        if [[ ! -f "$DEPLOYED" ]]; then
            echo "Ignition deployment output not found."
            exit 1
        fi

        ADDRESS="$(node -e \
            "const d=require('./$DEPLOYED'); console.log(d['DataStorageModule#DataStorage']||'')")"

        if [[ -z "$ADDRESS" ]]; then
            echo "Could not read deployed contract address."
            exit 1
        fi

        printf '%s\n' "$ADDRESS" >"$ADDRESS_FILE"
    fi

    # Synchronize backend address.
    printf '%s\n' "$ADDRESS" >../backend/contract_address.txt
)

# Final bytecode verification
ADDRESS="$(tr -d '[:space:]' <blockchain/contract_address.txt)"

if ! check_contract "$ADDRESS"; then
    echo "Contract bytecode verification failed."
    exit 1
fi

echo "Active contract: $ADDRESS"

# Start central API
start_bg api python -m uvicorn \
    backend.api_server:app \
    --host "$API_HOST" \
    --port "$API_PORT"

# Start Streamlit applications
start_bg sender python -m streamlit run \
    sender/app.py --server.port "$SENDER_PORT"

start_bg receiver python -m streamlit run \
    receiver/app.py --server.port "$RECEIVER_PORT"

if [[ -f admin/app.py ]]; then
    start_bg admin python -m streamlit run \
        admin/app.py --server.port "$ADMIN_PORT"
fi

echo
echo "======================================"
echo " CAPSTONE PROJECT STARTED"
echo "======================================"
echo
echo "API:      http://127.0.0.1:$API_PORT"
echo "Sender:   http://127.0.0.1:$SENDER_PORT"
echo "Receiver: http://127.0.0.1:$RECEIVER_PORT"
echo "Admin:    http://127.0.0.1:$ADMIN_PORT"
echo
echo "Hardhat RPC: $RPC_URL"
echo "IPFS API:    $IPFS_API_URL"
echo "Contract:    $ADDRESS"
echo
echo "Logs: .runtime/logs/"
echo "API secret: .runtime/api_secret"
echo "Stop services: ./stop.sh"
echo
