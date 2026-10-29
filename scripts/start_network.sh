#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="$ROOT/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "ERROR: Expected project virtualenv at $PY" >&2
  echo "Create/activate your existing .venv and install the project requirements first." >&2
  exit 1
fi
if ! "$PY" -c 'import streamlit' >/dev/null 2>&1; then
  echo "ERROR: Streamlit is not installed in $PY" >&2
  exit 1
fi
for f in admin/app.py sender/app.py receiver/app.py; do
  if [[ ! -f "$ROOT/$f" ]]; then
    echo "ERROR: Missing $f. Run this script from your existing project with admin, sender and receiver folders." >&2
    exit 1
  fi
done

mkdir -p logs
PIDS=()
cleanup() {
  trap - INT TERM EXIT
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup INT TERM EXIT

start_app() {
  local label="$1" file="$2" port="$3"
  if ss -ltn 2>/dev/null | grep -Eq ":${port}[[:space:]]"; then
    echo "ERROR: TCP port $port is already in use. Stop the old app first." >&2
    exit 1
  fi
  "$PY" -m streamlit run "$file" --server.address 0.0.0.0 --server.port "$port" --server.headless true --browser.gatherUsageStats false >"logs/${label}.log" 2>&1 &
  PIDS+=("$!")
}

start_app admin admin/app.py 8503
start_app sender sender/app.py 8501
start_app receiver receiver/app.py 8502
sleep 2

HOST_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}' || true)"
[[ -n "$HOST_IP" ]] || HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
TAILSCALE_IP="$(tailscale ip -4 2>/dev/null | head -n1 || true)"

cat <<INFO

Secure Storage portals are starting on this host.

Same Wi-Fi / phone hotspot:
  Admin:    http://${HOST_IP:-HOST_LAN_IP}:8503
  Sender:   http://${HOST_IP:-HOST_LAN_IP}:8501
  Receiver: http://${HOST_IP:-HOST_LAN_IP}:8502
INFO
if [[ -n "$TAILSCALE_IP" ]]; then
  cat <<INFO
Different networks (Tailscale):
  Admin:    http://${TAILSCALE_IP}:8503
  Sender:   http://${TAILSCALE_IP}:8501
  Receiver: http://${TAILSCALE_IP}:8502
INFO
else
  echo "Tailscale: not detected. Install/sign in on host and client PCs to enable different-network access."
fi
cat <<'INFO'

Logs: logs/admin.log, logs/sender.log, logs/receiver.log
Stop all portals with Ctrl+C in this terminal.
Do not expose IPFS RPC (5001) or Hardhat RPC (8545) to the network.
INFO
wait
