#!/usr/bin/env bash
set -u
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
for name in admin receiver sender api ipfs hardhat; do
  f=".runtime/pids/${name}.pid"
  if [[ -f "$f" ]]; then
    pid="$(cat "$f")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      echo "Stopped $name (PID $pid)"
    fi
    rm -f "$f"
  fi
done
echo "Note: if a child process remains, inspect it with: pgrep -af 'hardhat node|ipfs daemon|uvicorn|streamlit'"
