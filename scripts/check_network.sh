#!/usr/bin/env bash
set -u
printf '%s\n' '== Network addresses =='
ip -br -4 address 2>/dev/null || hostname -I
printf '\n%s\n' '== Tailscale =='
if command -v tailscale >/dev/null 2>&1; then
  tailscale status || true
  printf 'Tailscale IPv4: '
  tailscale ip -4 2>/dev/null || true
else
  echo 'Tailscale CLI not installed.'
fi
printf '\n%s\n' '== App listeners =='
ss -ltnp 2>/dev/null | grep -E ':(8501|8502|8503)\b' || echo 'No Streamlit listeners found on 8501-8503.'
printf '\n%s\n' '== Backend listeners (should normally be host-only) =='
ss -ltnp 2>/dev/null | grep -E ':(5001|8545)\b' || echo 'No IPFS/Hardhat listeners found on their default ports.'
