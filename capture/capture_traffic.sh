#!/usr/bin/env bash

set -e

OUT="${1:-tls_handshake.pcap}"
DURATION="${2:-20}"
IFACE="lo"

if [ "$EUID" -ne 0 ]; then
  echo "Run this with sudo: packet capture needs raw socket access."
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark not found. Install with: sudo apt install tshark"
  exit 1
fi

echo "Capturing on interface '$IFACE' for ${DURATION}s -> $OUT"
echo "Trigger the TLS test in the dashboard now (Run TLS Test button)."
echo "Filter: tcp port range 1024-65535 restricted to TLS handshake records."
echo

# capture filter narrows to loopback TCP traffic; the app binds an ephemeral
timeout "${DURATION}" tshark -i "${IFACE}" -f "tcp" -w "${OUT}" || true

echo
echo "Capture saved to ${OUT}"
echo "Quick summary:"
tshark -r "${OUT}" -Y "tls.handshake" -T fields \
  -e frame.number -e ip.src -e ip.dst -e tcp.port -e tls.handshake.type \
  2>/dev/null | head -30 || echo "(no TLS handshake frames found - did the test run during capture?)"

echo
echo "Full analysis: python3 parse_pcap.py ${OUT}"
