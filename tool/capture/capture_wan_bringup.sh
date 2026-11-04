#!/usr/bin/env bash
# (a) WAN bring-up capture — does the device fetch a script/binary over PLAINTEXT HTTP?
#
# POSITION IS EVERYTHING. You must capture on an interface that actually SEES the
# device's WAN-side traffic:
#   - in-path tap  : laptop bridged between the device's Ethernet WAN uplink and upstream
#   - on-device    : tcpdump on the device itself (needs a shell first)
#   - port mirror  : SPAN port on an upstream managed switch
# A LAN-side Wi-Fi client (e.g. wlp0s20f3 here) will NOT see the device's own WAN fetch.
#
# usage: ./capture_wan_bringup.sh <iface> [duration_sec]
set -euo pipefail

IFACE="${1:-}"
DUR="${2:-180}"
OUTDIR="${CAPTURE_OUTDIR:-$HOME/hackaton/data}"

if [ -z "$IFACE" ]; then
  echo "usage: $0 <iface> [duration_sec]" >&2
  echo "interfaces:" >&2
  ip -br link | awk '{print "  "$1"  "$2}' >&2
  exit 2
fi

mkdir -p "$OUTDIR"
TS="$(date +%Y%m%d-%H%M%S)"
OUT="$OUTDIR/wan-bringup-${IFACE}-${TS}.pcapng"

echo "[*] capturing on '$IFACE' for ${DUR}s"
echo "[*] output: $OUT"
echo "[!] NOW power-cycle the device / bounce its WAN so the bring-up fetch happens."
echo "    (Ctrl-C to stop early)"
# dumpcap has cap_net_raw/admin here -> no sudo needed
dumpcap -i "$IFACE" -a duration:"$DUR" -w "$OUT" -q || true
echo "[+] saved: $OUT"
echo "[*] next: python3 $(cd "$(dirname "$0")" && pwd)/analyze_capture.py \"$OUT\""
