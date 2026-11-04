#!/usr/bin/env bash
# Path 2 -- make THIS laptop the device's WAN upstream, so every packet the device
# sends on bring-up (DNS + the plaintext HTTP update fetch) flows through us.
#
# Wiring:  [separate modem/ONT] --(laptop's UPLINK: wifi hotspot / usb tether)-->
#          laptop --enp1s0--> [EX3301-T0 WAN port]
# The device gets DHCP+DNS+gateway from us on DEV_IFACE; we NAT it out via UPLINK.
# We also run dnsmasq with query logging and dumpcap on DEV_IFACE.
#
# usage:
#   sudo ./wan_gateway.sh up   <dev_iface> <uplink_iface>   # e.g. up enp1s0 usb0
#   sudo ./wan_gateway.sh down <dev_iface> <uplink_iface>
#
# Reversible: 'down' tears everything back down. Only touches YOUR laptop.
set -euo pipefail

CMD="${1:-}"; DEV="${2:-}"; UP="${3:-}"
NET="10.77.0"; DEV_IP="${NET}.1/24"
OUTDIR="${CAPTURE_OUTDIR:-$HOME/hackaton/data}"
PIDF="/run/user/$(id -u)/wan_gateway"
STATE="$PIDF/ip_forward.orig"

usage(){ echo "usage: sudo $0 up|down <dev_iface> <uplink_iface>" >&2; exit 2; }
[ -z "$CMD" ] || [ -z "$DEV" ] || [ -z "$UP" ] && usage
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 1; }
mkdir -p "$PIDF" "$OUTDIR"

up(){
  echo "[*] bringing up WAN-gateway: device on $DEV, uplink via $UP"
  cat /proc/sys/net/ipv4/ip_forward > "$STATE"
  sysctl -q -w net.ipv4.ip_forward=1

  ip addr flush dev "$DEV" || true
  ip addr add "$DEV_IP" dev "$DEV"
  ip link set "$DEV" up

  # NAT device -> uplink
  iptables -t nat -A POSTROUTING -o "$UP" -j MASQUERADE
  iptables -A FORWARD -i "$DEV" -o "$UP" -j ACCEPT
  iptables -A FORWARD -i "$UP" -o "$DEV" -m state --state RELATED,ESTABLISHED -j ACCEPT

  # DHCP + DNS for the device; log every query so we see its target hosts
  local dnslog="$OUTDIR/dnsmasq-queries-$(date +%Y%m%d-%H%M%S).log"
  dnsmasq --keep-in-foreground --no-daemon \
          --interface="$DEV" --bind-interfaces --except-interface=lo \
          --listen-address="${NET}.1" \
          --dhcp-range="${NET}.50,${NET}.150,12h" \
          --dhcp-option=3,"${NET}.1" --dhcp-option=6,"${NET}.1" \
          --server=1.1.1.1 --server=8.8.8.8 \
          --log-queries --log-facility="$dnslog" \
          --pid-file="$PIDF/dnsmasq.pid" &
  echo $! > "$PIDF/dnsmasq.wrap"
  echo "[+] dnsmasq up (DHCP ${NET}.50-150, DNS logged to $dnslog)"

  local ts pcap; ts="$(date +%Y%m%d-%H%M%S)"; pcap="$OUTDIR/wan-bringup-${DEV}-${ts}.pcapng"
  dumpcap -i "$DEV" -w "$pcap" -q &
  echo $! > "$PIDF/dumpcap.pid"
  echo "[+] capturing on $DEV -> $pcap"
  echo
  echo "[!] NOW: plug EX3301 WAN port into $DEV and power-cycle it."
  echo "    Watch live DNS:  tail -f $dnslog"
  echo "    Stop + analyze:  sudo $0 down $DEV $UP   then   analyze_capture.py $pcap"
}

down(){
  echo "[*] tearing down"
  [ -f "$PIDF/dumpcap.pid" ] && kill "$(cat "$PIDF/dumpcap.pid")" 2>/dev/null || true
  [ -f "$PIDF/dnsmasq.wrap" ] && kill "$(cat "$PIDF/dnsmasq.wrap")" 2>/dev/null || true
  [ -f "$PIDF/dnsmasq.pid" ] && kill "$(cat "$PIDF/dnsmasq.pid")" 2>/dev/null || true
  iptables -t nat -D POSTROUTING -o "$UP" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "$DEV" -o "$UP" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$UP" -o "$DEV" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  ip addr flush dev "$DEV" 2>/dev/null || true
  [ -f "$STATE" ] && sysctl -q -w net.ipv4.ip_forward="$(cat "$STATE")" || true
  rm -f "$PIDF"/*.pid "$PIDF"/*.wrap "$STATE" 2>/dev/null || true
  echo "[+] restored"
}

case "$CMD" in
  up) up ;;
  down) down ;;
  *) usage ;;
esac
