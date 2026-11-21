#!/usr/bin/env bash
# Full packet capture of honeypot traffic, written on the GATEWAY.
# The honeypot's own logs are attacker-writable; this is the source of truth.
set -euo pipefail
. /etc/honeypot.env
D=/var/lib/honeypot/pcap
mkdir -p "$D"
# -s0 full payload, rotate hourly, gzip on rotate. The file count is a
# ceiling only; actual disk use is bounded in bytes by honeypot-pcap-reaper,
# because file size depends on how much traffic arrives.
exec /usr/bin/tcpdump -i "$PRIV_IF" -s0 -n -w "$D/hp-%Y%m%d-%H%M%S.pcap" \
  -G 3600 -W 120 -z /usr/bin/gzip "host $HONEY_IP"
