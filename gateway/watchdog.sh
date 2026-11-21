#!/usr/bin/env bash
# Trip the kill switch if honeypot egress spikes. Runs every 60s via timer.
#
# HP_COUNTER_CMD exists so the decision logic can be tested without
# generating real traffic; in production it is left unset.
set -euo pipefail
# Capture caller-supplied overrides BEFORE sourcing: sourcing assigns
# unconditionally and would otherwise silently discard them.
_in_egress=${EGRESS_BYTES_PER_MIN:-}
_in_disk=${DISK_MIN_FREE_BYTES:-}
. /etc/honeypot.env
EGRESS_BYTES_PER_MIN=${_in_egress:-${EGRESS_BYTES_PER_MIN:-5000000}}
DISK_MIN_FREE_BYTES=${_in_disk:-${DISK_MIN_FREE_BYTES:-1000000000}}
STATE=/var/lib/honeypot/watchdog.state
mkdir -p /var/lib/honeypot
[ -f /var/lib/honeypot/killswitch.tripped ] && exit 0

read_bytes() {
  if [ -n "${HP_COUNTER_CMD:-}" ]; then
    eval "$HP_COUNTER_CMD"
  else
    nft -j list counters table inet filter \
      | jq '[.nftables[].counter | select(.name=="egress_web").bytes] | add // 0'
  fi
}

# A full disk silently ends the packet capture, which is the evidence this
# whole design protects. Stop inviting traffic before that happens.
MIN_FREE=$DISK_MIN_FREE_BYTES
free=$(df -B1 --output=avail /var/lib/honeypot 2>/dev/null | tail -1 | tr -d ' ')
case "$free" in
  ''|*[!0-9]*) : ;;
  *) if [ "$free" -lt "$MIN_FREE" ]; then
       /usr/local/sbin/honeypot-killswitch \
         "disk nearly full: ${free} bytes free (min ${MIN_FREE}); capture at risk"
       exit 0
     fi;;
esac

now=$(read_bytes)
case "$now" in ''|*[!0-9]*) echo "watchdog: bad counter read: $now" >&2; exit 1;; esac
prev=$(cat "$STATE" 2>/dev/null || echo "$now")
case "$prev" in ''|*[!0-9]*) prev=$now;; esac
printf '%s\n' "$now" > "$STATE"

# Counters reset to 0 on reload; treat that as no data rather than a spike.
if [ "$now" -lt "$prev" ]; then exit 0; fi
delta=$(( now - prev ))
limit=$EGRESS_BYTES_PER_MIN

if [ "$delta" -gt "$limit" ]; then
  /usr/local/sbin/honeypot-killswitch "egress spike: ${delta} bytes in one window (limit ${limit})"
fi
