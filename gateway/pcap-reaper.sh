#!/usr/bin/env bash
# Keep the capture directory inside a byte budget.
#
# Hourly rotation with a file-count limit does not bound disk use, because
# file size depends on how much traffic arrives. A honeypot under active
# scanning can fill a small boot disk in a day, and a full disk means tcpdump
# stops writing. Losing the capture is the one failure this whole design
# exists to prevent, so the budget is enforced in bytes.
#
# Oldest files go first, and the file currently being written is never
# touched. Pruning does destroy evidence, which is the trade for keeping the
# capture alive: raise PCAP_MAX_BYTES or attach a bigger disk if the window
# matters more than the headroom.
set -euo pipefail
# Capture any caller-supplied override BEFORE sourcing, because sourcing
# assigns unconditionally and would otherwise silently discard it.
_in_max=${PCAP_MAX_BYTES:-}
. /etc/honeypot.env
DIR=/var/lib/honeypot/pcap
MAX=${_in_max:-${PCAP_MAX_BYTES:-4000000000}}

[ -d "$DIR" ] || exit 0

total() { du -sb "$DIR" 2>/dev/null | awk '{print $1}'; }

cur=$(total)
[ -n "$cur" ] || exit 0
[ "$cur" -le "$MAX" ] && exit 0

echo "pcap dir at $cur bytes, budget $MAX; pruning oldest"
# Sort by mtime, oldest first, and never consider the newest (being written).
mapfile -t files < <(find "$DIR" -maxdepth 1 -type f \
  \( -name '*.pcap' -o -name '*.pcap.gz' \) -printf '%T@ %p\n' \
  | sort -n | awk '{ $1=""; sub(/^ /,""); print }')
n=${#files[@]}
[ "$n" -le 1 ] && exit 0

removed=0
for ((i = 0; i < n - 1; i++)); do
  f=${files[$i]}
  sz=$(stat -c %s -- "$f" 2>/dev/null || echo 0)
  rm -f -- "$f"
  removed=$((removed + 1))
  logger -t honeypot-pcap-reaper "pruned $f ($sz bytes) to stay under budget"
  cur=$((cur - sz))
  [ "$cur" -le "$MAX" ] && break
done
echo "pruned $removed file(s); now $(total) bytes"
