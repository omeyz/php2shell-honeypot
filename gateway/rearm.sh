#!/usr/bin/env bash
# Remove kill-switch rules after you have imaged the disk and reverted.
set -euo pipefail
. /etc/honeypot.env
while read -r h; do nft delete rule inet filter forward handle "$h"; done < <(
  nft -a list chain inet filter forward | awk '/KILLSWITCH/ {print $NF}'
)
rm -f /var/lib/honeypot/killswitch.tripped
echo "re-armed at $(date -Is)"
