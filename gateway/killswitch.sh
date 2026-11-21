#!/usr/bin/env bash
# Cut the honeypot off the network, now. Idempotent. Survives until re-armed.
#
# These rules go in the forward chain, so they stop internet-to-honeypot and
# honeypot-to-internet traffic. Traffic originating on the gateway itself
# traverses the output hook and is intentionally NOT blocked, which is what
# keeps admin access alive. Verify with honeypot-killswitch-verify, not by
# curling the honeypot from the gateway: that path is supposed to still work.
set -euo pipefail
. /etc/honeypot.env
nft insert rule inet filter forward iifname "$PRIV_IF" log prefix "KILLSWITCH-EGRESS " level warn drop
nft insert rule inet filter forward oifname "$PRIV_IF" log prefix "KILLSWITCH-INGRESS " level warn drop
date -Is > /var/lib/honeypot/killswitch.tripped
logger -t honeypot-killswitch "kill switch tripped: ${1:-manual}"
echo "honeypot isolated at $(date -Is): ${1:-manual}"
