#!/usr/bin/env bash
# Temporarily lift the honeypot's egress throttle so it can be built.
#
#   provision-mode.sh on    unthrottled web egress for the honeypot
#   provision-mode.sh off   back to 6 new connections/minute
#
# The honeypot has to install packages, and the steady-state rate limit is
# deliberately too tight for apt. Turning this on widens the hole, so it is
# a separate, explicit, reversible step and must be off before exposure.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
MARK="PROVISION-MODE "

# Read the chain into a variable before matching. Piping into `grep -q` makes
# grep exit on the first match and close the pipe, which SIGPIPEs nft; under
# `pipefail` that turns a successful match into a failed pipeline, so the
# check reports "off" while the rule is in fact live. A false "off" here
# would let an unthrottled honeypot be exposed.
is_on() {
  local chain
  chain=$(nft list chain inet filter honeypot_egress)
  case "$chain" in *"$MARK"*) return 0;; *) return 1;; esac
}

case "${1:-}" in
  on)
    if is_on; then
      echo "already on"; exit 0
    fi
    # Insert at the top so it precedes the rate-limited rule.
    nft insert rule inet filter honeypot_egress \
      tcp dport '{ 80, 443 }' log prefix "\"$MARK\"" level info accept
    echo "provision mode ON: honeypot web egress is unthrottled."
    echo "Run '$0 off' as soon as the build finishes."
    ;;
  off)
    removed=0
    while read -r h; do
      [ -n "$h" ] || continue
      nft delete rule inet filter honeypot_egress handle "$h"
      removed=$((removed + 1))
    done < <(nft -a list chain inet filter honeypot_egress \
             | awk -v m="$MARK" 'index($0, m) { print $NF }')
    echo "provision mode OFF ($removed rule(s) removed); throttle restored"
    ;;
  status)
    if is_on; then
      echo "ON (unthrottled) -- not safe to expose"; exit 1
    else
      echo "OFF (throttled)"; exit 0
    fi
    ;;
  *) echo "usage: $0 {on|off|status}" >&2; exit 1;;
esac
