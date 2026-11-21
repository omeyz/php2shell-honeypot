#!/usr/bin/env bash
# Render nftables.conf.tmpl -> an nftables config using honeypot.env.
# Usage: render-nftables.sh [env-file] [out-file]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENVF="${1:-$HERE/honeypot.env}"
[ -f "$ENVF" ] || { echo "missing env file: $ENVF (copy honeypot.env.example)" >&2; exit 1; }
# shellcheck disable=SC1090
. "$ENVF"
for v in PUB_IF PRIV_IF GW_IP HONEY_IP ADMIN_CIDR SSH_PORT RESOLVER; do
  [ -n "${!v:-}" ] || { echo "$v unset in $ENVF" >&2; exit 1; }
done
# ADMIN_CIDR may be a single CIDR or an nft set like "{ a/20, b/32 }", so a
# trailing-"/0" test is not enough: a default route hidden inside a set would
# slip past it and open admin SSH to the internet.
case "$ADMIN_CIDR" in
  *0.0.0.0/0*|*::/0*|*/0)
    echo "refusing: ADMIN_CIDR must not contain a default route ($ADMIN_CIDR)" >&2
    exit 1;;
esac
out="${2:-/etc/nftables.conf}"
sed -e "s|@PUB_IF@|$PUB_IF|g"       -e "s|@PRIV_IF@|$PRIV_IF|g" \
    -e "s|@GW_IP@|$GW_IP|g"         -e "s|@HONEY_IP@|$HONEY_IP|g" \
    -e "s|@ADMIN_CIDR@|$ADMIN_CIDR|g" \
    -e "s|@SSH_PORT@|$SSH_PORT|g"   -e "s|@RESOLVER@|$RESOLVER|g" \
    "$HERE/nftables.conf.tmpl" > "$out"
chmod 0755 "$out"
echo "wrote $out"
if command -v nft >/dev/null; then nft -c -f "$out" && echo "ruleset parses OK"; fi
