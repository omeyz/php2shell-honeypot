#!/usr/bin/env bash
# Offline self-test for the gateway logic. Intended to run inside a container
# with --net=none --cap-add=NET_ADMIN, so loading rules touches nothing real.
set -uo pipefail
fail=0
ok()   { echo "  PASS  $1"; }
bad()  { echo "  FAIL  $1"; fail=1; }

cd /w || exit 1
sed "s#^ADMIN_CIDR=.*#ADMIN_CIDR=203.0.113.4/32#" gateway/honeypot.env.example > /tmp/good.env
install -m 0600 /tmp/good.env /etc/honeypot.env
install -d -m 0750 /var/lib/honeypot
install -m 0755 gateway/killswitch.sh /usr/local/sbin/honeypot-killswitch
install -m 0755 gateway/rearm.sh      /usr/local/sbin/honeypot-rearm
install -m 0755 gateway/watchdog.sh   /usr/local/sbin/honeypot-watchdog

echo "[1] ruleset renders and loads"
gateway/render-nftables.sh /tmp/good.env /tmp/rendered.conf >/dev/null \
  && nft -f /tmp/rendered.conf && ok "load" || bad "load"

echo "[2] default policies are deny"
for c in input forward; do
  out=$(nft list chain inet filter "$c")
  case "$out" in *"policy drop"*) ok "$c drop";; *) bad "$c drop";; esac
done

echo "[3] mail egress is dropped, not accepted"
eg=$(nft list chain inet filter honeypot_egress)
smtp=$(printf '%s\n' "$eg" | grep -E 'dport \{ 25')
case "$smtp" in *drop*) ok "smtp drop";; *) bad "smtp drop: $smtp";; esac

echo "[4] private-space egress is dropped"
case "$eg" in *10.0.0.0/8*) ok "rfc1918 rule present";; *) bad "rfc1918 rule present";; esac

echo "[5] egress chain ends in an explicit drop (no fallthrough accept)"
tailing=$(printf '%s\n' "$eg" | tail -3)
case "$tailing" in *drop*) ok "terminal drop";; *) bad "terminal drop";; esac

echo "[6] watchdog counter query returns a number"
v=$(nft -j list counters table inet filter \
    | jq '[.nftables[].counter | select(.name=="egress_web").bytes] | add // 0')
case "$v" in ''|*[!0-9]*) bad "counter query ($v)";; *) ok "counter query -> $v";; esac

echo "[7] watchdog does not trip on zero traffic"
/usr/local/sbin/honeypot-watchdog
[ -f /var/lib/honeypot/killswitch.tripped ] && bad "tripped spuriously" || ok "no spurious trip"

echo "[8] watchdog arithmetic: no trip just under the limit, trip just over"
lim=$(sed -n 's/^EGRESS_BYTES_PER_MIN=//p' /etc/honeypot.env)
echo 0 > /var/lib/honeypot/watchdog.state
HP_COUNTER_CMD="echo $lim" /usr/local/sbin/honeypot-watchdog
[ -f /var/lib/honeypot/killswitch.tripped ] && bad "tripped at exactly the limit" || ok "no trip at limit"
echo 0 > /var/lib/honeypot/watchdog.state
HP_COUNTER_CMD="echo $(( lim + 1 ))" /usr/local/sbin/honeypot-watchdog >/dev/null
[ -f /var/lib/honeypot/killswitch.tripped ] && ok "tripped one byte over" || bad "tripped one byte over"

echo "[8b] counter reset (reload) is not treated as a spike"
/usr/local/sbin/honeypot-rearm >/dev/null
echo 999999999 > /var/lib/honeypot/watchdog.state
HP_COUNTER_CMD="echo 0" /usr/local/sbin/honeypot-watchdog
[ -f /var/lib/honeypot/killswitch.tripped ] && bad "spurious trip on reset" || ok "no trip on counter reset"

echo "[8c] re-trip for the ordering checks below"
echo 0 > /var/lib/honeypot/watchdog.state
HP_COUNTER_CMD="echo $(( lim + 1 ))" /usr/local/sbin/honeypot-watchdog >/dev/null

echo "[9] kill switch isolates both directions"
n=$(nft -a list chain inet filter forward | grep -c KILLSWITCH)
[ "$n" -ge 2 ] && ok "killswitch rules inserted ($n)" || bad "killswitch rules inserted ($n)"

echo "[10] kill-switch drops sit ABOVE the accept rules"
fwd=$(nft list chain inet filter forward)
first=$(printf '%s\n' "$fwd" | grep -E 'KILLSWITCH|accept' | head -1)
case "$first" in *KILLSWITCH*) ok "killswitch precedes accepts";; *) bad "killswitch precedes accepts ($first)";; esac

echo "[11] rearm removes them"
/usr/local/sbin/honeypot-rearm >/dev/null
n=$(nft -a list chain inet filter forward | grep -c KILLSWITCH)
[ "$n" = 0 ] && ok "rearm clean" || bad "rearm left $n rule(s)"

echo "[12] single-NIC safety: DNAT keys on the gateway's own address"
nat=$(nft list table ip nat)
case "$nat" in
  *"ip daddr 10.99.0.2 tcp dport 80"*) ok "dnat keyed on gateway ip";;
  *) bad "dnat not keyed on gateway ip";;
esac
# An interface-only match would also rewrite the honeypot's own outbound
# HTTP, pointing it back at itself.
case "$nat" in
  *iifname*"tcp dport 80 dnat"*) bad "dnat is still interface-only";;
  *) ok "dnat not interface-only";;
esac

echo "[12b] forward chain discriminates by address, not interface"
fwdc=$(nft list chain inet filter forward)
case "$fwdc" in
  *"ip saddr 10.99.0.10"*) ok "egress matched by source address";;
  *) bad "egress not matched by source address";;
esac
case "$fwdc" in
  *"ip daddr 10.99.0.10 tcp dport 80"*) ok "inbound matched by dest address";;
  *) bad "inbound not matched by dest address";;
esac

echo "[13] provision mode reports its state honestly"
install -m 0755 gateway/provision-mode.sh /usr/local/sbin/honeypot-provision-mode
/usr/local/sbin/honeypot-provision-mode status >/dev/null \
  && ok "reports OFF when off" || bad "reports OFF when off"
/usr/local/sbin/honeypot-provision-mode on >/dev/null
# A false OFF here would let an unthrottled honeypot be exposed, so the
# check must survive being piped and must see its own rule.
if /usr/local/sbin/honeypot-provision-mode status >/dev/null; then
  bad "reports OFF while the rule is live"
else
  ok "reports ON when on"
fi
pm=$(nft list chain inet filter honeypot_egress)
case "$pm" in *"PROVISION-MODE"*) ok "rule actually present";; *) bad "rule missing";; esac
/usr/local/sbin/honeypot-provision-mode off >/dev/null
/usr/local/sbin/honeypot-provision-mode status >/dev/null \
  && ok "off removes it" || bad "off removes it"

echo "[14] pcap reaper enforces a byte budget, oldest first"
install -m 0755 gateway/pcap-reaper.sh /usr/local/sbin/honeypot-pcap-reaper
install -d -m 0750 /var/lib/honeypot/pcap
for i in 1 2 3 4; do
  dd if=/dev/zero of="/var/lib/honeypot/pcap/hp-00$i.pcap" bs=1M count=2 \
     status=none
  touch -d "2026-10-0$i" "/var/lib/honeypot/pcap/hp-00$i.pcap"
done
before=$(find /var/lib/honeypot/pcap -name 'hp-*.pcap' | wc -l | tr -d ' ')
# Budget of 5MB against 8MB of files: it must prune, but never the newest.
PCAP_MAX_BYTES=5000000 /usr/local/sbin/honeypot-pcap-reaper >/dev/null
after=$(find /var/lib/honeypot/pcap -name 'hp-*.pcap' | wc -l | tr -d ' ')
[ "$after" -lt "$before" ] && ok "pruned ($before -> $after)" || bad "did not prune"
[ -f /var/lib/honeypot/pcap/hp-004.pcap ] \
  && ok "newest capture kept" || bad "newest capture deleted"
[ -f /var/lib/honeypot/pcap/hp-001.pcap ] \
  && bad "oldest capture kept" || ok "oldest capture pruned first"
PCAP_MAX_BYTES=99999999999 /usr/local/sbin/honeypot-pcap-reaper >/dev/null
n=$(find /var/lib/honeypot/pcap -name 'hp-*.pcap' | wc -l | tr -d ' ')
[ "$n" = "$after" ] && ok "no pruning under budget" || bad "pruned under budget"

echo "[14b] watchdog trips when the capture disk is nearly full"
/usr/local/sbin/honeypot-rearm >/dev/null 2>&1 || true
echo 0 > /var/lib/honeypot/watchdog.state
DISK_MIN_FREE_BYTES=99999999999999 HP_COUNTER_CMD="echo 0" \
  /usr/local/sbin/honeypot-watchdog >/dev/null 2>&1 || true
[ -f /var/lib/honeypot/killswitch.tripped ] \
  && ok "tripped on low disk" || bad "did not trip on low disk"
/usr/local/sbin/honeypot-rearm >/dev/null

echo "[15] shellcheck"
if shellcheck -S warning gateway/*.sh honeypot/*.sh ops/*.sh tests/*.sh; then
  ok "shellcheck clean"; else bad "shellcheck findings"; fi

echo
[ "$fail" = 0 ] && echo "ALL GATEWAY TESTS PASSED" || echo "SOME TESTS FAILED"
exit "$fail"
