#!/usr/bin/env bash
# Prove the kill switch actually isolates the honeypot.
#
# Test the FORWARDED path, not the gateway's own. The kill switch adds rules
# to the forward chain, so traffic originating on the gateway itself goes
# through the output hook and is deliberately unaffected: that is what keeps
# admin access alive while the honeypot is cut off. Probing the honeypot
# FROM the gateway therefore succeeds even when the kill switch is engaged,
# and reads like a failure when it is not one.
#
# The real paths are internet-to-honeypot and honeypot-to-internet, both of
# which are forwarded. This drives the second one from the honeypot itself.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
. /etc/honeypot.env

KEY=${HP_KEY:-/home/$(logname 2>/dev/null || echo root)/hp_admin}
HPUSER=${HP_USER:-hpadmin}
[ -f "$KEY" ] || { echo "need an SSH key to the honeypot: set HP_KEY" >&2; exit 1; }

probe() {
  local out
  # curl -w already prints 000 when the attempt fails, so adding a fallback
  # echo concatenates two codes ("000000") and breaks the comparison. Take
  # curl's word for it and normalise to exactly three digits.
  out=$(ssh -i "$KEY" -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
            -o LogLevel=ERROR "$HPUSER@$HONEY_IP" \
            'curl -sS -o /dev/null -m 10 -w "%{http_code}" http://deb.debian.org/ 2>/dev/null' \
        2>/dev/null) || out=""
  out=$(printf '%s' "$out" | tr -cd '0-9')
  printf '%s' "${out:0:3}"
  [ -n "$out" ] || printf '000'
}

# A dead SSH and a blocked curl both surface as 000, which reads as "the kill
# switch failed" when it may mean "we lost the box". Settle that first, so a
# drill never reports a containment failure it did not observe.
if ! ssh -i "$KEY" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
        -o LogLevel=ERROR "$HPUSER@$HONEY_IP" true 2>/dev/null; then
  echo "INCONCLUSIVE: cannot SSH to $HPUSER@$HONEY_IP." >&2
  echo "The kill switch was NOT tested. Fix admin access and re-run." >&2
  exit 2
fi

fail=0
tripped_before=0
[ -f /var/lib/honeypot/killswitch.tripped ] && tripped_before=1

if [ "$tripped_before" = 1 ]; then
  echo "kill switch is already engaged; re-arming first for a clean test"
  /usr/local/sbin/honeypot-rearm >/dev/null
  sleep 2
fi

echo "1. baseline: honeypot egress should work"
a=$(probe)
[ "$a" != "000" ] && echo "   PASS egress works ($a)" \
                  || { echo "   FAIL egress already broken ($a)"; fail=1; }

echo "2. engaging the kill switch"
/usr/local/sbin/honeypot-killswitch "killswitch-verify drill" >/dev/null
sleep 1
b=$(probe)
[ "$b" = "000" ] && echo "   PASS egress cut off" \
                 || { echo "   FAIL egress still working ($b)"; fail=1; }

echo "3. re-arming"
/usr/local/sbin/honeypot-rearm >/dev/null
sleep 2
c=$(probe)
[ "$c" != "000" ] && echo "   PASS egress restored ($c)" \
                  || { echo "   FAIL egress not restored ($c)"; fail=1; }

echo
if [ "$fail" = 0 ]; then
  echo "kill switch verified on the forwarded path"
else
  echo "KILL SWITCH DID NOT BEHAVE AS EXPECTED -- do not expose the honeypot" >&2
fi
exit "$fail"
