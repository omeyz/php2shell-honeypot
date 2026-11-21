#!/usr/bin/env bash
# Cut the honeypot off from the cloud metadata server.
#
# Run this LAST, on the honeypot, and only after you have confirmed you can
# still reach the box through the gateway. It breaks the Google guest agent
# and SSH key syncing, which is the point: the metadata server is how a
# rooted VM mints cloud credentials, and VPC firewall rules cannot block it.
#
# DHCP is left working, so the instance keeps its lease. Only TCP to the
# metadata address is refused, which is the HTTP API that serves tokens.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

RESOLVER=${RESOLVER:-1.1.1.1}

# On GCP the guest agent syncs SSH keys from instance metadata into
# authorized_keys. Once metadata is blocked that sync stops, and a key the
# agent was managing can go away. So an admin user whose authorized_keys is
# a plain local file, not agent-managed, has to exist BEFORE this runs.
#
# Pass HP_FALLBACK_USER to have it checked, and HP_FALLBACK_KEY to create it.
FB_USER=${HP_FALLBACK_USER:-}
FB_KEY=${HP_FALLBACK_KEY:-}
if [ -n "$FB_USER" ] && [ -n "$FB_KEY" ] && ! id "$FB_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$FB_USER"
  install -d -m 0700 -o "$FB_USER" -g "$FB_USER" "/home/$FB_USER/.ssh"
  printf '%s\n' "$FB_KEY" > "/home/$FB_USER/.ssh/authorized_keys"
  chown "$FB_USER:$FB_USER" "/home/$FB_USER/.ssh/authorized_keys"
  chmod 0600 "/home/$FB_USER/.ssh/authorized_keys"
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$FB_USER" > "/etc/sudoers.d/90-$FB_USER"
  chmod 0440 "/etc/sudoers.d/90-$FB_USER"
  echo "created agent-independent admin user: $FB_USER"
fi
if [ -n "$FB_USER" ]; then
  [ -s "/home/$FB_USER/.ssh/authorized_keys" ] || {
    echo "REFUSING: $FB_USER has no authorized_keys. Blocking metadata now" >&2
    echo "would risk locking you out of the honeypot entirely." >&2
    exit 1; }
  echo "fallback admin confirmed: $FB_USER"
else
  echo "WARNING: no HP_FALLBACK_USER given. If your only SSH key is managed" >&2
  echo "by the guest agent, you may lose access after this." >&2
fi

# DNS first: the metadata server is also the resolver on GCP, so pin a real
# one before refusing it, or name resolution dies with the next lookup.
#
# /etc/resolv.conf ships as a SYMLINK into /run/systemd/resolve/. Writing
# through it lands on tmpfs, where chattr +i is unsupported, and resolved
# rewrites the file on its next refresh with the DHCP nameserver -- the
# metadata server this script is about to block. DNS then dies quietly some
# time after build, taking all egress with it. So replace the symlink with a
# static file on disk, tell resolved the same thing, and VERIFY the immutable
# flag instead of swallowing the failure.
chattr -i /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf
printf 'nameserver %s\noptions timeout:2 attempts:2\n' "$RESOLVER" > /etc/resolv.conf
chmod 0644 /etc/resolv.conf

if [ -d /etc/systemd ]; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/99-honeypot.conf <<CONF
[Resolve]
DNS=$RESOLVER
FallbackDNS=
DNSStubListener=no
CONF
  systemctl restart systemd-resolved 2>/dev/null || true
fi

chattr +i /etc/resolv.conf
if ! lsattr /etc/resolv.conf 2>/dev/null | awk '{print $1}' | grep -q i; then
  echo "REFUSING: /etc/resolv.conf is not immutable, so the DNS pin will not" >&2
  echo "hold and egress will fail silently once resolved refreshes." >&2
  exit 1
fi

apt-get install -y -qq nftables

cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
# Honeypot-local ruleset. An attacker with root can flush this; it is defence
# in depth only. The hard boundary is the VPC egress deny plus the fact that
# this instance has no service account to steal a token for.
flush ruleset

table inet local {
  chain output {
    type filter hook output priority 0; policy accept;

    # Keep the DHCP lease alive.
    udp dport { 67, 68 } accept
    udp sport { 67, 68 } accept

    # Refuse the metadata HTTP API. This is the credential endpoint.
    #
    # The LOGGING is rate-limited but the verdict is not. The guest agent
    # polls metadata constantly; logging every packet produced hundreds of
    # thousands of lines that buried the real traffic and, because it all
    # forwards over UDP, pushed genuine Apache lines out of the queue.
    #
    # Note the limit sits on a log-only rule that carries NO verdict and
    # falls through to the reject below. Putting "limit rate" on the reject
    # rule itself would mean packets over the limit stop matching it, and
    # metadata would quietly become reachable again.
    ip daddr 169.254.169.254 tcp dport { 80, 443 } \
        limit rate 6/minute burst 10 packets \
        log prefix "METADATA-BLOCK " level warn
    ip daddr 169.254.169.254 tcp dport { 80, 443 } reject with tcp reset

    # Everything else link-local goes nowhere useful.
    ip daddr 169.254.0.0/16 limit rate 6/minute burst 10 packets \
        log prefix "LINKLOCAL-BLOCK " level warn
    ip daddr 169.254.0.0/16 drop
  }
}
EOF
chmod 0755 /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable --now nftables

echo "metadata API blocked. Verifying it is actually refused:"
if curl -fsS -m 3 -H 'Metadata-Flavor: Google' \
     http://169.254.169.254/computeMetadata/v1/instance/service-accounts/ >/dev/null 2>&1; then
  echo "  WARNING: metadata still reachable. Do not expose this host." >&2
  exit 1
else
  echo "  OK: metadata unreachable"
fi
echo "Confirm DNS still works:"
getent hosts deb.debian.org >/dev/null && echo "  OK: DNS resolves" || echo "  WARNING: DNS broken"
