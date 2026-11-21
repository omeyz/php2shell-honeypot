#!/usr/bin/env bash
# Install gateway services. Run as root on the GATEWAY only.
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -f honeypot.env ] || { echo "create honeypot.env from the .example first" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
# tshark asks whether non-root users may capture; answer it up front.
echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections
apt-get update
apt-get install -y nftables tcpdump jq rsyslog tshark

install -m 0600 honeypot.env /etc/honeypot.env
install -d -m 0750 /var/lib/honeypot /var/lib/honeypot/remote
install -m 0755 capture.sh    /usr/local/sbin/honeypot-capture
install -m 0755 watchdog.sh   /usr/local/sbin/honeypot-watchdog
install -m 0755 pcap-reaper.sh /usr/local/sbin/honeypot-pcap-reaper
install -m 0755 provision-mode.sh /usr/local/sbin/honeypot-provision-mode
install -m 0755 killswitch.sh /usr/local/sbin/honeypot-killswitch
install -m 0755 rearm.sh      /usr/local/sbin/honeypot-rearm
install -m 0755 killswitch-verify.sh /usr/local/sbin/honeypot-killswitch-verify

./render-nftables.sh honeypot.env /etc/nftables.conf

cat > /etc/systemd/system/honeypot-capture.service <<'U'
[Unit]
Description=Honeypot full packet capture
After=network-online.target nftables.service
[Service]
ExecStart=/usr/local/sbin/honeypot-capture
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
U

cat > /etc/systemd/system/honeypot-watchdog.service <<'U'
[Unit]
Description=Honeypot egress watchdog
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-watchdog
U

cat > /etc/systemd/system/honeypot-watchdog.timer <<'U'
[Unit]
Description=Run honeypot egress watchdog every minute
[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=5s
[Install]
WantedBy=timers.target
U

cat > /etc/systemd/system/honeypot-pcap-reaper.service <<'U'
[Unit]
Description=Keep the honeypot pcap directory inside its byte budget
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/honeypot-pcap-reaper
U

cat > /etc/systemd/system/honeypot-pcap-reaper.timer <<'U'
[Unit]
Description=Prune honeypot captures every 10 minutes
[Timer]
OnBootSec=120
OnUnitActiveSec=600
AccuracySec=30s
[Install]
WantedBy=timers.target
U

cat > /etc/rsyslog.d/10-honeypot-collector.conf <<'U'
module(load="imudp")
input(type="imudp" port="514")
template(name="hpfile" type="string" string="/var/lib/honeypot/remote/%HOSTNAME%.log")
if ($fromhost-ip != "127.0.0.1") then { action(type="omfile" dynaFile="hpfile") stop }
U

printf 'net.ipv4.ip_forward=1\nnet.ipv6.conf.all.disable_ipv6=1\n' > /etc/sysctl.d/99-honeypot.conf
sysctl -p /etc/sysctl.d/99-honeypot.conf

systemctl daemon-reload
systemctl enable --now nftables honeypot-capture.service \
  honeypot-watchdog.timer honeypot-pcap-reaper.timer
systemctl restart rsyslog
echo "gateway ready. Verify with: nft list ruleset | head -40"
