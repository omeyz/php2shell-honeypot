#!/usr/bin/env bash
# Build the bait: Debian 12 + Apache mod_php on a PRE-PATCH PHP, plus a stock
# WordPress so the box looks like a real site.
#
# Run ONLY on the isolated honeypot VM, behind the gateway, with no public IP.
# This machine is EXPECTED to be compromised. Put nothing real on it: no
# personal SSH keys, no tailnet membership, no reused passwords.
#
# WHY A DATED SNAPSHOT RATHER THAN A VERSION PIN
#
# Distributions backport security fixes without changing the upstream version
# number, so "8.2.32 < 8.2.35" does not prove a package is unpatched. What
# does prove it is the date: a package published before the fix existed
# cannot contain the fix. So we pin Debian's snapshot archive to a timestamp
# before 2026-10-21 and take whatever PHP was current then.
#
# The packaged repositories no longer carry a pre-patch PHP at all, which is
# the expected and correct state of the world.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"

FIX_DATE=20261021           # the day the PHP2Shell fixes shipped
SNAP=${HP_SNAPSHOT:-20261018T000000Z}
PHPV=${HP_PHP_VERSION:-8.2}
PHP_PKG_VER=${HP_PHP_PKG_VER:-8.2.32-1~deb12u1}
GATEWAY_PRIV_IP="${GATEWAY_PRIV_IP:-}"
# Title of the bait WordPress site. Pick something bland and plausible.
SITE_TITLE="${HP_SITE_TITLE:-Example Supply Co}"

# The pin must predate the fix, or this builds a patched box that collects
# nothing but scan attempts.
if [ "${SNAP%%T*}" -ge "$FIX_DATE" ]; then
  echo "REFUSING: snapshot $SNAP is not before the fix date $FIX_DATE." >&2
  echo "A patched honeypot is not a honeypot." >&2
  exit 1
fi

# Refuse to build on a box reachable directly from the internet.
if ip -4 -o addr show scope global | awk '{print $4}' \
   | grep -qvE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
  echo "REFUSING: this host has a non-private global address." >&2
  echo "The honeypot must sit behind the gateway on private addressing only." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
echo "== base packages from the current repo =="
apt-get update -qq
apt-get install -y -qq apache2 mariadb-server curl ca-certificates \
  auditd audispd-plugins rsyslog

echo "== pinning Debian snapshot $SNAP for PHP =="
cat > /etc/apt/sources.list.d/snapshot-php.list <<EOF
# Dated snapshot, taken before the PHP2Shell fixes shipped on $FIX_DATE.
deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/$SNAP/ bookworm main
EOF
# Snapshot Release files are expired by definition; allow that for this source.
cat > /etc/apt/apt.conf.d/99-snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
EOF
apt-get update -qq

echo "== installing PHP $PHPV at $PHP_PKG_VER (pre-patch by date) =="
apt-get install -y -qq --allow-downgrades \
  "libapache2-mod-php$PHPV=$PHP_PKG_VER" \
  "php$PHPV-cli=$PHP_PKG_VER" \
  "php$PHPV-common=$PHP_PKG_VER" \
  "php$PHPV-mysql=$PHP_PKG_VER" \
  "php$PHPV-opcache=$PHP_PKG_VER" \
  "php$PHPV-readline=$PHP_PKG_VER"
apt-mark hold "libapache2-mod-php$PHPV" "php$PHPV-cli" "php$PHPV-common" \
  "php$PHPV-mysql" "php$PHPV-opcache" "php$PHPV-readline" >/dev/null

echo "== verifying the installed build does not already carry the fix =="
# A positive check rather than version arithmetic: if the changelog mentions
# either CVE, the fix is in and this host is useless as bait.
CL=/usr/share/doc/php$PHPV-common/changelog.Debian.gz
if [ -f "$CL" ] && zgrep -qE 'CVE-2026-109(618|619)' "$CL"; then
  echo "REFUSING: installed PHP changelog references the PHP2Shell CVEs." >&2
  echo "This build is patched. Pick an earlier snapshot." >&2
  exit 1
fi
echo "  ok: no reference to CVE-2026-109618/109619 in the changelog"

# mod_php + prefork: long-lived workers with shared state. This is the
# configuration PHP flagged as highest risk, and the condition the published
# chain needs. Capturing it is the point.
echo "== apache: mod_php with prefork, long-lived workers =="
a2dismod -q mpm_event 2>/dev/null || true
a2enmod -q mpm_prefork
a2enmod -q "php$PHPV"

cat > "/etc/php/$PHPV/apache2/conf.d/99-honeypot.ini" <<'INI'
; Upstream defaults, stated explicitly so the exposure is documented rather
; than accidental.
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
memory_limit = 128M
expose_php = On
display_errors = Off
log_errors = On
error_log = /var/log/php_errors.log
INI

cat > /etc/apache2/conf-available/honeypot-tuning.conf <<'CONF'
<IfModule mpm_prefork_module>
  StartServers 4
  MinSpareServers 4
  MaxSpareServers 8
  MaxRequestWorkers 32
  MaxConnectionsPerChild 0
</IfModule>
ServerSignature On
ServerTokens Full
CONF
a2enconf -q honeypot-tuning

echo "== WordPress, so the site is plausible to a human operator =="
install -d -o www-data -g www-data -m 0755 /var/www/wordpress
if [ ! -f /var/www/wordpress/wp-settings.php ]; then
  DBPASS=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)
  mysql -e "CREATE DATABASE IF NOT EXISTS wp;
            CREATE USER IF NOT EXISTS 'wp'@'localhost' IDENTIFIED BY '$DBPASS';
            GRANT ALL ON wp.* TO 'wp'@'localhost'; FLUSH PRIVILEGES;"
  tmp=$(mktemp -d)
  curl -fsSL https://wordpress.org/latest.tar.gz -o "$tmp/wp.tar.gz"
  chmod 0711 "$tmp"; chmod 0644 "$tmp/wp.tar.gz"
  # Extracted as www-data so no recursive ownership change is needed.
  runuser -u www-data -- tar -xzf "$tmp/wp.tar.gz" --strip-components=1 \
    -C /var/www/wordpress
  runuser -u www-data -- cp /var/www/wordpress/wp-config-sample.php \
    /var/www/wordpress/wp-config.php
  runuser -u www-data -- sed -i \
    "s/database_name_here/wp/; s/username_here/wp/; s/password_here/$DBPASS/" \
    /var/www/wordpress/wp-config.php
  printf '%s\n' "$DBPASS" > /root/.wp-db-pass; chmod 600 /root/.wp-db-pass
fi

# WordPress makes outbound HTTP calls on page load. With egress throttled
# those calls hang, the landing page takes ~26s, and the logs fill with
# WordPress's own traffic. Blocking them makes the bait respond like a real
# site AND means any egress we do see is the attacker's, not the CMS's.
grep -q WP_HTTP_BLOCK_EXTERNAL /var/www/wordpress/wp-config.php || \
  runuser -u www-data -- sed -i \
    "s/^\(\/\* That's all, stop editing.*\)/define('WP_HTTP_BLOCK_EXTERNAL', true);\ndefine('AUTOMATIC_UPDATER_DISABLED', true);\n\n\1/" \
    /var/www/wordpress/wp-config.php

# Finish the install so / renders a real page. The admin password is strong
# on purpose: the intended way in is the PHP flaw, not a guessable login,
# or the intel gets muddied by unrelated brute-force traffic.
if ! mysql -N -B -e 'SHOW TABLES' wp 2>/dev/null | grep -q '^wp_options$'; then
  WPADMINPW=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 28)
  printf '%s\n' "$WPADMINPW" > /root/.wp-admin-pass; chmod 600 /root/.wp-admin-pass
  curl -fsS -m 120 -o /dev/null \
    --data-urlencode "weblog_title=$SITE_TITLE" \
    --data-urlencode "user_name=siteadmin" \
    --data-urlencode "admin_password=$WPADMINPW" \
    --data-urlencode "admin_password2=$WPADMINPW" \
    --data-urlencode "pw_weak=1" \
    --data-urlencode "admin_email=webmaster@localhost.localdomain" \
    --data-urlencode "blog_public=1" \
    "http://127.0.0.1/wp-admin/install.php?step=2" \
    && echo "  WordPress install completed (admin password in /root/.wp-admin-pass)" \
    || echo "  WARNING: WordPress install did not complete; / will redirect to the installer"
fi

sed -i 's#DocumentRoot /var/www/html#DocumentRoot /var/www/wordpress#' \
  /etc/apache2/sites-available/000-default.conf
grep -q 'Directory /var/www/wordpress' /etc/apache2/apache2.conf || \
cat >> /etc/apache2/apache2.conf <<'CONF'
<Directory /var/www/wordpress>
  Options Indexes FollowSymLinks
  AllowOverride All
  Require all granted
</Directory>
CONF

echo "== keep the shipped logs shippable =="
# php_errors.log must exist before rsyslog starts or imfile will not monitor
# it, and copytruncate keeps every shipped log's inode stable across rotation.
# Without that, imfile follows the rotated-away inode and live requests stop
# reaching the gateway with no error anywhere.
touch /var/log/php_errors.log
chown www-data:adm /var/log/php_errors.log 2>/dev/null || true
chmod 0640 /var/log/php_errors.log
cat > /etc/logrotate.d/honeypot-shipped <<'CONF'
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/php_errors.log
{
  daily
  rotate 7
  copytruncate
  missingok
  notifempty
  compress
  delaycompress
}
CONF

echo "== command logging, shipped off-box as it happens =="
# A root attacker can stop this. The gateway's pcap is why that does not
# cost us the capture.
install -m 0640 "$HERE/auditd-rules.rules" /etc/audit/rules.d/99-honeypot.rules
augenrules --load >/dev/null 2>&1 || true
systemctl enable --now auditd >/dev/null 2>&1 || true

if [ -n "$GATEWAY_PRIV_IP" ]; then
  sed "s/GATEWAY_PRIV_IP/$GATEWAY_PRIV_IP/" "$HERE/rsyslog-ship.conf" \
    > /etc/rsyslog.d/90-ship.conf
  systemctl restart rsyslog
  echo "  shipping logs to $GATEWAY_PRIV_IP:514"
else
  echo "  >>> re-run with GATEWAY_PRIV_IP=<ip>, or edit /etc/rsyslog.d/90-ship.conf"
fi

systemctl restart apache2

echo
echo "=== built ==="
php -v | head -1
echo "snapshot pin:     $SNAP (fix shipped $FIX_DATE)"
printf 'upload_progress:  '; php -r 'echo ini_get("session.upload_progress.enabled")?"On":"Off","\n";'
printf 'apache mpm:       '; apache2ctl -M 2>/dev/null | grep -o 'mpm_[a-z]*' | head -1
printf 'php sapi in use:  '; apache2ctl -M 2>/dev/null | grep -o "php[0-9_]*" | head -1
curl -fsS -o /dev/null -w 'local http:         %{http_code}\n' http://127.0.0.1/ || true
cat <<'WARN'

This host is intentionally running unpatched PHP. It must stay behind the
gateway with egress denied by default, and be reverted to a clean snapshot
after each observation window.

Not verified here: that the flaw is actually exploitable. Confirming that
would mean running an exploit, which this repo does not contain. What is
verified is the package predates the fix, the risky SAPI is in use, and the
feature the published chain relies on is enabled.
WARN
