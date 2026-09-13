#!/bin/bash
# Opt-in Xray extension for an existing Ragnar installation. Run on the VPS as root.
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
VERSION="v26.3.27"
ROOT=/etc/ragnar/xray
BACKUP="$ROOT/ssh-backup"
WORK=""
MIGRATING=no
SUCCESS=no
fail() { echo "ERROR: $*" >&2; exit 1; }

cleanup() {
  local status=$?
  if [ "$MIGRATING" = yes ] && [ "$SUCCESS" != yes ]; then
    echo "Setup failed; restoring the original SSH listeners." >&2
    systemctl disable --now ragnar-xray-expire.timer ragnar-xray.service 2>/dev/null || true
    rm -f /etc/systemd/system/wsproxy.service.d/ragnar-xray.conf
    cp -a "$BACKUP/stunnel.conf" /etc/stunnel/stunnel.conf
    cp -a "$BACKUP/ssh-tls.conf" /etc/stunnel/ssh-tls.conf
    rm -f "$ROOT/state.json" "$ROOT/config.json"
    systemctl daemon-reload
    systemctl restart wsproxy stunnel4 || true
    echo "SSH backups remain at $BACKUP. Check: systemctl status wsproxy stunnel4" >&2
  fi
  [ -z "$WORK" ] || rm -rf -- "$WORK"
  exit "$status"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || fail "Run as root."
[ -d /run/systemd/system ] || fail "This installer requires systemd on a Debian/Ubuntu VPS."
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) fail "Only Debian/Ubuntu are supported." ;; esac
[ -f "$BASE/ragnar_xray.py" ] || fail "Run from a complete Ragnar repository checkout."
[ ! -e "$ROOT/state.json" ] || fail "Already configured. Use menu -> Xray; users were not changed."
[ ! -e /etc/systemd/system/wsproxy.service.d/ragnar-xray.conf ] || fail "Existing migration override found; inspect it first."
for service in wsproxy stunnel4; do
  systemctl is-active --quiet "$service" || fail "Existing Ragnar $service must be running before migration."
done
for file in /etc/stunnel/stunnel.conf /etc/stunnel/ssh-tls.conf; do
  [ -f "$file" ] || fail "Missing Ragnar stunnel configuration: $file"
  grep -Eq '^[[:space:]]*accept[[:space:]]*=[[:space:]]*443[[:space:]]*$' "$file" \
    || fail "Custom stunnel configuration detected ($file). Migrate manually rather than overwrite it."
done

echo "Xray installation is optional and will change existing SSH client ports:"
echo "  SSH WebSocket: 80 -> 8080     SSH TLS: 443 -> 444     SSH: 22 unchanged"
echo "  VLESS WS: 80 non-TLS / 443 TLS; VMess WS: 8081 non-TLS / 8443 TLS"
echo "  Trojan WS: 2053 TLS; VLESS TCP: 2082 non-TLS / 2443 TLS"
echo "  VMess TCP: 2086 non-TLS / 2444 TLS; Trojan TCP: 2445 TLS"
echo "Each listener needs its own port. Ports can be changed through the Xray menu."
echo "Non-TLS VLESS does not encrypt traffic. Trojan is TLS-only."
echo "Raw TCP requires DNS-only/direct access, not Cloudflare's standard HTTP proxy."
echo "Account changes/expiry restart Xray and disconnect ALL Xray sessions."
echo "Keep this SSH session open. Allow 444 and 8080 in your provider firewall first."
read -r -p "Type MOVE SSH to accept these port changes: " confirm
[ "$confirm" = "MOVE SSH" ] || fail "Cancelled; no services changed."
DOMAIN=$(grep -m1 '^[[:space:]]*cert[[:space:]]*=' /etc/stunnel/ssh-tls.conf | awk '{print $3}' | sed 's|.*live/||;s|/.*||')
read -r -p "TLS domain [$DOMAIN]: " domain_input
DOMAIN=${domain_input:-$DOMAIN}
python3 - "$BASE" "$DOMAIN" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from ragnar_xray import hostname
hostname(sys.argv[2])
PY
CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
[ -s "$CERT" ] && [ -s "$KEY" ] || fail "Install a valid Let's Encrypt certificate for $DOMAIN first."
openssl x509 -in "$CERT" -noout -checkhost "$DOMAIN" | grep -q 'does match certificate' \
  || fail "Certificate does not cover $DOMAIN."
openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null || fail "Certificate has expired."

# Fail before touching SSH if any new default port is occupied (IPv4 or dual-stack IPv6).
python3 - "$BASE" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from ragnar_xray import check_port, DEFAULTS
for port in [444, 8080] + [entry[2] for entry in DEFAULTS if entry[2] not in (80, 443)]:
    check_port(port)
PY
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl unzip python3 openssl
case "$(uname -m)" in
  x86_64) ARCH=64 ;;
  aarch64|arm64) ARCH=arm64-v8a ;;
  *) fail "Supported CPU architectures: x86_64 and arm64." ;;
esac
WORK=$(mktemp -d)
ASSET="Xray-linux-$ARCH.zip"
URL="https://github.com/XTLS/Xray-core/releases/download/$VERSION/$ASSET"
curl --fail --location --retry 3 --proto '=https' -o "$WORK/$ASSET" "$URL"
curl --fail --location --retry 3 --proto '=https' -o "$WORK/checksum" "$URL.dgst"
SHA=$(awk '/^SHA2-256=/{print $2}' "$WORK/checksum")
[[ "$SHA" =~ ^[a-fA-F0-9]{64}$ ]] || fail "Missing official SHA256 checksum."
(cd "$WORK" && printf '%s  %s\n' "$SHA" "$ASSET" | sha256sum -c -) || fail "Xray checksum mismatch."
unzip -q "$WORK/$ASSET" xray -d "$WORK"
install -d -m 755 /usr/local/lib/ragnar-xray
install -m 755 "$WORK/xray" /usr/local/lib/ragnar-xray/xray
install -m 755 "$BASE/ragnar_xray.py" /usr/local/bin/ragnar-xray
/usr/local/lib/ragnar-xray/xray version
install -d -m 700 "$ROOT" "$BACKUP"
# Refuse to overwrite original migration backups from an earlier failed attempt.
[ -e "$BACKUP/stunnel.conf" ] || cp -a /etc/stunnel/stunnel.conf "$BACKUP/stunnel.conf"
[ -e "$BACKUP/ssh-tls.conf" ] || cp -a /etc/stunnel/ssh-tls.conf "$BACKUP/ssh-tls.conf"

cat > /etc/systemd/system/ragnar-xray.service <<'UNIT'
[Unit]
Description=Ragnar Xray (VLESS / VMess / Trojan)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
UMask=0077
ExecStartPre=/usr/local/bin/ragnar-xray render-boot
ExecStart=/usr/local/lib/ragnar-xray/xray run -config /etc/ragnar/xray/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/ragnar/xray
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/ragnar-xray-expire.service <<'UNIT'
[Unit]
Description=Revoke expired Ragnar Xray accounts
After=ragnar-xray.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ragnar-xray sync
UMask=0077
UNIT
cat > /etc/systemd/system/ragnar-xray-expire.timer <<'UNIT'
[Unit]
Description=Check Ragnar Xray expiry every 30 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=1s
Unit=ragnar-xray-expire.service

[Install]
WantedBy=timers.target
UNIT

# Only the following section modifies SSH. Failure restores the saved settings.
MIGRATING=yes
systemctl stop wsproxy stunnel4
install -d -m 755 /etc/systemd/system/wsproxy.service.d
cat > /etc/systemd/system/wsproxy.service.d/ragnar-xray.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /usr/local/bin/wsproxy.py -p 8080 -s 22
UNIT
sed -i -E 's/^([[:space:]]*accept[[:space:]]*=[[:space:]]*)443[[:space:]]*$/\1444/' \
  /etc/stunnel/stunnel.conf /etc/stunnel/ssh-tls.conf
/usr/local/bin/ragnar-xray init --domain "$DOMAIN" --certificate "$CERT" --key "$KEY"
systemctl daemon-reload
systemctl restart wsproxy stunnel4
systemctl enable --now ragnar-xray.service ragnar-xray-expire.timer
sleep 2
for service in wsproxy stunnel4 ragnar-xray; do
  systemctl is-active --quiet "$service" || fail "$service failed after migration."
done

# Standalone certbot needs port 80 free. Record only services that were running,
# then restore them even after a failed renewal (post hooks run on failure too).
install -d -m 755 /etc/letsencrypt/renewal-hooks/{pre,post,deploy}
cat > /etc/letsencrypt/renewal-hooks/pre/ragnar-xray.sh <<'HOOK'
#!/bin/bash
set -eu
umask 077
install -d -m 700 /run/ragnar-cert-renew
: > /run/ragnar-cert-renew/services
for service in wsproxy ragnar-xray; do
  if systemctl is-active --quiet "$service"; then
    echo "$service" >> /run/ragnar-cert-renew/services
    systemctl stop "$service"
  fi
done
HOOK
cat > /etc/letsencrypt/renewal-hooks/post/ragnar-xray.sh <<'HOOK'
#!/bin/bash
if [ -f /run/ragnar-cert-renew/services ]; then
  failed=0
  while read -r service; do
    case "$service" in wsproxy|ragnar-xray) systemctl start "$service" || failed=1 ;; esac
  done < /run/ragnar-cert-renew/services
  [ "$failed" -ne 0 ] || rm -f /run/ragnar-cert-renew/services
  exit "$failed"
fi
HOOK
# Replace Ragnar's old unconditional restart hook (which could start port 80 early).
cat > /etc/letsencrypt/renewal-hooks/deploy/ragnar-restart.sh <<'HOOK'
#!/bin/bash
systemctl try-restart stunnel4
if [ ! -f /run/ragnar-cert-renew/services ]; then
  systemctl try-restart ragnar-xray
fi
HOOK
chmod 755 /etc/letsencrypt/renewal-hooks/{pre,post}/ragnar-xray.sh \
  /etc/letsencrypt/renewal-hooks/deploy/ragnar-restart.sh
systemctl enable --now certbot.timer
if command -v ufw >/dev/null 2>&1; then
  for port in 80 443 444 8080 8081 8443 2053 2082 2443 2086 2444 2445; do
    ufw allow "$port/tcp" || echo "WARNING: manually open TCP $port in the firewall."
  done
fi
SUCCESS=yes
echo "Xray is ready. Create users using menu -> 11 (Xray), or ragnar-xray --help."
echo "SSH clients must now use WS 8080 / TLS 444. Plain SSH remains on 22."
echo "Allow the listed ports in your hosting provider firewall too."
echo "Expiry is checked every 30 seconds and on every Xray start (dates are UTC)."
echo "Check renewal on your VPS: certbot renew --dry-run"
/usr/local/bin/ragnar-xray listeners
