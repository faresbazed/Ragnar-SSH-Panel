#!/bin/bash
# Install/repair Xray without moving SSH ports. Run on the VPS as root.
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# os-release owns VERSION; never use it for a software release URL.
readonly XRAY_RELEASE="v26.3.27"
. /etc/os-release
fail() { echo "ERROR: $*" >&2; exit 1; }

xray_download_url() {
  local arch
  case "${1:-$(uname -m)}" in
    x86_64) arch=64 ;;
    aarch64|arm64) arch=arm64-v8a ;;
    *) echo "Unsupported CPU architecture" >&2; return 1 ;;
  esac
  printf 'https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip\n' "$XRAY_RELEASE" "$arch"
}
# Safe diagnostic/regression-test entry point; no root, writes or installation.
if [ "${1:-}" = --download-url ]; then
  xray_download_url "${2:-$(uname -m)}"
  exit
fi

ROOT=/etc/ragnar/xray
WORK=""
CHANGED=no
SUCCESS=no
FILES=(/usr/local/bin/ragnar-xray /usr/local/lib/ragnar-xray/xray
  /etc/systemd/system/ragnar-xray.service /etc/systemd/system/ragnar-xray-expire.service
  /etc/systemd/system/ragnar-xray-expire.timer
  /etc/systemd/system/wsproxy.service.d/ragnar-owner.conf
  /etc/systemd/system/stunnel4.service.d/ragnar-owner.conf
  /etc/systemd/system/wsproxy.service.d/ragnar-xray.conf
  /etc/stunnel/stunnel.conf /etc/stunnel/ssh-tls.conf
  /etc/letsencrypt/renewal-hooks/pre/ragnar-xray.sh
  /etc/letsencrypt/renewal-hooks/post/ragnar-xray.sh
  /etc/letsencrypt/renewal-hooks/deploy/ragnar-restart.sh
  "$ROOT/state.json" "$ROOT/config.json")
SERVICES=(wsproxy stunnel4 ragnar-xray ragnar-xray-expire.timer)
declare -A WAS_ACTIVE WAS_ENABLED
cleanup() {
  local status=$? file service
  set +e
  if [ "$CHANGED" = yes ] && [ "$SUCCESS" != yes ]; then
    echo "Setup failed; restoring previous configuration and selected services." >&2
    systemctl stop ragnar-xray-expire.timer ragnar-xray-expire.service
    systemctl stop ragnar-xray wsproxy stunnel4
    for file in "${FILES[@]}"; do
      if [ -e "$WORK/snapshot$file" ]; then
        cp -a "$WORK/snapshot$file" "$file"
      else
        rm -f "$file"
      fi
    done
    systemctl daemon-reload
    for service in "${SERVICES[@]}"; do
      if [ "${WAS_ENABLED[$service]}" = yes ]; then
        systemctl enable "$service"
      else
        systemctl disable "$service"
      fi
      if [ "${WAS_ACTIVE[$service]}" = yes ]; then
        systemctl start "$service" || echo "RECOVERY: check systemctl status $service" >&2
      fi
    done
    echo "Review the error above before retrying. No account data was intentionally removed." >&2
  fi
  [ -z "$WORK" ] || rm -rf -- "$WORK"
  exit "$status"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || fail "Run as root."
[ -d /run/systemd/system ] || fail "This installer needs a systemd Debian/Ubuntu VPS."
case "$ID" in debian|ubuntu) ;; *) fail "Only Debian/Ubuntu are supported." ;; esac
[ -f "$BASE/ragnar_xray.py" ] || fail "Run from a complete updated Ragnar checkout."
[ ! -f /run/ragnar-cert-renew/services ] || fail "Finish/recover certificate renewal before setup."
for service in wsproxy stunnel4; do
  systemctl cat "$service" >/dev/null || fail "Install the base Ragnar SSH panel first ($service missing)."
done
LEGACY=no
if [ -f /etc/systemd/system/wsproxy.service.d/ragnar-xray.conf ]; then
  LEGACY=yes
  echo "Old port-migration setup detected. This repair restores SSH WS 80 and TLS 443."
fi
for file in /etc/stunnel/stunnel.conf /etc/stunnel/ssh-tls.conf; do
  [ -f "$file" ] || fail "Missing Ragnar stunnel configuration: $file"
  if [ "$LEGACY" = yes ]; then
    grep -Eq '^[[:space:]]*accept[[:space:]]*=[[:space:]]*(443|444)[[:space:]]*$' "$file" \
      || fail "Custom stunnel ports detected; inspect $file manually."
  else
    grep -Eq '^[[:space:]]*accept[[:space:]]*=[[:space:]]*443[[:space:]]*$' "$file" \
      || fail "Expected SSH TLS on 443; custom configuration left untouched."
  fi
done

echo "SSH keeps WebSocket 80 and TLS 443; plain SSH stays on 22."
echo "Both SSH and Xray users can be saved for these ports. Only one service owns each port."
echo "New setup keeps SSH active by default. Switch each port using menu -> 12."
echo "Existing Xray users and port selections are preserved when repairing/updating."
echo "Other Xray defaults: VMess WS 8081/8443; Trojan WS TLS 2053; TCP 2082/2443/2086/2444/2445."
echo "Non-TLS VLESS is unencrypted; Trojan requires TLS. TCP requires direct/DNS-only access."
read -r -p "Install/repair Xray? [y/N]: " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || fail "Cancelled; services unchanged."
DOMAIN=$(grep -m1 '^[[:space:]]*cert[[:space:]]*=' /etc/stunnel/ssh-tls.conf | awk '{print $3}' | sed 's|.*live/||;s|/.*||')
read -r -p "TLS domain [$DOMAIN]: " domain_input
DOMAIN=${domain_input:-$DOMAIN}
python3 -B - "$BASE" "$DOMAIN" <<'PY'
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
URL=$(xray_download_url)
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl unzip python3 openssl util-linux
WORK=$(mktemp -d)
echo "Downloading Xray $XRAY_RELEASE from $URL"
curl --fail --location --retry 3 --proto '=https' -o "$WORK/xray.zip" "$URL"
curl --fail --location --retry 3 --proto '=https' -o "$WORK/checksum" "$URL.dgst"
SHA=$(awk '/^SHA2-256=/{print $2}' "$WORK/checksum")
[[ "$SHA" =~ ^[a-fA-F0-9]{64}$ ]] || fail "Missing official SHA256 checksum."
(cd "$WORK" && printf '%s  xray.zip\n' "$SHA" | sha256sum -c -) || fail "Xray checksum mismatch."
unzip -q "$WORK/xray.zip" xray -d "$WORK"
chmod 755 "$WORK/xray"
"$WORK/xray" version

for file in "${FILES[@]}"; do
  if [ -e "$file" ]; then
    mkdir -p "$WORK/snapshot$(dirname "$file")"
    cp -a "$file" "$WORK/snapshot$file"
  fi
done
for service in "${SERVICES[@]}"; do
  WAS_ACTIVE[$service]=no; WAS_ENABLED[$service]=no
  if systemctl is-active --quiet "$service"; then WAS_ACTIVE[$service]=yes; fi
  if systemctl is-enabled --quiet "$service"; then WAS_ENABLED[$service]=yes; fi
done
CHANGED=yes
systemctl stop ragnar-xray-expire.timer ragnar-xray-expire.service 2>/dev/null || true
systemctl stop ragnar-xray 2>/dev/null || true
install -d -m 700 "$ROOT"
install -d -m 755 /usr/local/lib/ragnar-xray
install -m 755 "$WORK/xray" /usr/local/lib/ragnar-xray/xray
install -m 755 "$BASE/ragnar_xray.py" /usr/local/bin/ragnar-xray
if [ "$LEGACY" = yes ]; then
  systemctl stop wsproxy stunnel4
  rm -f /etc/systemd/system/wsproxy.service.d/ragnar-xray.conf
  sed -i -E 's/^([[:space:]]*accept[[:space:]]*=[[:space:]]*)444[[:space:]]*$/\1443/' \
    /etc/stunnel/stunnel.conf /etc/stunnel/ssh-tls.conf
fi
if [ -f "$ROOT/state.json" ]; then
  # Upgrade state atomically, preserving users, credentials, listeners and expiry.
  python3 -B - "$BASE" "$DOMAIN" "$CERT" "$KEY" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from ragnar_xray import Manager, atomic, encoded
manager = Manager()
state = manager.load()
state.setdefault('port_owners', {'80': 'ssh', '443': 'ssh'})
state.update(domain=sys.argv[2], certificate=sys.argv[3], key=sys.argv[4])
atomic(manager.state_path, encoded(state))
PY
else
  /usr/local/bin/ragnar-xray init --domain "$DOMAIN" --certificate "$CERT" --key "$KEY"
fi

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
install -d -m 755 /etc/systemd/system/{wsproxy,stunnel4}.service.d
cat > /etc/systemd/system/wsproxy.service.d/ragnar-owner.conf <<'UNIT'
[Service]
ExecCondition=/usr/local/bin/ragnar-xray allow-ssh 80
UNIT
cat > /etc/systemd/system/stunnel4.service.d/ragnar-owner.conf <<'UNIT'
[Service]
ExecCondition=/usr/local/bin/ragnar-xray allow-ssh 443
UNIT
systemctl daemon-reload
# Stop only SSH services whose ports are selected for Xray. No port rewriting.
for pair in '80 wsproxy' '443 stunnel4'; do
  read -r port service <<< "$pair"
  if ! /usr/local/bin/ragnar-xray allow-ssh "$port"; then
    systemctl stop "$service"
  fi
done
systemctl enable wsproxy stunnel4 ragnar-xray ragnar-xray-expire.timer
systemctl restart ragnar-xray
systemctl start wsproxy stunnel4 ragnar-xray-expire.timer
sleep 2
systemctl is-active --quiet ragnar-xray || fail "Xray failed; inspect journalctl -u ragnar-xray."
for pair in '80 wsproxy' '443 stunnel4'; do
  read -r port service <<< "$pair"
  if /usr/local/bin/ragnar-xray allow-ssh "$port"; then
    systemctl is-active --quiet "$service" || fail "$service failed on its original port."
  fi
done

install -d -m 755 /etc/letsencrypt/renewal-hooks/{pre,post,deploy}
cat > /etc/letsencrypt/renewal-hooks/pre/ragnar-xray.sh <<'HOOK'
#!/bin/bash
set -eu
umask 077
install -d -m 700 /run/ragnar-cert-renew
exec 9>/etc/ragnar/xray/.lock
flock -x 9
[ ! -f /run/ragnar-cert-renew/services ] || exit 1
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
umask 077
exec 9>/etc/ragnar/xray/.lock
flock -x 9 || exit 1
if [ -f /run/ragnar-cert-renew/services ]; then
  failed=0
  while read -r service; do
    case "$service" in wsproxy|ragnar-xray) systemctl start "$service" || failed=1 ;; esac
  done < /run/ragnar-cert-renew/services
  [ "$failed" -ne 0 ] || rm -f /run/ragnar-cert-renew/services
  exit "$failed"
fi
HOOK
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
  for port in 80 443 8081 8443 2053 2082 2443 2086 2444 2445; do
    ufw allow "$port/tcp" || echo "WARNING: manually open TCP $port."
  done
fi
SUCCESS=yes
echo "Xray installed/configured. SSH ports remain 80/443; accounts are preserved."
/usr/local/bin/ragnar-xray ports
read -r -p "Switch BOTH 80 and 443 to Xray now (disconnects SSH tunnels)? [y/N]: " use_xray
if [[ "$use_xray" =~ ^[Yy]$ ]]; then
  /usr/local/bin/ragnar-xray switch both xray --yes
fi
echo "Create users: menu -> 11. Switch individual ports: menu -> 12."
echo "Plain SSH 22 and DNS tunneling remain available regardless of port selection."
echo "Check provider firewalls and run: certbot renew --dry-run"
