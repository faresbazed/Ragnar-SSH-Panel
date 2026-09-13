#!/bin/bash
# Fresh, reproducible dnstt setup. Does not disable systemd-resolved or move SSH.
set -euo pipefail
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly DNSTT_RELEASE=20260501
readonly DNSTT_SHA256=a7b21d3d787570d9127643e360e150d2da7b33aa8039d0546a04dcfe8ee1864f
readonly GO_RELEASE=1.26.1
fail() { echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail "Run as root."
[ -d /run/systemd/system ] || fail "systemd is required."
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) fail "Debian/Ubuntu only." ;; esac
[ -f "$BASE/ragnar_dns.py" ] || fail "Update the complete Ragnar checkout first."
echo "This replaces the old DNS setup with official dnstt built from verified source."
echo "UDP 53 binds to a local VPS IP directly; systemd-resolved and SSH 22 stay untouched."
echo "Existing DNS keys are preserved. Only Ragnar's old 53 -> 5300 redirect is removed."
echo "DNS accounts use your normal SSH username/password."
read -r -p "Rebuild/configure DNS tunneling (disconnects existing DNS tunnels)? [y/N]: " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || fail "Cancelled."

WORK=$(mktemp -d)
CHANGED=no
SUCCESS=no
REMOVED=0
DNS_ACTIVE=no; DNS_ENABLED=no; LEGACY_ACTIVE=no; LEGACY_ENABLED=no
FILES=(/usr/local/bin/dnstt-server /usr/local/bin/dnstt-client /usr/local/bin/ragnar-dns
  /etc/systemd/system/dnstt-server.service /etc/systemd/system/ragnar-iptables.service
  /etc/iptables/rules.v4 /etc/dnstt/ragnar.json)
cleanup() {
  local status=$? file n
  set +e
  if [ "$CHANGED" = yes ] && [ "$SUCCESS" != yes ]; then
    echo "DNS setup failed; restoring previous binaries/configuration and legacy rules." >&2
    systemctl stop dnstt-server
    for file in "${FILES[@]}"; do
      if [ -e "$WORK/snapshot$file" ]; then
        cp -a "$WORK/snapshot$file" "$file"
      else
        rm -f "$file"
      fi
    done
    for ((n=0; n<REMOVED; n++)); do
      iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
    done
    systemctl daemon-reload
    if [ "$DNS_ENABLED" = yes ]; then systemctl enable dnstt-server; else systemctl disable dnstt-server; fi
    if [ "$LEGACY_ENABLED" = yes ]; then systemctl enable ragnar-iptables; fi
    if [ "$LEGACY_ACTIVE" = yes ]; then systemctl start ragnar-iptables; fi
    if [ "$DNS_ACTIVE" = yes ]; then systemctl start dnstt-server; fi
    echo "Existing keys were preserved. Read the failure above; check journalctl -u dnstt-server." >&2
  fi
  rm -rf -- "$WORK"
  exit "$status"
}
trap cleanup EXIT
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl ca-certificates unzip python3 openssl dnsutils iproute2 iptables util-linux
case "$(uname -m)" in
  x86_64) GO_ARCH=amd64; GO_SHA256=031f088e5d955bab8657ede27ad4e3bc5b7c1ba281f05f245bcc304f327c987a ;;
  aarch64|arm64) GO_ARCH=arm64; GO_SHA256=a290581cfe4fe28ddd737dde3095f3dbeb7f2e4065cab4eae44dfc53b760c2f7 ;;
  *) fail "Only amd64 and arm64 are supported." ;;
esac
# An isolated verified toolchain also works on systems whose apt Go is too old.
curl --fail --location --retry 3 --proto '=https' -o "$WORK/go.tar.gz" \
  "https://go.dev/dl/go$GO_RELEASE.linux-$GO_ARCH.tar.gz"
printf '%s  %s\n' "$GO_SHA256" "$WORK/go.tar.gz" | sha256sum -c -
tar -xzf "$WORK/go.tar.gz" -C "$WORK"
curl --fail --location --retry 3 --proto '=https' -o "$WORK/dnstt.zip" \
  "https://www.bamsoftware.com/software/dnstt/dnstt-$DNSTT_RELEASE.zip"
printf '%s  %s\n' "$DNSTT_SHA256" "$WORK/dnstt.zip" | sha256sum -c -
unzip -q "$WORK/dnstt.zip" -d "$WORK"
export GOPATH="$WORK/gopath" GOCACHE="$WORK/gocache" GOTMPDIR="$WORK/gotmp"
export GOTOOLCHAIN=local GOTELEMETRY=off GOMAXPROCS=2 GOMEMLIMIT=256MiB
mkdir -p "$GOTMPDIR"
echo "Building server AND client with Go $GO_RELEASE (limited to two build jobs)..."
(
  cd "$WORK/dnstt-$DNSTT_RELEASE"
  "$WORK/go/bin/go" build -mod=readonly -p 2 -trimpath -o "$WORK/dnstt-server" ./dnstt-server
  "$WORK/go/bin/go" build -mod=readonly -p 2 -trimpath -o "$WORK/dnstt-client" ./dnstt-client
)
for file in "${FILES[@]}"; do
  if [ -e "$file" ]; then
    mkdir -p "$WORK/snapshot$(dirname "$file")"
    cp -a "$file" "$WORK/snapshot$file"
  fi
done
if systemctl is-active --quiet dnstt-server; then DNS_ACTIVE=yes; fi
if systemctl is-enabled --quiet dnstt-server; then DNS_ENABLED=yes; fi
if systemctl is-active --quiet ragnar-iptables; then LEGACY_ACTIVE=yes; fi
if systemctl is-enabled --quiet ragnar-iptables; then LEGACY_ENABLED=yes; fi
CHANGED=yes
systemctl stop dnstt-server 2>/dev/null || true
systemctl disable --now ragnar-iptables 2>/dev/null || true
while iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null; do
  iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
  REMOVED=$((REMOVED+1))
done
# Edit only exact old Ragnar rules in the persisted NAT ruleset, not other firewall entries.
python3 -B - "$BASE" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from ragnar_dns import strip_legacy_rules, atomic
path = Path('/etc/iptables/rules.v4')
if path.exists():
    atomic(path, strip_legacy_rules(path.read_text()).encode(), path.stat().st_mode & 0o777)
PY
rm -f /etc/systemd/system/ragnar-iptables.service
install -d -m 700 /etc/dnstt
install -m 755 "$WORK/dnstt-server" /usr/local/bin/dnstt-server
install -m 755 "$WORK/dnstt-client" /usr/local/bin/dnstt-client
install -m 755 "$BASE/ragnar_dns.py" /usr/local/bin/ragnar-dns
systemctl daemon-reload
if command -v ufw >/dev/null 2>&1; then
  ufw allow 53/udp || echo "WARNING: open UDP 53 manually in the VPS firewall."
fi
/usr/local/bin/ragnar-dns setup
SUCCESS=yes
echo "Fresh DNS tunnel setup completed. LOCAL authenticated DNS-to-SSH test passed."
echo "Now add the printed A/NS records, allow UDP 53 in your provider firewall, then run:"
echo "  ragnar-dns diagnose"
echo "PUBLIC reachability is not confirmed until that end-to-end resolver test passes."
