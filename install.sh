#!/bin/bash
# ==========================================================
#   RAGNAR SSH PANEL - Installer
#   SSH-WS :80 (wsproxy) | SSH-TLS :443 (stunnel+SNI)
#   badvpn-udpgw :7300 | dnstt :53 | SSH :22
#   Tested: Debian 11/12, Ubuntu 20.04-24.04
# ==========================================================
set -e
C_RED='\033[0;31m'; C_GRN='\033[0;32m'; C_YLW='\033[0;33m'; C_CYN='\033[0;36m'; C_NC='\033[0m'
ok()  { echo -e "${C_GRN}[ OK ]${C_NC} $1"; }
info(){ echo -e "${C_CYN}[ .. ]${C_NC} $1"; }
warn(){ echo -e "${C_YLW}[ !! ]${C_NC} $1"; }
die() { echo -e "${C_RED}[FAIL]${C_NC} $1"; exit 1; }

[ "$(id -u)" -ne 0 ] && die "Run as root (sudo -i)."
export DEBIAN_FRONTEND=noninteractive

. /etc/os-release
case "$ID" in debian|ubuntu) : ;; *) die "Unsupported OS: $ID" ;; esac
info "Detected: $PRETTY_NAME"

info "Installing packages (may take a few minutes)..."
apt-get update -y
apt-get install -y curl wget git unzip python3 stunnel4 certbot ufw >> /tmp/ragnar-install.log 2>&1 || die "apt install failed - see /tmp/ragnar-install.log"
ok "Packages installed"

# ---------- badvpn-udpgw ----------
if ! command -v badvpn-udpgw >/dev/null 2>&1; then
  info "Fetching badvpn-udpgw..."
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  URL="https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64" ;;
    aarch64) URL="https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgwarm" ;;
    *) die "No prebuilt badvpn for $ARCH" ;;
  esac
  wget -qO /usr/local/bin/badvpn-udpgw "$URL" || true
  if [ -s /usr/local/bin/badvpn-udpgw ] && head -c2 /usr/local/bin/badvpn-udpgw | grep -q ELF; then
    chmod +x /usr/local/bin/badvpn-udpgw && ok "badvpn-udpgw binary installed"
  else
    rm -f /usr/local/bin/badvpn-udpgw
    info "Building badvpn-udpgw from source..."
    apt-get install -y cmake g++ make >> /tmp/ragnar-install.log 2>&1
    cd /tmp && rm -rf badvpn && git clone --depth 1 https://github.com/ambrop72/badvpn.git >> /tmp/ragnar-install.log 2>&1
    cd badvpn && cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 . >> /tmp/ragnar-install.log 2>&1
    make -j"$(nproc)" udpgw >> /tmp/ragnar-install.log 2>&1
    install -m 755 udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw
    ok "badvpn-udpgw built from source"
  fi
fi

# ---------- clone panel ----------
info "Installing panel to /opt/ragnar ..."
rm -rf /opt/ragnar
git clone --depth 1 https://github.com/faresbazed/Ragnar-SSH-Panel.git /opt/ragnar >> /tmp/ragnar-install.log 2>&1 \
  || { wget -qO /tmp/ragnar.zip https://github.com/faresbazed/Ragnar-SSH-Panel/archive/refs/heads/main.zip \
       && unzip -qo /tmp/ragnar.zip -d /opt && mv /opt/Ragnar-SSH-Panel-main /opt/ragnar; }
install -m 755 /opt/ragnar/wsproxy.py /usr/local/bin/wsproxy.py
install -m 755 /opt/ragnar/menu /usr/local/bin/ragnar
ok "Panel installed"

# ---------- input ----------
read -p "Your domain for TLS/SNI (e.g. vpn.example.com): " DOMAIN
[ -z "$DOMAIN" ] && die "Domain required."
read -p "Email for Let's Encrypt: " EMAIL

# ---------- SSL cert (standalone - port 80 must be free) ----------
info "Issuing Let's Encrypt cert for $DOMAIN ..."
certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" >> /tmp/ragnar-install.log 2>&1 \
  || { systemctl stop wsproxy 2>/dev/null; certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" || die "Certbot failed"; }
ok "Certificate issued"

# ---------- stunnel 443 SNI ----------
cat > /etc/stunnel/ssh-tls.conf <<EOF
; Ragnar SSH Panel - SSH over TLS on 443 (SNI: $DOMAIN)
[ssh-tls]
accept  = 443
connect = 127.0.0.1:22
cert    = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
key     = /etc/letsencrypt/live/$DOMAIN/privkey.pem
EOF
sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 2>/dev/null || true
systemctl enable stunnel4 >/dev/null 2>&1
systemctl restart stunnel4
ok "stunnel4 on 443"

# ---------- wsproxy.service (port 80) ----------
cat > /etc/systemd/system/wsproxy.service <<'EOF'
[Unit]
Description=SSH WebSocket Proxy (port 80)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wsproxy.py -p 80 -s 22
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ---------- badvpn.service ----------
cat > /etc/systemd/system/badvpn-udpgw.service <<'EOF'
[Unit]
Description=badvpn UDP Gateway (7300)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 100
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# ---------- dnstt ----------
info "Setting up dnstt (DNS tunnel)..."
if ! command -v dnstt-server >/dev/null 2>&1; then
  apt-get install -y golang-go >> /tmp/ragnar-install.log 2>&1 || true
  cd /tmp && rm -rf dnstt && git clone --depth 1 https://github.com/bamsoftware/dnstt.git >> /tmp/ragnar-install.log 2>&1 || warn "dnstt clone failed"
  cd dnstt && go build ./dnstt-server >> /tmp/ragnar-install.log 2>&1 || warn "dnstt build failed"
  [ -f /tmp/dnstt/dnstt-server ] && install -m 755 /tmp/dnstt/dnstt-server /usr/local/bin/dnstt-server
fi
mkdir -p /etc/dnstt
[ -f /etc/dnstt/server.key ] || /usr/local/bin/dnstt-server -gen-key -privkey-file /etc/dnstt/server.key -pubkey-file /etc/dnstt/server.pub

cat > /etc/systemd/system/dnstt-server.service <<'EOF'
[Unit]
Description=dnstt DNS Tunnel (53/udp)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey-file /etc/dnstt/server.key NS_ZONE 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF
sed -i "s/NS_ZONE/t.$DOMAIN/" /etc/systemd/system/dnstt-server.service
iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || \
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

# ---------- firewall ----------
ufw allow 22/tcp,80/tcp,443/tcp,7300/tcp >/dev/null 2>&1
ufw allow 53/udp >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1
ok "Firewall configured"

systemctl daemon-reload
systemctl enable wsproxy badvpn-udpgw dnstt-server >/dev/null 2>&1
systemctl restart wsproxy badvpn-udpgw dnstt-server 2>/dev/null || true

echo ""
echo "=========================================================="
echo "  RAGNAR SSH PANEL installed"
echo "   SSH-WS  : 80      DNS-TUN : 53/udp (dnstt)"
echo "   SSH-TLS : 443     UDP-GW  : 7300 (badvpn)"
echo "   SSH     : 22      Panel   : ragnar"
echo "  Create DNS records for dnstt:"
echo "   A   ns.$DOMAIN     -> <VPS IP>"
echo "   NS  t.$DOMAIN      -> ns.$DOMAIN"
echo "=========================================================="
exec ragnar
