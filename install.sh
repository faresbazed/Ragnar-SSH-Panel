#!/bin/bash
# ==========================================================
#   RAGNAR SSH PANEL - Installer
#   SSH-WS :80 (wsproxy) | SSH-TLS :443 (stunnel+SNI)
#   badvpn-udpgw :7300 | dnstt :53 | SSH :22
#   Tested: Debian 11/12, Ubuntu 20.04-24.04
#
#   Improvements over original:
#   - read -r (no backslash mangling on domain/email)
#   - Input validation for domain & email
#   - Safe sed delimiter for domain substitution (| not affected by domain chars)
#   - iptables rules persisted via netfilter-persistent
#   - exec menu -> exec /usr/local/bin/menu (PATH-hash safe)
#   - A&&B||C anti-pattern fixed with proper if blocks
#   - Cleanup of /tmp build dirs on failure
#   - Better certbot port-80 conflict handling
# ==========================================================
set -euo pipefail
C_RED='\033[0;31m'; C_GRN='\033[0;32m'; C_YLW='\033[0;33m'; C_CYN='\033[0;36m'; C_NC='\033[0m'
ok()  { echo -e "${C_GRN}[ OK ]${C_NC} $1"; }
info(){ echo -e "${C_CYN}[ .. ]${C_NC} $1"; }
warn(){ echo -e "${C_YLW}[ !! ]${C_NC} $1"; }
die() { echo -e "${C_RED}[FAIL]${C_NC} $1"; exit 1; }

LOGFILE="/tmp/ragnar-install.log"
trap 'rm -rf /tmp/badvpn /tmp/dnstt /tmp/dnstt.zip /tmp/ragnar.zip 2>/dev/null' EXIT

[ "$(id -u)" -ne 0 ] && die "Run as root (sudo -i)."
# The base installer would put SSH back on ports 80/443 and collide with Xray.
[ ! -e /etc/ragnar/xray/state.json ] || die "Xray is already configured. Do not rerun the base installer; update the panel files without resetting services."
export DEBIAN_FRONTEND=noninteractive

# shellcheck source=/dev/null
. /etc/os-release
case "$ID" in debian|ubuntu) : ;; *) die "Unsupported OS: $ID" ;; esac
info "Detected: $PRETTY_NAME"

info "Installing packages (may take a few minutes)..."
apt-get update -y >> "$LOGFILE" 2>&1

# Core packages (no conflict risk)
apt-get install -y curl wget git unzip python3 stunnel4 certbot ufw >> "$LOGFILE" 2>&1 \
  || die "apt install failed - see $LOGFILE"

# iptables-persistent / netfilter-persistent conflict with ufw on Ubuntu 24.04+.
# Install them separately; if they conflict, we persist iptables via a systemd
# unit instead (see PERSIST_IPTABLES below).
PERSIST_IPTABLES="no"
if apt-get install -y iptables-persistent >> "$LOGFILE" 2>&1; then
  PERSIST_IPTABLES="yes"
else
  warn "iptables-persistent unavailable (ufw conflict on Noble) - using systemd unit for rule persistence"
fi
ok "Packages installed"

# ---------- badvpn-udpgw (fixed build) ----------
if ! command -v badvpn-udpgw >/dev/null 2>&1; then
  info "Fetching prebuilt badvpn-udpgw..."
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64)  PB_URL="https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64" ;;
    aarch64) PB_URL="https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgwarm" ;;
    *) PB_URL="" ;;
  esac
  if [ -n "$PB_URL" ]; then
    wget -qO /usr/local/bin/badvpn-udpgw "$PB_URL" 2>/dev/null || rm -f /usr/local/bin/badvpn-udpgw
  fi
  if [ -s /usr/local/bin/badvpn-udpgw ] && [ "$(head -c2 /usr/local/bin/badvpn-udpgw)" = "ELF" ]; then
    chmod +x /usr/local/bin/badvpn-udpgw
    ok "badvpn-udpgw prebuilt installed"
  else
    rm -f /usr/local/bin/badvpn-udpgw
    info "Prebuilt unavailable, building from source (~2 min)..."
    apt-get install -y build-essential cmake >> "$LOGFILE" 2>&1
    rm -rf /tmp/badvpn
    git clone --depth 1 https://github.com/ambrop72/badvpn.git /tmp/badvpn >> "$LOGFILE" 2>&1 \
      || die "badvpn git clone failed"
    mkdir -p /tmp/badvpn/build
    # Use a subshell so a cd failure doesn't affect the rest of the script
    if ! ( cd /tmp/badvpn/build && \
           cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >> "$LOGFILE" 2>&1 && \
           make -j"$(nproc)" >> "$LOGFILE" 2>&1 ); then
      die "badvpn build failed - see $LOGFILE"
    fi
    BIN=$(find /tmp/badvpn/build -name badvpn-udpgw -type f | head -n1)
    [ -n "$BIN" ] || die "badvpn binary not found after build"
    install -m 755 "$BIN" /usr/local/bin/badvpn-udpgw
    ok "badvpn-udpgw built from source"
  fi
fi

# ---------- clone panel ----------
info "Installing panel to /opt/ragnar ..."
rm -rf /opt/ragnar
if git clone --depth 1 https://github.com/faresbazed/Ragnar-SSH-Panel.git /opt/ragnar >> "$LOGFILE" 2>&1; then
  : # clone ok
elif wget -qO /tmp/ragnar.zip https://github.com/faresbazed/Ragnar-SSH-Panel/archive/refs/heads/main.zip \
     && unzip -qo /tmp/ragnar.zip -d /opt && mv /opt/Ragnar-SSH-Panel-main /opt/ragnar; then
  : # zip fallback ok
else
  die "Could not download panel"
fi
install -m 755 /opt/ragnar/wsproxy.py /usr/local/bin/wsproxy.py
install -m 755 /opt/ragnar/menu /usr/local/bin/menu     # <-- "menu" command
install -m 755 /opt/ragnar/menu /usr/local/bin/ragnar   # <-- "ragnar" command
ok "Panel installed (commands: menu / ragnar)"

# ---------- input ----------
read -r -p "Your domain for TLS/SNI (e.g. vpn.example.com): " DOMAIN
[ -n "$DOMAIN" ] || die "Domain required."
# Basic domain validation
if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
  die "Invalid domain format: $DOMAIN"
fi
read -r -p "Email for Let's Encrypt: " EMAIL
[ -n "$EMAIL" ] || die "Email required."
if ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
  die "Invalid email format: $EMAIL"
fi

# ---------- SSL cert (standalone - port 80 must be free) ----------
info "Issuing Let's Encrypt cert for $DOMAIN ..."
# Stop anything that might hold port 80
systemctl stop wsproxy 2>/dev/null || true
systemctl stop stunnel4 2>/dev/null || true
if certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" >> "$LOGFILE" 2>&1; then
  ok "Certificate issued"
else
  warn "Certbot standalone failed - check that port 80 is free and DNS points to this server"
  die "Certbot failed - see $LOGFILE"
fi

# ---------- Auto-renewal hook ----------
# certbot.timer runs twice daily and renews certs 30 days before expiry,
# but it does NOT restart stunnel4 by default. We install a deploy hook
# so stunnel4 picks up the new cert automatically after each renewal.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/ragnar-restart.sh <<'HOOKEOF'
#!/bin/bash
# Ragnar SSH Panel - auto-restart services after cert renewal
logger -t ragnar "Cert renewed by certbot, restarting stunnel4 + wsproxy"
systemctl restart stunnel4 2>/dev/null || true
systemctl restart wsproxy 2>/dev/null || true
HOOKEOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/ragnar-restart.sh
# Make sure the certbot systemd timer is enabled
systemctl enable certbot.timer >/dev/null 2>&1 || true
systemctl start certbot.timer >/dev/null 2>&1 || true
ok "Auto-renewal enabled (certbot.timer + deploy hook restarts stunnel4)"

# ---------- stunnel 443 SNI ----------
# On Ubuntu 24.04 the default /etc/stunnel/stunnel.conf ships broken and
# crashes the service. The init.d script loads ssh-tls.conf (not stunnel.conf),
# so we must write the FULL config (with pid=) to BOTH files.
# Without pid= the init.d script fails with "check that you have specified the pid=".

STUNNEL_CONF="
; Ragnar SSH Panel - SSH over TLS on 443 (SNI: $DOMAIN)

; --- global options ---
cert     = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
key      = /etc/letsencrypt/live/$DOMAIN/privkey.pem
pid      = /var/run/stunnel4/stunnel4.pid
output   = /var/log/stunnel4/stunnel.log

; --- SSH over TLS ---
[ssh-tls]
accept  = 443
connect = 127.0.0.1:22
"

# Write the full config to BOTH files - init.d reads ssh-tls.conf on Ubuntu 24.04
echo "$STUNNEL_CONF" > /etc/stunnel/stunnel.conf
echo "$STUNNEL_CONF" > /etc/stunnel/ssh-tls.conf

# Ensure ENABLED=1 in the default config
sed -i 's/^ENABLED=.*/ENABLED=1/' /etc/default/stunnel4 2>/dev/null || true
# Ensure the log + pid directories exist (missing on some installs)
mkdir -p /var/log/stunnel4 /var/run/stunnel4
chown -R stunnel4:stunnel4 /var/log/stunnel4 /var/run/stunnel4 2>/dev/null || true

systemctl enable stunnel4 >/dev/null 2>&1
if systemctl restart stunnel4 2>/dev/null; then
  ok "stunnel4 on 443"
else
  # Retry after a short delay (sometimes the port isn't released yet)
  sleep 2
  if systemctl restart stunnel4 2>/dev/null; then
    ok "stunnel4 on 443 (started on retry)"
  else
    warn "stunnel4 failed to start - check: journalctl -xeu stunnel4"
    warn "  common fixes: ensure port 443 is free, certs exist at /etc/letsencrypt/live/$DOMAIN/"
  fi
fi

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

# ---------- dnstt (optional - DNS tunnel) ----------
DNSTT_OK="no"
info "Setting up dnstt (DNS tunnel)..."
if ! command -v dnstt-server >/dev/null 2>&1; then
  apt-get install -y golang-go >> "$LOGFILE" 2>&1 || warn "golang-go install failed"
  rm -rf /tmp/dnstt /tmp/dnstt.zip
  # 1) try maintained GitHub mirror, 2) fall back to author's tarball (no git auth)
  if git clone --depth 1 https://github.com/Mygod/dnstt.git /tmp/dnstt >> "$LOGFILE" 2>&1; then
    :
  elif wget -qO /tmp/dnstt.zip https://www.bamsoftware.com/software/dnstt/dnstt-20260501.zip; then
    ( cd /tmp && unzip -qo dnstt.zip && mv /tmp/dnstt-* /tmp/dnstt ) >> "$LOGFILE" 2>&1 || true
  else
    warn "dnstt download failed"
  fi
  if [ -d /tmp/dnstt ]; then
    if ( cd /tmp/dnstt && go build ./dnstt-server >> "$LOGFILE" 2>&1 ); then
      if [ -f /tmp/dnstt/dnstt-server ]; then
        install -m 755 /tmp/dnstt/dnstt-server /usr/local/bin/dnstt-server
        ok "dnstt-server built and installed"
        DNSTT_OK="yes"
      else
        warn "dnstt-server binary not found after build"
      fi
    else
      warn "dnstt build failed (DNS tunnel will be skipped - see $LOGFILE)"
    fi
  fi
else
  DNSTT_OK="yes"
fi

# Only configure dnstt service + keys if we actually have the binary
if [ "$DNSTT_OK" = "yes" ] && [ -x /usr/local/bin/dnstt-server ]; then
  mkdir -p /etc/dnstt
  if [ ! -f /etc/dnstt/server.key ]; then
    /usr/local/bin/dnstt-server -gen-key -privkey-file /etc/dnstt/server.key -pubkey-file /etc/dnstt/server.pub \
      || warn "dnstt key generation failed"
  fi

  cat > /etc/systemd/system/dnstt-server.service <<EOF
[Unit]
Description=dnstt DNS Tunnel (53/udp)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey-file /etc/dnstt/server.key t.$DOMAIN 127.0.0.1:22
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  # iptables redirect 53 -> 5300, then persist so it survives reboot
  iptables -t nat -C PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || \
    iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
  ok "dnstt configured (DNS tunnel on port 53)"

  # Persist iptables rules so they survive reboot
  if [ "$PERSIST_IPTABLES" = "yes" ] && command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  else
    # No iptables-persistent (ufw conflict on Noble) - systemd unit fallback
    cat > /etc/systemd/system/ragnar-iptables.service <<'EOF'
[Unit]
Description=Ragnar SSH Panel - iptables DNAT rule for dnstt (53->5300)
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
ExecStop=/sbin/iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ragnar-iptables >/dev/null 2>&1 || true
  fi
else
  warn "dnstt skipped - DNS tunnel unavailable (other features still work)"
  warn "  You can install it later manually: see https://www.bamsoftware.com/software/dnstt/"
fi


# ---------- firewall ----------
ufw allow 22/tcp >/dev/null 2>&1 || true
ufw allow 80/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 7300/tcp >/dev/null 2>&1 || true
ufw allow 53/udp >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true
ok "Firewall configured"

systemctl daemon-reload
systemctl enable wsproxy badvpn-udpgw >/dev/null 2>&1
systemctl restart wsproxy badvpn-udpgw 2>/dev/null || warn "some services failed to start (check: menu -> 5)"

# Only enable/start dnstt if it was actually installed
if [ "$DNSTT_OK" = "yes" ]; then
  systemctl enable dnstt-server >/dev/null 2>&1 || true
  systemctl restart dnstt-server 2>/dev/null || warn "dnstt-server failed to start"
fi

echo ""
echo "=========================================================="
echo "  RAGNAR SSH PANEL installed"
echo "   SSH-WS  : 80      DNS-TUN : 53/udp $( [ "$DNSTT_OK" = "yes" ] && echo '(dnstt)' || echo '(skipped)')"
echo "   SSH-TLS : 443     UDP-GW  : 7300 (badvpn)"
echo "   SSH     : 22      Panel   : menu (or ragnar)"
if [ "$DNSTT_OK" = "yes" ]; then
  echo "  Create DNS records for dnstt:"
  echo "   A   ns.$DOMAIN     -> <VPS IP>"
  echo "   NS  t.$DOMAIN      -> ns.$DOMAIN"
fi
echo "=========================================================="
echo "  Optional VLESS / VMess / Trojan: menu -> 11 -> Install Xray"
echo "  Xray setup asks before moving SSH-WS to 8080 and SSH-TLS to 444."
exec /usr/local/bin/menu
