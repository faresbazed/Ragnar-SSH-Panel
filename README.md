# Ragnar SSH Panel

SSH tunnel management panel for Linux VPS (Debian 11/12, Ubuntu 20.04–24.04).

## Features
- **SSH over WebSocket — port 80** (payload/proxy support)
- **SSH over TLS — port 443** (stunnel + Let's Encrypt, SNI)
- **badvpn-udpgw — port 7300** (UDP through SSH via tun2socks)
- **dnstt — DNS tunnel on port 53** (slowdns)

## Install (run as root)
```bash
bash <(curl -Ls https://raw.githubusercontent.com/faresbazed/Ragnar-SSH-Panel/main/install.sh)
