# Ragnar SSH Panel

Terminal-based SSH tunnel management panel for Linux VPS (Debian 11/12, Ubuntu 20.04–24.04).

## Features
- SSH over WebSocket — port 80 before enabling Xray
- SSH over TLS — port 443 before enabling Xray (stunnel + Let's Encrypt, SNI)
- badvpn-udpgw — port 7300 (UDP through SSH via tun2socks)
- dnstt — DNS tunnel on port 53 (slowdns)
- Optional Xray-core: VLESS / VMess / Trojan, WebSocket and TCP listeners
- Separate Xray accounts with expiration dates, disable/enable, renewal and deletion
- Copyable `vless://`, `vmess://`, and `trojan://` URIs; no subscription server or QR codes

## Install (run as root)
```bash
bash <(curl -Ls https://raw.githubusercontent.com/faresbazed/Ragnar-SSH-Panel/main/install.sh)
```

## Enable Xray on an existing panel

Once the Xray changes are merged into `main`, update a Git-based installation **without rerunning the base installer**:

```bash
cd /opt/ragnar
git pull --ff-only
install -m 755 menu /usr/local/bin/menu
install -m 755 menu /usr/local/bin/ragnar
menu
```

For an archive-based installation, obtain a complete updated checkout first; the menu and `install-xray.sh` need to come from the same version. Back up local modifications before updating.

Choose **11) Xray -> 1) Install Xray**. Alternatively, run `bash /opt/ragnar/install-xray.sh` as root. The extension requires a working Ragnar SSH setup, systemd, an x86_64/arm64 VPS, an IPv4 DNS A record pointing to that VPS, and an existing valid Let's Encrypt certificate for the selected domain. Do not publish an AAAA record unless you separately configure IPv6 listeners; generated listeners currently bind IPv4.

### Important SSH port change

**Xray cannot bind ports already occupied by SSH services.** Setup shows the complete port plan and requires typing `MOVE SSH` before migrating:

| Existing service | Before Xray | After Xray |
| --- | --- | --- |
| SSH WebSocket | 80 | 8080 |
| SSH TLS | 443 | 444 |
| Plain SSH | 22 | 22 (unchanged) |

Update existing SSH clients accordingly. Keep a plain SSH session open during setup and allow the replacement SSH ports in the hosting provider firewall beforehand. The installer backs up SSH settings and renewal hooks under `/etc/ragnar/xray/ssh-backup` and attempts to restore them if migration fails. It never intentionally replaces existing Xray account state or an unrelated 3x-ui installation.

### Default Xray listeners

| Protocol | Transport | Non-TLS port | TLS port | WS path |
| --- | --- | --- | --- | --- |
| VLESS | WebSocket | **80** | **443** | `/vless` |
| VMess | WebSocket | 8081 | 8443 | `/vmess` |
| Trojan | WebSocket | Not supported | 2053 | `/trojan` |
| VLESS | TCP | 2082 | 2443 | — |
| VMess | TCP | 2086 | 2444 | — |
| Trojan | TCP | Not supported | 2445 | — |

**VLESS + TLS + WebSocket on 443 is the primary profile.** All TLS profiles use the selected domain's certificate and SNI. TLS verification is not disabled in exported URIs. Non-TLS VLESS does not encrypt traffic; use it only when that is intentional. VMess uses AEAD (`alterId=0`). Trojan is TLS-only.

Each listener has its own port. The Xray menu can add/delete listeners to change the port allocation or switch a port between WS and TCP; it does not multiplex several independent listeners on the same port. Port 80 is enforced as non-TLS; 443, 8443 and 2053 are enforced as TLS. SSH/DNS/gateway ports and occupied ports are rejected. Other free ports can use TLS or non-TLS, except Trojan always requires TLS.

The installer adds UFW rules for the defaults, but you must also allow them in the provider firewall. Newly added listeners print a firewall reminder; they do not silently modify firewall rules. Remove obsolete firewall rules yourself after deleting a listener.

### Cloudflare and DNS

For the simplest setup, use **DNS-only (direct)** access. Cloudflare's standard proxy can carry WebSocket traffic on supported HTTP(S) ports, but **not raw TCP**. For TLS WS through Cloudflare use Full (strict), enable WebSockets, and bypass caching/challenges on the WS paths. Port 8081 is not a standard Cloudflare-proxied port. All exported URIs currently use the configured hostname, so a proxied hostname is not suitable for the TCP profiles. HTTP-to-HTTPS redirects must not redirect non-TLS WS requests on port 80.

## Xray user management

Use **menu -> 11** to create, list, renew, disable, enable or delete users, and display their URIs. These are Xray accounts, not Linux SSH accounts. Each user belongs to one protocol and receives URIs for every configured listener of that protocol. Account credentials are generated securely; credentials are not printed by the user-list action. Treat exported URIs as passwords.

CLI examples (run as root; choose a future date):

```bash
ragnar-xray add-user alice vless --expires 2027-12-31
ragnar-xray uri alice
ragnar-xray renew-user alice --expires 2028-01-31
ragnar-xray disable-user alice
ragnar-xray enable-user alice
ragnar-xray delete-user alice
ragnar-xray listeners
ragnar-xray add-listener vmess tcp 30443 --tls
ragnar-xray delete-listener vmess-tcp-30443
```

Expiration means **valid through the selected date in UTC**, ending at 00:00 UTC the following day. The timer checks every 30 seconds (plus systemd scheduling/startup delay). Expired/disabled accounts are removed from the running Xray configuration. A boot-time check also removes expired users before Xray opens listeners. Renewing an expired account restores access; renewing a manually disabled account does not enable it.

**Applying account/listener changes or an expiry batch restarts Xray and disconnects all Xray sessions**, including still-valid users. Clients may reconnect afterward; expired credentials cannot. This deliberately simple implementation does not provide 3x-ui's live API updates, traffic quotas, subscription management or a web UI. SSH sessions are unaffected by Xray account changes.

State is kept in `/etc/ragnar/xray/state.json`, protected by a root-only directory, mode-0600 files, atomic replacements and an advisory management lock. Back up this file securely. `config.json` is generated: do not edit it directly. Normal failed updates attempt rollback; failed expiry reconciliation stops Xray rather than leaving expired credentials active. Fix the underlying error, then restart the service.

## Certificates and troubleshooting

Xray is pinned to **v26.3.27**, downloaded from the official XTLS release and checked against its published SHA256 digest. The panel uses its own `/usr/local/lib/ragnar-xray/xray` binary and `ragnar-xray.service`; it does not reuse or overwrite an existing `xray.service`.

Certbot pre/post hooks release port 80 and restore previously running services after standalone renewal, including failed certificate attempts. The deploy hook refreshes stunnel certificates. Hooks and account management share a lock so expiry cannot restart Xray during a challenge. Certificate renewal briefly interrupts tunnels. After installation, verify this on your VPS:

```bash
certbot renew --dry-run
systemctl status ragnar-xray ragnar-xray-expire.timer
journalctl -u ragnar-xray -u ragnar-xray-expire.service --since '1 hour ago'
ss -ltnp
ragnar-xray sync
```

If renewal is interrupted and leaves `/run/ragnar-cert-renew/services`, first make sure certbot has finished, fix any service/certificate errors, then run `bash /etc/letsencrypt/renewal-hooks/post/ragnar-xray.sh` to retry recovery. Do not remove the marker while a challenge is still running.

Common connection problems: closed provider firewall ports, wrong DNS, an unwanted AAAA record, Cloudflare proxy on a TCP profile, redirects/challenges on non-TLS WS paths, expired certificates, client clock skew (VMess), or a client using the wrong path/security/transport. Use `ragnar-xray uri NAME` rather than assembling a link manually.

## Tests

Tests use temporary directories inside the checkout and do not install VPS services:

```bash
python3 -B -m unittest -v test_xray
# Optional: use a verified local Xray binary for actual traffic tests.
XRAY_TEST_BINARY=/absolute/path/to/xray python3 -B -m unittest -v test_xray
bash -n install.sh install-xray.sh menu
```

The real-Xray tests validate production configurations, decode exported URIs into clients, pass authenticated traffic through all ten profiles with certificate verification enabled, reject incorrect credentials, and check connection revocation/renewal. Unit tests cover account lifecycle, UTC expiry boundaries, private storage, rollback, boot filtering, port conflicts, and renewal hooks using a local service stub. A real systemd installation, public DNS, provider firewall and Let's Encrypt renewal still need verification on the target VPS.
