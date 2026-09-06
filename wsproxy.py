#!/usr/bin/env python3
"""
Ragnar SSH Panel - Universal WebSocket SSH Proxy

Supports ALL payload types used by SSH tunneling clients:
  - Simple GET / HTTP/1.1 (standard WS)
  - POST / HTTP/1.1 (HTTP Injector / NapsternetV)
  - CONNECT host:port (HTTP CONNECT proxy mode)
  - CF-RAY / fronting payloads (Cloudflare bypass)
  - Multi-line payloads with multiple Host: headers
  - Custom User-Agent, X-Forwarded-Host, CF-CONNECTING-IP, etc.
  - Any arbitrary HTTP method (GET/POST/PUT/DELETE/OPTIONS/etc.)

How it works:
  1. Read the full HTTP header block (up to MAX_HEADER bytes)
  2. Parse the first request line to detect method + any CONNECT target
  3. If CONNECT: open connection to the CONNECT target, not SSH
  4. Otherwise: connect to SSH (or --ssh-host:--ssh-port)
  5. Send a 101 Switching Protocols reply (for WS clients) OR a
     200 OK reply (for HTTP CONNECT / fronting clients)
  6. Bidirectionally bridge client <-> target (raw TCP relay)
"""

import asyncio
import argparse
import sys
import logging

BUF = 64 * 1024
MAX_HEADER = 16 * 1024  # allow larger headers for complex payloads

log = logging.getLogger("wsproxy")


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )


# --- Reply templates ---------------------------------------------------------

# Standard WebSocket upgrade reply
WS_101 = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"\r\n"
)

# HTTP CONNECT proxy success reply
CONNECT_200 = b"HTTP/1.1 200 Connection established\r\n\r\n"

# Generic 200 OK (for fronting / CF-RAY payloads)
OK_200 = b"HTTP/1.1 200 OK\r\n\r\n"


def _choose_reply(method: bytes) -> bytes:
    """Pick the right reply based on the HTTP method."""
    if method == b"CONNECT":
        return CONNECT_200
    return WS_101


def _parse_connect_target(first_line: bytes) -> tuple:
    """
    Parse the first HTTP request line.
    Returns (method, host, port) or (method, None, None).

    Examples:
      b'GET / HTTP/1.1'                    -> (b'GET', None, None)
      b'POST / HTTP/1.1'                   -> (b'POST', None, None)
      b'CONNECT example.com:443 HTTP/1.1'  -> (b'CONNECT', b'example.com', 443)
      b'CONNECT 1.2.3.4:22 HTTP/1.1'        -> (b'CONNECT', b'1.2.3.4', 22)
    """
    parts = first_line.split(b" ")
    if len(parts) < 2:
        return (b"UNKNOWN", None, None)

    method = parts[0].upper()

    # CONNECT method: CONNECT host:port HTTP/1.1
    if method == b"CONNECT" and len(parts) >= 2:
        target = parts[1]
        # strip any protocol prefix
        if target.startswith(b"http://"):
            target = target[7:]
        elif target.startswith(b"https://"):
            target = target[8:]
        # split host:port
        if b":" in target:
            host_b, port_b = target.rsplit(b":", 1)
            try:
                port = int(port_b)
            except ValueError:
                port = 443
            return (method, host_b, port)
        return (method, target, 443)

    # Any other method (GET, POST, PUT, DELETE, etc.)
    return (method, None, None)


async def relay(reader, writer, tag: str = ""):
    """Pump data from *reader* to *writer* until EOF or error."""
    try:
        while True:
            data = await reader.read(BUF)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as exc:
        log.debug("relay %s error: %s", tag, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle(c_r, c_w, ssh_host: str, ssh_port: int):
    """
    Handle one client connection.

    Reads the HTTP payload header, determines the target (SSH or CONNECT
    target), sends the appropriate reply, then bridges bidirectionally.
    """
    peer = c_w.get_extra_info("peername")
    try:
        # --- Read the full HTTP header block ---
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = await c_r.read(4096)
            if not chunk:
                c_w.close()
                return
            header += chunk
            if len(header) > MAX_HEADER:
                log.warning("header too large from %s, dropping", peer)
                c_w.close()
                return

        # --- Parse the first request line ---
        first_line = header.split(b"\r\n", 1)[0]
        method, conn_host, conn_port = _parse_connect_target(first_line)
        log.debug("%s: method=%s target=%s:%s", peer, method, conn_host, conn_port)

        # --- Determine the target ---
        if method == b"CONNECT" and conn_host is not None:
            # HTTP CONNECT proxy mode -> connect to the CONNECT target
            target_host = conn_host.decode("ascii", errors="replace")
            target_port = conn_port
            reply = CONNECT_200
        else:
            # Standard WS/HTTP payload -> connect to SSH
            target_host = ssh_host
            target_port = ssh_port
            reply = _choose_reply(method)

        # --- Send the reply to the client ---
        c_w.write(reply)
        await c_w.drain()

        # --- Connect to the target ---
        s_r, s_w = await asyncio.open_connection(target_host, target_port)
        log.debug("%s: connected to %s:%s", peer, target_host, target_port)

    except (ConnectionRefusedError, OSError) as exc:
        log.warning("cannot reach %s:%s -> %s", target_host, target_port, exc)
        # Send an error reply so the client knows what happened
        try:
            if method == b"CONNECT":
                c_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            else:
                c_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await c_w.drain()
        except Exception:
            pass
        try:
            c_w.close()
        except Exception:
            pass
        return
    except Exception as exc:
        log.debug("handle error from %s: %s", peer, exc)
        try:
            c_w.close()
        except Exception:
            pass
        return

    # --- Bridge both directions concurrently ---
    await asyncio.gather(
        relay(c_r, s_w, tag="c->s"),
        relay(s_r, c_w, tag="s->c"),
        return_exceptions=True,
    )


async def main(args):
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, args.ssh_host, args.ssh_port),
        args.bind,
        args.listen,
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.warning(
        "wsproxy listening on %s -> SSH %s:%s (supports GET/POST/CONNECT/CF-RAY)",
        addrs, args.ssh_host, args.ssh_port,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Universal WebSocket-to-SSH proxy")
    ap.add_argument("-p", "--listen", type=int, default=80, help="listen port (default 80)")
    ap.add_argument("-s", "--ssh-port", type=int, default=22, help="SSH port (default 22)")
    ap.add_argument("--ssh-host", default="127.0.0.1", help="SSH host (default 127.0.0.1)")
    ap.add_argument("--bind", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = ap.parse_args()
    _setup_logging(args.verbose)
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        pass
