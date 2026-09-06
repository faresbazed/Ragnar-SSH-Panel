#!/usr/bin/env python3
# Ragnar SSH Panel - WebSocket SSH proxy (port 80, payload support)
#
# Improvements over original:
#   - Bounded header read (prevents memory-exhaustion DoS)
#   - Optional WebSocket 101 handshake reply for standards-compliant clients
#   - Explicit args passing (no fragile global)
#   - Lightweight error logging to stderr for debugging
#   - Graceful double-close handling
import asyncio
import argparse
import sys
import logging

BUF = 64 * 1024
MAX_HEADER = 8 * 1024          # refuse headers bigger than 8 KiB
WS_HANDSHAKE = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

log = logging.getLogger("wsproxy")


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )


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


async def handle(c_r, c_w, ssh_host: str, ssh_port: int, do_handshake: bool):
    """Handle one client connection: read HTTP payload, bridge to SSH."""
    peer = c_w.get_extra_info("peername")
    try:
        # Read the HTTP header block (the "payload") up to the blank line.
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = await c_r.read(1024)
            if not chunk:
                c_w.close()
                return
            header += chunk
            if len(header) > MAX_HEADER:
                log.warning("header too large from %s, dropping", peer)
                c_w.close()
                return

        # Optionally send a WebSocket upgrade response so standards-compliant
        # WS clients (not just HTTP Injector) can proceed.
        if do_handshake:
            c_w.write(WS_HANDSHAKE)
            await c_w.drain()

        s_r, s_w = await asyncio.open_connection(ssh_host, ssh_port)
    except (ConnectionRefusedError, OSError) as exc:
        log.warning("cannot reach SSH %s:%s -> %s", ssh_host, ssh_port, exc)
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

    # Bridge both directions concurrently.
    await asyncio.gather(
        relay(c_r, s_w, tag="c->s"),
        relay(s_r, c_w, tag="s->c"),
        return_exceptions=True,
    )


async def main(args):
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, args.ssh_host, args.ssh_port, args.handshake),
        args.bind,
        args.listen,
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.warning("wsproxy listening on %s -> SSH %s:%s", addrs, args.ssh_host, args.ssh_port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="WebSocket-to-SSH proxy")
    ap.add_argument("-p", "--listen", type=int, default=80, help="listen port (default 80)")
    ap.add_argument("-s", "--ssh-port", type=int, default=22, help="SSH port (default 22)")
    ap.add_argument("--ssh-host", default="127.0.0.1", help="SSH host (default 127.0.0.1)")
    ap.add_argument("--bind", default="0.0.0.0", help="bind address (default 0.0.0.0)")
    ap.add_argument("--handshake", action="store_true", help="send WS 101 upgrade reply")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = ap.parse_args()
    _setup_logging(args.verbose)
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        pass
