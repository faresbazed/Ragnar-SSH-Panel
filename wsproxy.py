#!/usr/bin/env python3
"""
Ragnar SSH Panel - Universal WebSocket SSH Proxy (optimized for speed)

Supports ALL payload types used by SSH tunneling clients:
  - GET / POST / PUT / DELETE / any HTTP method
  - CONNECT host:port (HTTP CONNECT proxy mode)
  - CF-RAY / fronting payloads (multi-line)
  - Custom User-Agent, X-Forwarded-Host, etc.

Performance optimizations:
  - TCP_NODELAY on both sockets (disables Nagle's algorithm -> no 200ms delay)
  - SO_SNDBUF / SO_RCVBUF set to 256 KiB for high throughput
  - Larger read buffer (256 KiB) per iteration
  - Non-blocking drain: only await drain() when the write buffer is full,
    not on every single read (eliminates the per-chunk await overhead)
  - Connection to SSH opened in parallel with reply send
  - Zero-copy write semantics (no unnecessary copying)
"""

import asyncio
import argparse
import socket
import sys
import logging

BUF = 256 * 1024           # larger read buffer = fewer iterations
MAX_HEADER = 16 * 1024     # allow larger headers for complex payloads
SOCKET_BUF = 256 * 1024    # TCP send/recv buffer size

log = logging.getLogger("wsproxy")


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )


# --- Reply templates ---------------------------------------------------------

WS_101 = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"\r\n"
)
CONNECT_200 = b"HTTP/1.1 200 Connection established\r\n\r\n"
OK_200 = b"HTTP/1.1 200 OK\r\n\r\n"


def _choose_reply(method: bytes) -> bytes:
    if method == b"CONNECT":
        return CONNECT_200
    return WS_101


def _parse_connect_target(first_line: bytes) -> tuple:
    parts = first_line.split(b" ")
    if len(parts) < 2:
        return (b"UNKNOWN", None, None)
    method = parts[0].upper()
    if method == b"CONNECT" and len(parts) >= 2:
        target = parts[1]
        if target.startswith(b"http://"):
            target = target[7:]
        elif target.startswith(b"https://"):
            target = target[8:]
        if b":" in target:
            host_b, port_b = target.rsplit(b":", 1)
            try:
                port = int(port_b)
            except ValueError:
                port = 443
            return (method, host_b, port)
        return (method, target, 443)
    return (method, None, None)


def _optimize_socket(sock):
    """Apply TCP performance optimizations to a socket."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUF)
    except OSError:
        pass


async def relay(reader, writer, tag: str = ""):
    """
    High-performance bidirectional relay.

    Key optimization: instead of awaiting drain() after every read, we
    only yield to the event loop when the transport's write buffer is
    actually full. This eliminates the per-chunk await overhead that
    caused the slowdown after a few seconds of sustained transfer.
    """
    transport = writer.transport
    try:
        while True:
            data = await reader.read(BUF)
            if not data:
                break
            writer.write(data)
            # Only await drain() if the write buffer is getting large.
            # transport.is_writing() returns False when paused (buffer full).
            # Checking get_write_buffer_size() avoids unnecessary awaits.
            try:
                if transport.get_write_buffer_size() > SOCKET_BUF:
                    await writer.drain()
            except (AttributeError, OSError):
                # Fallback: just drain (older Python or transport doesn't support it)
                await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as exc:
        log.debug("relay %s error: %s", tag, exc)
    finally:
        try:
            # Final flush of any remaining buffered data
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle(c_r, c_w, ssh_host: str, ssh_port: int):
    peer = c_w.get_extra_info("peername")

    # Optimize the client socket immediately
    try:
        _optimize_socket(c_w.get_extra_info("socket"))
    except Exception:
        pass

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
            target_host = conn_host.decode("ascii", errors="replace")
            target_port = conn_port
            reply = CONNECT_200
        else:
            target_host = ssh_host
            target_port = ssh_port
            reply = _choose_reply(method)

        # --- Send reply + connect to target in parallel ---
        # Open the SSH/target connection while the reply is being sent.
        c_w.write(reply)
        connect_task = asyncio.ensure_future(
            asyncio.open_connection(target_host, target_port)
        )
        # Drain the reply while the connection opens
        await c_w.drain()
        s_r, s_w = await connect_task
        log.debug("%s: connected to %s:%s", peer, target_host, target_port)

        # Optimize the target socket
        try:
            _optimize_socket(s_w.get_extra_info("socket"))
        except Exception:
            pass

    except (ConnectionRefusedError, OSError) as exc:
        log.warning("cannot reach %s:%s -> %s", target_host, target_port, exc)
        try:
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
        # Start with a larger backlog for connection bursts
        backlog=128,
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.warning(
        "wsproxy listening on %s -> SSH %s:%s (GET/POST/CONNECT/CF-RAY, optimized)",
        addrs, args.ssh_host, args.ssh_port,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Universal WebSocket-to-SSH proxy (optimized)")
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
