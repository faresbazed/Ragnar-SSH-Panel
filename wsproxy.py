#!/usr/bin/env python3
# Ragnar SSH Panel - WebSocket SSH proxy (port 80, payload support)
import asyncio, argparse

BUF = 64 * 1024

async def relay(reader, writer):
    try:
        while True:
            data = await reader.read(BUF)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def handle(c_r, c_w):
    try:
        # read HTTP header block (the "payload") until blank line
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = await c_r.read(1024)
            if not chunk:
                c_w.close()
                return
            header += chunk
        s_r, s_w = await asyncio.open_connection(args.ssh_host, args.ssh_port)
        await asyncio.gather(relay(c_r, s_w), relay(s_r, c_w))
    except Exception:
        pass
    finally:
        c_w.close()

async def main():
    server = await asyncio.start_server(handle, args.bind, args.listen)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--listen", type=int, default=80)
    ap.add_argument("-s", "--ssh-port", type=int, default=22)
    ap.add_argument("--ssh-host", default="127.0.0.1")
    ap.add_argument("--bind", default="0.0.0.0")
    args = ap.parse_args()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
