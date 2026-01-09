#!/usr/bin/env python3
"""
WebSocket-to-IRC Gateway for pyIRCX
Allows web browsers to connect to IRC via WebSocket

Copyright (C) 2026 pyIRCX Project
License: GPL-3.0
"""

import asyncio
import json
import ssl
import logging
import argparse
import signal
from pathlib import Path

try:
    import websockets
except ImportError:
    print("Error: websockets library not installed. Run: pip install websockets")
    exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('irc-gateway')

# Default Configuration (can be overridden via command line)
IRC_HOST = 'localhost'
IRC_PORT = 6667
WS_HOST = '0.0.0.0'
WS_PORT = 8765
WEBIRC_PASSWORD = 'changeme'  # IMPORTANT: Change this in production!
WEBIRC_GATEWAY = 'pyircx-webchat'


class IRCWebSocketGateway:
    """Bridges WebSocket connections to IRC server"""

    def __init__(self, irc_host, irc_port, use_ssl=False, webirc_pass=None):
        self.irc_host = irc_host
        self.irc_port = irc_port
        self.use_ssl = use_ssl
        self.webirc_pass = webirc_pass
        self.connections = {}

    def get_client_ip(self, websocket):
        """Get real client IP from WebSocket connection, checking X-Forwarded-For"""
        # Try multiple ways to access headers (websockets library version compatibility)
        headers = None

        # websockets 15.x: websocket.request.headers
        if hasattr(websocket, 'request') and websocket.request:
            req = websocket.request
            if hasattr(req, 'headers'):
                headers = req.headers

        # websockets 10-14: websocket.request_headers
        if not headers:
            headers = getattr(websocket, 'request_headers', None)

        # Try to get X-Forwarded-For or X-Real-IP
        if headers:
            # X-Forwarded-For header (Apache/nginx reverse proxy)
            forwarded_for = headers.get('X-Forwarded-For', '') or headers.get('x-forwarded-for', '')
            if forwarded_for:
                # X-Forwarded-For can be comma-separated; first IP is the original client
                client_ip = forwarded_for.split(',')[0].strip()
                logger.debug(f"Got IP from X-Forwarded-For: {client_ip}")
                return client_ip

            # X-Real-IP header (alternative)
            real_ip = headers.get('X-Real-IP', '') or headers.get('x-real-ip', '')
            if real_ip:
                logger.debug(f"Got IP from X-Real-IP: {real_ip}")
                return real_ip.strip()

        # Fall back to direct connection IP
        try:
            remote = websocket.remote_address
            if remote:
                logger.debug(f"Using remote_address: {remote[0]}")
                return remote[0]
        except:
            pass

        return '0.0.0.0'

    async def handle_websocket(self, websocket, path=None):
        """Handle a new WebSocket connection"""
        client_id = id(websocket)

        # Debug: log available header sources
        if hasattr(websocket, 'request') and websocket.request:
            req = websocket.request
            if hasattr(req, 'headers'):
                logger.debug(f"[{client_id}] Request headers: {dict(req.headers)}")
        elif hasattr(websocket, 'request_headers'):
            logger.debug(f"[{client_id}] request_headers: {dict(websocket.request_headers)}")

        client_ip = self.get_client_ip(websocket)
        logger.info(f"New WebSocket connection: {client_id} from {client_ip}")

        irc_reader = None
        irc_writer = None

        try:
            # Connect to IRC server
            if self.use_ssl:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                irc_reader, irc_writer = await asyncio.open_connection(
                    self.irc_host, self.irc_port, ssl=ssl_ctx
                )
            else:
                irc_reader, irc_writer = await asyncio.open_connection(
                    self.irc_host, self.irc_port
                )

            logger.info(f"Connected to IRC server for client {client_id}")

            self.connections[client_id] = {
                'websocket': websocket,
                'irc_writer': irc_writer,
                'irc_reader': irc_reader,
                'client_ip': client_ip,
                'webirc_sent': False
            }

            # Create tasks for bidirectional communication
            ws_to_irc = asyncio.create_task(self.ws_to_irc(websocket, irc_writer, client_id))
            irc_to_ws = asyncio.create_task(self.irc_to_ws(irc_reader, websocket, client_id))

            done, pending = await asyncio.wait(
                [ws_to_irc, irc_to_ws],
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        except Exception as e:
            logger.error(f"Error for client {client_id}: {e}")
            try:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': f'Connection error: {str(e)}'
                }))
            except:
                pass
        finally:
            if irc_writer:
                try:
                    irc_writer.write(b'QUIT :WebChat disconnected\r\n')
                    await irc_writer.drain()
                    irc_writer.close()
                    await irc_writer.wait_closed()
                except:
                    pass

            if client_id in self.connections:
                del self.connections[client_id]

            logger.info(f"Connection closed: {client_id}")

    async def ws_to_irc(self, websocket, irc_writer, client_id):
        """Forward messages from WebSocket to IRC"""
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)

                    if data.get('type') == 'raw':
                        cmd = data.get('command', '').strip()
                        if cmd:
                            irc_writer.write(f"{cmd}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                    elif data.get('type') == 'connect':
                        nick = data.get('nick', 'WebUser')
                        username = data.get('username', 'webchat')
                        realname = data.get('realname', 'WebChat User')
                        password = data.get('password')

                        # Send WEBIRC before registration if configured
                        conn = self.connections.get(client_id)
                        if conn and self.webirc_pass and not conn.get('webirc_sent'):
                            client_ip = conn.get('client_ip', '0.0.0.0')
                            # WEBIRC password gateway hostname ip :realhost
                            # The realhost can be the IP if no reverse DNS
                            webirc_cmd = f"WEBIRC {self.webirc_pass} {WEBIRC_GATEWAY} {client_ip} {client_ip}"
                            irc_writer.write(f"{webirc_cmd}\r\n".encode('utf-8'))
                            conn['webirc_sent'] = True
                            logger.info(f"[{client_id}] Sent WEBIRC for {client_ip}")

                        if password:
                            irc_writer.write(f"PASS {password}\r\n".encode('utf-8'))
                        irc_writer.write(f"NICK {nick}\r\n".encode('utf-8'))
                        irc_writer.write(f"USER {username} 0 * :{realname}\r\n".encode('utf-8'))
                        await irc_writer.drain()

                    elif data.get('type') == 'message':
                        target = data.get('target', '')
                        text = data.get('text', '')
                        if target and text:
                            irc_writer.write(f"PRIVMSG {target} :{text}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                    elif data.get('type') == 'join':
                        channel = data.get('channel', '')
                        key = data.get('key', '')
                        if channel:
                            cmd = f"JOIN {channel}" + (f" {key}" if key else "")
                            irc_writer.write(f"{cmd}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                    elif data.get('type') == 'part':
                        channel = data.get('channel', '')
                        reason = data.get('reason', '')
                        if channel:
                            cmd = f"PART {channel}" + (f" :{reason}" if reason else "")
                            irc_writer.write(f"{cmd}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                    elif data.get('type') == 'nick':
                        nick = data.get('nick', '')
                        if nick:
                            irc_writer.write(f"NICK {nick}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                    elif data.get('type') == 'quit':
                        reason = data.get('reason', 'Leaving')
                        irc_writer.write(f"QUIT :{reason}\r\n".encode('utf-8'))
                        await irc_writer.drain()
                        break

                except json.JSONDecodeError:
                    if message.strip():
                        irc_writer.write(f"{message.strip()}\r\n".encode('utf-8'))
                        await irc_writer.drain()

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"[{client_id}] WS->IRC error: {e}")

    async def irc_to_ws(self, irc_reader, websocket, client_id):
        """Forward messages from IRC to WebSocket"""
        buffer = b''

        try:
            while True:
                data = await irc_reader.read(4096)
                if not data:
                    break

                buffer += data

                while b'\r\n' in buffer:
                    line, buffer = buffer.split(b'\r\n', 1)
                    try:
                        line_str = line.decode('utf-8', errors='replace')
                    except:
                        line_str = line.decode('latin-1', errors='replace')

                    # Handle PING
                    if line_str.startswith('PING'):
                        pong = line_str.replace('PING', 'PONG', 1)
                        conn = self.connections.get(client_id)
                        if conn:
                            conn['irc_writer'].write(f"{pong}\r\n".encode('utf-8'))
                            await conn['irc_writer'].drain()
                        continue

                    parsed = self.parse_irc_message(line_str)
                    await websocket.send(json.dumps(parsed))

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logger.error(f"[{client_id}] IRC->WS error: {e}")

    def parse_irc_message(self, line):
        """Parse IRC message into structured format"""
        result = {'type': 'irc', 'raw': line, 'prefix': None, 'command': None, 'params': []}

        if not line:
            return result

        if line.startswith(':'):
            space = line.find(' ')
            if space != -1:
                result['prefix'] = line[1:space]
                line = line[space+1:]
            else:
                result['prefix'] = line[1:]
                return result

        if ' :' in line:
            before_trailing, trailing = line.split(' :', 1)
            parts = before_trailing.split()
            if parts:
                result['command'] = parts[0]
                result['params'] = parts[1:] + [trailing]
        else:
            parts = line.split()
            if parts:
                result['command'] = parts[0]
                result['params'] = parts[1:]

        if result['prefix'] and '!' in result['prefix']:
            result['nick'] = result['prefix'].split('!')[0]
        elif result['prefix']:
            result['nick'] = result['prefix']

        return result


async def main():
    parser = argparse.ArgumentParser(description='WebSocket-to-IRC Gateway')
    parser.add_argument('--ws-host', default=WS_HOST, help='WebSocket bind address')
    parser.add_argument('--ws-port', type=int, default=WS_PORT, help='WebSocket port')
    parser.add_argument('--irc-host', default=IRC_HOST, help='IRC server host')
    parser.add_argument('--irc-port', type=int, default=IRC_PORT, help='IRC server port')
    parser.add_argument('--irc-ssl', action='store_true', help='Use SSL for IRC')
    parser.add_argument('--ssl-cert', help='SSL cert for WebSocket server')
    parser.add_argument('--ssl-key', help='SSL key for WebSocket server')
    parser.add_argument('--webirc-pass', default=WEBIRC_PASSWORD, help='WEBIRC password for IP forwarding')
    args = parser.parse_args()

    gateway = IRCWebSocketGateway(args.irc_host, args.irc_port, args.irc_ssl, args.webirc_pass)

    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(args.ssl_cert, args.ssl_key)

    stop = asyncio.Event()

    def signal_handler():
        stop.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    async with websockets.serve(gateway.handle_websocket, args.ws_host, args.ws_port, ssl=ssl_context):
        logger.info(f"WebSocket gateway on {args.ws_host}:{args.ws_port} -> IRC {args.irc_host}:{args.irc_port}")
        await stop.wait()


if __name__ == '__main__':
    asyncio.run(main())
