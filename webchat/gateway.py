#!/usr/bin/env python3
"""
WebSocket-to-IRC Gateway for pyIRCX
Allows web browsers to connect to IRC via WebSocket
"""

import asyncio
import json
import ssl
import logging
import argparse
import signal
import configparser
import time
from pathlib import Path
from collections import defaultdict

try:
    import websockets
except ImportError:
    print("Error: websockets library not installed. Run: pip install websockets")
    exit(1)

# Import validators
try:
    from validators import (
        validate_nickname, validate_username, validate_realname,
        validate_channel, validate_message, validate_reason,
        validate_password, validate_key, validate_raw_command, sanitize_ip
    )
except ImportError:
    print("Error: validators.py not found. Ensure it's in the same directory as gateway.py")
    exit(1)


# =============================================================================
# CONSTANTS
# =============================================================================

# Default network settings
DEFAULT_WS_HOST = '0.0.0.0'
DEFAULT_WS_PORT = 8765
DEFAULT_IRC_HOST = 'localhost'
DEFAULT_IRC_PORT = 6667

# Buffer and message limits
MAX_BUFFER_SIZE = 65536  # 64KB
IRC_READ_CHUNK = 4096

# Rate limiting
MAX_MESSAGES_PER_SECOND = 5
MAX_CONNECTIONS = 1000
MAX_CONNECTIONS_PER_IP = 5

# Timeouts (seconds)
PING_INTERVAL = 30
PONG_TIMEOUT = 10
AUTH_TIMEOUT = 5

# WEBIRC
WEBIRC_GATEWAY = 'pyircx-webchat'


# =============================================================================
# CONFIGURATION
# =============================================================================

def load_config(config_file='/etc/pyircx/webchat.conf'):
    """Load configuration from file

    Args:
        config_file: Path to configuration file

    Returns:
        dict: Configuration settings

    Note:
        If config file doesn't exist, returns defaults (except WEBIRC password)
    """
    config = configparser.ConfigParser()

    # Default configuration
    settings = {
        'ws_host': DEFAULT_WS_HOST,
        'ws_port': DEFAULT_WS_PORT,
        'ws_ssl_cert': None,
        'ws_ssl_key': None,
        'irc_host': DEFAULT_IRC_HOST,
        'irc_port': DEFAULT_IRC_PORT,
        'irc_ssl': False,
        'irc_verify_ssl': True,
        'webirc_password': None,
        'webirc_gateway': WEBIRC_GATEWAY,
        'max_connections': MAX_CONNECTIONS,
        'max_connections_per_ip': MAX_CONNECTIONS_PER_IP,
        'max_messages_per_second': MAX_MESSAGES_PER_SECOND,
        'max_buffer_size': MAX_BUFFER_SIZE,
        'ping_interval': PING_INTERVAL,
        'pong_timeout': PONG_TIMEOUT,
        'auth_timeout': AUTH_TIMEOUT,
        'log_level': 'INFO',
    }

    # Try to load config file
    if Path(config_file).exists():
        config.read(config_file)

        # WebSocket settings
        if config.has_section('websocket'):
            settings['ws_host'] = config.get('websocket', 'host', fallback=settings['ws_host'])
            settings['ws_port'] = config.getint('websocket', 'port', fallback=settings['ws_port'])
            settings['ws_ssl_cert'] = config.get('websocket', 'ssl_cert', fallback=None) or None
            settings['ws_ssl_key'] = config.get('websocket', 'ssl_key', fallback=None) or None

        # IRC settings
        if config.has_section('irc'):
            settings['irc_host'] = config.get('irc', 'host', fallback=settings['irc_host'])
            settings['irc_port'] = config.getint('irc', 'port', fallback=settings['irc_port'])
            settings['irc_ssl'] = config.getboolean('irc', 'ssl', fallback=settings['irc_ssl'])
            settings['irc_verify_ssl'] = config.getboolean('irc', 'verify_ssl', fallback=settings['irc_verify_ssl'])

        # WEBIRC settings
        if config.has_section('webirc'):
            webirc_pass = config.get('webirc', 'password', fallback=None)
            if webirc_pass and webirc_pass.strip():
                settings['webirc_password'] = webirc_pass.strip()
            settings['webirc_gateway'] = config.get('webirc', 'gateway', fallback=settings['webirc_gateway'])

        # Limits
        if config.has_section('limits'):
            settings['max_connections'] = config.getint('limits', 'max_connections', fallback=settings['max_connections'])
            settings['max_connections_per_ip'] = config.getint('limits', 'max_connections_per_ip', fallback=settings['max_connections_per_ip'])
            settings['max_messages_per_second'] = config.getint('limits', 'max_messages_per_second', fallback=settings['max_messages_per_second'])
            settings['max_buffer_size'] = config.getint('limits', 'max_buffer_size', fallback=settings['max_buffer_size'])

        # Timeouts
        if config.has_section('timeouts'):
            settings['ping_interval'] = config.getint('timeouts', 'ping_interval', fallback=settings['ping_interval'])
            settings['pong_timeout'] = config.getint('timeouts', 'pong_timeout', fallback=settings['pong_timeout'])
            settings['auth_timeout'] = config.getint('timeouts', 'auth_timeout', fallback=settings['auth_timeout'])

        # Logging
        if config.has_section('logging'):
            settings['log_level'] = config.get('logging', 'level', fallback=settings['log_level'])

    return settings


# =============================================================================
# RATE LIMITER
# =============================================================================

class RateLimiter:
    """Rate limiter for preventing message flooding"""

    def __init__(self, messages_per_second=5):
        """Initialize rate limiter

        Args:
            messages_per_second: Maximum messages allowed per second
        """
        self.messages_per_second = messages_per_second
        self.clients = defaultdict(list)

    def check(self, client_id):
        """Check if client is within rate limit

        Args:
            client_id: Unique client identifier

        Returns:
            bool: True if within limit, False if exceeded
        """
        now = time.time()

        # Clean old entries (older than 1 second)
        self.clients[client_id] = [ts for ts in self.clients[client_id] if now - ts < 1.0]

        # Check if rate limit exceeded
        if len(self.clients[client_id]) >= self.messages_per_second:
            return False

        # Record this message
        self.clients[client_id].append(now)
        return True

    def cleanup(self, client_id):
        """Remove client from rate limiter

        Args:
            client_id: Unique client identifier
        """
        if client_id in self.clients:
            del self.clients[client_id]


# =============================================================================
# IRC WEBSOCKET GATEWAY
# =============================================================================

class IRCWebSocketGateway:
    """Bridges WebSocket connections to IRC server"""

    def __init__(self, config):
        """Initialize gateway

        Args:
            config: Configuration dictionary from load_config()
        """
        self.irc_host = config['irc_host']
        self.irc_port = config['irc_port']
        self.use_ssl = config['irc_ssl']
        self.verify_ssl = config['irc_verify_ssl']
        self.webirc_pass = config['webirc_password']
        self.webirc_gateway = config['webirc_gateway']
        self.max_connections = config['max_connections']
        self.max_connections_per_ip = config['max_connections_per_ip']
        self.max_buffer_size = config['max_buffer_size']

        self.connections = {}
        self.rate_limiter = RateLimiter(config['max_messages_per_second'])
        self.ip_connection_count = defaultdict(int)

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, config['log_level'].upper(), logging.INFO),
            format='[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('irc-gateway')

    def get_client_ip(self, websocket):
        """Get real client IP from WebSocket connection

        Args:
            websocket: WebSocket connection object

        Returns:
            str: Client IP address (sanitized)
        """
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
                return sanitize_ip(client_ip)

            # X-Real-IP header (alternative)
            real_ip = headers.get('X-Real-IP', '') or headers.get('x-real-ip', '')
            if real_ip:
                return sanitize_ip(real_ip.strip())

        # Fall back to direct connection IP
        try:
            remote = websocket.remote_address
            if remote:
                return sanitize_ip(remote[0])
        except (AttributeError, TypeError, IndexError):
            pass

        return '0.0.0.0'

    async def handle_websocket(self, websocket, path=None):
        """Handle a new WebSocket connection

        Args:
            websocket: WebSocket connection object
            path: Request path (optional, for compatibility)
        """
        client_id = id(websocket)
        client_ip = self.get_client_ip(websocket)

        # Check connection limits
        if len(self.connections) >= self.max_connections:
            self.logger.warning(f"Connection refused from {client_ip} - server at capacity ({self.max_connections} connections)")
            try:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Server at capacity - please try again later'
                }))
                await websocket.close()
            except Exception:
                pass
            return

        # Check per-IP connection limits
        if self.ip_connection_count[client_ip] >= self.max_connections_per_ip:
            self.logger.warning(f"Connection refused from {client_ip} - too many connections from this IP")
            try:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Too many connections from your IP - please close some connections first'
                }))
                await websocket.close()
            except Exception:
                pass
            return

        self.logger.info(f"New connection: {client_id} from {client_ip}")

        irc_reader = None
        irc_writer = None

        try:
            # Connect to IRC server
            if self.use_ssl:
                ssl_ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                irc_reader, irc_writer = await asyncio.open_connection(
                    self.irc_host, self.irc_port, ssl=ssl_ctx
                )
            else:
                irc_reader, irc_writer = await asyncio.open_connection(
                    self.irc_host, self.irc_port
                )

            self.logger.info(f"Connected to IRC for client {client_id}")

            # Track connection
            self.connections[client_id] = {
                'websocket': websocket,
                'irc_writer': irc_writer,
                'irc_reader': irc_reader,
                'client_ip': client_ip,
                'webirc_sent': False
            }
            self.ip_connection_count[client_ip] += 1

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

        except ConnectionRefusedError:
            self.logger.error(f"IRC server refused connection for client {client_id}")
            try:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Unable to connect to chat server - please try again later'
                }))
            except Exception:
                pass
        except asyncio.TimeoutError:
            self.logger.error(f"IRC connection timeout for client {client_id}")
            try:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Connection timeout - please try again later'
                }))
            except Exception:
                pass
        except Exception as e:
            self.logger.error(f"Error for client {client_id}: {type(e).__name__}")
            try:
                await websocket.send(json.dumps({
                    'type': 'error',
                    'message': 'Connection error - please try again later'
                }))
            except Exception:
                pass
        finally:
            # Clean up IRC connection
            if irc_writer:
                try:
                    irc_writer.write(b'QUIT :WebChat disconnected\r\n')
                    await irc_writer.drain()
                    irc_writer.close()
                    await irc_writer.wait_closed()
                except Exception:
                    pass

            # Clean up tracking
            if client_id in self.connections:
                del self.connections[client_id]
            if client_ip in self.ip_connection_count:
                self.ip_connection_count[client_ip] -= 1
                if self.ip_connection_count[client_ip] <= 0:
                    del self.ip_connection_count[client_ip]
            self.rate_limiter.cleanup(client_id)

            self.logger.info(f"Connection closed: {client_id}")

    async def ws_to_irc(self, websocket, irc_writer, client_id):
        """Forward messages from WebSocket to IRC

        Args:
            websocket: WebSocket connection
            irc_writer: IRC connection writer
            client_id: Unique client identifier
        """
        try:
            async for message in websocket:
                # Rate limiting check
                if not self.rate_limiter.check(client_id):
                    self.logger.warning(f"[{client_id}] Rate limit exceeded")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Sending messages too fast - please slow down'
                    }))
                    continue

                try:
                    data = json.loads(message)

                    # Raw command (with validation)
                    if data.get('type') == 'raw':
                        cmd = data.get('command', '').strip()
                        if cmd:
                            try:
                                validated_cmd = validate_raw_command(cmd)
                                irc_writer.write(f"{validated_cmd}\r\n".encode('utf-8'))
                                await irc_writer.drain()
                            except ValueError as e:
                                await websocket.send(json.dumps({
                                    'type': 'error',
                                    'message': str(e)
                                }))

                    # Connect to IRC
                    elif data.get('type') == 'connect':
                        try:
                            nick = validate_nickname(data.get('nick', 'WebUser'))
                            username = validate_username(data.get('username', 'webchat'))
                            realname = validate_realname(data.get('realname', 'WebChat User'))
                            password = data.get('password')

                            # Send WEBIRC before registration if configured
                            conn = self.connections.get(client_id)
                            if conn and self.webirc_pass and not conn.get('webirc_sent'):
                                client_ip = conn.get('client_ip', '0.0.0.0')
                                webirc_cmd = f"WEBIRC {self.webirc_pass} {self.webirc_gateway} {client_ip} {client_ip}"
                                irc_writer.write(f"{webirc_cmd}\r\n".encode('utf-8'))
                                conn['webirc_sent'] = True
                                self.logger.info(f"[{client_id}] Sent WEBIRC for {client_ip}")

                            # Send connection commands
                            if password:
                                validated_pass = validate_password(password)
                                irc_writer.write(f"PASS {validated_pass}\r\n".encode('utf-8'))
                            irc_writer.write(f"NICK {nick}\r\n".encode('utf-8'))
                            irc_writer.write(f"USER {username} 0 * :{realname}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                        except ValueError as e:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'message': str(e)
                            }))

                    # Send message
                    elif data.get('type') == 'message':
                        try:
                            target = data.get('target', '')
                            text = data.get('text', '')

                            # Debug: log what we received
                            if 'ACTION' in text:
                                logging.info(f"Received from webchat: repr={repr(text)}, has_x01={chr(1) in text}, bytes={text.encode('utf-8')[:50].hex()}")

                            # Validate target (could be nick or channel)
                            if target.startswith('#'):
                                target = validate_channel(target)
                            else:
                                target = validate_nickname(target)

                            text = validate_message(text)

                            # Debug: log ACTION messages
                            if '\x01' in text:
                                logging.info(f"Sending CTCP/ACTION: repr={repr(text)}, bytes={text.encode('utf-8').hex()}")

                            irc_writer.write(f"PRIVMSG {target} :{text}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                        except ValueError as e:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'message': str(e)
                            }))

                    # Join channel
                    elif data.get('type') == 'join':
                        try:
                            channel = validate_channel(data.get('channel', ''))
                            key = validate_key(data.get('key', ''))

                            cmd = f"JOIN {channel}" + (f" {key}" if key else "")
                            irc_writer.write(f"{cmd}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                        except ValueError as e:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'message': str(e)
                            }))

                    # Part channel
                    elif data.get('type') == 'part':
                        try:
                            channel = validate_channel(data.get('channel', ''))
                            reason = validate_reason(data.get('reason', ''))

                            cmd = f"PART {channel}" + (f" :{reason}" if reason else "")
                            irc_writer.write(f"{cmd}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                        except ValueError as e:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'message': str(e)
                            }))

                    # Change nickname
                    elif data.get('type') == 'nick':
                        try:
                            nick = validate_nickname(data.get('nick', ''))
                            irc_writer.write(f"NICK {nick}\r\n".encode('utf-8'))
                            await irc_writer.drain()

                        except ValueError as e:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'message': str(e)
                            }))

                    # Quit IRC
                    elif data.get('type') == 'quit':
                        reason = validate_reason(data.get('reason', 'Leaving'))
                        irc_writer.write(f"QUIT :{reason}\r\n".encode('utf-8'))
                        await irc_writer.drain()
                        break

                except json.JSONDecodeError:
                    # If not JSON, treat as raw IRC command (with validation)
                    if message.strip():
                        try:
                            validated_cmd = validate_raw_command(message.strip())
                            irc_writer.write(f"{validated_cmd}\r\n".encode('utf-8'))
                            await irc_writer.drain()
                        except ValueError as e:
                            await websocket.send(json.dumps({
                                'type': 'error',
                                'message': str(e)
                            }))

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            self.logger.error(f"[{client_id}] WS->IRC error: {type(e).__name__}")

    async def irc_to_ws(self, irc_reader, websocket, client_id):
        """Forward messages from IRC to WebSocket

        Args:
            irc_reader: IRC connection reader
            websocket: WebSocket connection
            client_id: Unique client identifier
        """
        buffer = b''

        try:
            while True:
                data = await irc_reader.read(IRC_READ_CHUNK)
                if not data:
                    break

                buffer += data

                # Buffer overflow protection
                if len(buffer) > self.max_buffer_size:
                    self.logger.warning(f"[{client_id}] Buffer overflow - disconnecting")
                    await websocket.send(json.dumps({
                        'type': 'error',
                        'message': 'Connection error - please reconnect'
                    }))
                    break

                while b'\r\n' in buffer:
                    line, buffer = buffer.split(b'\r\n', 1)
                    try:
                        line_str = line.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        line_str = line.decode('latin-1', errors='replace')

                    # Handle PING automatically
                    if line_str.startswith('PING'):
                        pong = line_str.replace('PING', 'PONG', 1)
                        conn = self.connections.get(client_id)
                        if conn:
                            conn['irc_writer'].write(f"{pong}\r\n".encode('utf-8'))
                            await conn['irc_writer'].drain()
                        continue

                    # Parse and forward to WebSocket
                    parsed = self.parse_irc_message(line_str)
                    await websocket.send(json.dumps(parsed))

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            self.logger.error(f"[{client_id}] IRC->WS error: {type(e).__name__}")

    def parse_irc_message(self, line):
        """Parse IRC message into structured format

        Args:
            line: Raw IRC message line

        Returns:
            dict: Parsed message structure
        """
        result = {'type': 'irc', 'raw': line, 'prefix': None, 'command': None, 'params': []}

        if not line:
            return result

        # Extract prefix if present
        if line.startswith(':'):
            space = line.find(' ')
            if space != -1:
                result['prefix'] = line[1:space]
                line = line[space+1:]
            else:
                result['prefix'] = line[1:]
                return result

        # Parse command and parameters
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

        # Extract nickname from prefix
        if result['prefix'] and '!' in result['prefix']:
            result['nick'] = result['prefix'].split('!')[0]
        elif result['prefix']:
            result['nick'] = result['prefix']

        return result


# =============================================================================
# MAIN
# =============================================================================

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='WebSocket-to-IRC Gateway for pyIRCX')
    parser.add_argument('--config', default='/etc/pyircx/webchat.conf',
                       help='Configuration file path')
    parser.add_argument('--ws-host', help='WebSocket bind address (overrides config)')
    parser.add_argument('--ws-port', type=int, help='WebSocket port (overrides config)')
    parser.add_argument('--irc-host', help='IRC server host (overrides config)')
    parser.add_argument('--irc-port', type=int, help='IRC server port (overrides config)')
    parser.add_argument('--irc-ssl', action='store_true', help='Use SSL for IRC (overrides config)')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL verification (not recommended)')
    parser.add_argument('--ssl-cert', help='SSL cert for WebSocket server (overrides config)')
    parser.add_argument('--ssl-key', help='SSL key for WebSocket server (overrides config)')
    parser.add_argument('--webirc-pass', help='WEBIRC password (overrides config)')
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Command line overrides
    if args.ws_host:
        config['ws_host'] = args.ws_host
    if args.ws_port:
        config['ws_port'] = args.ws_port
    if args.irc_host:
        config['irc_host'] = args.irc_host
    if args.irc_port:
        config['irc_port'] = args.irc_port
    if args.irc_ssl:
        config['irc_ssl'] = True
    if args.no_verify_ssl:
        config['irc_verify_ssl'] = False
    if args.ssl_cert:
        config['ws_ssl_cert'] = args.ssl_cert
    if args.ssl_key:
        config['ws_ssl_key'] = args.ssl_key
    if args.webirc_pass:
        config['webirc_password'] = args.webirc_pass

    # Validate WEBIRC password is configured
    if not config['webirc_password']:
        print("ERROR: WEBIRC password not configured!")
        print("Please set the WEBIRC password in your configuration file:")
        print(f"  {args.config}")
        print("Or provide it via command line: --webirc-pass YOUR_PASSWORD")
        print("\nSecurity Note: The WEBIRC password should match your IRC server configuration.")
        exit(1)

    # Create gateway
    gateway = IRCWebSocketGateway(config)

    # Configure WebSocket SSL
    ssl_context = None
    if config['ws_ssl_cert'] and config['ws_ssl_key']:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(config['ws_ssl_cert'], config['ws_ssl_key'])

    # Set up signal handlers for graceful shutdown
    stop = asyncio.Event()

    def signal_handler():
        stop.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Start server
    async with websockets.serve(
        gateway.handle_websocket,
        config['ws_host'],
        config['ws_port'],
        ssl=ssl_context
    ):
        gateway.logger.info(f"WebSocket gateway started: {config['ws_host']}:{config['ws_port']} -> IRC {config['irc_host']}:{config['irc_port']}")
        gateway.logger.info(f"Max connections: {config['max_connections']} total, {config['max_connections_per_ip']} per IP")
        gateway.logger.info(f"Rate limit: {config['max_messages_per_second']} messages/second")
        await stop.wait()

    gateway.logger.info("Gateway shutting down")


if __name__ == '__main__':
    asyncio.run(main())
