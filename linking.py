"""
pyIRCX Server Linking Module
Implements server-to-server linking protocol (pyIRCX-Only)

IMPORTANT: This linking implementation is designed ONLY for pyIRCX-to-pyIRCX
connections. It is NOT compatible with other IRC daemons (ircd-hybrid,
UnrealIRCd, InspIRCd, etc.) and does not attempt RFC 2813 compliance.

This allows us to:
- Use enhanced protocol features without RFC constraints
- Make breaking changes between major versions
- Optimize for pyIRCX-specific behavior
- Simplify version compatibility checking

DO NOT attempt to link to non-pyIRCX servers.
"""

import asyncio
import bcrypt
import time
import logging
from typing import Dict, Set, Optional, Tuple

logger = logging.getLogger(__name__)

# Will be set by pyircx.py when module is imported
CONFIG = None

# pyIRCX Linking Protocol
PYIRCX_VERSION = "1.3.0"  # Software version
LINKING_PROTOCOL_VERSION = "2"  # Protocol version (increment on breaking changes)
MIN_COMPATIBLE_VERSION = "1.2.0"  # Minimum compatible pyIRCX version
MAX_CLOCK_SKEW = 60  # Maximum acceptable clock skew in seconds (strict)
CLOCK_SKEW_WARNING = 10  # Warn if skew exceeds this (non-fatal)
_User = None  # Cache for User class to avoid reimporting
_Channel = None  # Cache for Channel class to avoid reimporting


class LinkedServer:
    """Represents a linked server in the network"""

    def __init__(self, name: str, hopcount: int, description: str,
                 writer: Optional[asyncio.StreamWriter] = None, role: str = 'unknown'):
        self.name = name
        self.hopcount = hopcount
        self.description = description
        self.writer = writer
        self.role = role  # 'hub', 'leaf', 'standalone', or 'unknown'
        self.connected_at = time.time()
        self.is_direct = writer is not None  # Direct connection vs. downstream
        self.users: Set[str] = set()  # Nicknames from this server
        self.last_ping = time.time()
        self.last_pong = time.time()

        # Burst state tracking
        self.burst_complete = False

        # Version and compatibility
        self.version = None  # e.g., "1.3.0"
        self.protocol_version = None  # e.g., "2"
        self.time_delta = 0  # Detected clock skew in seconds

    async def send(self, message: str):
        """Send a message to this server"""
        if self.writer and not self.writer.is_closing():
            try:
                self.writer.write((message + '\r\n').encode('utf-8', errors='replace'))
                await self.writer.drain()
            except Exception as e:
                logger.error(f"Error sending to {self.name}: {e}")

    def add_user(self, nickname: str):
        """Track a user from this server"""
        self.users.add(nickname)

    def remove_user(self, nickname: str):
        """Remove a user from this server"""
        self.users.discard(nickname)


class ServerLinkManager:
    """Manages server-to-server links"""

    def __init__(self, irc_server):
        self.irc_server = irc_server
        self.servers: Dict[str, LinkedServer] = {}  # servername -> LinkedServer
        self.linked_servers = self.servers  # Alias for compatibility
        self.enabled = CONFIG.get('linking', 'enabled', default=False)
        self.server_role = CONFIG.get('linking', 'server_role', default='standalone')
        self.bind_host = CONFIG.get('linking', 'bind_host', default='0.0.0.0')
        self.bind_port = CONFIG.get('linking', 'bind_port', default=7001)
        self.links_config = CONFIG.get('linking', 'links', default=[])
        self.link_server = None

        # Auto-reconnect tracking
        self.reconnect_attempts: Dict[str, int] = {}  # servername -> retry count
        self.reconnect_tasks: Dict[str, asyncio.Task] = {}  # servername -> task
        self.max_reconnect_delay = 60  # Maximum backoff delay in seconds

        # Ping/Pong monitoring
        self.ping_interval = 60  # Send PING every 60 seconds
        self.ping_timeout = 120  # Expect PONG within 120 seconds
        self.monitor_task = None  # Monitoring task

        # Validate server role
        valid_roles = ['standalone', 'trunk', 'branch']
        if self.server_role not in valid_roles:
            logger.error(f"Invalid server_role '{self.server_role}'. Must be one of: {valid_roles}")
            self.server_role = 'standalone'

    def validate_link_roles(self, my_role: str, remote_role: str) -> Tuple[bool, str]:
        """
        Validate if two servers can link based on their roles.
        Returns (is_valid, error_message)

        Rules:
        - standalone cannot link to anything
        - trunk can only link to branch
        - branch can only link to trunk
        - This enforces a flat trunk-and-branch topology (no multi-tier)
        """
        # Standalone servers don't link
        if my_role == 'standalone':
            return False, "This server is configured as standalone (linking disabled)"

        if remote_role == 'standalone':
            return False, f"Remote server is configured as standalone"

        # Trunk-to-Trunk not allowed (prevents complex hierarchies)
        if my_role == 'trunk' and remote_role == 'trunk':
            return False, "Trunk-to-Trunk linking not allowed (would create multi-tier topology)"

        # Branch-to-Branch not allowed
        if my_role == 'branch' and remote_role == 'branch':
            return False, "Branch-to-Branch linking not allowed (branches must connect to trunk)"

        # Trunk can link to branch
        if my_role == 'trunk' and remote_role == 'branch':
            return True, ""

        # Branch can link to trunk
        if my_role == 'branch' and remote_role == 'trunk':
            return True, ""

        # Anything else is invalid
        return False, f"Invalid role combination: {my_role} <-> {remote_role}"

    async def _validate_version(self, line: str, remote_name: str, writer: asyncio.StreamWriter) -> bool:
        """Validate remote server version"""
        parts = line.split()
        if len(parts) < 2 or parts[0] != 'VERSION':
            logger.error(f"Invalid VERSION response from {remote_name}: {line}")
            await self.send_to_writer(writer, f"ERROR :Invalid VERSION response")
            writer.close()
            return False

        # Parse VERSION pyIRCX/1.3.0 PROTO/2
        version_info = {}
        for part in parts[1:]:
            if '/' in part:
                key, value = part.split('/', 1)
                version_info[key] = value

        remote_version = version_info.get('pyIRCX', '0.0.0')
        remote_proto = version_info.get('PROTO', '1')

        logger.info(f"Remote server {remote_name}: pyIRCX/{remote_version} PROTO/{remote_proto}")

        # Require EXACT version match (strict - no risk tolerance)
        if remote_version != PYIRCX_VERSION:
            logger.error(
                f"Version mismatch from {remote_name}: "
                f"{remote_version} != {PYIRCX_VERSION} (exact match required)"
            )
            await self.send_to_writer(
                writer,
                f"ERROR :Version mismatch. Remote: {remote_version}, Local: {PYIRCX_VERSION}. "
                f"Versions must match exactly. Please upgrade/downgrade to match."
            )
            writer.close()
            return False

        # Check protocol version (must match exactly for now)
        if remote_proto != LINKING_PROTOCOL_VERSION:
            logger.error(
                f"Incompatible protocol version from {remote_name}: "
                f"{remote_proto} != {LINKING_PROTOCOL_VERSION}"
            )
            await self.send_to_writer(
                writer,
                f"ERROR :Incompatible linking protocol {remote_proto}. "
                f"Required: {LINKING_PROTOCOL_VERSION}"
            )
            writer.close()
            return False

        logger.info(f"Version check passed for {remote_name}")
        return True

    async def _validate_time_sync(self, line: str, remote_name: str, writer: asyncio.StreamWriter) -> Optional[int]:
        """Validate time synchronization. Returns time_delta or None on failure."""
        parts = line.split()
        if len(parts) < 2 or parts[0] != 'TIMESYNC':
            logger.error(f"Invalid TIMESYNC response from {remote_name}: {line}")
            await self.send_to_writer(writer, f"ERROR :Invalid TIMESYNC response")
            writer.close()
            return None

        try:
            remote_time = int(parts[1])
            local_time = int(time.time())
            time_delta = abs(local_time - remote_time)

            logger.info(f"Time sync check for {remote_name}: delta = {time_delta}s")

            # Strict: Reject if >60 seconds
            if time_delta > MAX_CLOCK_SKEW:
                logger.error(
                    f"Clock skew too large for {remote_name}: {time_delta}s > {MAX_CLOCK_SKEW}s limit. "
                    f"Please synchronize clocks with NTP!"
                )
                await self.send_to_writer(
                    writer,
                    f"ERROR :Clock skew {time_delta}s exceeds {MAX_CLOCK_SKEW}s limit. "
                    f"Synchronize clocks with NTP (same time source recommended)."
                )
                writer.close()
                return None

            # Warning if >10 seconds
            if time_delta > CLOCK_SKEW_WARNING:
                logger.warning(
                    f"Clock skew detected for {remote_name}: {time_delta}s. "
                    f"Allowing link but please sync NTP!"
                )

            logger.info(f"Time sync check passed for {remote_name}")
            return remote_time - local_time  # Return signed delta

        except (ValueError, IndexError) as e:
            logger.error(f"Invalid TIMESYNC from {remote_name}: {e}")
            await self.send_to_writer(writer, f"ERROR :Invalid TIMESYNC format")
            writer.close()
            return None

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare semantic versions. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2"""
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]

            # Pad to same length
            while len(v1_parts) < len(v2_parts):
                v1_parts.append(0)
            while len(v2_parts) < len(v1_parts):
                v2_parts.append(0)

            for a, b in zip(v1_parts, v2_parts):
                if a < b:
                    return -1
                elif a > b:
                    return 1
            return 0
        except ValueError:
            return 0  # Can't compare, assume equal

    async def start(self):
        """Start the linking subsystem"""
        if not self.enabled:
            logger.info("Server linking disabled in config")
            return

        # Start listening for incoming server connections
        try:
            self.link_server = await asyncio.start_server(
                self.handle_incoming_link,
                self.bind_host,
                self.bind_port
            )
            logger.info(f"Server linking listening on {self.bind_host}:{self.bind_port}")

            # Auto-connect to configured links
            for link_cfg in self.links_config:
                if link_cfg.get('autoconnect', False):
                    asyncio.create_task(self.connect_to_server(link_cfg))

            # Start ping monitoring task
            self.monitor_task = asyncio.create_task(self._monitor_links())
            logger.info("Link monitoring task started")

        except Exception as e:
            logger.error(f"Failed to start server linking: {e}")

    async def stop(self):
        """Stop the linking subsystem"""
        # Close all server connections
        for server in list(self.servers.values()):
            await self.squit_server(server.name, "Server shutting down")

        # Stop listening
        if self.link_server:
            self.link_server.close()
            await self.link_server.wait_closed()

        # Stop monitoring task
        if self.monitor_task:
            self.monitor_task.cancel()

    async def _monitor_links(self):
        """Monitor all server links for health (ping/pong)"""
        logger.info("Link health monitoring started")
        try:
            while True:
                await asyncio.sleep(self.ping_interval)

                current_time = time.time()

                for servername, server in list(self.servers.items()):
                    if not server.is_direct:
                        continue  # Only monitor direct connections

                    # Check if we need to send a PING
                    time_since_ping = current_time - server.last_ping
                    if time_since_ping >= self.ping_interval:
                        await server.send(f"PING :{self.irc_server.servername}")
                        server.last_ping = current_time
                        logger.debug(f"Sent PING to {servername}")

                    # Check if server has timed out (no PONG received)
                    time_since_pong = current_time - server.last_pong
                    if time_since_pong >= self.ping_timeout:
                        logger.error(
                            f"Server {servername} ping timeout "
                            f"({time_since_pong:.0f}s since last PONG, limit {self.ping_timeout}s)"
                        )
                        # Trigger split handling
                        await self.handle_server_split(server)

        except asyncio.CancelledError:
            logger.info("Link monitoring task cancelled")
        except Exception as e:
            logger.error(f"Link monitoring error: {e}")

    async def handle_incoming_link(self, reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter):
        """Handle an incoming server connection"""
        peer = writer.get_extra_info('peername')
        logger.info(f"Incoming server connection from {peer}")

        try:
            # Wait for SERVER command
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if not line:
                    break

                line = line.decode('utf-8', errors='replace').strip()
                if not line:
                    continue

                parts = line.split(' ', 5)
                if parts[0] == 'SERVER' and len(parts) >= 5:
                    servername = parts[1]
                    password = parts[2]
                    hopcount = int(parts[3])
                    remote_role = parts[4]
                    description = parts[5].lstrip(':') if len(parts) > 5 else ''

                    # Authenticate
                    if not await self.authenticate_server(servername, password):
                        logger.warning(f"Failed auth from {servername} at {peer}")
                        await self.send_to_writer(writer, f"ERROR :Bad password")
                        writer.close()
                        return

                    # Validate role compatibility
                    valid, error_msg = self.validate_link_roles(self.server_role, remote_role)
                    if not valid:
                        logger.warning(f"Role validation failed for {servername}: {error_msg}")
                        await self.send_to_writer(writer, f"ERROR :Link rejected - {error_msg}")
                        writer.close()
                        return

                    logger.info(f"Role validation passed: {self.server_role} <-> {remote_role}")

                    # Send our SERVER line with role
                    network_name = CONFIG.get('server', 'network', default='IRCX Network')
                    await self.send_to_writer(
                        writer,
                        f"SERVER {self.irc_server.servername} {password} 0 {self.server_role} :{network_name}"
                    )

                    # Receive VERSION from remote
                    line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                    line = line.decode('utf-8', errors='replace').strip()
                    if not await self._validate_version(line, servername, writer):
                        return

                    # Send our VERSION
                    await self.send_to_writer(
                        writer,
                        f"VERSION pyIRCX/{PYIRCX_VERSION} PROTO/{LINKING_PROTOCOL_VERSION}"
                    )

                    # Receive TIMESYNC from remote
                    line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                    line = line.decode('utf-8', errors='replace').strip()
                    time_delta = await self._validate_time_sync(line, servername, writer)
                    if time_delta is None:
                        return  # Failed validation

                    # Send our TIMESYNC
                    await self.send_to_writer(writer, f"TIMESYNC {int(time.time())}")

                    # Create linked server with time delta
                    server = LinkedServer(servername, hopcount, description, writer, remote_role)
                    server.time_delta = time_delta
                    self.servers[servername] = server

                    # Burst our state
                    await self.burst_to_server(server)

                    # Start reading server messages
                    asyncio.create_task(self.read_server_messages(server, reader))

                    logger.info(f"Server {servername} linked successfully")
                    await self.broadcast_to_local(f":{self.irc_server.servername} NOTICE * :Server {servername} linked", exclude_modes='a')
                    break

        except asyncio.TimeoutError:
            logger.warning(f"Server handshake timeout from {peer}")
            writer.close()
        except Exception as e:
            logger.error(f"Server handshake error: {e}")
            writer.close()

    async def connect_to_server(self, link_cfg: dict):
        """Connect to a remote server"""
        servername = link_cfg['name']
        host = link_cfg['host']
        port = link_cfg['port']
        password = link_cfg['password']

        try:
            logger.info(f"Connecting to {servername} at {host}:{port}")
            reader, writer = await asyncio.open_connection(host, port)

            # Send SERVER command with role
            network_name = CONFIG.get('server', 'network', default='IRCX Network')
            await self.send_to_writer(
                writer,
                f"SERVER {self.irc_server.servername} {password} 0 {self.server_role} :{network_name}"
            )

            # Wait for SERVER response
            line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            line = line.decode('utf-8', errors='replace').strip()
            parts = line.split(' ', 5)

            if parts[0] == 'SERVER' and len(parts) >= 5:
                remote_name = parts[1]
                # parts[2] is password (we already know it)
                hopcount = int(parts[3])
                remote_role = parts[4]
                description = parts[5].lstrip(':') if len(parts) > 5 else ''

                # Validate role compatibility
                valid, error_msg = self.validate_link_roles(self.server_role, remote_role)
                if not valid:
                    logger.error(f"Role validation failed for {remote_name}: {error_msg}")
                    writer.close()
                    return

                logger.info(f"Role validation passed: {self.server_role} <-> {remote_role}")

                # Send VERSION and TIMESYNC
                await self.send_to_writer(
                    writer,
                    f"VERSION pyIRCX/{PYIRCX_VERSION} PROTO/{LINKING_PROTOCOL_VERSION}"
                )
                await self.send_to_writer(writer, f"TIMESYNC {int(time.time())}")

                # Receive VERSION
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                line = line.decode('utf-8', errors='replace').strip()
                if not await self._validate_version(line, remote_name, writer):
                    return

                # Receive TIMESYNC
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                line = line.decode('utf-8', errors='replace').strip()
                time_delta = await self._validate_time_sync(line, remote_name, writer)
                if time_delta is None:
                    return  # Failed validation, connection closed

                # Create linked server
                server = LinkedServer(remote_name, hopcount, description, writer, remote_role)
                server.time_delta = time_delta
                self.servers[remote_name] = server

                # Burst our state
                await self.burst_to_server(server)

                # Start reading messages
                asyncio.create_task(self.read_server_messages(server, reader))

                logger.info(f"Successfully linked to {remote_name}")
                await self.broadcast_to_local(f":{self.irc_server.servername} NOTICE * :Linked to server {remote_name}", exclude_modes='a')

                # Reset reconnect attempts on successful connection
                self.reconnect_attempts[servername] = 0

            elif parts[0] == 'ERROR':
                logger.error(f"Link to {servername} rejected: {line}")
                writer.close()
                # Schedule reconnect if autoconnect is enabled
                await self.schedule_reconnect(link_cfg)

        except Exception as e:
            logger.error(f"Failed to connect to {servername}: {e}")
            # Schedule reconnect if autoconnect is enabled
            await self.schedule_reconnect(link_cfg)

    async def schedule_reconnect(self, link_cfg: dict):
        """Schedule a reconnect attempt with exponential backoff"""
        servername = link_cfg['name']

        # Only reconnect if autoconnect is enabled
        if not link_cfg.get('autoconnect', False):
            logger.debug(f"Not scheduling reconnect for {servername} (autoconnect disabled)")
            return

        # Cancel existing reconnect task if any
        if servername in self.reconnect_tasks:
            self.reconnect_tasks[servername].cancel()

        # Get current retry count
        retry_count = self.reconnect_attempts.get(servername, 0)

        # Calculate backoff delay: 5s, 10s, 20s, 40s, 60s (max)
        delay = min(5 * (2 ** retry_count), self.max_reconnect_delay)

        logger.info(f"Scheduling reconnect to {servername} in {delay}s (attempt #{retry_count + 1})")

        # Increment retry count
        self.reconnect_attempts[servername] = retry_count + 1

        # Schedule reconnect task
        self.reconnect_tasks[servername] = asyncio.create_task(
            self._delayed_reconnect(link_cfg, delay)
        )

    async def _delayed_reconnect(self, link_cfg: dict, delay: float):
        """Delayed reconnect helper"""
        servername = link_cfg['name']
        try:
            await asyncio.sleep(delay)
            logger.info(f"Attempting reconnect to {servername}")
            await self.connect_to_server(link_cfg)
        except asyncio.CancelledError:
            logger.debug(f"Reconnect to {servername} cancelled")
        except Exception as e:
            logger.error(f"Reconnect attempt to {servername} failed: {e}")
        finally:
            # Clean up task reference
            self.reconnect_tasks.pop(servername, None)

    async def burst_to_server(self, server: LinkedServer):
        """Send full state burst to a newly linked server"""
        # Check if we're a services hub - if so, burst services to leaf servers
        is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)
        services_mode = CONFIG.get('services', 'mode', default='local')

        # Burst services if we're a hub and in centralized mode
        if is_services_hub and services_mode == 'centralized':
            # Burst staff accounts first (network-wide admin)
            try:
                import aiosqlite
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT username, level, password_hash FROM users WHERE level IN ('ADMIN', 'SYSOP', 'GUIDE')") as cursor:
                        staff_count = 0
                        async for row in cursor:
                            username, level, password_hash = row
                            # STAFFSYNC <username> <level> <password_hash>
                            await server.send(f"STAFFSYNC {username} {level} {password_hash}")
                            staff_count += 1
                        await server.send("STAFFSYNC_END")
                        logger.info(f"Burst {staff_count} staff accounts to {server.name}")
            except Exception as e:
                logger.error(f"Error bursting staff accounts to {server.name}: {e}")

            # Burst service bots
            for nickname, user in self.irc_server.users.items():
                if user.is_virtual and user.has_mode('s'):
                    # Service user - burst with special SVCNICK command
                    modes = user.get_mode_str()
                    await server.send(
                        f"SVCNICK {nickname} 1 {int(user.signon_time)} {user.username} "
                        f"{user.host} {self.irc_server.servername} +{modes} :{user.realname}"
                    )
                    logger.info(f"Bursting service {nickname} to {server.name}")

        # Burst all regular users
        for nickname, user in self.irc_server.users.items():
            if not user.is_virtual and not hasattr(user, 'from_server'):
                # NICK <nick> <hop> <ts> <user> <host> <server> <modes> :<real>
                modes = user.get_mode_str()
                await server.send(
                    f"NICK {nickname} 1 {int(user.signon_time)} {user.username} "
                    f"{user.host} {self.irc_server.servername} +{modes} :{user.realname}"
                )

        # Burst all channels
        for chan_name, channel in self.irc_server.channels.items():
            if chan_name == '#System':
                continue

            # Build nicklist with prefixes
            nicklist = []
            for nick, member in channel.members.items():
                if member.is_virtual or hasattr(member, 'from_server'):
                    continue
                prefix = ''
                if nick in channel.owners:
                    prefix = '@'
                elif nick in channel.hosts:
                    prefix = '+'
                nicklist.append(prefix + nick)

            if nicklist:
                # SJOIN <ts> <channel> <modes> :<nicklist>
                modes = ''.join(k for k, v in channel.modes.items() if v)
                await server.send(
                    f"SJOIN {int(channel.created_at)} {chan_name} +{modes} :{' '.join(nicklist)}"
                )

                # Send topic if exists
                if channel.topic:
                    await server.send(
                        f"TOPIC {chan_name} {self.irc_server.servername} {int(time.time())} :{channel.topic}"
                    )

        # Send End of Burst marker
        await server.send("EOB")
        logger.info(f"Sent EOB (End of Burst) to {server.name}")

    async def read_server_messages(self, server: LinkedServer, reader: asyncio.StreamReader):
        """Read and process messages from a linked server"""
        try:
            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break

                line = line.decode('utf-8', errors='replace').strip()
                if not line:
                    continue

                await self.process_server_message(server, line)

        except Exception as e:
            logger.error(f"Error reading from {server.name}: {e}")
        finally:
            # Server disconnected - handle split
            await self.handle_server_split(server)

    async def process_server_message(self, server: LinkedServer, line: str):
        """Process a message from a linked server"""
        parts = line.split(' ')
        if not parts:
            return

        cmd = parts[0].upper()

        # Handle server commands
        if cmd == 'STAFFAUTH':
            # Staff authentication request from branch
            await self.handle_staff_auth_request(server, parts)
        elif cmd == 'STAFFOK':
            # Staff authentication success response from trunk
            await self.handle_staff_auth_response(server, parts, success=True)
        elif cmd == 'STAFFFAIL':
            # Staff authentication failure response from trunk
            await self.handle_staff_auth_response(server, parts, success=False)
        elif cmd == 'STAFFSYNC':
            # Staff account sync from trunk during burst
            await self.handle_staff_sync(server, parts)
        elif cmd == 'STAFFSYNC_END':
            # End of staff sync burst
            logger.info(f"Staff sync completed from {server.name}")
        elif cmd == 'STAFFCMD':
            # Staff command proxy from branch to trunk
            await self.handle_staff_command_proxy(server, parts)
        elif cmd == 'STAFFUPDATE':
            # Staff account update broadcast from trunk
            await self.handle_staff_update(server, parts)
        elif cmd == 'STAFFREPLY':
            # Staff command reply from trunk to user on branch
            await self.handle_staff_reply(server, parts)
        elif cmd == 'REGCMD':
            # Registration command proxy from branch to trunk
            await self.handle_registration_command_proxy(server, parts)
        elif cmd == 'REGUPDATE':
            # Registration update broadcast from trunk
            await self.handle_registration_update(server, parts)
        elif cmd == 'REGREPLY':
            # Registration command reply from trunk to user on branch
            await self.handle_registration_reply(server, parts)
        elif cmd == 'MEMOCMD':
            # Memo command proxy from branch to trunk
            await self.handle_memo_command_proxy(server, parts)
        elif cmd == 'MEMOREPLY':
            # Memo command reply from trunk to user on branch
            await self.handle_memo_reply(server, parts)
        elif cmd == 'SVCNICK':
            # Service nickname from trunk
            await self.handle_service_nick(server, parts)
        elif cmd == 'NICK':
            await self.handle_remote_nick(server, parts)
        elif cmd == 'SJOIN':
            await self.handle_remote_sjoin(server, parts)
        elif cmd == 'TOPIC':
            await self.handle_remote_topic(server, parts)
        elif cmd == 'PING':
            # Respond to PING
            if len(parts) >= 2:
                await server.send(f"PONG {self.irc_server.servername} {parts[1]}")
        elif cmd == 'PONG':
            server.last_pong = time.time()
        elif cmd == 'EOB':
            # End of Burst received
            server.burst_complete = True
            logger.info(f"Received EOB from {server.name} - burst complete")
        elif cmd == 'SQUIT':
            # Server quit
            if len(parts) >= 2:
                await self.squit_server(parts[1].lstrip(':'), "Remote SQUIT")
        elif line.startswith(':'):
            # Prefixed message from remote user/server
            await self.handle_prefixed_message(server, line)

    async def handle_staff_auth_request(self, server: LinkedServer, parts: list):
        """Handle STAFFAUTH request from branch server (trunk only)"""
        if len(parts) < 4:
            return

        # STAFFAUTH <auth_id> <username> <password>
        auth_id = parts[1]
        username = parts[2]
        password = parts[3]

        # Authenticate against local database
        authenticated = False
        level = "USER"
        email = None
        realname = None
        force_realname = False

        try:
            from pyircx import check_password_async
            row = await self.irc_server.db_pool.execute_one(
                "SELECT password_hash, level, email, realname, force_realname FROM users WHERE username=?",
                (username,)
            )
            if row:
                # Check if this is SASL authentication (already verified by branch)
                if password == '*SASL*':
                    # SASL has already authenticated - just look up staff level
                    authenticated = True
                    level = row[1]
                    email = row[2]
                    realname = row[3]
                    force_realname = bool(row[4])
                    logger.info(f"Trunk: SASL staff auth SUCCESS for {username} ({level})")
                # Verify password for PASS authentication
                elif await check_password_async(password, row[0]):
                    authenticated = True
                    level = row[1]
                    email = row[2]
                    realname = row[3]
                    force_realname = bool(row[4])
                    logger.info(f"Trunk: Staff auth SUCCESS for {username} ({level})")
                else:
                    logger.info(f"Trunk: Staff auth FAILED for {username} (bad password)")
            else:
                logger.info(f"Trunk: Staff auth FAILED for {username} (not found)")
        except Exception as e:
            logger.error(f"Trunk: Staff auth error for {username}: {e}")

        # Send response back to branch
        if authenticated:
            # STAFFOK <auth_id> <level> <email> <realname> <force_realname>
            email_str = email if email else ""
            realname_str = realname if realname else ""
            await server.send(f"STAFFOK {auth_id} {level} {email_str} {realname_str} {int(force_realname)}")
        else:
            # STAFFFAIL <auth_id>
            await server.send(f"STAFFFAIL {auth_id}")

    async def handle_staff_auth_response(self, server: LinkedServer, parts: list, success: bool):
        """Handle STAFFOK/STAFFFAIL response from trunk (branch only)"""
        if not hasattr(self, '_pending_staff_auth'):
            return

        if len(parts) < 2:
            return

        auth_id = parts[1]

        if auth_id not in self._pending_staff_auth:
            logger.warning(f"Received staff auth response for unknown ID: {auth_id}")
            return

        pending = self._pending_staff_auth[auth_id]
        future = pending['future']

        if success:
            # STAFFOK <auth_id> <level> <email> <realname> <force_realname>
            if len(parts) < 3:
                future.set_result(None)
                del self._pending_staff_auth[auth_id]
                return

            level = parts[2]
            email = parts[3] if len(parts) > 3 and parts[3] else None
            realname = parts[4] if len(parts) > 4 and parts[4] else None
            force_realname = bool(int(parts[5])) if len(parts) > 5 else False

            result = {
                'authenticated': True,
                'level': level,
                'email': email,
                'realname': realname,
                'force_realname': force_realname
            }
            future.set_result(result)
            logger.info(f"Branch: Staff auth SUCCESS via trunk for {pending['username']} ({level})")
        else:
            # STAFFFAIL
            result = {
                'authenticated': False,
                'level': 'USER',
                'email': None,
                'realname': None,
                'force_realname': False
            }
            future.set_result(result)
            logger.info(f"Branch: Staff auth FAILED via trunk for {pending['username']}")

        del self._pending_staff_auth[auth_id]

    async def handle_staff_sync(self, server: LinkedServer, parts: list):
        """Handle STAFFSYNC from trunk during burst (branch only)"""
        if len(parts) < 4:
            logger.warning(f"Invalid STAFFSYNC from {server.name}: {parts}")
            return

        # STAFFSYNC <username> <level> <password_hash>
        username = parts[1]
        level = parts[2]
        password_hash = parts[3]

        try:
            import aiosqlite
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if staff account exists
                async with db.execute("SELECT username FROM users WHERE username=?", (username,)) as cursor:
                    existing = await cursor.fetchone()

                if existing:
                    # Update existing staff account
                    await db.execute(
                        "UPDATE users SET level=?, password_hash=? WHERE username=?",
                        (level, password_hash, username)
                    )
                else:
                    # Insert new staff account
                    await db.execute(
                        "INSERT INTO users (username, level, password_hash) VALUES (?, ?, ?)",
                        (username, level, password_hash)
                    )

                await db.commit()
                logger.info(f"Staff sync: {username} ({level}) from {server.name}")

        except Exception as e:
            logger.error(f"Error syncing staff account {username}: {e}")

    async def handle_staff_command_proxy(self, server: LinkedServer, parts: list):
        """Handle STAFFCMD proxy from branch (trunk only)"""
        if len(parts) < 3:
            logger.warning(f"Invalid STAFFCMD from {server.name}: {parts}")
            return

        # STAFFCMD <nickname> <subcmd> [args...]
        nickname = parts[1]
        subcmd = parts[2].upper()

        # Find the user on trunk (they're connected to branch, but we need to process command)
        user = self.irc_server.users_by_nick.get(nickname)
        if not user:
            logger.warning(f"STAFFCMD for unknown user {nickname} from {server.name}")
            await server.send(f"STAFFREPLY {nickname} :Error: User not found on trunk")
            return

        try:
            if subcmd == 'PASSWORD':
                # STAFFCMD <nickname> PASSWORD <old_pass> <new_pass>
                if len(parts) < 5:
                    await server.send(f"STAFFREPLY {nickname} :Error: Invalid PASSWORD command syntax")
                    return

                old_pass = parts[3]
                new_pass = parts[4]

                # Validate old password and update
                from pyircx import check_password_async, hash_password_async
                import aiosqlite

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT password_hash FROM users WHERE username=?", (user.username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await server.send(f"STAFFREPLY {nickname} :Error: Staff account not found")
                            return

                        if not await check_password_async(old_pass, row[0]):
                            await server.send(f"STAFFREPLY {nickname} :Error: Incorrect current password")
                            return

                        # Hash new password
                        new_hash = await hash_password_async(new_pass)

                        # Update password
                        await db.execute("UPDATE users SET password_hash=? WHERE username=?", (new_hash, user.username))
                        await db.commit()

                        # Broadcast update to all servers
                        await self.broadcast_to_servers(f"STAFFUPDATE {user.username} PASSWORD_HASH {new_hash}")

                        # Send success reply
                        await server.send(f"STAFFREPLY {nickname} :Password changed successfully")
                        logger.info(f"Staff password changed for {user.username} via {server.name}")

            elif subcmd == 'ADD':
                # STAFFCMD <nickname> ADD <new_username> <password> <level>
                if len(parts) < 6:
                    await server.send(f"STAFFREPLY {nickname} :Error: Invalid ADD command syntax")
                    return

                # Check if user has permission (ADMIN only)
                if user.staff_level != 'ADMIN':
                    await server.send(f"STAFFREPLY {nickname} :Error: Permission denied (ADMIN only)")
                    return

                new_username = parts[3]
                password = parts[4]
                level = parts[5].upper()

                if level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                    await server.send(f"STAFFREPLY {nickname} :Error: Invalid staff level (must be ADMIN, SYSOP, or GUIDE)")
                    return

                from pyircx import hash_password_async
                import aiosqlite

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if username exists
                    async with db.execute("SELECT username FROM users WHERE username=?", (new_username,)) as cursor:
                        if await cursor.fetchone():
                            await server.send(f"STAFFREPLY {nickname} :Error: Username {new_username} already exists")
                            return

                    # Create staff account
                    password_hash = await hash_password_async(password)
                    await db.execute("INSERT INTO users (username, level, password_hash) VALUES (?, ?, ?)",
                                   (new_username, level, password_hash))
                    await db.commit()

                    # Broadcast to all servers
                    await self.broadcast_to_servers(f"STAFFUPDATE {new_username} ADDED {level} {password_hash}")

                    # Send success reply
                    await server.send(f"STAFFREPLY {nickname} :Staff account {new_username} created with level {level}")
                    logger.info(f"Staff account {new_username} ({level}) added by {user.username} via {server.name}")

            elif subcmd == 'REMOVE':
                # STAFFCMD <nickname> REMOVE <username>
                if len(parts) < 4:
                    await server.send(f"STAFFREPLY {nickname} :Error: Invalid REMOVE command syntax")
                    return

                # Check if user has permission (ADMIN only)
                if user.staff_level != 'ADMIN':
                    await server.send(f"STAFFREPLY {nickname} :Error: Permission denied (ADMIN only)")
                    return

                target_username = parts[3]

                import aiosqlite
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if username exists
                    async with db.execute("SELECT username FROM users WHERE username=?", (target_username,)) as cursor:
                        if not await cursor.fetchone():
                            await server.send(f"STAFFREPLY {nickname} :Error: Staff account {target_username} not found")
                            return

                    # Prevent self-removal
                    if target_username == user.username:
                        await server.send(f"STAFFREPLY {nickname} :Error: Cannot remove your own staff account")
                        return

                    # Remove staff account
                    await db.execute("DELETE FROM users WHERE username=?", (target_username,))
                    await db.commit()

                    # Broadcast to all servers
                    await self.broadcast_to_servers(f"STAFFUPDATE {target_username} REMOVED")

                    # Send success reply
                    await server.send(f"STAFFREPLY {nickname} :Staff account {target_username} removed")
                    logger.info(f"Staff account {target_username} removed by {user.username} via {server.name}")

            elif subcmd == 'LEVEL':
                # STAFFCMD <nickname> LEVEL <username> <new_level>
                if len(parts) < 5:
                    await server.send(f"STAFFREPLY {nickname} :Error: Invalid LEVEL command syntax")
                    return

                # Check if user has permission (ADMIN only)
                if user.staff_level != 'ADMIN':
                    await server.send(f"STAFFREPLY {nickname} :Error: Permission denied (ADMIN only)")
                    return

                target_username = parts[3]
                new_level = parts[4].upper()

                if new_level not in ['ADMIN', 'SYSOP', 'GUIDE', 'USER']:
                    await server.send(f"STAFFREPLY {nickname} :Error: Invalid level (must be ADMIN, SYSOP, GUIDE, or USER)")
                    return

                import aiosqlite
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if username exists
                    async with db.execute("SELECT username FROM users WHERE username=?", (target_username,)) as cursor:
                        if not await cursor.fetchone():
                            await server.send(f"STAFFREPLY {nickname} :Error: Staff account {target_username} not found")
                            return

                    # Update level
                    await db.execute("UPDATE users SET level=? WHERE username=?", (new_level, target_username))
                    await db.commit()

                    # Broadcast to all servers
                    await self.broadcast_to_servers(f"STAFFUPDATE {target_username} LEVEL {new_level}")

                    # Send success reply
                    await server.send(f"STAFFREPLY {nickname} :Staff level for {target_username} changed to {new_level}")
                    logger.info(f"Staff level for {target_username} changed to {new_level} by {user.username} via {server.name}")

            else:
                await server.send(f"STAFFREPLY {nickname} :Error: Unknown staff command {subcmd}")

        except Exception as e:
            logger.error(f"Error processing STAFFCMD {subcmd} from {server.name}: {e}")
            await server.send(f"STAFFREPLY {nickname} :Error: Command failed - {e}")

    async def handle_staff_update(self, server: LinkedServer, parts: list):
        """Handle STAFFUPDATE broadcast from trunk (branch only)"""
        if len(parts) < 3:
            logger.warning(f"Invalid STAFFUPDATE from {server.name}: {parts}")
            return

        # STAFFUPDATE <username> <field> [value...]
        username = parts[1]
        field = parts[2].upper()

        try:
            import aiosqlite
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                if field == 'PASSWORD_HASH':
                    if len(parts) < 4:
                        return
                    password_hash = parts[3]
                    await db.execute("UPDATE users SET password_hash=? WHERE username=?", (password_hash, username))
                    await db.commit()
                    logger.info(f"Staff update: password changed for {username}")

                elif field == 'LEVEL':
                    if len(parts) < 4:
                        return
                    level = parts[3]
                    await db.execute("UPDATE users SET level=? WHERE username=?", (level, username))
                    await db.commit()
                    logger.info(f"Staff update: level changed for {username} to {level}")

                elif field == 'ADDED':
                    if len(parts) < 5:
                        return
                    level = parts[3]
                    password_hash = parts[4]
                    # Check if exists
                    async with db.execute("SELECT username FROM users WHERE username=?", (username,)) as cursor:
                        if await cursor.fetchone():
                            # Update existing
                            await db.execute("UPDATE users SET level=?, password_hash=? WHERE username=?",
                                           (level, password_hash, username))
                        else:
                            # Insert new
                            await db.execute("INSERT INTO users (username, level, password_hash) VALUES (?, ?, ?)",
                                           (username, level, password_hash))
                    await db.commit()
                    logger.info(f"Staff update: {username} added with level {level}")

                elif field == 'REMOVED':
                    await db.execute("DELETE FROM users WHERE username=?", (username,))
                    await db.commit()
                    logger.info(f"Staff update: {username} removed")

        except Exception as e:
            logger.error(f"Error processing STAFFUPDATE for {username}: {e}")

    async def handle_staff_reply(self, server: LinkedServer, parts: list):
        """Handle STAFFREPLY from trunk to user on branch (branch only)"""
        if len(parts) < 3:
            return

        # STAFFREPLY <nickname> :<message>
        nickname = parts[1]
        message = ' '.join(parts[2:]).lstrip(':')

        # Find user on this branch
        user = self.irc_server.users_by_nick.get(nickname)
        if user:
            await user.send(f":{self.irc_server.servername} NOTICE {nickname} :{message}")
        else:
            logger.warning(f"STAFFREPLY for unknown user {nickname}")

    async def handle_registration_command_proxy(self, server: LinkedServer, parts: list):
        """Handle REGCMD proxy from branch (trunk only)"""
        if len(parts) < 3:
            logger.warning(f"Invalid REGCMD from {server.name}: {parts}")
            return

        # REGCMD <nickname> <subcmd> [args...]
        nickname = parts[1]
        subcmd = parts[2].upper()

        # Find the user on trunk (they're connected to branch)
        user = self.irc_server.users_by_nick.get(nickname)
        if not user:
            logger.warning(f"REGCMD for unknown user {nickname} from {server.name}")
            await server.send(f"REGREPLY {nickname} :Error: User not found on trunk")
            return

        try:
            import aiosqlite
            import uuid
            import time
            from pyircx import check_password_async, hash_password_async

            if subcmd == 'REGISTER_NICK':
                # REGCMD <nickname> REGISTER_NICK <account> <password> <email>
                if len(parts) < 6:
                    await server.send(f"REGREPLY {nickname} :Error: Invalid REGISTER syntax")
                    return

                account = parts[3]
                password = parts[4]
                email_param = parts[5]
                email = None if email_param == '*' else email_param

                # Check if account is already registered
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?", (account,)) as cursor:
                        if await cursor.fetchone():
                            await server.send(f"REGREPLY {nickname} :Error: Nickname {account} is already registered")
                            return

                    # Register nickname
                    nick_uuid = str(uuid.uuid4())
                    password_hash = await hash_password_async(password)
                    now = int(time.time())

                    await db.execute("""INSERT INTO registered_nicks
                        (uuid, nickname, password_hash, email, registered_at, last_seen, registered_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (nick_uuid, account, password_hash, email, now, now, user.prefix()))
                    await db.commit()

                    # Broadcast update to all servers (user gets +r mode)
                    await self.broadcast_to_servers(f"REGUPDATE REGISTERED {nickname}")

                    # Send success reply
                    await server.send(f"REGREPLY {nickname} :Nickname {account} has been registered")
                    logger.info(f"Registration: {account} registered via {server.name}")

            elif subcmd == 'UNREGISTER_NICK':
                # REGCMD <nickname> UNREGISTER_NICK <account>
                if len(parts) < 4:
                    await server.send(f"REGREPLY {nickname} :Error: Invalid UNREGISTER syntax")
                    return

                account = parts[3]

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    await db.execute("DELETE FROM registered_nicks WHERE nickname = ?", (account,))
                    await db.commit()

                    # Broadcast update to all servers (user loses +r mode)
                    await self.broadcast_to_servers(f"REGUPDATE UNREGISTERED {nickname}")

                    # Send success reply
                    await server.send(f"REGREPLY {nickname} :Nickname {account} has been unregistered")
                    logger.info(f"Unregistration: {account} unregistered via {server.name}")

            elif subcmd == 'IDENTIFY':
                # REGCMD <nickname> IDENTIFY <account> <password>
                if len(parts) < 5:
                    await server.send(f"REGREPLY {nickname} :Error: Invalid IDENTIFY syntax")
                    return

                account = parts[3]
                password = parts[4]

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT uuid, password_hash, mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                         (account,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await server.send(f"REGREPLY {nickname} :Error: Nickname {account} is not registered")
                            return

                        nick_uuid, password_hash, mfa_enabled, mfa_secret = row

                        if await check_password_async(password, password_hash):
                            if mfa_enabled and mfa_secret:
                                # MFA required - can't complete via proxy yet
                                await server.send(f"REGREPLY {nickname} :Error: MFA-protected accounts must identify on trunk server")
                                return

                            # Update last_seen
                            await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE uuid = ?",
                                           (int(time.time()), nick_uuid))
                            await db.commit()

                            # Broadcast update to all servers (user gets +r mode)
                            await self.broadcast_to_servers(f"REGUPDATE IDENTIFIED {nickname}")

                            # Send success reply
                            await server.send(f"REGREPLY {nickname} :You are now identified as {account}")
                            logger.info(f"Identification: {account} identified via {server.name}")
                        else:
                            await server.send(f"REGREPLY {nickname} :Error: Incorrect password")

            elif subcmd == 'REGISTER_CHANNEL':
                # REGCMD <nickname> REGISTER_CHANNEL <channel> <password>
                if len(parts) < 5:
                    await server.send(f"REGREPLY {nickname} :Error: Invalid channel REGISTER syntax")
                    return

                chan_name = parts[3]
                password_param = parts[4]
                password = None if password_param == '*' else password_param

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if channel is already registered
                    async with db.execute("SELECT uuid FROM registered_channels WHERE channel_name = ?",
                                         (chan_name,)) as cursor:
                        if await cursor.fetchone():
                            await server.send(f"REGREPLY {nickname} :Error: Channel {chan_name} is already registered")
                            return

                    # Get user's registered_nicks uuid
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (nickname,)) as cursor:
                        nick_row = await cursor.fetchone()
                        if not nick_row:
                            await server.send(f"REGREPLY {nickname} :Error: You must be identified to register a channel")
                            return
                        owner_uuid = nick_row[0]

                    # Register channel
                    chan_uuid = str(uuid.uuid4())
                    password_hash = await hash_password_async(password) if password else None
                    now = int(time.time())

                    await db.execute("""INSERT INTO registered_channels
                        (uuid, channel_name, owner_uuid, password_hash, registered_at, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                        (chan_uuid, chan_name, owner_uuid, password_hash, now, now))
                    await db.commit()

                    # Send success reply
                    await server.send(f"REGREPLY {nickname} :Channel {chan_name} has been registered")
                    logger.info(f"Channel registration: {chan_name} registered by {nickname} via {server.name}")

            elif subcmd == 'UNREGISTER_CHANNEL':
                # REGCMD <nickname> UNREGISTER_CHANNEL <channel>
                if len(parts) < 4:
                    await server.send(f"REGREPLY {nickname} :Error: Invalid channel UNREGISTER syntax")
                    return

                chan_name = parts[3]

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if channel is registered
                    async with db.execute("SELECT owner_uuid FROM registered_channels WHERE channel_name = ?",
                                         (chan_name,)) as cursor:
                        chan_row = await cursor.fetchone()
                        if not chan_row:
                            await server.send(f"REGREPLY {nickname} :Error: Channel {chan_name} is not registered")
                            return

                    # Verify ownership (admins can bypass)
                    if not user.has_mode('a'):
                        async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                             (nickname,)) as cursor:
                            nick_row = await cursor.fetchone()
                            if not nick_row or nick_row[0] != chan_row[0]:
                                await server.send(f"REGREPLY {nickname} :Error: You don't own channel {chan_name}")
                                return

                    # Unregister channel
                    await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (chan_name,))
                    await db.commit()

                    # Send success reply
                    await server.send(f"REGREPLY {nickname} :Channel {chan_name} has been unregistered")
                    logger.info(f"Channel unregistration: {chan_name} unregistered by {nickname} via {server.name}")

            elif subcmd == 'CHGPASS':
                # REGCMD <nickname> CHGPASS <old_password> <new_password>
                if len(parts) < 5:
                    await server.send(f"REGREPLY {nickname} :Error: Invalid CHGPASS syntax")
                    return

                old_pass = parts[3]
                new_pass = parts[4]

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check registered nickname
                    async with db.execute("SELECT password_hash FROM registered_nicks WHERE nickname = ?",
                                         (nickname,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await server.send(f"REGREPLY {nickname} :Error: Nickname not registered")
                            return

                        # Verify old password
                        if not await check_password_async(old_pass, row[0]):
                            await server.send(f"REGREPLY {nickname} :Error: Incorrect password")
                            return

                        # Update password
                        new_hash = await hash_password_async(new_pass)
                        await db.execute("UPDATE registered_nicks SET password_hash = ? WHERE nickname = ?",
                                        (new_hash, nickname))
                        await db.commit()

                        # Send success reply
                        await server.send(f"REGREPLY {nickname} :Password changed successfully")
                        logger.info(f"CHGPASS: {nickname} changed password via {server.name}")

            else:
                await server.send(f"REGREPLY {nickname} :Error: Unknown registration command {subcmd}")

        except Exception as e:
            logger.error(f"Error processing REGCMD {subcmd} from {server.name}: {e}")
            await server.send(f"REGREPLY {nickname} :Error: Command failed - {e}")

    async def handle_registration_update(self, server: LinkedServer, parts: list):
        """Handle REGUPDATE broadcast from trunk (branch only)"""
        if len(parts) < 3:
            logger.warning(f"Invalid REGUPDATE from {server.name}: {parts}")
            return

        # REGUPDATE <action> <nickname>
        action = parts[1].upper()
        nickname = parts[2]

        # Find user on this branch
        user = self.irc_server.users_by_nick.get(nickname)
        if not user:
            logger.debug(f"REGUPDATE for user {nickname} not on this branch")
            return

        try:
            if action == 'REGISTERED' or action == 'IDENTIFIED':
                # User registered or identified - set +r mode
                user.set_mode('r', True)
                await user.send(f":{nickname} MODE {nickname} :+r")
                logger.info(f"Registration update: {nickname} {action.lower()}")

            elif action == 'UNREGISTERED':
                # User unregistered - remove +r mode
                user.set_mode('r', False)
                await user.send(f":{nickname} MODE {nickname} :-r")
                logger.info(f"Registration update: {nickname} unregistered")

        except Exception as e:
            logger.error(f"Error processing REGUPDATE for {nickname}: {e}")

    async def handle_registration_reply(self, server: LinkedServer, parts: list):
        """Handle REGREPLY from trunk to user on branch (branch only)"""
        if len(parts) < 3:
            return

        # REGREPLY <nickname> :<message>
        nickname = parts[1]
        message = ' '.join(parts[2:]).lstrip(':')

        # Find user on this branch
        user = self.irc_server.users_by_nick.get(nickname)
        if user:
            await user.send(f":{self.irc_server.servername} NOTICE {nickname} :{message}")
        else:
            logger.warning(f"REGREPLY for unknown user {nickname}")

    async def handle_memo_command_proxy(self, server: LinkedServer, parts: list):
        """Handle MEMOCMD proxy from branch (trunk only)"""
        if len(parts) < 3:
            logger.warning(f"Invalid MEMOCMD from {server.name}: {parts}")
            return

        # MEMOCMD <nickname> <subcmd> [args...]
        nickname = parts[1]
        subcmd = parts[2].upper()

        # Find the user on trunk (they're connected to branch)
        user = self.irc_server.users_by_nick.get(nickname)
        if not user:
            logger.warning(f"MEMOCMD for unknown user {nickname} from {server.name}")
            await server.send(f"MEMOREPLY {nickname} :Error: User not found on trunk")
            return

        try:
            import aiosqlite
            import time

            if subcmd == 'SEND':
                # MEMOCMD <nickname> SEND <target> :<message>
                if len(parts) < 5:
                    await server.send(f"MEMOREPLY {nickname} :Error: Invalid MEMO SEND syntax")
                    return

                target_nick = parts[3]
                message = ' '.join(parts[4:]).lstrip(':')

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if target is registered
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (target_nick,)) as cursor:
                        if not await cursor.fetchone():
                            await server.send(f"MEMOREPLY {nickname} :Error: Nickname {target_nick} is not registered")
                            return

                    # Store memo
                    await db.execute("""
                        INSERT INTO memos (recipient, sender, message, sent_at, read)
                        VALUES (?, ?, ?, ?, 0)
                    """, (target_nick.lower(), nickname, message, int(time.time())))
                    await db.commit()

                    # Send success reply
                    await server.send(f"MEMOREPLY {nickname} :Memo sent to {target_nick}")
                    logger.info(f"Memo sent: {nickname} -> {target_nick} via {server.name}")

                    # If recipient is online and identified, notify them
                    target_user = self.irc_server.users_by_nick.get(target_nick)
                    if target_user and target_user.has_mode('r'):
                        # Find which server target_user is on
                        if hasattr(target_user, 'from_server') and target_user.from_server:
                            target_server = self.servers.get(target_user.from_server)
                            if target_server:
                                await target_server.send(f"MEMOREPLY {target_nick} :You have a new memo from {nickname}. Use MEMO READ to view.")
                        else:
                            # User on trunk
                            await target_user.send(f":{self.irc_server.servername} NOTICE {target_nick} :You have a new memo from {nickname}. Use MEMO READ to view.")

            elif subcmd == 'LIST':
                # MEMOCMD <nickname> LIST
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("""
                        SELECT id, sender, sent_at, read FROM memos
                        WHERE recipient = ? ORDER BY sent_at DESC LIMIT 20
                    """, (nickname.lower(),)) as cursor:
                        memos = await cursor.fetchall()

                    if not memos:
                        await server.send(f"MEMOREPLY {nickname} :You have no memos")
                    else:
                        await server.send(f"MEMOREPLY {nickname} :You have {len(memos)} memo(s):")
                        for mid, sender, sent_at, is_read in memos:
                            timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                            read_status = "[READ]" if is_read else "[NEW]"
                            await server.send(f"MEMOREPLY {nickname} :  #{mid} from {sender} {read_status} ({timestamp})")

            elif subcmd == 'READ':
                # MEMOCMD <nickname> READ [memo_id]
                memo_id = None
                if len(parts) > 3 and parts[3].isdigit():
                    memo_id = int(parts[3])

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    if memo_id:
                        async with db.execute("""
                            SELECT id, sender, message, sent_at FROM memos
                            WHERE recipient = ? AND id = ?
                        """, (nickname.lower(), memo_id)) as cursor:
                            row = await cursor.fetchone()
                        if not row:
                            await server.send(f"MEMOREPLY {nickname} :Memo #{memo_id} not found")
                            return
                        memos = [row]
                    else:
                        # Read all unread memos
                        async with db.execute("""
                            SELECT id, sender, message, sent_at FROM memos
                            WHERE recipient = ? AND read = 0 ORDER BY sent_at
                        """, (nickname.lower(),)) as cursor:
                            memos = await cursor.fetchall()

                    if not memos:
                        await server.send(f"MEMOREPLY {nickname} :No unread memos")
                        return

                    for mid, sender, message, sent_at in memos:
                        timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                        await server.send(f"MEMOREPLY {nickname} :Memo #{mid} from {sender} ({timestamp}):")
                        await server.send(f"MEMOREPLY {nickname} :{message}")

                    # Mark as read
                    ids = [m[0] for m in memos]
                    placeholders = ",".join("?" * len(ids))
                    await db.execute(f"UPDATE memos SET read = 1 WHERE id IN ({placeholders})", ids)
                    await db.commit()

            elif subcmd == 'DEL':
                # MEMOCMD <nickname> DEL <id|ALL>
                if len(parts) < 4:
                    await server.send(f"MEMOREPLY {nickname} :Error: Invalid MEMO DEL syntax")
                    return

                target = parts[3]

                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    if target.upper() == "ALL":
                        await db.execute("DELETE FROM memos WHERE recipient = ?", (nickname.lower(),))
                        await db.commit()
                        await server.send(f"MEMOREPLY {nickname} :All memos deleted")
                    elif target.isdigit():
                        cursor = await db.execute("DELETE FROM memos WHERE recipient = ? AND id = ?",
                                                 (nickname.lower(), int(target)))
                        await db.commit()
                        if cursor.rowcount > 0:
                            await server.send(f"MEMOREPLY {nickname} :Memo #{target} deleted")
                        else:
                            await server.send(f"MEMOREPLY {nickname} :Memo #{target} not found")
                    else:
                        await server.send(f"MEMOREPLY {nickname} :Error: Invalid memo ID")

            else:
                await server.send(f"MEMOREPLY {nickname} :Error: Unknown memo command {subcmd}")

        except Exception as e:
            logger.error(f"Error processing MEMOCMD {subcmd} from {server.name}: {e}")
            await server.send(f"MEMOREPLY {nickname} :Error: Command failed - {e}")

    async def handle_memo_reply(self, server: LinkedServer, parts: list):
        """Handle MEMOREPLY from trunk to user on branch (branch only)"""
        if len(parts) < 3:
            return

        # MEMOREPLY <nickname> :<message>
        nickname = parts[1]
        message = ' '.join(parts[2:]).lstrip(':')

        # Find user on this branch
        user = self.irc_server.users_by_nick.get(nickname)
        if user:
            await user.send(f":{self.irc_server.servername} NOTICE {nickname} :{message}")
        else:
            logger.warning(f"MEMOREPLY for unknown user {nickname}")

    async def handle_service_nick(self, server: LinkedServer, parts: list):
        """Handle SVCNICK (service user) from services hub"""
        if len(parts) < 9:
            return

        # SVCNICK <nick> <hop> <ts> <user> <host> <server> <modes> :<real>
        nickname = parts[1]
        timestamp = int(parts[3])
        username = parts[4]
        hostname = parts[5]
        origin_server = parts[6]
        modes = parts[7].lstrip('+')
        realname = ' '.join(parts[8:]).lstrip(':')

        # Create service user object (use cached import to avoid circular dependency)
        global _User
        if _User is None:
            import sys
            # pyircx might be loaded as '__main__' when run as a script
            if 'pyircx' in sys.modules:
                _User = sys.modules['pyircx'].User
            elif '__main__' in sys.modules and hasattr(sys.modules['__main__'], 'User'):
                _User = sys.modules['__main__'].User
            else:
                # Last resort - this will trigger module reload
                from pyircx import User as _User

        service = _User(None, None, is_virtual=True)
        service.nickname = nickname
        service.username = username
        service.host = hostname
        service.realname = realname
        service.signon_time = timestamp
        service.registered = True
        service.staff_level = "SERVICE"

        # Parse modes string
        for mode_char in modes.lstrip('+'):
            if mode_char in service.modes:
                service.modes[mode_char] = True

        service.from_server = origin_server
        service.is_remote = True
        service.is_service_proxy = True  # Mark as service proxy from trunk

        self.irc_server.users[nickname] = service
        server.add_user(nickname)

        logger.info(f"Added remote service {nickname} from trunk {origin_server}")

    async def handle_remote_nick(self, server: LinkedServer, parts: list):
        """Handle NICK introduction from remote server"""
        logger.info(f"handle_remote_nick called from {server.name} with {len(parts)} parts: {' '.join(parts[:5])}")
        if len(parts) < 9:
            logger.warning(f"handle_remote_nick: Not enough parts ({len(parts)}), need 9+")
            return

        # NICK <nick> <hop> <ts> <user> <host> <server> <modes> :<real>
        nickname = parts[1]
        logger.info(f"Processing NICK for {nickname} from {server.name}")
        timestamp = int(parts[3])
        username = parts[4]
        hostname = parts[5]
        origin_server = parts[6]
        modes = parts[7].lstrip('+')
        realname = ' '.join(parts[8:]).lstrip(':')

        # Create virtual user object using cached User class
        global _User
        if _User is None:
            import sys
            if 'pyircx' in sys.modules:
                _User = sys.modules['pyircx'].User
            elif '__main__' in sys.modules and hasattr(sys.modules['__main__'], 'User'):
                _User = sys.modules['__main__'].User
            else:
                from pyircx import User as _User

        user = _User(None, None, is_virtual=True)
        user.nickname = nickname
        user.username = username
        user.host = hostname
        user.realname = realname
        user.signon_time = timestamp
        user.registered = True
        # Parse modes string (e.g., "+aio" -> set a, i, o to True)
        for mode_char in modes.lstrip('+'):
            if mode_char in user.modes:
                user.modes[mode_char] = True
        user.from_server = origin_server
        user.is_remote = True
        user.server = self.irc_server  # Link to server for routing responses

        # Check for nick collision
        existing_user = self.irc_server.users.get(nickname)
        if existing_user:
            # Nick collision detected
            existing_ts = getattr(existing_user, 'signon_time', 0)
            incoming_ts = timestamp

            logger.warning(
                f"Nick collision: {nickname} "
                f"(existing: {existing_ts} from {getattr(existing_user, 'from_server', 'local')}, "
                f"incoming: {incoming_ts} from {origin_server})"
            )

            # Determine which user to keep based on timestamp
            # Lower timestamp (older signon) wins
            if incoming_ts < existing_ts:
                # Incoming user is older, kill the existing user
                logger.info(f"Collision resolution: Keeping incoming {nickname} (older timestamp)")
                # KILL existing user
                if not (hasattr(existing_user, 'is_remote') and existing_user.is_remote):
                    # Existing is local, send KILL to local user
                    try:
                        await existing_user.send(
                            f":{self.irc_server.servername} KILL {nickname} :Nick collision with {origin_server}"
                        )
                        await self.irc_server.quit_user(existing_user)
                    except Exception as e:
                        logger.error(f"Error killing local user in collision: {e}")
                else:
                    # Existing is remote, send KILL through the network
                    existing_server = getattr(existing_user, 'from_server', None)
                    kill_msg = f":{self.irc_server.servername} KILL {nickname} :Nick collision"
                    await self.broadcast_to_servers(kill_msg)
                    # Remove existing user locally
                    self.irc_server.users.pop(nickname, None)

                # Accept incoming user (fall through to add below)
            elif incoming_ts > existing_ts:
                # Existing user is older, kill the incoming user
                logger.info(f"Collision resolution: Keeping existing {nickname} (older timestamp)")
                # Send KILL for incoming user back through the link
                kill_msg = f":{self.irc_server.servername} KILL {nickname} :Nick collision"
                await server.send(kill_msg)
                # Don't add the incoming user
                return
            else:
                # Timestamps equal, use server name as tiebreaker (alphabetical)
                existing_server = getattr(existing_user, 'from_server', self.irc_server.servername)
                if origin_server < existing_server:
                    # Incoming server name is "smaller", kill existing
                    logger.info(f"Collision resolution: Tie broken by server name, keeping incoming {nickname}")
                    if not (hasattr(existing_user, 'is_remote') and existing_user.is_remote):
                        try:
                            await existing_user.send(
                                f":{self.irc_server.servername} KILL {nickname} :Nick collision"
                            )
                            await self.irc_server.quit_user(existing_user)
                        except Exception as e:
                            logger.error(f"Error killing local user in collision: {e}")
                    else:
                        kill_msg = f":{self.irc_server.servername} KILL {nickname} :Nick collision"
                        await self.broadcast_to_servers(kill_msg)
                        self.irc_server.users.pop(nickname, None)
                else:
                    # Existing server name is "smaller" or equal, kill incoming
                    logger.info(f"Collision resolution: Tie broken by server name, keeping existing {nickname}")
                    kill_msg = f":{self.irc_server.servername} KILL {nickname} :Nick collision"
                    await server.send(kill_msg)
                    return

        self.irc_server.users[nickname] = user
        server.add_user(nickname)

        logger.info(f"✓ Added remote user {nickname} from {origin_server} (total users: {len(self.irc_server.users)})")

        # Forward NICK to all other linked servers (except the one it came from)
        nick_msg = (
            f"NICK {nickname} 1 {timestamp} {username} "
            f"{hostname} {origin_server} +{modes} :{realname}"
        )
        await self.broadcast_to_servers(nick_msg, exclude_server=server.name)
        logger.debug(f"Forwarded NICK for {nickname} to other servers")

    async def handle_remote_sjoin(self, server: LinkedServer, parts: list):
        """Handle SJOIN (channel sync) from remote server"""
        if len(parts) < 5:
            return

        # SJOIN <ts> <channel> <modes> :<nicklist>
        timestamp = int(parts[1])
        chan_name = parts[2]
        modes = parts[3].lstrip('+')
        nicklist = ' '.join(parts[4:]).lstrip(':').split()

        # Get or create channel using cached class
        channel = self.irc_server.channels.get(chan_name)
        channel_existed = channel is not None

        if not channel:
            global _Channel
            if _Channel is None:
                import sys
                if 'pyircx' in sys.modules:
                    _Channel = sys.modules['pyircx'].Channel
                elif '__main__' in sys.modules and hasattr(sys.modules['__main__'], 'Channel'):
                    _Channel = sys.modules['__main__'].Channel
                else:
                    from pyircx import Channel as _Channel
            channel = _Channel(chan_name)
            channel.created_at = timestamp
            self.irc_server.channels[chan_name] = channel
            logger.info(f"Created new channel {chan_name} from SJOIN (ts={timestamp})")
        else:
            # Channel exists - compare timestamps for merge strategy
            local_ts = int(channel.created_at)
            remote_ts = timestamp

            logger.info(
                f"Channel merge for {chan_name}: local_ts={local_ts}, remote_ts={remote_ts}"
            )

            if remote_ts < local_ts:
                # Remote channel is older - accept remote state completely
                logger.info(f"Channel {chan_name}: Remote is older, accepting remote state")
                # Clear local modes and ops
                channel.modes = {}
                channel.owners.clear()
                channel.hosts.clear()
                channel.voices.clear()
                # Update timestamp
                channel.created_at = remote_ts
                # Modes will be set below

            elif remote_ts > local_ts:
                # Local channel is older - keep local state, only merge users
                logger.info(f"Channel {chan_name}: Local is older, keeping local state")
                # Don't set modes from remote (keep local modes)
                modes = ''  # Clear modes so we don't apply them below

            else:
                # Timestamps equal - merge ops/voices (union)
                logger.info(f"Channel {chan_name}: Equal timestamp, merging state")
                # Modes will be merged (union)
                # Ops/voices will be merged (union)
                # Keep processing normally

        # Set modes (if remote is older or timestamps equal)
        if modes:
            for mode in modes:
                if mode in channel.modes:
                    channel.modes[mode] = True

        # Add users to channel
        for nick_entry in nicklist:
            prefix = ''
            nickname = nick_entry
            if nick_entry.startswith('@'):
                prefix = '@'
                nickname = nick_entry[1:]
            elif nick_entry.startswith('+'):
                prefix = '+'
                nickname = nick_entry[1:]

            user = self.irc_server.users.get(nickname)
            if user:
                channel.members[nickname] = user
                user.channels.add(chan_name)

                # Only apply prefixes if:
                # - Remote is older (already cleared local ops), OR
                # - Timestamps are equal (merge), OR
                # - New channel (no conflict)
                remote_ts = timestamp
                local_ts = int(channel.created_at) if channel_existed else remote_ts

                if remote_ts <= local_ts:
                    if prefix == '@':
                        channel.owners.add(nickname)
                    elif prefix == '+':
                        channel.hosts.add(nickname)

    async def handle_remote_topic(self, server: LinkedServer, parts: list):
        """Handle TOPIC from remote server"""
        if len(parts) < 5:
            return

        chan_name = parts[1]
        setter = parts[2]
        timestamp = int(parts[3])
        topic = ' '.join(parts[4:]).lstrip(':')

        channel = self.irc_server.channels.get(chan_name)
        if channel:
            channel.topic = topic
            channel.topic_set_by = setter
            channel.topic_set_at = timestamp

    async def handle_prefixed_message(self, server: LinkedServer, line: str):
        """Handle prefixed messages (user actions) from remote servers"""
        # Format: :nickname COMMAND params
        parts = line.split(' ')
        source = parts[0].lstrip(':')
        if len(parts) < 2:
            return

        cmd = parts[1].upper()

        # Route common commands
        if cmd in ('PRIVMSG', 'NOTICE'):
            # Extract target and message
            if len(parts) >= 3:
                target = parts[2]
                message_text = ' '.join(parts[3:]).lstrip(':')

                # Check if target is a service and handle it
                target_lower = target.lower()
                service_handlers = {
                    'registrar': '_handle_registrar_msg',
                    'nickserv': '_handle_registrar_msg',
                    'chanserv': '_handle_registrar_msg',
                    'messenger': '_handle_messenger_msg',
                    'memoserv': '_handle_messenger_msg',
                    'newsflash': '_handle_newsflash_msg',
                }

                if target_lower in service_handlers and cmd == 'PRIVMSG':
                    # Target is a service - create virtual user for the remote sender
                    # Parse source (nickname!user@host)
                    if '!' in source:
                        nickname = source.split('!')[0]
                        userhost = source.split('!')[1]
                        username = userhost.split('@')[0].lstrip('~')
                        hostname = userhost.split('@')[1] if '@' in userhost else 'unknown'
                    else:
                        nickname = source
                        username = source
                        hostname = server.name

                    # Get or create remote user object
                    remote_user = self.irc_server.users.get(nickname)
                    if not remote_user:
                        # Create temporary virtual user for service interaction
                        global _User
                        if _User is None:
                            import sys
                            if '__main__' in sys.modules and hasattr(sys.modules['__main__'], 'User'):
                                _User = sys.modules['__main__'].User

                        if _User:
                            remote_user = _User(None, None, is_virtual=True)
                            remote_user.nickname = nickname
                            remote_user.username = username
                            remote_user.host = hostname
                            remote_user.from_server = server.name
                            remote_user.is_remote = True
                            remote_user.server = self.irc_server  # Link to server for routing responses
                            self.irc_server.users[nickname] = remote_user
                            server.add_user(nickname)
                            logger.debug(f"Created virtual remote user {nickname} from {server.name}")

                    if remote_user:
                        # Call the service handler directly
                        handler_name = service_handlers[target_lower]
                        handler = getattr(self.irc_server, handler_name, None)
                        if handler:
                            await handler(remote_user, message_text)
                            logger.debug(f"Routed PRIVMSG from {nickname} to {target}")
                        else:
                            logger.error(f"Service handler {handler_name} not found!")
                    else:
                        logger.error(f"Failed to create/find remote user {nickname}")
                else:
                    # Target is not a service - check if it's a local user or channel
                    # Parse source to get nickname
                    if '!' in source:
                        source_nick = source.split('!')[0]
                    else:
                        source_nick = source

                    # Check if target is a channel
                    if target.startswith('#') or target.startswith('&'):
                        # Message to channel - broadcast to local members
                        channel = self.irc_server.channels.get(target)
                        if channel:
                            # Broadcast to LOCAL channel members only (exclude remote users to avoid loops)
                            logger.info(f"Processing channel message from {server.name}: {source_nick} -> {target}")
                            logger.info(f"  Channel {target} has {len(channel.members)} total members")
                            for member in channel.members.values():
                                is_remote = hasattr(member, 'is_remote') and member.is_remote
                                logger.info(f"  Member {member.nickname}: is_remote={is_remote}")
                                if not is_remote:
                                    logger.info(f"    -> Sending to {member.nickname}")
                                    await member.send(line)
                            # Forward to other servers ONLY if we're trunk (hub forwards between branches)
                            if self.server_role == 'trunk':
                                logger.info(f"  Forwarding to other servers (exclude={server.name})")
                                await self.broadcast_to_servers(line, exclude_server=server.name)
                            else:
                                logger.info(f"  NOT forwarding (branch server)")
                    else:
                        # Message to user - check if user is local
                        target_user = self.irc_server.users.get(target)
                        if target_user and not (hasattr(target_user, 'is_remote') and target_user.is_remote):
                            # User is local, deliver message
                            await target_user.send(line)
                            logger.debug(f"Delivered private message from {source_nick} to {target}")
                        else:
                            # User not found locally - forward to other servers ONLY if we're trunk
                            if self.server_role == 'trunk':
                                await self.broadcast_to_servers(line, exclude_server=server.name)
                                logger.debug(f"Forwarded private message from {source_nick} to {target}")
                            else:
                                logger.debug(f"User {target} not found locally on branch server")
        elif cmd == 'JOIN':
            # User joined channel
            logger.info(f"Processing remote JOIN from {server.name}: {line[:100]}")
            if len(parts) >= 3:
                chan_name = parts[2].lstrip(':')
                # Extract nickname from source prefix (nick!user@host)
                if '!' in source:
                    nickname = source.split('!')[0]
                else:
                    nickname = source
                user = self.irc_server.users.get(nickname)
                logger.info(f"JOIN: user={nickname}, channel={chan_name}, user_found={user is not None}")

                # Get or create channel
                channel = self.irc_server.channels.get(chan_name)
                if not channel:
                    global _Channel
                    if _Channel is None:
                        import sys
                        if 'pyircx' in sys.modules:
                            _Channel = sys.modules['pyircx'].Channel
                        elif '__main__' in sys.modules and hasattr(sys.modules['__main__'], 'Channel'):
                            _Channel = sys.modules['__main__'].Channel
                        else:
                            from pyircx import Channel as _Channel
                    channel = _Channel(chan_name)
                    self.irc_server.channels[chan_name] = channel
                    logger.info(f"Created channel {chan_name} for remote JOIN")

                if user:
                    channel.members[nickname] = user
                    user.channels.add(chan_name)
                    logger.info(f"Added {nickname} to {chan_name}, broadcasting to local users")
                    await self.broadcast_to_local(line, exclude_server=server.name)
                    # Forward JOIN to other linked servers ONLY if we're trunk
                    if self.server_role == 'trunk':
                        await self.broadcast_to_servers(line, exclude_server=server.name)
                        logger.info(f"JOIN forwarded to other servers for {nickname} in {chan_name}")
                    logger.info(f"JOIN processing complete for {nickname} in {chan_name}")
        elif cmd == 'PART':
            # User left channel
            if len(parts) >= 3:
                chan_name = parts[2]
                # Extract nickname from source prefix (nick!user@host)
                if '!' in source:
                    nickname = source.split('!')[0]
                else:
                    nickname = source
                user = self.irc_server.users.get(nickname)
                channel = self.irc_server.channels.get(chan_name)
                if user and channel:
                    channel.members.pop(nickname, None)
                    user.channels.discard(chan_name)
                    await self.broadcast_to_local(line, exclude_server=server.name)
                    # Forward PART to other linked servers ONLY if we're trunk
                    if self.server_role == 'trunk':
                        await self.broadcast_to_servers(line, exclude_server=server.name)
        elif cmd == 'QUIT':
            # User quit
            # Extract nickname from source prefix (nick!user@host)
            if '!' in source:
                nickname = source.split('!')[0]
            else:
                nickname = source
            user = self.irc_server.users.pop(nickname, None)
            if user:
                for chan_name in list(user.channels):
                    channel = self.irc_server.channels.get(chan_name)
                    if channel:
                        channel.members.pop(nickname, None)
                server.remove_user(nickname)
                await self.broadcast_to_local(line, exclude_server=server.name)
                # Forward QUIT to other linked servers ONLY if we're trunk
                if self.server_role == 'trunk':
                    await self.broadcast_to_servers(line, exclude_server=server.name)
        elif cmd == 'TOPIC':
            # Topic change
            # Format: :nickname!user@host TOPIC #channel :new topic
            if len(parts) >= 3:
                chan_name = parts[2]
                new_topic = ' '.join(parts[3:]).lstrip(':') if len(parts) > 3 else ''
                # Extract nickname from source prefix (nick!user@host)
                if '!' in source:
                    nickname = source.split('!')[0]
                else:
                    nickname = source
                channel = self.irc_server.channels.get(chan_name)
                if channel:
                    # Update topic locally
                    channel.topic = new_topic
                    channel.topic_set_by = nickname
                    channel.topic_set_at = int(time.time())
                    logger.info(f"Remote TOPIC set in {chan_name} by {nickname}: {new_topic}")
                    # Broadcast to LOCAL channel members only (exclude remote users)
                    for member in channel.members.values():
                        is_remote = hasattr(member, 'is_remote') and member.is_remote
                        if not is_remote:
                            await member.send(line)
                    # Forward TOPIC to other linked servers ONLY if we're trunk
                    if self.server_role == 'trunk':
                        await self.broadcast_to_servers(line, exclude_server=server.name)
        elif cmd == 'MODE':
            # Channel or user mode change
            # Format: :nickname!user@host MODE #channel +o user
            # Format: :nickname!user@host MODE nickname +i
            if len(parts) >= 3:
                target = parts[2]
                # Check if it's a channel mode
                if target.startswith('#') or target.startswith('&'):
                    # Channel mode
                    channel = self.irc_server.channels.get(target)
                    if channel and len(parts) >= 4:
                        modes = parts[3]
                        # Parse mode parameters
                        mode_params = parts[4:] if len(parts) > 4 else []

                        adding = True
                        param_idx = 0
                        for char in modes:
                            if char == '+':
                                adding = True
                            elif char == '-':
                                adding = False
                            elif char in 'qov':  # Owner, operator, voice
                                if param_idx < len(mode_params):
                                    target_nick = mode_params[param_idx]
                                    param_idx += 1

                                    if char == 'q':  # Owner
                                        if adding:
                                            channel.owners.add(target_nick)
                                            logger.info(f"Remote MODE: Added {target_nick} as owner of {target}")
                                        else:
                                            channel.owners.discard(target_nick)
                                            logger.info(f"Remote MODE: Removed {target_nick} as owner of {target}")
                                    elif char == 'o':  # Operator/Host
                                        if adding:
                                            channel.hosts.add(target_nick)
                                            logger.info(f"Remote MODE: Added {target_nick} as host of {target}")
                                        else:
                                            channel.hosts.discard(target_nick)
                                            logger.info(f"Remote MODE: Removed {target_nick} as host of {target}")
                                    elif char == 'v':  # Voice
                                        if adding:
                                            channel.voices.add(target_nick)
                                            logger.info(f"Remote MODE: Added {target_nick} as voice in {target}")
                                        else:
                                            channel.voices.discard(target_nick)
                                            logger.info(f"Remote MODE: Removed {target_nick} as voice in {target}")
                            elif char == 'b':  # Ban list
                                if param_idx < len(mode_params):
                                    ban_mask = mode_params[param_idx]
                                    param_idx += 1
                                    if adding:
                                        if ban_mask not in channel.ban_list:
                                            channel.ban_list.append(ban_mask)
                                            logger.info(f"Remote MODE: Added ban {ban_mask} to {target}")
                                    else:
                                        if ban_mask in channel.ban_list:
                                            channel.ban_list.remove(ban_mask)
                                            logger.info(f"Remote MODE: Removed ban {ban_mask} from {target}")
                            elif char == 'k':  # Key
                                if adding:
                                    if param_idx < len(mode_params):
                                        channel.key = mode_params[param_idx]
                                        channel.modes['k'] = True
                                        param_idx += 1
                                        logger.info(f"Remote MODE: Set key on {target}")
                                else:
                                    channel.key = None
                                    channel.modes['k'] = False
                                    logger.info(f"Remote MODE: Removed key from {target}")
                            elif char == 'l':  # Limit
                                if adding:
                                    if param_idx < len(mode_params):
                                        try:
                                            channel.user_limit = int(mode_params[param_idx])
                                            channel.modes['l'] = True
                                            param_idx += 1
                                            logger.info(f"Remote MODE: Set limit on {target}")
                                        except ValueError:
                                            param_idx += 1
                                else:
                                    channel.user_limit = None
                                    channel.modes['l'] = False
                                    logger.info(f"Remote MODE: Removed limit from {target}")
                            elif char in channel.modes:
                                # Other simple flags (t, m, n, i, s, etc.)
                                channel.modes[char] = adding
                                logger.info(f"Remote MODE: Set {target} {'+' if adding else '-'}{char}")

                        # Broadcast to LOCAL channel members only
                        for member in channel.members.values():
                            is_remote = hasattr(member, 'is_remote') and member.is_remote
                            if not is_remote:
                                await member.send(line)
                        # Forward MODE to other linked servers ONLY if we're trunk
                        if self.server_role == 'trunk':
                            await self.broadcast_to_servers(line, exclude_server=server.name)
                else:
                    # User mode change
                    # Format: :nickname MODE nickname :+i or :-i
                    user = self.irc_server.users.get(target)
                    if user and len(parts) >= 4:
                        modes = parts[3].lstrip(':')
                        adding = True
                        for char in modes:
                            if char == '+':
                                adding = True
                            elif char == '-':
                                adding = False
                            elif char == 'i':
                                # Update invisible mode
                                user.set_mode('i', adding)
                                logger.info(f"Remote MODE: {target} {'set' if adding else 'unset'} +i")
                            # Other user modes (o, a, g, s, etc.) are typically server-controlled
                            # and shouldn't be propagated from remote servers for security

                        # Forward MODE to other linked servers ONLY if we're trunk
                        if self.server_role == 'trunk':
                            await self.broadcast_to_servers(line, exclude_server=server.name)
        elif cmd == 'KICK':
            # User kicked from channel
            # Format: :nickname!user@host KICK #channel target :reason
            if len(parts) >= 4:
                chan_name = parts[2]
                target_nick = parts[3]
                reason = ' '.join(parts[4:]).lstrip(':') if len(parts) > 4 else ''

                channel = self.irc_server.channels.get(chan_name)
                if channel:
                    # Remove target from channel
                    channel.members.pop(target_nick, None)
                    channel.owners.discard(target_nick)
                    channel.hosts.discard(target_nick)
                    channel.voices.discard(target_nick)
                    channel.gagged.discard(target_nick)

                    # Update target user's channel list if they're local
                    target_user = self.irc_server.users.get(target_nick)
                    if target_user:
                        target_user.channels.discard(chan_name)

                    logger.info(f"Remote KICK: {target_nick} from {chan_name} by {source}")

                    # Broadcast to LOCAL channel members only
                    for member in channel.members.values():
                        is_remote = hasattr(member, 'is_remote') and member.is_remote
                        if not is_remote:
                            await member.send(line)

                    # Forward KICK to other linked servers ONLY if we're trunk
                    if self.server_role == 'trunk':
                        await self.broadcast_to_servers(line, exclude_server=server.name)
        elif cmd == 'INVITE':
            # User invited to channel
            # Format: :nickname!user@host INVITE target :#channel
            if len(parts) >= 4:
                target_nick = parts[2]
                chan_name = parts[3].lstrip(':')

                # Check if target is local
                target_user = self.irc_server.users.get(target_nick)
                if target_user and not (hasattr(target_user, 'is_remote') and target_user.is_remote):
                    # Target is local, deliver INVITE
                    target_user.invited_to.add(chan_name)
                    await target_user.send(line)
                    logger.info(f"Remote INVITE: {target_nick} to {chan_name} from {source}")
                else:
                    # Target not found locally - forward to other servers ONLY if we're trunk
                    if self.server_role == 'trunk':
                        await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'NICK':
            # Nickname change
            # Format: :oldnick!user@host NICK newnick
            if len(parts) >= 3:
                # Extract old nickname from source prefix
                if '!' in source:
                    old_nick = source.split('!')[0]
                else:
                    old_nick = source
                new_nick = parts[2].lstrip(':')

                # Update user in users dictionary
                user = self.irc_server.users.get(old_nick)
                if user:
                    # Update users dictionary
                    del self.irc_server.users[old_nick]
                    user.nickname = new_nick
                    self.irc_server.users[new_nick] = user

                    # Update channel memberships
                    for chan_name in list(user.channels):
                        channel = self.irc_server.channels.get(chan_name)
                        if channel:
                            if old_nick in channel.members:
                                channel.members[new_nick] = channel.members.pop(old_nick)
                            if old_nick in channel.owners:
                                channel.owners.discard(old_nick)
                                channel.owners.add(new_nick)
                            if old_nick in channel.hosts:
                                channel.hosts.discard(old_nick)
                                channel.hosts.add(new_nick)
                            if old_nick in channel.voices:
                                channel.voices.discard(old_nick)
                                channel.voices.add(new_nick)

                    logger.info(f"Remote NICK: {old_nick} -> {new_nick}")

                    # Broadcast to LOCAL users who can see this user
                    notified = set()
                    for chan_name in user.channels:
                        channel = self.irc_server.channels.get(chan_name)
                        if channel:
                            for member in channel.members.values():
                                if not (hasattr(member, 'is_remote') and member.is_remote):
                                    if member.nickname not in notified:
                                        await member.send(line)
                                        notified.add(member.nickname)

                # Forward NICK to other linked servers ONLY if we're trunk
                if self.server_role == 'trunk':
                    await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'KILL':
            # User killed
            # Format: :staff!user@host KILL target :reason
            if len(parts) >= 3:
                target_nick = parts[2]
                reason = ' '.join(parts[3:]).lstrip(':') if len(parts) > 3 else 'Killed'

                # Find target user
                target = self.irc_server.users.get(target_nick)
                if target:
                    # Don't kill local users via remote KILL (security)
                    if hasattr(target, 'is_remote') and target.is_remote:
                        logger.info(f"Remote KILL ignored: {target_nick} is remote on this server")
                    else:
                        # Send KILL message to local target
                        await target.send(f":{self.irc_server.servername} KILL {target_nick} :{reason}")
                        logger.info(f"Remote KILL: {target_nick} ({reason})")
                        await self.irc_server.quit_user(target)

                # Forward KILL to other linked servers ONLY if we're trunk
                if self.server_role == 'trunk':
                    await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'WHOIS':
            # WHOIS query
            # Format: :nickname!user@host WHOIS target
            if len(parts) >= 3:
                # Extract requester from source
                if '!' in source:
                    requester_nick = source.split('!')[0]
                else:
                    requester_nick = source
                target_nick = parts[2]

                # Check if target is local
                target = self.irc_server.users.get(target_nick)
                if target and not (hasattr(target, 'is_remote') and target.is_remote):
                    # Target is local, send WHOIS replies back through the link
                    # We need to route replies back to the requester
                    # For now, log that we received the query
                    logger.info(f"Remote WHOIS: {requester_nick} querying {target_nick}")
                    # TODO: Send WHOIS replies back through server link
                else:
                    # Target not found locally - forward to other servers ONLY if we're trunk
                    if self.server_role == 'trunk':
                        await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'AWAY':
            # Away status change
            # Format: :nickname!user@host AWAY :message
            # Format: :nickname!user@host AWAY (no message = back from away)
            if '!' in source:
                nickname = source.split('!')[0]
            else:
                nickname = source

            user = self.irc_server.users.get(nickname)
            if user:
                if len(parts) >= 3:
                    # Setting away
                    away_msg = ' '.join(parts[2:]).lstrip(':')
                    user.away_msg = away_msg
                    logger.info(f"Remote AWAY: {nickname} is away: {away_msg}")
                else:
                    # Returning from away
                    user.away_msg = None
                    logger.info(f"Remote AWAY: {nickname} is back")

            # Forward AWAY to other linked servers ONLY if we're trunk
            if self.server_role == 'trunk':
                await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'WHISPER':
            # WHISPER message to user in channel
            # Format: :sender!user@host WHISPER #channel target :message
            if len(parts) >= 5:
                chan_name = parts[2]
                target_nick = parts[3]
                message_text = ' '.join(parts[4:]).lstrip(':')

                # Check if target is local
                target_user = self.irc_server.users.get(target_nick)
                if target_user and not (hasattr(target_user, 'is_remote') and target_user.is_remote):
                    # Target is local, deliver WHISPER
                    await target_user.send(line)
                    logger.info(f"Remote WHISPER: {source} to {target_nick} in {chan_name}")
                else:
                    # Target not found locally - forward to other servers ONLY if we're trunk
                    if self.server_role == 'trunk':
                        await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'ACCESS':
            # ACCESS list modification
            # Format: :nickname!user@host ACCESS #channel ADD|DELETE|CLEAR ...
            if len(parts) >= 4:
                obj = parts[2]
                action = parts[3].upper()

                # Only process channel ACCESS (not server ACCESS)
                if obj.startswith('#') or obj.startswith('&'):
                    channel = self.irc_server.channels.get(obj)
                    if channel:
                        # Re-execute ACCESS command locally
                        # Parse the user who initiated this
                        if '!' in source:
                            nickname = source.split('!')[0]
                        else:
                            nickname = source

                        remote_user = self.irc_server.users.get(nickname)
                        if remote_user:
                            # Build params for ACCESS handler
                            access_params = parts[2:]  # [#channel, ACTION, ...]
                            # Execute ACCESS locally (this will modify channel.access_list)
                            try:
                                await self.irc_server.handle_access(remote_user, access_params)
                                logger.info(f"Remote ACCESS: {nickname} executed ACCESS {action} on {obj}")
                            except Exception as e:
                                logger.error(f"Remote ACCESS execution error: {e}")

                # Forward ACCESS to other linked servers ONLY if we're trunk
                if self.server_role == 'trunk':
                    await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'PROP':
            # PROP channel property change
            # Format: :nickname!user@host PROP #channel property value
            if len(parts) >= 4:
                chan_name = parts[2]
                prop_name = parts[3]
                prop_value = ' '.join(parts[4:]).lstrip(':') if len(parts) > 4 else ""

                # Only process channel PROP
                if chan_name.startswith('#') or chan_name.startswith('&'):
                    channel = self.irc_server.channels.get(chan_name)
                    if channel:
                        # Parse the user who initiated this
                        if '!' in source:
                            nickname = source.split('!')[0]
                        else:
                            nickname = source

                        remote_user = self.irc_server.users.get(nickname)
                        if remote_user:
                            # Build params for PROP handler
                            prop_params = parts[2:]  # [#channel, property, value...]
                            # Execute PROP locally (this will modify channel properties)
                            try:
                                await self.irc_server.handle_prop(remote_user, prop_params)
                                logger.info(f"Remote PROP: {nickname} set {prop_name} on {chan_name}")
                            except Exception as e:
                                logger.error(f"Remote PROP execution error: {e}")

                # Forward PROP to other linked servers ONLY if we're trunk
                if self.server_role == 'trunk':
                    await self.broadcast_to_servers(line, exclude_server=server.name)

        elif cmd == 'KNOCK':
            # KNOCK channel request
            # Format: :nickname!user@host KNOCK #channel :message
            if len(parts) >= 3:
                chan_name = parts[2]
                message = ' '.join(parts[3:]).lstrip(':') if len(parts) > 3 else ""

                # Only process channel KNOCK
                if chan_name.startswith('#') or chan_name.startswith('&'):
                    channel = self.irc_server.channels.get(chan_name)
                    if channel:
                        # Extract knock notification message
                        # Format: :servername 710 #channel nickname user@host :has asked for an invite
                        if '!' in source:
                            nickname = source.split('!')[0]
                            userhost = source.split('!')[1]
                        else:
                            nickname = source
                            userhost = "unknown@unknown"

                        # Build KNOCK notification for local owners/hosts
                        knock_msg = f":{self.irc_server.servername} 710 {chan_name} {nickname} {nickname}!{userhost} :has asked for an invite"
                        if message:
                            knock_msg += f" ({message})"

                        # Send to LOCAL owners/hosts only
                        for nick in channel.members:
                            if nick in channel.owners or nick in channel.hosts:
                                member = channel.members[nick]
                                if not (hasattr(member, 'is_remote') and member.is_remote):
                                    await member.send(knock_msg)

                        logger.info(f"Remote KNOCK: {nickname} knocked on {chan_name}")

                # Forward KNOCK to other linked servers ONLY if we're trunk
                if self.server_role == 'trunk':
                    await self.broadcast_to_servers(line, exclude_server=server.name)

    async def broadcast_to_servers(self, message: str, exclude_server: str = None):
        """Broadcast a message to all linked servers"""
        logger.info(f"broadcast_to_servers called with message: {message[:80]}...")
        logger.info(f"Available servers: {list(self.servers.keys())}, exclude={exclude_server}")
        for servername, server in self.servers.items():
            if servername != exclude_server and server.is_direct:
                logger.info(f"  Sending to {servername}: {message[:60]}...")
                await server.send(message)
                logger.info(f"  Sent to {servername}")

    async def broadcast_to_local(self, message: str, exclude_server: str = None,
                                exclude_modes: str = None):
        """Broadcast to local users only"""
        for user in self.irc_server.users.values():
            if hasattr(user, 'is_remote') and user.is_remote:
                continue
            if exclude_modes and any(user.has_mode(m) for m in exclude_modes):
                continue
            await user.send(message)

    async def handle_server_split(self, server: LinkedServer):
        """Handle a server disconnecting (network divergence)"""
        logger.warning(f"Server {server.name} disconnected (split)")

        # Remove the server
        self.servers.pop(server.name, None)

        # QUIT all users from that server
        for nickname in list(server.users):
            user = self.irc_server.users.pop(nickname, None)
            if user:
                quit_msg = f":{nickname} QUIT :{server.name} {self.irc_server.servername}"
                # Remove from all channels
                for chan_name in list(user.channels):
                    channel = self.irc_server.channels.get(chan_name)
                    if channel:
                        channel.members.pop(nickname, None)
                        # Broadcast quit to local users
                        for member in channel.members.values():
                            if not hasattr(member, 'is_remote') or not member.is_remote:
                                member.send(quit_msg)

        # Notify local users
        await self.broadcast_to_local(
            f":{self.irc_server.servername} NOTICE * :Server {server.name} has split",
            exclude_modes='a'
        )

        # Propagate SQUIT to all other linked servers
        squit_msg = f"SQUIT {server.name} :{server.name} {self.irc_server.servername}"
        await self.broadcast_to_servers(squit_msg, exclude_server=server.name)
        logger.info(f"Propagated SQUIT for {server.name} to all linked servers")

        # Schedule reconnect if this was an autoconnect link
        for link_cfg in self.links_config:
            if link_cfg['name'] == server.name:
                await self.schedule_reconnect(link_cfg)
                break

    async def squit_server(self, servername: str, reason: str = ""):
        """Disconnect a server"""
        server = self.servers.get(servername)
        if not server:
            return

        # Send SQUIT
        if server.writer:
            await server.send(f"SQUIT {servername} :{reason}")
            server.writer.close()

        # Handle as split
        await self.handle_server_split(server)

    async def authenticate_server(self, servername: str, password: str) -> bool:
        """Authenticate an incoming server connection using bcrypt"""
        loop = asyncio.get_event_loop()

        for link in self.links_config:
            if link['name'] == servername:
                # Get password hash from config (should be bcrypt hash)
                password_hash = link['password']

                # Support both bcrypt hashes and plaintext for backwards compatibility
                # Check if it's a bcrypt hash (starts with $2b$)
                if password_hash.startswith('$2b$') or password_hash.startswith('$2a$') or password_hash.startswith('$2y$'):
                    try:
                        # Verify bcrypt hash asynchronously
                        result = await loop.run_in_executor(
                            None,
                            bcrypt.checkpw,
                            password.encode(),
                            password_hash.encode()
                        )
                        return result
                    except (ValueError, TypeError) as e:
                        logger.error(f"bcrypt verification error for {servername}: {e}")
                        return False
                else:
                    # Fall back to plaintext comparison (deprecated - log warning)
                    logger.warning(f"Server link {servername} using PLAINTEXT password - UPDATE TO BCRYPT IMMEDIATELY")
                    return password_hash == password

        return False

    def get_services_hub(self) -> Optional[LinkedServer]:
        """Get the services hub server connection"""
        hub_name = CONFIG.get('services', 'hub_server')
        if not hub_name:
            logger.debug("No hub_server configured in services")
            return None

        trunk = self.servers.get(hub_name)
        if not trunk:
            logger.warning(f"Trunk server '{hub_name}' not found in linked servers")
        else:
            logger.debug(f"Found trunk server '{hub_name}', is_direct={trunk.is_direct}")

        return trunk

    async def route_to_services_hub(self, message: str) -> bool:
        """
        Route a message to the services hub.
        Returns True if routed successfully, False otherwise.
        """
        hub = self.get_services_hub()
        if hub and hub.is_direct:
            await hub.send(message)
            logger.debug(f"Routed message to trunk")
            return True
        else:
            if hub:
                logger.warning(f"Trunk found but not direct: {hub.name}, is_direct={hub.is_direct}")
            else:
                logger.warning("No trunk server found for service routing")
        return False

    def is_service_user(self, nickname: str) -> bool:
        """Check if a nickname is a service user"""
        user = self.irc_server.users.get(nickname)
        if not user:
            return False
        return user.is_virtual and user.has_mode('s')

    async def route_staff_auth(self, username: str, password: str, user_obj) -> Optional[dict]:
        """
        Route staff authentication request to trunk server.
        Returns dict with auth result or None if trunk unavailable.

        Result dict: {
            'authenticated': bool,
            'level': str,  # 'ADMIN', 'SYSOP', 'GUIDE', or 'USER'
            'email': str,
            'realname': str,
            'force_realname': bool
        }
        """
        trunk = self.get_services_hub()
        if not trunk or not trunk.is_direct:
            logger.warning(f"Staff auth routing failed: No trunk connection")
            return None

        # Create a unique ID for this auth request
        import uuid
        auth_id = str(uuid.uuid4())[:8]

        # Store pending auth request
        if not hasattr(self, '_pending_staff_auth'):
            self._pending_staff_auth = {}

        # Create future for response
        future = asyncio.Future()
        self._pending_staff_auth[auth_id] = {
            'future': future,
            'username': username,
            'user_obj': user_obj
        }

        # Send STAFFAUTH request to trunk
        # Format: STAFFAUTH <auth_id> <username> <password>
        await trunk.send(f"STAFFAUTH {auth_id} {username} {password}")
        logger.debug(f"Sent staff auth request to trunk: {username} (id: {auth_id})")

        try:
            # Wait for response with timeout
            result = await asyncio.wait_for(future, timeout=5.0)
            return result
        except asyncio.TimeoutError:
            logger.error(f"Staff auth timeout for {username}")
            del self._pending_staff_auth[auth_id]
            return None
        except Exception as e:
            logger.error(f"Staff auth error for {username}: {e}")
            if auth_id in self._pending_staff_auth:
                del self._pending_staff_auth[auth_id]
            return None

    @staticmethod
    async def send_to_writer(writer: asyncio.StreamWriter, message: str):
        """Helper to send a message to a writer"""
        if not writer.is_closing():
            writer.write((message + '\r\n').encode('utf-8', errors='replace'))
            await writer.drain()
