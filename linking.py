"""
pyIRCX Server Linking Module
Implements server-to-server linking protocol

Copyright (C) 2026 pyIRCX Project

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import bcrypt
import time
import logging
from typing import Dict, Set, Optional, Tuple

logger = logging.getLogger(__name__)

# Will be set by pyircx.py when module is imported
CONFIG = None
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

                    # Create linked server
                    server = LinkedServer(servername, hopcount, description, writer, remote_role)
                    self.servers[servername] = server

                    # Send our SERVER line with role
                    network_name = CONFIG.get('server', 'network', default='IRCX Network')
                    await self.send_to_writer(
                        writer,
                        f"SERVER {self.irc_server.servername} {password} 0 {self.server_role} :{network_name}"
                    )

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

                # Create linked server
                server = LinkedServer(remote_name, hopcount, description, writer, remote_role)
                self.servers[remote_name] = server

                # Burst our state
                await self.burst_to_server(server)

                # Start reading messages
                asyncio.create_task(self.read_server_messages(server, reader))

                logger.info(f"Successfully linked to {remote_name}")
                await self.broadcast_to_local(f":{self.irc_server.servername} NOTICE * :Linked to server {remote_name}", exclude_modes='a')

            elif parts[0] == 'ERROR':
                logger.error(f"Link to {servername} rejected: {line}")
                writer.close()

        except Exception as e:
            logger.error(f"Failed to connect to {servername}: {e}")

    async def burst_to_server(self, server: LinkedServer):
        """Send full state burst to a newly linked server"""
        # Check if we're a services hub - if so, burst services to leaf servers
        is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)
        services_mode = CONFIG.get('services', 'mode', default='local')

        # Burst services if we're a hub and in centralized mode
        if is_services_hub and services_mode == 'centralized':
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
                # Verify password
                if await check_password_async(password, row[0]):
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

        # Set modes
        for mode in modes:
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
        """Handle a server disconnecting (netsplit)"""
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
        self.broadcast_to_local(
            f":{self.irc_server.servername} NOTICE * :Server {server.name} has split",
            exclude_modes='a'
        )

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
