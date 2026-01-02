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
import time
import logging
from typing import Dict, Set, Optional, Tuple

logger = logging.getLogger(__name__)

# Will be set by pyircx.py when module is imported
CONFIG = None


class LinkedServer:
    """Represents a linked server in the network"""

    def __init__(self, name: str, hopcount: int, description: str,
                 writer: Optional[asyncio.StreamWriter] = None):
        self.name = name
        self.hopcount = hopcount
        self.description = description
        self.writer = writer
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
        self.bind_host = CONFIG.get('linking', 'bind_host', default='0.0.0.0')
        self.bind_port = CONFIG.get('linking', 'bind_port', default=7001)
        self.links_config = CONFIG.get('linking', 'links', default=[])
        self.link_server = None

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

                parts = line.split(' ', 4)
                if parts[0] == 'SERVER' and len(parts) >= 4:
                    servername = parts[1]
                    password = parts[2]
                    hopcount = int(parts[3])
                    description = parts[4].lstrip(':') if len(parts) > 4 else ''

                    # Authenticate
                    if not self.authenticate_server(servername, password):
                        logger.warning(f"Failed auth from {servername} at {peer}")
                        await self.send_to_writer(writer, f"ERROR :Bad password")
                        writer.close()
                        return

                    # Create linked server
                    server = LinkedServer(servername, hopcount, description, writer)
                    self.servers[servername] = server

                    # Send our SERVER line
                    network_name = CONFIG.get('server', 'network', default='IRCX Network')
                    await self.send_to_writer(
                        writer,
                        f"SERVER {self.irc_server.servername} {password} 0 :{network_name}"
                    )

                    # Burst our state
                    await self.burst_to_server(server)

                    # Start reading server messages
                    asyncio.create_task(self.read_server_messages(server, reader))

                    logger.info(f"Server {servername} linked successfully")
                    self.broadcast_to_local(f":{self.irc_server.servername} NOTICE * :Server {servername} linked", exclude_modes='a')
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

            # Send SERVER command
            network_name = CONFIG.get('server', 'network', default='IRCX Network')
            await self.send_to_writer(
                writer,
                f"SERVER {self.irc_server.servername} {password} 0 :{network_name}"
            )

            # Wait for SERVER response
            line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            line = line.decode('utf-8', errors='replace').strip()
            parts = line.split(' ', 4)

            if parts[0] == 'SERVER':
                remote_name = parts[1]
                hopcount = int(parts[3])
                description = parts[4].lstrip(':') if len(parts) > 4 else ''

                # Create linked server
                server = LinkedServer(remote_name, hopcount, description, writer)
                self.servers[remote_name] = server

                # Burst our state
                await self.burst_to_server(server)

                # Start reading messages
                asyncio.create_task(self.read_server_messages(server, reader))

                logger.info(f"Successfully linked to {remote_name}")
                self.broadcast_to_local(f":{self.irc_server.servername} NOTICE * :Linked to server {remote_name}", exclude_modes='a')

            elif parts[0] == 'ERROR':
                logger.error(f"Link to {servername} rejected: {line}")
                writer.close()

        except Exception as e:
            logger.error(f"Failed to connect to {servername}: {e}")

    async def burst_to_server(self, server: LinkedServer):
        """Send full state burst to a newly linked server"""
        # Burst all users
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
        if cmd == 'NICK':
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

    async def handle_remote_nick(self, server: LinkedServer, parts: list):
        """Handle NICK introduction from remote server"""
        if len(parts) < 9:
            return

        # NICK <nick> <hop> <ts> <user> <host> <server> <modes> :<real>
        nickname = parts[1]
        timestamp = int(parts[3])
        username = parts[4]
        hostname = parts[5]
        origin_server = parts[6]
        modes = parts[7].lstrip('+')
        realname = ' '.join(parts[8:]).lstrip(':')

        # Create virtual user object
        # Create a remote user object (import here to avoid circular dependency)
        from pyircx import User

        user = User(None, None, is_virtual=True)
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

        self.irc_server.users[nickname] = user
        server.add_user(nickname)

        logger.debug(f"Added remote user {nickname} from {origin_server}")

    async def handle_remote_sjoin(self, server: LinkedServer, parts: list):
        """Handle SJOIN (channel sync) from remote server"""
        if len(parts) < 5:
            return

        # SJOIN <ts> <channel> <modes> :<nicklist>
        timestamp = int(parts[1])
        chan_name = parts[2]
        modes = parts[3].lstrip('+')
        nicklist = ' '.join(parts[4:]).lstrip(':').split()

        # Get or create channel
        channel = self.irc_server.channels.get(chan_name)
        if not channel:
            from pyircx import Channel
            channel = Channel(chan_name, self.irc_server)
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
            # Broadcast to local users in target channel
            await self.broadcast_to_local(line, exclude_server=server.name)
        elif cmd == 'JOIN':
            # User joined channel
            if len(parts) >= 3:
                chan_name = parts[2].lstrip(':')
                user = self.irc_server.users.get(source)
                channel = self.irc_server.channels.get(chan_name)
                if user and channel:
                    channel.members[source] = user
                    user.channels.add(chan_name)
                    await self.broadcast_to_local(line, exclude_server=server.name)
        elif cmd == 'PART':
            # User left channel
            if len(parts) >= 3:
                chan_name = parts[2]
                user = self.irc_server.users.get(source)
                channel = self.irc_server.channels.get(chan_name)
                if user and channel:
                    channel.members.pop(source, None)
                    user.channels.discard(chan_name)
                    await self.broadcast_to_local(line, exclude_server=server.name)
        elif cmd == 'QUIT':
            # User quit
            user = self.irc_server.users.pop(source, None)
            if user:
                for chan_name in list(user.channels):
                    channel = self.irc_server.channels.get(chan_name)
                    if channel:
                        channel.members.pop(source, None)
                server.remove_user(source)
                await self.broadcast_to_local(line, exclude_server=server.name)

    async def broadcast_to_servers(self, message: str, exclude_server: str = None):
        """Broadcast a message to all linked servers"""
        for servername, server in self.servers.items():
            if servername != exclude_server and server.is_direct:
                await server.send(message)

    async def broadcast_to_local(self, message: str, exclude_server: str = None,
                                exclude_modes: str = None):
        """Broadcast to local users only"""
        for user in self.irc_server.users.values():
            if hasattr(user, 'is_remote') and user.is_remote:
                continue
            if exclude_modes and any(user.has_mode(m) for m in exclude_modes):
                continue
            user.send(message)

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

    def authenticate_server(self, servername: str, password: str) -> bool:
        """Authenticate an incoming server connection"""
        for link in self.links_config:
            if link['name'] == servername and link['password'] == password:
                return True
        return False

    @staticmethod
    async def send_to_writer(writer: asyncio.StreamWriter, message: str):
        """Helper to send a message to a writer"""
        if not writer.is_closing():
            writer.write((message + '\r\n').encode('utf-8', errors='replace'))
            await writer.drain()
