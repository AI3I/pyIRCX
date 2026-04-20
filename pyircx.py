#!/usr/bin/env python3
"""
pyIRCX - Python IRCX Server

An async IRC/IRCX server implementation with database-backed authentication,
channel persistence, flood protection, and staff management features.
"""

# Version info - sourced from version.json
from version import VERSION as __version__, VERSION_LABEL as __version_label__, CREATED as __created__

import asyncio
import aiosqlite
import bcrypt
import time
import logging
import logging.handlers
import fnmatch
import json
import traceback
import sys
import re
import uuid
import pyotp
import base64
import socket

# Compiled regex patterns for performance (avoid recompiling in hot paths)
_IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_IPV6_PATTERN = re.compile(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
_HOSTNAME_PATTERN = re.compile(r'^[\w-]+\.[\w.-]+$')
_CLONE_CHANNEL_PATTERN = re.compile(r'^(.+?)(\d+)$')
_FORMATTING_PATTERN = re.compile(r'\x03(\d{1,2}(,\d{1,2})?)?')
_TAG_PATTERN = re.compile(r'^[A-Za-z][A-Za-z0-9.]*$')
import signal
import argparse
import os
import ssl
from pathlib import Path
from collections import defaultdict, deque, OrderedDict
import validation
import user as user_module
import channel as channel_module
import security as security_module
import database as database_module
import ssl_manager as ssl_manager_module
import service_bot as service_bot_module
from config import ServerConfig
from responses import RESPONSES, SERVER_MESSAGES, SERVICE_HELP, EASTER_EGG_JOKES, ENTITY_RESPONSES, get_log_message
import help_text
import modes as modes_module
import linking
from linking import ServerLinkManager

# ==============================================================================
# LOGGING SETUP
# ==============================================================================

def setup_logging(systemd_mode=False, log_file='pyircx.log', log_level='INFO'):
    """
    Configure logging for the server.

    Args:
        systemd_mode: If True, log to stdout only (journald captures it)
        log_file: Path to log file (ignored in systemd mode)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Base format - simpler for systemd (no timestamp, journald adds it)
    if systemd_mode:
        fmt = '[%(levelname)s] %(name)s: %(message)s'
    else:
        fmt = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'

    handlers = []

    if systemd_mode:
        # Systemd mode: only stdout, journald handles the rest
        handlers.append(logging.StreamHandler(sys.stdout))
    else:
        # Standalone mode: stdout + file
        handlers.append(logging.StreamHandler(sys.stdout))
        try:
            # Rotating file handler: 10MB max, keep 5 backups
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            handlers.append(file_handler)
        except Exception as e:
            print(f"Warning: Could not create log file {log_file}: {e}", file=sys.stderr)

    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=handlers,
        force=True  # Override any existing configuration
    )

    return logging.getLogger('pyIRCX')

# Default logger setup (will be reconfigured in main if needed)
logger = setup_logging()

# ==============================================================================
# CONFIGURATION - ServerConfig moved to config.py
# ==============================================================================

CONFIG = ServerConfig()
linking.CONFIG = CONFIG  # Share CONFIG with linking module
validation.CONFIG = CONFIG  # Share CONFIG with validation module
user_module.CONFIG = CONFIG  # Share CONFIG with user module
channel_module.CONFIG = CONFIG  # Share CONFIG with channel module
security_module.CONFIG = CONFIG  # Share CONFIG with security module
ssl_manager_module.CONFIG = CONFIG  # Share CONFIG with ssl_manager module
service_bot_module.CONFIG = CONFIG  # Share CONFIG with service_bot module

# ==============================================================================
# VALIDATION FUNCTIONS - imported from validation module
# ==============================================================================

# Import validation functions and constants
from validation import (
    validate_nickname,
    validate_username,
    validate_channel_name,
    validate_regex_pattern,
    is_channel,
    is_local_channel,
    is_reserved_service,
    mask_host,
    FORBIDDEN_CHARS,
    CHANNEL_FORBIDDEN_CHARS,
    CHANNEL_PREFIXES,
    RESERVED_SERVICES
)

# Import user-related classes
from user import User, FloodProtection, RateLimiter

# Import channel class
from channel import Channel

# Import security classes
from security import (
    ConnectionThrottle,
    FailedAuthTracker,
    DNSBLChecker,
    ProxyDetector,
    ConnectionScorer
)

# Import database utilities
from database import DatabasePool, check_password_async, hash_password_async

# Import SSL manager
from ssl_manager import SSLManager

# Import service bot monitor
from service_bot import ServiceBotMonitor


# ==============================================================================
# SECURITY CLASSES - moved to security.py and database.py
# ==============================================================================
# Note: FloodProtection and RateLimiter moved to user.py
# Note: ConnectionThrottle, FailedAuthTracker, DNSBLChecker, ProxyDetector, ConnectionScorer moved to security.py
# Note: DatabasePool, check_password_async, hash_password_async moved to database.py


# Global instances (initialized by server)
DNSBL_CHECKER = None
PROXY_DETECTOR = None
CONNECTION_SCORER = None


# Global SSL manager instance (SSLManager class moved to ssl_manager.py)
SSL_MANAGER = None


# ==============================================================================
# RESPONSE/MESSAGE TABLES - moved to responses.py
# ==============================================================================
# RESPONSES and SERVER_MESSAGES are now imported from responses.py


# ==============================================================================
# IRCv3 MESSAGE TAG HELPERS
# ==============================================================================

def _unescape_tag_value(value):
    """Unescape IRCv3 message tag value per spec."""
    result = []
    i = 0
    while i < len(value):
        if value[i] == '\\' and i + 1 < len(value):
            c = value[i + 1]
            if c == ':':
                result.append(';')
            elif c == 's':
                result.append(' ')
            elif c == '\\':
                result.append('\\')
            elif c == 'r':
                result.append('\r')
            elif c == 'n':
                result.append('\n')
            else:
                result.append(c)
            i += 2
        else:
            result.append(value[i])
            i += 1
    return ''.join(result)


def _escape_tag_value(value):
    """Escape a string for use as an IRCv3 message tag value."""
    return (value
        .replace('\\', '\\\\')
        .replace(';', '\\:')
        .replace(' ', '\\s')
        .replace('\r', '\\r')
        .replace('\n', '\\n'))


# ==============================================================================
# MAIN SERVER CLASS
# ==============================================================================


class pyIRCXServer:
    # Command routing table - maps IRC commands to their handler methods
    # This replaces the long elif chain in dispatch() for better maintainability
    COMMAND_HANDLERS = {
        # Channel operations
        'CREATE': 'handle_create',
        'WHOIS': 'handle_whois',
        'WHO': 'handle_who',
        'WHOWAS': 'handle_whowas',
        'LASTLOGONS': 'handle_lastlogons',
        'AWAY': 'handle_away',
        'TOPIC': 'handle_topic',
        'TRANSCRIPT': 'handle_transcript',
        'KNOCK': 'handle_knock',
        'PROP': 'handle_prop',
        'ACCESS': 'handle_access',
        'EVENT': 'handle_event',
        'KILL': 'handle_kill',
        'KICK': 'handle_kick',
        'INVITE': 'handle_invite',
        'MODE': 'handle_mode',
        'NAMES': 'handle_names',

        # Server/network commands
        'STATS': 'handle_stats',
        'CONFIG': 'handle_config',
        'STAFF': 'handle_staff',
        'PROFANITY': 'handle_profanity',
        'LINK': 'handle_link',
        'UNLINK': 'handle_unlink',
        'LINKS': 'handle_links',
        'MAP': 'handle_map',
        'INFO': 'handle_info',
        'MOTD': 'handle_motd',
        'LUSERS': 'handle_lusers',

        # IRCv3 extended commands
        'CHATHISTORY': 'handle_chathistory',
        'RENAME': 'handle_rename',

        # User commands
        'ISON': 'handle_ison',
        'USERHOST': 'handle_userhost',
        'REGISTER': 'handle_register',
        'UNREGISTER': 'handle_unregister',
        'AUTH': 'handle_auth',
        'DROP': 'handle_drop',
        'IDENTIFY': 'handle_identify',
        'MFA': 'handle_mfa',
        'MONITOR': 'handle_monitor',
        'SILENCE': 'handle_silence',
        'CHGPASS': 'handle_chgpass',
        'MEMO': 'handle_memo',
        'SETNAME': 'handle_setname',
    }

    # Command aliases - short forms and IRCv3 equivalents mapped to full commands
    COMMAND_ALIASES = {
        'J': 'JOIN', 'P': 'PART', 'W': 'WHOIS', 'M': 'PRIVMSG', 'N': 'NICK',
        'Q': 'QUIT', 'T': 'TOPIC', 'K': 'KICK', 'I': 'INVITE', 'L': 'LIST',
        'WW': 'WHOWAS', 'WH': 'WHISPER', 'H': 'HELP',
        'LOGONS': 'LASTLOGONS', 'LASTLOGON': 'LASTLOGONS',
        'WATCH': 'MONITOR',   # IRCX WATCH -> IRCv3 MONITOR (both syntaxes supported)
        'CONNECT': 'LINK',    # RFC CONNECT -> LINK
        'SQUIT': 'UNLINK',    # RFC SQUIT -> UNLINK
    }

    # Commands that trigger flood protection
    MESSAGE_COMMANDS = frozenset(['PRIVMSG', 'NOTICE', 'WHISPER', 'BROADCAST', 'TAGMSG'])

    # Service name mappings for error messages
    OTHER_SERVICES = {
        'operserv': 'OperServ', 'helpserv': 'HelpServ', 'infoserv': 'InfoServ',
        'botserv': 'BotServ', 'hostserv': 'HostServ', 'statserv': 'StatServ',
        'global': 'Global', 'alis': 'ALIS', 'services': 'Services',
    }

    def __init__(self):
        self.servername = CONFIG.get('server', 'name', default='irc.local')
        self.servername_short = self.servername.split('.')[0][:8]
        self.users = {}
        self.users_lower = {}  # lowercase nickname -> canonical nickname (O(1) lookups)
        self.channels = {}
        self.channels_lower = {}  # lowercase channel name -> canonical name (O(1) lookups)
        self.channel_creation_lock = asyncio.Lock()  # Prevent race conditions in channel creation
        self.user_update_lock = asyncio.Lock()  # Prevent race conditions in user dict modifications
        self.whowas = OrderedDict()  # LRU cache for WHOWAS
        self.whowas_max_entries = 1000  # Maximum entries to keep
        self.whowas_max_age = 86400  # 24 hours in seconds
        self.session_history = deque(
            maxlen=CONFIG.get('limits', 'max_connection_sessions', default=1000)
        )  # Recent completed client sessions
        self.boot_time = int(time.time())
        self.debug_mode = True
        self.max_users_seen = 0

        self.connection_throttle = ConnectionThrottle(
            max_connections=CONFIG.get(
                'security', 'connection_throttle', default=3),
            window=CONFIG.get('security', 'throttle_window', default=10.0)
        )

        # Failed authentication tracking for lockout
        self.failed_auth_tracker = FailedAuthTracker(
            max_attempts=CONFIG.get('security', 'auth_max_attempts', default=5),
            lockout_duration=CONFIG.get('security', 'auth_lockout_duration', default=300),
            window=CONFIG.get('security', 'auth_lockout_window', default=600)
        )

        # Database connection pool (trunk and standalone servers need database, branches don't)
        server_role = CONFIG.get('linking', 'server_role', default='standalone')
        if server_role in ['trunk', 'standalone']:
            self.db_pool = DatabasePool(
                CONFIG.get('database', 'path', default='pyircx.db'),
                pool_size=CONFIG.get('database', 'pool_size', default=5)
            )
        else:
            self.db_pool = None  # Branch servers don't need database (services are centralized)

        # CAP negotiation timeout (seconds)
        self.cap_timeout = CONFIG.get('security', 'cap_timeout', default=60)

        self.stats = {
            'total_connections': 0,
            'messages_sent': 0,
            'commands_processed': 0,
            'command_usage': {},  # Track usage count per command
            'peak_users': 0,  # Peak simultaneous users
            'peak_time': None,  # When peak occurred
            'flood_events': 0,  # Total flood protection triggers
            'messages_by_channel': {},  # Message count per channel
            'servicebot_violations': {},  # Violation type -> count
            'servicebot_actions': {},  # Action type -> count
            # Performance metrics
            'regex_cache_hits': 0,  # Profanity filter regex cache hits
            'regex_cache_misses': 0,  # Profanity filter regex cache recompiles
            'config_cache_reloads': 0,  # ServiceBot config cache reloads
            'db_queries': 0,  # Total database queries
            'db_query_times': [],  # Recent query times (keep last 100)
            # Real-time metrics (per-minute tracking)
            'messages_per_minute': deque(maxlen=60),  # Last 60 minutes
            'commands_per_minute': deque(maxlen=60),  # Last 60 minutes
            'last_minute_reset': int(time.time() / 60),  # Current minute bucket
            'current_minute_messages': 0,
            'current_minute_commands': 0,
            # Historical trends
            'busiest_channels': {},  # channel -> total message count (all time)
            'most_active_users': {},  # username -> command count (all time)
            'network_divergence_history': [],  # [(timestamp, server_name, reason), ...] (last 10)
            'network_convergence_history': [],  # [(timestamp, server_name), ...] (last 10)
        }

        self.access_list = {
            'GRANT': [],  # [(mask, set_by, set_at, timeout, reason), ...]
            'DENY': []    # timeout=0 means permanent, else Unix timestamp when entry expires
        }

        # Server-level IP bans: {ip_address: (expires_at, reason, set_by)}
        # expires_at is Unix timestamp when ban expires, 0 for permanent
        self.server_bans = {}

        # WATCH: maps nickname (lowercase) -> set of User objects watching that nick
        self.watchers = {}
        self._pending_remote_whois = {}  # request_id -> pending cross-server WHOIS state

        self.servicebots = {}  # ServiceBot instances
        self.channel_monitors = {}  # Channel name -> ServiceBotMonitor
        self.save_task = None
        self.link_manager = None  # Will be set by ServerManager if linking is enabled

        # Cached CONFIG values for performance (avoid repeated CONFIG.get() calls)
        self._cache_config_values()

    def _cache_config_values(self):
        """Cache frequently-accessed CONFIG values for performance."""
        self.db_path = CONFIG.get('database', 'path', default='pyircx.db')
        self.services_mode = CONFIG.get('services', 'mode', default='local')
        self.is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)
        self.network_name = CONFIG.get('server', 'network', default='pyIRCX')
        self.system_nick = CONFIG.get('system', 'nick', default='System')
        self.servicebot_enabled = CONFIG.get('servicebot', 'enabled', default=True)
        self.max_users = CONFIG.get('limits', 'max_users', default=1000)
        self.max_users_per_channel = CONFIG.get('limits', 'max_users_per_channel', default=500)
        self.max_nick_length = CONFIG.get('limits', 'max_nick_length', default=30)
        self.max_user_length = CONFIG.get('limits', 'max_user_length', default=30)
        self.max_connection_sessions = max(1, int(CONFIG.get('limits', 'max_connection_sessions', default=1000) or 1000))
        self.connection_session_retention_days = max(0, int(CONFIG.get('limits', 'connection_session_retention_days', default=0) or 0))
        self.max_topic_length = CONFIG.get('limits', 'max_topic_length', default=390)
        self.flood_protection = CONFIG.get('security', 'enable_flood_protection', default=True)
        self.flood_messages = CONFIG.get('security', 'flood_messages', default=5)
        self.flood_window = CONFIG.get('security', 'flood_window', default=2.0)
        self.max_msg_length = CONFIG.get('limits', 'msg_length', default=512)

    def get_channel(self, name):
        """Case-insensitive channel lookup. Returns (channel, canonical_name) or (None, None)."""
        # Try exact match first (most common case)
        if name in self.channels:
            return self.channels[name], name
        # O(1) case-insensitive lookup via index
        canonical = self.channels_lower.get(name.lower())
        if canonical:
            return self.channels[canonical], canonical
        return None, None

    def get_user(self, nickname):
        """Case-insensitive user lookup. Returns User or None."""
        # Try exact match first (most common case)
        user = self.users.get(nickname)
        if user:
            return user
        # O(1) case-insensitive lookup via index
        canonical = self.users_lower.get(nickname.lower())
        if canonical:
            return self.users.get(canonical)
        return None

    def _build_who_flags(self, member, viewer, show_invisible=False):
        """Build WHO reply flags for a user.

        Args:
            member: The user being displayed in WHO results
            viewer: The user who issued the WHO command
            show_invisible: Whether to show +i flag (staff/self can see)

        Returns:
            str: WHO flags string (e.g., "Hixr", "G*", etc.)
        """
        # Base flag: H (here) or G (gone/away)
        flags = "G" if member.away_msg else "H"

        # Invisible flag - only show if allowed
        if member.has_mode('i') and show_invisible:
            flags += "i"

        # IRCX mode flag
        if member.has_mode('x') or member.is_ircx:
            flags += "x"

        # Registered nickname flag
        if member.has_mode('r'):
            flags += "r"

        # Staff/operator flags depend on viewer's IRCX mode
        if viewer.is_ircx:
            # IRCX mode - show specific staff/service letters
            if member.has_mode('G'):  # God - divine watcher
                flags += "G"
            elif member.has_mode('S'):  # System - omnipresent
                flags += "S"
            elif member.has_mode('s'):
                flags += "s"
            elif member.has_mode('a'):
                flags += "a"
            elif member.has_mode('o'):
                flags += "o"
            elif member.has_mode('g'):
                flags += "g"
        else:
            # Non-IRCX mode - show * for any IRC operator/service
            if member.has_mode('G') or member.has_mode('S'):  # God/System
                flags += "*"
            elif member.has_mode('s'):
                flags += "*"
            elif member.is_high_staff():
                flags += "*"

        return flags

    async def _build_whois_replies(self, viewer, target):
        """Build the full WHOIS numeric reply set for a target user."""
        replies = []

        display_host = mask_host(target.host, viewer.is_staff())
        replies.append(self.get_reply(
            "311", viewer, target=target.nickname, ident=target.username,
            host=display_host, real=target.realname
        ))

        if target.channels:
            chan_list = " ".join(target.channels)
            replies.append(self.get_reply(
                "319", viewer, target=target.nickname, channels=chan_list
            ))

        replies.append(self.get_reply("312", viewer, target=target.nickname))

        if target.has_mode('S'):
            role = "has an omnipresence"
        elif target.has_mode('G'):
            role = "is watching over you"
        elif target.is_service():
            role = "is an IRC service"
        elif target.has_mode('a'):
            role = "is an IRC administrator"
        elif target.has_mode('o'):
            role = "is an IRC operator"
        elif target.has_mode('g'):
            role = "is an IRC guide"
        else:
            role = None

        if role:
            replies.append(self.get_reply(
                "313", viewer, target=target.nickname, role=role
            ))

        if target.has_mode('r'):
            replies.append(self.get_reply(
                "307", viewer, target=target.nickname,
                message=SERVER_MESSAGES['whois_identified']
            ))

        if target.has_mode('b'):
            replies.append(self.get_reply("335", viewer, target=target.nickname))

        if target.away_msg:
            replies.append(self.get_reply(
                "301", viewer, target=target.nickname, message=target.away_msg
            ))

        idle = int(time.time() - target.last_activity)
        replies.append(self.get_reply(
            "317", viewer, target=target.nickname, idle=idle,
            signon=target.signon_time
        ))

        if viewer.is_staff():
            ip_info = target.ip
            try:
                hostname = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, socket.gethostbyaddr, target.ip
                    ),
                    timeout=2.0
                )
                ip_info = f"{target.ip} ({hostname[0]})"
            except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
                pass
            replies.append(self.get_reply(
                "320", viewer, target=target.nickname, ip=ip_info
            ))

        replies.append(self.get_reply("318", viewer, target=target.nickname))
        return replies

    async def _remote_whois_timeout(self, request_id):
        """Expire a pending cross-server WHOIS lookup."""
        await asyncio.sleep(0.75)

        pending = self._pending_remote_whois.pop(request_id, None)
        if not pending:
            return

        user = pending['user']
        batch_id = pending['batch_id']
        if not pending.get('found'):
            await self.send_batched(user, batch_id, self.get_reply(
                "401", user, target=pending['target_nick']
            ))
            await self.send_batched(user, batch_id, self.get_reply(
                "318", user, target=pending['target_nick']
            ))
        await self.end_batch(user, batch_id)

    async def _start_remote_whois_lookup(self, user, batch_id, target_nick):
        """Dispatch a WHOIS lookup to linked servers and track the pending batch."""
        request_id = uuid.uuid4().hex[:8]
        timeout_task = asyncio.create_task(self._remote_whois_timeout(request_id))
        self._pending_remote_whois[request_id] = {
            'user': user,
            'batch_id': batch_id,
            'target_nick': target_nick,
            'found': False,
            'timeout_task': timeout_task,
        }
        await self.link_manager.broadcast_to_servers(
            f"WHOISREQ {request_id} {user.nickname} {target_nick}"
        )

    async def handle_remote_whois_reply(self, request_id, message):
        """Attach a routed WHOIS numeric to a pending local request."""
        pending = self._pending_remote_whois.get(request_id)
        if not pending:
            return False

        pending['found'] = True
        await self.send_batched(pending['user'], pending['batch_id'], message)
        return True

    async def handle_remote_whois_done(self, request_id, found=True):
        """Complete a pending routed WHOIS request."""
        pending = self._pending_remote_whois.pop(request_id, None)
        if not pending:
            return False

        timeout_task = pending.get('timeout_task')
        if timeout_task:
            timeout_task.cancel()

        user = pending['user']
        batch_id = pending['batch_id']
        if not found and not pending.get('found'):
            await self.send_batched(user, batch_id, self.get_reply(
                "401", user, target=pending['target_nick']
            ))
            await self.send_batched(user, batch_id, self.get_reply(
                "318", user, target=pending['target_nick']
            ))

        await self.end_batch(user, batch_id)
        return True

    def _service_target_names(self):
        """Return all nicknames and aliases that should dispatch to services."""
        targets = {
            'system', 'god',
            'registrar', 'messenger', 'newsflash',
            'nickserv', 'chanserv', 'memoserv',
            'servicebot',
        }
        targets.update(name.lower() for name in self.OTHER_SERVICES)
        bot_count = CONFIG.get('services', 'servicebot_count', default=10)
        for i in range(1, bot_count + 1):
            targets.add(f"servicebot{i:02d}")
        servicebots = getattr(self, 'servicebots', {})
        targets.update(bot.lower() for bot in servicebots.keys())
        return targets

    async def _dispatch_service_target(self, user, target, text):
        """Handle service-style targets using the same path for local and linked users."""
        target_lower = target.lower()

        if target_lower in ('system', 'god'):
            entity_name = 'System' if target_lower == 'system' else 'God'
            if not user.has_mode('a'):
                await self._mystical_entity_random_response(user, entity_name)
                return True
            await self._handle_mystical_entity(user, entity_name, text)
            return True

        if target_lower in ('registrar', 'nickserv', 'chanserv'):
            await self._handle_registrar_msg(user, text)
            return True

        if target_lower in ('messenger', 'memoserv'):
            await self._handle_messenger_msg(user, text)
            return True

        if target_lower == 'newsflash':
            await self._handle_newsflash_msg(user, text)
            return True

        if target_lower in self.OTHER_SERVICES:
            service_name = self.OTHER_SERVICES[target_lower]
            await self._send_service_msg(service_name, user, "svc_alias_title", service_name=service_name)
            await self._send_service_msg(service_name, user, "svc_alias_implemented")
            await self._send_service_msg(service_name, user, "svc_alias_available")
            await self._send_service_msg(service_name, user, "svc_alias_registrar")
            await self._send_service_msg(service_name, user, "svc_alias_chanserv")
            await self._send_service_msg(service_name, user, "svc_alias_messenger")
            await self._send_service_msg(service_name, user, "svc_alias_newsflash")
            await self._send_service_msg(service_name, user, "svc_alias_servicebot")
            await self._send_service_msg(service_name, user, "svc_alias_full_list")
            return True

        if target_lower == 'servicebot':
            await self._handle_servicebot_msg(user, text, "ServiceBot")
            return True

        for botname in getattr(self, 'servicebots', {}):
            if target_lower == botname.lower():
                await self._handle_servicebot_msg(user, text, botname)
                return True

        return False

    async def _join_virtual_service_to_channel(self, service_user, channel, chan_name):
        """Join a local virtual service to a channel and propagate that state cleanly."""
        channel.members[service_user.nickname] = service_user
        service_user.channels.add(chan_name)
        channel.owners.add(service_user.nickname)

        join_msg = f":{service_user.prefix()} JOIN {chan_name}"
        mode_msg = f":{self.servername} MODE {chan_name} +q {service_user.nickname}"

        local_tasks = []
        for member in channel.members.values():
            if not member.is_remote:
                local_tasks.append(member.send(join_msg))
        await asyncio.gather(*local_tasks, return_exceptions=True)

        local_mode_tasks = []
        for member in channel.members.values():
            if not member.is_remote:
                local_mode_tasks.append(member.send(mode_msg))
        await asyncio.gather(*local_mode_tasks, return_exceptions=True)

        if self.link_manager and self.link_manager.enabled:
            await self.link_manager.broadcast_to_servers(join_msg)
            await self.link_manager.broadcast_to_servers(mode_msg)

    def get_clone_original(self, channel_name):
        """Get the original channel for a potential clone name.
        Returns (original_channel, base_name) if found, or (None, None).
        E.g., #lobby1 -> returns (#lobby channel, "#lobby") if #lobby has +d mode.
        """
        # Check if name ends with digits (potential clone pattern)
        match = _CLONE_CHANNEL_PATTERN.match(channel_name)
        if not match:
            return None, None
        base_name = match.group(1)
        original, canon_name = self.get_channel(base_name)
        if original and original.is_clone_enabled():
            return original, canon_name
        return None, None

    def find_available_clone(self, original):
        """Find first non-full channel in the clone chain (original or its clones).
        Returns the channel to join, or None if all are full.
        Respects both channel +l limit and server-wide max_users_per_channel cap.
        """
        cap = self.max_users_per_channel
        # Check original first
        if not original.is_full() and len(original.members) < cap:
            return original
        # Check existing clones in order
        for clone_name in original.clone_children:
            clone, _ = self.get_channel(clone_name)
            if clone and not clone.is_full() and len(clone.members) < cap:
                return clone
        return None

    def create_clone(self, original):
        """Create a new clone of the original channel.
        Returns the new clone channel.
        """
        # Determine next clone index
        next_index = 1
        if original.clone_children:
            # Find the highest existing index and add 1
            for clone_name in original.clone_children:
                clone, _ = self.get_channel(clone_name)
                if clone:
                    next_index = max(next_index, clone.clone_index + 1)

        # Create clone channel name (e.g., #lobby1, #lobby2)
        clone_name = f"{original.name}{next_index}"

        # Create new channel
        clone = Channel(clone_name)

        # Copy properties from original
        clone.topic = original.topic
        clone.topic_set_by = original.topic_set_by
        clone.topic_set_at = original.topic_set_at
        clone.props = original.props.copy()
        clone.ban_list = original.ban_list.copy()
        clone.key = original.key
        clone.host_key = original.host_key
        clone.owner_key = original.owner_key
        clone.voice_key = original.voice_key
        clone.user_limit = original.user_limit

        # Copy modes (except +d, add +e)
        for mode, value in original.modes.items():
            if mode != 'd':  # Don't copy clone mode to clones
                clone.modes[mode] = value
        clone.modes['e'] = True   # Mark as clone
        clone.modes['d'] = False  # Clones cannot spawn clones

        # Set clone relationships
        clone.clone_parent = original.name
        clone.clone_index = next_index

        # Add to original's children list
        original.clone_children.append(clone_name)

        # Register the clone
        self.channels[clone_name] = clone
        self.channels_lower[clone_name.lower()] = clone_name

        return clone

    async def sync_mode_to_clones(self, original, mode, value, param=None):
        """Propagate a mode change from original to all its clones.
        Skips +d and +e modes.
        """
        if mode in ('d', 'e'):
            return

        for clone_name in original.clone_children:
            clone, _ = self.get_channel(clone_name)
            if not clone:
                continue

            # Apply the mode
            if mode == 'l':
                clone.user_limit = param if value else None
                clone.modes['l'] = value
            elif mode == 'k':
                clone.key = param if value else None
                clone.modes['k'] = value
            else:
                clone.modes[mode] = value

            # Broadcast mode change to clone members
            if clone.members:
                if param:
                    mode_str = f"+{mode} {param}" if value else f"-{mode}"
                else:
                    mode_str = f"+{mode}" if value else f"-{mode}"
                msg = f":{self.servername} MODE {clone_name} {mode_str}"
                await clone.broadcast(msg)

    def _create_virtual_service(self, nickname, ident, realname, is_admin=False, is_servicebot=False, omnipresent=False, divine=False):
        """Create a virtual service user"""
        service = User(None, None, is_virtual=True)
        service.nickname = nickname
        service.username = ident
        service.host = self.servername
        service.realname = realname
        service.staff_level = "ADMIN" if is_admin else "SERVICE"
        service.registered = True

        # Special modes for mystical entities
        if omnipresent:
            service.set_mode('S', True)  # System - omnipresent (undeclared, capital S)
        elif divine:
            service.set_mode('G', True)  # God - divine watcher (undeclared, capital G)
        else:
            service.set_mode('s', True)  # Regular service mode
        service.set_mode('b', True)  # Mark all services as bots

        if is_admin:
            service.set_mode('a', True)
            # Apply relaxed rate limits for admin services
            service.rate_limiter = RateLimiter(RateLimiter.STAFF_COOLDOWNS)
        if is_servicebot:
            service.max_channels = CONFIG.get('services', 'servicebot_max_channels', default=10)
            self.servicebots[nickname] = service  # Track servicebot
        self.users[nickname] = service
        self.users_lower[nickname.lower()] = nickname
        return service

    def _channel_has_servicebot(self, channel):
        """Check if a channel has at least one ServiceBot present"""
        if isinstance(channel, str):
            channel = self.channels.get(channel)
        if not channel:
            return False
        return any(nick in self.servicebots for nick in channel.members)

    def _get_channel_monitor(self, channel_name):
        """Get or create a monitor for a channel"""
        if channel_name not in self.channel_monitors:
            self.channel_monitors[channel_name] = ServiceBotMonitor()
        return self.channel_monitors[channel_name]

    def _reload_all_monitor_configs(self):
        """Reload config cache for all channel monitors (called when PROFANITY config changes)"""
        for monitor in self.channel_monitors.values():
            monitor.reload_config()
        # Track config cache reloads for performance monitoring
        self.stats['config_cache_reloads'] += 1

    def _get_servicebot_for_channel(self, channel):
        """Get the first ServiceBot in a channel (for sending messages)"""
        if isinstance(channel, str):
            channel = self.channels.get(channel)
        if not channel:
            return None
        for nick in channel.members:
            if nick in self.servicebots:
                return self.servicebots[nick]
        return None

    async def _servicebot_action(self, channel, user, violation_type, action, details):
        """
        Execute a ServiceBot action against a user.
        Actions: warn, gag, kick, ban
        """
        if not self.servicebot_enabled:
            return

        # Track violation and action
        if violation_type not in self.stats['servicebot_violations']:
            self.stats['servicebot_violations'][violation_type] = 0
        self.stats['servicebot_violations'][violation_type] += 1

        if action not in self.stats['servicebot_actions']:
            self.stats['servicebot_actions'][action] = 0
        self.stats['servicebot_actions'][action] += 1

        bot = self._get_servicebot_for_channel(channel)
        if not bot:
            return

        channel_name = channel.name if hasattr(channel, 'name') else channel
        channel = self.channels.get(channel_name) if isinstance(channel, str) else channel
        if not channel:
            return

        bot_prefix = f":{bot.nickname}!{bot.username}@{self.servername}"

        if action == "warn":
            warn_msg = CONFIG.get('servicebot', 'profanity_filter', 'warn_message',
                                 default="Please follow channel rules.")
            if violation_type == "profanity":
                warn_msg = CONFIG.get('servicebot', 'profanity_filter', 'warn_message',
                                     default="Please watch your language.")
            elif violation_type == "flood":
                warn_msg = SERVER_MESSAGES["rate_limit_flood"]
            elif violation_type == "caps":
                warn_msg = SERVER_MESSAGES["servicebot_warn_caps"]
            elif violation_type == "repeat":
                warn_msg = SERVER_MESSAGES["servicebot_warn_repeat"]
            elif violation_type == "url_spam":
                warn_msg = SERVER_MESSAGES["servicebot_warn_url_spam"]

            await user.send(f"{bot_prefix} NOTICE {user.nickname} :[{channel_name}] {warn_msg}")
            logger.info(get_log_message("servicebot_warned", bot=bot.nickname, user=user.nickname, channel=channel_name, violation=violation_type))

        elif action == "gag":
            if user.nickname not in channel.gagged:
                channel.gagged.add(user.nickname)
                user.set_mode('z', True)
                # Shadow ban - no notification to user or channel
                logger.info(get_log_message("servicebot_gagged", bot=bot.nickname, user=user.nickname, channel=channel_name, violation=violation_type))

        elif action == "kick":
            kick_reason = SERVER_MESSAGES['servicebot_kick_reason'].format(violation=violation_type)
            msg = f"{bot_prefix} KICK {channel_name} {user.nickname} :{kick_reason}"
            await channel.broadcast(msg)
            channel.members.pop(user.nickname, None)
            channel.owners.discard(user.nickname)
            channel.hosts.discard(user.nickname)
            channel.voices.discard(user.nickname)
            channel.gagged.discard(user.nickname)
            user.channels.discard(channel_name)
            logger.info(get_log_message("servicebot_kicked", bot=bot.nickname, user=user.nickname, channel=channel_name, violation=violation_type))

        elif action == "ban":
            # Add ban mask and kick
            ban_mask = f"*!*@{user.host}"
            if ban_mask not in channel.ban_list:
                channel.ban_list.append(ban_mask)
                ban_msg = f"{bot_prefix} MODE {channel_name} +b {ban_mask}"
                await channel.broadcast(ban_msg)

            kick_reason = SERVER_MESSAGES['servicebot_ban_reason'].format(violation=violation_type)
            kick_msg = f"{bot_prefix} KICK {channel_name} {user.nickname} :{kick_reason}"
            await channel.broadcast(kick_msg)
            channel.members.pop(user.nickname, None)
            channel.owners.discard(user.nickname)
            channel.hosts.discard(user.nickname)
            channel.voices.discard(user.nickname)
            channel.gagged.discard(user.nickname)
            user.channels.discard(channel_name)
            logger.info(get_log_message("servicebot_banned", bot=bot.nickname, user=user.nickname, channel=channel_name, violation=violation_type))

    async def _check_servicebot_violations(self, channel, user, text):
        """
        Check a message for violations if ServiceBot is present.
        Executes appropriate actions for violations found.
        """
        if not self.servicebot_enabled:
            return

        if not self._channel_has_servicebot(channel):
            return

        # Don't check messages from staff or services
        if user.is_privileged():
            return

        # Don't check virtual users
        if user.is_virtual:
            return

        monitor = self._get_channel_monitor(channel.name)
        violations = monitor.analyze_message(user.nickname, text)

        # Execute actions for violations (strongest action wins)
        action_priority = {'warn': 1, 'gag': 2, 'kick': 3, 'ban': 4}
        for violation_type, action, details in sorted(violations,
                                                       key=lambda x: action_priority.get(x[1], 0),
                                                       reverse=True):
            await self._servicebot_action(channel, user, violation_type, action, details)
            break  # Only execute the strongest action

    def log_transcript(self, channel, event_type, user, message=None, target=None):
        """
        Log an event to a channel's transcript file if +y mode is enabled.

        Args:
            channel: Channel object or channel name
            event_type: Type of event (MSG, NOTICE, JOIN, PART, KICK, TOPIC, MODE, etc.)
            user: User object who initiated the event
            message: Optional message content
            target: Optional target (for KICK, MODE changes)
        """
        if not CONFIG.get('transcript', 'enabled', default=True):
            return

        # Get channel object if string passed
        if isinstance(channel, str):
            channel = self.channels.get(channel)
        if not channel:
            return

        # Check if transcript mode is enabled for this channel
        if not channel.modes.get('y', False):
            return

        # Build the log entry
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        nick = user.nickname if hasattr(user, 'nickname') else str(user)

        if event_type == "MSG":
            entry = f"<{nick}> {message}"
        elif event_type == "NOTICE":
            entry = f"-{nick}- {message}"
        elif event_type == "ACTION":
            entry = f"* {nick} {message}"
        elif event_type == "JOIN":
            entry = f"*** {nick} ({user.username}@{user.host}) has joined {channel.name}"
        elif event_type == "PART":
            reason = f" ({message})" if message else ""
            entry = f"*** {nick} has left {channel.name}{reason}"
        elif event_type == "KICK":
            reason = f" ({message})" if message else ""
            entry = f"*** {target} was kicked by {nick}{reason}"
        elif event_type == "QUIT":
            reason = f" ({message})" if message else ""
            entry = f"*** {nick} has quit{reason}"
        elif event_type == "TOPIC":
            entry = f"*** {nick} changed the topic to: {message}"
        elif event_type == "MODE":
            entry = f"*** {nick} sets mode: {message}"
        elif event_type == "NICK":
            entry = f"*** {nick} is now known as {target}"
        else:
            entry = f"*** {event_type}: {nick} {message or ''}"

        log_line = f"[{timestamp}] {entry}"

        # Write to transcript file
        try:
            transcript_dir = Path(CONFIG.get('transcript', 'directory', default='transcripts'))
            transcript_dir.mkdir(parents=True, exist_ok=True)

            # Sanitize channel name for filename (remove # or &, replace unsafe chars)
            safe_name = channel.name.lstrip('#&').replace('/', '_').replace('\\', '_')
            transcript_file = transcript_dir / f"{safe_name}.log"

            with open(transcript_file, 'a', encoding='utf-8') as f:
                f.write(log_line + '\n')

        except Exception as e:
            if self.debug_mode:
                logger.error(get_log_message("transcript_write_error", channel=channel.name, error=e))

    def get_transcript(self, channel_name, lines=50, offset=0):
        """
        Get recent transcript lines for a channel.

        Args:
            channel_name: Channel name
            lines: Number of lines to retrieve (default 50)
            offset: Number of lines to skip from end (for pagination)

        Returns:
            List of transcript lines or empty list
        """
        try:
            transcript_dir = Path(CONFIG.get('transcript', 'directory', default='transcripts'))
            safe_name = channel_name.lstrip('#&').replace('/', '_').replace('\\', '_')
            transcript_file = transcript_dir / f"{safe_name}.log"

            if not transcript_file.exists():
                return []

            with open(transcript_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()

            # Get last N lines with offset
            if offset > 0:
                return all_lines[-(lines + offset):-offset]
            else:
                return all_lines[-lines:]

        except Exception as e:
            if self.debug_mode:
                logger.error(get_log_message("transcript_read_error", channel=channel_name, error=e))
            return []

    async def boot(self):
        logger.info(get_log_message("server_header"))
        logger.info(get_log_message("server_name", servername=self.servername))
        logger.info(get_log_message("server_network", network=self.network_name))
        logger.info(get_log_message("server_header"))

        # Validate config file permissions for security
        config_path = os.path.abspath(getattr(CONFIG, 'config_file', 'pyircx_config.json'))
        try:
            import stat
            st = os.stat(config_path)
            mode = st.st_mode
            if mode & stat.S_IROTH or mode & stat.S_IWOTH:
                logger.error(get_log_message("server_header"))
                logger.error(get_log_message("config_permissions_warning"))
                logger.error(get_log_message("config_file_info", file=config_path))
                logger.error(get_log_message("config_permissions_current", permissions=oct(stat.S_IMODE(mode))))
                logger.error(get_log_message("config_permissions_fix"))
                logger.error(get_log_message("server_header"))
            elif mode & stat.S_IRGRP or mode & stat.S_IWGRP:
                if os.path.abspath(config_path) == '/etc/pyircx/pyircx_config.json':
                    logger.info(get_log_message("config_group_readable", file=config_path))
                else:
                    logger.warning(get_log_message("config_group_readable", file=config_path))
        except FileNotFoundError:
            pass  # Using alternate config location
        except Exception as e:
            logger.warning(get_log_message("config_permissions_error", error=e))

        # Trunk and standalone servers both keep a local database. Branch
        # servers leave self.db_pool unset because services are centralized.
        if self.db_pool:
            async with self.db_pool.connection() as db:
                # Staff users table with all required columns
                await db.execute("""CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT,
                level TEXT,
                created_at INTEGER DEFAULT 0,
                last_login INTEGER DEFAULT 0,
                registered_nick TEXT,
                email TEXT,
                realname TEXT,
                force_realname INTEGER DEFAULT 0
            )""")

                # Create default admin account if no staff accounts exist
                async with db.execute("SELECT COUNT(*) FROM users") as cursor:
                    row = await cursor.fetchone()
                    if row[0] == 0:
                        default_user = CONFIG.get('admin', 'default_username', default='admin')
                        default_pass = CONFIG.get('admin', 'default_password', default='__CHANGE_ME__')
                        password_hash = await hash_password_async(default_pass)
                        await db.execute(
                            "INSERT INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                            (default_user, password_hash, 'ADMIN')
                        )
                        await db.commit()
                        logger.warning(get_log_message("default_admin_created", username=default_user))
                        logger.warning(get_log_message("default_admin_warning"))

                # Migrate users table schema (add missing columns for existing installations)
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN created_at INTEGER DEFAULT 0")
                except aiosqlite.OperationalError:
                    pass  # Column already exists
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN last_login INTEGER DEFAULT 0")
                except aiosqlite.OperationalError:
                    pass  # Column already exists
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN registered_nick TEXT")
                except aiosqlite.OperationalError:
                    pass  # Column already exists
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN email TEXT")
                except aiosqlite.OperationalError:
                    pass  # Column already exists
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN realname TEXT")
                except aiosqlite.OperationalError:
                    pass  # Column already exists
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN force_realname INTEGER DEFAULT 0")
                except aiosqlite.OperationalError:
                    pass  # Column already exists
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")
                except aiosqlite.OperationalError:
                    pass  # Column already exists
                try:
                    await db.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
                except aiosqlite.OperationalError:
                    pass  # Column already exists

                # Registered nicknames with UUID and MFA
                await db.execute("""CREATE TABLE IF NOT EXISTS registered_nicks (
                uuid TEXT PRIMARY KEY,
                nickname TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                registered_at INTEGER,
                last_seen INTEGER,
                mfa_enabled INTEGER DEFAULT 0,
                mfa_secret TEXT,
                registered_by TEXT
                )""")

                # Registered channels with UUID
                await db.execute("""CREATE TABLE IF NOT EXISTS registered_channels (
                    uuid TEXT PRIMARY KEY,
                    channel_name TEXT UNIQUE NOT NULL,
                    owner_uuid TEXT,
                    registered_at INTEGER,
                    last_used INTEGER,
                    description TEXT,
                    properties TEXT,
                    FOREIGN KEY (owner_uuid) REFERENCES registered_nicks(uuid)
                )""")

                # Server access rules
                await db.execute("""CREATE TABLE IF NOT EXISTS server_access (
                    id INTEGER PRIMARY KEY,
                    type TEXT,
                    pattern TEXT,
                    set_by TEXT,
                    set_at INTEGER,
                    reason TEXT,
                    timeout INTEGER DEFAULT 0
                )""")

                # Messenger mailbox
                await db.execute("""CREATE TABLE IF NOT EXISTS mailbox (
                    id INTEGER PRIMARY KEY,
                    recipient_uuid TEXT,
                    sender_nick TEXT,
                    message TEXT,
                    sent_at INTEGER,
                    read INTEGER DEFAULT 0,
                    FOREIGN KEY (recipient_uuid) REFERENCES registered_nicks(uuid)
                )""")

                # NewsFlash rotating messages
                await db.execute("""CREATE TABLE IF NOT EXISTS newsflash (
                    id INTEGER PRIMARY KEY,
                    message TEXT NOT NULL,
                    priority INTEGER DEFAULT 0,
                    active INTEGER DEFAULT 1,
                    created_by TEXT,
                    created_at INTEGER,
                    expires_at INTEGER
                )""")

                # Memos (offline messaging via MEMO command)
                await db.execute("""CREATE TABLE IF NOT EXISTS memos (
                    id INTEGER PRIMARY KEY,
                    recipient TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    message TEXT NOT NULL,
                    sent_at INTEGER,
                    read INTEGER DEFAULT 0
                )""")

                # Recent completed client sessions for staff LASTLOGONS.
                await db.execute("""CREATE TABLE IF NOT EXISTS connection_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nickname TEXT NOT NULL,
                    username TEXT NOT NULL,
                    realname TEXT,
                    ip_address TEXT,
                    host TEXT,
                    logon_time INTEGER NOT NULL,
                    logout_time INTEGER NOT NULL,
                    duration INTEGER NOT NULL,
                    reason TEXT
                )""")

                # Create indexes for performance optimization
                # Nickname lookups (IDENTIFY, registration checks)
                await db.execute("CREATE INDEX IF NOT EXISTS idx_reg_nicks_nickname ON registered_nicks(nickname)")
                # Channel registration lookups
                await db.execute("CREATE INDEX IF NOT EXISTS idx_reg_chans_name ON registered_channels(channel_name)")
                # Offline message lookups by recipient
                await db.execute("CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox(recipient_uuid)")
                # Memo lookups by recipient
                await db.execute("CREATE INDEX IF NOT EXISTS idx_memos_recipient ON memos(recipient)")
                # Staff user lookups
                await db.execute("CREATE INDEX IF NOT EXISTS idx_staff_username ON users(username)")
                # Access list pattern lookups
                await db.execute("CREATE INDEX IF NOT EXISTS idx_access_pattern ON server_access(pattern)")
                # LASTLOGONS query/filter support
                await db.execute("CREATE INDEX IF NOT EXISTS idx_connection_sessions_logon ON connection_sessions(logon_time)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_connection_sessions_nick ON connection_sessions(nickname)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_connection_sessions_user ON connection_sessions(username)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_connection_sessions_ip ON connection_sessions(ip_address)")

                await db.commit()
                logger.info(get_log_message("db_initialized"))
        else:
            logger.info(get_log_message("db_skipped"))

        # Load ACCESS list (branches will have empty list until synced)
        await self._load_access_list()

        # Channels are now dynamic - only loaded when users join
        # Registered channels restore their properties from registered_channels table

        # Check if we should create local services
        services_enabled = CONFIG.get('services', 'enabled', default=True)
        services_mode = self.services_mode
        is_services_hub = self.is_services_hub

        # Only create services if:
        # 1. Services are globally enabled, AND
        # 2. We're in "local" mode OR we're designated as the services hub
        should_create_services = services_enabled and (services_mode == 'local' or is_services_hub)

        if should_create_services:
            self.channels["#System"] = Channel("#System")
            self.channels_lower["#system"] = "#System"
            self.channels["#System"].registered = True
            self.channels["#System"].account_uuid = str(uuid.uuid4())

            # Create System virtual user (omnipresent)
            sys_user = self._create_virtual_service('System', 'System', "System", omnipresent=True)
            logger.info(get_log_message("system_channel_created"))

            # Create God virtual user (omniscient watcher)
            god_user = self._create_virtual_service('God', 'God', "God", divine=True)
            self.users[god_user.nickname] = god_user
            logger.info(get_log_message("god_user_created"))

            # Create Registrar service - handles nick/channel registration
            registrar = self._create_virtual_service('Registrar', 'Registrar', "Registration Services")
            logger.info(get_log_message("registrar_created"))

            # Create Messenger service - handles mailbox and global messages
            messenger = self._create_virtual_service('Messenger', 'Messenger', "Message Services")
            logger.info(get_log_message("messenger_created"))

            # Create NewsFlash alias - part of Messenger for rotating/push messages
            newsflash = self._create_virtual_service('NewsFlash', 'NewsFlash', "News Broadcast Services")
            logger.info(get_log_message("newsflash_created"))

            # Create ServiceBots - configurable count
            self.servicebots = {}
            bot_count = CONFIG.get('services', 'servicebot_count', default=10)
            for i in range(1, bot_count + 1):
                bot_name = f"ServiceBot{i:02d}"
                bot = self._create_virtual_service(bot_name, 'ServiceBot', f"Service Bot #{i}", is_servicebot=True)
                self.servicebots[bot_name] = bot
            logger.info(get_log_message("servicebots_created", count=bot_count))

            # Create ServiceBot dispatcher - virtual user that routes to available bots
            servicebot_dispatcher = self._create_virtual_service('ServiceBot', 'ServiceBot', "ServiceBot Pool Dispatcher")
            logger.info(get_log_message("servicebot_dispatcher_created"))

            logger.info(get_log_message("services_initialized", mode=services_mode) +
                       (get_log_message("services_with_hub") if is_services_hub else ""))
        else:
            # No local services - we're a branch server in centralized mode
            self.servicebots = {}
            if services_mode == 'centralized' and not is_services_hub:
                logger.info(get_log_message("services_disabled_branch"))
                logger.info(get_log_message("services_trunk_info", trunk=CONFIG.get('services', 'hub_server', default='(not configured)')))
            elif not services_enabled:
                logger.info(get_log_message("services_disabled"))
            else:
                logger.warning(get_log_message("services_config_error"))

        # Initialize DNSBL and connection security checkers
        global DNSBL_CHECKER, PROXY_DETECTOR, CONNECTION_SCORER
        DNSBL_CHECKER = DNSBLChecker()
        PROXY_DETECTOR = ProxyDetector()
        CONNECTION_SCORER = ConnectionScorer(DNSBL_CHECKER, PROXY_DETECTOR)
        if CONFIG.get('security', 'dnsbl', 'enabled', default=False):
            logger.info(get_log_message("dnsbl_enabled"))
        if CONFIG.get('security', 'proxy_detection', 'enabled', default=False):
            logger.info(get_log_message("proxy_detection_enabled"))
        if CONFIG.get('security', 'connection_scoring', 'enabled', default=False):
            logger.info(get_log_message("connection_scoring_enabled"))

        # Removed: periodic_save - channels now persist on registration, not periodically

        # Initialize database connection pool (trunk only)
        if self.db_pool:
            await self.db_pool.initialize()
            logger.info(get_log_message("db_pool_initialized"))

        # Start CAP timeout monitor
        self.cap_timeout_task = asyncio.create_task(self._cap_timeout_monitor())
        logger.info(get_log_message("cap_monitor_started", timeout=self.cap_timeout))

    async def _load_access_list(self):
        """Load server-wide ACCESS rules from database (trunk only)"""
        server_role = CONFIG.get('linking', 'server_role', default='trunk')

        # Branches don't load from database - they keep ACCESS in-memory only
        if server_role == 'branch':
            logger.info(get_log_message("access_in_memory"))
            return

        # Trunk loads from database
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT type, pattern, set_by, set_at, COALESCE(timeout, 0), reason FROM server_access") as cursor:
                    now = int(time.time())
                    async for row in cursor:
                        access_type, pattern, set_by, set_at, timeout, reason = row
                        # Skip expired entries
                        if timeout > 0 and now >= timeout:
                            continue
                        if access_type in self.access_list:
                            self.access_list[access_type].append((pattern, set_by, set_at, timeout, reason or ""))
            grant_count = len(self.access_list['GRANT'])
            deny_count = len(self.access_list['DENY'])
            if grant_count or deny_count:
                logger.info(get_log_message("access_loaded", grant=grant_count, deny=deny_count))
        except Exception as e:
            logger.error(get_log_message("access_load_error", error=e))

    async def load_registered_channel(self, channel_name):
        """Load a registered channel from database if it exists"""
        if not self.db_pool:
            return None
        try:
            async with self.db_pool.connection() as db:
                # Check registered_channels table
                async with db.execute("SELECT uuid, owner_uuid, properties FROM registered_channels WHERE LOWER(channel_name) = LOWER(?)", (channel_name,)) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        # Create a new channel object and mark it as registered
                        channel = Channel(channel_name)
                        channel.registered = True
                        channel.account_uuid = row[0]
                        channel.modes['r'] = True  # Set +r mode for registered channels
                        # Load saved properties (owners, hosts, voices, ACCESS, topic, keys, etc.)
                        channel.load_properties_json(row[2])
                        logger.info(get_log_message("channel_loaded", channel=channel.name))
                        return channel
        except Exception as e:
            logger.error(get_log_message("channel_load_error", channel=channel_name, error=e))
        return None

    # Removed: load_channels(), save_channels(), periodic_save() - channels are now dynamic

    async def _cap_timeout_monitor(self):
        """Monitor for clients stuck in CAP negotiation and disconnect them"""
        while True:
            await asyncio.sleep(10)  # Check every 10 seconds
            now = time.time()
            timed_out = []

            for nickname, user in list(self.users.items()):
                if user.cap_negotiating and user.cap_start_time:
                    if now - user.cap_start_time > self.cap_timeout:
                        timed_out.append(user)

            for user in timed_out:
                try:
                    await user.send(f"ERROR :{SERVER_MESSAGES['error_cap_timeout'].format(timeout=self.cap_timeout)}")
                    logger.warning(get_log_message("cap_timeout", ip=user.ip))
                    await self.quit_user(user)
                except Exception as e:
                    logger.error(get_log_message("cap_timeout_error", error=e))

    def get_reply(self, code, recipient, **kwargs):
        template = RESPONSES.get(code, f"{code} :Unknown")
        params = {
            "nick": recipient.nickname,
            "servername": self.servername,
            "network": CONFIG.get('server', 'network', default='IRC Network'),
            "network_name": CONFIG.get('server', 'network', default='IRC').replace(' ', '-'),
            "version": __version__,
            "version_label": __version_label__,
            "created_date": __created__,
            # User modes (from modes module or config override)
            "usermodes": CONFIG.get('modes', 'user', default=modes_module.USER_MODES_STR),
            # Channel modes (from modes module or config override)
            "chanmodes": CONFIG.get('modes', 'channel', default=modes_module.CHANNEL_MODES_STR),
            # CHANMODES parameter (IRCv3 format: A,B,C,D)
            "chanmodes_param": modes_module.CHANMODES_PARAM,
            "max_modes": CONFIG.get('limits', 'max_modes_per_command', default=6),
            "uptime": int(time.time() - self.boot_time),
            "loc1": CONFIG.get('admin', 'loc1', default=''),
            "loc2": CONFIG.get('admin', 'loc2', default=''),
            "email": CONFIG.get('admin', 'email', default=''),
            "server_count": 1,
            "max_users": self.max_users_seen,
            "nicklen": CONFIG.get('limits', 'max_nick_length', default=30),
            "userlen": CONFIG.get('limits', 'max_user_length', default=30),
            "chanlen": CONFIG.get('limits', 'max_channel_length', default=50),
            "topiclen": CONFIG.get('limits', 'max_topic_length', default=390),
            "awaylen": CONFIG.get('limits', 'max_away_length', default=200),
            "kicklen": CONFIG.get('limits', 'max_kick_length', default=390),
            "monitorlen": CONFIG.get('limits', 'max_monitor', default=100),
            "silencelen": CONFIG.get('limits', 'max_silence', default=100),
            "maxtargets": CONFIG.get('limits', 'max_targets', default=1),
            "max_chathistory": CONFIG.get('limits', 'max_chathistory', default=100),
            **kwargs
        }
        try:
            txt = template.format(**params)
            if code == "800":
                return f":{self.servername} 800 {recipient.nickname if recipient.registered else '*'} {txt}"
            no_colon = [
                "005", "006", "007", "219", "252", "253", "254", "256", "257", "258", "259", "265", "266", "271", "272", "301", "303", "307", "311", "312", "313", "314", "315", "317",
                "318", "319", "320", "321", "322", "324", "331", "332", "335", "351", "352", "353", "364", "365", "366", "367", "368", "369", "371", "374", "382", "391", "401", "403", "404", "407",
                "421", "432", "433", "441", "442", "443", "461", "468", "471", "473", "474", "475", "479", "482", "600", "601", "602", "604", "605", "606", "607",
                "696", "710", "711", "712", "713", "714", "716", "760", "761", "762", "763", "764", "765", "766", "803", "804", "805", "811", "812", "817", "818", "819", "820", "821", "822", "823", "824", "825", "830",
                "831", "832", "833", "834", "835", "840", "841", "842", "843", "844", "845", "846", "847", "848", "850", "851", "852", "853", "854", "855",
                "856", "857", "858", "859", "860", "861", "862", "863", "864", "865", "866", "867", "868", "869", "870", "871", "872", "873",
                "877", "878", "879", "880", "881", "882", "884", "885", "886", "887", "888", "889", "890", "891", "892", "893", "894", "895",
                "896", "897", "898", "899", "900", "908", "910", "911", "912", "913", "914", "915",
                "916", "917", "918", "919", "920", "921", "922", "923", "924", "925", "926", "927", "928", "929", "930", "931", "932", "933", "940", "941", "942", "943", "960", "961", "962", "963", "964", "965", "970", "971",
                "972", "973", "974", "975", "976", "977", "978"
            ]
            if code == "433":
                return f":{self.servername} 433 {recipient.nickname if recipient.nickname != '*' else '*'} {txt}"
            if code == "710":
                return f":{self.servername} 710 {txt}"
            sep = " " if code in no_colon else " :"
            return f":{self.servername} {code} {recipient.nickname}{sep}{txt}"
        except Exception as e:
            logger.error(get_log_message("reply_error", code=code, error=e))
            return f":{self.servername} 500 {recipient.nickname} :Format Error"

    async def send_notice(self, user, message_key, **kwargs):
        """
        Send a NOTICE using centralized messages from SERVER_MESSAGES.

        Args:
            user: Recipient user object
            message_key: Key in SERVER_MESSAGES dict
            **kwargs: Template variables for formatting

        Usage:
            await self.send_notice(user, "broadcast_sent", type="PRIVMSG", count=5, server="irc.example.com")
        """
        # Try SERVER_MESSAGES first (text templates)
        if message_key in SERVER_MESSAGES:
            try:
                message = SERVER_MESSAGES[message_key].format(**kwargs)
                await user.send(f":{self.servername} NOTICE {user.nickname} :{message}")
            except KeyError as e:
                logger.error(get_log_message("template_error", key=message_key, error=e))
                await user.send(f":{self.servername} NOTICE {user.nickname} :{SERVER_MESSAGES['msg_format_invalid']}")
        else:
            logger.error(get_log_message("unknown_message_key", key=message_key))
            await user.send(f":{self.servername} NOTICE {user.nickname} :{SERVER_MESSAGES['internal_error']}")

    async def send_server_message(self, user, message_key, msg_type=None, **kwargs):
        """
        Send a server message with configurable NOTICE/PRIVMSG type.

        Args:
            user: Recipient user object
            message_key: Key in SERVER_MESSAGES dict
            msg_type: Optional explicit 'NOTICE' or 'PRIVMSG', defaults to config-based
            **kwargs: Template variables for formatting

        Usage:
            await self.send_server_message(user, "staff_pass_old_required")
        """
        from responses import get_message_type

        # Determine message type from config if not explicitly specified
        if msg_type is None:
            msg_type = get_message_type(message_key, CONFIG.data)

        if message_key in SERVER_MESSAGES:
            try:
                message = SERVER_MESSAGES[message_key].format(**kwargs)
                await user.send(f":{self.servername} {msg_type} {user.nickname} :{message}")
            except KeyError as e:
                logger.error(get_log_message("template_error", key=message_key, error=e))
                await user.send(f":{self.servername} {msg_type} {user.nickname} :{SERVER_MESSAGES['msg_format_invalid']}")
        else:
            logger.error(get_log_message("unknown_message_key", key=message_key))
            await user.send(f":{self.servername} {msg_type} {user.nickname} :{SERVER_MESSAGES['internal_error']}")

    async def send_multi_line(self, user, message_keys, msg_type=None, **kwargs):
        """
        Send multiple server messages with optional shared format variables.

        Args:
            user: Recipient user object
            message_keys: List of keys in SERVER_MESSAGES dict
            msg_type: Optional explicit 'NOTICE' or 'PRIVMSG'
            **kwargs: Template variables for formatting (applied to all messages)

        Usage:
            await self.send_multi_line(user, ["stats_help_header", "stats_help_general_u", ...])
        """
        for key in message_keys:
            await self.send_server_message(user, key, msg_type=msg_type, **kwargs)

    async def send_raw_notice(self, user, text):
        """
        Send a raw NOTICE with custom text. Use sparingly - prefer send_server_message.

        Args:
            user: Recipient user object
            text: Raw text to send
        """
        await user.send(f":{self.servername} NOTICE {user.nickname} :{text}")

    def _strip_formatting(self, text):
        """Strip mIRC/IRC formatting codes from text (for +f channels)"""
        # Remove color codes: ^C followed by optional fg,bg numbers
        text = _FORMATTING_PATTERN.sub('', text)
        # Remove bold, italic, underline, reverse, reset codes
        for code in ['\x02', '\x1D', '\x1F', '\x16', '\x0F']:
            text = text.replace(code, '')
        return text

    # =========================================================================
    # DATABASE HELPER METHODS (consolidate duplicate queries)
    # =========================================================================

    async def _get_nick_uuid(self, nickname):
        """Get UUID for a registered nickname. Returns None if not found."""
        async with self.db_pool.connection() as db:
            async with db.execute(
                "SELECT uuid FROM registered_nicks WHERE nickname = ?", (nickname,)
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else None

    async def _get_mfa_state(self, nickname):
        """Get MFA state for a registered nickname.
        Returns (mfa_enabled, mfa_secret) tuple or (None, None) if not found."""
        async with self.db_pool.connection() as db:
            async with db.execute(
                "SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                (nickname,)
            ) as cursor:
                row = await cursor.fetchone()
                return (row[0], row[1]) if row else (None, None)

    async def _get_db_stats(self):
        """Get database statistics. Returns dict with counts."""
        stats = {'nicks': 0, 'channels': 0, 'messages': 0}
        async with self.db_pool.connection() as db:
            async with db.execute("SELECT COUNT(*) FROM registered_nicks") as cursor:
                row = await cursor.fetchone()
                stats['nicks'] = row[0] if row else 0
            async with db.execute("SELECT COUNT(*) FROM registered_channels") as cursor:
                row = await cursor.fetchone()
                stats['channels'] = row[0] if row else 0
            async with db.execute("SELECT COUNT(*) FROM mailbox") as cursor:
                row = await cursor.fetchone()
                stats['messages'] = row[0] if row else 0
        return stats

    async def _update_nick_last_seen(self, nickname):
        """Update last_seen timestamp for a registered nickname."""
        async with self.db_pool.connection() as db:
            await db.execute(
                "UPDATE registered_nicks SET last_seen = ? WHERE nickname = ?",
                (int(time.time()), nickname)
            )
            await db.commit()

    async def fire_trap(self, cls, action, user, channel_name=None):
        """Fire event notification to subscribed administrators/operators

        Events are sent to users with +a (admin) or +o (operator) who have
        matching traps subscribed. SOCKET events are never fired.
        """
        # SOCKET events are accepted but never fired
        if cls == 'SOCKET':
            return

        ts = int(time.time())
        # EVENTs go to staff only - show real unmasked host
        unmasked_prefix = f"{user.nickname}!{user.username}@{user.host}"
        channel_part = channel_name if channel_name else ""
        ip_port = f"{user.ip}:{user.port}"

        for admin in self.users.values():
            # Only send to IRC operators and administrators
            if admin.is_high_staff():
                for t_cls, t_mask in admin.traps:
                    # Skip SOCKET traps (they never match)
                    if t_cls == 'SOCKET':
                        continue
                    # Match against unmasked prefix (EVENTs always show real host)
                    if t_cls == cls and fnmatch.fnmatch(unmasked_prefix, t_mask):
                        # Send as numeric 814 for better client compatibility
                        await admin.send(self.get_reply("814", admin,
                            servername=self.servername,
                            timestamp=ts,
                            cls=cls,
                            action=action,
                            channel=channel_part,
                            user_prefix=unmasked_prefix,
                            ip_port=ip_port,
                            data="0.0.0.0:0"))
                        break

    async def log_staff(self, staff_nick, action, target, details="None"):
        """Log staff actions to the server log only (no #System relay)"""
        log_raw = RESPONSES['STAFF_LOG'].format(
            action=action, staff=staff_nick, target=target, details=details)
        logger.info(get_log_message("staff_log", message=log_raw))

# Continuing pyIRCXServer class...

    async def handle_client(self, reader, writer):
        user = User(reader, writer)

        # Check server-level IP ban
        if user.ip in self.server_bans:
            expires_at, reason, set_by = self.server_bans[user.ip]
            # Check if ban has expired
            if expires_at > 0 and time.time() > expires_at:
                # Ban expired, remove it
                del self.server_bans[user.ip]
            else:
                # Ban is still active, refuse connection
                logger.warning(get_log_message("banned_connection", ip=user.ip, reason=reason))
                try:
                    writer.write(f"ERROR :{SERVER_MESSAGES['error_banned'].format(reason=reason)}\r\n".encode('utf-8'))
                    await writer.drain()
                except Exception:
                    pass
                writer.close()
                await writer.wait_closed()
                return

        if CONFIG.get('security', 'enable_connection_throttle', default=True):
            if not self.connection_throttle.check(user.ip):
                logger.warning(get_log_message("throttled_connection", ip=user.ip))
                writer.close()
                await writer.wait_closed()
                return

        if len(self.users) >= self.max_users:
            logger.warning(get_log_message("max_users_reached"))
            writer.close()
            await writer.wait_closed()
            return

        # Resolve hostname from IP address
        user.host = await self.resolve_hostname(user.ip)

        # DNSBL check - reject known bad IPs
        if DNSBL_CHECKER:
            should_reject, reject_msg = await DNSBL_CHECKER.check_and_act(user.ip, writer)
            if should_reject:
                try:
                    writer.write(f"ERROR :{reject_msg}\r\n".encode('utf-8'))
                    await writer.drain()
                except Exception:
                    pass
                writer.close()
                await writer.wait_closed()
                return

            # Check if IP is listed (for marking, even if not rejecting)
            is_listed, listed_on = await DNSBL_CHECKER.check_ip(user.ip)
            if is_listed:
                user.dnsbl_listed = listed_on

        # Connection scoring (if enabled)
        if CONNECTION_SCORER:
            score, factors = await CONNECTION_SCORER.score_connection(user.ip, user.host)
            if score > 0:
                user.connection_score = score
                user.connection_factors = factors
                if CONNECTION_SCORER.should_reject(score):
                    logger.warning(get_log_message("connection_score_exceeded", score=score, ip=user.ip))
                    try:
                        writer.write(f"ERROR :{SERVER_MESSAGES['error_risk_score']}\r\n".encode('utf-8'))
                        await writer.drain()
                    except Exception:
                        pass
                    writer.close()
                    await writer.wait_closed()
                    return

        self.stats['total_connections'] += 1
        self.max_users_seen = max(self.max_users_seen, len(self.users))

        # Track peak users
        current_users = sum(1 for u in self.users.values() if not u.is_virtual)
        if current_users > self.stats['peak_users']:
            self.stats['peak_users'] = current_users
            self.stats['peak_time'] = int(time.time())

        try:
            while True:
                # Add timeout to prevent ghost connections from dead clients
                # Clients should send data (including PING/PONG) regularly
                client_timeout = CONFIG.get('limits', 'client_timeout', default=300)
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=float(client_timeout))
                except asyncio.TimeoutError:
                    logger.info(get_log_message("client_timeout", timeout=client_timeout, nickname=user.nickname, ip=user.ip))
                    break

                if not line:
                    break
                raw = line.decode('utf-8', errors='replace').strip()
                if not raw:
                    continue
                if self.debug_mode:
                    logger.debug(get_log_message("client_debug", nickname=user.nickname, data=raw))
                await self.dispatch(user, raw)
                # Check if user has been disconnected (QUIT, KILL, etc.)
                # Works for all user types: registered, unregistered, CAP negotiation
                if user.disconnected:
                    break
                # Flush write buffer to prevent backpressure
                try:
                    await writer.drain()
                except (ConnectionResetError, BrokenPipeError, OSError):
                    break
        except Exception as e:
            if self.debug_mode:
                logger.error(get_log_message("client_error", nickname=user.nickname, error=e))
                logger.error(get_log_message("client_traceback", traceback=traceback.format_exc()))
        finally:
            await self.quit_user(user)

    async def dispatch(self, user, raw):
        """
        Route IRC commands to their appropriate handlers.

        This method parses incoming IRC commands and dispatches them to the
        appropriate handler methods using a routing table for maintainability.
        """
        tags = {}

        # Parse IRCv3 message tags (@key=value;key2=value2)
        if raw.startswith('@'):
            tag_end = raw.find(' ')
            if tag_end == -1 or tag_end > 8191:
                return  # Malformed or oversized tags
            tag_str = raw[1:tag_end]
            raw = raw[tag_end + 1:]
            for tag in tag_str.split(';'):
                if '=' in tag:
                    k, v = tag.split('=', 1)
                    tags[k] = _unescape_tag_value(v)
                else:
                    tags[tag] = None

        user._msg_tags = tags

        parts = raw.split(' :', 1)
        args = parts[0].split()
        if not args:
            return
        cmd = args[0].upper()
        params = args[1:]
        if len(parts) > 1:
            params.append(parts[1])

        # Map alias to full command (uses class-level constant)
        if cmd in self.COMMAND_ALIASES:
            cmd = self.COMMAND_ALIASES[cmd]

        user.last_activity = int(time.time())
        self.stats['commands_processed'] += 1

        # Track individual command usage (only valid ASCII commands to avoid garbage in stats)
        if cmd.isascii() and cmd.isalnum():
            self.stats['command_usage'][cmd] = self.stats['command_usage'].get(cmd, 0) + 1

        # Track per-user activity for historical trends
        username = user.username_clean  # Pre-stripped in User class
        self.stats['most_active_users'][username] = self.stats['most_active_users'].get(username, 0) + 1

        # Track per-minute command rate
        current_minute = int(time.time() / 60)
        if current_minute != self.stats['last_minute_reset']:
            # New minute - save previous minute's count and reset
            self.stats['commands_per_minute'].append(self.stats['current_minute_commands'])
            self.stats['current_minute_commands'] = 0
            self.stats['last_minute_reset'] = current_minute
        self.stats['current_minute_commands'] += 1

        # Flood protection - only apply to message commands (uses class-level frozenset)
        is_service = user.has_mode('s')

        if cmd in self.MESSAGE_COMMANDS and user.registered and not is_service:
            if self.flood_protection:
                flood_ok = user.check_flood()
                if not flood_ok:
                    self.stats['flood_events'] += 1
                    await user.send(self.get_reply("834", user))
                    logger.warning(get_log_message("flood_triggered", nickname=user.nickname))
                    return

        # ====================================================================
        # PRE-REGISTRATION COMMANDS (processed before registration check)
        # ====================================================================

        if cmd == "CAP":
            await self.handle_cap(user, params)
            return
        elif cmd == "AUTHENTICATE":
            await self.handle_authenticate(user, params)
            return
        elif cmd == "PASS":
            user.provided_pass = params[0].lstrip(':') if params else None
            return
        elif cmd in ["IRCX", "ISIRCX"]:
            user.is_ircx = True
            user.set_mode('x', True)
            # Return SYST for staff, AUTH if authenticated, ANON if anonymous
            if user.is_staff():
                auth_status = "SYST"
            elif user.authenticated:
                auth_status = "AUTH"
            else:
                auth_status = "ANON"
            await user.send(self.get_reply("800", user, auth_status=auth_status))
            return
        elif cmd == "PING":
            await user.send(
                f":{self.servername} PONG {self.servername} :{params[0] if params else ''}")
            return
        elif cmd == "WEBIRC":
            await self.handle_webirc(user, params)
            return
        elif cmd == "NICK":
            await self.handle_nick(user, params)
            return
        elif cmd == "USER":
            await self.handle_user(user, params)
            return

        # ====================================================================
        # REGISTRATION CHECK - all commands below require registered user
        # ====================================================================

        if not user.registered:
            if cmd not in ["NICK", "USER", "PASS", "IRCX", "ISIRCX", "PING", "WEBIRC"]:
                await user.send(self.get_reply("451", user))
            return

        # ====================================================================
        # MFA CHECK - restrict commands until MFA verification is complete
        # ====================================================================

        if user.pending_mfa:
            allowed_during_mfa = ["PING", "PONG", "QUIT"]
            # Allow PRIVMSG only to Registrar for MFA VERIFY command
            if cmd == "PRIVMSG" and params and params[0].lower() == "registrar":
                pass  # Allow
            elif cmd not in allowed_during_mfa:
                await self.send_server_message(user, "mfa_pending_registrar")
                return

        # ====================================================================
        # IRCv3 LABELED-RESPONSE SETUP
        # ====================================================================

        label = tags.get('label') if 'labeled-response' in user.enabled_caps else None
        user._label = label
        user._label_batch_id = None
        user._label_sent = False
        if label and 'batch' in user.enabled_caps:
            label_batch_id = self._generate_batch_id()
            await user.send(f"@label={_escape_tag_value(label)} :{self.servername} BATCH +{label_batch_id} labeled-response")
            user._label_batch_id = label_batch_id

        try:
            await self._dispatch_command(user, cmd, params)
        finally:
            if label:
                if user._label_batch_id:
                    await user.send(f":{self.servername} BATCH -{user._label_batch_id}")
                elif not user._label_sent:
                    await user.send(f"@label={_escape_tag_value(label)} :{self.servername} ACK")
                user._label_batch_id = None
                user._label = None
                user._label_sent = False

    async def _dispatch_command(self, user, cmd, params):
        """Execute a post-registration command (separated for labeled-response wrapping)."""

        # ====================================================================
        # COMMANDS WITH SPECIAL HANDLING (need custom logic before routing)
        # ====================================================================

        if cmd == "JOIN":
            if not params:
                await user.send(self.get_reply("461", user, command=cmd))
                return
            channels = params[0].split(',')
            keys = params[1].split(',') if len(params) > 1 else []
            for idx, channel_name in enumerate(channels):
                channel_name = channel_name.strip()
                if channel_name:
                    key = keys[idx].strip() if idx < len(keys) else None
                    await self.handle_join(user, channel_name, key)
            return

        elif cmd == "PART":
            if not params:
                await user.send(self.get_reply("461", user, command=cmd))
                return
            for t in params[0].split(','):
                t = t.strip()
                if t:
                    await self.handle_part(user, t)
            return

        elif cmd in ["LIST", "LISTX"]:
            pattern = params[0] if params else None
            await self.handle_list(user, cmd == "LISTX", pattern)
            return

        elif cmd == "TIME":
            await user.send(self.get_reply("391", user, time=time.ctime()))
            return

        elif cmd == "VERSION":
            await user.send(self.get_reply("351", user))
            return

        elif cmd == "JEDI":
            # Undocumented easter egg - God's response
            if "God" in self.users:
                await self._send_service_msg("God", user, "easter_jedi")
            return

        elif cmd == "WALLOPS":
            # Undocumented easter egg - System complains about violence
            if "System" in self.users:
                await self._send_service_msg("System", user, "easter_wallops")
            return

        elif cmd == "JOKE":
            # Undocumented easter egg - Random clean jokes
            import random
            joke = random.choice(EASTER_EGG_JOKES)
            await user.send(f":{self.servername} NOTICE {user.nickname} :{joke}")
            return

        elif cmd in ["DATA", "REQUEST", "REPLY"]:
            await self.handle_data(user, params, cmd)
            return

        elif cmd in ["PRIVMSG", "WHISPER", "NOTICE"]:
            await self.handle_msg(user, params, cmd)
            return

        elif cmd == "TAGMSG":
            await self.handle_tagmsg(user, params)
            return

        elif cmd in ["GAG", "UNGAG"]:
            await self.handle_gag_alias(user, params, cmd == "GAG")
            return

        elif cmd == "QUIT":
            reason = params[0].lstrip(':') if params else None
            await self.quit_user(user, reason=reason)
            return  # Exit dispatch to break the read loop

        elif cmd == "ADMIN":
            await user.send(self.get_reply("256", user))
            await user.send(self.get_reply("257", user))
            await user.send(self.get_reply("258", user))
            await user.send(self.get_reply("259", user))
            return

        elif cmd in ["HELP", "H"]:
            await self.handle_help(user, params)
            return

        # ====================================================================
        # COMMAND ROUTING TABLE - standard commands routed to handlers
        # ====================================================================

        # Check if command has a handler in the routing table
        if cmd in self.COMMAND_HANDLERS:
            handler_name = self.COMMAND_HANDLERS[cmd]
            handler = getattr(self, handler_name)
            await handler(user, params)
            return

        # ====================================================================
        # UNKNOWN COMMAND
        # ====================================================================

        await user.send(self.get_reply("421", user, command=cmd))

    async def handle_nick(self, user, params):
        if not params:
            return
        new, old = params[0], user.nickname

        # Validate nickname BEFORE any assignment - blocks sign-on if invalid
        valid, error = validate_nickname(new)
        if not valid:
            await user.send(self.get_reply("432", user, target=new, error=error))
            return

        # Nick change cooldown (only for registered users, not initial sign-on)
        # SYSOPs and ADMINs are exempt from cooldown
        if user.registered and not user.is_high_staff():
            cooldown = CONFIG.get('limits', 'nick_change_cooldown', default=60)
            if cooldown > 0:
                elapsed = time.time() - user.last_nick_change
                if elapsed < cooldown:
                    remaining = int(cooldown - elapsed)
                    await user.send(self.get_reply("835", user, seconds=remaining))
                    return

        # Use lock to prevent TOCTOU race condition in nick changes
        async with self.user_update_lock:
            # Check for nickname collision
            if new in self.users and self.users[new] != user:
                await user.send(self.get_reply("433", user, target=new))
                return

            if old != "*" and old in self.users and self.users[old] == user:
                del self.users[old]
                self.users_lower.pop(old.lower(), None)
            user.nickname = new
            self.users[new] = user
            self.users_lower[new.lower()] = new

        # Update nick change timestamp for registered users
        if user.registered:
            user.last_nick_change = time.time()

        # Send NICK change message
        if user.registered and old != "*":
            nick_msg = f":{old}!{user.username}@{user.host} NICK {new}"
            # Send to the user themselves first
            await user.send(nick_msg)
            # Track who we've notified to avoid duplicates
            notified = {user.nickname}
            # Broadcast to all channels the user is in
            for cn in list(user.channels):
                if cn in self.channels:
                    c = self.channels[cn]
                    if old in c.members:
                        c.members[new] = c.members.pop(old)
                        if old in c.owners:
                            c.owners.discard(old)
                            c.owners.add(new)
                        if old in c.hosts:
                            c.hosts.discard(old)
                            c.hosts.add(new)
                        if old in c.voices:
                            c.voices.discard(old)
                            c.voices.add(new)
                    # Notify channel members (skip those already notified)
                    for member in c.members.values():
                        if member.nickname not in notified:
                            await member.send(nick_msg)
                            notified.add(member.nickname)

            # Propagate NICK change to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    await self.link_manager.broadcast_to_servers(nick_msg)

            # Fire USER/NICK event for monitoring
            await self.fire_trap("USER", "NICK", user)

        else:
            # Just update channel membership for unregistered users
            for cn in list(user.channels):
                if cn in self.channels:
                    c = self.channels[cn]
                    if old in c.members:
                        c.members[new] = c.members.pop(old)
                        if old in c.owners:
                            c.owners.discard(old)
                            c.owners.add(new)
                        if old in c.hosts:
                            c.hosts.discard(old)
                            c.hosts.add(new)
                        if old in c.voices:
                            c.voices.discard(old)
                            c.voices.add(new)

        await self.check_reg(user)

    async def handle_webirc(self, user, params):
        """Handle WEBIRC command for IP spoofing from trusted gateways.

        WEBIRC password gateway hostname ip [:realhost]

        This allows trusted WebSocket/CGI gateways to pass through the real
        client IP address. Must be sent BEFORE NICK/USER registration.
        """
        if user.registered:
            # Too late, already registered
            return

        if len(params) < 4:
            await user.send(self.get_reply("461", user, command="WEBIRC"))
            return

        # Check if WEBIRC is enabled
        if not CONFIG.get('security', 'webirc', 'enabled', default=False):
            logger.warning(get_log_message("webirc_disabled", ip=user.ip))
            return

        password = params[0]
        gateway = params[1]
        hostname = params[2]
        client_ip = params[3]

        # Get trusted hosts configuration
        hosts_config = CONFIG.get('security', 'webirc', 'hosts', default={})
        gateway_config = hosts_config.get(gateway)

        if not gateway_config:
            logger.warning(get_log_message("webirc_unknown_gateway", gateway=gateway, ip=user.ip))
            return

        # Verify password
        if gateway_config.get('password') != password:
            logger.warning(get_log_message("webirc_invalid_password", gateway=gateway, ip=user.ip))
            return

        # Verify source IP is allowed
        allowed_ips = gateway_config.get('allowed_ips', [])
        if user.ip not in allowed_ips:
            logger.warning(get_log_message("webirc_not_allowed", gateway=gateway, ip=user.ip))
            return

        # Validate client IP (basic validation for IPv4/IPv6)
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            # Update user's IP and hostname to the real client values
            old_ip = user.ip
            user.ip = str(ip_obj)
            if hostname != client_ip:
                user.hostname = hostname
                user.host = hostname
            else:
                user.hostname = await self.resolve_hostname(user.ip)
                user.host = user.hostname
            user.webirc_gateway = gateway
            logger.info(get_log_message("webirc_spoofed", gateway=gateway, old_ip=old_ip, new_ip=user.ip, hostname=user.hostname))
        except ValueError:
            logger.warning(get_log_message("webirc_invalid_client_ip", client_ip=client_ip, gateway=gateway))
            return

    async def handle_user(self, user, params):
        if len(params) < 4:
            await user.send(self.get_reply("461", user, command="USER"))
            return
        if user.registered:
            await user.send(self.get_reply("462", user))
            return

        username = params[0]

        # Validate username BEFORE any assignment - blocks sign-on if invalid
        valid, error = validate_username(username)
        if not valid:
            await user.send(self.get_reply("468", user, error=error))
            return

        user.username = username
        user.realname = params[3].lstrip(':')
        await self.check_reg(user)

    async def check_reg(self, user):
        if user.registered or user.nickname == "*" or user.username == "unknown":
            return
        # Don't complete registration during CAP negotiation
        if user.cap_negotiating:
            return
        user.registered = True
        auth, level = False, "USER"

        # Check if user authenticated via SASL
        if user.sasl_authenticated and user.sasl_account:
            # Check if we should route to trunk for authentication
            services_mode = self.services_mode
            is_services_hub = self.is_services_hub

            # If centralized mode and we're NOT the trunk, route to trunk
            if services_mode == 'centralized' and not is_services_hub:
                # Branch server - route SASL auth to trunk
                if self.link_manager and self.link_manager.enabled:
                    # SASL has already authenticated the user, so we pass special marker
                    # The trunk will look up the account without password verification
                    auth_result = await self.link_manager.route_staff_auth(user.sasl_account, '*SASL*', user)
                    if auth_result:
                        auth, level = auth_result['authenticated'], auth_result['level']
                        if auth:
                            user.staff_email = auth_result.get('email')
                            user.staff_realname = auth_result.get('realname')
                            user.force_staff_realname = auth_result.get('force_realname', False)
                            logger.info(get_log_message("sasl_staff_auth_trunk", account=user.sasl_account, level=level))
                    else:
                        # Trunk not available - deny staff authentication
                        logger.warning(get_log_message("sasl_staff_auth_failed_trunk", account=user.sasl_account))
                        auth, level = False, "USER"
                else:
                    logger.warning(get_log_message("sasl_staff_auth_failed_link", account=user.sasl_account))
                    auth, level = False, "USER"
            else:
                # Trunk server or local mode - authenticate locally
                try:
                    async with self.db_pool.connection() as db:
                        async with db.execute("SELECT level FROM users WHERE username=?",
                                             (user.sasl_account,)) as cursor:
                            row = await cursor.fetchone()
                            if row:
                                auth, level = True, row[0]
                except Exception as e:
                    if self.debug_mode:
                        logger.error(get_log_message("sasl_auth_lookup_error", error=e))

        # Fall back to PASS-based authentication
        elif user.provided_pass:
            # Check SSL requirement for PASS-based staff authentication (configurable)
            pass_require_ssl = CONFIG.get('security', 'pass_require_ssl', default=True)
            if pass_require_ssl and not user.using_ssl:
                # Block staff auth via PASS on non-SSL connections
                logger.warning(get_log_message("pass_staff_blocked_ssl", username=user.username, ip=user.ip))
                # User will connect as regular user (no staff privileges)
                auth, level = False, "USER"
            else:
                # Check if we should route to trunk for authentication
                services_mode = self.services_mode
                is_services_hub = self.is_services_hub

                # If centralized mode and we're NOT the trunk, route to trunk
                if services_mode == 'centralized' and not is_services_hub:
                    # Branch server - route staff auth to trunk
                    if self.link_manager and self.link_manager.enabled:
                        auth_result = await self.link_manager.route_staff_auth(user.username, user.provided_pass, user)
                        if auth_result:
                            auth, level = auth_result['authenticated'], auth_result['level']
                            if auth:
                                user.staff_email = auth_result.get('email')
                                user.staff_realname = auth_result.get('realname')
                                user.force_staff_realname = auth_result.get('force_realname', False)
                                logger.info(get_log_message("staff_auth_trunk", username=user.username, level=level))
                        else:
                            # Trunk not available - deny authentication
                            logger.warning(get_log_message("staff_auth_failed_trunk", username=user.username))
                            auth, level = False, "USER"
                else:
                    # Trunk server or local mode - authenticate locally
                    try:
                        logger.info(get_log_message("pass_auth_attempt", username=user.username, ip=user.ip))
                        row = await self.db_pool.execute_one(
                            "SELECT password_hash, level, email, realname, force_realname FROM users WHERE username=?",
                            (user.username,)
                        )
                        if row:
                            logger.info(get_log_message("pass_auth_found", username=user.username))
                            # Use non-blocking bcrypt check
                            if await check_password_async(user.provided_pass, row[0]):
                                auth, level = True, row[1]
                                user.staff_email = row[2]
                                user.staff_realname = row[3]
                                user.force_staff_realname = bool(row[4])
                                self.failed_auth_tracker.record_success(user.ip)
                                logger.info(get_log_message("pass_auth_success", username=user.username, level=level))
                            else:
                                self.failed_auth_tracker.record_failure(user.ip)
                                logger.warning(get_log_message("pass_auth_wrong_password", username=user.username))
                        else:
                            logger.info(get_log_message("pass_auth_not_found", username=user.username))
                    except Exception as e:
                        logger.error(get_log_message("pass_auth_error", username=user.username, error=e))

        if auth and level in ["ADMIN", "SYSOP", "GUIDE"]:
            user.host = self.servername
            user.authenticated = True
            user.staff_level = level
            # Apply relaxed rate limits for staff
            user.rate_limiter = RateLimiter(RateLimiter.STAFF_COOLDOWNS)
            # Apply forced realname if set
            if hasattr(user, 'force_staff_realname') and user.force_staff_realname and hasattr(user, 'staff_realname') and user.staff_realname:
                user.realname = user.staff_realname
            # ADMIN gets +a (administrator) mode, SYSOP gets +o (operator), GUIDE gets +g (guide)
            if level == "ADMIN":
                user.set_mode('a', True)
            elif level == "SYSOP":
                user.set_mode('o', True)
            elif level == "GUIDE":
                user.set_mode('g', True)
        else:
            # Non-authenticated users get tilde prefix on username
            if not user.username.startswith('~'):
                user.username = '~' + user.username

        # Server-wide ACCESS check (ADMIN bypasses DENY rules)
        if not user.has_mode('a'):  # ADMIN bypasses
            user_hostmask = user.prefix()
            # Check DENY rules first
            for pattern, set_by, set_at, timeout, reason in self.access_list['DENY']:
                # Check if entry has expired
                if timeout > 0 and time.time() > timeout:
                    continue
                if fnmatch.fnmatch(user_hostmask, pattern) or fnmatch.fnmatch(user.ip or '', pattern):
                    reason_msg = f" ({reason})" if reason else ""
                    await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['access_denied_with_reason'].format(reason=reason_msg)))
                    await user.send(f"ERROR :{SERVER_MESSAGES['error_access_denied'].format(nickname=user.nickname)}")
                    await self.quit_user(user)
                    return

        # Staff-only trunk mode check
        restrict_to_staff = CONFIG.get('server', 'restrict_to_staff_only', default=False)
        is_services_hub = self.is_services_hub

        if restrict_to_staff and is_services_hub:
            # Trunk is configured for staff-only access
            # Allow staff members (ADMIN, SYSOP, GUIDE)
            is_staff = auth and level in ["ADMIN", "SYSOP", "GUIDE"]

            # Check if user matches any ACCESS GRANT patterns
            user_hostmask = user.prefix()
            in_access_grant = False
            for pattern, set_by, set_at, timeout, reason in self.access_list['GRANT']:
                # Check if entry has expired
                if timeout > 0 and time.time() > timeout:
                    continue
                # Check if user matches this grant pattern
                if fnmatch.fnmatch(user_hostmask, pattern) or fnmatch.fnmatch(user.ip or '', pattern):
                    in_access_grant = True
                    logger.info(get_log_message("access_grant_matched", nickname=user.nickname, pattern=pattern))
                    break

            # Deny if user is neither staff nor in ACCESS GRANT
            if not is_staff and not in_access_grant:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['server_restricted']))
                await self.send_server_message(user, "server_use_branch")
                await user.send(f"ERROR :{SERVER_MESSAGES['error_staff_only'].format(nickname=user.nickname)}")
                logger.info(get_log_message("access_rejected", nickname=user.nickname, ip=user.ip))
                await self.quit_user(user)
                return

        await user.send(self.get_reply("001", user))
        await user.send(self.get_reply("002", user))
        await user.send(self.get_reply("003", user))
        await user.send(self.get_reply("004", user))
        await user.send(self.get_reply("005", user))

        # Staff count includes staff users AND services/bots
        ops = sum(1 for u in self.users.values() if u.is_staff() or u.is_virtual)
        # User count excludes services/bots
        real_users = sum(1 for u in self.users.values() if not u.is_virtual)
        # Count linked servers
        server_count = 1  # This server
        if hasattr(self, 'link_manager') and self.link_manager:
            server_count += len(self.link_manager.linked_servers)
        # Only show invisible count to staff users
        if auth:
            invisible = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
        else:
            invisible = 0  # Hide from non-staff

        # Send complete LUSERS info during registration
        await user.send(self.get_reply("251", user, users=real_users, invisible=invisible, server_count=server_count))
        await user.send(self.get_reply("252", user, ops=ops))
        channels = len([ch for ch in self.channels.values() if not ch.is_local])
        await user.send(self.get_reply("254", user, channels=channels))
        await user.send(self.get_reply("255", user, users=real_users, server_count=server_count))
        # Local and global user counts
        local_users = len([u for u in self.users.values() if not u.is_virtual])
        await user.send(self.get_reply("265", user, local=local_users, local_max=self.max_users_seen))
        await user.send(self.get_reply("266", user, global_users=real_users, global_max=self.max_users_seen))
        await self.handle_motd(user)

        if auth:
            mode = 'a' if level == "ADMIN" else 'o' if level == "SYSOP" else 'g'
            user.set_mode(mode, True)
            user.set_mode('r', True)  # Set registered mode
            mode_msg = f":{user.nickname} MODE {user.nickname} :+{mode}r"
            await user.send(mode_msg)
            # Propagate MODE to linked servers
            if self.link_manager and self.link_manager.enabled:
                await self.link_manager.broadcast_to_servers(mode_msg)
            # Dynamic role name for 381
            role = "administrator" if level == "ADMIN" else "operator" if level == "SYSOP" else "guide"
            await user.send(self.get_reply("381", user, role=role))
            # Configurable staff login message
            staff_msg = CONFIG.get('server', 'staff_login_message',
                                   default='Welcome to the staff team.')
            await user.send(self.get_reply("386", user, message=staff_msg))
            logger.info(get_log_message("auth_success", username=user.username, nickname=user.nickname, ip=user.ip, level=level))

        await self.fire_trap("CONNECT", "USER LOGON", user)

        # Introduce user to linked servers
        if self.link_manager and self.link_manager.enabled:
            modes = user.get_mode_str()
            nick_burst = (
                f"NICK {user.nickname} 1 {int(user.signon_time)} {user.username} "
                f"{user.host} {self.servername} +{modes} :{user.realname}"
            )
            logger.info(get_log_message("nick_burst_broadcasting", nickname=user.nickname, burst=nick_burst))
            await self.link_manager.broadcast_to_servers(nick_burst)
            logger.info(get_log_message("nick_burst_sent", nickname=user.nickname))

        # Send newsflash on connect
        await self.send_newsflash_on_connect(user)

        # Notify watchers that this user has come online
        await self.notify_watchers_online(user)

    async def handle_msg(self, user, params, cmd):
        if user.has_mode('z'):
            return
        if len(params) < 2:
            await user.send(self.get_reply("461", user, command=cmd))
            return
        target = params[0]

        # Server-wide messaging: PRIVMSG/NOTICE $ sends to all local users (staff only)
        if target == '$':
            # Require staff privileges for server-wide messages
            if not user.is_high_staff():
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['broadcast_restricted']))
                return

            text = params[1]
            msg_type = "NOTICE" if cmd == "NOTICE" else "PRIVMSG"
            sent_count = 0

            # Send to all local users (not virtual, not services)
            for local_user in self.users.values():
                if local_user.is_virtual or local_user == user:
                    continue
                await local_user.send(f":{user.prefix()} {msg_type} $ :{text}")
                sent_count += 1

            # Confirm to sender
            await self.send_notice(user, "broadcast_sent", type=msg_type, count=sent_count, server=self.servername)
            return

        # WHISPER restrictions: single recipient only, 5s rate limit
        if cmd == "WHISPER":
            # WHISPER requires IRCX mode (+x)
            if not (user.has_mode('x') or user.is_ircx):
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_ircx'].format(command="WHISPER")))
                return

            if ',' in target:
                await user.send(self.get_reply("407", user, target=target))
                return
            if not user.rate_limiter.check('WHISPER'):
                await user.send(self.get_reply("832", user))
                return

        text = params[2] if cmd == "WHISPER" and len(params) >= 3 else params[1]

        # Validate message length
        if len(text) > self.max_msg_length:
            text = text[:self.max_msg_length]
            await self.send_notice(user, "message_truncated", max=self.max_msg_length)

        # Check if we need to route to services hub (centralized services mode)
        services_mode = self.services_mode
        is_services_hub = self.is_services_hub
        service_targets = self._service_target_names()

        # If we're in centralized mode and NOT the hub, route to hub
        if services_mode == 'centralized' and not is_services_hub:
            if target.lower() in service_targets:
                # Route to services hub
                if self.link_manager and self.link_manager.enabled:
                    source = f":{user.prefix()}"
                    message = f"{source} {cmd} {target} :{text}"
                    routed = await self.link_manager.route_to_services_hub(message)
                    if routed:
                        logger.debug(get_log_message("service_routed", nickname=user.nickname, target=target))
                        return
                    else:
                        # Trunk not available - inform user
                        logger.warning(get_log_message("service_route_failed", target=target))
                        await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_trunk_offline']))
                        return

        if await self._dispatch_service_target(user, target, text):
            return

        source = f":{user.prefix()}"
        out = f"{source} {cmd} {target} {params[1] + ' ' if cmd in ['WHISPER', 'DATA'] and len(params) > 2 else ''}:{text}"

        # High staff wildcard broadcast (PRIVMSG/NOTICE * only)
        if target == '*':
            if cmd not in ['PRIVMSG', 'NOTICE']:
                return
            if not user.is_high_staff():
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command="PRIVMSG (wildcard)")))
                return

            # Rate limit broadcasts to prevent abuse (max 10 per minute)
            if not user.check_rate_limit('BROADCAST'):
                await user.send(self.get_reply("830", user))
                return

            broadcast_out = f"{source} {cmd} * :{text}"
            broadcast_count = 0
            # Use asyncio.gather for efficient concurrent sends with backpressure
            send_tasks = []
            for recipient in self.users.values():
                if not recipient.is_virtual:
                    send_tasks.append(recipient.send(broadcast_out))
                    broadcast_count += 1
            await asyncio.gather(*send_tasks, return_exceptions=True)
            self.stats['messages_sent'] += broadcast_count
            return

        # Case-insensitive user lookup for private messages
        recipient = self.get_user(target)
        if not recipient:
            # Try case-insensitive search
            target_lower = target.lower()
            for nick, usr in self.users.items():
                if nick.lower() == target_lower:
                    recipient = usr
                    break

        if recipient:
            # Check if sender is silenced by recipient
            if self.is_silenced(user, recipient):
                return  # Silently drop the message

            # Build client-only tag prefix for message-tags relay
            tag_prefix = self._build_msg_tags(user)

            # Check if recipient is a remote user
            if recipient.is_remote:
                # Route to the owning server when it is still directly reachable.
                if self.link_manager and self.link_manager.enabled and recipient.from_server:
                    target_server = self.link_manager.servers.get(recipient.from_server)
                    if target_server and target_server.is_direct:
                        await target_server.send(tag_prefix + out if tag_prefix else out)
                    else:
                        self.users.pop(recipient.nickname, None)
                        self.users_lower.pop(recipient.nickname.lower(), None)
                        await user.send(self.get_reply("401", user, target=target))
                        return
                else:
                    await user.send(self.get_reply("401", user, target=target))
                    return
            else:
                # Local user - send with appropriate tags based on caps
                if 'message-tags' in recipient.enabled_caps:
                    await recipient.send(tag_prefix + out)
                elif 'account-tag' in recipient.enabled_caps:
                    acct = user.sasl_account or '*'
                    await recipient.send(f"@account={acct} " + out)
                else:
                    await recipient.send(out)
            # IRCv3 echo-message: echo the message back to the sender
            if 'echo-message' in user.enabled_caps:
                if 'message-tags' in user.enabled_caps:
                    await user.send(tag_prefix + out)
                elif 'account-tag' in user.enabled_caps:
                    acct = user.sasl_account or '*'
                    await user.send(f"@account={acct} " + out)
                else:
                    await user.send(out)
            self.stats['messages_sent'] += 1
        elif is_channel(target):
            channel, chan_name = self.get_channel(target)
            if not channel:
                await user.send(self.get_reply("403", user, target=target))
                return
            # Check +n (no external messages) - non-members cannot send
            # Exception: Service users (System, Messenger, Registrar, NewsFlash, ServiceBots) can always message
            is_service = user.has_mode('s') or user.has_mode('S') or user.has_mode('G')
            if not channel.has_member(user.nickname) and channel.modes.get('n', False) and not is_service:
                await user.send(self.get_reply("842", user, channel=chan_name))
                return
            # Check +m (moderated) - only voiced/host/owner can send
            if channel.modes.get('m', False) and channel.has_member(user.nickname):
                # Staff can always speak, as can voiced/host/owner
                is_staff = user.is_staff()
                is_privileged = (user.nickname in channel.owners or
                                user.nickname in channel.hosts or
                                user.nickname in channel.voices)
                can_speak = is_staff or is_privileged
                if not can_speak:
                    await user.send(self.get_reply("841", user, channel=chan_name))
                    return
            if user.nickname in channel.gagged:
                return
            # Channel mode +w: no whispers allowed
            if cmd == "WHISPER" and channel.modes.get('w', False):
                await user.send(self.get_reply("843", user, channel=chan_name))
                return

            # WHISPER to channel is private message to a specific user in channel
            # Format: WHISPER #channel targetuser :message
            if cmd == "WHISPER":
                if len(params) < 3:
                    await user.send(self.get_reply("461", user, command="WHISPER"))
                    return
                target_nick = params[1]
                # Find the target user (case-insensitive)
                target_user = self.get_user(target_nick)
                if not target_user:
                    await user.send(self.get_reply("401", user, target=target_nick))
                    return
                # Check if target is in channel
                if not channel.has_member(target_user.nickname):
                    await user.send(self.get_reply("441", user, target=target_user.nickname, channel=chan_name))
                    return
                # Send to target (local or route to remote server)
                whisper_out = f"{source} WHISPER {chan_name} {target_user.nickname} :{text}"
                if target_user.is_remote:
                    # Target is on a remote server, route through link manager
                    if self.link_manager and self.link_manager.enabled:
                        await self.link_manager.broadcast_to_servers(whisper_out)
                else:
                    # Target is local, send directly
                    await target_user.send(whisper_out)
                self.stats['messages_sent'] += 1
                return

            # Rebuild output with canonical channel name
            chan_out = f"{source} {cmd} {chan_name} {params[1] + ' ' if cmd in ['DATA'] and len(params) > 2 else ''}:{text}"
            # Channel mode +f: strip formatting codes
            if channel.modes.get('f', False):
                text = self._strip_formatting(text)
                chan_out = f"{source} {cmd} {chan_name} {params[1] + ' ' if cmd in ['DATA'] and len(params) > 2 else ''}:{text}"
            # Build client-only tag prefix for message-tags relay
            tag_prefix = self._build_msg_tags(user)
            # Broadcast to LOCAL channel members only (exclude remote users to avoid routing loops)
            for member in channel.members.values():
                if member != user and not (member.is_remote):
                    if 'message-tags' in member.enabled_caps:
                        await member.send(tag_prefix + chan_out)
                    elif 'account-tag' in member.enabled_caps:
                        acct = user.sasl_account or '*'
                        await member.send(f"@account={acct} " + chan_out)
                    else:
                        await member.send(chan_out)
            # IRCv3 echo-message: echo the message back to the sender
            if 'echo-message' in user.enabled_caps:
                if 'message-tags' in user.enabled_caps:
                    await user.send(tag_prefix + chan_out)
                elif 'account-tag' in user.enabled_caps:
                    acct = user.sasl_account or '*'
                    await user.send(f"@account={acct} " + chan_out)
                else:
                    await user.send(chan_out)
            # Propagate channel message to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    await self.link_manager.broadcast_to_servers(tag_prefix + chan_out if tag_prefix else chan_out)
            self.stats['messages_sent'] += 1

            # Track messages by channel (current session and all-time)
            if chan_name not in self.stats['messages_by_channel']:
                self.stats['messages_by_channel'][chan_name] = 0
            self.stats['messages_by_channel'][chan_name] += 1

            # Track all-time busiest channels
            if chan_name not in self.stats['busiest_channels']:
                self.stats['busiest_channels'][chan_name] = 0
            self.stats['busiest_channels'][chan_name] += 1

            # Log to transcript if +y mode is enabled
            if cmd == "PRIVMSG":
                # Check for ACTION (/me)
                if text.startswith('\x01ACTION ') and text.endswith('\x01'):
                    action_text = text[8:-1]  # Strip \x01ACTION and trailing \x01
                    self.log_transcript(channel, "ACTION", user, action_text)
                else:
                    self.log_transcript(channel, "MSG", user, text)
            elif cmd == "NOTICE":
                self.log_transcript(channel, "NOTICE", user, text)

            # ServiceBot monitoring - check for violations
            if cmd == "PRIVMSG":  # Only check regular messages, not notices
                await self._check_servicebot_violations(channel, user, text)
        else:
            # Unknown nick: linked users are synchronized in-memory, so failing local lookup is final.
            await user.send(self.get_reply("401", user, target=target))

    async def handle_tagmsg(self, user, params):
        """Handle TAGMSG - message with tags only, no text content.

        Used for typing indicators, reactions, and other tag-only messages.
        Requires the message-tags capability.
        """
        if 'message-tags' not in user.enabled_caps:
            return  # Silently ignore from clients without message-tags

        if not params:
            await user.send(self.get_reply("461", user, command="TAGMSG"))
            return

        target = params[0]
        client_tags = {k: v for k, v in user._msg_tags.items() if k.startswith('+')}
        if not client_tags:
            return  # No client tags to relay

        # Build tag string: client-only tags + server-generated tags (msgid, account, bot)
        parts = []
        for k, v in client_tags.items():
            parts.append(f"{k}={_escape_tag_value(v)}" if v is not None else k)
        msgid = self._generate_msgid()
        parts.append(f"msgid={msgid}")
        account = user.sasl_account or '*'
        parts.append(f"account={account}")
        if user.has_mode('b'):
            parts.append("bot")
        tag_str = ';'.join(parts)

        source = f":{user.prefix()}"
        tagged_msg = f"@{tag_str} {source} TAGMSG {target}"

        # Route to channel or user
        recipient = self.get_user(target)
        if recipient:
            if 'message-tags' in recipient.enabled_caps:
                await recipient.send(tagged_msg)
            if 'echo-message' in user.enabled_caps and 'message-tags' in user.enabled_caps:
                await user.send(tagged_msg)
        elif is_channel(target):
            channel, chan_name = self.get_channel(target)
            if not channel:
                await user.send(self.get_reply("403", user, target=target))
                return
            # Check +n (no external messages)
            if not channel.has_member(user.nickname) and channel.modes.get('n', False):
                await user.send(self.get_reply("842", user, channel=chan_name))
                return
            # Rebuild with canonical channel name
            tagged_msg = f"@{tag_str} {source} TAGMSG {chan_name}"
            for member in channel.members.values():
                if member != user and not member.is_remote:
                    if 'message-tags' in member.enabled_caps:
                        await member.send(tagged_msg)
            if 'echo-message' in user.enabled_caps and 'message-tags' in user.enabled_caps:
                await user.send(tagged_msg)
        else:
            await user.send(self.get_reply("401", user, target=target))

    async def handle_data(self, user, params, cmd):
        """Handle DATA/REQUEST/REPLY commands (IRCX)

        Syntax: DATA/REQUEST/REPLY <target> <tag> :<message>

        - DATA: Send tagged data (one-way communication)
        - REQUEST: Send tagged data expecting a reply
        - REPLY: Respond to a previous REQUEST

        Tags identify how to interpret the payload. Reserved prefixes:
        - ADM.* requires IRC administrator (+a)
        - SYS.* requires IRC operator (+o)
        - GDE.* requires IRC guide (+g)
        - OWN.* requires channel owner (+q) when targeting channels
        - HST.* requires channel host (+o) when targeting channels
        """
        # Require IRCX mode
        if not (user.has_mode('x') or user.is_ircx):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_ircx'].format(command=cmd)))
            return

        if len(params) < 3:
            await user.send(self.get_reply("461", user, command=cmd))
            return

        targets_str = params[0]
        tag = params[1]
        message = params[2]

        # Split comma-separated targets
        targets = [t.strip() for t in targets_str.split(',') if t.strip()]
        if not targets:
            await user.send(self.get_reply("461", user, command=cmd))
            return

        # Validate tag format
        # Valid characters: [A-Za-z0-9.]
        # Must start with letter
        # Max 15 characters
        if not tag or len(tag) > 15:
            await user.send(self.get_reply("869", user, param=SERVER_MESSAGES['tag_invalid_length']))
            return

        if not tag[0].isalpha():
            await user.send(self.get_reply("869", user, param=SERVER_MESSAGES['tag_invalid_start']))
            return

        if not _TAG_PATTERN.match(tag):
            await user.send(self.get_reply("869", user, param=SERVER_MESSAGES['tag_invalid_chars']))
            return

        # Check reserved prefix permissions
        tag_upper = tag.upper()

        # ADM.* requires IRC administrator
        if tag_upper.startswith('ADM.'):
            if not user.has_mode('a'):
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['tag_reserved_adm']))
                return

        # SYS.* requires IRC operator
        elif tag_upper.startswith('SYS.'):
            if not user.has_mode('o'):
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['tag_reserved_sys']))
                return

        # GDE.* requires IRC guide
        elif tag_upper.startswith('GDE.'):
            if not user.has_mode('g'):
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['tag_reserved_gde']))
                return

        # OWN.* and HST.* require channel context - validate for all channel targets
        if tag_upper.startswith(('OWN.', 'HST.')):
            # Check if any target is a channel
            has_channel = any(is_channel(t) for t in targets)
            if not has_channel:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['tag_channel_only'].format(prefix=tag_upper[:3])))
                return

            # Validate permissions for all channel targets
            for target in targets:
                if is_channel(target):
                    channel, chan_name = self.get_channel(target)
                    if not channel:
                        continue  # Will handle error later

                    # OWN.* requires channel owner
                    if tag_upper.startswith('OWN.'):
                        if user.nickname not in channel.owners and not user.is_high_staff():
                            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['tag_requires_owner'].format(channel=chan_name)))
                            return

                    # HST.* requires channel host
                    elif tag_upper.startswith('HST.'):
                        if user.nickname not in channel.hosts and user.nickname not in channel.owners and not user.is_high_staff():
                            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['tag_requires_host'].format(channel=chan_name)))
                            return

        # Escape control characters in message (except CTCP which uses \x01)
        # Replace newlines, carriage returns, etc.
        message = message.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

        # Route to all targets (channels and/or users)
        for target in targets:
            if is_channel(target):
                channel, chan_name = self.get_channel(target)
                if not channel:
                    await user.send(self.get_reply("403", user, target=target))
                    continue

                if user.nickname not in channel.members:
                    await user.send(self.get_reply("442", user, target=chan_name))
                    continue

                # Broadcast DATA/REQUEST/REPLY to channel members (IRCX clients only)
                for member in channel.members.values():
                    # Only send to IRCX-enabled clients
                    if member != user and (member.has_mode('x') or member.is_ircx):
                        # Each viewer sees appropriately masked host
                        prefix = user.prefix(viewer=member)
                        data_msg = f":{prefix} {cmd} {chan_name} {tag} :{message}"
                        await member.send(data_msg)

                # Propagate to linked servers (unmasked for server-to-server)
                if self.link_manager and self.link_manager.enabled:
                    if not (user.is_remote):
                        unmasked_prefix = f"{user.nickname}!{user.username}@{user.host}"
                        server_msg = f":{unmasked_prefix} {cmd} {chan_name} {tag} :{message}"
                        await self.link_manager.broadcast_to_servers(server_msg)

            else:
                # Direct message to user
                target_user = self.get_user(target)
                if not target_user:
                    await user.send(self.get_reply("401", user, target=target))
                    continue

                # Only send to IRCX-enabled clients
                if not (target_user.has_mode('x') or target_user.is_ircx):
                    await self.send_notice(user, "data_target_no_ircx", target=target)
                    continue

                # Target user sees appropriately masked host
                prefix = user.prefix(viewer=target_user)
                data_msg = f":{prefix} {cmd} {target} {tag} :{message}"
                await target_user.send(data_msg)

    async def handle_who(self, user, params):
        target = params[0] if params else "*"
        is_staff = user.is_staff()
        is_high_staff = user.is_high_staff()  # SYSOP or ADMIN

        # Start batch for WHO response
        batch_id = await self.start_batch(user, "draft/who-reply", target)

        # WHO * (all users) restricted to SYSOP/ADMIN only
        if target == "*":
            if not is_high_staff:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['who_restricted']))
                await self.send_batched(user, batch_id, self.get_reply("315", user, target=target))
                await self.end_batch(user, batch_id)
                return
            # Rate limit for full WHO
            if not user.rate_limiter.check('WHO'):
                await user.send(self.get_reply("831", user))
                await self.send_batched(user, batch_id, self.get_reply("315", user, target=target))
                await self.end_batch(user, batch_id)
                return
            # Return all visible users (staff can see ServiceBots)
            for member in self.users.values():
                # Skip virtual users unless requester is high staff (ADMIN/SYSOP)
                if member.is_virtual and not is_high_staff:
                    continue
                if member.has_mode('i') and not is_high_staff and user != member:
                    continue
                flags = self._build_who_flags(member, user, show_invisible=True)
                # Staff see real IP, non-staff see masked host
                display_host = member.ip if is_staff else mask_host(member.host, False)
                await self.send_batched(user, batch_id, self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            await self.send_batched(user, batch_id, self.get_reply("315", user, target=target))
            await self.end_batch(user, batch_id)
            return

        # Pattern matching for nicknames (e.g., *pattern*, %pattern%)
        if '*' in target or '%' in target:
            # Convert % to * for fnmatch
            pattern = target.replace('%', '*')
            match_count = 0
            max_results = 50  # Limit results for non-staff
            for member in self.users.values():
                # Skip virtual users unless requester is staff (ADMIN/SYSOP/GUIDE)
                if member.is_virtual and not is_staff:
                    continue
                if not fnmatch.fnmatch(member.nickname.lower(), pattern.lower()):
                    continue
                if member.has_mode('i') and not is_staff and user != member:
                    continue
                match_count += 1
                if not is_staff and match_count > max_results:
                    await self.send_server_message(user, "who_truncated", max=max_results)
                    break
                flags = self._build_who_flags(member, user, show_invisible=(is_staff or user == member))
                # Staff see real IP, non-staff see masked host
                display_host = member.ip if is_staff else mask_host(member.host, False)
                await self.send_batched(user, batch_id, self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            await self.send_batched(user, batch_id, self.get_reply("315", user, target=target))
            await self.end_batch(user, batch_id)
            return

        # IP search (staff only) - matches exact IP or IP patterns
        # Examples: WHO 192.168.100.100 or WHO 192.168.100.* or WHO 2001:db8:*
        if is_staff and ('.' in target or ':' in target):
            pattern = target.replace('%', '*')
            has_wildcard = '*' in pattern
            match_count = 0
            for member in self.users.values():
                # Skip virtual users
                if member.is_virtual:
                    continue
                # Match IP
                if has_wildcard:
                    if not fnmatch.fnmatch(member.ip, pattern):
                        continue
                elif member.ip != target:
                    continue
                match_count += 1
                flags = self._build_who_flags(member, user, show_invisible=True)
                # Staff always see real IP in WHO results
                display_host = member.ip
                await self.send_batched(user, batch_id, self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            await self.send_batched(user, batch_id, self.get_reply("315", user, target=target))
            await self.end_batch(user, batch_id)
            return

        # Check if target is a channel
        channel, chan_name = self.get_channel(target)
        if channel:
            # Create snapshot of members to avoid iteration issues
            for nick in list(channel.members.keys()):
                member = channel.members.get(nick)
                if not member:
                    continue  # Member left during iteration

                # Build base flags using helper
                flags = self._build_who_flags(member, user, show_invisible=(is_staff or user == member))

                # Channel rank flags (., @, +)
                if nick in channel.owners:
                    flags += "."
                elif nick in channel.hosts:
                    flags += "@"
                elif nick in channel.voices:
                    flags += "+"

                # NOTE: Never expose 'z' (gagged) to non-staff users

                # Staff see real IP, non-staff see masked host
                display_host = member.ip if is_staff else mask_host(member.host, False)
                await self.send_batched(user, batch_id, self.get_reply("352", user, channel=chan_name, ident=member.username,
                                        host=display_host, target=nick, flags=flags, real=member.realname))
            await self.send_batched(user, batch_id, self.get_reply("315", user, target=chan_name))
            await self.end_batch(user, batch_id)
            return

        # Check if target is a specific user (case-insensitive nickname match)
        member = self.get_user(target)
        if not member:
            # Try case-insensitive search
            target_lower = target.lower()
            for nick, usr in self.users.items():
                if nick.lower() == target_lower:
                    member = usr
                    break

        if member:
            # Skip invisible users unless requester is staff or is the member
            if not (member.has_mode('i') and not is_staff and user != member):
                # Skip virtual users unless requester is staff OR member is a service
                if not (member.is_virtual and not is_staff and not member.has_mode('s')):
                    flags = "G" if member.away_msg else "H"
                    if member.has_mode('i') and (is_staff or user == member):
                        flags += "i"
                    if member.has_mode('x') or member.is_ircx:
                        flags += "x"
                    if user.is_ircx:
                        if member.has_mode('G'):  # God - divine watcher
                            flags += "G"
                        elif member.has_mode('S'):  # System - omnipresent
                            flags += "S"
                        elif member.has_mode('s'):
                            flags += "s"
                        elif member.has_mode('a'):
                            flags += "a"
                        elif member.has_mode('o'):
                            flags += "o"
                        elif member.has_mode('g'):
                            flags += "g"
                    else:
                        if member.has_mode('G') or member.has_mode('S'):  # God/System
                            flags += "*"
                        elif member.has_mode('s'):
                            flags += "*"
                        elif member.is_high_staff():
                            flags += "*"
                    # Staff see real IP/host, non-staff see masked
                    display_host = mask_host(member.host, is_staff)
                    await self.send_batched(user, batch_id, self.get_reply("352", user, channel="*", ident=member.username,
                                            host=display_host, target=member.nickname, flags=flags, real=member.realname))

        await self.send_batched(user, batch_id, self.get_reply("315", user, target=target))
        await self.end_batch(user, batch_id)

    async def handle_whois(self, user, params):
        # Rate limit WHOIS lookups
        if not user.rate_limiter.check('WHOIS'):
            await user.send(self.get_reply("830", user))
            return
        if not params:
            return
        for target_nick in params[0].split(','):
            # Start batch for this WHOIS target
            batch_id = await self.start_batch(user, "draft/whois-reply", target_nick)

            # Case-insensitive user lookup
            target = self.get_user(target_nick)

            # Reserved service names that don't exist redirect to System
            if not target and is_reserved_service(target_nick):
                system_user = self.users.get('System')
                if system_user:
                    await self.send_batched(user, batch_id, self.get_reply("311", user, target=target_nick, ident='Services',
                                             host=self.servername, real=f"Alias for {system_user.nickname}"))
                    await self.send_batched(user, batch_id, self.get_reply("312", user, target=target_nick))
                    await self.send_batched(user, batch_id, self.get_reply("313", user, target=target_nick, role="is a network service"))
                    await self.send_batched(user, batch_id, self.get_reply("318", user, target=target_nick))
                    await self.end_batch(user, batch_id)
                    continue

            if not target:
                # Route WHOIS query to linked servers if target not found locally
                if self.link_manager and self.link_manager.enabled:
                    await self._start_remote_whois_lookup(user, batch_id, target_nick)
                    continue
                await self.send_batched(user, batch_id, self.get_reply("401", user, target=target_nick))
                await self.send_batched(user, batch_id, self.get_reply("318", user, target=target_nick))
                await self.end_batch(user, batch_id)
                continue

            for reply in await self._build_whois_replies(user, target):
                await self.send_batched(user, batch_id, reply)
            await self.end_batch(user, batch_id)

    async def handle_whowas(self, user, params):
        # Rate limit WHOWAS lookups
        if not user.rate_limiter.check('WHOWAS'):
            await user.send(self.get_reply("830", user))
            await user.send(self.get_reply("369", user, target=params[0] if params else "*"))
            return
        if not params:
            return
        target_nick = params[0]
        if target_nick in self.whowas:
            info = self.whowas[target_nick]
            await user.send(self.get_reply("314", user, target=target_nick,
                                     ident=info.get('username', 'unknown'),
                                     host=info.get('host', 'unknown'),
                                     real=info.get('realname', 'unknown')))
        await user.send(self.get_reply("369", user, target=target_nick))

    async def handle_lastlogons(self, user, params):
        """Show recent connection sessions to staff as a flat IRC numeric table.

        Syntax:
          LASTLOGONS [VERBOSE] [filter] [limit]
          LOGONS [VERBOSE] [filter] [limit]

        The filter is matched case-insensitively across nick, user, real name,
        IP, and host. Limits are capped at 250 rows.
        """
        if not user.is_staff():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_staff'].format(command="LASTLOGONS")))
            return

        if not user.rate_limiter.check('LASTLOGONS'):
            await user.send(self.get_reply("830", user))
            return

        verbose, filter_text, limit = self._parse_lastlogons_params(params)
        limit = max(1, min(limit, 250))

        entries = self._current_session_entries() + await self._completed_session_entries()
        entries.sort(key=lambda entry: entry.get('logon_time', 0), reverse=True)
        matched = [entry for entry in entries if self._session_matches(entry, filter_text)]
        shown = matched[:limit]
        reply_filter = self._lastlogons_reply_token(filter_text)

        await user.send(self.get_reply("976", user, filter=reply_filter, shown=len(shown), total=len(matched), limit=limit))
        header, separator = self._lastlogons_header_rows(verbose=verbose)
        await user.send(self.get_reply("977", user, row=header))
        await user.send(self.get_reply("977", user, row=separator))

        for entry in shown:
            await user.send(self.get_reply("977", user, row=self._format_session_entry(entry, verbose=verbose)))

        await user.send(self.get_reply("978", user))

    @staticmethod
    def _parse_lastlogons_params(params):
        verbose = False
        limit = 50
        filter_parts = []

        for param in params or []:
            if str(param).upper() == "VERBOSE":
                verbose = True
            elif str(param).isdigit():
                limit = int(param)
            else:
                filter_parts.append(str(param))

        filter_text = " ".join(filter_parts) if filter_parts else "*"
        return verbose, filter_text, limit

    def _current_session_entries(self):
        now = int(time.time())
        entries = []
        for active_user in self.users.values():
            if active_user.is_virtual or active_user.is_remote or not active_user.registered:
                continue
            entries.append(self._build_session_entry(active_user, now, active=True))
        return entries

    def _record_session_history(self, user, logout_time, reason=None):
        if user.is_virtual or user.is_remote or user.nickname == "*" or not user.registered:
            return None
        entry = self._build_session_entry(user, logout_time, active=False, reason=reason)
        self.session_history.appendleft(entry)
        return entry

    async def _record_persistent_session_history(self, entry):
        if not self.db_pool:
            return
        try:
            async with self.db_pool.connection() as db:
                await db.execute(
                    """INSERT INTO connection_sessions
                       (nickname, username, realname, ip_address, host, logon_time, logout_time, duration, reason)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry.get('nick', ''),
                        entry.get('username', ''),
                        entry.get('realname', ''),
                        entry.get('ip', ''),
                        entry.get('host', ''),
                        entry.get('logon_time', 0),
                        entry.get('logout_time', 0),
                        entry.get('duration', 0),
                        entry.get('reason', ''),
                    )
                )
                await db.execute(
                    """DELETE FROM connection_sessions
                       WHERE id NOT IN (
                           SELECT id FROM connection_sessions
                           ORDER BY logon_time DESC, id DESC
                           LIMIT ?
                       )""",
                    (self.max_connection_sessions,)
                )
                if self.connection_session_retention_days:
                    cutoff = int(time.time()) - (self.connection_session_retention_days * 86400)
                    await db.execute(
                        "DELETE FROM connection_sessions WHERE logout_time < ?",
                        (cutoff,)
                    )
                await db.commit()
        except Exception as e:
            if self.debug_mode:
                logger.error("Connection session write failed: %s", e)

    async def _completed_session_entries(self):
        if not self.db_pool:
            return list(self.session_history)
        try:
            async with self.db_pool.connection() as db:
                async with db.execute(
                    """SELECT nickname, username, realname, ip_address, host,
                              logon_time, logout_time, duration, reason
                       FROM connection_sessions
                       ORDER BY logon_time DESC, id DESC
                       LIMIT ?""",
                    (self.max_connection_sessions,)
                ) as cursor:
                    rows = await cursor.fetchall()
            return [
                {
                    'nick': row[0],
                    'username': row[1],
                    'realname': row[2] or '',
                    'ip': row[3] or '',
                    'host': row[4] or '',
                    'logon_time': row[5],
                    'logout_time': row[6],
                    'duration': row[7],
                    'active': False,
                    'reason': row[8] or '',
                }
                for row in rows
            ]
        except Exception as e:
            if self.debug_mode:
                logger.error("Connection session lookup failed: %s", e)
            return list(self.session_history)

    def _build_session_entry(self, user, logout_time, active=False, reason=None):
        logon_time = int(getattr(user, 'signon_time', logout_time) or logout_time)
        logout_time = int(logout_time)
        return {
            'nick': user.nickname,
            'username': user.username,
            'realname': user.realname,
            'ip': user.ip,
            'host': user.host,
            'logon_time': logon_time,
            'logout_time': logout_time,
            'duration': max(0, logout_time - logon_time),
            'active': active,
            'reason': reason or "",
        }

    def _session_matches(self, entry, filter_text):
        if not filter_text or filter_text == "*":
            return True
        pattern = filter_text.replace('%', '*').lower()
        if '*' not in pattern and '?' not in pattern:
            pattern = f"*{pattern}*"
        fields = (
            entry.get('nick', ''),
            entry.get('username', ''),
            entry.get('realname', ''),
            entry.get('ip', ''),
            entry.get('host', ''),
        )
        return any(fnmatch.fnmatch(str(field).lower(), pattern) for field in fields)

    def _format_session_entry(self, entry, verbose=False):
        nick_width, user_width = self._lastlogons_name_widths()
        ip = entry.get('ip') or 'unknown'
        logon = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.get('logon_time', 0)))
        duration = self._format_session_duration(entry.get('duration', 0))
        status = "online" if entry.get('active') else "offline"
        row = (
            f"{self._clip(entry.get('nick', ''), nick_width):<{nick_width}} "
            f"{self._clip(entry.get('username', ''), user_width):<{user_width}} "
            f"{self._clip(entry.get('realname', ''), 20):<20} "
            f"{self._clip(ip, 39):<39} "
            f"{logon:<19} "
            f"{duration:>8} "
            f"{status:<7}"
        )
        if not verbose:
            return row

        logout = "-"
        if not entry.get('active'):
            logout = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.get('logout_time', 0)))
        reason = self._clip(entry.get('reason', ''), 50)
        return f"{row} {logout:<19} {reason:<50}"

    def _lastlogons_header_rows(self, verbose=False):
        nick_width, user_width = self._lastlogons_name_widths()
        columns = [
            ("Nickname", nick_width),
            ("Username", user_width),
            ("Real Name", 20),
            ("IP Address", 39),
            ("Logon Time", 19),
            ("Duration", 8),
            ("Status", 7),
        ]
        if verbose:
            columns.extend([
                ("Logout Time", 19),
                ("Reason", 50),
            ])
        header = " ".join(f"{label:<{width}}" for label, width in columns)
        separator = " ".join("-" * width for _, width in columns)
        return header, separator

    def _lastlogons_name_widths(self):
        nick_width = max(len("Nickname"), int(getattr(self, 'max_nick_length', 30) or 30))
        # Anonymous users get a server-added '~' prefix after USER validation.
        user_width = max(len("Username"), int(getattr(self, 'max_user_length', 30) or 30) + 1)
        return nick_width, user_width

    @staticmethod
    def _lastlogons_reply_token(filter_text):
        token = str(filter_text or "*").strip()
        return token.replace(" ", "_") or "*"

    @staticmethod
    def _clip(value, width):
        value = str(value or "")
        if len(value) <= width:
            return value
        if width <= 1:
            return value[:width]
        return value[:width - 1] + "~"

    @staticmethod
    def _format_session_duration(seconds):
        seconds = max(0, int(seconds or 0))
        days, rem = divmod(seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, secs = divmod(rem, 60)
        if days:
            return f"{days}d{hours:02d}h"
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    async def handle_list(self, user, is_listx=False, pattern=None):
        # Rate limit LIST/LISTX commands
        if not user.rate_limiter.check('LIST'):
            await user.send(self.get_reply("833", user))
            return

        # LISTX requires IRCX mode (+x)
        if is_listx and not (user.has_mode('x') or user.is_ircx):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_ircx'].format(command="LISTX")))
            return

        is_staff = user.is_staff()

        # Start batch for LIST response
        batch_type = "draft/listx-reply" if is_listx else "draft/list-reply"
        batch_id = await self.start_batch(user, batch_type)

        if is_listx:
            await self.send_batched(user, batch_id, self.get_reply("811", user))
            for name, channel in self.channels.items():
                # Hide +s (secret) and +h (hidden) channels from non-staff unless they're in it
                if (channel.modes.get('s', False) or channel.modes.get('h', False)) and not is_staff and user.nickname not in channel.members:
                    continue
                # Apply pattern filter if provided
                if pattern and not fnmatch.fnmatch(name.lower(), pattern.lower()):
                    continue

                # Build channel mode string for LISTX (no arguments, just flags)
                mode_str = "+"
                for mode_char in "tnsmihpklud":  # Common channel modes
                    if channel.modes.get(mode_char, False):
                        mode_str += mode_char
                # If no modes set, show just "+"
                if mode_str == "+":
                    mode_str = "+"

                await self.send_batched(user, batch_id, self.get_reply("812", user, channel=name, users=len(channel.members),
                                         modes=mode_str, topic=channel.topic or ""))
            await self.send_batched(user, batch_id, self.get_reply("813", user))
        else:
            await self.send_batched(user, batch_id, self.get_reply("321", user))
            for name, channel in self.channels.items():
                # Hide +s (secret) and +h (hidden) channels from non-staff unless they're in it
                if (channel.modes.get('s', False) or channel.modes.get('h', False)) and not is_staff and user.nickname not in channel.members:
                    continue
                # Apply pattern filter if provided
                if pattern and not fnmatch.fnmatch(name.lower(), pattern.lower()):
                    continue
                await self.send_batched(user, batch_id, self.get_reply("322", user, channel=name, users=len(channel.members),
                                         topic=channel.topic or ""))
            await self.send_batched(user, batch_id, self.get_reply("323", user))

        await self.end_batch(user, batch_id)

    async def handle_join(self, user, channel_name, key=None):
        is_staff = user.is_staff()

        # Validate channel name
        valid, error = validate_channel_name(channel_name)
        if not valid:
            await user.send(self.get_reply("479", user, channel=channel_name, error=error))
            return

        # Case-insensitive #System check
        if channel_name.lower() == "#system" and not is_staff:
            await user.send(self.get_reply("473", user, target="#System"))
            return

        # Use lock to prevent race condition where multiple users create the same channel
        async with self.channel_creation_lock:
            # Case-insensitive channel lookup
            channel, chan_name = self.get_channel(channel_name)

            # Check if trying to join a clone directly - redirect through original
            # Staff (SYSOP, ADMIN, GUIDE) and services/bots can join any clone directly
            if not channel and not is_staff and not user.is_virtual:
                original, original_name = self.get_clone_original(channel_name)
                if original:
                    # Redirect: treat as joining the original, clone logic will handle placement
                    channel = original
                    chan_name = original_name

            if not channel:
                # New channel - use provided name as canonical
                chan_name = channel_name
                # Try to load from database first if registered
                channel = await self.load_registered_channel(chan_name)
                if not channel:
                    # Not registered - create new dynamic channel
                    channel = Channel(chan_name)
                    # Fire CHANNEL/CREATE event for monitoring (new dynamic channel)
                    await self.fire_trap("CHANNEL", "CREATE", user, chan_name)
                self.channels[chan_name] = channel
                self.channels_lower[chan_name.lower()] = chan_name

        used_owner_key = key and channel.owner_key and key.lower() == channel.owner_key.lower()
        used_host_key = key and channel.host_key and key.lower() == channel.host_key.lower()
        used_voice_key = key and channel.voice_key and key.lower() == channel.voice_key.lower()

        # Check channel ACCESS lists for grants
        access_grants = channel.get_access_grants(user)
        has_access_grant = 'GRANT' in access_grants or 'OWNER' in access_grants or 'HOST' in access_grants or 'VOICE' in access_grants

        if not is_staff and not used_owner_key and not used_host_key and not used_voice_key:
            # Check ACCESS DENY (works like ban)
            denied, deny_reason = channel.check_access(user, 'DENY')
            if denied or channel.is_banned(user):
                await user.send(self.get_reply("474", user, target=chan_name))
                return
            # Check invite-only (ACCESS GRANT or access levels bypass this)
            if channel.modes.get('i') and chan_name not in user.invited_to and not has_access_grant:
                await user.send(self.get_reply("473", user, target=chan_name))
                return
            if channel.modes.get('k') and channel.key:
                if not key or key.lower() != channel.key.lower():
                    await user.send(self.get_reply("475", user, target=chan_name))
                    return
            # Effective limit is the lower of channel +l and server cap
            effective_limit = self.max_users_per_channel
            if channel.modes.get('l') and channel.user_limit:
                effective_limit = min(channel.user_limit, self.max_users_per_channel)
            if len(channel.members) >= effective_limit:
                # Check for clone mode - redirect to clone if enabled
                if channel.is_clone_enabled():
                    target = self.find_available_clone(channel)
                    if not target:
                        target = self.create_clone(channel)
                    channel = target
                    chan_name = channel.name
                else:
                    await user.send(self.get_reply("471", user, target=chan_name))
                    return

        user.invited_to.discard(chan_name)
        channel.members[user.nickname] = user
        user.channels.add(chan_name)  # Store canonical name

        # ADMINs, SYSOPs, and services/bots always get +q, owner key grants +q
        # First user gets +q ONLY for unregistered (dynamic) channels
        # Channel mode +g grants owner to guides
        # ACCESS OWNER/HOST/VOICE entries also grant modes
        is_high_staff = user.is_high_staff()
        is_service = user.has_mode('s')
        is_guide = user.has_mode('g')
        is_first_in_dynamic = len(channel.members) == 1 and not channel.registered
        guide_auto_op = channel.modes.get('g', False) and is_guide
        grant_owner = is_high_staff or is_service or is_first_in_dynamic or used_owner_key or 'OWNER' in access_grants or guide_auto_op
        grant_host = (used_host_key or 'HOST' in access_grants) and not grant_owner
        grant_voice = (used_voice_key or 'VOICE' in access_grants) and not grant_owner and not grant_host

        # Track mode to grant (applied after JOIN broadcast so clients see it)
        if grant_owner:
            channel.owners.add(user.nickname)
        elif grant_host:
            channel.hosts.add(user.nickname)
        elif grant_voice:
            channel.voices.add(user.nickname)

        # User sees their own unmasked host
        await user.send(f":{user.prefix(viewer=user)} JOIN {chan_name}")
        if channel.topic:
            await user.send(self.get_reply(
                "332", user, channel=chan_name, topic=channel.topic))
            # Send topic metadata (who set it and when) for proper client display
            if channel.topic_set_by:
                await user.send(self.get_reply("333", user,
                    channel=chan_name,
                    nick=channel.topic_set_by,
                    timestamp=channel.topic_set_at
                ))
        else:
            await user.send(self.get_reply("331", user, channel=chan_name))
        names = " ".join([channel.get_prefix(nick) + nick for nick in channel.members])
        await user.send(self.get_reply("353", user, channel=chan_name, names=names))
        await user.send(self.get_reply("366", user, channel=chan_name))
        
        # Send channel modes (324 numeric)
        modes = "".join([k for k, v in channel.modes.items() if v])
        # Add +r if channel is registered
        if channel.registered and 'r' not in modes:
            modes += 'r'
        # Sort modes for consistent display
        modes = ''.join(sorted(modes))
        mode_params = []
        if channel.modes.get('l') and channel.user_limit:
            mode_params.append(str(channel.user_limit))
        # Only show key to channel hosts/owners or staff
        can_see_key = (user.nickname in channel.owners or
                      user.nickname in channel.hosts or
                      user.is_high_staff())
        if channel.modes.get('k') and channel.key:
            if can_see_key:
                mode_params.append(channel.key)
            else:
                mode_params.append("*")  # Hide actual key
        param_str = " " + " ".join(mode_params) if mode_params else ""
        await user.send(self.get_reply("324", user, channel=chan_name, modes=modes, param_str=param_str))

        # Broadcast JOIN to LOCAL channel members with host masking
        # (exclude remote users to avoid routing loops)
        # IRCv3 extended-join: :nick!user@host JOIN #channel account :realname
        account = user.sasl_account or "*"
        tasks = []
        for member in channel.members.values():
            if member != user and not (member.is_remote):
                # Each viewer sees appropriately masked host
                prefix = user.prefix(viewer=member)
                if 'extended-join' in member.enabled_caps:
                    msg = f":{prefix} JOIN {chan_name} {account} :{user.realname}"
                else:
                    msg = f":{prefix} JOIN {chan_name}"
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Propagate JOIN to linked servers (if not a remote user) - use unmasked prefix
        if self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                server_msg = f":{user.prefix()} JOIN {chan_name}"
                logger.info(get_log_message("join_propagated_sending", message=server_msg))
                await self.link_manager.broadcast_to_servers(server_msg)
                logger.info(get_log_message("join_propagated", nickname=user.nickname, channel=chan_name))

        # Fire MEMBER/JOIN event for monitoring
        await self.fire_trap("MEMBER", "JOIN", user, chan_name)

        # Broadcast MODE after JOIN so other clients see the user first
        if grant_owner:
            mode_msg = f":{user.prefix()} MODE {chan_name} +q {user.nickname}"
            for member in channel.members.values():
                if not (member.is_remote):
                    await member.send(mode_msg)
            # Propagate MODE to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    await self.link_manager.broadcast_to_servers(mode_msg)
        elif grant_host:
            mode_msg = f":{user.prefix()} MODE {chan_name} +o {user.nickname}"
            for member in channel.members.values():
                if not (member.is_remote):
                    await member.send(mode_msg)
            # Propagate MODE to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    await self.link_manager.broadcast_to_servers(mode_msg)
        elif grant_voice:
            mode_msg = f":{user.prefix()} MODE {chan_name} +v {user.nickname}"
            for member in channel.members.values():
                if not (member.is_remote):
                    await member.send(mode_msg)
            # Propagate MODE to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    await self.link_manager.broadcast_to_servers(mode_msg)

        # Log to transcript if +y mode is enabled
        self.log_transcript(channel, "JOIN", user)

        # Send ONJOIN message if set (IRCX PROP ONJOIN)
        if channel.onjoin:
            # ONJOIN supports \n for multiple lines
            for line in channel.onjoin.replace('\\n', '\n').split('\n'):
                if line.strip():
                    await user.send(f":{chan_name}!{chan_name}@{self.servername} PRIVMSG {user.nickname} :{line}")

    async def handle_create(self, user, params):
        """Handle IRCX CREATE command - create channel with initial modes

        IRCX Syntax: CREATE <channel> [<modes> [<modeargs>]]

        Examples:
          CREATE #test
          CREATE #test +mnt
          CREATE #test +mntkl 50 secretkey
          CREATE #test +cmnt (fail if channel exists)

        Requirements:
          - User must be in IRCX mode (user.is_ircx)
          - Modes can only be applied to newly created channels
          - The 'c' flag causes failure if channel already exists
        """
        # IRCX mode requirement
        if not user.is_ircx:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_ircx'].format(command="CREATE")))
            return

        # Parse parameters
        if not params:
            await user.send(self.get_reply("461", user, command="CREATE"))
            return

        channel_name = params[0]
        modes_str = params[1] if len(params) > 1 else None
        mode_args = params[2:] if len(params) > 2 else []

        # Normalize mode string - add '+' if not present
        if modes_str and not modes_str.startswith('+') and not modes_str.startswith('-'):
            modes_str = '+' + modes_str

        is_staff = user.is_staff()

        # Validate channel name
        valid, error = validate_channel_name(channel_name)
        if not valid:
            await user.send(self.get_reply("479", user, channel=channel_name, error=error))
            return

        # Case-insensitive #System check
        if channel_name.lower() == "#system":
            await user.send(self.get_reply("473", user, target="#System"))
            return

        # Parse mode flags to check for 'c' (create-only) flag
        create_only = False
        if modes_str and modes_str.startswith('+'):
            create_only = 'c' in modes_str

        # Check if channel exists
        async with self.channel_creation_lock:
            channel, chan_name = self.get_channel(channel_name)

            # Handle 'c' flag - fail if channel already exists
            if create_only and channel:
                # ERR_CHANNELEXIST (IRCX extension - 926)
                await user.send(self.get_reply("926", user, channel=channel_name, message=SERVER_MESSAGES['channel_already_exists']))
                return

            # If channel exists, join it (modes are ignored for existing channels)
            if channel:
                # Channel exists - just join it (like regular JOIN)
                # Note: IRCX spec says modes cannot be applied to existing channels via CREATE
                await self.handle_join(user, channel_name, None)
                return

            # Channel doesn't exist - create it
            chan_name = channel_name

            # Try to load from database first if registered
            channel = await self.load_registered_channel(chan_name)
            if channel:
                # Registered channel loaded from DB - cannot apply modes via CREATE
                self.channels[chan_name] = channel
                self.channels_lower[chan_name.lower()] = chan_name
                # Just join it
                await self.handle_join(user, channel_name, None)
                return
            else:
                # Create new dynamic channel
                channel = Channel(chan_name)
                self.channels[chan_name] = channel
                self.channels_lower[chan_name.lower()] = chan_name

                # Fire CHANNEL/CREATE event for monitoring
                await self.fire_trap("CHANNEL", "CREATE", user, chan_name)

                # Apply initial modes if specified (only for new channels)
                if modes_str and modes_str.startswith('+'):
                    # Remove the 'c' flag from modes_str before applying (it's not a channel mode)
                    modes_to_apply = modes_str.replace('c', '')

                    if modes_to_apply and len(modes_to_apply) > 1:  # More than just '+'
                        # Parse and apply channel modes
                        await self._apply_create_modes(channel, user, modes_to_apply, mode_args)

        # Add user to channel
        channel.members[user.nickname] = user
        user.channels.add(chan_name)

        # User becomes owner of the channel
        channel.owners.add(user.nickname)

        # Send JOIN confirmation to user
        join_msg = f":{user.prefix()} JOIN {chan_name}"
        await user.send(join_msg)

        # Notify all other channel members
        for member in channel.members.values():
            if member != user and not (member.is_remote):
                await member.send(join_msg)

        # Propagate JOIN to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                await self.link_manager.broadcast_to_servers(join_msg)

        # Send topic if set
        if channel.topic:
            await user.send(self.get_reply("332", user, channel=chan_name, topic=channel.topic))
            if channel.topic_set_by and channel.topic_set_at:
                await user.send(self.get_reply("333", user, channel=chan_name,
                                         setter=channel.topic_set_by, time=channel.topic_set_at))
        else:
            await user.send(self.get_reply("331", user, channel=chan_name))

        # Send NAMES list
        names = " ".join([channel.get_prefix(nick) + nick for nick in channel.members])
        await user.send(self.get_reply("353", user, channel=chan_name, names=names))
        await user.send(self.get_reply("366", user, channel=chan_name))

        # Send MODE message showing applied modes
        if modes_str:
            mode_msg = f":{self.servername} MODE {chan_name} {modes_str}"
            if mode_args:
                mode_msg += " " + " ".join(mode_args)
            await user.send(mode_msg)

        # Send ONJOIN message if set (IRCX PROP ONJOIN)
        if channel.onjoin:
            # ONJOIN supports \n for multiple lines
            for line in channel.onjoin.replace('\\n', '\n').split('\n'):
                if line.strip():
                    await user.send(f":{chan_name}!{chan_name}@{self.servername} PRIVMSG {user.nickname} :{line}")

    async def _apply_create_modes(self, channel, user, modes_str, mode_args):
        """Apply initial modes during CREATE command

        Parses mode string like '+mntk' with arguments like ['secretkey']
        and applies them to the newly created channel.
        """
        if not modes_str or not modes_str.startswith('+'):
            return

        mode_chars = modes_str[1:]  # Remove the '+'
        arg_index = 0

        for mode_char in mode_chars:
            if mode_char in ['k', 'l', 'u']:
                # Modes that require arguments
                if arg_index < len(mode_args):
                    arg = mode_args[arg_index]
                    arg_index += 1

                    if mode_char == 'k':
                        # Channel key (password)
                        channel.key = arg
                        channel.modes['k'] = True
                    elif mode_char == 'l':
                        # User limit (capped at server maximum)
                        try:
                            limit = int(arg)
                            if limit > 0:
                                channel.user_limit = min(limit, self.max_users_per_channel)
                                channel.modes['l'] = True
                        except ValueError:
                            pass
                    elif mode_char == 'u':
                        # IRCX: Owner key
                        channel.owner_key = arg
                        channel.modes['u'] = True
            else:
                # Modes without arguments
                if mode_char in channel.modes:
                    channel.modes[mode_char] = True
    async def handle_part(self, user, channel_name):
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=channel_name))
            return
        if chan_name not in user.channels:
            await user.send(self.get_reply("442", user, target=chan_name))
            return
        # Broadcast PART to LOCAL channel members with host masking
        # (exclude remote users to avoid routing loops)
        tasks = []
        for member in channel.members.values():
            if not (member.is_remote):
                # Each viewer sees appropriately masked host
                prefix = user.prefix(viewer=member)
                msg = f":{prefix} PART {chan_name}"
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # Propagate PART to linked servers (if not a remote user) - use unmasked prefix
        if self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                server_msg = f":{user.prefix()} PART {chan_name}"
                await self.link_manager.broadcast_to_servers(server_msg)

        # Fire MEMBER/PART event for monitoring
        await self.fire_trap("MEMBER", "PART", user, chan_name)

        channel.members.pop(user.nickname, None)
        channel.owners.discard(user.nickname)
        channel.hosts.discard(user.nickname)
        channel.voices.discard(user.nickname)
        channel.gagged.discard(user.nickname)
        user.channels.discard(chan_name)

        # Log to transcript if +y mode is enabled (before channel deletion check)
        self.log_transcript(channel, "PART", user)

        # Send ONPART message if set (IRCX PROP ONPART)
        if channel.onpart:
            for line in channel.onpart.replace('\\n', '\n').split('\n'):
                if line.strip():
                    await user.send(f":{chan_name}!{chan_name}@{self.servername} NOTICE {user.nickname} :{line}")

        # Delete dynamic (unregistered) channels when empty
        # Registered channels and #System persist even when empty
        if len(channel.members) == 0 and not channel.registered and chan_name.lower() != "#system":
            # Fire CHANNEL/DELETE event for monitoring (last user caused deletion)
            await self.fire_trap("CHANNEL", "DELETE", user, chan_name)

            # If this is a clone, remove from parent's clone_children list
            if channel.is_clone() and channel.clone_parent:
                parent, _ = self.get_channel(channel.clone_parent)
                if parent and chan_name in parent.clone_children:
                    parent.clone_children.remove(chan_name)
            del self.channels[chan_name]
            self.channels_lower.pop(chan_name.lower(), None)

    async def handle_away(self, user, params):
        if params:
            away_msg = params[0].lstrip(':')
            max_away = CONFIG.get('limits', 'max_away_length', default=200)
            if len(away_msg) > max_away:
                away_msg = away_msg[:max_away]
            user.away_msg = away_msg
            await user.send(self.get_reply("306", user))
            # Propagate AWAY status to linked servers
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    away_msg = f":{user.prefix()} AWAY :{user.away_msg}"
                    await self.link_manager.broadcast_to_servers(away_msg)
            # IRCv3 away-notify: notify users in shared channels
            await self.send_away_notify(user)
        else:
            user.away_msg = None
            await user.send(self.get_reply("305", user))
            # Propagate AWAY removal (no message = back from away)
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    away_msg = f":{user.prefix()} AWAY"
                    await self.link_manager.broadcast_to_servers(away_msg)
            # IRCv3 away-notify: notify users in shared channels
            await self.send_away_notify(user)

    async def send_away_notify(self, user):
        """Send IRCv3 away-notify to users in shared channels"""
        # Find all users who share channels with this user and have away-notify
        notified = set()
        for chan_name in user.channels:
            channel = self.channels.get(chan_name)
            if not channel:
                continue
            for member_nick in channel.members:
                if member_nick in notified or member_nick == user.nickname:
                    continue
                member = self.users.get(member_nick)
                if member and not member.is_remote and 'away-notify' in member.enabled_caps:
                    if user.away_msg:
                        await member.send(f":{user.prefix()} AWAY :{user.away_msg}")
                    else:
                        await member.send(f":{user.prefix()} AWAY")
                    notified.add(member_nick)

    async def send_account_notify(self, user):
        """Send IRCv3 account-notify to users in shared channels"""
        # Find all users who share channels with this user and have account-notify
        account = user.sasl_account or "*"
        notified = set()
        for chan_name in user.channels:
            channel = self.channels.get(chan_name)
            if not channel:
                continue
            for member_nick in channel.members:
                if member_nick in notified or member_nick == user.nickname:
                    continue
                member = self.users.get(member_nick)
                if member and not member.is_remote and 'account-notify' in member.enabled_caps:
                    await member.send(f":{user.prefix()} ACCOUNT {account}")
                    notified.add(member_nick)

    async def send_chghost_notify(self, user, old_user, old_host):
        """Send IRCv3 chghost notification to users in shared channels

        Args:
            user: The user whose host changed
            old_user: The old username (before change)
            old_host: The old host (before change)
        """
        notified = set()
        for chan_name in user.channels:
            channel = self.channels.get(chan_name)
            if not channel:
                continue
            for member_nick in channel.members:
                if member_nick in notified or member_nick == user.nickname:
                    continue
                member = self.users.get(member_nick)
                if member and not member.is_remote and 'chghost' in member.enabled_caps:
                    # Format: :nick!olduser@oldhost CHGHOST newuser newhost
                    await member.send(f":{user.nickname}!{old_user}@{old_host} CHGHOST {user.username} {user.host}")
                    notified.add(member_nick)

    async def send_setname_notify(self, user):
        """Send IRCv3 setname notification to users in shared channels"""
        notified = set()
        for chan_name in user.channels:
            channel = self.channels.get(chan_name)
            if not channel:
                continue
            for member_nick in channel.members:
                if member_nick in notified or member_nick == user.nickname:
                    continue
                member = self.users.get(member_nick)
                if member and not member.is_remote and 'setname' in member.enabled_caps:
                    await member.send(f":{user.prefix()} SETNAME :{user.realname}")
                    notified.add(member_nick)

    # ==========================================================================
    # IRCv3 BATCH HELPERS
    # ==========================================================================

    _batch_counter = 0  # Class-level counter for unique batch IDs

    def _generate_batch_id(self):
        """Generate a unique batch reference tag"""
        pyIRCXServer._batch_counter += 1
        # Use a simple incrementing counter with server name hash for uniqueness
        return f"{pyIRCXServer._batch_counter:x}"

    async def start_batch(self, user, batch_type, *params):
        """Start a batch for a user if they support the batch capability

        Args:
            user: The user to send to
            batch_type: The batch type (e.g., 'chathistory', 'netjoin', or custom)
            *params: Additional parameters for the batch start

        Returns:
            batch_id if user supports batch, None otherwise
        """
        if 'batch' not in user.enabled_caps:
            return None

        batch_id = self._generate_batch_id()
        params_str = " ".join(str(p) for p in params) if params else ""
        if params_str:
            await user.send(f":{self.servername} BATCH +{batch_id} {batch_type} {params_str}")
        else:
            await user.send(f":{self.servername} BATCH +{batch_id} {batch_type}")
        return batch_id

    async def end_batch(self, user, batch_id):
        """End a batch for a user

        Args:
            user: The user to send to
            batch_id: The batch ID returned from start_batch
        """
        if batch_id is None:
            return
        await user.send(f":{self.servername} BATCH -{batch_id}")

    async def send_batched(self, user, batch_id, message):
        """Send a message as part of a batch

        Args:
            user: The user to send to
            batch_id: The batch ID (or None for non-batched)
            message: The message to send (without batch tag)
        """
        if batch_id and 'batch' in user.enabled_caps:
            # Prepend the batch tag
            await user.send(f"@batch={batch_id} {message}")
        else:
            await user.send(message)

    # ==========================================================================
    # IRCv3 MESSAGE ID GENERATION
    # ==========================================================================

    _msgid_counter = 0  # Class-level counter for unique message IDs

    def _generate_msgid(self):
        """Generate a unique message ID for IRCv3 msgid tag"""
        pyIRCXServer._msgid_counter += 1
        return f"{self.servername_short}-{pyIRCXServer._msgid_counter:x}"

    # ==========================================================================
    # IRCv3 UNIFIED TAG BUILDING
    # ==========================================================================

    def _build_msg_tags(self, user, include_msgid=True):
        """Build full tag prefix string combining client-only tags, msgid, account, and bot.

        Returns the tag prefix string (e.g., '@+reply=x;msgid=abc;account=nick ')
        or empty string if no tags.
        """
        parts = []

        # Client-only tags (from sender's message)
        msg_tags = getattr(user, '_msg_tags', None)
        if msg_tags:
            for k, v in msg_tags.items():
                if k.startswith('+'):
                    parts.append(f"{k}={_escape_tag_value(v)}" if v is not None else k)

        # Server-generated tags
        if include_msgid:
            parts.append(f"msgid={self._generate_msgid()}")
        account = user.sasl_account or '*'
        parts.append(f"account={account}")

        # Bot tag for users with +b mode
        if user.has_mode('b'):
            parts.append("bot")

        if not parts:
            return ""
        return f"@{';'.join(parts)} "

    # ==========================================================================
    # IRCv3 STANDARD REPLIES (FAIL/WARN/NOTE)
    # ==========================================================================

    async def send_fail(self, user, command, code, *context, description=""):
        """Send a FAIL standard reply (IRCv3 standard-replies)"""
        ctx = " ".join(context)
        if ctx:
            await user.send(f":{self.servername} FAIL {command} {code} {ctx} :{description}")
        else:
            await user.send(f":{self.servername} FAIL {command} {code} :{description}")

    async def send_warn(self, user, command, code, *context, description=""):
        """Send a WARN standard reply (IRCv3 standard-replies)"""
        ctx = " ".join(context)
        if ctx:
            await user.send(f":{self.servername} WARN {command} {code} {ctx} :{description}")
        else:
            await user.send(f":{self.servername} WARN {command} {code} :{description}")

    async def send_note(self, user, command, code, *context, description=""):
        """Send a NOTE standard reply (IRCv3 standard-replies)"""
        ctx = " ".join(context)
        if ctx:
            await user.send(f":{self.servername} NOTE {command} {code} {ctx} :{description}")
        else:
            await user.send(f":{self.servername} NOTE {command} {code} :{description}")

    # ==========================================================================
    # IRCv3 CHATHISTORY
    # ==========================================================================

    async def handle_chathistory(self, user, params):
        """Handle CHATHISTORY command - retrieve channel history.

        Syntax:
            CHATHISTORY LATEST <target> * <limit>
            CHATHISTORY BEFORE <target> timestamp=<ts> <limit>
            CHATHISTORY AFTER <target> timestamp=<ts> <limit>
            CHATHISTORY BETWEEN <target> timestamp=<ts1> timestamp=<ts2> <limit>

        Requires: Channel membership and +y mode on channel.
        """
        if not params or len(params) < 3:
            await self.send_fail(user, "CHATHISTORY", "NEED_MORE_PARAMS",
                                 description="Not enough parameters")
            return

        subcmd = params[0].upper()
        target = params[1]

        if subcmd not in ('LATEST', 'BEFORE', 'AFTER', 'BETWEEN'):
            await self.send_fail(user, "CHATHISTORY", "INVALID_PARAMS", subcmd,
                                 description="Unknown subcommand")
            return

        # Resolve channel
        channel, chan_name = self.get_channel(target)
        if not channel:
            await self.send_fail(user, "CHATHISTORY", "INVALID_TARGET", target,
                                 description="No such channel")
            return

        # Must be a member
        if not channel.has_member(user.nickname):
            await self.send_fail(user, "CHATHISTORY", "INVALID_TARGET", chan_name,
                                 description="You are not on that channel")
            return

        # Channel must have +y (transcript) mode
        if not channel.modes.get('y', False):
            await self.send_fail(user, "CHATHISTORY", "INVALID_TARGET", chan_name,
                                 description="Channel does not have history enabled")
            return

        # Parse limit (last param)
        max_history = CONFIG.get('limits', 'max_chathistory', default=100)
        try:
            limit = int(params[-1])
            limit = max(1, min(limit, max_history))
        except ValueError:
            limit = 50

        # Get transcript lines
        all_lines = self.get_transcript(chan_name, lines=max_history)

        if subcmd == 'LATEST':
            lines = all_lines[-limit:]
        elif subcmd == 'BEFORE':
            ts_ref = self._parse_chathistory_ref(params[2])
            lines = [l for l in all_lines
                     if self._transcript_timestamp(l) and
                     ts_ref and self._transcript_timestamp(l) < ts_ref][-limit:]
        elif subcmd == 'AFTER':
            ts_ref = self._parse_chathistory_ref(params[2])
            lines = [l for l in all_lines
                     if self._transcript_timestamp(l) and
                     ts_ref and self._transcript_timestamp(l) > ts_ref][:limit]
        elif subcmd == 'BETWEEN':
            if len(params) < 5:
                await self.send_fail(user, "CHATHISTORY", "NEED_MORE_PARAMS",
                                     description="BETWEEN requires two timestamps")
                return
            ts_start = self._parse_chathistory_ref(params[2])
            ts_end = self._parse_chathistory_ref(params[3])
            if ts_start and ts_end and ts_start > ts_end:
                ts_start, ts_end = ts_end, ts_start
            lines = [l for l in all_lines
                     if self._transcript_timestamp(l) and
                     ts_start and ts_end and
                     ts_start <= self._transcript_timestamp(l) <= ts_end][:limit]
        else:
            lines = []

        # Send as batch
        batch_id = await self.start_batch(user, "chathistory", chan_name)

        for line in lines:
            irc_msg = self._transcript_to_privmsg(line, chan_name)
            if irc_msg:
                await self.send_batched(user, batch_id, irc_msg)

        await self.end_batch(user, batch_id)

    def _parse_chathistory_ref(self, ref):
        """Parse a CHATHISTORY reference (timestamp=... or msgid=...)."""
        from datetime import datetime, timezone
        if ref == '*':
            return None
        if ref.startswith('timestamp='):
            ts_str = ref[10:]
            try:
                ts_str = ts_str.rstrip('Z')
                if '.' in ts_str:
                    return datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%f').replace(tzinfo=timezone.utc)
                else:
                    return datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None  # msgid refs not supported (no persistent msgid storage)

    def _transcript_timestamp(self, line):
        """Extract datetime from transcript line format [YYYY-MM-DD HH:MM:SS]."""
        from datetime import datetime, timezone
        if line.startswith('[') and ']' in line:
            ts_str = line[1:line.index(']')]
            try:
                return datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            except ValueError:
                return None
        return None

    def _transcript_to_privmsg(self, line, channel):
        """Convert a transcript log line to IRC PRIVMSG format.

        Input formats:
            [2024-01-15 10:30:00] <nick> message      -> PRIVMSG
            [2024-01-15 10:30:00] -nick- message       -> NOTICE
            [2024-01-15 10:30:00] * nick message       -> PRIVMSG ACTION

        Returns formatted IRC message or None for non-message lines.
        """
        if not line.startswith('[') or ']' not in line:
            return None

        ts_end = line.index(']')
        ts_str = line[1:ts_end]
        content = line[ts_end + 2:].rstrip('\n')

        # Generate server-time tag from transcript timestamp
        try:
            from datetime import datetime, timezone
            ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            time_tag = ts.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        except ValueError:
            time_tag = None

        time_prefix = f"time={time_tag};" if time_tag else ""

        if content.startswith('<') and '>' in content:
            nick = content[1:content.index('>')]
            msg = content[content.index('>') + 2:]
            return f"@{time_prefix}msgid=history-{hash(line) & 0xFFFFFFFF:08x} :{nick}!*@* PRIVMSG {channel} :{msg}"
        elif content.startswith('-') and '- ' in content[1:]:
            nick = content[1:content.index('-', 1)]
            msg = content[content.index('-', 1) + 2:]
            return f"@{time_prefix}msgid=history-{hash(line) & 0xFFFFFFFF:08x} :{nick}!*@* NOTICE {channel} :{msg}"
        elif content.startswith('* '):
            parts = content[2:].split(' ', 1)
            if len(parts) == 2:
                nick, msg = parts
                return f"@{time_prefix}msgid=history-{hash(line) & 0xFFFFFFFF:08x} :{nick}!*@* PRIVMSG {channel} :\x01ACTION {msg}\x01"

        return None  # JOIN/PART/QUIT/etc not replayed as messages

    # ==========================================================================
    # IRCv3 CHANNEL RENAME
    # ==========================================================================

    async def handle_rename(self, user, params):
        """Handle RENAME command - rename a channel (staff only).

        Syntax: RENAME <oldchannel> <newchannel> [:<reason>]
        """
        if not user.is_high_staff():
            await user.send(self.get_reply("481", user, message="Permission denied - RENAME requires ADMIN or SYSOP"))
            return

        if len(params) < 2:
            await user.send(self.get_reply("461", user, command="RENAME"))
            return

        old_name = params[0]
        new_name = params[1]
        reason = params[2] if len(params) > 2 else "Channel renamed"

        # Validate new channel name
        if not is_channel(new_name):
            await self.send_fail(user, "RENAME", "INVALID_PARAMS", new_name,
                                 description="Invalid channel name")
            return

        # Check channel name length
        max_chanlen = CONFIG.get('limits', 'max_channel_length', default=50)
        if len(new_name) > max_chanlen:
            await self.send_fail(user, "RENAME", "INVALID_PARAMS", new_name,
                                 description="Channel name too long")
            return

        # Find old channel
        channel, old_canonical = self.get_channel(old_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=old_name))
            return

        # Check new name isn't taken
        existing, _ = self.get_channel(new_name)
        if existing:
            await self.send_fail(user, "RENAME", "CHANNEL_NAME_IN_USE", new_name,
                                 description="Channel already exists")
            return

        # Perform rename
        # 1. Remove old entries
        del self.channels[old_canonical]
        self.channels_lower.pop(old_canonical.lower(), None)

        # 2. Update channel object
        channel.name = new_name

        # 3. Add new entries
        self.channels[new_name] = channel
        self.channels_lower[new_name.lower()] = new_name

        # 4. Update member channel lists
        for member in channel.members.values():
            if old_canonical in member.channels:
                member.channels.discard(old_canonical)
                member.channels.add(new_name)

        # 5. Notify all members
        rename_msg = f":{self.servername} RENAME {old_canonical} {new_name} :{reason}"
        for member in channel.members.values():
            if not member.is_remote:
                await member.send(rename_msg)

        # 6. Propagate to linked servers
        if self.link_manager and self.link_manager.enabled:
            await self.link_manager.broadcast_to_servers(rename_msg)

    async def handle_topic(self, user, params):
        if not params:
            await user.send(self.get_reply("461", user, command="TOPIC"))
            return

        channel, chan_name = self.get_channel(params[0])
        if not channel:
            await user.send(self.get_reply("403", user, target=params[0]))
            return

        if user.nickname not in channel.members:
            await user.send(self.get_reply("442", user, target=chan_name))
            return

        if len(params) == 1:
            if channel.topic:
                await user.send(self.get_reply(
                    "332", user, channel=chan_name, topic=channel.topic))
                if channel.topic_set_by:
                    await user.send(self.get_reply("333", user,
                        channel=chan_name,
                        nick=channel.topic_set_by,
                        timestamp=channel.topic_set_at
                    ))
            else:
                await user.send(self.get_reply("331", user, channel=chan_name))
        else:
            # Rate limit topic changes
            if not user.rate_limiter.check('TOPIC'):
                await user.send(self.get_reply("830", user))
                return

            new_topic = params[1]
            if channel.modes.get('t'):
                if not (user.nickname in channel.owners or
                       user.nickname in channel.hosts or
                       user.has_mode('a')):
                    await user.send(self.get_reply("482", user, target=chan_name))
                    return

            # Enforce topic length limit
            max_topic_len = CONFIG.get('limits', 'max_topic_length', default=390)
            if len(new_topic) > max_topic_len:
                new_topic = new_topic[:max_topic_len]

            channel.topic = new_topic
            channel.topic_set_by = user.nickname
            channel.topic_set_at = int(time.time())

            msg = f":{user.prefix()} TOPIC {chan_name} :{new_topic}"
            # Broadcast to LOCAL channel members only
            for member in channel.members.values():
                if not (member.is_remote):
                    await member.send(msg)
            # Propagate TOPIC to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    await self.link_manager.broadcast_to_servers(msg)

            # Fire CHANNEL/TOPIC event for monitoring
            await self.fire_trap("CHANNEL", "TOPIC", user, chan_name)

            # Log to transcript if +y mode is enabled
            self.log_transcript(channel, "TOPIC", user, message=new_topic)
            logger.info(get_log_message("topic_set", channel=chan_name, nickname=user.nickname))

    async def handle_transcript(self, user, params):
        """
        Handle TRANSCRIPT command to view channel transcript logs.

        Syntax:
            TRANSCRIPT #channel [lines] [offset]

        Requires: Channel owner/host or staff (+o/+a) to view
        The channel must have +y mode enabled.
        """
        # Rate limit TRANSCRIPT commands
        if not user.rate_limiter.check('TRANSCRIPT'):
            await user.send(self.get_reply("830", user))
            return

        if not params:
            await user.send(self.get_reply("461", user, command="TRANSCRIPT"))
            return

        channel_name = params[0]
        if not is_channel(channel_name):
            await user.send(self.get_reply("403", user, target=channel_name))
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=channel_name))
            return

        # Check permissions - must be channel owner or high staff (operator/administrator)
        is_owner = user.nickname in channel.owners
        is_high_staff = user.is_high_staff()
        if not (is_owner or is_high_staff):
            await user.send(self.get_reply("482", user, target=chan_name))
            return

        # Check if transcript mode is enabled
        if not channel.modes.get('y', False):
            await user.send(self.get_reply("845", user, channel=chan_name))
            return

        # Parse optional line count and offset
        lines = 50  # default
        offset = 0
        if len(params) > 1:
            try:
                lines = int(params[1])
                lines = max(1, min(lines, 500))  # Clamp between 1 and 500
            except ValueError:
                pass
        if len(params) > 2:
            try:
                offset = int(params[2])
                offset = max(0, offset)
            except ValueError:
                pass

        # Get transcript
        transcript_lines = self.get_transcript(channel_name, lines, offset)

        if not transcript_lines:
            await self.send_server_message(user, "transcript_unavailable", channel=channel_name)
            return

        # Send transcript header
        await self.send_server_message(user, "transcript_header", channel=channel_name, count=len(transcript_lines))

        # Send each line
        for line in transcript_lines:
            await self.send_raw_notice(user, line)

        # Send transcript footer
        await self.send_server_message(user, "transcript_footer")

    async def handle_knock(self, user, params):
        # Rate limit KNOCK commands
        if not user.rate_limiter.check('KNOCK'):
            await user.send(self.get_reply("830", user))
            return

        if not params:
            await user.send(self.get_reply("461", user, command="KNOCK"))
            return

        channel_name = params[0]
        message = params[1] if len(params) > 1 else ""

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=channel_name))
            return

        if user.nickname in channel.members:
            await user.send(self.get_reply("714", user, target=chan_name))
            return

        if not channel.modes.get('i'):
            await user.send(self.get_reply("713", user, target=chan_name))
            return

        if channel.is_banned(user):
            await user.send(self.get_reply("474", user, target=chan_name))
            return

        # Channel mode +u: knock mode (knocking restricted - staff and ACCESS GRANT can bypass)
        if channel.modes.get('u', False):
            is_staff = user.is_staff()
            access_grants = channel.get_access_grants(user)
            has_access_grant = 'GRANT' in access_grants or 'OWNER' in access_grants or 'HOST' in access_grants or 'VOICE' in access_grants
            if not is_staff and not has_access_grant:
                await user.send(self.get_reply("716", user, target=chan_name))
                return

        now = time.time()
        last_knock = channel.knock_cooldowns.get(user.nickname, 0)
        if now - last_knock < 60:
            await user.send(self.get_reply("712", user, target=chan_name))
            return
        channel.knock_cooldowns[user.nickname] = now

        msg = "has asked for an invite"
        if message:
            msg = f"has asked for an invite ({message})"
        knock_msg = self.get_reply("710", user, channel=chan_name, knocker=user.nickname, host=user.prefix(), message=msg)

        # Send to LOCAL owners/hosts only
        for nick in channel.members:
            if nick in channel.owners or nick in channel.hosts:
                member = channel.members[nick]
                if not (member.is_remote):
                    await member.send(knock_msg)

        # Propagate KNOCK to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                knock_cmd = f":{user.prefix()} KNOCK {chan_name}"
                if message:
                    knock_cmd += f" :{message}"
                await self.link_manager.broadcast_to_servers(knock_cmd)

        await user.send(self.get_reply("711", user, target=chan_name))

    async def handle_prop(self, user, params):
        # Rate limit PROP commands
        if not user.rate_limiter.check('PROP'):
            await user.send(self.get_reply("830", user))
            return

        # Require IRCX mode (+x)
        if not (user.has_mode('x') or user.is_ircx):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_ircx'].format(command="PROP")))
            return

        if not params:
            await user.send(self.get_reply("461", user, command="PROP"))
            return

        channel_name = params[0]

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=channel_name))
            return

        if len(params) == 1:
            for prop_name, prop_value in channel.props.items():
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop=prop_name, value=prop_value))
            await user.send(self.get_reply("818", user, target=chan_name))
            return

        prop_name = params[1]
        prop_upper = prop_name.upper()

        # Handle read-only properties
        READ_ONLY_PROPS = {'CREATION', 'ACCOUNT'}

        if len(params) == 2:
            # Query mode - handle special properties
            if prop_upper == 'CREATION':
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='CREATION', value=str(channel.created_at)))
                return
            elif prop_upper == 'ACCOUNT':
                value = channel.account_uuid if channel.account_uuid else ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='ACCOUNT', value=value))
                return
            elif prop_upper == 'TOPIC':
                value = channel.topic or ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='TOPIC', value=value))
                return
            elif prop_upper == 'ONJOIN':
                value = channel.onjoin or ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='ONJOIN', value=value))
                return
            elif prop_upper == 'ONPART':
                value = channel.onpart or ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='ONPART', value=value))
                return
            elif prop_upper == 'MEMBERKEY':
                value = channel.key or ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='MEMBERKEY', value=value))
                return
            elif prop_upper == 'HOSTKEY':
                value = channel.host_key or ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='HOSTKEY', value=value))
                return
            elif prop_upper == 'OWNERKEY':
                # Only owners can view OWNERKEY
                if user.nickname not in channel.owners and not user.has_mode('a'):
                    await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['ownerkey_owners_only']))
                    return
                value = channel.owner_key or ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='OWNERKEY', value=value))
                return
            elif prop_upper == 'VOICEKEY':
                value = channel.voice_key or ""
                await user.send(self.get_reply("817", user, target=chan_name,
                                         prop='VOICEKEY', value=value))
                return
            prop_value = channel.props.get(prop_name, "")
            await user.send(self.get_reply("817", user, target=chan_name,
                                     prop=prop_name, value=prop_value))
            return

        # Check for write attempts to read-only props
        if prop_upper in READ_ONLY_PROPS:
            await user.send(self.get_reply("846", user, channel=chan_name, prop=prop_name))
            return

        # Only channel owners or admins can set properties
        if not (user.nickname in channel.owners or user.has_mode('a')):
            await user.send(self.get_reply("482", user, target=chan_name))
            return

        prop_value = params[2] if len(params) > 2 else ""

        if prop_value:
            if prop_upper == 'TOPIC':
                # Enforce topic length limit
                max_topic_len = CONFIG.get('limits', 'max_topic_length', default=390)
                if len(prop_value) > max_topic_len:
                    prop_value = prop_value[:max_topic_len]
                channel.topic = prop_value
            elif prop_upper == 'ONJOIN':
                channel.onjoin = prop_value
            elif prop_upper == 'ONPART':
                channel.onpart = prop_value
            else:
                channel.props[prop_name] = prop_value
            if prop_upper == 'MEMBERKEY':
                channel.key = prop_value
                channel.modes['k'] = True
            elif prop_upper == 'HOSTKEY':
                channel.host_key = prop_value
            elif prop_upper == 'OWNERKEY':
                channel.owner_key = prop_value
            elif prop_upper == 'VOICEKEY':
                channel.voice_key = prop_value
        else:
            if prop_upper == 'TOPIC':
                channel.topic = ""
            elif prop_upper == 'ONJOIN':
                channel.onjoin = None
            elif prop_upper == 'ONPART':
                channel.onpart = None
            else:
                channel.props.pop(prop_name, None)
            if prop_upper == 'MEMBERKEY':
                channel.key = None
                channel.modes['k'] = False
            elif prop_upper == 'HOSTKEY':
                channel.host_key = None
            elif prop_upper == 'OWNERKEY':
                channel.owner_key = None
            elif prop_upper == 'VOICEKEY':
                channel.voice_key = None

        await user.send(self.get_reply("819", user, target=chan_name,
                                 prop=prop_name, value=prop_value))
        logger.info(get_log_message("prop_set", channel=chan_name, prop=prop_name, value=prop_value, nickname=user.nickname))

        # Propagate PROP command to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                prop_cmd = f":{user.prefix()} PROP {' '.join(params)}"
                await self.link_manager.broadcast_to_servers(prop_cmd)

    async def handle_invite(self, user, params):
        # Rate limit INVITE commands
        if not user.rate_limiter.check('INVITE'):
            await user.send(self.get_reply("830", user))
            return

        if len(params) < 2:
            await user.send(self.get_reply("461", user, command="INVITE"))
            return

        target_nick = params[0]
        channel_name = params[1]

        # Case-insensitive nickname lookup
        target = self.get_user(target_nick)
        if not target:
            await user.send(self.get_reply("401", user, target=target_nick))
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=channel_name))
            return

        if user.nickname not in channel.members:
            await user.send(self.get_reply("442", user, target=chan_name))
            return

        # Channel mode +j: no invitations allowed (staff, services, and ACCESS GRANT can bypass)
        if channel.modes.get('j', False):
            is_staff = user.is_staff()
            is_service = user.nickname in self.servicebots
            access_grants = channel.get_access_grants(user)
            has_access_grant = 'GRANT' in access_grants or 'OWNER' in access_grants or 'HOST' in access_grants or 'VOICE' in access_grants
            if not is_staff and not is_service and not has_access_grant:
                await user.send(self.get_reply("844", user, channel=chan_name))
                return

        if channel.modes.get('i'):
            if not (user.nickname in channel.owners or
                    user.nickname in channel.hosts or
                    user.has_mode('a')):
                await user.send(self.get_reply("482", user, target=chan_name))
                return

        if target.nickname in channel.members:
            await user.send(self.get_reply("443", user, target=target.nickname, channel=chan_name))
            return

        # ServiceBot dispatcher - pick available bot from pool
        if target.nickname == "ServiceBot":
            if not user.is_staff():
                await user.send(self.get_reply("848", user))
                return

            # Find first available ServiceBot
            available_bot = None
            for bot_name in sorted(self.servicebots.keys()):  # Sort to get ServiceBot01, 02, etc. in order
                bot = self.servicebots[bot_name]
                max_chans = getattr(bot, 'max_channels', 10)
                if len(bot.channels) < max_chans:
                    available_bot = (bot_name, bot)
                    break

            if not available_bot:
                await user.send(self.get_reply("847", user, target="ServiceBot", max=max_chans))
                return

            bot_name, bot = available_bot
            # Auto-join the available bot
            await self._join_virtual_service_to_channel(bot, channel, chan_name)
            await self.send_server_message(user, "servicebot_dispatched", bot=bot_name, channel=chan_name)
            logger.info(get_log_message("servicebot_dispatcher_assigned", bot=bot_name, channel=chan_name, nickname=user.nickname))
            return

        # ServiceBot invitation - Staff only (guide/operator/administrator)
        if target.nickname in self.servicebots:
            if not user.is_staff():
                await user.send(self.get_reply("848", user))
                return
            bot = self.servicebots[target.nickname]
            max_chans = getattr(bot, 'max_channels', 10)
            if len(bot.channels) >= max_chans:
                await user.send(self.get_reply("847", user, target=target.nickname, max=max_chans))
                return
            # ServiceBot joins the channel automatically
            await self._join_virtual_service_to_channel(bot, channel, chan_name)
            await user.send(self.get_reply("341", user, target=target.nickname, channel=chan_name))
            logger.info(get_log_message("servicebot_invited", bot=target.nickname, channel=chan_name, nickname=user.nickname))
            return

        # System and God mystical entities - Auto-join like ServiceBots (silent observers)
        if target.nickname.lower() in ['system', 'god']:
            # Normalize entity name to proper capitalization
            entity_name = 'System' if target.nickname.lower() == 'system' else 'God'
            entity_user = self.users.get(entity_name)

            # Only admins can invite mystical entities
            if not user.has_mode('a'):
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['admin_invite_only'].format(entity=entity_name)))
                return

            # Auto-join the entity to the channel
            await self._join_virtual_service_to_channel(entity_user, channel, chan_name)
            await user.send(self.get_reply("341", user, target=entity_name, channel=chan_name))
            logger.info(get_log_message("entity_invited", entity=entity_name, channel=chan_name, nickname=user.nickname))
            return

        target.invited_to.add(chan_name)
        await user.send(self.get_reply("341", user, target=target.nickname, channel=chan_name))

        # Send INVITE to target (local or route to remote server)
        invite_msg = f":{user.prefix()} INVITE {target.nickname} :{chan_name}"
        if target.is_remote:
            # Target is on a remote server, route through link manager
            if self.link_manager and self.link_manager.enabled:
                await self.link_manager.broadcast_to_servers(invite_msg)
        else:
            # Target is local, send directly
            await target.send(invite_msg)

        # IRCv3 invite-notify: notify channel members with the capability
        for member_nick in channel.members:
            if member_nick == user.nickname:
                continue
            member = self.users.get(member_nick)
            if member and 'invite-notify' in member.enabled_caps:
                await member.send(f":{user.prefix()} INVITE {target.nickname} {chan_name}")

    async def handle_access(self, user, params):
        """
        IRCX ACCESS command - manage access lists for channels or server.

        Requires IRCX mode (+x).

        Syntax:
            ACCESS <object> LIST [level]
            ACCESS <object> ADD <level> <mask> [timeout] [:<reason>]
            ACCESS <object> DELETE <level> <mask>
            ACCESS <object> CLEAR [level]

        Objects:
            #channel - Channel access list
            $ or *   - Server access list (staff only)

        Levels:
            OWNER - Grants +q on join (channel only)
            HOST  - Grants +o on join (channel only)
            VOICE - Grants +v on join (channel only)
            GRANT - Allows access (bypasses +i for channels)
            DENY  - Denies access (acts as ban)

        Timeout: Minutes until entry expires (0 = permanent)
        """
        # Rate limit ACCESS commands
        if not user.rate_limiter.check('ACCESS'):
            await user.send(self.get_reply("830", user))
            return

        # Require IRCX mode (+x)
        if not (user.has_mode('x') or user.is_ircx):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_ircx'].format(command="ACCESS")))
            return

        if len(params) < 2:
            await user.send(self.get_reply("461", user, command="ACCESS"))
            return

        obj = params[0]
        action = params[1].upper()

        # Determine if this is server or channel access
        is_server_access = obj in ('$', '*')
        channel = None
        chan_name = None

        if is_server_access:
            # Server access requires staff
            if not user.is_high_staff():
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command="ACCESS (server)")))
                return
            valid_levels = ['GRANT', 'DENY']
        else:
            # Channel access
            channel, chan_name = self.get_channel(obj)
            if not channel:
                await user.send(self.get_reply("403", user, target=obj))
                return
            # Require channel owner/host or staff
            if not (user.nickname in channel.owners or user.nickname in channel.hosts or
                    user.is_high_staff()):
                await user.send(self.get_reply("482", user, target=chan_name))
                return
            valid_levels = ['OWNER', 'HOST', 'VOICE', 'GRANT', 'DENY']

        if action in ("LIST", "L"):
            filter_level = params[2].upper() if len(params) > 2 else None
            if filter_level and filter_level not in valid_levels:
                filter_level = None
            levels_to_show = [filter_level] if filter_level else valid_levels

            if is_server_access:
                access_data = self.access_list
                target_name = "server"
            else:
                access_data = channel.access_list
                target_name = chan_name

            await user.send(self.get_reply("803", user, target=target_name, message=SERVER_MESSAGES['access_list_start']))
            now = int(time.time())
            for level in levels_to_show:
                if level not in access_data:
                    continue
                for entry in access_data[level]:
                    mask, set_by, set_at, timeout, reason = entry
                    # Check if expired
                    if timeout > 0 and now >= timeout:
                        continue
                    timeout_str = f" ({(timeout - now) // 60}m)" if timeout > 0 else ""
                    reason_str = f" :{reason}" if reason else ""
                    await user.send(self.get_reply("804", user, target=target_name, level=level, mask=mask, set_by=set_by, details=f"{timeout_str}{reason_str}"))
            await user.send(self.get_reply("805", user, target=target_name))

        elif action in ("ADD", "A"):
            if len(params) < 4:
                await user.send(self.get_reply("461", user, command="ACCESS ADD"))
                return

            level = params[2].upper()
            if level not in valid_levels:
                await user.send(self.get_reply("850", user, levels=', '.join(valid_levels)))
                return

            mask = params[3]
            timeout = 0  # Default permanent
            reason = ""

            # Parse optional timeout and reason
            if len(params) > 4:
                # Check if it's a timeout (number) or reason (starts with :)
                if params[4].startswith(':'):
                    reason = params[4].lstrip(':')
                else:
                    try:
                        timeout_mins = int(params[4])
                        if timeout_mins > 0:
                            timeout = int(time.time()) + (timeout_mins * 60)
                    except ValueError:
                        pass
                    if len(params) > 5:
                        reason = params[5].lstrip(':')

            if is_server_access:
                access_data = self.access_list
                target_name = "server"
            else:
                access_data = channel.access_list
                target_name = chan_name

            # Check if mask already exists
            for i, (m, _, _, _, _) in enumerate(access_data[level]):
                if m.lower() == mask.lower():
                    await user.send(self.get_reply("851", user, mask=mask, level=level))
                    return

            # Cannot add services to DENY lists
            if level == 'DENY':
                def mask_targets_service(mask_value: str) -> bool:
                    nick_pattern = mask_value.split('!', 1)[0].strip() if mask_value else ''
                    if not nick_pattern:
                        return False

                    # Known service nicknames (even if not currently connected)
                    service_nicks = {
                        self.system_nick,
                        'System',
                        'God',
                        'Registrar',
                        'Messenger',
                        'NewsFlash',
                        'OperServ',
                        'HelpServ',
                        'InfoServ',
                        'BotServ',
                        'HostServ',
                        'StatServ',
                        'Global',
                        'ALIS',
                        'Services',
                        'ServiceBot',
                    }

                    # Include configured ServiceBots
                    try:
                        bot_count = CONFIG.get('services', 'servicebot_count', default=10)
                        for i in range(1, int(bot_count) + 1):
                            service_nicks.add(f"ServiceBot{i:02d}")
                    except Exception:
                        pass

                    # Include any connected service users
                    for nick, u in self.users.items():
                        if u.is_service():
                            service_nicks.add(nick)

                    nick_pattern_lower = nick_pattern.lower()
                    for nick in service_nicks:
                        if fnmatch.fnmatch(nick.lower(), nick_pattern_lower):
                            return True
                    return False

                if mask_targets_service(mask):
                    await user.send(self.get_reply("825", user, target=mask))
                    return

                for nick, u in self.users.items():
                    if u.is_service():
                        user_mask = f"{nick}!{u.username}@{u.host}"
                        if fnmatch.fnmatch(user_mask.lower(), mask.lower()) or fnmatch.fnmatch(nick.lower(), mask.lower()):
                            await user.send(self.get_reply("825", user, target=mask))
                            return

            # Add the entry: (mask, set_by, set_at, timeout, reason)
            timestamp = int(time.time())
            access_data[level].append((mask, user.nickname, timestamp, timeout, reason))

            # For server access, persist to database
            if is_server_access:
                try:
                    async with self.db_pool.connection() as db:
                        await db.execute(
                            "INSERT INTO server_access (type, pattern, set_by, set_at, timeout, reason) VALUES (?, ?, ?, ?, ?, ?)",
                            (level, mask, user.nickname, timestamp, timeout, reason)
                        )
                        await db.commit()
                except Exception as e:
                    logger.error(get_log_message("access_add_error", error=e))

            timeout_str = f" for {params[4]} minutes" if timeout > 0 else ""
            await user.send(self.get_reply("854", user, target=target_name, level=level, mask=mask, timeout=timeout_str))
            logger.info(get_log_message("access_add", target=target_name, level=level, mask=mask, nickname=user.nickname))

            # Propagate ACCESS command to linked servers (for channels only)
            if not is_server_access and self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    access_cmd = f":{user.prefix()} ACCESS {' '.join(params)}"
                    await self.link_manager.broadcast_to_servers(access_cmd)

        elif action in ("DELETE", "DEL", "D"):
            if len(params) < 4:
                await user.send(self.get_reply("461", user, command="ACCESS DELETE"))
                return

            level = params[2].upper()
            if level not in valid_levels:
                await user.send(self.get_reply("850", user, levels=', '.join(valid_levels)))
                return

            mask = params[3]

            if is_server_access:
                access_data = self.access_list
                target_name = "server"
            else:
                access_data = channel.access_list
                target_name = chan_name

            # Find and remove
            found = False
            for i, (m, set_by, _, _, _) in enumerate(access_data[level]):
                if m.lower() == mask.lower():
                    # Hosts can't remove owner-added entries (unless they're staff)
                    if not is_server_access and user.nickname in channel.hosts and user.nickname not in channel.owners:
                        if set_by in channel.owners and not user.is_high_staff():
                            await user.send(self.get_reply("853", user))
                            return
                    access_data[level].pop(i)
                    found = True
                    break

            if not found:
                await user.send(self.get_reply("852", user, mask=mask, level=level))
                return

            # For server access, remove from database
            if is_server_access:
                try:
                    async with self.db_pool.connection() as db:
                        await db.execute(
                            "DELETE FROM server_access WHERE type = ? AND pattern = ?",
                            (level, mask)
                        )
                        await db.commit()
                except Exception as e:
                    logger.error(get_log_message("access_del_error", error=e))

            await user.send(self.get_reply("855", user, target=target_name, level=level, mask=mask))
            logger.info(get_log_message("access_del", target=target_name, level=level, mask=mask, nickname=user.nickname))

            # Propagate ACCESS DELETE to linked servers (for channels only)
            if not is_server_access and self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    access_cmd = f":{user.prefix()} ACCESS {' '.join(params)}"
                    await self.link_manager.broadcast_to_servers(access_cmd)

        elif action in ("CLEAR", "C"):
            level = params[2].upper() if len(params) > 2 else None

            if is_server_access:
                access_data = self.access_list
                target_name = "server"
            else:
                # Only owners can CLEAR (not hosts)
                if user.nickname not in channel.owners and not user.is_high_staff():
                    await user.send(self.get_reply("857", user))
                    return
                access_data = channel.access_list
                target_name = chan_name

            levels_to_clear = [level] if level and level in valid_levels else valid_levels
            cleared = 0

            for lvl in levels_to_clear:
                if lvl in access_data:
                    cleared += len(access_data[lvl])
                    access_data[lvl] = []

            # For server access, clear from database
            if is_server_access:
                try:
                    async with self.db_pool.connection() as db:
                        if level:
                            await db.execute("DELETE FROM server_access WHERE type = ?", (level,))
                        else:
                            await db.execute("DELETE FROM server_access")
                        await db.commit()
                except Exception as e:
                    logger.error(get_log_message("access_clear_error", error=e))

            level_str = level if level else "all levels"
            await user.send(self.get_reply("856", user, target=target_name, count=cleared, level=level_str))

            # Propagate ACCESS CLEAR to linked servers (for channels only)
            if not is_server_access and self.link_manager and self.link_manager.enabled:
                if not (user.is_remote):
                    access_cmd = f":{user.prefix()} ACCESS {' '.join(params)}"
                    await self.link_manager.broadcast_to_servers(access_cmd)
            logger.info(get_log_message("access_clear", target=target_name, level=level_str, nickname=user.nickname))

        else:
            await user.send(self.get_reply("461", user, command="ACCESS"))

    async def handle_stats(self, user, params):
        """
        STATS command implementation.
        Public flags (anyone):
          s: online staff listing
          u: system uptime
        Staff flags (GUIDE+):
          a: online ADMINs
          o: online SYSOPs
          g: online GUIDEs
          i: invisible users count
          k: ACCESS DENY list
          s: services/bots (mode +s)
          z: gagged users
          c: configuration
          d: database info
          l: links (placeholder)
          y: anonymous users count
          x: IRCX users count
          w: authenticated users count
        """
        # Rate limit STATS queries
        if not user.rate_limiter.check('STATS'):
            await user.send(self.get_reply("830", user))
            await user.send(self.get_reply("219", user, flag="*"))
            return
        if not params:
            await user.send(self.get_reply("219", user, flag="*"))
            return

        flag = params[0].lower() if params[0] not in ('?', '*') else params[0]
        is_staff = user.is_staff()
        is_admin = user.has_mode('a')

        # STATS ? - Help menu (also shown when no flag provided)
        if flag == '?' or not flag:
            await self.send_server_message(user, "stats_help_header")
            await self.send_server_message(user, "stats_help_general_header")
            await self.send_server_message(user, "stats_help_general_u")
            await self.send_server_message(user, "stats_help_general_s")
            await self.send_server_message(user, "stats_help_general_i")
            await self.send_server_message(user, "stats_help_general_x")
            await self.send_server_message(user, "stats_help_general_w")
            await self.send_server_message(user, "stats_help_general_y")
            await self.send_server_message(user, "stats_help_general_c")
            await self.send_server_message(user, "stats_help_general_f")
            await self.send_server_message(user, "stats_help_general_n")

            # Show guide/staff flags only if user is staff
            if user.is_staff() or user.is_high_staff():
                await self.send_server_message(user, "stats_help_staff_header")
                await self.send_server_message(user, "stats_help_staff_a")
                await self.send_server_message(user, "stats_help_staff_o")
                await self.send_server_message(user, "stats_help_staff_g")
                await self.send_server_message(user, "stats_help_staff_b")
                await self.send_server_message(user, "stats_help_staff_z")

            # Show operator/administrator flags only if user is operator or administrator
            if user.is_high_staff():
                await self.send_server_message(user, "stats_help_oper_header")
                await self.send_server_message(user, "stats_help_oper_d")
                await self.send_server_message(user, "stats_help_oper_k")
                await self.send_server_message(user, "stats_help_oper_l")
                await self.send_server_message(user, "stats_help_oper_m")
                await self.send_server_message(user, "stats_help_oper_p")
                await self.send_server_message(user, "stats_help_oper_t")
                await self.send_server_message(user, "stats_help_oper_v")
                await self.send_server_message(user, "stats_help_oper_star")

            await self.send_server_message(user, "stats_help_footer")
            await user.send(self.get_reply("219", user, flag=flag if flag else '?'))
            return

        # STATS * - All stats combined (Operator+ only)
        if flag == '*':
            if not user.is_high_staff():
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command="STATS *")))
                await user.send(self.get_reply("219", user, flag=flag))
                return

            await self.send_server_message(user, "stats_all_header")

            # Uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            secs = uptime_secs % 60
            await self.send_server_message(user, "stats_uptime", days=days, hours=hours, mins=mins, secs=secs)

            # User counts - Single iteration for performance
            user_stats = {
                'total': 0, 'invisible': 0, 'ircx': 0, 'auth': 0,
                'anon': 0, 'gagged': 0, 'admins': 0, 'sysops': 0, 'guides': 0
            }

            for u in self.users.values():
                if u.is_virtual:
                    continue

                user_stats['total'] += 1
                if u.has_mode('i'):
                    user_stats['invisible'] += 1
                if u.is_ircx:
                    user_stats['ircx'] += 1
                if u.authenticated:
                    user_stats['auth'] += 1
                if u.username.startswith('~'):
                    user_stats['anon'] += 1
                if u.has_mode('z'):
                    user_stats['gagged'] += 1
                if u.has_mode('a'):
                    user_stats['admins'] += 1
                elif u.has_mode('o'):
                    user_stats['sysops'] += 1
                if u.has_mode('g'):
                    user_stats['guides'] += 1

            await self.send_server_message(user, "stats_users_header")
            await self.send_server_message(user, "stats_users_total", count=user_stats['total'])
            await self.send_server_message(user, "stats_users_invisible", count=user_stats['invisible'])
            await self.send_server_message(user, "stats_users_ircx", count=user_stats['ircx'])
            await self.send_server_message(user, "stats_users_auth", count=user_stats['auth'])
            await self.send_server_message(user, "stats_users_anon", count=user_stats['anon'])
            await self.send_server_message(user, "stats_users_gagged", count=user_stats['gagged'])

            # Staff counts (already collected above)

            await self.send_server_message(user, "stats_staff_header")
            await self.send_server_message(user, "stats_staff_admins", count=user_stats['admins'])
            await self.send_server_message(user, "stats_staff_sysops", count=user_stats['sysops'])
            await self.send_server_message(user, "stats_staff_guides", count=user_stats['guides'])

            # Channel stats - Single iteration for performance
            chan_stats = {'global': 0, 'local': 0, 'registered': 0}
            for c in self.channels.values():
                if c.name.startswith('&'):
                    chan_stats['local'] += 1
                else:
                    chan_stats['global'] += 1
                if c.registered:
                    chan_stats['registered'] += 1

            await self.send_server_message(user, "stats_channels_header")
            await self.send_server_message(user, "stats_channels_global", count=chan_stats['global'])
            await self.send_server_message(user, "stats_channels_local", count=chan_stats['local'])
            await self.send_server_message(user, "stats_channels_registered", count=chan_stats['registered'])

            # Access lists
            deny_count = len(self.access_list['DENY'])
            grant_count = len(self.access_list['GRANT'])

            await self.send_server_message(user, "stats_access_header")
            await self.send_server_message(user, "stats_access_deny", count=deny_count)
            await self.send_server_message(user, "stats_access_grant", count=grant_count)

            # Server stats
            await self.send_server_message(user, "stats_server_header")
            await self.send_server_message(user, "stats_server_commands", count=self.stats.get('commands_processed', 0))
            await self.send_server_message(user, "stats_server_connections", count=self.stats.get('total_connections', 0))
            await self.send_server_message(user, "stats_server_max_users", count=self.max_users_seen)

            # Command usage (all commands)
            if self.stats.get('command_usage'):
                await self.send_server_message(user, "stats_command_header")
                sorted_cmds = sorted(self.stats['command_usage'].items(), key=lambda x: x[1], reverse=True)
                for cmd, count in sorted_cmds:
                    await self.send_server_message(user, "stats_command_entry", command=cmd, count=count)

            # Peak usage
            await self.send_server_message(user, "stats_peak_header")
            await self.send_server_message(user, "stats_peak_users", count=self.stats['peak_users'])
            if self.stats['peak_time']:
                import datetime
                peak_dt = datetime.datetime.fromtimestamp(self.stats['peak_time'])
                await self.send_server_message(user, "stats_peak_time", time=peak_dt.strftime('%Y-%m-%d %H:%M:%S'))

            # Flood protection
            await self.send_server_message(user, "stats_flood_header")
            await self.send_server_message(user, "stats_flood_events", count=self.stats['flood_events'])
            flood_msgs = CONFIG.get('security', 'flood_messages', default=5)
            flood_window = CONFIG.get('security', 'flood_window', default=2.0)
            await self.send_server_message(user, "stats_flood_threshold", msgs=flood_msgs, window=flood_window)

            # Message statistics
            await self.send_server_message(user, "stats_message_header")
            await self.send_server_message(user, "stats_total_messages", count=self.stats['messages_sent'])
            if self.stats.get('messages_by_channel'):
                await self.send_server_message(user, "stats_active_channels_by_msg")
                sorted_channels = sorted(self.stats['messages_by_channel'].items(), key=lambda x: x[1], reverse=True)
                for channel, cnt in sorted_channels:
                    await self.send_server_message(user, "stats_channel_msg_entry", channel=channel, count=cnt)

            # ServiceBot statistics
            if self.servicebot_enabled:
                await self.send_server_message(user, "stats_servicebot_header")
                await self.send_server_message(user, "stats_active_bots", count=len(self.servicebots))
                if self.stats.get('servicebot_violations'):
                    total_violations = sum(self.stats['servicebot_violations'].values())
                    await self.send_server_message(user, "stats_total_violations", count=total_violations)
                    all_violations = sorted(self.stats['servicebot_violations'].items(), key=lambda x: x[1], reverse=True)
                    for vtype, cnt in all_violations:
                        await self.send_server_message(user, "stats_violation_entry", type=vtype, count=cnt)
                if self.stats.get('servicebot_actions'):
                    total_actions = sum(self.stats['servicebot_actions'].values())
                    await self.send_server_message(user, "stats_total_actions", count=total_actions)
                # User bots (+b mode, excluding services)
                bot_users = [u for u in self.users.values() if u.has_mode('b') and not u.has_mode('s')]
                await self.send_server_message(user, "stats_bot_users", count=len(bot_users))

            # Ban statistics
            await self.send_server_message(user, "stats_ban_header")
            await self.send_server_message(user, "stats_access_deny", count=len(self.access_list['DENY']))
            await self.send_server_message(user, "stats_server_bans", count=len(self.server_bans))

            # Database statistics
            await self.send_server_message(user, "stats_database_header")
            try:
                if os.path.exists(self.db_path):
                    size = os.path.getsize(self.db_path)
                    await self.send_server_message(user, "stats_db_path", path=self.db_path)
                    await self.send_server_message(user, "stats_db_size_bytes", size=size, kb=size / 1024)
                    try:
                        stats = await self._get_db_stats()
                        await self.send_server_message(user, "stats_db_nicks", count=stats['nicks'])
                        await self.send_server_message(user, "stats_db_channels", count=stats['channels'])
                        await self.send_server_message(user, "stats_db_messages", count=stats['messages'])
                    except Exception as e:
                        logger.error(get_log_message("database_stats_error", error=e))
                        await self.send_server_message(user, "stats_db_unavailable")
                else:
                    await self.send_server_message(user, "stats_db_not_configured")
            except Exception as e:
                logger.error(get_log_message("stats_error", error=e))
                await self.send_server_message(user, "stats_unavailable")

            # Configuration summary
            await self.send_server_message(user, "stats_config_header")
            await self.send_server_message(user, "ssl_server", server=self.servername)
            await self.send_server_message(user, "ssl_network", network=self.network_name)
            await self.send_server_message(user, "stats_version", version=__version__, label=__version_label__)
            dnsbl_status = 'enabled' if CONFIG.get('security', 'dnsbl', 'enabled', default=False) else 'disabled'
            await self.send_server_message(user, "stats_dnsbl", status=dnsbl_status)

            # SSL/TLS status
            if SSL_MANAGER:
                ssl_info = SSL_MANAGER.get_info()
                await self.send_server_message(user, "stats_ssl_header")
                if ssl_info.get('enabled'):
                    await self.send_server_message(user, "ssl_enabled")
                    if ssl_info.get('context_loaded'):
                        await self.send_server_message(user, "stats_ssl_cert", file=ssl_info.get('cert_file', 'N/A'))
                        if 'expiry' in ssl_info:
                            days_left = ssl_info.get('days_left', 0)
                            status = "OK" if days_left > 14 else ("WARNING" if days_left > 3 else "CRITICAL")
                            await self.send_server_message(user, "stats_ssl_expires", expiry=ssl_info['expiry'], days=days_left, status=status)
                        if ssl_info.get('subject'):
                            await self.send_server_message(user, "stats_ssl_subject", subject=ssl_info['subject'])
                    else:
                        await self.send_server_message(user, "ssl_no_certs")
                else:
                    await self.send_server_message(user, "ssl_disabled")

            # Performance metrics (v2.0.0 optimizations)
            await self.send_server_message(user, "stats_perf_header")
            config_reloads = self.stats.get('config_cache_reloads', 0)
            await self.send_server_message(user, "stats_config_reloads", count=config_reloads)
            await self.send_server_message(user, "stats_channel_monitors", count=len(self.channel_monitors))
            if config_reloads > 0:
                messages_per_reload = self.stats['messages_sent'] // config_reloads if config_reloads else 0
                await self.send_server_message(user, "stats_avg_msg_reload", count=messages_per_reload)

            # Real-time metrics
            await self.send_server_message(user, "stats_realtime_header")
            # Calculate current rates
            if self.stats['commands_per_minute']:
                recent_cmds = list(self.stats['commands_per_minute'])[-5:]  # Last 5 minutes
                avg_cmd_rate = sum(recent_cmds) / len(recent_cmds) if recent_cmds else 0
                await self.send_server_message(user, "stats_cmd_rate_avg", rate=avg_cmd_rate)
                max_cmd_rate = max(self.stats['commands_per_minute']) if self.stats['commands_per_minute'] else 0
                await self.send_server_message(user, "stats_cmd_rate_peak", count=max_cmd_rate)

            # Current load
            current_load_pct = (user_stats['total'] / self.max_users) * 100
            await self.send_server_message(user, "stats_current_load", pct=current_load_pct, current=user_stats['total'], max=self.max_users)

            # Historical trends
            await self.send_server_message(user, "stats_history_header")
            if self.stats.get('busiest_channels'):
                top_channels = sorted(self.stats['busiest_channels'].items(), key=lambda x: x[1], reverse=True)
                await self.send_server_message(user, "stats_busiest_channels")
                for channel, cnt in top_channels:
                    await self.send_server_message(user, "stats_busiest_channel_entry", channel=channel, count=cnt)

            if self.stats.get('most_active_users'):
                top_users = sorted(self.stats['most_active_users'].items(), key=lambda x: x[1], reverse=True)
                await self.send_server_message(user, "stats_most_active_users")
                for username, cnt in top_users:
                    await self.send_server_message(user, "stats_most_active_user_entry", username=username, count=cnt)

            # Distributed/linking stats
            if hasattr(self, 'link_manager') and self.link_manager and self.link_manager.enabled:
                await self.send_server_message(user, "stats_distributed_header")
                server_role = CONFIG.get('linking', 'server_role', default='trunk')
                await self.send_server_message(user, "stats_server_role", role=server_role.upper())
                linked_count = len(self.link_manager.linked_servers)
                await self.send_server_message(user, "stats_linked_servers", count=linked_count)

                if linked_count > 0:
                    await self.send_server_message(user, "stats_connected_servers")
                    for server_name, linked_server in self.link_manager.linked_servers.items():
                        user_count = getattr(linked_server, 'user_count', 0)
                        await self.send_server_message(user, "stats_linked_server_entry", server=server_name, users=user_count)

                # Network divergence/convergence history
                if self.stats['network_divergence_history']:
                    await self.send_server_message(user, "stats_divergence_header", count=len(self.stats['network_divergence_history']))
                    import datetime
                    for timestamp, server, reason in self.stats['network_divergence_history'][-5:]:
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        await self.send_server_message(user, "stats_divergence_entry", server=server, time=dt.strftime('%H:%M:%S'), reason=reason)

                if self.stats['network_convergence_history']:
                    await self.send_server_message(user, "stats_convergence_header", count=len(self.stats['network_convergence_history']))
                    import datetime
                    for timestamp, server in self.stats['network_convergence_history'][-5:]:
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        await self.send_server_message(user, "stats_convergence_entry", server=server, time=dt.strftime('%H:%M:%S'))

            await self.send_server_message(user, "stats_all_footer")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Public stats - available to all users
        if flag == 'u':
            # System uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            secs = uptime_secs % 60
            await user.send(self.get_reply("242", user, days=days, hours=hours, mins=mins, secs=secs))
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Define permission tiers for STATS flags
        PUBLIC_FLAGS = {'u', 's', 'i', 'x', 'w', 'y', 'c', 'f', 'n'}
        GUIDE_FLAGS = {'a', 'o', 'g', 'b', 'z'}
        OPERATOR_FLAGS = {'d', 'k', 'l', 'm', 'p', 't', 'v'}

        # Check permissions based on flag
        is_high_staff = user.is_high_staff()

        if flag in OPERATOR_FLAGS and not is_high_staff:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command=f"STATS {flag}")))
            await user.send(self.get_reply("219", user, flag=flag))
            return

        if flag in GUIDE_FLAGS and not is_staff:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_staff'].format(command=f"STATS {flag}")))
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Staff listing - public for everyone (optimized single pass)
        if flag == 's':
            await self.send_server_message(user, "stats_online_staff")
            staff_found = False
            for u in self.users.values():
                if u.is_virtual:
                    continue
                if u.has_mode('a'):
                    await self.send_server_message(user, "stats_staff_admin_entry", nickname=u.nickname)
                    staff_found = True
                elif u.has_mode('o'):
                    await self.send_server_message(user, "stats_staff_oper_entry", nickname=u.nickname)
                    staff_found = True
                elif u.has_mode('g'):
                    await self.send_server_message(user, "stats_staff_guide_entry", nickname=u.nickname)
                    staff_found = True
            if not staff_found:
                await self.send_server_message(user, "stats_no_staff")
            await self.send_server_message(user, "stats_end_staff")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        if flag == 'a':
            # Online IRC administrators
            admins = [u for u in self.users.values() if u.has_mode('a') and not u.is_virtual]
            await self.send_server_message(user, "stats_admins_header", count=len(admins))
            if not admins:
                await self.send_server_message(user, "stats_no_admins")
            else:
                for u in admins:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await self.send_server_message(user, "stats_admin_entry", prefix=f"{u.nickname}!{u.username}@{u.host}", idle=idle_str)
            await self.send_server_message(user, "stats_admins_footer")

        elif flag == 'o':
            # Online IRC operators
            sysops = [u for u in self.users.values() if u.has_mode('o') and not u.has_mode('a') and not u.is_virtual]
            await self.send_server_message(user, "stats_opers_header", count=len(sysops))
            if not sysops:
                await self.send_server_message(user, "stats_no_opers")
            else:
                for u in sysops:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await self.send_server_message(user, "stats_oper_entry", prefix=f"{u.nickname}!{u.username}@{u.host}", idle=idle_str)
            await self.send_server_message(user, "stats_opers_footer")

        elif flag == 'g':
            # Online IRC Guides
            guides = [u for u in self.users.values() if u.has_mode('g') and not u.is_virtual]
            await self.send_server_message(user, "stats_guides_header", count=len(guides))
            if not guides:
                await self.send_server_message(user, "stats_no_guides")
            else:
                for u in guides:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await self.send_server_message(user, "stats_guide_entry", prefix=f"{u.nickname}!{u.username}@{u.host}", idle=idle_str)
            await self.send_server_message(user, "stats_guides_footer")

        elif flag == 'i':
            # Invisible users count
            count = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
            await self.send_server_message(user, "stats_invisible_count", count=count)

        elif flag == 'k':
            # Ban statistics - ACCESS DENY + server bans
            await self.send_server_message(user, "stats_ban_header")

            # ACCESS DENY list
            await self.send_server_message(user, "stats_access_deny_entries", count=len(self.access_list['DENY']))
            if self.access_list['DENY']:
                for pattern, set_by, set_at, reason in self.access_list['DENY']:
                    reason_str = f" :{reason}" if reason else ""
                    await self.send_server_message(user, "stats_access_deny_entry", pattern=pattern, by=set_by, reason=reason_str)

            # Server bans
            await self.send_server_message(user, "stats_server_bans_count", count=len(self.server_bans))
            if self.server_bans:
                for ip, (expires_at, reason, set_by) in list(self.server_bans.items()):
                    if expires_at == 0:
                        duration = "permanent"
                    else:
                        remaining = expires_at - int(time.time())
                        if remaining > 0:
                            duration = f"{remaining}s remaining"
                        else:
                            duration = "expired"
                    await self.send_server_message(user, "stats_server_ban_entry", ip=ip, duration=duration, by=set_by)

            await self.send_server_message(user, "stats_end")

        elif flag == 's':
            # Services/bots (users with +s mode) - includes virtual services
            await self.send_server_message(user, "stats_services_bots_header")
            for u in self.users.values():
                if u.is_service():
                    await self.send_server_message(user, "stats_service_entry", prefix=f"{u.nickname}!{u.username}@{u.host}")
            await self.send_server_message(user, "stats_end")

        elif flag == 'z':
            # Gagged users
            await self.send_server_message(user, "stats_gagged_header")
            for u in self.users.values():
                if u.has_mode('z') and not u.is_virtual:
                    await self.send_server_message(user, "stats_gagged_entry", prefix=f"{u.nickname}!{u.username}@{u.host}")
            await self.send_server_message(user, "stats_end")

        elif flag == 'c':
            # Configuration
            await self.send_server_message(user, "stats_config_header")
            await self.send_server_message(user, "ssl_server", server=self.servername)
            await self.send_server_message(user, "ssl_network", network=self.network_name)
            await self.send_server_message(user, "stats_version", version=__version__, label=__version_label__)
            await self.send_server_message(user, "stats_max_users", count=self.max_users)
            await self.send_server_message(user, "stats_user_modes", modes=CONFIG.get('modes', 'user', default='agiorsxz'))
            await self.send_server_message(user, "stats_chan_modes", modes=CONFIG.get('modes', 'channel', default='adefghijklmnprstuwxyz'))
            await self.send_server_message(user, "stats_flood_enabled", status=CONFIG.get('security', 'enable_flood_protection', default=True))
            await self.send_server_message(user, "stats_end")

        elif flag == 'd':
            # Database statistics
            await self.send_server_message(user, "stats_database_header")
            await self.send_server_message(user, "stats_db_path", path=self.db_path)
            try:
                db_path = self.db_path
                if os.path.exists(db_path):
                    size = os.path.getsize(db_path)
                    await self.send_server_message(user, "stats_db_size_bytes", size=size, kb=size / 1024)

                    try:
                        stats = await self._get_db_stats()
                        await self.send_server_message(user, "stats_db_nicks", count=stats['nicks'])
                        await self.send_server_message(user, "stats_db_channels", count=stats['channels'])
                        await self.send_server_message(user, "stats_db_messages", count=stats['messages'])
                        # News items (not in common stats)
                        async with self.db_pool.connection() as db:
                            async with db.execute("SELECT COUNT(*) FROM newsflash WHERE active = 1") as cursor:
                                row = await cursor.fetchone()
                                await self.send_server_message(user, "stats_db_news", count=row[0])
                    except Exception as e:
                        logger.error(get_log_message("newsflash_stats_error", error=e))
                        await self.send_server_message(user, "stats_news_unavailable")
                else:
                    await self.send_server_message(user, "stats_db_not_configured")
            except Exception as e:
                logger.error(get_log_message("newsflash_error", error=e))
                await self.send_server_message(user, "stats_news_temp_unavailable")
            await self.send_server_message(user, "stats_end")

        elif flag == 'l':
            # Server linking statistics
            await self.send_server_message(user, "stats_linking_header")
            linking_enabled = CONFIG.get('linking', 'enabled', default=False)
            await self.send_server_message(user, "stats_linking_enabled", status='enabled' if linking_enabled else 'disabled')
            if linking_enabled:
                bind_host = CONFIG.get('linking', 'bind_host', default='0.0.0.0')
                bind_port = CONFIG.get('linking', 'bind_port', default=7001)
                await self.send_server_message(user, "stats_linking_bind", host=bind_host, port=bind_port)
                links = CONFIG.get('linking', 'links', default=[])
                await self.send_server_message(user, "stats_linking_configured", count=len(links))
                if links:
                    for link in links:
                        await self.send_server_message(user, "stats_linking_name", name=link.get('name', 'unknown'))
                else:
                    await self.send_server_message(user, "stats_linking_none")
            await self.send_server_message(user, "stats_end")

        elif flag == 'y':
            # Anonymous users count (users with ~ prefix, not authenticated)
            count = sum(1 for u in self.users.values() if u.username.startswith('~') and not u.is_virtual)
            await self.send_server_message(user, "stats_anonymous_count", count=count)

        elif flag == 'x':
            # IRCX users count
            count = sum(1 for u in self.users.values() if u.is_ircx and not u.is_virtual)
            await self.send_server_message(user, "stats_ircx_count", count=count)

        elif flag == 'w':
            # Authenticated users count
            count = sum(1 for u in self.users.values() if u.authenticated and not u.is_virtual)
            await self.send_server_message(user, "stats_auth_count", count=count)

        elif flag == 't':
            # SSL/TLS status
            await self.send_server_message(user, "stats_ssl_header")
            if SSL_MANAGER:
                ssl_info = SSL_MANAGER.get_info()
                if ssl_info.get('enabled'):
                    await self.send_server_message(user, "ssl_enabled")
                    if ssl_info.get('context_loaded'):
                        await self.send_server_message(user, "stats_ssl_cert", file=ssl_info.get('cert_file', 'N/A'))
                        await self.send_server_message(user, "stats_ssl_key", file=ssl_info.get('key_file', 'N/A'))
                        if 'expiry' in ssl_info:
                            days_left = ssl_info.get('days_left', 0)
                            if days_left <= 0:
                                status = "EXPIRED"
                            elif days_left <= 3:
                                status = "CRITICAL"
                            elif days_left <= 14:
                                status = "WARNING"
                            else:
                                status = "OK"
                            await self.send_server_message(user, "stats_ssl_expires", expiry=ssl_info['expiry'], days=days_left, status=status)
                        if ssl_info.get('subject'):
                            await self.send_server_message(user, "stats_ssl_subject", subject=ssl_info['subject'])
                        min_ver = CONFIG.get('ssl', 'min_version', default='TLSv1.2')
                        await self.send_server_message(user, "stats_ssl_min_tls", version=min_ver)
                        ssl_ports = CONFIG.get('ssl', 'ports', default=[6697])
                        await self.send_server_message(user, "stats_ssl_ports", ports=', '.join(map(str, ssl_ports)))
                    else:
                        await self.send_server_message(user, "ssl_no_certs")
                else:
                    await self.send_server_message(user, "ssl_disabled")
            else:
                await self.send_server_message(user, "stats_ssl_not_init")
            await self.send_server_message(user, "stats_end")

        elif flag == 'p':
            # Peak usage statistics
            await self.send_server_message(user, "stats_peak_header")
            await self.send_server_message(user, "stats_peak_users", count=self.stats['peak_users'])
            if self.stats['peak_time']:
                import datetime
                peak_dt = datetime.datetime.fromtimestamp(self.stats['peak_time'])
                await self.send_server_message(user, "stats_peak_time", time=peak_dt.strftime('%Y-%m-%d %H:%M:%S'))
            await self.send_server_message(user, "stats_peak_current", count=sum(1 for u in self.users.values() if not u.is_virtual))
            await self.send_server_message(user, "stats_peak_max", count=self.max_users_seen)
            await self.send_server_message(user, "stats_end")

        elif flag == 'f':
            # Flood protection statistics
            await self.send_server_message(user, "stats_flood_header")
            flood_enabled = CONFIG.get('security', 'enable_flood_protection', default=True)
            await self.send_server_message(user, "stats_flood_status", status=flood_enabled)
            if flood_enabled:
                flood_msgs = CONFIG.get('security', 'flood_messages', default=5)
                flood_window = CONFIG.get('security', 'flood_window', default=2.0)
                await self.send_server_message(user, "stats_flood_config", msgs=flood_msgs, window=flood_window)
                await self.send_server_message(user, "stats_flood_total", count=self.stats['flood_events'])
            await self.send_server_message(user, "stats_end")

        elif flag == 'm':
            # Message statistics
            await self.send_server_message(user, "stats_message_header")
            await self.send_server_message(user, "stats_total_messages", count=self.stats['messages_sent'])

            # Most active channels (all)
            if self.stats['messages_by_channel']:
                await self.send_server_message(user, "stats_most_active_channels")
                sorted_channels = sorted(self.stats['messages_by_channel'].items(), key=lambda x: x[1], reverse=True)
                for channel, cnt in sorted_channels:
                    await self.send_server_message(user, "stats_active_channel_entry", channel=channel, count=cnt)
            else:
                await self.send_server_message(user, "stats_no_message_data")

            # Current channels
            total_channels = len([c for c in self.channels.values() if not c.name.startswith('&')])
            await self.send_server_message(user, "stats_active_channels", count=total_channels)
            await self.send_server_message(user, "stats_end")

        elif flag == 'b':
            # ServiceBot statistics
            await self.send_server_message(user, "stats_servicebot_header")
            await self.send_server_message(user, "stats_servicebots_enabled", status=self.servicebot_enabled)

            if self.servicebot_enabled:
                await self.send_server_message(user, "stats_active_bots", count=len(self.servicebots))

                # Violations
                if self.stats['servicebot_violations']:
                    await self.send_server_message(user, "stats_violations_detected")
                    for violation_type, cnt in sorted(self.stats['servicebot_violations'].items(), key=lambda x: x[1], reverse=True):
                        await self.send_server_message(user, "stats_violation_entry", type=violation_type, count=cnt)
                else:
                    await self.send_server_message(user, "stats_no_violations")

                # Actions taken
                if self.stats['servicebot_actions']:
                    await self.send_server_message(user, "stats_actions_taken")
                    for action, cnt in sorted(self.stats['servicebot_actions'].items(), key=lambda x: x[1], reverse=True):
                        await self.send_server_message(user, "stats_action_entry", action=action, count=cnt)

                # Configuration
                profanity_enabled = CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False)
                malicious_enabled = CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=False)
                await self.send_server_message(user, "stats_profanity_status", status='enabled' if profanity_enabled else 'disabled')
                await self.send_server_message(user, "stats_malicious_status", status='enabled' if malicious_enabled else 'disabled')

            await self.send_server_message(user, "stats_end")

        elif flag == 'n':
            # Network statistics
            await self.send_server_message(user, "stats_network_header")
            await self.send_server_message(user, "ssl_server", server=self.servername)
            await self.send_server_message(user, "ssl_network", network=self.network_name)

            # Totals
            total_users = sum(1 for u in self.users.values() if not u.is_virtual)
            total_channels = len(self.channels)
            await self.send_server_message(user, "stats_users_count", count=total_users)
            await self.send_server_message(user, "stats_channels_count", count=total_channels)
            await self.send_server_message(user, "stats_services_count", count=sum(1 for u in self.users.values() if u.is_virtual))

            # Server version
            await self.send_server_message(user, "stats_version", version=__version__, label=__version_label__)

            # Uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            await self.send_server_message(user, "stats_uptime_short", days=days, hours=hours, mins=mins)

            await self.send_server_message(user, "stats_end")

        elif flag == 'v':
            # Command usage statistics (Operator+)
            await self.send_server_message(user, "stats_command_usage_header")
            if self.stats['command_usage']:
                # Sort by usage count (descending)
                sorted_cmds = sorted(self.stats['command_usage'].items(), key=lambda x: x[1], reverse=True)
                for cmd, cnt in sorted_cmds:
                    await self.send_server_message(user, "stats_command_usage_entry", command=cmd, count=cnt)
                await self.send_server_message(user, "stats_total_commands", count=self.stats['commands_processed'])
            else:
                await self.send_server_message(user, "stats_no_command_data")
            await self.send_server_message(user, "stats_end")

        else:
            await self.send_server_message(user, "stats_unknown_flag", flag=flag)

        await user.send(self.get_reply("219", user, flag=flag))

    async def handle_config(self, user, params):
        """
        CONFIG command - In-band configuration management for administrators.

        Subcommands:
          CONFIG LIST [section]     - List all config or a specific section (SYSOP+)
          CONFIG GET <section.key>  - Get a specific value (SYSOP+)
          CONFIG SET <section.key> <value> - Set a value (ADMIN only)
          CONFIG SAVE               - Save config to disk (ADMIN only)
          CONFIG RELOAD             - Reload config from disk (ADMIN only)
        """
        is_admin = user.has_mode('a')
        is_sysop = user.has_mode('o')

        if not is_admin and not is_sysop:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG")))
            return

        if not params:
            await user.send(self.get_reply("461", user, command="CONFIG"))
            return

        subcmd = params[0].upper()

        if subcmd == "LIST":
            # List configuration - SYSOP+ can view
            section = params[1].lower() if len(params) > 1 else None

            if section:
                # List specific section
                sect_data = CONFIG.get_section(section)
                if not sect_data:
                    await self.send_server_message(user, "config_section_unknown", section=section)
                    return
                await user.send(self.get_reply("940", user, section=section))
                for key, value in sect_data.items():
                    await user.send(self.get_reply("941", user, key=f"{section}.{key}", value=json.dumps(value)))
                await user.send(self.get_reply("943", user))
            else:
                # List all sections
                await user.send(self.get_reply("940", user, section="All"))
                for section in CONFIG.get_all_sections():
                    sect_data = CONFIG.get_section(section)
                    await user.send(self.get_reply("942", user, section=section, count=len(sect_data)))
                await user.send(self.get_reply("943", user))

        elif subcmd == "GET":
            # Get specific value - SYSOP+ can view
            if len(params) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_config_get']))
                return

            path = params[1].split('.')
            if len(path) < 2:
                await user.send(self.get_reply("861", user))
                return

            value = CONFIG.get(*path)
            if value is None:
                await user.send(self.get_reply("892", user, key=params[1]))
            else:
                await user.send(self.get_reply("890", user, key=params[1], value=json.dumps(value)))

        elif subcmd == "SET":
            # Set value - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG SET")))
                return

            if len(params) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_config_set']))
                return

            path = params[1].split('.')
            if len(path) < 2:
                await user.send(self.get_reply("861", user))
                return

            # Parse value - try JSON first, then string
            raw_value = ' '.join(params[2:])

            # Size limit to prevent DoS via large JSON
            if len(raw_value) > 10000:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['config_value_too_large'].format(max_size="10KB")))
                return

            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                # Treat as string if not valid JSON
                value = raw_value

            old_value = CONFIG.get(*path)
            if CONFIG.set(*path, value=value):
                await user.send(self.get_reply("891", user, key=params[1], value=json.dumps(value)))
                logger.info(get_log_message("config_set_log", nickname=user.nickname, key=params[1], value=json.dumps(value)))
            else:
                await user.send(self.get_reply("893", user))

        elif subcmd == "SAVE":
            # Save to disk - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG SAVE")))
                return

            CONFIG.save()
            await user.send(self.get_reply("382", user, config_file=CONFIG.config_file, message="Configuration saved"))
            logger.info(get_log_message("config_saved_log", nickname=user.nickname))

        elif subcmd == "RELOAD":
            # Reload from disk - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="CONFIG RELOAD")))
                return

            CONFIG.load()
            await user.send(self.get_reply("382", user, config_file=CONFIG.config_file, message="Configuration reloaded"))
            await self.send_server_message(user, "config_restart_note")
            logger.info(get_log_message("config_reloaded_log", nickname=user.nickname))

        else:
            await self.send_server_message(user, "config_subcmd_unknown", subcmd=subcmd)
            await user.send(self.get_reply("461", user, command="CONFIG"))

    async def handle_link(self, user, params):
        """
        LINK command - Connect to a remote server.
        Syntax: LINK <servername>
        Aliases: CONNECT
        Requires ADMIN privileges.
        """
        if not user.is_admin():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="LINK/UNLINK")))
            return

        if not params:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_link']))
            return

        if not hasattr(self, 'link_manager') or not self.link_manager:
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['link_not_enabled']))
            return

        target_server = params[0]

        # Find link config for this server
        links = CONFIG.get('linking', 'links', default=[])
        link_cfg = None
        for link in links:
            if link.get('name', '').lower() == target_server.lower():
                link_cfg = link
                break

        if not link_cfg:
            await user.send(self.get_reply("897", user, server=target_server))
            return

        # Check if already connected
        if target_server in self.link_manager.linked_servers:
            await user.send(self.get_reply("859", user, server=target_server))
            return

        # Attempt connection
        await user.send(self.get_reply("898", user))
        try:
            await self.link_manager.connect_to_server(link_cfg)
            await user.send(self.get_reply("894", user, server=target_server))
            # Track network convergence in history
            self.stats['network_convergence_history'].append((int(time.time()), target_server))
            if len(self.stats['network_convergence_history']) > 10:
                self.stats['network_convergence_history'] = self.stats['network_convergence_history'][-10:]
            logger.info(get_log_message("link_success", nickname=user.nickname, server=target_server))
        except Exception as e:
            logger.error(get_log_message("link_failed_log", server=target_server, error=e))
            await user.send(self.get_reply("896", user, server=target_server))

    async def handle_unlink(self, user, params):
        """
        UNLINK command - Disconnect a linked server.
        Syntax: UNLINK <servername> [reason]
        Aliases: SQUIT
        Requires ADMIN privileges.
        """
        if not user.is_admin():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="LINK/UNLINK")))
            return

        if not params:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_unlink']))
            return

        if not hasattr(self, 'link_manager') or not self.link_manager:
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['link_not_enabled']))
            return

        target_server = params[0]
        reason = params[1] if len(params) > 1 else f"Requested by {user.nickname}"

        if target_server not in self.link_manager.linked_servers:
            await user.send(self.get_reply("897", user, server=target_server))
            return

        await user.send(self.get_reply("898", user))
        try:
            await self.link_manager.squit_server(target_server, reason)
            await user.send(self.get_reply("895", user, server=target_server))
            # Track network divergence in history
            self.stats['network_divergence_history'].append((int(time.time()), target_server, reason))
            if len(self.stats['network_divergence_history']) > 10:
                self.stats['network_divergence_history'] = self.stats['network_divergence_history'][-10:]
            logger.info(get_log_message("unlink_success", nickname=user.nickname, server=target_server, reason=reason))
        except Exception as e:
            logger.error(get_log_message("unlink_failed", server=target_server, error=e))
            await user.send(self.get_reply("896", user, server=target_server))

    async def handle_links(self, user, params):
        """
        LINKS command - Show network topology.
        Syntax: LINKS
        """
        if not hasattr(self, 'link_manager') or not self.link_manager:
            # No linking enabled, just show this server
            await user.send(self.get_reply("364", user, server=self.servername, uplink=self.servername, hopcount="0", desc=self.network_name))
            await user.send(self.get_reply("365", user, message=SERVER_MESSAGES['links_end']))
            return

        # Show local server
        await user.send(self.get_reply("364", user, server=self.servername, uplink=self.servername, hopcount="0", desc=self.network_name))

        # Show linked servers
        for server_name, linked_server in self.link_manager.linked_servers.items():
            hopcount = linked_server.hopcount
            desc = linked_server.description
            uplink = self.servername if linked_server.is_direct else "via"
            await user.send(self.get_reply("364", user, server=server_name, uplink=uplink, hopcount=str(hopcount), desc=desc))

        await user.send(self.get_reply("365", user, message=SERVER_MESSAGES['links_end']))

    async def handle_map(self, user, params):
        """
        MAP command - Show network topology as a tree.
        Syntax: MAP
        """
        if not hasattr(self, 'link_manager') or not self.link_manager:
            # No linking enabled, just show this server
            local_users = sum(1 for u in self.users.values() if not u.is_virtual)
            await user.send(self.get_reply("006", user, text=f"{self.servername} ({local_users})"))
            await user.send(self.get_reply("007", user, message=SERVER_MESSAGES['map_end']))
            return

        # Count local users
        local_users = sum(1 for u in self.users.values() if not u.is_virtual and not (u.is_remote))

        # Show local server
        await user.send(self.get_reply("006", user, text=f"{self.servername} ({local_users})"))

        # Show linked servers with indentation
        for server_name, linked_server in self.link_manager.linked_servers.items():
            remote_users = linked_server.user_count if hasattr(linked_server, 'user_count') else 0
            indent = "  " if linked_server.is_direct else "    "
            await user.send(self.get_reply("006", user, text=f"{indent}`-{server_name} ({remote_users})"))

        await user.send(self.get_reply("007", user, message=SERVER_MESSAGES['map_end']))

    async def handle_staff(self, user, params):
        """
        STAFF command - In-band staff account management.

        Staff accounts are associated with usernames (USER ident), not nicknames.
        Authentication happens via PASS username:password before USER command.

        Subcommands:
          STAFF LIST                          - List all staff accounts (SYSOP+)
          STAFF ADD <username> <password> <level> - Add staff account (ADMIN only)
          STAFF DELETE <username>             - Remove staff account (ADMIN only)
          STAFF SET <username> <level>        - Change staff level (ADMIN only)
          STAFF PASS <username> <newpass>     - Change password (ADMIN, or self)

        Levels: ADMIN, SYSOP, GUIDE
        """
        is_admin = user.has_mode('a')
        is_sysop = user.has_mode('o')

        if not is_admin and not is_sysop:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF")))
            return

        if not params:
            await self.send_server_message(user, "staff_subcommands")
            await self.send_server_message(user, "staff_levels")
            return

        subcmd = params[0].upper()

        if subcmd in ("LIST", "L"):
            # List all staff accounts - SYSOP+ can view
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} LIST")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            try:
                async with self.db_pool.connection() as db:
                    async with db.execute("SELECT username, level FROM users ORDER BY level, username") as cursor:
                        rows = await cursor.fetchall()

                await user.send(self.get_reply("930", user, count=len(rows)))
                if not rows:
                    await self.send_notice(user, "staff_list_none")
                else:
                    # Build online staff map in single pass (performance optimization)
                    online_staff = {}
                    for u in self.users.values():
                        username = u.username.lstrip('~')
                        if u.has_mode('a'):
                            online_staff[username] = 'ADMIN'
                        elif u.has_mode('o'):
                            online_staff[username] = 'SYSOP'
                        elif u.has_mode('g'):
                            online_staff[username] = 'GUIDE'

                    # Group by level
                    admins = [r[0] for r in rows if r[1] == 'ADMIN']
                    sysops = [r[0] for r in rows if r[1] == 'SYSOP']
                    guides = [r[0] for r in rows if r[1] == 'GUIDE']

                    if admins:
                        await user.send(self.get_reply("931", user, level="ADMIN", count=len(admins)))
                        for admin in admins:
                            status = " [ONLINE]" if admin in online_staff and online_staff[admin] == 'ADMIN' else ""
                            await user.send(self.get_reply("932", user, username=admin, status=status))
                    if sysops:
                        await user.send(self.get_reply("931", user, level="SYSOP", count=len(sysops)))
                        for sysop in sysops:
                            status = " [ONLINE]" if sysop in online_staff and online_staff[sysop] == 'SYSOP' else ""
                            await user.send(self.get_reply("932", user, username=sysop, status=status))
                    if guides:
                        await user.send(self.get_reply("931", user, level="GUIDE", count=len(guides)))
                        for guide in guides:
                            status = " [ONLINE]" if guide in online_staff and online_staff[guide] == 'GUIDE' else ""
                            await user.send(self.get_reply("932", user, username=guide, status=status))

                await user.send(self.get_reply("933", user))
            except Exception as e:
                logger.error(get_log_message("staff_list_error", error=e))
                await user.send(self.get_reply("884", user))

        elif subcmd in ("ADD", "A"):
            # Add staff account - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF ADD")))
                return

            if len(params) < 4:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_add']))
                await self.send_notice(user, "staff_levels_hint")
                return

            # Check if branch in centralized mode - proxy to trunk
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} ADD {params[1]} {params[2]} {params[3]}")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            username = params[1]
            password = params[2]
            level = params[3].upper()

            if level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                await user.send(self.get_reply("862", user, levels=SERVER_MESSAGES['valid_staff_levels']))
                return

            if len(password) < 6:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['staff_password_min']))
                return

            # Validate username
            valid, error = validate_username(username)
            if not valid:
                await user.send(self.get_reply("863", user, error=error))
                return

            try:
                async with self.db_pool.connection() as db:
                    # Check if already exists
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if await cursor.fetchone():
                            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['already_exists_account'].format(username=username)))
                            return

                    # Hash password and insert
                    password_hash = await hash_password_async(password)
                    await db.execute("INSERT INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                                    (username, password_hash, level))
                    await db.commit()

                await user.send(self.get_reply("880", user, username=username, level=level))
                logger.info(get_log_message("staff_added", nickname=user.nickname, username=username, level=level))
                await self.log_staff(user.nickname, "STAFF ADD", username, get_log_message("audit_staff_add_level", level=level))

            except Exception as e:
                logger.error(get_log_message("staff_add_error", error=e))
                await user.send(self.get_reply("885", user))

        elif subcmd in ("DELETE", "DEL", "D"):
            # Remove staff account - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF DELETE")))
                return

            if len(params) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_delete']))
                return

            # Check if branch in centralized mode - proxy to trunk
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} REMOVE {params[1]}")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            username = params[1]

            # Prevent self-deletion
            if username.lower() == user.username.lower().lstrip('~'):
                await user.send(self.get_reply("858", user))
                return

            try:
                async with self.db_pool.connection() as db:
                    # Check if exists
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(self.get_reply("889", user, username=username))
                            return
                        old_level = row[0]

                    await db.execute("DELETE FROM users WHERE username = ?", (username,))
                    await db.commit()

                await user.send(self.get_reply("881", user, username=username))
                logger.info(get_log_message("staff_deleted", nickname=user.nickname, username=username, level=old_level))
                await self.log_staff(user.nickname, "STAFF DELETE", username, get_log_message("audit_staff_delete_level", old_level=old_level))

            except Exception as e:
                logger.error(get_log_message("staff_del_error", error=e))
                await user.send(self.get_reply("886", user))

        elif subcmd in ("SET", "S"):
            # Change staff level - ADMIN only
            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF SET")))
                return

            if len(params) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_set']))
                await self.send_notice(user, "staff_levels_hint")
                return

            # Check if branch in centralized mode - proxy to trunk
            if not self.is_services_hub and \
               self.services_mode == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} LEVEL {params[1]} {params[2]}")
                        await self.send_notice(user, "staff_forwarded")
                        return
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                return

            username = params[1]
            new_level = params[2].upper()

            if new_level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                await user.send(self.get_reply("862", user, levels=SERVER_MESSAGES['valid_staff_levels']))
                return

            try:
                async with self.db_pool.connection() as db:
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(self.get_reply("889", user, username=username))
                            return
                        old_level = row[0]

                    if old_level == new_level:
                        await self.send_server_message(user, "staff_already_level", username=username, level=new_level)
                        return

                    await db.execute("UPDATE users SET level = ? WHERE username = ?", (new_level, username))
                    await db.commit()

                await user.send(self.get_reply("882", user, username=username, level=new_level))
                logger.info(get_log_message("staff_level_changed", nickname=user.nickname, username=username, old_level=old_level, new_level=new_level))
                await self.log_staff(user.nickname, "STAFF SET", username, get_log_message("audit_staff_level_change", old_level=old_level, new_level=new_level))

            except Exception as e:
                logger.error(get_log_message("staff_set_error", error=e))
                await user.send(self.get_reply("887", user))

        elif subcmd in ("PASS", "P"):
            # Change staff password - ADMIN or self
            # Syntax: STAFF PASS <username> <oldpassword> <newpassword> (for own password)
            #         STAFF PASS <username> <newpassword> (ADMIN changing others - less secure, local only)

            own_username = user.username.lstrip('~')

            if len(params) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                await self.send_server_message(user, "staff_pass_old_required")
                await self.send_server_message(user, "staff_pass_admin_hint")
                return

            username = params[1]
            is_self = username.lower() == own_username.lower()

            # Determine if 2 or 3 parameter format
            if len(params) == 4:
                # STAFF PASS <username> <oldpass> <newpass> - secure format
                old_password = params[2]
                new_password = params[3]

                # Check if branch in centralized mode - proxy to trunk
                if not self.is_services_hub and \
                   self.services_mode == 'centralized':
                    if self.link_manager and self.link_manager.servers:
                        trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                        if trunk_server:
                            await trunk_server.send(f"STAFFCMD {user.nickname} PASSWORD {old_password} {new_password}")
                            await self.send_server_message(user, "staff_pass_forwarded")
                            return
                    await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['trunk_unavailable']))
                    return

            elif len(params) == 3:
                # STAFF PASS <username> <newpass> - ADMIN-only shorthand (trunk only)
                if not is_admin:
                    await self.send_server_message(user, "staff_pass_old_required")
                    await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                    return

                if not self.is_services_hub:
                    await self.send_server_message(user, "trunk_only_format")
                    await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                    return

                new_password = params[2]
                old_password = None  # Admin override, no validation
            else:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_staff_pass']))
                return

            # Check permissions
            if not is_admin and not is_self:
                await self.send_server_message(user, "staff_pass_self_only")
                return

            if len(new_password) < 6:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['staff_password_min']))
                return

            try:
                async with self.db_pool.connection() as db:
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if not await cursor.fetchone():
                            await user.send(self.get_reply("889", user, username=username))
                            return

                    password_hash = await hash_password_async(new_password)
                    await db.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                                    (password_hash, username))
                    await db.commit()

                await user.send(self.get_reply("883", user, message=f"The password was changed for staff account {username}"))
                logger.info(get_log_message("staff_password_changed", nickname=user.nickname, username=username))
                if not is_self:
                    await self.log_staff(user.nickname, "STAFF PASS", username, get_log_message("audit_staff_pass_changed"))

            except Exception as e:
                logger.error(get_log_message("staff_pass_error", error=e))
                await user.send(self.get_reply("888", user))


        elif subcmd in ("MFA", "M"):
            # Manage MFA for staff accounts (ADMIN only)
            # Syntax: STAFF MFA <username> ENABLE <code>   - Enable MFA with verified code
            #         STAFF MFA <username> DISABLE <code>  - Disable MFA with verified code
            #         STAFF MFA <username> STATUS          - Show MFA status

            if not is_admin:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_admin'].format(command="STAFF MFA")))
                await self.send_server_message(user, "staff_mfa_own_hint")
                return

            if len(params) < 3:
                await self.send_server_message(user, "staff_mfa_usage")
                return

            username = params[1]
            mfa_action = params[2].upper()

            try:
                async with self.db_pool.connection() as db:
                    # Check if user exists
                    async with db.execute("SELECT mfa_enabled, mfa_secret FROM users WHERE username = ?",
                                         (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(self.get_reply("889", user, username=username))
                            return

                        mfa_enabled, mfa_secret = row

                    if mfa_action == "STATUS":
                        # Show MFA status
                        status = "enabled" if mfa_enabled else ("setup pending" if mfa_secret else "disabled")
                        await self.send_server_message(user, "staff_mfa_status", username=username, status=status)
                        if mfa_secret and not mfa_enabled:
                            await self.send_server_message(user, "staff_mfa_secret_pending")
                        logger.info(get_log_message("staff_mfa_checked", nickname=user.nickname, username=username))

                    elif mfa_action == "ENABLE":
                        # Enable MFA with code verification
                        if len(params) < 4:
                            await self.send_server_message(user, "staff_mfa_enable_usage", username=username)
                            await self.send_server_message(user, "staff_mfa_user_needs_secret")
                            return

                        code = params[3]

                        if mfa_enabled:
                            await self.send_server_message(user, "staff_mfa_already_enabled", username=username)
                            return

                        if not mfa_secret:
                            await self.send_server_message(user, "staff_mfa_user_enable_first", username=username)
                            return

                        # Verify the code
                        import pyotp
                        totp = pyotp.TOTP(mfa_secret)

                        if not totp.verify(code, valid_window=1):
                            await self.send_server_message(user, "staff_mfa_invalid_code_for_user", username=username)
                            logger.warning(get_log_message("staff_mfa_enable_failed", nickname=user.nickname, username=username))
                            return

                        # Enable MFA!
                        await db.execute("UPDATE users SET mfa_enabled = 1 WHERE username = ?",
                                        (username,))
                        await db.commit()

                        await self.send_server_message(user, "staff_mfa_enabled_for_user", username=username)
                        logger.info(get_log_message("staff_mfa_enabled", nickname=user.nickname, username=username))
                        await self.log_staff(user.nickname, "STAFF MFA ENABLE", username, get_log_message("audit_staff_mfa_enabled"))

                    elif mfa_action == "DISABLE":
                        # Disable MFA with code verification
                        if len(params) < 4:
                            await self.send_server_message(user, "staff_mfa_disable_usage", username=username)
                            await self.send_server_message(user, "staff_mfa_disable_code_required")
                            return

                        code = params[3]

                        if not mfa_enabled:
                            await self.send_server_message(user, "staff_mfa_not_enabled", username=username)
                            return

                        if not mfa_secret:
                            await self.send_server_message(user, "staff_mfa_config_error_for_user", username=username)
                            return

                        # Verify the code
                        import pyotp
                        totp = pyotp.TOTP(mfa_secret)

                        if not totp.verify(code, valid_window=1):
                            await self.send_server_message(user, "staff_mfa_invalid_code_for_user", username=username)
                            logger.warning(get_log_message("staff_mfa_disable_failed", nickname=user.nickname, username=username))
                            return

                        # Disable MFA
                        await db.execute("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = ?",
                                        (username,))
                        await db.commit()

                        await self.send_server_message(user, "staff_mfa_disabled_for_user", username=username)
                        logger.info(get_log_message("staff_mfa_disabled", nickname=user.nickname, username=username))
                        await self.log_staff(user.nickname, "STAFF MFA DISABLE", username, get_log_message("audit_staff_mfa_disabled"))

                    else:
                        await self.send_server_message(user, "staff_mfa_invalid_action", action=mfa_action)
                        await self.send_server_message(user, "staff_mfa_available_actions")

            except Exception as e:
                logger.error(get_log_message("staff_mfa_error", error=e))
                await self.send_server_message(user, "staff_mfa_op_failed")
        else:
            await self.send_server_message(user, "staff_unknown_subcommand", subcmd=subcmd)
            await self.send_server_message(user, "staff_subcommands")

    async def handle_profanity(self, user, params):
        """
        PROFANITY command - Manage profanity filter (ADMIN only).

        Subcommands:
          PROFANITY LIST                    - Show current words and patterns
          PROFANITY ADD WORD <word>         - Add a word to filter
          PROFANITY ADD PATTERN <pattern>   - Add a regex pattern
          PROFANITY DELETE WORD <word>      - Remove a word
          PROFANITY DELETE PATTERN <pattern> - Remove a pattern
          PROFANITY ENABLE                  - Enable profanity filter
          PROFANITY DISABLE                 - Disable profanity filter
          PROFANITY TEST <text>             - Test if text would be caught
        """
        if not user.is_high_staff():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command="PROFANITY")))
            return

        if not params:
            await self.send_server_message(user, "profanity_subcommands")
            await self.send_server_message(user, "profanity_examples")
            return

        subcmd = params[0].upper()

        if subcmd in ("LIST", "L"):
            # Show current filter configuration
            enabled = CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False)
            words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
            patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
            case_sensitive = CONFIG.get('servicebot', 'profanity_filter', 'case_sensitive', default=False)
            action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')

            await self.send_server_message(user, "profanity_header")
            await self.send_server_message(user, "profanity_status", status='Enabled' if enabled else 'Disabled')
            await self.send_server_message(user, "profanity_action", action=action)
            await self.send_server_message(user, "profanity_case", status='Yes' if case_sensitive else 'No')
            await self.send_server_message(user, "profanity_blank_line")

            if words:
                await self.send_server_message(user, "profanity_words_header", count=len(words))
                for word in words:
                    await self.send_server_message(user, "profanity_word_entry", word=word)
            else:
                await self.send_server_message(user, "profanity_words_none")

            await self.send_server_message(user, "profanity_blank_line")

            if patterns:
                await self.send_server_message(user, "profanity_patterns_header", count=len(patterns))
                for pattern in patterns:
                    await self.send_server_message(user, "profanity_pattern_entry", pattern=pattern)
            else:
                await self.send_server_message(user, "profanity_patterns_none")

        elif subcmd in ("ADD", "A"):
            if len(params) < 3:
                await self.send_server_message(user, "profanity_add_usage")
                return

            add_type = params[1].upper()
            value = ' '.join(params[2:])

            if add_type == "WORD":
                current_words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
                if value in current_words:
                    await self.send_server_message(user, "profanity_word_exists", word=value)
                    return
                current_words.append(value)
                CONFIG.set('servicebot', 'profanity_filter', 'words', current_words)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_word_added", word=value)
                logger.info(get_log_message("profanity_word_added_log", nickname=user.nickname, word=value))

            elif add_type == "PATTERN":
                # Validate regex with ReDoS protection
                valid, error = validate_regex_pattern(value)
                if not valid:
                    await self.send_raw_notice(user, error)
                    return

                current_patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
                if value in current_patterns:
                    await self.send_server_message(user, "profanity_pattern_exists", pattern=value)
                    return
                current_patterns.append(value)
                CONFIG.set('servicebot', 'profanity_filter', 'patterns', current_patterns)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_pattern_added", pattern=value)
                logger.info(get_log_message("profanity_pattern_added_log", nickname=user.nickname, pattern=value))

            else:
                await self.send_server_message(user, "profanity_type_unknown", type=add_type)

        elif subcmd in ("DELETE", "DEL", "D"):
            if len(params) < 3:
                await self.send_server_message(user, "profanity_del_usage")
                return

            del_type = params[1].upper()
            value = ' '.join(params[2:])

            if del_type == "WORD":
                current_words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
                if value not in current_words:
                    await self.send_server_message(user, "profanity_word_not_found", word=value)
                    return
                current_words.remove(value)
                CONFIG.set('servicebot', 'profanity_filter', 'words', current_words)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_word_removed", word=value)
                logger.info(get_log_message("profanity_word_removed_log", nickname=user.nickname, word=value))

            elif del_type == "PATTERN":
                current_patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
                if value not in current_patterns:
                    await self.send_server_message(user, "profanity_pattern_not_found", pattern=value)
                    return
                current_patterns.remove(value)
                CONFIG.set('servicebot', 'profanity_filter', 'patterns', current_patterns)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await self.send_server_message(user, "profanity_pattern_removed", pattern=value)
                logger.info(get_log_message("profanity_pattern_removed_log", nickname=user.nickname, pattern=value))

            else:
                await self.send_server_message(user, "profanity_type_unknown", type=del_type)

        elif subcmd in ("ENABLE", "E"):
            CONFIG.set('servicebot', 'profanity_filter', 'enabled', True)
            await CONFIG.save()
            self._reload_all_monitor_configs()  # Reload cached config in all monitors
            await self.send_server_message(user, "profanity_enabled")
            logger.info(get_log_message("profanity_enabled_log", nickname=user.nickname))

        elif subcmd == "DISABLE":
            CONFIG.set('servicebot', 'profanity_filter', 'enabled', False)
            await CONFIG.save()
            self._reload_all_monitor_configs()  # Reload cached config in all monitors
            await self.send_server_message(user, "profanity_disabled")
            logger.info(get_log_message("profanity_disabled_log", nickname=user.nickname))

        elif subcmd in ("TEST", "T"):
            if len(params) < 2:
                await self.send_server_message(user, "profanity_test_usage")
                return

            test_text = ' '.join(params[1:])
            monitor = ServiceBotMonitor()
            has_profanity, matched = monitor.check_profanity(test_text)

            if has_profanity:
                await self.send_server_message(user, "profanity_test_would_catch", matched=matched)
            else:
                await self.send_server_message(user, "profanity_test_clean")

        else:
            await self.send_server_message(user, "profanity_unknown_subcommand", subcmd=subcmd)
            await self.send_server_message(user, "profanity_available_subcommands")

    async def handle_help(self, user, params):
        """Handle HELP command - show command help using data-driven help text"""
        topic = params[0] if params else None
        is_staff = user.is_staff()
        is_admin = user.is_admin()
        is_high_staff = user.is_high_staff()

        found, lines = help_text.get_topic_lines(
            topic,
            is_staff=is_staff,
            is_admin=is_admin,
            is_high_staff=is_high_staff,
            nickname=user.nickname
        )

        if found and lines:
            for line in lines:
                await self.send_raw_notice(user, line)
        elif topic:
            # Topic not found - show suggestions
            suggestions = help_text.get_help_suggestions(topic)
            await self.send_server_message(user, "help_not_found", topic=topic)
            if suggestions:
                await self.send_server_message(user, "help_suggestions", suggestions=', '.join(suggestions))
            await self.send_server_message(user, "help_available_topics")
            if is_staff:
                await self.send_server_message(user, "help_staff_topic")
            await self.send_server_message(user, "help_try_command")

    async def handle_info(self, user, params=None):
        """Handle INFO command - return server information (RFC 2812)"""
        info_lines = [
            f"pyIRCX Server version {__version__}",
            f"Written in Python 3 with asyncio",
            f"",
            f"Server name: {self.servername}",
            f"Network: {self.network_name}",
            f"",
            f"Supported protocols:",
            f"  - RFC 1459 (Internet Relay Chat Protocol)",
            f"  - RFC 2812 (Internet Relay Chat: Client Protocol)",
            f"  - IRCX (Microsoft Chat Extensions)",
            f"",
            f"Special features:",
            f"  - Channel cloning (+d mode)",
            f"  - ACCESS control lists",
            f"  - PROP channel properties",
            f"  - ServiceBot monitoring",
            f"  - SASL authentication",
            f"  - Nickname registration",
            f"",
            f"For more information, contact the server administrators."
        ]
        for line in info_lines:
            await user.send(self.get_reply("371", user, info=line))
        await user.send(self.get_reply("374", user))

    async def handle_motd(self, user, params=None):
        """Handle MOTD command - display message of the day"""
        await user.send(self.get_reply("375", user))
        # Read MOTD from config (no hardcoded default - should be in config file)
        motd_lines = CONFIG.get('server', 'motd', default=[])
        if isinstance(motd_lines, str):
            motd_lines = [motd_lines]
        for line in motd_lines:
            # Send blank lines as just a space to preserve spacing
            if not line or line.strip() == '':
                await user.send(self.get_reply("372", user, text=" "))
            else:
                await user.send(self.get_reply("372", user, text=line))
        await user.send(self.get_reply("376", user))

    async def handle_lusers(self, user, params=None):
        """Handle LUSERS command - display user statistics"""
        # Count local users (not virtual, not remote)
        local_users = sum(1 for u in self.users.values() if not u.is_virtual and not (u.is_remote))
        # Count remote users (from linked servers)
        remote_users = sum(1 for u in self.users.values() if not u.is_virtual and u.is_remote)
        # Total users
        total_users = local_users + remote_users

        # Staff count includes staff users AND services/bots (local only for accuracy)
        ops = sum(1 for u in self.users.values() if (u.is_staff() or u.is_virtual) and not (u.is_remote))
        unknown = 0  # Connections not yet registered
        channels = len(self.channels)

        # Count linked servers
        server_count = 1  # This server
        if hasattr(self, 'link_manager') and self.link_manager:
            server_count += len(self.link_manager.linked_servers)

        # Only show invisible count to staff
        is_staff = user.is_staff()
        if is_staff:
            invisible = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
        else:
            invisible = 0  # Hide from non-staff

        await user.send(self.get_reply("251", user, users=total_users, invisible=invisible, server_count=server_count))
        await user.send(self.get_reply("252", user, ops=ops))
        if unknown > 0:
            await user.send(self.get_reply("253", user, unknown=unknown))
        await user.send(self.get_reply("254", user, channels=channels))
        await user.send(self.get_reply("255", user, users=total_users))
        await user.send(self.get_reply("265", user, local=local_users, local_max=self.max_users_seen))
        await user.send(self.get_reply("266", user, global_users=total_users, global_max=self.max_users_seen))

    async def handle_ison(self, user, params):
        """Handle ISON command - check if nicknames are online"""
        if not params:
            await user.send(self.get_reply("461", user, command="ISON"))
            return
        # ISON can take multiple nicknames separated by spaces
        nicks_to_check = params[0].split() if len(params) == 1 else params
        online_nicks = []
        for nick in nicks_to_check:
            target = self.get_user(nick)
            if target and not target.is_service():
                online_nicks.append(target.nickname)
        await user.send(self.get_reply("303", user, nicks=" ".join(online_nicks)))

    async def handle_userhost(self, user, params):
        """Handle USERHOST command - get user@host for nicknames (RFC 2812)

        Returns RPL_USERHOST (302) with format:
        :server 302 nick :nick1*=+user1@host1 nick2=+user2@host2 ...

        The * indicates an IRC operator.
        The + or - indicates away status (+ = here, - = away).
        """
        if not params:
            await user.send(self.get_reply("461", user, command="USERHOST"))
            return

        # USERHOST can check up to 5 nicknames
        nicks_to_check = params[:5]
        userhost_info = []

        for nick in nicks_to_check:
            target = self.get_user(nick)
            if target and not target.is_service():
                # Build userhost reply: nick*=+user@host
                # * = operator, + = here, - = away
                oper_flag = "*" if target.is_high_staff() else ""
                away_flag = "-" if target.away_msg else "+"
                userhost_info.append(f"{target.nickname}{oper_flag}={away_flag}{target.username}@{target.host}")

        await user.send(self.get_reply("302", user, userhosts=" ".join(userhost_info)))

    async def handle_names(self, user, params):
        """Handle NAMES command - list channel members

        IRCv3 capabilities:
        - multi-prefix: Show all prefixes for each user (.@+ instead of just highest)
        - userhost-in-names: Show full user!ident@host instead of just nick
        - batch: Group NAMES responses in a batch
        """
        # Rate limit NAMES lookups
        if not user.rate_limiter.check('NAMES'):
            await user.send(self.get_reply("830", user))
            return

        # Determine prefix method based on multi-prefix capability
        use_multi_prefix = 'multi-prefix' in user.enabled_caps
        use_userhost = 'userhost-in-names' in user.enabled_caps

        def format_member(channel, nick):
            """Format a member entry based on enabled capabilities"""
            if use_multi_prefix:
                prefix = channel.get_all_prefixes(nick)
            else:
                prefix = channel.get_prefix(nick)

            if use_userhost:
                member = self.users.get(nick)
                if member:
                    return f"{prefix}{nick}!{member.username}@{member.host}"
            return f"{prefix}{nick}"

        # Start batch for NAMES response
        batch_id = await self.start_batch(user, "draft/names-reply")

        if not params:
            # No channel specified - list all visible channels
            for channel_name, channel in self.channels.items():
                # Skip hidden/secret channels unless user is in them
                if channel.modes.get('s') or channel.modes.get('h'):
                    if channel_name not in user.channels:
                        continue
                names = " ".join([format_member(channel, nick) for nick in channel.members])
                await self.send_batched(user, batch_id, self.get_reply("353", user, channel=channel_name, names=names))
            await self.send_batched(user, batch_id, self.get_reply("366", user, channel="*"))
            await self.end_batch(user, batch_id)
            return

        # Specific channels requested
        requested_names = params[0].split(',')
        for req_name in requested_names:
            req_name = req_name.strip()
            channel, chan_name = self.get_channel(req_name)
            if not channel:
                await self.send_batched(user, batch_id, self.get_reply("366", user, channel=req_name))
                continue

            # Check visibility - secret/hidden channels only visible to members
            if (channel.modes.get('s') or channel.modes.get('h')) and chan_name not in user.channels:
                await self.send_batched(user, batch_id, self.get_reply("366", user, channel=chan_name))
                continue

            names = " ".join([format_member(channel, nick) for nick in channel.members])
            await self.send_batched(user, batch_id, self.get_reply("353", user, channel=chan_name, names=names))
            await self.send_batched(user, batch_id, self.get_reply("366", user, channel=chan_name))

        await self.end_batch(user, batch_id)

    # ==========================================================================
    # REGISTRATION COMMANDS (REGISTER, UNREGISTER, IDENTIFY, MFA)
    # ==========================================================================

    async def handle_register(self, user, params):
        """Handle REGISTER command for nicknames and channels

        Syntax:
          REGISTER <account> {*|<email>} <password>  - Register nickname
          REGISTER <#channel> [<password>]           - Register channel
        """
        if not params:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_register']))
            await self.send_server_message(user, "reg_usage_alt")
            return

        target = params[0]

        if is_channel(target):
            # Channel registration (only global # channels, not local &)
            if is_local_channel(target):
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['channel_local_no_register']))
                return
            channel_password = params[1] if len(params) > 1 else None
            await self._register_channel(user, target, channel_password)
        else:
            # Nickname registration
            if len(params) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_register']))
                return
            account = params[0]
            email_or_star = params[1]
            password = params[2]
            email = None if email_or_star == '*' else email_or_star
            await self._register_nick(user, account, password, email)

    async def handle_unregister(self, user, params):
        """Handle UNREGISTER command for nicknames and channels

        Syntax: UNREGISTER <account|#channel>
        """
        if not params:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_unregister']))
            return

        target = params[0]

        if is_channel(target):
            await self._unregister_channel(user, target)
        else:
            await self._unregister_nick(user, target)

    async def handle_identify(self, user, params):
        """Handle IDENTIFY command for nickname authentication

        Syntax: IDENTIFY [<account>] <password>
        """
        if not params:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_identify']))
            return

        if len(params) == 1:
            # IDENTIFY <password> - use current nickname
            account = user.nickname
            password = params[0]
        else:
            # IDENTIFY <account> <password>
            account = params[0]
            password = params[1]

        await self._identify_nick(user, account, password)

    async def handle_mfa(self, user, params):
        """Handle MFA command for multi-factor authentication

        Syntax:
          MFA ENABLE           - Start MFA setup
          MFA VERIFY <code>    - Verify MFA code (for setup or login)
          MFA DISABLE <code>   - Disable MFA (requires valid code)
        """
        if not params:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_mfa']))
            return

        subcmd = params[0].upper()

        if subcmd == "ENABLE":
            await self._mfa_enable(user)
        elif subcmd == "VERIFY":
            if len(params) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_mfa_verify']))
                return
            await self._mfa_verify(user, params[1])
        elif subcmd == "DISABLE":
            code = params[1] if len(params) > 1 else None
            await self._mfa_disable(user, code)
        else:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_mfa']))

    async def _register_nick(self, user, account, password, email):
        """Register a nickname/account"""
        # Must be using the nickname to register it
        if user.nickname.lower() != account.lower():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['reg_must_use_nickname']))
            return

        if user.has_mode('r'):
            await user.send(self.get_reply("872", user))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    email_param = email if email else '*'
                    await trunk_server.send(f"REGCMD {user.nickname} REGISTER_NICK {account} {password} {email_param}")
                    await self.send_server_message(user, "reg_request_sent")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (account,)) as cursor:
                    if await cursor.fetchone():
                        await user.send(self.get_reply("870", user, nick=account))
                        return

                nick_uuid = str(uuid.uuid4())
                password_hash = await hash_password_async(password)
                now = int(time.time())

                await db.execute("""INSERT INTO registered_nicks
                    (uuid, nickname, password_hash, email, registered_at, last_seen, registered_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (nick_uuid, account, password_hash, email, now, now, user.prefix()))
                await db.commit()

                user.set_mode('r', True)
                await user.send(f":{user.nickname} MODE {user.nickname} :+r")
                await user.send(self.get_reply("874", user, message=f"Your nickname {account} has been registered (UUID: {nick_uuid})"))
                logger.info(get_log_message("register_nick", account=account, prefix=user.prefix()))

        except Exception as e:
            logger.error(get_log_message("register_nick_error", error=e))
            await user.send(self.get_reply("764", user))

    async def _register_channel(self, user, channel_name, password):
        """Register a channel"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['reg_requires_identify']))
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=channel_name))
            return

        if user.nickname not in channel.owners:
            await user.send(self.get_reply("482", user, target=chan_name))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    password_param = password if password else '*'
                    await trunk_server.send(f"REGCMD {user.nickname} REGISTER_CHANNEL {chan_name} {password_param}")
                    await self.send_server_message(user, "reg_channel_request_sent")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_channels WHERE channel_name = ?",
                                     (chan_name,)) as cursor:
                    if await cursor.fetchone():
                        await user.send(self.get_reply("918", user, channel=chan_name))
                        return

                # For staff users, use their username; for regular users, use their nickname
                if user.authenticated and user.staff_level in ["ADMIN", "SYSOP", "GUIDE"]:
                    # Staff user - look up or create registered_nicks entry for their username
                    account_name = user.username.lstrip('~')
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (account_name,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            # Auto-create a registered_nicks entry for this staff account
                            staff_uuid = str(uuid.uuid4())
                            now = int(time.time())
                            # Use a dummy password hash since staff authenticate via users table
                            await db.execute("""INSERT INTO registered_nicks
                                (uuid, nickname, password_hash, registered_at, last_seen, registered_by)
                                VALUES (?, ?, ?, ?, ?, ?)""",
                                (staff_uuid, account_name, "", now, now, f"SYSTEM (staff account)"))
                            owner_uuid = staff_uuid
                        else:
                            owner_uuid = owner_row[0]
                else:
                    # Regular user - check their nickname is registered
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (user.nickname,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['reg_nick_required']))
                            return
                        owner_uuid = owner_row[0]

                chan_uuid = str(uuid.uuid4())
                now = int(time.time())

                # Save channel properties (owners, hosts, voices, ACCESS, topic, keys, etc.)
                properties_json = channel.get_properties_json()

                await db.execute("""INSERT INTO registered_channels
                    (uuid, channel_name, owner_uuid, registered_at, properties)
                    VALUES (?, ?, ?, ?, ?)""",
                    (chan_uuid, chan_name, owner_uuid, now, properties_json))
                await db.commit()

                channel.registered = True
                channel.account_uuid = chan_uuid
                channel.modes['r'] = True  # Set +r mode for registered channel
                # Broadcast mode change to channel
                await channel.broadcast(f":{user.prefix()} MODE {chan_name} +r")
                if password:
                    channel.owner_key = password

                await user.send(self.get_reply("874", user, message=f"Your channel {chan_name} has been registered"))
                logger.info(get_log_message("register_channel", channel=chan_name, nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("register_channel_error", error=e))
            await user.send(self.get_reply("764", user))

    async def _unregister_nick(self, user, account):
        """Unregister a nickname/account"""
        if user.nickname.lower() != account.lower():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['unreg_must_be_owner']))
            return

        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify_unregister']))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} UNREGISTER_NICK {account}")
                    await self.send_server_message(user, "unreg_request_sent")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                await db.execute("DELETE FROM registered_nicks WHERE nickname = ?", (account,))
                await db.commit()

                user.set_mode('r', False)
                await user.send(f":{user.nickname} MODE {user.nickname} :-r")
                await user.send(self.get_reply("875", user, message=f"Your nickname {account} has been unregistered"))
                logger.info(get_log_message("unregister_nick", account=account))

        except Exception as e:
            logger.error(get_log_message("unregister_nick_error", error=e))
            await user.send(self.get_reply("766", user))

    async def _unregister_channel(self, user, channel_name):
        """Unregister a channel"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify']))
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(self.get_reply("403", user, target=channel_name))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} UNREGISTER_CHANNEL {chan_name}")
                    await self.send_server_message(user, "unreg_channel_request_sent")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                # Check if channel is registered
                async with db.execute("SELECT owner_uuid FROM registered_channels WHERE channel_name = ?",
                                     (chan_name,)) as cursor:
                    chan_row = await cursor.fetchone()
                    if not chan_row:
                        await user.send(self.get_reply("919", user, channel=chan_name))
                        return

                # ADMINs can unregister any channel without needing a registered_nicks entry
                if user.has_mode('a'):
                    pass  # Skip ownership check for ADMIN
                else:
                    # Verify ownership - for staff, use username; for regular users, use nickname
                    if user.authenticated and user.staff_level in ["ADMIN", "SYSOP", "GUIDE"]:
                        account_name = user.username.lstrip('~')
                        async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                             (account_name,)) as cursor:
                            nick_row = await cursor.fetchone()
                            if not nick_row:
                                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['unreg_staff_not_registered']))
                                return
                    else:
                        async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                             (user.nickname,)) as cursor:
                            nick_row = await cursor.fetchone()
                            if not nick_row:
                                await user.send(self.get_reply("871", user, nick=user.nickname))
                                return

                    # Verify ownership
                    if chan_row[0] != nick_row[0]:
                        await user.send(self.get_reply("482", user, target=chan_name))
                        return

                await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (chan_name,))
                await db.commit()

                channel.registered = False
                channel.account_uuid = None
                channel.modes['r'] = False  # Remove +r mode
                # Broadcast mode change to channel
                await channel.broadcast(f":{user.prefix()} MODE {chan_name} -r")
                await user.send(self.get_reply("875", user, message=f"Your channel {chan_name} has been unregistered"))
                logger.info(get_log_message("unregister_channel", channel=chan_name, nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("unregister_channel_error", error=e))
            await user.send(self.get_reply("766", user))

    async def _identify_nick(self, user, account, password):
        """Identify to a registered nickname"""
        if user.nickname.lower() != account.lower():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['identify_must_use_nickname']))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} IDENTIFY {account} {password}")
                    await self.send_server_message(user, "identify_in_progress")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid, password_hash, mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (account,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("871", user, nick=account))
                        return

                    nick_uuid, password_hash, mfa_enabled, mfa_secret = row
                    # Use non-blocking bcrypt check
                    if await check_password_async(password, password_hash):
                        self.failed_auth_tracker.record_success(user.ip)
                        if mfa_enabled and mfa_secret:
                            user.pending_mfa = nick_uuid
                            await self.send_server_message(user, "identify_mfa_required")
                            return

                        # Only set +r mode if not already set
                        if not user.has_mode('r'):
                            user.set_mode('r', True)
                            await user.send(f":{user.nickname} MODE {user.nickname} :+r")

                        # Set account name for IRCv3 features
                        user.sasl_account = account

                        await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE uuid = ?",
                                        (int(time.time()), nick_uuid))
                        await db.commit()
                        await user.send(self.get_reply("876", user, message=f"You are now identified as {account}"))
                        logger.info(get_log_message("identify_success", account=account))

                        # IRCv3 account-notify: notify users in shared channels
                        await self.send_account_notify(user)
                        if self.link_manager and self.link_manager.enabled and not user.is_remote:
                            await self.link_manager.broadcast_to_servers(
                                f":{user.prefix()} ACCOUNT {user.sasl_account or '*'}"
                            )

                        # Deliver pending memos
                        await self.deliver_pending_memos(user)
                    else:
                        self.failed_auth_tracker.record_failure(user.ip)
                        await user.send(self.get_reply("864", user))

        except Exception as e:
            logger.error(get_log_message("identify_error", error=e))
            await user.send(self.get_reply("765", user, message="Identification failed - please try again later"))

    async def _mfa_enable(self, user):
        """Enable MFA for authenticated user"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify_mfa']))
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['not_found_nick']))
                        return

                    mfa_enabled, existing_secret = row
                    if mfa_enabled and existing_secret:
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mfa_already_enabled']))
                        return

                secret = pyotp.random_base32()
                totp = pyotp.TOTP(secret)

                await db.execute("UPDATE registered_nicks SET mfa_secret = ? WHERE nickname = ?",
                                (secret, user.nickname))
                await db.commit()

                issuer = CONFIG.get('server', 'name', default='irc.local')
                provisioning_uri = totp.provisioning_uri(name=user.nickname, issuer_name=issuer)

                await user.send(self.get_reply("878", user, secret=secret))
                await self.send_server_message(user, "mfa_uri", uri=provisioning_uri)
                logger.info(get_log_message("mfa_setup_initiated", nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("mfa_enable_error", error=e))
            await self.send_server_message(user, "mfa_setup_failed")

    async def _mfa_verify(self, user, code):
        """Verify MFA code for login or setup"""
        try:
            async with self.db_pool.connection() as db:
                # Case 1: Completing MFA login
                if user.pending_mfa:
                    async with db.execute("SELECT mfa_secret, nickname FROM registered_nicks WHERE uuid = ?",
                                         (user.pending_mfa,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await self.send_server_message(user, "mfa_session_expired")
                            user.pending_mfa = None
                            return

                        mfa_secret, nickname = row
                        totp = pyotp.TOTP(mfa_secret)

                        if totp.verify(code, valid_window=1):
                            user.pending_mfa = None
                            user.set_mode('r', True)
                            await user.send(f":{user.nickname} MODE {user.nickname} :+r")
                            await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE nickname = ?",
                                            (int(time.time()), nickname))
                            await db.commit()
                            await user.send(self.get_reply("928", user, nickname=nickname))
                            logger.info(get_log_message("mfa_identify_success", nickname=nickname))
                        else:
                            await user.send(self.get_reply("865", user))
                    return

                # Case 2: Completing MFA setup
                if not user.has_mode('r'):
                    await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify']))
                    return

                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['not_found_nick']))
                        return

                    mfa_enabled, mfa_secret = row
                    if mfa_enabled:
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mfa_already_enabled']))
                        return
                    if not mfa_secret:
                        await self.send_server_message(user, "mfa_enable_first")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if totp.verify(code, valid_window=1):
                        await db.execute("UPDATE registered_nicks SET mfa_enabled = 1 WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()
                        await self.send_server_message(user, "mfa_enabled_success")
                        logger.info(get_log_message("mfa_enabled", nickname=user.nickname))
                    else:
                        await self.send_server_message(user, "mfa_code_invalid_cancelled")
                        await db.execute("UPDATE registered_nicks SET mfa_secret = NULL WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()

        except Exception as e:
            logger.error(get_log_message("mfa_verify_error", error=e))
            await user.send(self.get_reply("765", user, message=SERVER_MESSAGES['mfa_verify_failed']))

    async def _mfa_disable(self, user, code):
        """Disable MFA for authenticated user"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify']))
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['not_found_nick']))
                        return

                    mfa_enabled, mfa_secret = row
                    if not mfa_enabled:
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mfa_not_enabled']))
                        return

                    if not code:
                        await self.send_server_message(user, "mfa_disable_usage")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if not totp.verify(code, valid_window=1):
                        await user.send(self.get_reply("865", user))
                        return

                    await db.execute("UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE nickname = ?",
                                    (user.nickname,))
                    await db.commit()
                    await user.send(self.get_reply("879", user))
                    logger.info(get_log_message("mfa_disabled", nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("mfa_disable_error", error=e))
            await self.send_server_message(user, "mfa_disable_failed")

    # ==========================================================================
    # STAFF AUTH COMMAND
    # ==========================================================================

    async def handle_auth(self, user, params):
        """Handle AUTH command for staff privilege elevation

        Syntax:
          AUTH <username> <password>      - Elevate to staff (initiate MFA if enabled)
          AUTH VERIFY <code>              - Complete MFA verification
          AUTH ENABLE <password>          - Enable MFA for your staff account
          AUTH DISABLE <password> <code>  - Disable MFA (requires valid code)
        """
        if not params:
            await self.send_server_message(user, "auth_usage_full")
            return

        subcmd = params[0].upper()

        # Handle AUTH VERIFY, AUTH ENABLE, AUTH DISABLE
        if subcmd == "VERIFY":
            await self._auth_verify(user, params)
            return
        elif subcmd == "ENABLE":
            await self._auth_enable(user, params)
            return
        elif subcmd == "DISABLE":
            await self._auth_disable(user, params)
            return

        # Otherwise, treat first param as username for AUTH <username> <password>
        if len(params) < 2:
            await self.send_server_message(user, "auth_usage_basic")
            return

        username = params[0]
        password = params[1]

        # Check SSL requirement (configurable)
        auth_require_ssl = CONFIG.get('security', 'auth_require_ssl', default=True)
        if auth_require_ssl and not user.using_ssl:
            await user.send(self.get_reply("760", user))
            await self.send_server_message(user, "auth_plaintext_warning")
            logger.warning(get_log_message("auth_no_ssl", nickname=user.nickname, ip=user.ip))
            await self._send_system_alert(SERVER_MESSAGES['auth_alert_blocked_ssl'].format(nickname=user.nickname, ip=user.ip))
            return

        # Progressive delay tracking
        delay = await self._get_auth_delay(username, user.ip)
        if delay > 0:
            await asyncio.sleep(delay)

        # Check lockout
        if await self._is_auth_locked_out(username, user.ip):
            remaining = await self._get_lockout_remaining(username, user.ip)
            await user.send(self.get_reply("761", user))
            await user.send(self.get_reply("763", user, remaining=remaining))
            logger.warning(get_log_message("auth_lockout", username=username, ip=user.ip))
            await self._send_system_alert(SERVER_MESSAGES['auth_alert_lockout'].format(username=username, nickname=user.nickname, ip=user.ip))
            return

        # In centralized-services mode, branch servers must proxy AUTH to the hub.
        if self.services_mode == 'centralized' and not self.is_services_hub:
            if self.link_manager and self.link_manager.enabled:
                auth_result = await self.link_manager.route_staff_auth(username, password, user)
                if not auth_result:
                    logger.warning(f"AUTH routing to trunk failed for {username}")
                    await user.send(self.get_reply("464", user, message=SERVER_MESSAGES['auth_failed']))
                    return

                if not auth_result.get('authenticated'):
                    await self._record_auth_failure(username, user.ip)
                    await user.send(self.get_reply("464", user, message=SERVER_MESSAGES['auth_failed']))
                    logger.warning(get_log_message("auth_wrong_password", username=username, nickname=user.nickname, ip=user.ip))
                    await self._send_system_alert(SERVER_MESSAGES['auth_alert_failed_password'].format(username=username, nickname=user.nickname, ip=user.ip))
                    return

                await self._record_auth_success(username, user.ip)
                await self._apply_staff_auth(
                    user,
                    username,
                    auth_result['level'],
                    auth_result.get('email'),
                    auth_result.get('realname'),
                    auth_result.get('force_realname', False),
                )
                return

            logger.warning(f"AUTH routing unavailable on branch for {username}")
            await user.send(self.get_reply("464", user, message=SERVER_MESSAGES['auth_failed']))
            return

        # Authenticate against staff database
        try:
            row = await self.db_pool.execute_one(
                "SELECT password_hash, level, mfa_enabled, mfa_secret, email, realname, force_realname FROM users WHERE username=?",
                (username,)
            )

            if not row:
                await self._record_auth_failure(username, user.ip)
                await user.send(self.get_reply("464", user, message=SERVER_MESSAGES['auth_failed']))
                logger.warning(get_log_message("auth_unknown_user", username=username, nickname=user.nickname, ip=user.ip))
                await self._send_system_alert(SERVER_MESSAGES['auth_alert_failed_user'].format(username=username, nickname=user.nickname, ip=user.ip))
                return

            password_hash, level, mfa_enabled, mfa_secret, email, realname, force_realname = row

            # Verify password
            if not await check_password_async(password, password_hash):
                await self._record_auth_failure(username, user.ip)
                await user.send(self.get_reply("464", user, message=SERVER_MESSAGES['auth_failed']))
                logger.warning(get_log_message("auth_wrong_password", username=username, nickname=user.nickname, ip=user.ip))
                await self._send_system_alert(SERVER_MESSAGES['auth_alert_failed_password'].format(username=username, nickname=user.nickname, ip=user.ip))
                return

            # Password correct! Clear failed attempts
            await self._record_auth_success(username, user.ip)

            # Check if MFA is enabled
            if mfa_enabled and mfa_secret:
                # Set pending state - modes will NOT be applied until MFA verify
                user.pending_staff_auth = {
                    'username': username,
                    'level': level,
                    'email': email,
                    'realname': realname,
                    'force_realname': bool(force_realname),
                    'timestamp': time.time()
                }
                await self.send_server_message(user, "auth_mfa_required")
                await self.send_server_message(user, "auth_enter_code")
                logger.info(get_log_message("auth_pending_mfa", username=username, nickname=user.nickname, ip=user.ip))
                await self._send_system_alert(SERVER_MESSAGES['auth_alert_pending_mfa'].format(username=username, nickname=user.nickname, ip=user.ip, level=level))
                return

            # No MFA - apply privileges immediately
            await self._apply_staff_auth(user, username, level, email, realname, bool(force_realname))

        except Exception as e:
            logger.error(get_log_message("auth_error", error=e))
            await user.send(self.get_reply("464", user, message=SERVER_MESSAGES['auth_failed']))

    async def _auth_verify(self, user, params):
        """Verify MFA code for pending AUTH or to complete MFA setup"""
        if len(params) < 2:
            await self.send_server_message(user, "auth_verify_usage")
            return

        code = params[1]

        # Case 1: Pending authentication (user just did AUTH <username> <password>)
        if user.pending_staff_auth:
            # Check timeout (5 minutes)
            if time.time() - user.pending_staff_auth['timestamp'] > 300:
                user.pending_staff_auth = None
                await self.send_server_message(user, "auth_session_expired")
                logger.info(get_log_message("auth_mfa_expired", nickname=user.nickname))
                return

            username = user.pending_staff_auth['username']
            level = user.pending_staff_auth['level']

            try:
                row = await self.db_pool.execute_one(
                    "SELECT mfa_secret, mfa_enabled FROM users WHERE username=?",
                    (username,)
                )

                if not row or not row[0]:
                    user.pending_staff_auth = None
                    await self.send_server_message(user, "auth_mfa_config_error")
                    logger.error(get_log_message("auth_mfa_secret_missing", username=username))
                    return

                mfa_secret, mfa_enabled = row

                # Verify TOTP code
                import pyotp
                totp = pyotp.TOTP(mfa_secret)

                if not totp.verify(code, valid_window=1):
                    await user.send(self.get_reply("865", user))
                    logger.warning(get_log_message("auth_mfa_invalid", username=username, nickname=user.nickname, ip=user.ip))
                    await self._send_system_alert(SERVER_MESSAGES['auth_alert_mfa_failed'].format(username=username, nickname=user.nickname, ip=user.ip))
                    return

                # Code is valid! If MFA was in setup mode, enable it now
                if not mfa_enabled:
                    await self.db_pool.execute(
                        "UPDATE users SET mfa_enabled = 1 WHERE username = ?",
                        (username,)
                    )
                    logger.info(get_log_message("auth_mfa_first_verify", username=username))

                # MFA verified! Apply privileges NOW
                email = user.pending_staff_auth.get('email')
                realname = user.pending_staff_auth.get('realname')
                force_realname = user.pending_staff_auth.get('force_realname', False)
                user.pending_staff_auth = None

                await self._apply_staff_auth(user, username, level, email, realname, force_realname)

            except Exception as e:
                logger.error(get_log_message("auth_verify_error", error=e))
                await user.send(self.get_reply("765", user, message=SERVER_MESSAGES['mfa_verify_failed']))
            return

        # Case 2: Completing MFA setup (user is already authenticated and ran AUTH ENABLE)
        if user.authenticated and user.staff_level in ["ADMIN", "SYSOP", "GUIDE"]:
            username = user.username.lstrip('~')

            try:
                row = await self.db_pool.execute_one(
                    "SELECT mfa_enabled, mfa_secret FROM users WHERE username=?",
                    (username,)
                )

                if not row:
                    await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['not_found'].format(item=SERVER_MESSAGES['item_staff_account'])))
                    return

                mfa_enabled, mfa_secret = row

                if mfa_enabled:
                    await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mfa_already_enabled']))
                    return

                if not mfa_secret:
                    await self.send_server_message(user, "auth_enable_first")
                    return

                # Verify the code
                import pyotp
                totp = pyotp.TOTP(mfa_secret)

                if totp.verify(code, valid_window=1):
                    await self.db_pool.execute(
                        "UPDATE users SET mfa_enabled = 1 WHERE username = ?",
                        (username,)
                    )
                    await self.send_server_message(user, "auth_mfa_enabled")
                    await self.send_server_message(user, "auth_mfa_required_hint")
                    logger.info(get_log_message("auth_verify_mfa_enabled", username=username))
                else:
                    await self.send_server_message(user, "auth_mfa_setup_cancelled")
                    await self.db_pool.execute(
                        "UPDATE users SET mfa_secret = NULL WHERE username = ?",
                        (username,)
                    )
                    logger.warning(get_log_message("auth_verify_mfa_failed", username=username))

            except Exception as e:
                logger.error(get_log_message("auth_verify_setup_error", error=e))
                await user.send(self.get_reply("765", user, message=SERVER_MESSAGES['mfa_verify_failed']))
            return

        # Case 3: No pending auth and not authenticated - error
        await self.send_server_message(user, "auth_no_pending")
        await self.send_server_message(user, "auth_or_enable")

    async def _auth_enable(self, user, params):
        """Enable MFA for staff account (self-service)"""
        if len(params) < 2:
            await self.send_server_message(user, "auth_enable_usage")
            await user.send(self.get_reply("461", user, command="AUTH ENABLE"))
            return

        password = params[1]

        # Must be authenticated staff
        if not user.authenticated or user.staff_level not in ["ADMIN", "SYSOP", "GUIDE"]:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['auth_must_be_staff']))
            return

        username = user.username.lstrip('~')

        try:
            row = await self.db_pool.execute_one(
                "SELECT password_hash, mfa_enabled, mfa_secret FROM users WHERE username=?",
                (username,)
            )

            if not row:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['not_found'].format(item=SERVER_MESSAGES['item_staff_account'])))
                return

            password_hash, mfa_enabled, existing_secret = row

            # Verify password
            if not await check_password_async(password, password_hash):
                await user.send(self.get_reply("762", user))
                logger.warning(get_log_message("auth_enable_bad_password", username=username))
                return

            if mfa_enabled and existing_secret:
                await self.send_server_message(user, "auth_mfa_already_enabled")
                return

            # Generate new TOTP secret
            import pyotp
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)

            # Store secret but don't enable yet
            await self.db_pool.execute(
                "UPDATE users SET mfa_secret = ? WHERE username = ?",
                (secret, username)
            )

            # Generate provisioning URI
            issuer = CONFIG.get('server', 'name', default='pyIRCX')
            provisioning_uri = totp.provisioning_uri(name=username, issuer_name=issuer)

            await user.send(self.get_reply("878", user, secret=secret))
            await self.send_server_message(user, "mfa_uri", uri=provisioning_uri)
            logger.info(get_log_message("auth_enable_secret_generated", username=username))

        except Exception as e:
            logger.error(get_log_message("auth_enable_error", error=e))
            await self.send_server_message(user, "auth_setup_failed")

    async def _auth_disable(self, user, params):
        """Disable MFA for staff account"""
        if len(params) < 3:
            await self.send_server_message(user, "auth_disable_usage")
            await user.send(self.get_reply("461", user, command="MFA DISABLE"))
            return

        password = params[1]
        code = params[2]

        # Must be authenticated staff
        if not user.authenticated or user.staff_level not in ["ADMIN", "SYSOP", "GUIDE"]:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['auth_staff_required']))
            return

        username = user.username.lstrip('~')

        try:
            row = await self.db_pool.execute_one(
                "SELECT password_hash, mfa_enabled, mfa_secret FROM users WHERE username=?",
                (username,)
            )

            if not row:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['not_found'].format(item=SERVER_MESSAGES['item_staff_account'])))
                return

            password_hash, mfa_enabled, mfa_secret = row

            # Verify password
            if not await check_password_async(password, password_hash):
                await user.send(self.get_reply("762", user))
                return

            if not mfa_enabled:
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mfa_not_enabled']))
                return

            if not mfa_secret:
                await self.send_server_message(user, "auth_mfa_config_error")
                return

            # Verify MFA code
            import pyotp
            totp = pyotp.TOTP(mfa_secret)

            if not totp.verify(code, valid_window=1):
                await user.send(self.get_reply("865", user))
                return

            # Disable MFA
            await self.db_pool.execute(
                "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = ?",
                (username,)
            )

            await self.send_server_message(user, "auth_mfa_disabled")
            logger.info(get_log_message("auth_disable_success", username=username))

        except Exception as e:
            logger.error(get_log_message("auth_disable_error", error=e))
            await self.send_server_message(user, "auth_mfa_disable_failed")

    async def _apply_staff_auth(self, user, username, level, email, realname, force_realname):
        """Apply staff authentication - set modes and update user state"""
        # Remove old staff modes if changing levels
        if user.authenticated:
            user.set_mode('a', False)
            user.set_mode('o', False)
            user.set_mode('g', False)

        # Capture old values for chghost notification
        old_user = user.username
        old_host = user.host

        # Save original host for DROP command (only if not already saved)
        if not hasattr(user, 'original_host') or user.original_host is None:
            user.original_host = user.host

        # Apply new staff authentication
        user.authenticated = True
        user.staff_level = level
        user.host = self.servername
        user.username = username

        # IRCv3 chghost: notify users in shared channels
        if old_user != user.username or old_host != user.host:
            await self.send_chghost_notify(user, old_user, old_host)
            if self.link_manager and self.link_manager.enabled and not user.is_remote:
                await self.link_manager.broadcast_to_servers(
                    f":{user.nickname}!{old_user}@{old_host} CHGHOST {user.username} {user.host}"
                )

        if email:
            user.staff_email = email
        if realname:
            user.staff_realname = realname
        if force_realname and realname:
            user.realname = realname

        # Apply mode based on level
        mode_char = None
        mode_name = None
        if level == "ADMIN":
            user.set_mode('a', True)
            mode_char = '+a'
            mode_name = "IRC administrator"
        elif level == "SYSOP":
            user.set_mode('o', True)
            mode_char = '+o'
            mode_name = "IRC operator"
        elif level == "GUIDE":
            user.set_mode('g', True)
            mode_char = '+g'
            mode_name = "IRC Guide"

        # Apply relaxed rate limits for staff
        user.rate_limiter = RateLimiter(RateLimiter.STAFF_COOLDOWNS)

        # Send mode change to user
        if mode_char:
            mode_msg = f":{user.nickname} MODE {user.nickname} :{mode_char}"
            await user.send(mode_msg)
            if self.link_manager and self.link_manager.enabled and not user.is_remote:
                await self.link_manager.broadcast_to_servers(mode_msg)

        # Send success message
        await self.send_server_message(user, "auth_success_as", level=mode_name)
        await user.send(self.get_reply("386", user, message=SERVER_MESSAGES['auth_numeric_success'].format(level=level.lower())))

        # Log successful authentication
        logger.info(get_log_message("auth_success", username=username, nickname=user.nickname, ip=user.ip, level=level))

        # Branch servers in centralized-services mode do not keep a local users table.
        if self.db_pool:
            try:
                await self.db_pool.execute(
                    "UPDATE users SET last_login = ? WHERE username = ?",
                    (int(time.time()), username)
                )
            except Exception as e:
                logger.error(get_log_message("auth_update_last_login_error", error=e))

        # Alert #System channel
        await self._send_system_alert(SERVER_MESSAGES['auth_alert_success'].format(username=username, nickname=user.nickname, ip=user.ip, level=level))

        # Log to staff audit
        await self.log_staff(username, "AUTH", user.nickname, get_log_message("audit_auth_success", level=level, ip=user.ip))

    async def _send_system_alert(self, message):
        """Send alert to #System channel about AUTH attempts"""
        if '#System' not in self.channels:
            return

        system_channel = self.channels['#System']
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        alert_msg = f":{self.servername} PRIVMSG #System :[{timestamp}] {message}"

        for member in system_channel.members.values():
            if member.has_mode('a') or member.has_mode('o'):
                await member.send(alert_msg)

    async def _get_auth_delay(self, username, ip):
        """Get progressive delay for failed auth attempts"""
        failure_count = await self._count_auth_failures(username, ip)
        delays = {0: 0, 1: 0, 2: 2, 3: 5, 4: 10}
        return delays.get(failure_count, 0)

    async def _is_auth_locked_out(self, username, ip):
        """Check if username/IP is locked out"""
        max_attempts = CONFIG.get('security', 'auth_max_attempts', default=5)
        failure_count = await self._count_auth_failures(username, ip)
        return failure_count >= max_attempts

    async def _get_lockout_remaining(self, username, ip):
        """Get remaining lockout time in seconds"""
        lockout_duration = CONFIG.get('security', 'auth_lockout_duration', default=900)
        try:
            first_failure = await self._get_first_failure_time(username, ip)
            if first_failure:
                elapsed = time.time() - first_failure
                remaining = max(0, lockout_duration - int(elapsed))
                return remaining
        except Exception:
            pass
        return lockout_duration

    async def _count_auth_failures(self, username, ip):
        """Count recent auth failures for username/IP within lockout window"""
        if not self.db_pool:
            return 0
        window = CONFIG.get('security', 'auth_lockout_window', default=600)
        cutoff = time.time() - window

        try:
            row = await self.db_pool.execute_one(
                """SELECT COUNT(*) FROM staff_audit
                   WHERE action = 'AUTH_FAIL'
                   AND (staff_username = ? OR details LIKE ?)
                   AND timestamp > ?""",
                (username, f'%{ip}%', cutoff)
            )
            return row[0] if row else 0
        except Exception as e:
            logger.error(get_log_message("auth_count_failures_error", error=e))
            return 0

    async def _get_first_failure_time(self, username, ip):
        """Get timestamp of first failure in current window"""
        if not self.db_pool:
            return None
        window = CONFIG.get('security', 'auth_lockout_window', default=600)
        cutoff = time.time() - window

        try:
            row = await self.db_pool.execute_one(
                """SELECT MIN(timestamp) FROM staff_audit
                   WHERE action = 'AUTH_FAIL'
                   AND (staff_username = ? OR details LIKE ?)
                   AND timestamp > ?""",
                (username, f'%{ip}%', cutoff)
            )
            return row[0] if row and row[0] else None
        except Exception:
            return None

    async def _record_auth_failure(self, username, ip):
        """Record failed AUTH attempt"""
        await self.log_staff(username, "AUTH_FAIL", "system", get_log_message("audit_auth_fail", ip=ip))

    async def _record_auth_success(self, username, ip):
        """Record successful AUTH attempt (clears failures)"""
        pass

    async def handle_drop(self, user, params):
        """Handle DROP command - drop staff privileges and return to regular user

        Syntax:
          DROP  - Drop staff authentication and return to regular user mode
        """
        if not user.authenticated:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['not_authenticated']))
            return

        # Store info before dropping
        old_level = user.staff_level
        old_username = user.username.lstrip('~')

        # Capture old values for chghost notification
        old_user_full = user.username
        old_host = user.host

        # Remove staff modes
        if user.has_mode('a'):
            user.set_mode('a', False)
            await user.send(f":{user.nickname} MODE {user.nickname} :-a")
        elif user.has_mode('o'):
            user.set_mode('o', False)
            await user.send(f":{user.nickname} MODE {user.nickname} :-o")
        elif user.has_mode('g'):
            user.set_mode('g', False)
            await user.send(f":{user.nickname} MODE {user.nickname} :-g")

        # Reset to regular user
        user.authenticated = False
        user.staff_level = "USER"
        user.username = '~' + user.nickname.lower()
        user.host = getattr(user, 'original_host', None) or user.ip

        # IRCv3 chghost: notify users in shared channels
        if old_user_full != user.username or old_host != user.host:
            await self.send_chghost_notify(user, old_user_full, old_host)
            if self.link_manager and self.link_manager.enabled and not user.is_remote:
                await self.link_manager.broadcast_to_servers(
                    f":{user.nickname}!{old_user_full}@{old_host} CHGHOST {user.username} {user.host}"
                )

        # Clear pending staff auth if any
        user.pending_staff_auth = None

        await user.send(self.get_reply("927", user))
        await self.send_server_message(user, "drop_reauth_hint")

        logger.info(get_log_message("drop_success", username=old_username, level=old_level, nickname=user.nickname, ip=user.ip))

        # Alert #System channel
        await self._send_system_alert(SERVER_MESSAGES['auth_alert_drop'].format(username=old_username, level=old_level, nickname=user.nickname, ip=user.ip))

        # Log to staff audit
        await self.log_staff(old_username, "DROP", user.nickname, get_log_message("audit_auth_drop", old_level=old_level, ip=user.ip))

    # ==========================================================================
    # WATCH, SILENCE, CHGPASS, MEMO COMMANDS
    # ==========================================================================

    async def handle_monitor(self, user, params):
        """Handle MONITOR/WATCH command for online/offline notifications

        MONITOR Syntax (IRCv3):
          MONITOR + nick1,nick2   - Add nicks to watch list (comma-separated)
          MONITOR - nick1,nick2   - Remove nicks from watch list
          MONITOR L               - List watched nicks
          MONITOR C               - Clear watch list
          MONITOR S               - Show status of watched nicks

        WATCH Syntax (IRCX) - also supported:
          WATCH +nick     - Add nick (+ attached to nick)
          WATCH -nick     - Remove nick
          WATCH L/C/S     - Same as MONITOR
        """
        # Rate limit MONITOR commands
        if not user.rate_limiter.check('MONITOR'):
            await user.send(self.get_reply("830", user))
            return

        if not params:
            # List all watched nicks
            if user.watch_list:
                nicks = " ".join(user.watch_list)
                await user.send(self.get_reply("606", user, nicks=nicks))
            await user.send(self.get_reply("607", user))
            return

        # Handle IRCv3 MONITOR syntax: "MONITOR + nick1,nick2" (+ is separate param)
        if params[0] == '+' and len(params) > 1:
            # Expand comma-separated nicks into WATCH format
            nicks = params[1].split(',')
            params = ['+' + nick.strip() for nick in nicks if nick.strip()]
        elif params[0] == '-' and len(params) > 1:
            nicks = params[1].split(',')
            params = ['-' + nick.strip() for nick in nicks if nick.strip()]

        max_monitor = CONFIG.get('limits', 'max_monitor', default=100)
        for target in params:
            if target.startswith('+'):
                # Add to watch list
                nick = target[1:]
                if not nick:
                    continue
                nick_lower = nick.lower()
                # Enforce MONITOR limit
                if nick_lower not in user.watch_list and len(user.watch_list) >= max_monitor:
                    await user.send(self.get_reply("734", user, limit=max_monitor, targets=nick))
                    return
                user.watch_list.add(nick_lower)
                # Add to server watchers dict
                if nick_lower not in self.watchers:
                    self.watchers[nick_lower] = set()
                self.watchers[nick_lower].add(user)

                # Check if nick is currently online
                online_user = self.get_user(nick_lower)
                if online_user and online_user.registered:
                    await user.send(self.get_reply("604", user, target=online_user.nickname, ident=online_user.username, host=online_user.host, signon=online_user.signon_time))
                else:
                    await user.send(self.get_reply("605", user, target=nick))

            elif target.startswith('-'):
                # Remove from watch list
                nick = target[1:]
                if not nick:
                    continue
                nick_lower = nick.lower()
                user.watch_list.discard(nick_lower)
                # Remove from server watchers dict
                if nick_lower in self.watchers:
                    self.watchers[nick_lower].discard(user)
                    if not self.watchers[nick_lower]:
                        del self.watchers[nick_lower]
                await user.send(self.get_reply("602", user, target=nick))

            elif target.upper() == 'L':
                # List watched nicks
                if user.watch_list:
                    nicks = " ".join(user.watch_list)
                    await user.send(self.get_reply("606", user, nicks=nicks))
                await user.send(self.get_reply("607", user))

            elif target.upper() == 'C':
                # Clear watch list
                for nick_lower in list(user.watch_list):
                    if nick_lower in self.watchers:
                        self.watchers[nick_lower].discard(user)
                        if not self.watchers[nick_lower]:
                            del self.watchers[nick_lower]
                user.watch_list.clear()
                await self.send_server_message(user, "watch_cleared")

            elif target.upper() == 'S':
                # Show status of all watched nicks
                for nick_lower in user.watch_list:
                    online_user = self.get_user(nick_lower)
                    if online_user and online_user.registered:
                        await user.send(self.get_reply("604", user, target=online_user.nickname, ident=online_user.username, host=online_user.host, signon=online_user.signon_time))
                    else:
                        await user.send(self.get_reply("605", user, target=nick_lower))
                await user.send(self.get_reply("607", user))

    async def notify_watchers_online(self, user):
        """Notify watchers that a user has come online"""
        nick_lower = user.nickname.lower()
        if nick_lower in self.watchers:
            for watcher in self.watchers[nick_lower]:
                if watcher != user and watcher.registered:
                    await watcher.send(self.get_reply("600", watcher, target=user.nickname, ident=user.username, host=user.host, signon=user.signon_time))

    async def notify_watchers_offline(self, user):
        """Notify watchers that a user has gone offline"""
        nick_lower = user.nickname.lower()
        if nick_lower in self.watchers:
            for watcher in self.watchers[nick_lower]:
                if watcher != user and watcher.registered:
                    await watcher.send(self.get_reply("601", watcher, target=user.nickname, ident=user.username, host=user.host, signon=user.signon_time))

    async def handle_silence(self, user, params):
        """Handle SILENCE command for server-side ignore

        Syntax:
          SILENCE +hostmask   - Add hostmask to silence list
          SILENCE -hostmask   - Remove hostmask from silence list
          SILENCE             - List current silence list
        """
        # Rate limit SILENCE commands
        if not user.rate_limiter.check('SILENCE'):
            await user.send(self.get_reply("830", user))
            return

        if not params:
            # List silence list
            for mask in user.silence_list:
                await user.send(self.get_reply("271", user, target=user.nickname, mask=mask))
            await user.send(self.get_reply("272", user))
            return

        max_silence = CONFIG.get('limits', 'max_silence', default=100)
        for target in params:
            if target.startswith('+'):
                mask = target[1:]
                if not mask:
                    continue
                # Validate mask format (should contain ! and @)
                if '!' not in mask or '@' not in mask:
                    mask = f"*!*@{mask}"  # Assume it's a hostname
                # Enforce SILENCE limit
                if mask not in user.silence_list and len(user.silence_list) >= max_silence:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Silence list is full ({max_silence} entries)")
                    return
                user.silence_list.add(mask)
                await self.send_server_message(user, "silence_added", mask=mask)

            elif target.startswith('-'):
                mask = target[1:]
                if not mask:
                    continue
                if '!' not in mask or '@' not in mask:
                    mask = f"*!*@{mask}"
                user.silence_list.discard(mask)
                await self.send_server_message(user, "silence_removed", mask=mask)

    def is_silenced(self, sender, recipient):
        """Check if sender is silenced by recipient"""
        if not recipient.silence_list:
            return False
        sender_mask = sender.prefix()
        for mask in recipient.silence_list:
            if fnmatch.fnmatch(sender_mask.lower(), mask.lower()):
                return True
        return False

    async def handle_chgpass(self, user, params):
        """Handle CHGPASS command for password change

        Syntax: CHGPASS <oldpassword> <newpassword>

        Works for registered nicknames only. Staff accounts should use
        STAFF PASS <username> <newpassword> instead.
        """
        if len(params) < 2:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_chgpass']))
            return

        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify']))
            return

        old_pass = params[0]
        new_pass = params[1]

        if len(new_pass) < 6:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['pass_too_short']))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} CHGPASS {old_pass} {new_pass}")
                    logger.debug(get_log_message("chgpass_proxied", nickname=user.nickname))
                    return
                else:
                    await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['pass_service_unavailable_trunk']))
                    return
            else:
                await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['pass_service_unavailable']))
                return

        # Trunk server - process locally
        try:
            async with self.db_pool.connection() as db:
                # Only check registered nicks table (staff use STAFF PASS)
                async with db.execute("SELECT password_hash FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['pass_nick_not_registered']))
                        return

                    # Use non-blocking bcrypt check
                    if not await check_password_async(old_pass, row[0]):
                        await user.send(self.get_reply("864", user))
                        return

                    new_hash = await hash_password_async(new_pass)
                    await db.execute("UPDATE registered_nicks SET password_hash = ? WHERE nickname = ?",
                                    (new_hash, user.nickname))
                    await db.commit()
                    await user.send(self.get_reply("883", user, message=SERVER_MESSAGES['pass_changed']))
                    logger.info(get_log_message("chgpass_success", nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("chgpass_error", error=e))
            await user.send(self.get_reply("888", user))

    async def handle_setname(self, user, params):
        """Handle IRCv3 SETNAME command to change realname

        Syntax: SETNAME <new realname>

        Allows users to change their realname (gecos) after connecting.
        Configurable via limits.setname_cooldown:
          - 0 or negative: SETNAME is disabled
          - positive: cooldown in seconds between changes
        SYSOPs and ADMINs are exempt from cooldown.
        """
        if not params:
            await user.send(self.get_reply("461", user, command="SETNAME"))
            return

        # Check if SETNAME is enabled and enforce cooldown
        # SYSOPs and ADMINs are exempt from cooldown
        cooldown = CONFIG.get('limits', 'setname_cooldown', default=60)
        if cooldown <= 0 and not user.is_high_staff():
            await user.send(f":{self.servername} FAIL SETNAME DISABLED :{SERVER_MESSAGES['setname_disabled']}")
            return

        if cooldown > 0 and not user.is_high_staff():
            elapsed = time.time() - user.last_setname_change
            if elapsed < cooldown:
                remaining = int(cooldown - elapsed)
                await user.send(f":{self.servername} FAIL SETNAME WAIT :{SERVER_MESSAGES['setname_wait'].format(remaining=remaining)}")
                return

        # Join all params as the new realname (in case of spaces)
        new_realname = " ".join(params)
        if new_realname.startswith(':'):
            new_realname = new_realname[1:]

        # Validate realname length
        max_realname = CONFIG.get('limits', 'max_realname_length', default=128)
        if len(new_realname) > max_realname:
            await user.send(f":{self.servername} FAIL SETNAME INVALID_REALNAME :{SERVER_MESSAGES['setname_too_long'].format(max_len=max_realname)}")
            return

        if not new_realname:
            await user.send(f":{self.servername} FAIL SETNAME INVALID_REALNAME :{SERVER_MESSAGES['setname_empty']}")
            return

        # Update the realname and timestamp
        user.realname = new_realname
        user.last_setname_change = time.time()

        # IRCv3 setname: notify users in shared channels
        await self.send_setname_notify(user)
        if self.link_manager and self.link_manager.enabled and not user.is_remote:
            await self.link_manager.broadcast_to_servers(
                f":{user.prefix()} SETNAME :{user.realname}"
            )

        logger.debug(get_log_message("setname_changed", nickname=user.nickname, realname=new_realname))

    async def handle_memo(self, user, params):
        """Handle MEMO command for offline messaging

        Syntax:
          MEMO SEND <nick> <message>  - Send memo to offline user
          MEMO LIST                   - List pending memos
          MEMO READ [id]              - Read memo(s)
          MEMO DELETE <id|ALL>        - Delete memo(s)
        """
        if not params:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_memo']))
            return

        subcmd = params[0].upper()

        if subcmd in ("SEND", "S"):
            if len(params) < 3:
                await self.send_server_message(user, "memo_send_usage")
                return
            target_nick = params[1]
            message = " ".join(params[2:])
            await self._memo_send(user, target_nick, message)

        elif subcmd in ("LIST", "L"):
            await self._memo_list(user)

        elif subcmd in ("READ", "R"):
            memo_id = int(params[1]) if len(params) > 1 and params[1].isdigit() else None
            await self._memo_read(user, memo_id)

        elif subcmd in ("DELETE", "DEL", "D"):
            if len(params) < 2:
                await self.send_server_message(user, "memo_del_usage")
                return
            target = params[1]
            await self._memo_del(user, target)

        else:
            await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_memo']))

    async def _memo_send(self, user, target_nick, message):
        """Send a memo to a user"""
        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    # Escape message to prevent protocol issues
                    escaped_message = message.replace('\r', '').replace('\n', ' ')
                    await trunk_server.send(f"MEMOCMD {user.nickname} SEND {target_nick} :{escaped_message}")
                    await self.send_server_message(user, "memo_request_sent")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                # Check if target is a registered nick
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (target_nick,)) as cursor:
                    if not await cursor.fetchone():
                        await self.send_server_message(user, "memo_nick_not_registered", target=target_nick)
                        return

                # Store memo
                await db.execute("""
                    INSERT INTO memos (recipient, sender, message, sent_at, read)
                    VALUES (?, ?, ?, ?, 0)
                """, (target_nick.lower(), user.nickname, message, int(time.time())))
                await db.commit()
                await user.send(self.get_reply("915", user, target=target_nick))

                # If recipient is online and identified, notify them
                target_user = self.get_user(target_nick)
                if target_user and target_user.has_mode('r'):
                    await target_user.send(self.get_reply("914", target_user, count=1))

        except Exception as e:
            logger.error(get_log_message("memo_send_error", error=e))
            await self.send_server_message(user, "memo_send_failed")

    async def _memo_list(self, user):
        """List user's memos"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify']))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"MEMOCMD {user.nickname} LIST")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("""
                    SELECT id, sender, sent_at, read, message FROM memos
                    WHERE recipient = ? ORDER BY sent_at DESC LIMIT 20
                """, (user.nickname.lower(),)) as cursor:
                    memos = await cursor.fetchall()

                if not memos:
                    await user.send(self.get_reply("913", user))
                    return

                await user.send(self.get_reply("960", user, count=len(memos)))
                for memo_id, sender, sent_at, read, message in memos:
                    status = "" if read else "[NEW] "
                    timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                    preview = (message[:30] + "...") if len(message) > 30 else message
                    await user.send(self.get_reply("961", user, status=status, id=memo_id, sender=sender, time=timestamp, preview=preview))
                await user.send(self.get_reply("962", user))

        except Exception as e:
            logger.error(get_log_message("memo_list_error", error=e))
            await self.send_server_message(user, "memo_list_failed")

    async def _memo_read(self, user, memo_id=None):
        """Read memo(s)"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify']))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    if memo_id:
                        await trunk_server.send(f"MEMOCMD {user.nickname} READ {memo_id}")
                    else:
                        await trunk_server.send(f"MEMOCMD {user.nickname} READ")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                if memo_id:
                    async with db.execute("""
                        SELECT id, sender, message, sent_at FROM memos
                        WHERE recipient = ? AND id = ?
                    """, (user.nickname.lower(), memo_id)) as cursor:
                        row = await cursor.fetchone()
                    if not row:
                        await self.send_server_message(user, "memo_not_found", id=memo_id)
                        return
                    memos = [row]
                else:
                    # Read all unread memos
                    async with db.execute("""
                        SELECT id, sender, message, sent_at FROM memos
                        WHERE recipient = ? AND read = 0 ORDER BY sent_at
                    """, (user.nickname.lower(),)) as cursor:
                        memos = await cursor.fetchall()

                if not memos:
                    await self.send_server_message(user, "memo_no_unread")
                    return

                for mid, sender, message, sent_at in memos:
                    timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                    await user.send(self.get_reply("963", user, id=mid, sender=sender, time=timestamp))
                    await self.send_raw_notice(user, message)

                # Mark as read
                ids = [m[0] for m in memos]
                placeholders = ",".join("?" * len(ids))
                await db.execute(f"UPDATE memos SET read = 1 WHERE id IN ({placeholders})", ids)
                await db.commit()

        except Exception as e:
            logger.error(get_log_message("memo_read_error", error=e))
            await self.send_server_message(user, "memo_read_failed")

    async def _memo_del(self, user, target):
        """Delete memo(s)"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_identify']))
            return

        # Check if branch in centralized mode - proxy to trunk
        if not self.is_services_hub and \
           self.services_mode == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"MEMOCMD {user.nickname} DELETE {target}")
                    await self.send_server_message(user, "memo_del_request_sent")
                    return
            await user.send(self.get_reply("912", user, message=SERVER_MESSAGES['services_unavailable']))
            return

        try:
            async with self.db_pool.connection() as db:
                if target.upper() == "ALL":
                    await db.execute("DELETE FROM memos WHERE recipient = ?", (user.nickname.lower(),))
                    await user.send(self.get_reply("917", user))
                elif target.isdigit():
                    result = await db.execute("DELETE FROM memos WHERE recipient = ? AND id = ?",
                                             (user.nickname.lower(), int(target)))
                    if result.rowcount > 0:
                        await user.send(self.get_reply("916", user, id=target))
                    else:
                        await self.send_server_message(user, "memo_not_found", id=target)
                else:
                    await self.send_server_message(user, "memo_del_usage")
                    return
                await db.commit()

        except Exception as e:
            logger.error(get_log_message("memo_del_error", error=e))
            await self.send_server_message(user, "memo_delete_failed")

    async def deliver_pending_memos(self, user):
        """Deliver pending memos when user identifies"""
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("""
                    SELECT COUNT(*) FROM memos WHERE recipient = ? AND read = 0
                """, (user.nickname.lower(),)) as cursor:
                    row = await cursor.fetchone()
                    count = row[0] if row else 0

                if count > 0:
                    await self.send_server_message(user, "memo_unread_count", count=count)

        except Exception as e:
            logger.error(get_log_message("memo_delivery_error", error=e))

    # ==========================================================================
    # CAP NEGOTIATION (IRCv3)
    # ==========================================================================

    # Supported capabilities
    # IRCv3 capabilities - only advertise what's actually implemented
    # See: https://ircv3.net/irc/
    SUPPORTED_CAPS = {
        'sasl',              # SASL authentication (PLAIN mechanism)
        'multi-prefix',      # Show all prefix modes in NAMES/WHO
        'away-notify',       # Notify when users go away
        'account-notify',    # Notify on account changes
        'extended-join',     # Extended JOIN with account info
        'server-time',       # Message timestamps (@time tag)
        'userhost-in-names', # Full hostmask in NAMES
        'cap-notify',        # Notify of cap changes (static caps, no NEW/DEL needed)
        'echo-message',      # Echo sent messages back to sender
        'invite-notify',     # Notify channel members of INVITEs
        'chghost',           # Notify when user's host changes
        'setname',           # Allow users to change realname
        'batch',             # Group related messages (NAMES, WHO, WHOIS, LIST)
        'message-tags',      # IRCv3.2 message tags (full client-only tag relay)
        'account-tag',       # Include sender's account in message tags
        'labeled-response',  # Correlate replies with commands via label tag
        'standard-replies',  # FAIL/WARN/NOTE structured error messages
        'draft/chathistory', # Channel history playback (uses existing +y transcripts)
    }

    # Supported SASL mechanisms
    SASL_MECHANISMS = ['PLAIN']

    async def handle_cap(self, user, params):
        """Handle IRCv3 CAP capability negotiation

        Syntax:
          CAP LS [version]    - List available capabilities
          CAP REQ <caps>      - Request capabilities
          CAP END             - End negotiation
          CAP LIST            - List enabled capabilities
          CAP ACK             - Acknowledge (server->client)
          CAP NAK             - Negative acknowledge (server->client)
        """
        if not params:
            await user.send(self.get_reply("410", user, message=SERVER_MESSAGES['cap_invalid']))
            return

        subcmd = params[0].upper()

        if subcmd == "LS":
            user.cap_negotiating = True
            user.cap_start_time = time.time()  # Track when CAP started for timeout
            version = params[1] if len(params) > 1 else "301"
            caps = " ".join(self.SUPPORTED_CAPS)
            # Multi-line if needed (CAP * LS * for continuation)
            await user.send(f":{self.servername} CAP {user.nickname} LS :{caps}")

        elif subcmd == "REQ":
            if len(params) < 2:
                return
            requested = params[1].lstrip(':').split()
            ack = []
            nak = []
            for cap in requested:
                cap_name = cap.lstrip('-')
                if cap.startswith('-'):
                    # Disable capability
                    user.enabled_caps.discard(cap_name)
                    ack.append(cap)
                elif cap_name in self.SUPPORTED_CAPS:
                    user.enabled_caps.add(cap_name)
                    ack.append(cap)
                else:
                    nak.append(cap)

            if nak:
                await user.send(f":{self.servername} CAP {user.nickname} NAK :{' '.join(nak)}")
            if ack:
                await user.send(f":{self.servername} CAP {user.nickname} ACK :{' '.join(ack)}")

        elif subcmd == "END":
            user.cap_negotiating = False
            user.cap_start_time = None  # Clear timeout tracker
            # Registration may proceed if NICK/USER already received
            if user.nickname != "*" and user.username != "unknown" and not user.registered:
                await self.check_reg(user)

        elif subcmd == "LIST":
            caps = " ".join(user.enabled_caps) if user.enabled_caps else ""
            await user.send(f":{self.servername} CAP {user.nickname} LIST :{caps}")

        else:
            await user.send(self.get_reply("410", user, message=SERVER_MESSAGES['cap_invalid_subcmd']))

    # ==========================================================================
    # SASL AUTHENTICATION
    # ==========================================================================

    async def handle_authenticate(self, user, params):
        """Handle SASL AUTHENTICATE command

        SASL flow:
        1. Client: CAP REQ :sasl
        2. Server: CAP ACK :sasl
        3. Client: AUTHENTICATE PLAIN
        4. Server: AUTHENTICATE +
        5. Client: AUTHENTICATE <base64(authzid\0authcid\0password)>
        6. Server: 903 :SASL authentication successful
           or: 904 :SASL authentication failed
        7. Client: CAP END
        """
        if not params:
            await user.send(self.get_reply("461", user, command="AUTHENTICATE"))
            return

        arg = params[0]

        # Client aborting - check this FIRST before rate limiting
        if arg == "*":
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(self.get_reply("906", user, message=SERVER_MESSAGES['sasl_aborted']))
            return

        # Check for auth lockout
        if self.failed_auth_tracker.is_locked_out(user.ip):
            remaining = self.failed_auth_tracker.get_lockout_remaining(user.ip)
            await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_lockout'].format(remaining=remaining)))
            return

        # Rate limit only the start of a SASL exchange. Continuation frames must
        # be allowed to arrive back-to-back or normal SASL clients will fail.
        starting_exchange = user.sasl_mechanism is None and arg.upper() in self.SASL_MECHANISMS
        if starting_exchange and not user.check_rate_limit('AUTHENTICATE'):
            await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_rate_limited']))
            return

        # Check if SASL capability is enabled
        if 'sasl' not in user.enabled_caps:
            await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_not_enabled']))
            return

        # Already authenticated via SASL
        if user.sasl_authenticated:
            await user.send(self.get_reply("907", user, message=SERVER_MESSAGES['sasl_already_auth']))
            return

        # Client requesting mechanism list or starting auth
        if arg.upper() in self.SASL_MECHANISMS:
            user.sasl_mechanism = arg.upper()
            user.sasl_buffer = ""
            # Send + to indicate ready for credentials
            await user.send("AUTHENTICATE +")
            return

        # Unknown mechanism
        if user.sasl_mechanism is None:
            # Check if it's an unsupported mechanism
            if arg.upper() not in self.SASL_MECHANISMS and not arg.startswith('+') and arg != "*":
                mechs = ",".join(self.SASL_MECHANISMS)
                await user.send(self.get_reply("908", user, mechanisms=mechs, message=SERVER_MESSAGES['sasl_mechanisms_available']))
                await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_failed']))
            return

        # Receiving credentials
        if arg == "+":
            # Empty auth (abort)
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(self.get_reply("906", user, message=SERVER_MESSAGES['sasl_aborted']))
            return

        # Add to buffer (for chunked data, max 400 bytes per line)
        user.sasl_buffer += arg

        # Check for too long SASL message (max 8KB base64)
        if len(user.sasl_buffer) > 8192:
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(self.get_reply("905", user, message=SERVER_MESSAGES['sasl_too_long']))
            return

        # If arg is exactly 400 chars, more data is coming
        if len(arg) == 400:
            return

        # Process the complete SASL data
        await self._process_sasl(user)

    async def _process_sasl(self, user):
        """Process completed SASL authentication data"""
        import base64

        try:
            # Decode base64 data
            decoded = base64.b64decode(user.sasl_buffer).decode('utf-8')
        except Exception as e:
            logger.warning(get_log_message("sasl_decode_error", nickname=user.nickname, error=e))
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_failed']))
            return

        user.sasl_buffer = ""

        if user.sasl_mechanism == "PLAIN":
            await self._sasl_plain(user, decoded)
        else:
            await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_failed']))

        user.sasl_mechanism = None

    async def _sasl_plain(self, user, decoded):
        """Handle SASL PLAIN authentication

        Format: authzid\0authcid\0password
        - authzid: authorization identity (usually empty or same as authcid)
        - authcid: authentication identity (username)
        - password: the password
        """
        try:
            parts = decoded.split('\0')
            if len(parts) != 3:
                self.failed_auth_tracker.record_failure(user.ip)
                await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_failed']))
                return

            authzid, authcid, password = parts

            # Use authcid as the username (authzid is often empty)
            username = authcid if authcid else authzid
            if not username or not password:
                self.failed_auth_tracker.record_failure(user.ip, username)
                await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_failed']))
                return

            # Authenticate against database using connection pool
            try:
                row = await self.db_pool.execute_one(
                    "SELECT password_hash, level FROM users WHERE username=?",
                    (username,)
                )
                if row:
                    # Use non-blocking bcrypt check
                    if await check_password_async(password, row[0]):
                        # Success - clear any failed attempts
                        self.failed_auth_tracker.record_success(user.ip, username)

                        user.sasl_authenticated = True
                        user.sasl_account = username
                        level = row[1]

                        # Mark as authenticated for staff
                        if level in ["ADMIN", "SYSOP", "GUIDE"]:
                            user.authenticated = True
                            user.staff_level = level
                            user.host = self.servername

                        # Send success responses
                        account_host = f"{user.nickname}!{username}@{user.host}"
                        await user.send(self.get_reply("900", user, account_host=account_host, username=username, message=SERVER_MESSAGES['sasl_logged_in'].format(username=username)))
                        await user.send(self.get_reply("903", user, message=SERVER_MESSAGES['sasl_successful']))
                        await self.send_account_notify(user)
                        if self.link_manager and self.link_manager.enabled and not user.is_remote:
                            await self.link_manager.broadcast_to_servers(
                                f":{user.prefix()} ACCOUNT {user.sasl_account or '*'}"
                            )
                        logger.info(get_log_message("sasl_plain_success", username=username, ip=user.ip))
                        return
            except Exception as e:
                logger.error(get_log_message("sasl_database_error", error=e))

            # Authentication failed - track failure by both IP and username
            self.failed_auth_tracker.record_failure(user.ip, username)
            logger.warning(get_log_message("sasl_plain_failed", username=username, ip=user.ip))
            await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_failed']))

        except Exception as e:
            logger.error(get_log_message("sasl_plain_error", error=e))
            self.failed_auth_tracker.record_failure(user.ip)
            await user.send(self.get_reply("904", user, message=SERVER_MESSAGES['sasl_failed']))

    # ==========================================================================
    # HOSTNAME RESOLUTION
    # ==========================================================================

    async def resolve_hostname(self, ip):
        """Resolve IP address to hostname asynchronously (supports IPv4 and IPv6)

        Returns hostname if successful, original IP if resolution fails or disabled
        """
        if not CONFIG.get('network', 'resolve_hostnames', default=True):
            return ip

        try:
            import ipaddress
            loop = asyncio.get_event_loop()

            # Determine address family for verification
            try:
                addr = ipaddress.ip_address(ip)
                family = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
            except ValueError:
                family = socket.AF_INET  # Default to IPv4 for invalid addresses

            # Run reverse DNS lookup in thread pool to avoid blocking
            result = await loop.run_in_executor(
                None,
                lambda: socket.gethostbyaddr(ip)
            )
            hostname = result[0]

            # Verify reverse lookup (prevent DNS spoofing)
            # Use getaddrinfo instead of gethostbyname for IPv6 support
            forward_result = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
            )

            # Check if any of the returned addresses match our IP
            for res in forward_result:
                addr_info = res[4]  # (ip, port) or (ip, port, flowinfo, scopeid)
                if addr_info[0] == ip:
                    return hostname

            return ip  # Forward lookup didn't match
        except (socket.herror, socket.gaierror, OSError):
            return ip  # Resolution failed, use IP

    async def handle_event(self, user, params):
        """Handle EVENT command for real-time server monitoring

        EVENT ADD <class> [<mask>] - Subscribe to events
        EVENT DELETE <class> [<mask>] - Unsubscribe from events
        EVENT LIST [<class>] - List active event subscriptions

        Classes: CONNECT, MEMBER, CHANNEL, USER, SERVER, SOCKET (ignored)
        """
        # Rate limit EVENT commands
        if not user.rate_limiter.check('EVENT'):
            await user.send(self.get_reply("830", user))
            return

        # Require IRCX mode (+x)
        if not (user.has_mode('x') or user.is_ircx):
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_ircx'].format(command="EVENT")))
            return

        # Require operator or admin privileges for EVENT
        if not user.is_high_staff():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_oper_admin'].format(command="EVENT")))
            return

        if not params:
            await self.send_notice(user, "event_usage")
            return

        action = params[0].upper()
        valid_classes = {'CONNECT', 'MEMBER', 'CHANNEL', 'USER', 'SERVER', 'SOCKET'}

        if action in ("ADD", "A"):
            if len(params) < 2:
                await self.send_server_message(user, "event_add_usage")
                return

            cls = params[1].upper()
            if cls not in valid_classes:
                await self.send_notice(user, "event_classes")
                return

            # SOCKET class is accepted but returns no events (silently ignored)
            mask = params[2] if len(params) >= 3 else "*!*@*"
            user.traps.append((cls, mask))
            await user.send(self.get_reply("806", user, cls=cls, mask=mask))

        elif action in ("DELETE", "DEL", "D"):
            if len(params) < 2:
                await self.send_server_message(user, "event_delete_usage")
                return

            cls = params[1].upper()
            mask = params[2] if len(params) >= 3 else "*!*@*"

            # Remove matching trap
            original_count = len(user.traps)
            user.traps = [(c, m) for c, m in user.traps if not (c == cls and m == mask)]

            if len(user.traps) < original_count:
                await user.send(self.get_reply("807", user, cls=cls, mask=mask))
            else:
                await self.send_server_message(user, "event_trap_not_found")

        elif action in ("LIST", "L"):
            # List all traps or filter by class
            filter_cls = params[1].upper() if len(params) >= 2 else None

            if filter_cls and filter_cls not in valid_classes:
                await self.send_notice(user, "event_classes")
                return

            await user.send(self.get_reply("808", user))

            # SOCKET traps are never shown (they don't fire events)
            for cls, mask in user.traps:
                if cls == 'SOCKET':
                    continue
                if filter_cls is None or cls == filter_cls:
                    await user.send(self.get_reply("809", user, cls=cls, mask=mask))

            await user.send(self.get_reply("810", user))

        else:
            await self.send_notice(user, "event_usage")

    # ==========================================================================
    # SERVICE HANDLERS (Registrar, Messenger, NewsFlash)
    # ==========================================================================

    async def _mystical_entity_random_response(self, user, entity_name):
        """Send random funny response from System/God to non-admin users

        God has biblical/divine musings, System has quirky IT/tech babble.
        Only responds to direct PRIVMSG/NOTICE (not in channels).
        """
        import random

        responses = ENTITY_RESPONSES.get(entity_name.lower(), ENTITY_RESPONSES["system"])
        response = random.choice(responses)

        await self._service_reply(entity_name, user, response)

    async def _handle_mystical_entity(self, admin, entity_name, text):
        """Handle commands to System/God mystical entities (administrator only)

        Admins can command these entities to perform actions:
        - PRIVMSG <target> <message> - Send message as the entity
        - NOTICE <target> <message> - Send notice as the entity
        - KICK <channel> <nick> <reason> - Kick user as the entity
        - KILL <nick> <reason> - Kill user as the entity
        - HELP - Show available commands
        """
        parts = text.strip().split(None, 3)
        if not parts:
            await self._send_service_msg(entity_name, admin, "entity_usage", entity_name=entity_name)
            return

        cmd = parts[0].upper()

        if cmd == "HELP":
            await self._send_service_help(entity_name, admin, "entity", entity_name=entity_name)
            return

        elif cmd == "PRIVMSG":
            if len(parts) < 3:
                await self._send_service_msg(entity_name, admin, "entity_privmsg_usage")
                return
            target = parts[1]
            message = ' '.join(parts[2:])

            # Send PRIVMSG masquerading as the entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"
            entity_msg = f":{entity_prefix} PRIVMSG {target} :{message}"

            if target == '*':
                send_tasks = []
                for recipient in self.users.values():
                    if not recipient.is_virtual:
                        send_tasks.append(recipient.send(entity_msg))
                await asyncio.gather(*send_tasks, return_exceptions=True)
                if self.link_manager and self.link_manager.enabled:
                    await self.link_manager.broadcast_to_servers(entity_msg)
            elif target.startswith('#') or target.startswith('&'):
                channel = self.channels.get(target)
                if not channel:
                    await self._send_service_msg(entity_name, admin, "entity_channel_not_found", target=target)
                    return
                send_tasks = []
                for member in channel.members.values():
                    if not member.is_remote:
                        send_tasks.append(member.send(entity_msg))
                await asyncio.gather(*send_tasks, return_exceptions=True)
                if self.link_manager and self.link_manager.enabled:
                    await self.link_manager.broadcast_to_servers(entity_msg)
            else:
                target_user = self.get_user(target)
                if not target_user:
                    await self._send_service_msg(entity_name, admin, "entity_user_not_found", target=target)
                    return
                if target_user.is_remote:
                    if self.link_manager and self.link_manager.enabled:
                        await self.link_manager.broadcast_to_servers(entity_msg)
                    else:
                        await target_user.send(entity_msg)
                else:
                    await target_user.send(entity_msg)

            await self._send_service_msg(entity_name, admin, "entity_privmsg_sent", target=target, entity_name=entity_name)
            return

        elif cmd == "NOTICE":
            if len(parts) < 3:
                await self._send_service_msg(entity_name, admin, "entity_notice_usage")
                return
            target = parts[1]
            message = ' '.join(parts[2:])

            # Send NOTICE masquerading as the entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"
            entity_msg = f":{entity_prefix} NOTICE {target} :{message}"

            if target == '*':
                send_tasks = []
                for recipient in self.users.values():
                    if not recipient.is_virtual:
                        send_tasks.append(recipient.send(entity_msg))
                await asyncio.gather(*send_tasks, return_exceptions=True)
                if self.link_manager and self.link_manager.enabled:
                    await self.link_manager.broadcast_to_servers(entity_msg)
            elif target.startswith('#') or target.startswith('&'):
                channel = self.channels.get(target)
                if not channel:
                    await self._send_service_msg(entity_name, admin, "entity_channel_not_found", target=target)
                    return
                send_tasks = []
                for member in channel.members.values():
                    if not member.is_remote:
                        send_tasks.append(member.send(entity_msg))
                await asyncio.gather(*send_tasks, return_exceptions=True)
                if self.link_manager and self.link_manager.enabled:
                    await self.link_manager.broadcast_to_servers(entity_msg)
            else:
                target_user = self.get_user(target)
                if not target_user:
                    await self._send_service_msg(entity_name, admin, "entity_user_not_found", target=target)
                    return
                if target_user.is_remote:
                    if self.link_manager and self.link_manager.enabled:
                        await self.link_manager.broadcast_to_servers(entity_msg)
                    else:
                        await target_user.send(entity_msg)
                else:
                    await target_user.send(entity_msg)

            await self._send_service_msg(entity_name, admin, "entity_notice_sent", target=target, entity_name=entity_name)
            return

        elif cmd == "KICK":
            if len(parts) < 3:
                await self._send_service_msg(entity_name, admin, "entity_kick_usage")
                return
            channel_name = parts[1]
            nick = parts[2]
            reason = parts[3] if len(parts) > 3 else f"Kicked by {entity_name}"

            channel = self.channels.get(channel_name)
            if not channel:
                await self._send_service_msg(entity_name, admin, "entity_channel_not_found", target=channel_name)
                return

            if nick not in channel.members:
                await self._send_service_msg(entity_name, admin, "entity_not_in_channel", nick=nick, channel=channel_name)
                return

            target_user = channel.members[nick]

            # Send KICK as entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"
            kick_msg = f":{entity_prefix} KICK {channel_name} {nick} :{reason}"
            send_tasks = []
            for member in channel.members.values():
                if not member.is_remote:
                    send_tasks.append(member.send(kick_msg))
            await asyncio.gather(*send_tasks, return_exceptions=True)

            # Remove user from channel
            del channel.members[nick]
            target_user.channels.discard(channel_name)
            channel.owners.discard(nick)
            channel.hosts.discard(nick)
            channel.voices.discard(nick)
            channel.gagged.discard(nick)

            if self.link_manager and self.link_manager.enabled:
                await self.link_manager.broadcast_to_servers(kick_msg)

            await self._send_service_msg(entity_name, admin, "entity_kicked", nick=nick, channel=channel_name, entity_name=entity_name)
            return

        elif cmd == "KILL":
            if len(parts) < 2:
                await self._send_service_msg(entity_name, admin, "entity_kill_usage")
                return
            nick = parts[1]
            reason = parts[2] if len(parts) > 2 else SERVER_MESSAGES['entity_kill_reason'].format(entity_name=entity_name)

            target_user = self.get_user(nick)
            if not target_user:
                await self._send_service_msg(entity_name, admin, "entity_user_not_found", target=nick)
                return

            # Can't kill other admins or the entity itself
            if target_user.has_mode('a'):
                await self._send_service_msg(entity_name, admin, "entity_cannot_kill_admin")
                return
            if target_user.is_virtual:
                await self._send_service_msg(entity_name, admin, "entity_cannot_kill_virtual")
                return

            # Send KILL as entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"
            kill_msg = f":{entity_prefix} KILL {nick} :{reason}"
            await target_user.send(kill_msg)

            if self.link_manager and self.link_manager.enabled and not target_user.is_remote:
                await self.link_manager.broadcast_to_servers(kill_msg)

            # Disconnect user
            await self.quit_user(target_user)

            await self._send_service_msg(entity_name, admin, "entity_killed", nick=nick, entity_name=entity_name, reason=reason)
            return

        else:
            await self._send_service_msg(entity_name, admin, "entity_unknown_cmd", cmd=cmd)

    async def _service_reply(self, service_name, user, message):
        """Send a reply from a service to a user"""
        if getattr(user, 'is_remote', False):
            target_server_name = getattr(user, 'from_server', None)
            if self.link_manager and self.link_manager.enabled and target_server_name:
                target_server = self.link_manager.servers.get(target_server_name)
                if target_server and target_server.is_direct:
                    await target_server.send(
                        f":{service_name}!{service_name}@{self.servername} NOTICE {user.nickname} :{message}"
                    )
                    return
        await user.send(f":{service_name}!{service_name}@{self.servername} NOTICE {user.nickname} :{message}")

    async def _send_service_msg(self, service_name, user, key, **kwargs):
        """Send a templated message from a service to a user"""
        template = SERVER_MESSAGES.get(key, key)
        message = template.format(**kwargs) if kwargs else template
        await self._service_reply(service_name, user, message)

    async def _send_service_help(self, service_name, user, help_key, **kwargs):
        """Send multi-line service help to a user"""
        lines = SERVICE_HELP.get(help_key, [])
        if isinstance(lines, str):
            msg = lines.format(**kwargs) if kwargs and '{' in lines else lines
            await self._service_reply(service_name, user, msg)
        else:
            for line in lines:
                msg = line.format(**kwargs) if kwargs and '{' in line else line
                await self._service_reply(service_name, user, msg)

    async def _handle_registrar_msg(self, user, text):
        """Handle messages to Registrar service - routes to direct command handlers

        This is a compatibility layer for users who prefer the traditional
        NickServ-style interface. All commands route to the same backend as
        the direct REGISTER, UNREGISTER, IDENTIFY, MFA commands.
        """
        parts = text.strip().split(None, 2)
        if not parts:
            await self._send_service_msg("Registrar", user, "registrar_help")
            await self._send_service_msg("Registrar", user, "registrar_tip")
            return

        cmd = parts[0].upper()

        if cmd == "HELP":
            await self._send_service_help("Registrar", user, "registrar")

        elif cmd == "REGISTER":
            # REGISTER <password> [email] -> REGISTER <nick> {*|email} <password>
            if len(parts) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_ns_register']))
                return
            password = parts[1]
            email = parts[2] if len(parts) > 2 else None
            await self._register_nick(user, user.nickname, password, email)

        elif cmd == "IDENTIFY":
            if len(parts) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_ns_identify']))
                return
            await self._identify_nick(user, user.nickname, parts[1])

        elif cmd == "DROP":
            await self._unregister_nick(user, user.nickname)

        elif cmd == "INFO":
            target = parts[1] if len(parts) > 1 else user.nickname
            await self._registrar_info(user, target)

        elif cmd == "CHANNEL":
            if len(parts) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_ns_channel_register']))
                return
            subcmd = parts[1].upper()
            channel_name = parts[2]
            if subcmd == "REGISTER":
                await self._register_channel(user, channel_name, None)
            elif subcmd == "DROP":
                await self._unregister_channel(user, channel_name)
            elif subcmd == "INFO":
                await self._registrar_channel_info(user, channel_name)
            else:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_ns_channel_full']))

        elif cmd == "SET":
            if len(parts) < 3:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_ns_set']))
                return
            setting = parts[1].upper()
            value = parts[2]
            await self._registrar_set(user, setting, value)

        elif cmd == "MFA":
            if len(parts) < 2:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_ns_mfa']))
                return
            subcmd = parts[1].upper()
            if subcmd == "ENABLE":
                await self._mfa_enable(user)
            elif subcmd == "DISABLE":
                code = parts[2] if len(parts) > 2 else None
                await self._mfa_disable(user, code)
            elif subcmd == "VERIFY":
                if len(parts) < 3:
                    await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_mfa_verify']))
                    return
                await self._mfa_verify(user, parts[2])
            else:
                await user.send(self.get_reply("860", user, usage=SERVER_MESSAGES['usage_ns_mfa']))

        else:
            await self._send_service_msg("Registrar", user, "registrar_unknown_cmd", cmd=cmd)

    async def _registrar_register_nick(self, user, password, email):
        """Register a nickname"""
        if user.has_mode('r'):
            await user.send(self.get_reply("872", user))
            return

        try:
            async with self.db_pool.connection() as db:
                # Check if nick already registered
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    if await cursor.fetchone():
                        await user.send(self.get_reply("870", user, nick=user.nickname))
                        return

                # Register the nickname
                nick_uuid = str(uuid.uuid4())
                password_hash = await hash_password_async(password)
                now = int(time.time())

                await db.execute("""INSERT INTO registered_nicks
                    (uuid, nickname, password_hash, email, registered_at, last_seen, registered_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (nick_uuid, user.nickname, password_hash, email, now, now, user.prefix()))
                await db.commit()

                user.set_mode('r', True)
                await user.send(f":{user.nickname} MODE {user.nickname} :+r")
                await user.send(self.get_reply("874", user, message=f"Your nickname {user.nickname} has been registered (UUID: {nick_uuid})"))
                logger.info(get_log_message("registrar_registered", nickname=user.nickname, prefix=user.prefix()))

        except Exception as e:
            logger.error(get_log_message("registrar_register_error", error=e))
            await user.send(self.get_reply("764", user))

    async def _registrar_identify(self, user, password):
        """Identify with a registered nickname"""
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid, password_hash, mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("871", user, nick=user.nickname))
                        return

                    nick_uuid, password_hash, mfa_enabled, mfa_secret = row
                    # Use non-blocking bcrypt check
                    if await check_password_async(password, password_hash):
                        self.failed_auth_tracker.record_success(user.ip)
                        # Check if MFA is enabled
                        if mfa_enabled and mfa_secret:
                            # Set pending MFA state - user must complete MFA verification
                            user.pending_mfa = nick_uuid
                            await user.send(self.get_reply("877", user))
                            return

                        # No MFA required - complete identification
                        user.set_mode('r', True)
                        await user.send(f":{user.nickname} MODE {user.nickname} :+r")
                        await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE uuid = ?",
                                        (int(time.time()), nick_uuid))
                        await db.commit()
                        await user.send(self.get_reply("876", user, message=f"You are now identified as {user.nickname}"))
                        logger.info(get_log_message("registrar_identified", nickname=user.nickname))
                    else:
                        self.failed_auth_tracker.record_failure(user.ip)
                        await user.send(self.get_reply("864", user))

        except Exception as e:
            logger.error(get_log_message("registrar_identify_error", error=e))
            await user.send(self.get_reply("765", user, message="Identification failed - please try again later"))

    async def _registrar_drop_nick(self, user):
        """Drop (unregister) a nickname"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("873", user))
            return

        try:
            async with self.db_pool.connection() as db:
                await db.execute("DELETE FROM registered_nicks WHERE nickname = ?", (user.nickname,))
                await db.commit()

                user.set_mode('r', False)
                await user.send(f":{user.nickname} MODE {user.nickname} :-r")
                await user.send(self.get_reply("875", user, message=f"Your nickname {user.nickname} has been dropped"))
                logger.info(get_log_message("registrar_dropped", nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("registrar_drop_error", error=e))
            await user.send(self.get_reply("766", user))

    async def _registrar_info(self, user, target_nick):
        """Get info about a registered nickname"""
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("""SELECT uuid, nickname, registered_at, last_seen, mfa_enabled
                                        FROM registered_nicks WHERE nickname = ?""",
                                     (target_nick,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("871", user, nick=target_nick))
                        return

                    nick_uuid, nickname, reg_at, last_seen, mfa = row
                    await self._send_service_msg("Registrar", user, "registrar_info_title", nickname=nickname)
                    await self._send_service_msg("Registrar", user, "registrar_info_uuid", uuid=nick_uuid)
                    await self._send_service_msg("Registrar", user, "registrar_info_registered", date=time.ctime(reg_at))
                    await self._send_service_msg("Registrar", user, "registrar_info_last_seen", date=time.ctime(last_seen))
                    await self._send_service_msg("Registrar", user, "registrar_info_mfa", status='Yes' if mfa else 'No')

        except Exception as e:
            logger.error(get_log_message("registrar_info_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_info_failed")

    async def _registrar_register_channel(self, user, channel_name):
        """Register a channel"""
        if not user.has_mode('r'):
            await self._send_service_msg("Registrar", user, "registrar_must_identify_reg")
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await self._send_service_msg("Registrar", user, "registrar_channel_not_exist")
            return

        if user.nickname not in channel.owners:
            await self._send_service_msg("Registrar", user, "registrar_must_be_owner", channel=chan_name)
            return

        try:
            async with self.db_pool.connection() as db:
                # Check if already registered
                async with db.execute("SELECT uuid FROM registered_channels WHERE channel_name = ?",
                                     (chan_name,)) as cursor:
                    if await cursor.fetchone():
                        await self._send_service_msg("Registrar", user, "registrar_channel_already_reg", channel=chan_name)
                        return

                # Get owner's UUID - for staff, use username; for regular users, use nickname
                if user.authenticated and user.staff_level in ["ADMIN", "SYSOP", "GUIDE"]:
                    account_name = user.username.lstrip('~')
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (account_name,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            # Auto-create a registered_nicks entry for this staff account
                            staff_uuid = str(uuid.uuid4())
                            now_temp = int(time.time())
                            await db.execute("""INSERT INTO registered_nicks
                                (uuid, nickname, password_hash, registered_at, last_seen, registered_by)
                                VALUES (?, ?, ?, ?, ?, ?)""",
                                (staff_uuid, account_name, "", now_temp, now_temp, f"SYSTEM (staff account)"))
                            owner_uuid = staff_uuid
                        else:
                            owner_uuid = owner_row[0]
                else:
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (user.nickname,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            await self._send_service_msg("Registrar", user, "registrar_nick_must_register")
                            return
                        owner_uuid = owner_row[0]

                # Register the channel
                chan_uuid = str(uuid.uuid4())
                now = int(time.time())

                # Save channel properties (owners, hosts, voices, ACCESS, topic, keys, etc.)
                properties_json = channel.get_properties_json()

                await db.execute("""INSERT INTO registered_channels
                    (uuid, channel_name, owner_uuid, registered_at, last_used, properties)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (chan_uuid, chan_name, owner_uuid, now, now, properties_json))
                await db.commit()

                channel.registered = True
                channel.account_uuid = chan_uuid
                channel.modes['r'] = True  # Set +r mode for registered channel
                # Broadcast mode change to channel
                await channel.broadcast(f":Registrar!registrar@{self.servername} MODE {chan_name} +r")
                await self._send_service_msg("Registrar", user, "registrar_channel_registered", channel=chan_name, uuid=chan_uuid)
                logger.info(get_log_message("registrar_channel_registered", channel=chan_name, nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("registrar_channel_register_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_channel_register_failed")

    async def _registrar_drop_channel(self, user, channel_name):
        """Drop (unregister) a channel"""
        if not user.has_mode('r'):
            await self._send_service_msg("Registrar", user, "registrar_identify_first")
            return

        try:
            async with self.db_pool.connection() as db:
                # Get owner's UUID - for staff, use username; for regular users, use nickname
                if user.authenticated and user.staff_level in ["ADMIN", "SYSOP", "GUIDE"]:
                    account_name = user.username.lstrip('~')
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (account_name,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            await self._send_service_msg("Registrar", user, "registrar_staff_not_registered")
                            return
                        owner_uuid = owner_row[0]
                else:
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (user.nickname,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            await self._send_service_msg("Registrar", user, "registrar_nick_not_registered")
                            return
                        owner_uuid = owner_row[0]

                # Check ownership
                async with db.execute("SELECT owner_uuid FROM registered_channels WHERE channel_name = ?",
                                     (channel_name,)) as cursor:
                    chan_row = await cursor.fetchone()
                    if not chan_row:
                        await self._send_service_msg("Registrar", user, "registrar_channel_not_reg")
                        return
                    if chan_row[0] != owner_uuid and not user.has_mode('a'):
                        await self._send_service_msg("Registrar", user, "registrar_only_owner_admin")
                        return

                await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (channel_name,))
                await db.commit()

                if channel_name in self.channels:
                    self.channels[channel_name].registered = False
                    self.channels[channel_name].account_uuid = None

                await self._send_service_msg("Registrar", user, "registrar_channel_dropped", channel=channel_name)
                logger.info(get_log_message("registrar_channel_dropped", channel=channel_name, nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("registrar_channel_drop_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_channel_drop_failed")

    async def _registrar_channel_info(self, user, channel_name):
        """Get info about a registered channel"""
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("""SELECT rc.uuid, rc.channel_name, rc.registered_at, rc.last_used,
                                        rc.description, rn.nickname as owner_nick
                                        FROM registered_channels rc
                                        LEFT JOIN registered_nicks rn ON rc.owner_uuid = rn.uuid
                                        WHERE rc.channel_name = ?""",
                                     (channel_name,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Registrar", user, "registrar_channel_not_reg")
                        return

                    chan_uuid, chan_name, reg_at, last_used, desc, owner = row
                    await self._send_service_msg("Registrar", user, "registrar_channel_info_title", name=chan_name)
                    await self._send_service_msg("Registrar", user, "registrar_channel_info_uuid", uuid=chan_uuid)
                    await self._send_service_msg("Registrar", user, "registrar_channel_info_owner", owner=owner or 'Unknown')
                    await self._send_service_msg("Registrar", user, "registrar_channel_info_registered", date=time.ctime(reg_at))
                    if desc:
                        await self._send_service_msg("Registrar", user, "registrar_channel_info_desc", description=desc)

        except Exception as e:
            logger.error(get_log_message("registrar_channel_info_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_channel_info_failed")

    async def _registrar_set(self, user, setting, value):
        """Change registration settings"""
        if not user.has_mode('r'):
            await self._send_service_msg("Registrar", user, "registrar_identify_first")
            return

        try:
            async with self.db_pool.connection() as db:
                if setting == "PASSWORD":
                    password_hash = await hash_password_async(value)
                    await db.execute("UPDATE registered_nicks SET password_hash = ? WHERE nickname = ?",
                                    (password_hash, user.nickname))
                    await db.commit()
                    await self._send_service_msg("Registrar", user, "registrar_set_password_updated")
                    logger.info(get_log_message("registrar_password_changed", nickname=user.nickname))

                elif setting == "EMAIL":
                    await db.execute("UPDATE registered_nicks SET email = ? WHERE nickname = ?",
                                    (value, user.nickname))
                    await db.commit()
                    await self._send_service_msg("Registrar", user, "registrar_set_email_updated", email=value)

                else:
                    await self._send_service_msg("Registrar", user, "registrar_set_unknown", setting=setting)

        except Exception as e:
            logger.error(get_log_message("registrar_set_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_set_failed")

    async def _registrar_mfa_enable(self, user):
        """Enable MFA for a registered nickname"""
        if not user.has_mode('r'):
            await self._send_service_msg("Registrar", user, "registrar_identify_first_mfa", action="enable")
            return

        try:
            async with self.db_pool.connection() as db:
                # Check if MFA is already enabled
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Registrar", user, "registrar_nick_not_found")
                        return

                    mfa_enabled, existing_secret = row
                    if mfa_enabled and existing_secret:
                        await self._send_service_msg("Registrar", user, "registrar_mfa_already_enabled")
                        return

                # Generate new TOTP secret
                secret = pyotp.random_base32()
                totp = pyotp.TOTP(secret)

                # Store the secret (but don't enable MFA yet - user must verify first)
                await db.execute("UPDATE registered_nicks SET mfa_secret = ? WHERE nickname = ?",
                                (secret, user.nickname))
                await db.commit()

                # Generate provisioning URI for authenticator apps
                issuer = CONFIG.get('server', 'name', default='irc.local')
                provisioning_uri = totp.provisioning_uri(name=user.nickname, issuer_name=issuer)

                # Send setup instructions
                await self._send_service_msg("Registrar", user, "registrar_mfa_setup_title")
                await self._send_service_msg("Registrar", user, "registrar_mfa_setup_secret", secret=secret)
                await self._send_service_msg("Registrar", user, "registrar_mfa_setup_uri", uri=provisioning_uri)
                await self._send_service_msg("Registrar", user, "registrar_mfa_setup_verify")
                await self._send_service_msg("Registrar", user, "registrar_mfa_setup_warning")
                logger.info(get_log_message("registrar_mfa_setup", nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("registrar_mfa_enable_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_mfa_setup_failed")

    async def _registrar_mfa_disable(self, user, code):
        """Disable MFA for a registered nickname"""
        if not user.has_mode('r'):
            await self._send_service_msg("Registrar", user, "registrar_identify_first_mfa", action="disable")
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Registrar", user, "registrar_nick_not_found")
                        return

                    mfa_enabled, mfa_secret = row
                    if not mfa_enabled:
                        await self._send_service_msg("Registrar", user, "registrar_mfa_not_enabled")
                        return

                    # Require valid code to disable MFA
                    if not code:
                        await self._send_service_msg("Registrar", user, "registrar_mfa_disable_usage")
                        await self._send_service_msg("Registrar", user, "registrar_mfa_disable_require")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if not totp.verify(code, valid_window=1):
                        await self._send_service_msg("Registrar", user, "registrar_mfa_code_invalid")
                        return

                    # Disable MFA
                    await db.execute("UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE nickname = ?",
                                    (user.nickname,))
                    await db.commit()

                    await self._send_service_msg("Registrar", user, "registrar_mfa_disabled_msg")
                    logger.info(get_log_message("registrar_mfa_disabled", nickname=user.nickname))

        except Exception as e:
            logger.error(get_log_message("registrar_mfa_disable_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_mfa_disable_failed")

    async def _registrar_mfa_verify(self, user, code):
        """Verify MFA code - either to complete login or to enable MFA"""
        try:
            async with self.db_pool.connection() as db:
                # Case 1: User is completing MFA verification after IDENTIFY
                if user.pending_mfa:
                    async with db.execute("SELECT mfa_secret, nickname FROM registered_nicks WHERE uuid = ?",
                                         (user.pending_mfa,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await self._send_service_msg("Registrar", user, "registrar_mfa_session_expired")
                            user.pending_mfa = None
                            return

                        mfa_secret, nickname = row
                        totp = pyotp.TOTP(mfa_secret)

                        if totp.verify(code, valid_window=1):
                            # MFA verified - complete identification
                            user.pending_mfa = None
                            user.set_mode('r', True)
                            await user.send(f":{user.nickname} MODE {user.nickname} :+r")
                            await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE nickname = ?",
                                            (int(time.time()), nickname))
                            await db.commit()
                            await self._send_service_msg("Registrar", user, "registrar_mfa_verified", nickname=user.nickname)
                            logger.info(get_log_message("registrar_mfa_identified", nickname=user.nickname))
                        else:
                            await self._send_service_msg("Registrar", user, "registrar_mfa_code_retry")
                    return

                # Case 2: User is enabling MFA (must be identified)
                if not user.has_mode('r'):
                    await self._send_service_msg("Registrar", user, "registrar_mfa_identify_or_verify")
                    return

                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Registrar", user, "registrar_nick_not_found")
                        return

                    mfa_enabled, mfa_secret = row

                    if mfa_enabled:
                        await self._send_service_msg("Registrar", user, "registrar_mfa_already_verify")
                        return

                    if not mfa_secret:
                        await self._send_service_msg("Registrar", user, "registrar_mfa_enable_first")
                        return

                    # Verify the code to enable MFA
                    totp = pyotp.TOTP(mfa_secret)
                    if totp.verify(code, valid_window=1):
                        await db.execute("UPDATE registered_nicks SET mfa_enabled = 1 WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()
                        await self._send_service_msg("Registrar", user, "registrar_mfa_now_enabled")
                        await self._send_service_msg("Registrar", user, "registrar_mfa_code_required")
                        logger.info(get_log_message("registrar_mfa_enabled", nickname=user.nickname))
                    else:
                        await self._send_service_msg("Registrar", user, "registrar_mfa_setup_cancelled")
                        # Clear the pending secret since verification failed
                        await db.execute("UPDATE registered_nicks SET mfa_secret = NULL WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()

        except Exception as e:
            logger.error(get_log_message("registrar_mfa_verify_error", error=e))
            await self._send_service_msg("Registrar", user, "registrar_mfa_verify_failed")

    async def _handle_messenger_msg(self, user, text):
        """Handle messages to Messenger service"""
        parts = text.strip().split(None, 2)
        if not parts:
            await self._send_service_msg("Messenger", user, "messenger_commands")
            return

        cmd = parts[0].upper()

        if cmd in ["HELP", "COMMANDS"]:
            await self._send_service_help("Messenger", user, "messenger")
            if user.is_admin():
                await self._send_service_help("Messenger", user, "messenger_admin")
            await self._send_service_help("Messenger", user, "messenger_tip")

        elif cmd == "SEND":
            if len(parts) < 3:
                await self._send_service_msg("Messenger", user, "messenger_send_usage")
                return
            target_nick = parts[1]
            message = parts[2]
            await self._messenger_send(user, target_nick, message)

        elif cmd in ("LIST", "L"):
            await self._messenger_list(user)

        elif cmd in ("READ", "R"):
            if len(parts) < 2:
                # No ID specified - read oldest unread
                await self._messenger_read(user, None)
            else:
                try:
                    msg_id = int(parts[1])
                    await self._messenger_read(user, msg_id)
                except ValueError:
                    await self._send_service_msg("Messenger", user, "messenger_delete_invalid_id")

        elif cmd in ("DELETE", "DEL", "D"):
            if len(parts) < 2:
                await self._send_service_msg("Messenger", user, "messenger_delete_usage")
                return
            try:
                msg_id = int(parts[1])
                await self._messenger_delete(user, msg_id)
            except ValueError:
                await self._send_service_msg("Messenger", user, "messenger_delete_invalid_id")

        elif cmd in ("CLEAR",):
            await self._messenger_clear(user)

        elif cmd == "COUNT":
            await self._messenger_count(user)

        elif cmd == "PUSH" and user.is_admin():
            # ADMIN only - push to all logged in users
            if len(parts) < 2:
                await self._send_service_msg("Messenger", user, "messenger_push_usage")
                return
            message = parts[1] if len(parts) == 2 else parts[1] + " " + parts[2]
            await self._messenger_push(user, message)

        else:
            await self._send_service_msg("Messenger", user, "messenger_unknown_cmd", cmd=cmd)

    async def _messenger_send(self, user, target_nick, message):
        """Send a message to a registered user's mailbox"""
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (target_nick,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Messenger", user, "messenger_nick_not_registered")
                        return
                    recipient_uuid = row[0]

                await db.execute("""INSERT INTO mailbox (recipient_uuid, sender_nick, message, sent_at)
                                   VALUES (?, ?, ?, ?)""",
                                (recipient_uuid, user.nickname, message, int(time.time())))
                await db.commit()

                await self._send_service_msg("Messenger", user, "messenger_sent", target=target_nick)

                # Notify if online, inform sender of delivery status
                target = self.get_user(target_nick)
                if target and not target.is_virtual:
                    await self._send_service_msg("Messenger", target, "messenger_new_message", sender=user.nickname)
                    await self._send_service_msg("Messenger", user, "messenger_user_online", target=target_nick)
                else:
                    await self._send_service_msg("Messenger", user, "messenger_user_offline", target=target_nick)

        except Exception as e:
            logger.error(get_log_message("messenger_send_error", error=e))
            await self._send_service_msg("Messenger", user, "messenger_send_failed")

    async def _messenger_list(self, user):
        """List messages in mailbox (without marking as read)"""
        if not user.has_mode('r'):
            await self._send_service_msg("Messenger", user, "messenger_identify_first")
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Messenger", user, "messenger_nick_not_reg")
                        return
                    user_uuid = row[0]

                async with db.execute("""SELECT id, sender_nick, message, sent_at, read
                                        FROM mailbox WHERE recipient_uuid = ? ORDER BY sent_at DESC LIMIT 20""",
                                     (user_uuid,)) as cursor:
                    messages = await cursor.fetchall()

                if not messages:
                    await self._send_service_msg("Messenger", user, "messenger_no_messages")
                    return

                await self._send_service_msg("Messenger", user, "messenger_list_header")
                for msg_id, sender, text, sent_at, is_read in messages:
                    status = "" if is_read else "[NEW] "
                    preview = text[:50] + "..." if len(text) > 50 else text
                    await self._send_service_msg("Messenger", user, "messenger_list_item",
                                                id=msg_id, status=status, sender=sender,
                                                time=time.ctime(sent_at), preview=preview)

        except Exception as e:
            logger.error(get_log_message("messenger_read_error", error=e))
            await self._send_service_msg("Messenger", user, "messenger_read_failed")

    async def _messenger_read(self, user, msg_id):
        """Read a specific message from mailbox"""
        if not user.has_mode('r'):
            await self._send_service_msg("Messenger", user, "messenger_identify_first")
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Messenger", user, "messenger_nick_not_reg")
                        return
                    user_uuid = row[0]

                if msg_id is not None:
                    # Read a specific message
                    async with db.execute("""SELECT id, sender_nick, message, sent_at
                                            FROM mailbox WHERE id = ? AND recipient_uuid = ?""",
                                         (msg_id, user_uuid)) as cursor:
                        row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Messenger", user, "messenger_not_found")
                        return
                    mid, sender, text, sent_at = row
                    await self._send_service_msg("Messenger", user, "messenger_read_header",
                                                id=mid, sender=sender, time=time.ctime(sent_at))
                    await self._send_service_msg("Messenger", user, "messenger_read_body", message=text)
                    await db.execute("UPDATE mailbox SET read = 1 WHERE id = ?", (mid,))
                    await db.commit()
                else:
                    # No ID specified - read oldest unread message
                    async with db.execute("""SELECT id, sender_nick, message, sent_at
                                            FROM mailbox WHERE recipient_uuid = ? AND read = 0
                                            ORDER BY sent_at ASC LIMIT 1""",
                                         (user_uuid,)) as cursor:
                        row = await cursor.fetchone()
                    if not row:
                        await self._send_service_msg("Messenger", user, "messenger_no_messages")
                        return
                    mid, sender, text, sent_at = row
                    await self._send_service_msg("Messenger", user, "messenger_read_header",
                                                id=mid, sender=sender, time=time.ctime(sent_at))
                    await self._send_service_msg("Messenger", user, "messenger_read_body", message=text)
                    await db.execute("UPDATE mailbox SET read = 1 WHERE id = ?", (mid,))
                    await db.commit()

        except Exception as e:
            logger.error(get_log_message("messenger_read_error", error=e))
            await self._send_service_msg("Messenger", user, "messenger_read_failed")

    async def _messenger_delete(self, user, msg_id):
        """Delete a message from mailbox"""
        if not user.has_mode('r'):
            await self._send_service_msg("Messenger", user, "messenger_identify_required")
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        return
                    user_uuid = row[0]

                result = await db.execute("DELETE FROM mailbox WHERE id = ? AND recipient_uuid = ?",
                                         (msg_id, user_uuid))
                await db.commit()

                if result.rowcount > 0:
                    await self._send_service_msg("Messenger", user, "messenger_deleted", msg_id=msg_id)
                else:
                    await self._send_service_msg("Messenger", user, "messenger_not_found")

        except Exception as e:
            logger.error(get_log_message("messenger_delete_error", error=e))
            await self._send_service_msg("Messenger", user, "messenger_delete_failed")

    async def _messenger_clear(self, user):
        """Clear all messages from mailbox"""
        if not user.has_mode('r'):
            await self._send_service_msg("Messenger", user, "messenger_identify_required")
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        return
                    user_uuid = row[0]

                await db.execute("DELETE FROM mailbox WHERE recipient_uuid = ?", (user_uuid,))
                await db.commit()
                await self._send_service_msg("Messenger", user, "messenger_cleared")

        except Exception as e:
            logger.error(get_log_message("messenger_delete_error", error=e))
            await self._send_service_msg("Messenger", user, "messenger_delete_failed")

    async def _messenger_count(self, user):
        """Count unread messages"""
        if not user.has_mode('r'):
            await self._send_service_msg("Messenger", user, "messenger_identify_required")
            return

        try:
            async with self.db_pool.connection() as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        return
                    user_uuid = row[0]

                async with db.execute("SELECT COUNT(*) FROM mailbox WHERE recipient_uuid = ? AND read = 0",
                                     (user_uuid,)) as cursor:
                    count = (await cursor.fetchone())[0]

                await self._send_service_msg("Messenger", user, "messenger_unread_count", count=count)

        except Exception as e:
            logger.error(get_log_message("messenger_count_error", error=e))

    async def _messenger_push(self, user, message):
        """Push a global message to all online users (ADMIN only)"""
        source = f":Messenger!Messenger@{self.servername}"
        out = f"{source} PRIVMSG * :{SERVER_MESSAGES['messenger_global_prefix'].format(message=message)}"
        count = 0
        for recipient in self.users.values():
            if not recipient.is_virtual:
                await recipient.send(out)
                count += 1
        if self.link_manager and self.link_manager.enabled:
            await self.link_manager.broadcast_to_servers(out)
        await self._send_service_msg("Messenger", user, "messenger_pushed", count=count)
        logger.info(get_log_message("messenger_global_push", nickname=user.nickname, message=message))

    async def _handle_newsflash_msg(self, user, text):
        """Handle messages to NewsFlash service"""
        parts = text.strip().split(None, 1)
        if not parts:
            await self._send_service_msg("NewsFlash", user, "newsflash_commands")
            return

        cmd = parts[0].upper()
        is_staff = user.is_staff()

        if cmd in ["HELP", "COMMANDS"]:
            await self._send_service_help("NewsFlash", user, "newsflash")
            if is_staff:
                await self._send_service_help("NewsFlash", user, "newsflash_staff")
            if user.is_admin():
                await self._send_service_help("NewsFlash", user, "newsflash_admin")
            await self._send_service_help("NewsFlash", user, "newsflash_tip")

        elif cmd in ("LIST", "L"):
            await self._newsflash_list(user)

        elif cmd in ("READ", "R"):
            if len(parts) < 2:
                await self._send_service_msg("NewsFlash", user, "newsflash_read_usage")
                return
            try:
                msg_id = int(parts[1])
                await self._newsflash_read(user, msg_id)
            except ValueError:
                await self._send_service_msg("NewsFlash", user, "newsflash_delete_invalid_id")

        elif cmd in ("ADD", "A") and is_staff:
            if len(parts) < 2:
                await self._send_service_msg("NewsFlash", user, "newsflash_add_usage")
                return
            await self._newsflash_add(user, parts[1])

        elif cmd in ("DELETE", "DEL", "D") and is_staff:
            if len(parts) < 2:
                await self._send_service_msg("NewsFlash", user, "newsflash_delete_usage")
                return
            try:
                msg_id = int(parts[1])
                await self._newsflash_delete(user, msg_id)
            except ValueError:
                await self._send_service_msg("NewsFlash", user, "newsflash_delete_invalid_id")

        elif cmd in ("PUSH", "P") and user.is_admin():
            if len(parts) < 2:
                await self._send_service_msg("NewsFlash", user, "newsflash_push_usage")
                return
            await self._newsflash_push(user, parts[1])

        else:
            if cmd in ["ADD", "A", "DELETE", "DEL", "D", "PUSH", "P"] and not is_staff:
                await self._send_service_msg("NewsFlash", user, "newsflash_staff_required")
            else:
                await self._send_service_msg("NewsFlash", user, "newsflash_unknown_cmd", cmd=cmd)

    async def _newsflash_list(self, user):
        """List active newsflash messages"""
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("""SELECT id, message, priority, created_by, created_at
                                        FROM newsflash WHERE active = 1 ORDER BY priority DESC, id DESC""") as cursor:
                    messages = await cursor.fetchall()

                if not messages:
                    await self._send_service_msg("NewsFlash", user, "newsflash_no_messages")
                    return

                await self._send_service_msg("NewsFlash", user, "newsflash_list_header")
                for msg_id, msg, priority, created_by, created_at in messages:
                    await self._send_service_msg("NewsFlash", user, "newsflash_list_item",
                                                id=msg_id, priority=priority, message=msg, author=created_by)

        except Exception as e:
            logger.error(get_log_message("newsflash_list_error", error=e))

    async def _newsflash_read(self, user, msg_id):
        """Read a specific newsflash message"""
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("""SELECT id, message, priority, created_by, created_at
                                        FROM newsflash WHERE id = ?""",
                                     (msg_id,)) as cursor:
                    row = await cursor.fetchone()

                if not row:
                    await self._send_service_msg("NewsFlash", user, "newsflash_not_found", id=msg_id)
                    return

                mid, msg, priority, created_by, created_at = row
                await self._send_service_msg("NewsFlash", user, "newsflash_read_header",
                                            id=mid, author=created_by, time=time.ctime(created_at))
                await self._send_service_msg("NewsFlash", user, "newsflash_read_body", message=msg)

        except Exception as e:
            logger.error(get_log_message("newsflash_list_error", error=e))

    async def _newsflash_add(self, user, message):
        """Add a newsflash message"""
        try:
            async with self.db_pool.connection() as db:
                await db.execute("""INSERT INTO newsflash (message, created_by, created_at)
                                   VALUES (?, ?, ?)""",
                                (message, user.nickname, int(time.time())))
                await db.commit()
                await self._send_service_msg("NewsFlash", user, "newsflash_added")
                logger.info(get_log_message("newsflash_added", nickname=user.nickname, message=message))

        except Exception as e:
            logger.error(get_log_message("newsflash_add_error", error=e))
            await self._send_service_msg("NewsFlash", user, "newsflash_add_failed")

    async def _newsflash_delete(self, user, msg_id):
        """Delete a newsflash message"""
        try:
            async with self.db_pool.connection() as db:
                await db.execute("DELETE FROM newsflash WHERE id = ?", (msg_id,))
                await db.commit()
                await self._send_service_msg("NewsFlash", user, "newsflash_deleted_msg", msg_id=msg_id)

        except Exception as e:
            logger.error(get_log_message("newsflash_delete_error", error=e))
            await self._send_service_msg("NewsFlash", user, "newsflash_delete_failed")

    async def _newsflash_push(self, user, message):
        """Push an immediate notice to all users (ADMIN only)"""
        source = f":NewsFlash!NewsFlash@{self.servername}"
        out = f"{source} NOTICE * :{SERVER_MESSAGES['newsflash_prefix'].format(message=message)}"
        count = 0
        for recipient in self.users.values():
            if not recipient.is_virtual:
                await recipient.send(out)
                count += 1
        if self.link_manager and self.link_manager.enabled:
            await self.link_manager.broadcast_to_servers(out)
        await self._send_service_msg("NewsFlash", user, "newsflash_pushed", count=count)
        logger.info(get_log_message("newsflash_push", nickname=user.nickname, message=message))

    async def _handle_servicebot_msg(self, user, text, botname):
        """Handle messages to ServiceBot"""
        cmd = text.strip().upper()

        if cmd in ["HELP", "COMMANDS", ""]:
            await self._send_service_help(botname, user, "servicebot")
            if CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False):
                action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')
                await self._send_service_help(botname, user, "servicebot_profanity_enabled", action=action)
            else:
                await self._send_service_help(botname, user, "servicebot_profanity_disabled")
            if CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=False):
                flood_action = CONFIG.get('servicebot', 'malicious_detection', 'flood_action', default='gag')
                caps_action = CONFIG.get('servicebot', 'malicious_detection', 'caps_action', default='warn')
                url_action = CONFIG.get('servicebot', 'malicious_detection', 'url_spam_action', default='warn')
                repeat_action = CONFIG.get('servicebot', 'malicious_detection', 'repeat_action', default='warn')
                await self._send_service_help(botname, user, "servicebot_flood_enabled", action=flood_action)
                await self._send_service_help(botname, user, "servicebot_caps_enabled", action=caps_action)
                await self._send_service_help(botname, user, "servicebot_url_enabled", action=url_action)
                await self._send_service_help(botname, user, "servicebot_repeat_enabled", action=repeat_action)
            else:
                await self._send_service_help(botname, user, "servicebot_malicious_disabled")
            await self._send_service_help(botname, user, "servicebot_help_footer")
            await self._send_service_msg(botname, user, "servicebot_invite_hint", botname=botname)
            await self._send_service_msg(botname, user, "servicebot_max_channels")

        elif cmd == "STATUS":
            await self._send_service_msg(botname, user, "servicebot_status_title", botname=botname)
            bot = self.servicebots.get(botname)
            if bot:
                channels = list(bot.channels)
                max_channels = getattr(bot, 'max_channels', 10)
                await self._send_service_msg(botname, user, "servicebot_active_channels", count=len(channels), max=max_channels)
                if channels:
                    await self._send_service_msg(botname, user, "servicebot_monitoring", channels=", ".join(channels))
                else:
                    await self._send_service_msg(botname, user, "servicebot_not_monitoring")
            if CONFIG.get('servicebot', 'enabled', default=False):
                await self._service_reply(botname, user, "")
                await self._send_service_msg(botname, user, "servicebot_detection_status")
                if CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False):
                    action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')
                    await self._send_service_help(botname, user, "servicebot_profanity_enabled", action=action)
                if CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=False):
                    flood_action = CONFIG.get('servicebot', 'malicious_detection', 'flood_action', default='gag')
                    await self._send_service_help(botname, user, "servicebot_flood_enabled", action=flood_action)
            else:
                await self._service_reply(botname, user, "")
                await self._send_service_msg(botname, user, "servicebot_monitoring_disabled")

        else:
            await self._send_service_msg(botname, user, "servicebot_unknown_cmd", cmd=cmd)

    async def send_newsflash_on_connect(self, user):
        """Send a random newsflash message to a user on connect"""
        if not CONFIG.get('newsflash', 'on_connect', default=False):
            return
        
        try:
            async with self.db_pool.connection() as db:
                async with db.execute("""SELECT message FROM newsflash 
                                        WHERE active = 1 
                                        ORDER BY RANDOM() LIMIT 1""") as cursor:
                    row = await cursor.fetchone()
                    if row:
                        source = f":NewsFlash!NewsFlash@{self.servername}"
                        await user.send(f"{source} NOTICE {user.nickname} :{SERVER_MESSAGES['newsflash_prefix'].format(message=row[0])}")
        except Exception as e:
            logger.debug(get_log_message("newsflash_connect_error", error=e))

    async def newsflash_periodic_broadcast(self):
        """Broadcast a random newsflash message to all users periodically"""
        while True:
            try:
                interval = CONFIG.get('newsflash', 'periodic_interval', default=30) * 60
                await asyncio.sleep(interval)
                
                if not CONFIG.get('newsflash', 'periodic_enabled', default=False):
                    continue
                
                async with self.db_pool.connection() as db:
                    async with db.execute("""SELECT message FROM newsflash 
                                            WHERE active = 1 
                                            ORDER BY RANDOM() LIMIT 1""") as cursor:
                        row = await cursor.fetchone()
                        if row:
                            source = f":NewsFlash!NewsFlash@{self.servername}"
                            out = f"{source} NOTICE * :{SERVER_MESSAGES['newsflash_prefix'].format(message=row[0])}"
                            count = 0
                            for recipient in self.users.values():
                                if not recipient.is_virtual and recipient.registered:
                                    await recipient.send(out)
                                    count += 1
                            if self.link_manager and self.link_manager.enabled:
                                await self.link_manager.broadcast_to_servers(out)
                            if count > 0:
                                logger.info(get_log_message("newsflash_periodic", count=count))
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(get_log_message("newsflash_periodic_error", error=e))


    async def handle_kill(self, staff, params):
        # Rate limit KILL commands
        if not staff.rate_limiter.check('KILL'):
            await staff.send(self.get_reply("830", staff))
            return

        if not staff.is_high_staff():
            await staff.send(self.get_reply("481", staff, message=SERVER_MESSAGES['requires_oper_admin'].format(command="GAG (channel)")))
            return
        if not params:
            await staff.send(self.get_reply("461", staff, command="KILL"))
            return
        target = params[0]
        reason = params[1].lstrip(':') if len(params) > 1 else "Terminated"

        if is_channel(target):
            # KILL #channel or &channel - kick all users and destroy channel
            await self._kill_channel(staff, target, reason)
        elif '*' in target or '!' in target or '@' in target:
            # KILL by pattern (IP or hostmask) - disconnect only, no ban
            await self._kill_pattern(staff, target, reason)
        else:
            # KILL single user (existing behavior)
            await self._kill_user(staff, target, reason)

    async def _kill_user(self, staff, target_nick, reason):
        """Kill a single user by nickname"""
        target = self.get_user(target_nick)
        if not target:
            await staff.send(self.get_reply("401", staff, target=target_nick))
            return
        # Cannot kill services
        if target.is_service():
            await staff.send(self.get_reply("823", staff, target=target_nick))
            return
        # Send KILL message to target
        await target.send(f":{self.system_nick} KILL {target_nick} :{reason}")
        # Send confirmation NOTICE to staff member
        await staff.send(self.get_reply("924", staff, target=target_nick, reason=reason))
        await self.log_staff(staff.nickname, "KILL", target_nick, reason)

        # Propagate KILL to linked servers for network-wide termination
        if self.link_manager and self.link_manager.enabled:
            if not (target.is_remote):
                kill_msg = f":{staff.prefix()} KILL {target_nick} :{reason}"
                await self.link_manager.broadcast_to_servers(kill_msg)

        await self.quit_user(target)

    async def _kill_channel(self, staff, channel_name, reason):
        """Kill a channel - kick all users and destroy it"""
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await staff.send(self.get_reply("403", staff, target=channel_name))
            return
        if chan_name.lower() == "#system":
            await self.send_notice(staff, "kill_cannot_system")
            return
        kill_count = 0
        for nick in list(channel.members.keys()):
            member = channel.members[nick]
            if not member.is_virtual:
                kick_msg = f":{self.system_nick} KICK {chan_name} {nick} :{reason}"
                await channel.broadcast(kick_msg)
                member.channels.discard(chan_name)
                kill_count += 1
        del self.channels[chan_name]
        self.channels_lower.pop(chan_name.lower(), None)
        await staff.send(self.get_reply("925", staff, channel=chan_name, count=kill_count))
        await self.log_staff(staff.nickname, "KILL", channel_name, get_log_message("audit_kill_channel", reason=reason))

    async def _kill_pattern(self, staff, pattern, reason):
        """Kill users matching IP pattern or hostmask"""
        kill_count = 0
        users_to_kill = []

        for user in list(self.users.values()):
            if user.is_virtual:
                continue
            # Check IP pattern (e.g., 192.168.1.*)
            if '!' not in pattern and '@' not in pattern:
                if fnmatch.fnmatch(user.ip or '', pattern):
                    users_to_kill.append(user)
            else:
                # Check hostmask pattern (e.g., *!*@hostname)
                hostmask = user.prefix()
                if fnmatch.fnmatch(hostmask, pattern):
                    users_to_kill.append(user)

        for user in users_to_kill:
            await user.send(f":{self.system_nick} KILL {user.nickname} :{reason}")
            await self.quit_user(user)
            kill_count += 1

        await staff.send(self.get_reply("929", staff, pattern=pattern, count=kill_count))
        await self.log_staff(staff.nickname, "KILL", pattern, get_log_message("audit_kill_pattern", reason=reason, kill_count=kill_count))

    async def handle_kick(self, user, params):
        # Rate limit KICK commands
        if not user.rate_limiter.check('KICK'):
            await user.send(self.get_reply("830", user))
            return

        if len(params) < 2:
            await user.send(self.get_reply("461", user, command="KICK"))
            return
        target_nick = params[1]
        reason = params[2].lstrip(':') if len(params) > 2 else user.nickname
        channel, chan_name = self.get_channel(params[0])
        if not channel:
            await user.send(self.get_reply("403", user, target=params[0]))
            return
        if not (user.nickname in channel.owners or user.nickname in channel.hosts or user.has_mode('a')):
            await user.send(self.get_reply("482", user, target=chan_name))
            return
        if target_nick not in channel.members:
            await user.send(self.get_reply("441", user, target=target_nick, channel=chan_name))
            return
        target = channel.members[target_nick]
        # Cannot kick services unless you're admin/sysop
        if target.is_service() and not user.is_high_staff():
            await user.send(self.get_reply("821", user, target=target_nick))
            return
        # Cannot kick staff members unless you're also staff
        if target.is_staff() and not user.is_staff():
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['cannot_target_staff'].format(action="kick")))
            return
        msg = f":{user.prefix()} KICK {chan_name} {target_nick} :{reason}"
        # Broadcast to LOCAL channel members only (exclude remote users to avoid routing loops)
        for member in channel.members.values():
            if not (member.is_remote):
                await member.send(msg)
        # Log to transcript if +y mode is enabled (before removing member)
        self.log_transcript(channel, "KICK", user, message=reason, target=target)
        channel.members.pop(target_nick, None)
        channel.owners.discard(target_nick)
        channel.hosts.discard(target_nick)
        channel.voices.discard(target_nick)
        channel.gagged.discard(target_nick)
        target.channels.discard(chan_name)
        # Propagate KICK to linked servers (if not a remote user)
        if self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                await self.link_manager.broadcast_to_servers(msg)

        # Fire MEMBER/KICK event for monitoring (use target as the affected user)
        await self.fire_trap("MEMBER", "KICK", target, chan_name)

        if user.is_high_staff():
            await self.log_staff(user.nickname, "KICK", get_log_message("audit_kick_target", target_nick=target_nick, chan_name=chan_name), reason)

    async def handle_mode(self, user, params):
        # Rate limit MODE commands
        if not user.rate_limiter.check('MODE'):
            await user.send(self.get_reply("830", user))
            return

        if not params:
            return
        target = params[0]
        if target == user.nickname:
            if len(params) == 1:
                modes = user.get_mode_str()
                await user.send(self.get_reply("221", user, modes=modes))
            else:
                # User mode setting
                mode_str = params[1]
                adding = True
                for char in mode_str:
                    if char == '+':
                        adding = True
                    elif char == '-':
                        adding = False
                    elif char in 'aogsr':
                        # Cannot set or unset +a/+o/+g/+s/+r (server-controlled)
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mode_cannot_set'].format(mode=char)))
                    elif char == 'x':
                        # +x can only be set (already set via IRCX command), cannot be unset
                        if not adding:
                            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mode_cannot_unset_x']))
                    elif char == 'z':
                        # +z cannot be set or unset manually (staff-controlled via GAG/UNGAG)
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mode_z_staff_controlled']))
                    elif char in ('i', 'b'):
                        # +i (invisible) and +b (bot) can be toggled by user
                        user.set_mode(char, adding)
                        sign = '+' if adding else '-'
                        mode_msg = f":{user.nickname} MODE {user.nickname} :{sign}{char}"
                        await user.send(mode_msg)
                        # Propagate user MODE change to linked servers
                        if self.link_manager and self.link_manager.enabled:
                            if not (user.is_remote):
                                await self.link_manager.broadcast_to_servers(mode_msg)

                        # Fire USER/MODE event for monitoring
                        await self.fire_trap("USER", "MODE", user)

                    else:
                        # Unknown mode
                        await user.send(self.get_reply("501", user, message=SERVER_MESSAGES['mode_unknown_flag']))
        elif is_channel(target):
            channel, chan_name = self.get_channel(target)
            if not channel:
                await user.send(self.get_reply("403", user, target=target))
                return
            if len(params) == 1:
                modes = "".join([k for k, v in channel.modes.items() if v])
                # Add +r if channel is registered
                if channel.registered and 'r' not in modes:
                    modes += 'r'
                # Sort modes for consistent display
                modes = ''.join(sorted(modes))
                mode_params = []
                if channel.modes.get('l') and channel.user_limit:
                    mode_params.append(str(channel.user_limit))
                # Only show key to channel hosts/owners or staff
                can_see_key = (user.nickname in channel.owners or
                              user.nickname in channel.hosts or
                              user.is_high_staff())
                if channel.modes.get('k') and channel.key:
                    if can_see_key:
                        mode_params.append(channel.key)
                    else:
                        mode_params.append("*")  # Hide actual key
                param_str = " " + " ".join(mode_params) if mode_params else ""
                await user.send(self.get_reply("324", user, channel=chan_name, modes=modes, param_str=param_str))
            else:
                mode_str = params[1]
                mode_params = params[2:] if len(params) > 2 else []

                # Ban list query: MODE #channel b (no +/- and no params)
                if mode_str == 'b' and not mode_params:
                    for ban_mask in channel.ban_list:
                        await user.send(self.get_reply("367", user, channel=chan_name, mask=ban_mask))
                    await user.send(self.get_reply("368", user, channel=chan_name))
                    return

                if not (user.nickname in channel.owners or user.nickname in channel.hosts or user.is_high_staff() or user.has_mode('s')):
                    await user.send(self.get_reply("482", user, target=chan_name))
                    return
                await self.apply_channel_modes(user, channel, mode_str, mode_params)

    # =========================================================================
    # Channel Mode Helper Methods
    # =========================================================================

    async def _apply_prefix_mode(self, user, channel, char, adding, target_nick):
        """Apply channel prefix mode (q=owner, o=host, v=voice)."""
        if target_nick not in channel.members:
            return False

        if char == 'q':
            if adding:
                channel.owners.add(target_nick)
            else:
                channel.owners.discard(target_nick)
        elif char == 'o':
            if adding:
                channel.hosts.add(target_nick)
            else:
                channel.hosts.discard(target_nick)
        elif char == 'v':
            if adding:
                channel.voices.add(target_nick)
            else:
                channel.voices.discard(target_nick)

        sign = '+' if adding else '-'
        msg = f":{user.prefix()} MODE {channel.name} {sign}{char} {target_nick}"
        await channel.broadcast(msg)
        return True

    async def _apply_ban_mode(self, user, channel, adding, ban_mask=None):
        """Apply channel ban mode (+b/-b)."""
        if ban_mask is None:
            # List bans
            for mask in channel.ban_list:
                await user.send(self.get_reply("367", user, channel=channel.name, mask=mask))
            await user.send(self.get_reply("368", user, channel=channel.name))
            return True

        if adding:
            # Check if ban would affect any service or staff
            for nick, member in channel.members.items():
                user_mask = f"{nick}!{member.username}@{member.host}"
                matches = fnmatch.fnmatch(user_mask.lower(), ban_mask.lower()) or fnmatch.fnmatch(nick.lower(), ban_mask.lower())
                if matches:
                    if member.is_service():
                        await user.send(self.get_reply("822", user, target=ban_mask))
                        return False
                    if member.is_staff() and not user.is_staff():
                        await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['cannot_target_staff'].format(action="ban")))
                        return False

            if ban_mask not in channel.ban_list:
                channel.ban_list.append(ban_mask)
                msg = f":{user.prefix()} MODE {channel.name} +b {ban_mask}"
                await channel.broadcast(msg)
        else:
            if ban_mask in channel.ban_list:
                channel.ban_list.remove(ban_mask)
                msg = f":{user.prefix()} MODE {channel.name} -b {ban_mask}"
                await channel.broadcast(msg)
        return True

    async def _apply_key_mode(self, user, channel, adding, key=None):
        """Apply channel key mode (+k/-k)."""
        if adding:
            if key is None:
                await user.send(self.get_reply("696", user, target=channel.name, mode="k", message=SERVER_MESSAGES['mode_key_required']))
                return False
            channel.key = key
            channel.modes['k'] = True
            channel.props['MEMBERKEY'] = key
            msg = f":{user.prefix()} MODE {channel.name} +k {key}"
            await channel.broadcast(msg)
            # Sync to clones
            if channel.is_clone_enabled() and channel.clone_children:
                await self.sync_mode_to_clones(channel, 'k', True, key)
        else:
            channel.key = None
            channel.modes['k'] = False
            channel.props.pop('MEMBERKEY', None)
            msg = f":{user.prefix()} MODE {channel.name} -k *"
            await channel.broadcast(msg)
            if channel.is_clone_enabled() and channel.clone_children:
                await self.sync_mode_to_clones(channel, 'k', False)
        return True

    async def _apply_limit_mode(self, user, channel, adding, limit=None):
        """Apply channel limit mode (+l/-l)."""
        if adding:
            if limit is None:
                await user.send(self.get_reply("696", user, target=channel.name, mode="l", message=SERVER_MESSAGES['mode_limit_required']))
                return False
            try:
                limit_val = int(limit)
                if limit_val <= 0:
                    return False
                # Cap at server maximum
                if limit_val > self.max_users_per_channel:
                    limit_val = self.max_users_per_channel
                    await self.send_server_message(user, "mode_limit_exceeds_cap", max=self.max_users_per_channel)
                channel.user_limit = limit_val
                channel.modes['l'] = True
                msg = f":{user.prefix()} MODE {channel.name} +l {limit_val}"
                await channel.broadcast(msg)
                if channel.is_clone_enabled() and channel.clone_children:
                    await self.sync_mode_to_clones(channel, 'l', True, limit_val)
            except ValueError:
                return False
        else:
            channel.user_limit = None
            channel.modes['l'] = False
            msg = f":{user.prefix()} MODE {channel.name} -l"
            await channel.broadcast(msg)
            if channel.is_clone_enabled() and channel.clone_children:
                await self.sync_mode_to_clones(channel, 'l', False)
        return True

    async def _apply_registered_mode(self, user, channel, adding):
        """Apply channel registered mode (+r/-r)."""
        if adding:
            await user.send(self.get_reply("696", user, target=channel.name, mode="r", message=SERVER_MESSAGES['mode_r_cannot_set']))
            return False

        # -r: Only high staff can unregister
        if not user.is_high_staff():
            await user.send(self.get_reply("696", user, target=channel.name, mode="r", message=SERVER_MESSAGES['mode_r_staff_only']))
            return False

        if channel.registered:
            try:
                async with self.db_pool.connection() as db:
                    await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (channel.name,))
                    await db.commit()
                channel.registered = False
                channel.account_uuid = None
                channel.modes['r'] = False
                msg = f":{user.prefix()} MODE {channel.name} -r"
                await channel.broadcast(msg)
                logger.info(get_log_message("mode_unregister_channel", channel=channel.name, nickname=user.nickname))
            except Exception as e:
                logger.error(get_log_message("mode_unregister_error", error=e))
                await user.send(self.get_reply("766", user))
                return False
        else:
            channel.modes['r'] = False
            msg = f":{user.prefix()} MODE {channel.name} -r"
            await channel.broadcast(msg)
        return True

    async def _apply_locked_mode(self, user, channel, adding):
        """Apply channel locked mode (+z/-z). Auto-sets +a and +r."""
        if not (user.is_high_staff() or user.is_service()):
            await user.send(self.get_reply("696", user, target=channel.name, mode="z", message=SERVER_MESSAGES['mode_z_staff_only']))
            return False

        if adding:
            if not channel.registered:
                await user.send(self.get_reply("696", user, target=channel.name, mode="z", message=SERVER_MESSAGES['mode_z_must_register']))
                return False
            channel.modes['z'] = True
            channel.modes['a'] = True
            channel.modes['r'] = True
            msg = f":{user.prefix()} MODE {channel.name} +zar"
            await channel.broadcast(msg)
            logger.info(get_log_message("mode_channel_locked", channel=channel.name, nickname=user.nickname))
        else:
            channel.modes['z'] = False
            channel.modes['a'] = False
            msg = f":{user.prefix()} MODE {channel.name} -za"
            await channel.broadcast(msg)
            logger.info(get_log_message("mode_channel_unlocked", channel=channel.name, nickname=user.nickname))
        return True

    async def _apply_simple_mode(self, user, channel, char, adding):
        """Apply a simple channel mode (no parameters)."""
        if char not in channel.modes:
            return False
        channel.modes[char] = adding
        sign = '+' if adding else '-'
        msg = f":{user.prefix()} MODE {channel.name} {sign}{char}"
        await channel.broadcast(msg)
        # Sync to clones (skip +d and +e)
        if char not in ('d', 'e') and channel.is_clone_enabled() and channel.clone_children:
            await self.sync_mode_to_clones(channel, char, adding)
        return True

    async def apply_channel_modes(self, user, channel, mode_str, mode_params):
        """Apply channel mode changes using helper methods for each mode type."""
        # Enforce MODES limit (max mode changes per command)
        max_modes = CONFIG.get('limits', 'max_modes_per_command', default=6)
        mode_count = sum(1 for c in mode_str if c not in '+-')
        if mode_count > max_modes:
            await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['mode_changes_limit'].format(max=max_modes)))
            return

        adding, param_idx = True, 0
        for char in mode_str:
            if char == '+':
                adding = True
            elif char == '-':
                adding = False
            elif char in 'qov':
                # Prefix modes (owner, host, voice)
                if param_idx < len(mode_params):
                    target_nick = mode_params[param_idx]
                    param_idx += 1
                    await self._apply_prefix_mode(user, channel, char, adding, target_nick)
            elif char == 'b':
                # Ban mode
                if param_idx < len(mode_params):
                    ban_mask = mode_params[param_idx]
                    param_idx += 1
                    await self._apply_ban_mode(user, channel, adding, ban_mask)
                else:
                    await self._apply_ban_mode(user, channel, adding, None)  # List bans
            elif char == 'k':
                # Key mode
                key = mode_params[param_idx] if param_idx < len(mode_params) else None
                if key:
                    param_idx += 1
                await self._apply_key_mode(user, channel, adding, key)
            elif char == 'l':
                # Limit mode
                limit = mode_params[param_idx] if param_idx < len(mode_params) else None
                if limit:
                    param_idx += 1
                await self._apply_limit_mode(user, channel, adding, limit)
            elif char == 'r':
                # Registered mode
                await self._apply_registered_mode(user, channel, adding)
            elif char == 'z':
                # Locked mode
                await self._apply_locked_mode(user, channel, adding)
            elif char in channel.modes:
                # Simple mode (no parameters)
                await self._apply_simple_mode(user, channel, char, adding)

        # Propagate MODE changes to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                mode_args_str = ' '.join(mode_params) if mode_params else ''
                mode_cmd = f":{user.prefix()} MODE {channel.name} {mode_str} {mode_args_str}".strip()
                await self.link_manager.broadcast_to_servers(mode_cmd)

        # Log the mode change to transcript if +y is enabled
        mode_args = ' '.join(mode_params) if mode_params else ''
        mode_msg = f"{mode_str} {mode_args}".strip()
        self.log_transcript(channel, "MODE", user, message=mode_msg)

    async def handle_gag_alias(self, user, params, is_gag):
        """Handle GAG/UNGAG command.

        Syntax:
            GAG nick           - Global gag (sets user mode +z)
            GAG #channel nick  - Channel gag (only in that channel)
            UNGAG nick         - Remove global gag
            UNGAG #channel nick - Remove channel gag

        Requires: Staff (+o/+a/+g) for global gag, channel host/owner for channel gag.
        """
        if len(params) < 1:
            await user.send(self.get_reply("461", user, command="GAG" if is_gag else "UNGAG"))
            return

        # Determine if this is a channel gag or global gag
        if params[0].startswith('#') or params[0].startswith('&'):
            # Channel gag: GAG #channel nick
            if len(params) < 2:
                await user.send(self.get_reply("461", user, command="GAG" if is_gag else "UNGAG"))
                return
            channel_name, target_nick = params[0], params[1]
            channel, chan_name = self.get_channel(channel_name)
            if not channel:
                await user.send(self.get_reply("403", user, target=channel_name))
                return
            # Require channel host/owner or staff
            if not (user.nickname in channel.owners or user.nickname in channel.hosts or
                    user.is_high_staff()):
                await user.send(self.get_reply("482", user, target=chan_name))
                return
            if target_nick not in channel.members:
                await user.send(self.get_reply("441", user, target=target_nick, channel=chan_name))
                return
            # Cannot gag services
            target_member = channel.members[target_nick]
            if target_member.is_service():
                await user.send(self.get_reply("824", user, target=target_nick))
                return
            if is_gag:
                channel.gagged.add(target_nick)
                await user.send(self.get_reply("920", user, target=target_nick, channel=chan_name))
                # Send notification to #System channel (shadow ban - target doesn't know)
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :{SERVER_MESSAGES['gag_channel_notify'].format(nickname=user.nickname, target=target_nick, channel=chan_name)}"
                    self.channels["#System"].broadcast(msg)
            else:
                channel.gagged.discard(target_nick)
                await user.send(self.get_reply("921", user, target=target_nick, channel=chan_name))
                # Send notification to #System channel
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :{SERVER_MESSAGES['ungag_channel_notify'].format(nickname=user.nickname, target=target_nick, channel=chan_name)}"
                    self.channels["#System"].broadcast(msg)
        else:
            # Global gag: GAG nick
            target_nick = params[0]
            # Require staff for global gag
            if not (user.is_staff()):
                await user.send(self.get_reply("481", user, message=SERVER_MESSAGES['requires_staff'].format(command="GAG")))
                return
            target_user = self.get_user(target_nick)
            if not target_user:
                await user.send(self.get_reply("401", user, target=target_nick))
                return
            # Cannot gag services
            if target_user.is_service():
                await user.send(self.get_reply("824", user, target=target_nick))
                return
            if is_gag:
                target_user.set_mode('z', True)
                await user.send(self.get_reply("922", user, target=target_nick))
                # Send notification to #System channel (shadow ban - target doesn't know)
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :{SERVER_MESSAGES['gag_global_notify'].format(nickname=user.nickname, target=target_nick)}"
                    self.channels["#System"].broadcast(msg)
            else:
                target_user.set_mode('z', False)
                await user.send(self.get_reply("923", user, target=target_nick))
                # Send notification to #System channel
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :{SERVER_MESSAGES['ungag_global_notify'].format(nickname=user.nickname, target=target_nick)}"
                    self.channels["#System"].broadcast(msg)

    async def quit_user(self, user, reason=None):
        nick = user.nickname
        # Prevent duplicate QUIT processing if already disconnected
        if user.disconnected:
            return
        user.disconnected = True  # Mark user as disconnected

        # Fire USER/LOGOFF event for monitoring (only for registered users)
        if user.registered:
            await self.fire_trap("USER", "LOGOFF", user)

        # Notify watchers that this user has gone offline
        if user.registered:
            await self.notify_watchers_offline(user)

        # Clean up this user's watch list from server watchers dict
        for watched_nick in user.watch_list:
            if watched_nick in self.watchers:
                self.watchers[watched_nick].discard(user)
                if not self.watchers[watched_nick]:
                    del self.watchers[watched_nick]
        user.watch_list.clear()

        quit_reason = reason or SERVER_MESSAGES['quit_client_exited']
        logout_time = int(time.time())
        session_entry = self._record_session_history(user, logout_time, quit_reason)
        if session_entry:
            await self._record_persistent_session_history(session_entry)

        if nick != "*" and user.registered:
            # Clean up expired WHOWAS entries
            now = logout_time
            expired = []
            for wn, info in self.whowas.items():
                if now - info.get('timestamp', 0) > self.whowas_max_age:
                    expired.append(wn)
                else:
                    break  # OrderedDict is sorted by insertion, so stop at first non-expired
            for wn in expired:
                del self.whowas[wn]

            # Enforce max entries limit (LRU - remove oldest)
            while len(self.whowas) >= self.whowas_max_entries:
                self.whowas.popitem(last=False)

            # Add new entry with timestamp
            self.whowas[nick] = {
                'username': user.username,
                'host': user.host,
                'realname': user.realname,
                'timestamp': now
            }
        for cn in list(user.channels):
            if cn in self.channels:
                c = self.channels[cn]
                if user.registered:
                    # Broadcast QUIT with per-viewer host masking
                    tasks = []
                    for member in c.members.values():
                        if member != user:
                            # Each viewer sees appropriately masked host
                            prefix = user.prefix(viewer=member)
                            msg = f":{prefix} QUIT :{quit_reason}"
                            tasks.append(member.send(msg))
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                c.members.pop(nick, None)
                c.owners.discard(nick)
                c.hosts.discard(nick)
                c.voices.discard(nick)
                c.gagged.discard(nick)
                if user.registered:
                    await self.fire_trap("MEMBER", "QUIT", user, channel_name=cn)
                # Delete dynamic (unregistered) channels when empty
                if len(c.members) == 0 and not c.registered and cn.lower() != "#system":
                    # If this is a clone, remove from parent's clone_children list
                    if c.is_clone() and c.clone_parent:
                        parent, _ = self.get_channel(c.clone_parent)
                        if parent and cn in parent.clone_children:
                            parent.clone_children.remove(cn)
                    del self.channels[cn]
                    self.channels_lower.pop(cn.lower(), None)

        # Propagate QUIT to linked servers (if not a remote user)
        if user.registered and self.link_manager and self.link_manager.enabled:
            if not (user.is_remote):
                quit_msg = f":{user.prefix()} QUIT :{quit_reason}"
                await self.link_manager.broadcast_to_servers(quit_msg)

        if nick in self.users and self.users[nick] == user:
            del self.users[nick]
            self.users_lower.pop(nick.lower(), None)
        if user.writer and not user.is_virtual:
            try:
                user.writer.close()
                await user.writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                # Normal disconnect - client closed connection
                pass
            except Exception as e:
                if self.debug_mode:
                    logger.error(get_log_message("close_error", error=e))

class ServerManager:
    """Manages server lifecycle, signals, and graceful shutdown."""

    def __init__(self):
        self.server = None
        self.tcp_servers = []
        self.ssl_servers = []
        self.shutdown_event = asyncio.Event()
        self.reload_event = asyncio.Event()
        self.ssl_manager = None
        self.link_manager = None

    async def start(self):
        """Start the IRC server with dual-stack (IPv4/IPv6) and SSL/TLS support."""
        global SSL_MANAGER

        self.server = pyIRCXServer()
        await self.server.boot()

        # Initialize SSL manager
        self.ssl_manager = SSLManager()
        SSL_MANAGER = self.ssl_manager
        ssl_context = self.ssl_manager.load_certificates()

        # Initialize server linking if enabled
        if CONFIG.get('linking', 'enabled', default=False):
            self.link_manager = ServerLinkManager(self.server)
            self.server.link_manager = self.link_manager  # Give server reference to link manager
            await self.link_manager.start()
            logger.info(get_log_message("linking_enabled"))

        ports = CONFIG.get('network', 'listen_ports', default=[6667, 7000])
        ssl_ports = CONFIG.get('ssl', 'ports', default=[6697]) if ssl_context else []
        addr_ipv4 = CONFIG.get('network', 'listen_addr', default='0.0.0.0')
        addr_ipv6 = CONFIG.get('network', 'listen_addr_ipv6', default=None)
        enable_ipv6 = CONFIG.get('network', 'enable_ipv6', default=True)

        # Build list of addresses to bind
        addresses = []
        if addr_ipv4:
            addresses.append((addr_ipv4, socket.AF_INET, 'IPv4'))

        # Add IPv6 if enabled and available
        if enable_ipv6:
            if addr_ipv6:
                addresses.append((addr_ipv6, socket.AF_INET6, 'IPv6'))
            elif socket.has_ipv6:
                # Default to :: (all IPv6 interfaces) if IPv6 is available
                addresses.append(('::', socket.AF_INET6, 'IPv6'))

        # Start plain (non-SSL) listeners
        for port in ports:
            for addr, family, family_name in addresses:
                try:
                    # Create socket manually for IPv6 to set IPV6_V6ONLY
                    if family == socket.AF_INET6:
                        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        # Set IPV6_V6ONLY to True so IPv6 socket only accepts IPv6
                        # This allows separate IPv4 socket on same port
                        try:
                            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        except (AttributeError, OSError):
                            pass  # Not available on all platforms
                        sock.bind((addr, port))
                        sock.listen(100)
                        sock.setblocking(False)
                        srv = await asyncio.start_server(
                            self.server.handle_client,
                            sock=sock
                        )
                    else:
                        srv = await asyncio.start_server(
                            self.server.handle_client,
                            addr,
                            port
                        )
                    self.tcp_servers.append(srv)
                    if family == socket.AF_INET6:
                        logger.info(get_log_message("listening_ipv6", addr=addr, port=port, family=family_name))
                    else:
                        logger.info(get_log_message("listening_ipv4", addr=addr, port=port, family=family_name))
                except Exception as e:
                    if family == socket.AF_INET6:
                        logger.warning(get_log_message("bind_failed_ipv6", addr=addr, port=port, family=family_name, error=e))
                    else:
                        logger.error(get_log_message("bind_failed_ipv4", addr=addr, port=port, family=family_name, error=e))

        # Start SSL/TLS listeners
        if ssl_context and ssl_ports:
            for port in ssl_ports:
                for addr, family, family_name in addresses:
                    try:
                        if family == socket.AF_INET6:
                            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            try:
                                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                            except (AttributeError, OSError):
                                pass
                            sock.bind((addr, port))
                            sock.listen(100)
                            sock.setblocking(False)
                            srv = await asyncio.start_server(
                                self.server.handle_client,
                                sock=sock,
                                ssl=ssl_context
                            )
                        else:
                            srv = await asyncio.start_server(
                                self.server.handle_client,
                                addr,
                                port,
                                ssl=ssl_context
                            )
                        self.ssl_servers.append(srv)
                        if family == socket.AF_INET6:
                            logger.info(get_log_message("listening_ipv6_ssl", addr=addr, port=port, family=family_name))
                        else:
                            logger.info(get_log_message("listening_ipv4_ssl", addr=addr, port=port, family=family_name))
                    except Exception as e:
                        if family == socket.AF_INET6:
                            logger.warning(get_log_message("bind_ssl_failed_ipv6", addr=addr, port=port, family=family_name, error=e))
                        else:
                            logger.error(get_log_message("bind_ssl_failed_ipv4", addr=addr, port=port, family=family_name, error=e))

        if not self.tcp_servers and not self.ssl_servers:
            logger.error(get_log_message("no_ports_available"))
            return False

        return True

    async def run(self):
        """Run the server until shutdown is requested."""
        background_tasks = []

        # Add SSL certificate monitoring task if SSL is enabled
        if self.ssl_manager and self.ssl_manager.ssl_context:
            background_tasks.append(asyncio.create_task(self._ssl_monitor_loop()))

        # Add newsflash periodic broadcast task
        background_tasks.append(asyncio.create_task(self.server.newsflash_periodic_broadcast()))

        # Add status dump task for admin interface
        background_tasks.append(asyncio.create_task(self._status_dump_loop()))

        # Add admin command queue check task
        background_tasks.append(asyncio.create_task(self._admin_command_loop()))

        try:
            await self.shutdown_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            for srv in self.tcp_servers + self.ssl_servers:
                srv.close()

            for task in background_tasks:
                task.cancel()

            if background_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*background_tasks, return_exceptions=True),
                        timeout=5.0
                    )
                except asyncio.TimeoutError:
                    logger.debug(get_log_message("shutdown_task_timeout"))

    async def _ssl_monitor_loop(self):
        """Background task to monitor SSL certificates for changes and expiry."""
        reload_interval = CONFIG.get('ssl', 'reload_interval', default=3600)

        while not self.shutdown_event.is_set():
            try:
                # Wait for the configured interval
                await asyncio.sleep(reload_interval)

                if self.ssl_manager:
                    # Check for certificate file changes
                    if self.ssl_manager.check_for_reload():
                        # Certificate was reloaded - update SSL servers
                        # Note: Existing connections keep old cert, new connections use new cert
                        logger.info(get_log_message("ssl_context_updated"))

                    # Check for expiry warnings
                    self.ssl_manager.check_expiry_warnings()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(get_log_message("ssl_monitor_error", error=e))

    async def _status_dump_loop(self):
        """Background task to dump server status for admin interface."""
        dump_interval = 10  # Update every 10 seconds
        # Use absolute path in WorkingDirectory (/opt/pyircx typically)
        status_file = Path(os.getcwd()) / 'pyircx_status.json'

        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(dump_interval)

                if self.server:
                    # Collect runtime statistics
                    status_data = {
                        'timestamp': time.time(),
                        'boot_time': self.server.boot_time,
                        'peak_users': self.server.max_users_seen,
                        'connected_users': [],
                        'active_channels': [],
                        'linked_servers': []
                    }

                    # Get connected users (exclude virtual users)
                    for nick, user in self.server.users.items():
                        if not user.is_virtual:
                            user_data = {
                                'nickname': nick,
                                'username': user.username,
                                'hostname': user.host,
                                'realname': user.realname,
                                'connected_at': user.signon_time,
                                'registered': user.registered,
                                'channels': list(user.channels),
                                'modes': ''.join(user.modes),
                                'away': user.away_msg is not None
                            }
                            status_data['connected_users'].append(user_data)

                    # Get active channels (exclude #System)
                    for chan_name, channel in self.server.channels.items():
                        if chan_name != '#System':
                            # Count only real users
                            real_members = [n for n, u in channel.members.items() if not u.is_virtual]
# Get mode string with +r for registered channels
                            mode_str = ''.join(k for k, v in channel.modes.items() if v)
                            if channel.registered and 'r' not in mode_str:
                                mode_str += 'r'
                            channel_data = {
                                'name': chan_name,
                                'topic': channel.topic,
                                'member_count': len(real_members),
                                'members': real_members[:50],  # Limit to first 50 for brevity
                                'registered': channel.registered,
                                'modes': mode_str,
                                'is_local': channel.is_local
                            }
                            status_data['active_channels'].append(channel_data)

                    # Get linked servers (if linking is enabled)
                    if hasattr(self, 'link_manager') and self.link_manager:
                        for server_name, linked_server in self.link_manager.linked_servers.items():
                            uptime = int(time.time() - linked_server.connected_at)
                            ping_age = int(time.time() - linked_server.last_pong)
                            server_data = {
                                'name': server_name,
                                'description': linked_server.description,
                                'hopcount': linked_server.hopcount,
                                'is_direct': linked_server.is_direct,
                                'user_count': len(linked_server.users),
                                'connected_at': int(linked_server.connected_at),
                                'uptime': uptime,
                                'ping_age': ping_age,
                                'status': 'ok' if ping_age < 60 else 'lagging'
                            }
                            status_data['linked_servers'].append(server_data)

                    # Write status file atomically
                    temp_file = status_file.with_suffix('.tmp')
                    with open(temp_file, 'w') as f:
                        json.dump(status_data, f, indent=2)
                    temp_file.replace(status_file)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(get_log_message("status_dump_error", error=e))

    async def shutdown(self):
        """Graceful shutdown with timeout."""
        logger.info(get_log_message("shutdown_initiated"))

        try:
            # Overall shutdown timeout of 10 seconds
            async with asyncio.timeout(10):
                # Shutdown link manager if active
                if self.link_manager:
                    try:
                        await asyncio.wait_for(self.link_manager.shutdown(), timeout=2.0)
                        logger.info(get_log_message("link_manager_shutdown"))
                    except (Exception, asyncio.TimeoutError) as e:
                        logger.warning(get_log_message("link_manager_shutdown_error", error=e))

                # Stop protocol-level background monitors owned by pyIRCXServer.
                cap_timeout_task = getattr(self.server, 'cap_timeout_task', None) if self.server else None
                if cap_timeout_task and not cap_timeout_task.done():
                    cap_timeout_task.cancel()
                    try:
                        await asyncio.wait_for(cap_timeout_task, timeout=1.0)
                    except asyncio.CancelledError:
                        pass
                    except asyncio.TimeoutError:
                        logger.warning(get_log_message("cap_timeout_monitor_shutdown_timeout"))

                # Stop accepting new clients immediately.
                all_servers = self.tcp_servers + self.ssl_servers
                for srv in all_servers:
                    srv.close()

                # Disconnect clients before waiting on server objects to close.
                if self.server:
                    disconnect_tasks = []
                    for user in list(self.server.users.values()):
                        if not user.is_virtual and user.writer:
                            disconnect_tasks.append(self._disconnect_user(user))

                    if disconnect_tasks:
                        try:
                            await asyncio.wait_for(
                                asyncio.gather(*disconnect_tasks, return_exceptions=True),
                                timeout=3.0
                            )
                        except asyncio.TimeoutError:
                            logger.warning(get_log_message("client_disconnect_timeout"))

                for srv in all_servers:
                    try:
                        await asyncio.wait_for(srv.wait_closed(), timeout=2.0)
                    except asyncio.TimeoutError:
                        logger.debug(get_log_message("server_close_timeout"))

                # Close database pool
                if self.server and getattr(self.server, 'db_pool', None):
                    try:
                        await asyncio.wait_for(self.server.db_pool.close(), timeout=2.0)
                        logger.info(get_log_message("db_pool_closed"))
                    except (Exception, asyncio.TimeoutError) as e:
                        logger.warning(get_log_message("db_pool_close_error", error=e))

        except asyncio.TimeoutError:
            logger.warning(get_log_message("shutdown_timeout"))
        except Exception as e:
            logger.error(get_log_message("shutdown_error", error=e))

        logger.info(get_log_message("shutdown_complete"))

    async def _disconnect_user(self, user):
        """Disconnect a single user with timeout."""
        try:
            await asyncio.wait_for(
                user.send(f":{self.server.servername} NOTICE * :{SERVER_MESSAGES['notice_server_shutdown']}"),
                timeout=0.5
            )
        except Exception:
            # Ignore errors during shutdown notification (connection may already be closed)
            pass
        try:
            user.writer.close()
            await asyncio.wait_for(user.writer.wait_closed(), timeout=0.5)
        except Exception:
            # Ignore errors during connection close (best effort cleanup)
            pass

    def handle_signal(self, sig):
        """Handle Unix signals."""
        if sig == signal.SIGTERM or sig == signal.SIGINT:
            logger.info(get_log_message("signal_shutdown", signal=sig.name))
            self.shutdown_event.set()
        elif sig == signal.SIGHUP:
            logger.info(get_log_message("signal_sighup_reload"))
            self.reload_config()

    async def _admin_command_loop(self):
        """Periodically check for admin commands from Web Admin interface."""
        while True:
            await asyncio.sleep(2)  # Check every 2 seconds
            await self.check_admin_commands()

    async def check_admin_commands(self):
        """Check for admin commands from Web Admin interface via command queue file."""
        cmd_file = '/opt/pyircx/admin_commands.queue'
        try:
            if os.path.exists(cmd_file):
                with open(cmd_file, 'r') as f:
                    commands = f.readlines()
                
                # Clear the file immediately
                with open(cmd_file, 'w') as f:
                    f.write('')
                
                # Process each command
                for line in commands:
                    line = line.strip()
                    if not line:
                        continue
                    
                    parts = line.split(':', 1)
                    if len(parts) != 2:
                        continue
                    
                    cmd, arg = parts
                    
                    if cmd == 'KILL_CHANNEL':
                        channel_name = arg.strip()
                        # Use built-in case-insensitive channel lookup
                        channel, actual_channel_name = self.server.get_channel(channel_name)

                        if channel:
                            # Kick all users and destroy channel
                            members_to_kick = list(channel.members.values())
                            for member in members_to_kick:
                                if not member.is_virtual:
                                    # Send PART to user and remove from channel
                                    await member.send(f":{member.prefix()} PART {actual_channel_name} :{SERVER_MESSAGES['part_channel_reconfig']}")
                                    # Remove channel from user's channel list
                                    if actual_channel_name in member.channels:
                                        member.channels.remove(actual_channel_name)
                            # Remove channel from server memory
                            del self.server.channels[actual_channel_name]
                            logger.info(get_log_message("admin_killed_channel", channel=actual_channel_name))

                    elif cmd == 'KILL_USER':
                        # Format: KILL_USER:nickname:reason
                        parts = arg.split(':', 1)
                        if len(parts) >= 1:
                            nickname = parts[0].strip()
                            reason = parts[1] if len(parts) > 1 else SERVER_MESSAGES['kill_default_reason']

                            user = self.server.users.get(nickname)
                            if user and not user.is_virtual:
                                # Send KILL message to user
                                await user.send(f":{self.server.system_nick} KILL {nickname} :{reason}")
                                logger.info(get_log_message("admin_killed_user", nickname=nickname, reason=reason))
                                # Disconnect the user
                                await self.server.quit_user(user, reason=SERVER_MESSAGES['quit_reason_killed'].format(reason=reason))

                    elif cmd == 'BAN_USER':
                        # Format: BAN_USER:nickname:duration:reason
                        parts = arg.split(':', 2)
                        if len(parts) >= 1:
                            nickname = parts[0].strip()
                            duration = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3600
                            reason = parts[2] if len(parts) > 2 else SERVER_MESSAGES['ban_default_reason']

                            user = self.server.users.get(nickname)
                            if user and not user.is_virtual:
                                ip = user.ip
                                # Add server-level IP ban
                                expires_at = time.time() + duration if duration > 0 else 0
                                self.server.server_bans[ip] = (expires_at, reason, "WebAdmin")

                                # Send KILL message to user
                                await user.send(f":{self.server.system_nick} KILL {nickname} :{SERVER_MESSAGES['kill_banned'].format(reason=reason)}")
                                logger.info(get_log_message("admin_banned_user", nickname=nickname, ip=ip, duration=duration, reason=reason))
                                # Disconnect the user
                                await self.server.quit_user(user, reason=SERVER_MESSAGES['quit_reason_banned'].format(reason=reason))

                    elif cmd == 'LOCK_CHANNEL':
                        # Format: LOCK_CHANNEL:channel:owner
                        parts = arg.split(':', 1)
                        if len(parts) >= 1:
                            channel_name = parts[0].strip()
                            owner = parts[1].strip() if len(parts) > 1 else "System"

                            # First, register the channel in the database
                            try:
                                db = self.server.db_pool.get_connection()
                                cursor = db.cursor()

                                # Check if channel already registered
                                cursor.execute("SELECT channel_name FROM registered_channels WHERE channel_name = ?", (channel_name,))
                                existing = cursor.fetchone()

                                if not existing:
                                    # Register the channel
                                    import uuid
                                    account_uuid = str(uuid.uuid4())
                                    cursor.execute("""
                                        INSERT INTO registered_channels
                                        (channel_name, owner, account_uuid, registered_at, modes)
                                        VALUES (?, ?, ?, ?, ?)
                                    """, (channel_name, owner, account_uuid, int(time.time()), "ra"))
                                    db.commit()
                                    logger.info(get_log_message("admin_registered_channel", channel=channel_name, owner=owner))
                                else:
                                    # Update existing channel to set +ra modes
                                    cursor.execute("""
                                        UPDATE registered_channels
                                        SET modes = 'ra', owner = ?
                                        WHERE channel_name = ?
                                    """, (owner, channel_name))
                                    db.commit()
                                    logger.info(get_log_message("admin_updated_channel", channel=channel_name, owner=owner))

                                self.server.db_pool.return_connection(db)

                                # Kill the channel to force reload with new settings
                                channel, actual_channel_name = self.server.get_channel(channel_name)
                                if channel:
                                    members_to_kick = list(channel.members.values())
                                    for member in members_to_kick:
                                        if not member.is_virtual:
                                            await member.send(f":{member.prefix()} PART {actual_channel_name} :{SERVER_MESSAGES['part_channel_locked']}")
                                            if actual_channel_name in member.channels:
                                                member.channels.remove(actual_channel_name)
                                    del self.server.channels[actual_channel_name]
                                    logger.info(get_log_message("admin_locked_channel", channel=actual_channel_name, owner=owner))

                            except Exception as e:
                                logger.error(get_log_message("admin_lock_channel_error", channel=channel_name, error=e))

                    elif cmd == 'SET_CHANNEL_MODE':
                        # Format: SET_CHANNEL_MODE:channel:mode_string
                        parts = arg.split(':', 1)
                        if len(parts) >= 2:
                            channel_name = parts[0].strip()
                            mode_string = parts[1].strip()

                            # Get the System user to send the MODE command
                            system_user = self.server.users.get(self.server.system_nick)

                            if system_user:
                                # Apply the mode using the MODE handler
                                await self.server.handle_mode(system_user, [channel_name, mode_string])
                                logger.info(get_log_message("admin_set_mode", mode=mode_string, channel=channel_name))
                            else:
                                logger.error(get_log_message("admin_system_user_missing", command="SET_CHANNEL_MODE"))


                    elif cmd == 'SET_CHANNEL_TOPIC':
                        # Format: SET_CHANNEL_TOPIC:channel:topic
                        parts = arg.split(':', 1)
                        if len(parts) >= 2:
                            channel_name = parts[0].strip()
                            topic = parts[1] if len(parts) > 1 else ''

                            # Get the System user to send the TOPIC command
                            system_user = self.server.users.get(self.server.system_nick)

                            if system_user:
                                # Apply the topic using the TOPIC handler
                                await self.server.handle_topic(system_user, [channel_name, topic])
                                logger.info(get_log_message("admin_set_topic", channel=channel_name))
                            else:
                                logger.error(get_log_message("admin_system_user_missing", command="SET_CHANNEL_TOPIC"))
        except Exception as e:
            logger.error(get_log_message("admin_command_error", error=e))

    def reload_config(self):
        """Reload configuration file and SSL certificates."""
        try:
            CONFIG.load()
            logger.info(get_log_message("config_reloaded"))
        except Exception as e:
            logger.error(get_log_message("config_reload_error", error=e))

        # Reload SSL certificates if enabled
        if self.ssl_manager:
            try:
                self.ssl_manager.force_reload()
            except Exception as e:
                logger.error(get_log_message("ssl_reload_error", error=e))


async def main(args):
    """Main entry point."""
    global logger

    # Reconfigure logging based on arguments
    logger = setup_logging(
        systemd_mode=args.systemd,
        log_file=args.log_file,
        log_level=args.log_level
    )

    logger.info(get_log_message("server_header"))
    logger.info(get_log_message("server_starting", pid=os.getpid()))
    logger.info(get_log_message("server_mode", mode='systemd' if args.systemd else 'standalone'))
    logger.info(get_log_message("server_header"))

    manager = ServerManager()

    # Set up signal handlers (Unix only)
    if hasattr(signal, 'SIGTERM'):
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: manager.handle_signal(s))
        if hasattr(signal, 'SIGHUP'):
            loop.add_signal_handler(signal.SIGHUP, lambda: manager.handle_signal(signal.SIGHUP))

    # Start server
    if not await manager.start():
        return 1

    # Run until shutdown
    try:
        await manager.run()
    finally:
        await manager.shutdown()

    return 0


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='pyIRCX - Python IRC/IRCX Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      Run in standalone mode
  %(prog)s --systemd            Run under systemd (journald logging)
  %(prog)s --log-level DEBUG    Enable debug logging
  %(prog)s --config /etc/pyircx/pyircx_config.json  Use custom config
        """
    )
    parser.add_argument(
        '--systemd',
        action='store_true',
        help='Run in systemd mode (log to stdout for journald)'
    )
    parser.add_argument(
        '--config', '-c',
        default='pyircx_config.json',
        dest='config_file',
        help='Path to configuration file (default: pyircx_config.json)'
    )
    parser.add_argument(
        '--log-file',
        default='pyircx.log',
        help='Path to log file (default: pyircx.log, ignored with --systemd)'
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level (default: INFO)'
    )
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'{__version_label__} {__version__}'
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    # Load config from specified file
    if args.config_file != 'pyircx_config.json':
        CONFIG.config_file = args.config_file
        CONFIG.load()

    try:
        exit_code = asyncio.run(main(args))
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(get_log_message("server_fatal", error=e))
        traceback.print_exc()
        sys.exit(1)
