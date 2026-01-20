#!/usr/bin/env python3
"""
pyIRCX - Python IRCX Server

An async IRC/IRCX server implementation with database-backed authentication,
channel persistence, flood protection, and staff management features.
"""

# Version info - updated with each release
__version__ = "2.0.0"
__version_label__ = "pyIRCX"
__created__ = "Sun Jan 18 08:04:14 AM EST 2026"

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
_GENERIC_HOST_PATTERNS = [
    re.compile(r'\d+[-\.]\d+[-\.]\d+[-\.]\d+'),  # IP in hostname
    re.compile(r'^(dsl|cable|dial|dynamic|dhcp|pool|client|user|host|node)'),
    re.compile(r'\.(dsl|cable|dynamic|dhcp)\.'),
    re.compile(r'(comcast|verizon|charter|cox|att|centurylink|frontier).*\d'),
]
import signal
import argparse
import os
import ssl
from pathlib import Path
from collections import defaultdict, deque, OrderedDict
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
# CONFIGURATION CLASS
# ==============================================================================


class ServerConfig:
    def __init__(self, config_file="pyircx_config.json"):
        self.config_file = config_file
        self.data = {}
        self.load()

    def _deep_copy(self, d):
        if isinstance(d, dict):
            return {k: self._deep_copy(v) for k, v in d.items()}
        return d

    def load(self):
        if Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.data = json.load(f)
                logger.info(f"Loaded config from {self.config_file}")
            except Exception as e:
                logger.error(f"Config error: {e}")
                raise
        else:
            logger.error(f"Config file not found: {self.config_file}")
            raise FileNotFoundError(f"Configuration file '{self.config_file}' is required but not found. Please run the installation script or create the config file.")

    def save(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info("Config saved")
        except Exception as e:
            logger.error(f"Save error: {e}")


    def get(self, *path, default=None):
        value = self.data
        for key in path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, *path, value):
        """Set a configuration value by path. Returns True on success."""
        if not path:
            return False
        current = self.data
        for key in path[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
        return True

    def get_section(self, section):
        """Get all keys in a section."""
        return self.data.get(section, {})

    def get_all_sections(self):
        """Get list of all section names."""
        return list(self.data.keys())


CONFIG = ServerConfig()
linking.CONFIG = CONFIG  # Share CONFIG with linking module

# ==============================================================================
# VALIDATION FUNCTIONS
# ==============================================================================

FORBIDDEN_CHARS = set('.+=#!@%&^$~:')


def validate_nickname(nick: str, check_reserved=True) -> tuple:
    """
    Validate nickname format. Returns (valid, error_message).
    Called in handle_nick BEFORE assignment - blocks sign-on if invalid.
    """
    max_len = CONFIG.get('limits', 'max_nick_length', default=30)

    if not nick or len(nick) > max_len:
        return False, "Erroneous nickname"
    if nick[0].isdigit():
        return False, "Erroneous nickname"
    if any(c in FORBIDDEN_CHARS for c in nick):
        return False, "Erroneous nickname"
    if _looks_like_ip_or_host(nick):
        return False, "Erroneous nickname"
    # Check reserved service names (can be disabled for internal use)
    if check_reserved and is_reserved_service(nick):
        return False, "Nickname is reserved for services"
    return True, ""


def validate_username(username: str) -> tuple:
    """
    Validate username format. Returns (valid, error_message).
    Called in handle_user BEFORE assignment - blocks sign-on if invalid.
    """
    max_len = CONFIG.get('limits', 'max_user_length', default=30)

    if not username or len(username) > max_len:
        return False, "Invalid username"
    if any(c in FORBIDDEN_CHARS for c in username):
        return False, "Invalid username"
    if _looks_like_ip_or_host(username):
        return False, "Invalid username"
    return True, ""


def _looks_like_ip_or_host(s: str) -> bool:
    """Check if string looks like IP address or hostname (IPv4 or IPv6)"""
    # Also check using ipaddress module for robust IPv6 detection
    if ':' in s:
        try:
            import ipaddress
            ipaddress.ip_address(s)
            return True
        except ValueError:
            pass
    return bool(_IPV4_PATTERN.match(s) or _IPV6_PATTERN.match(s) or _HOSTNAME_PATTERN.match(s))


# Reserved service names - these are virtual aliases pointing to System
RESERVED_SERVICES = {
    'operserv', 'helpserv', 'infoserv', 'nickserv', 'chanserv', 'memoserv',
    'botserv', 'hostserv', 'statserv', 'global', 'alis', 'services',
    'system', 'registrar', 'messenger', 'newsflash'
}

# Channel name forbidden characters (similar to nicknames but allows # and &)
CHANNEL_FORBIDDEN_CHARS = set('+=#!@%^$~, ')  # Note: & removed to allow local channels
CHANNEL_PREFIXES = ('#', '&')  # # = global, & = local


def is_channel(name: str) -> bool:
    """Check if a name is a channel (starts with # or &)"""
    return bool(name) and name[0] in CHANNEL_PREFIXES


def is_local_channel(name: str) -> bool:
    """Check if a channel is local (starts with &)"""
    return bool(name) and name.startswith('&')


def validate_channel_name(name: str) -> tuple:
    """
    Validate channel name format. Returns (valid, error_message).
    Called in handle_join BEFORE creating channel.

    Channel types:
    - # (global): Network-wide channels, persisted across restarts
    - & (local): Server-local channels, not persisted
    """
    max_len = CONFIG.get('limits', 'max_channel_length', default=50)

    if not name:
        return False, "No channel name specified"
    if not is_channel(name):
        return False, "Channel name must start with # or &"
    if len(name) > max_len:
        return False, f"Channel name too long (max {max_len})"

    # Check the part after prefix
    channel_part = name[1:]
    if not channel_part:
        return False, "Channel name cannot be just a prefix"
    if channel_part[0].isdigit():
        return False, "Channel name cannot start with a digit"
    # Check for forbidden chars (excluding the prefix)
    for c in channel_part:
        if c in CHANNEL_FORBIDDEN_CHARS or ord(c) < 32:
            return False, "Channel name contains invalid characters"
    if _looks_like_ip_or_host(channel_part):
        return False, "Channel name cannot look like IP/hostname"

    return True, ""


def is_reserved_service(name: str) -> bool:
    """Check if a nickname is a reserved service name"""
    return name.lower() in RESERVED_SERVICES


def mask_host(host_or_ip: str, viewer_is_staff: bool) -> str:
    """
    Mask host/IP for privacy. Staff see real host, non-staff see masked.

    IPv4: 192.168.100.45 → 192.168.100.XXX (mask last octet)
    IPv6: 2001:db8:85a3:1234:5678:90ab:cdef:1234 → 2001:db8:85a3:1234:XXXX:XXXX:XXXX:XXXX
    Hostname: user-pc.example.com → xxxxxxx.example.com (mask first component)
    """
    if viewer_is_staff:
        return host_or_ip

    # IPv4: mask last octet
    if _IPV4_PATTERN.match(host_or_ip):
        parts = host_or_ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.XXX"

    # IPv6: mask last 4 segments (interface identifier)
    if ':' in host_or_ip:
        try:
            import ipaddress
            ip = ipaddress.ip_address(host_or_ip)
            if isinstance(ip, ipaddress.IPv6Address):
                parts = host_or_ip.split(':')
                # Handle compressed notation (::)
                if '::' in host_or_ip:
                    # Expand it first for simpler handling
                    expanded = ip.exploded
                    parts = expanded.split(':')
                # Keep first 4 segments (network), mask last 4 (interface ID)
                if len(parts) >= 8:
                    return ':'.join(parts[:4]) + ':XXXX:XXXX:XXXX:XXXX'
                elif len(parts) >= 4:
                    return ':'.join(parts[:4]) + ':XXXX:XXXX:XXXX:XXXX'
                else:
                    # Short address, mask what we can
                    return ':'.join(parts[:max(1, len(parts)//2)]) + '::XXXX'
        except (ValueError, ImportError):
            pass

    # Hostname: mask first component with equal number of X's
    if '.' in host_or_ip:
        parts = host_or_ip.split('.')
        first_component = parts[0]
        masked_component = 'x' * len(first_component)
        return masked_component + '.' + '.'.join(parts[1:])

    # Single word hostname or unknown format - mask completely
    return 'x' * len(host_or_ip) if host_or_ip else 'xxxx'


# ==============================================================================
# SECURITY CLASSES
# ==============================================================================


class FloodProtection:
    def __init__(self, max_messages=5, window=2.0):
        self.max_messages = max_messages
        self.window = window
        self.messages = deque()

    def check(self):
        now = time.time()
        while self.messages and self.messages[0] < now - self.window:
            self.messages.popleft()
        if len(self.messages) >= self.max_messages:
            return False
        self.messages.append(now)
        return True


class ConnectionThrottle:
    def __init__(self, max_connections=3, window=10.0):
        self.max_connections = max_connections
        self.window = window
        self.connections = defaultdict(deque)

    def check(self, ip):
        now = time.time()
        while self.connections[ip] and self.connections[ip][0] < now - self.window:
            self.connections[ip].popleft()
        if len(self.connections[ip]) >= self.max_connections:
            return False
        self.connections[ip].append(now)
        return True


class RateLimiter:
    DEFAULT_COOLDOWNS = {
        'PRIVMSG': 0.5,
        'NOTICE': 0.5,
        'WHISPER': 5.0,
        'WHO': 2.0,
        'WHOIS': 1.0,
        'WHOWAS': 2.0,
        'LIST': 5.0,
        'LISTX': 5.0,
        'NAMES': 1.0,
        'MODE': 0.5,
        'PROP': 1.0,
        'INVITE': 2.0,
        'KICK': 1.0,
        'ACCESS': 2.0,
        'KNOCK': 5.0,
        'TOPIC': 1.0,
        'AUTHENTICATE': 2.0,  # Rate limit SASL auth attempts
        'BROADCAST': 6.0,     # Wildcard broadcasts
        'EVENT': 1.0,         # Staff monitoring
        'TRANSCRIPT': 2.0,    # Log access
        'STATS': 2.0,         # Server statistics
        'WATCH': 1.0,         # Watch list
        'SILENCE': 1.0,       # Silence list
        'KILL': 2.0,          # Administrative kill
    }

    # Relaxed limits for staff (ADMIN/SYSOP/GUIDE) - minimal delays for efficiency
    # Staff need to move quickly for monitoring, investigations, and rapid response
    STAFF_COOLDOWNS = {
        'PRIVMSG': 0.05,     # 10x faster (monitoring, EVENTs)
        'NOTICE': 0.05,      # 10x faster
        'WHISPER': 0.5,      # 10x faster
        'WHO': 0.1,          # 20x faster (IP searches, monitoring)
        'WHOIS': 0.05,       # 20x faster (investigations)
        'WHOWAS': 0.1,       # 20x faster (investigations)
        'LIST': 0.25,        # 20x faster
        'LISTX': 0.25,       # 20x faster
        'NAMES': 0.05,       # 20x faster
        'MODE': 0.05,        # 10x faster
        'PROP': 0.1,         # 10x faster
        'INVITE': 0.1,       # 20x faster
        'KICK': 0.05,        # 20x faster (rapid moderation)
        'ACCESS': 0.1,       # 20x faster
        'KNOCK': 0.25,       # 20x faster
        'TOPIC': 0.05,       # 10x faster
        'AUTHENTICATE': 2.0, # Keep auth protection
        'BROADCAST': 0.5,    # 12x faster
        'EVENT': 0.1,        # 10x faster (monitoring tool)
        'TRANSCRIPT': 0.1,   # 20x faster (log access)
        'STATS': 0.1,        # 20x faster (investigations)
        'WATCH': 0.05,       # 20x faster
        'SILENCE': 0.05,     # 20x faster
        'KILL': 0.1,         # 20x faster (rapid response)
    }

    def __init__(self, cooldowns=None):
        self.cooldowns = cooldowns or self.DEFAULT_COOLDOWNS
        self.last_used = {}

    def check(self, command):
        if command not in self.cooldowns:
            return True
        now = time.time()
        cooldown = self.cooldowns[command]
        last_time = self.last_used.get(command, 0)
        if now - last_time < cooldown:
            return False
        self.last_used[command] = now
        return True


class FailedAuthTracker:
    """Track failed authentication attempts per IP and username for lockout"""

    def __init__(self, max_attempts=5, lockout_duration=300, window=600):
        self.max_attempts = max_attempts  # Max failures before lockout
        self.lockout_duration = lockout_duration  # Lockout time in seconds
        self.window = window  # Time window to track failures
        self.ip_failures = defaultdict(deque)  # {ip: deque of timestamps}
        self.ip_lockouts = {}  # {ip: lockout_until_timestamp}
        self.username_failures = defaultdict(deque)  # {username: deque of timestamps}
        self.username_lockouts = {}  # {username: lockout_until_timestamp}

    def record_failure(self, ip, username=None):
        """Record a failed auth attempt for both IP and username"""
        now = time.time()

        # Track by IP
        self._cleanup_ip(ip, now)
        self.ip_failures[ip].append(now)
        if len(self.ip_failures[ip]) >= self.max_attempts:
            self.ip_lockouts[ip] = now + self.lockout_duration
            self.ip_failures[ip].clear()
            logger.warning(f"Auth lockout triggered for IP {ip} ({self.lockout_duration}s)")

        # Track by username if provided
        if username:
            self._cleanup_username(username, now)
            self.username_failures[username].append(now)
            if len(self.username_failures[username]) >= self.max_attempts:
                self.username_lockouts[username] = now + self.lockout_duration
                self.username_failures[username].clear()
                logger.warning(f"Auth lockout triggered for username {username} ({self.lockout_duration}s)")

    def record_success(self, ip, username=None):
        """Clear failures on successful auth"""
        if ip in self.ip_failures:
            del self.ip_failures[ip]
        if ip in self.ip_lockouts:
            del self.ip_lockouts[ip]
        if username:
            if username in self.username_failures:
                del self.username_failures[username]
            if username in self.username_lockouts:
                del self.username_lockouts[username]

    def is_locked_out(self, ip, username=None):
        """Check if IP or username is currently locked out"""
        now = time.time()

        # Check IP lockout
        if ip in self.ip_lockouts:
            if now < self.ip_lockouts[ip]:
                return True
            else:
                del self.ip_lockouts[ip]

        # Check username lockout
        if username and username in self.username_lockouts:
            if now < self.username_lockouts[username]:
                return True
            else:
                del self.username_lockouts[username]

        return False

    def get_lockout_remaining(self, ip, username=None):
        """Get remaining lockout time in seconds (returns max of IP or username)"""
        remaining_ip = 0
        remaining_username = 0

        if ip in self.ip_lockouts:
            remaining_ip = max(0, int(self.ip_lockouts[ip] - time.time()))

        if username and username in self.username_lockouts:
            remaining_username = max(0, int(self.username_lockouts[username] - time.time()))

        return max(remaining_ip, remaining_username)

    def _cleanup_ip(self, ip, now):
        """Remove old IP entries outside the window"""
        while self.ip_failures[ip] and self.ip_failures[ip][0] < now - self.window:
            self.ip_failures[ip].popleft()

    def _cleanup_username(self, username, now):
        """Remove old username entries outside the window"""
        while self.username_failures[username] and self.username_failures[username][0] < now - self.window:
            self.username_failures[username].popleft()


class DatabasePool:
    """Simple async SQLite connection pool"""

    def __init__(self, db_path, pool_size=5):
        self.db_path = db_path
        self.pool_size = pool_size
        self._pool = asyncio.Queue(maxsize=pool_size)
        self._initialized = False
        self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize the connection pool"""
        async with self._lock:
            if self._initialized:
                return
            for _ in range(self.pool_size):
                conn = await aiosqlite.connect(self.db_path)
                await self._pool.put(conn)
            self._initialized = True
            logger.info(f"Database pool initialized with {self.pool_size} connections")

    async def acquire(self):
        """Get a connection from the pool with queue monitoring"""
        if not self._initialized:
            await self.initialize()
        # Log warning if pool is saturated
        if self._pool.qsize() == 0:
            logger.warning(f"Database pool exhausted ({self.pool_size} connections in use). Consider increasing pool_size.")
        return await self._pool.get()

    async def release(self, conn):
        """Return a connection to the pool"""
        await self._pool.put(conn)

    async def close(self):
        """Close all connections in the pool"""
        async with self._lock:
            while not self._pool.empty():
                conn = await self._pool.get()
                await conn.close()
            self._initialized = False

    async def execute(self, query, params=None):
        """Execute a query and return results"""
        conn = await self.acquire()
        try:
            async with conn.execute(query, params or ()) as cursor:
                return await cursor.fetchall()
        finally:
            await self.release(conn)

    async def execute_one(self, query, params=None):
        """Execute a query and return first result"""
        conn = await self.acquire()
        try:
            async with conn.execute(query, params or ()) as cursor:
                return await cursor.fetchone()
        finally:
            await self.release(conn)

    async def execute_write(self, query, params=None):
        """Execute a write query with commit"""
        conn = await self.acquire()
        try:
            await conn.execute(query, params or ())
            await conn.commit()
        finally:
            await self.release(conn)


async def check_password_async(password: str, password_hash: str) -> bool:
    """Non-blocking bcrypt password check using executor"""
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(
            None,
            bcrypt.checkpw,
            password.encode(),
            password_hash.encode()
        )
    except Exception:
        return False


async def hash_password_async(password: str) -> str:
    """Non-blocking bcrypt password hashing using executor"""
    loop = asyncio.get_event_loop()
    salt = await loop.run_in_executor(None, bcrypt.gensalt)
    hashed = await loop.run_in_executor(
        None,
        bcrypt.hashpw,
        password.encode(),
        salt
    )
    return hashed.decode()


# ==============================================================================
# USER CLASS
# ==============================================================================


class User:
    def __init__(self, reader, writer, is_virtual=False):
        self.reader = reader
        self.writer = writer
        self.nickname = "*"
        self.username = "unknown"
        self.realname = "unknown"
        self.host = "CHAT"
        self.ip = "127.0.0.1"
        self.port = 0

        if not is_virtual and writer:
            peername = writer.get_extra_info('peername')
            if peername:
                self.ip, self.port = peername[0], peername[1]
            # Detect SSL/TLS connection
            self.using_ssl = writer.get_extra_info('ssl_object') is not None
        else:
            self.using_ssl = False

        self.is_virtual = is_virtual
        # User modes: a=ADMIN, g=GUIDE, i=invisible, o=SYSOP, r=registered, s=service, x=IRCX, z=gagged
        self.modes = {m: False for m in CONFIG.get(
            'modes', 'user', default='agiorsxz')}
        self.registered = False
        self.authenticated = False
        self.is_ircx = False
        self.cap_negotiating = False  # True during CAP negotiation
        self.cap_start_time = None  # When CAP negotiation started (for timeout)
        self.enabled_caps = set()  # Enabled IRCv3 capabilities
        self.sasl_mechanism = None  # Current SASL mechanism being used
        self.sasl_buffer = ""  # Buffer for multi-chunk SASL data
        self.sasl_authenticated = False  # True if SASL auth succeeded
        self.sasl_account = None  # Account name from SASL auth
        self.away_msg = None
        self.provided_pass = None
        self.channels = set()
        self.traps = []
        self.invited_to = set()
        self.signon_time = int(time.time())
        self.last_activity = int(time.time())
        self.staff_level = "USER"
        self.last_nick_change = 0  # Timestamp of last nick change
        self.pending_mfa = None  # UUID of nick awaiting MFA verification
        self.pending_staff_auth = None  # Dict with username, level, timestamp for AUTH MFA
        self.watch_list = set()  # Nicknames this user is watching
        self.silence_list = set()  # Hostmask patterns to ignore
        self.disconnected = False  # Flag set when user is being disconnected

        # DNSBL and connection security
        self.dnsbl_listed = []  # List of DNSBLs this IP is on (if any)
        self.connection_score = 0  # Risk score for this connection
        self.connection_factors = {}  # Factors contributing to score
        self.webirc_gateway = None  # Name of WEBIRC gateway if used

        # Enhanced: Flood protection and rate limiting
        self.flood_protection = FloodProtection(
            max_messages=CONFIG.get('security', 'flood_messages', default=5),
            window=CONFIG.get('security', 'flood_window', default=2.0)
        )
        self.rate_limiter = RateLimiter()

    def set_mode(self, m, state):
        self.modes[m] = state

    def has_mode(self, m):
        return self.modes.get(m, False)

    def get_mode_str(self):
        return "".join([k for k, v in self.modes.items() if v])

    # Privilege helper methods
    def is_admin(self):
        """Check if user is ADMIN (+a)"""
        return self.has_mode('a')

    def is_sysop(self):
        """Check if user is SYSOP (+o)"""
        return self.has_mode('o')

    def is_guide(self):
        """Check if user is GUIDE (+g)"""
        return self.has_mode('g')

    def is_service(self):
        """Check if user is service (+s)"""
        return self.has_mode('s')

    def is_high_staff(self):
        """Check if user is ADMIN or SYSOP"""
        return self.has_mode('a') or self.has_mode('o')

    def is_staff(self):
        """Check if user is any staff (ADMIN/SYSOP/GUIDE)"""
        return self.has_mode('a') or self.has_mode('o') or self.has_mode('g')

    def is_privileged(self):
        """Check if user is staff or service"""
        return self.has_mode('a') or self.has_mode('o') or self.has_mode('g') or self.has_mode('s')

    def prefix(self, viewer=None):
        """
        Return user prefix with host masking based on viewer.
        If viewer is provided and is staff, show real host. Otherwise mask.
        """
        viewer_is_staff = viewer.is_staff() if viewer else False
        host = mask_host(self.host, viewer_is_staff)
        return f"{self.nickname}!{self.username}@{host}"

    def check_flood(self):
        return self.flood_protection.check()

    def check_rate_limit(self, cmd):
        return self.rate_limiter.check(cmd)

    async def send(self, msg):
        """Send message to client with backpressure control"""
        # Handle remote users (from linked servers) - route back through link
        if hasattr(self, 'is_remote') and self.is_remote and hasattr(self, 'from_server'):
            # This is a user from a remote server - route message back through link
            if hasattr(self, 'server') and self.server and hasattr(self.server, 'link_manager'):
                link_manager = self.server.link_manager
                if link_manager and link_manager.enabled:
                    # Find the server this user is from
                    for server_name, linked_server in link_manager.servers.items():
                        if self.from_server == server_name and linked_server.is_direct:
                            # Route message to that server
                            await linked_server.send(msg.rstrip('\r\n'))
                            return
            return

        if self.is_virtual or not self.writer:
            return
        max_len = CONFIG.get('limits', 'msg_length', default=512)
        if len(msg) > max_len:
            msg = msg[:max_len]
        out = msg if msg.endswith("\r\n") else msg + "\r\n"
        try:
            self.writer.write(out.encode('utf-8', errors='replace'))
            await self.writer.drain()  # Apply backpressure
        except (ConnectionResetError, BrokenPipeError):
            # Client disconnected, mark for cleanup
            self.writer = None
        except Exception as e:
            logger.error(f"Send error {self.nickname}: {e}")

# ==============================================================================
# DNSBL (DNS BLACKLIST) CHECKER
# ==============================================================================


class DNSBLChecker:
    """
    Checks IP addresses against DNS-based blacklists (DNSBL).

    How DNSBL works:
    1. Reverse the IP octets: 1.2.3.4 becomes 4.3.2.1
    2. Append the DNSBL domain: 4.3.2.1.dnsbl.example.org
    3. Do a DNS A lookup - if it resolves, the IP is listed
    4. The returned IP indicates the listing reason (e.g., 127.0.0.2 = spam)
    """

    def __init__(self):
        self.cache = {}  # {ip: (is_listed, listed_on, timestamp)}
        self.cache_ttl = CONFIG.get('security', 'dnsbl', 'cache_ttl', default=3600)

    def _reverse_ip(self, ip):
        """
        Reverse IP for DNSBL query.

        IPv4: Reverse octets (1.2.3.4 -> 4.3.2.1)
        IPv6: Reverse nibbles (2001:db8::1 -> 1.0.0.0...8.b.d.0.1.0.0.2)

        Returns tuple: (reversed_ip, is_ipv6)
        """
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)

            if isinstance(addr, ipaddress.IPv4Address):
                # IPv4: reverse the octets
                parts = ip.split('.')
                if len(parts) == 4:
                    return ('.'.join(reversed(parts)), False)
            elif isinstance(addr, ipaddress.IPv6Address):
                # IPv6: expand to full form, then reverse each nibble
                # 2001:db8::1 -> 2001:0db8:0000:0000:0000:0000:0000:0001
                # Then take each hex digit and reverse: 1.0.0.0.0.0.0.0...
                expanded = addr.exploded.replace(':', '')  # Remove colons
                # Reverse the nibbles (each hex digit)
                reversed_nibbles = '.'.join(reversed(expanded))
                return (reversed_nibbles, True)
        except ValueError:
            # Fallback for invalid addresses - try IPv4 string parsing
            try:
                parts = ip.split('.')
                if len(parts) == 4:
                    return ('.'.join(reversed(parts)), False)
            except Exception:
                pass
        except Exception:
            pass
        return (None, False)

    def _is_whitelisted(self, ip):
        """Check if IP is in the whitelist (supports IPv4 and IPv6)."""
        whitelist = CONFIG.get('security', 'dnsbl', 'whitelist', default=[])

        for entry in whitelist:
            if '/' in entry:
                # CIDR notation
                if self._ip_in_cidr(ip, entry):
                    return True
            elif ip == entry:
                return True

        # Use ipaddress module for robust private/loopback detection
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            # Check if loopback (127.0.0.0/8 for IPv4, ::1 for IPv6)
            if addr.is_loopback:
                return True
            # Check if private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 for IPv4,
            # fc00::/7 for IPv6 ULA)
            if addr.is_private:
                return True
            # Check if link-local (169.254.0.0/16 for IPv4, fe80::/10 for IPv6)
            if addr.is_link_local:
                return True
            # Check if reserved/unspecified
            if addr.is_reserved or addr.is_unspecified:
                return True
        except ValueError:
            # Invalid IP format - fall back to string checks for IPv4
            if ip.startswith('127.') or ip.startswith('10.') or \
               ip.startswith('192.168.') or ip.startswith('172.16.') or \
               ip.startswith('172.17.') or ip.startswith('172.18.') or \
               ip.startswith('172.19.') or ip.startswith('172.2') or \
               ip.startswith('172.30.') or ip.startswith('172.31.'):
                return True

        return False

    def _ip_in_cidr(self, ip, cidr):
        """Check if IP is within a CIDR range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except Exception:
            return False

    def _get_cached(self, ip):
        """Get cached result if still valid."""
        if ip in self.cache:
            is_listed, listed_on, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return (is_listed, listed_on)
        return None

    def _set_cached(self, ip, is_listed, listed_on):
        """Cache a lookup result."""
        self.cache[ip] = (is_listed, listed_on, time.time())

        # Cleanup old entries periodically (keep cache under 10000 entries)
        if len(self.cache) > 10000:
            now = time.time()
            self.cache = {k: v for k, v in self.cache.items()
                         if now - v[2] < self.cache_ttl}

    async def check_ip(self, ip):
        """
        Check an IP against configured DNSBL lists (supports IPv4 and IPv6).

        Returns:
            tuple: (is_listed: bool, listed_on: list of DNSBL names)
        """
        if not CONFIG.get('security', 'dnsbl', 'enabled', default=False):
            return (False, [])

        # Check whitelist
        if self._is_whitelisted(ip):
            return (False, [])

        # Check cache
        cached = self._get_cached(ip)
        if cached is not None:
            return cached

        reversed_ip, is_ipv6 = self._reverse_ip(ip)
        if not reversed_ip:
            return (False, [])

        dnsbl_lists = CONFIG.get('security', 'dnsbl', 'lists', default=[])
        timeout = CONFIG.get('security', 'dnsbl', 'timeout', default=3.0)
        listed_on = []

        for dnsbl in dnsbl_lists:
            # For IPv6, most DNSBLs don't support it yet
            # Some DNSBLs have separate IPv6 zones (e.g., dnsbl6.example.org)
            # or use the same zone with ip6.arpa-style queries
            if is_ipv6:
                # Skip DNSBLs that don't typically support IPv6
                # Note: DroneBL and some others do support IPv6
                query = f"{reversed_ip}.{dnsbl}"
            else:
                query = f"{reversed_ip}.{dnsbl}"

            try:
                # Use asyncio DNS resolution
                # Use AF_UNSPEC to allow both IPv4 and IPv6 responses
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.getaddrinfo(query, None, family=socket.AF_INET),
                    timeout=timeout
                )
                if result:
                    # IP is listed in this DNSBL
                    listed_on.append(dnsbl)
                    logger.info(f"DNSBL: {ip} listed in {dnsbl}")
            except (socket.gaierror, asyncio.TimeoutError, OSError):
                # Not listed or timeout - this is normal
                pass
            except Exception as e:
                logger.debug(f"DNSBL check error for {dnsbl}: {e}")

        is_listed = len(listed_on) > 0
        self._set_cached(ip, is_listed, listed_on)

        return (is_listed, listed_on)

    async def check_and_act(self, ip, writer):
        """
        Check IP and take configured action if listed.

        Returns:
            tuple: (should_reject: bool, message: str or None)
        """
        is_listed, listed_on = await self.check_ip(ip)

        if not is_listed:
            return (False, None)

        action = CONFIG.get('security', 'dnsbl', 'action', default='reject')
        reject_msg = CONFIG.get('security', 'dnsbl', 'reject_message',
                                default='Connection refused (DNSBL)')

        logger.warning(f"DNSBL: {ip} listed in {', '.join(listed_on)} - action: {action}")

        if action == 'reject':
            return (True, reject_msg)
        elif action == 'warn':
            # Don't reject, but log warning
            return (False, None)
        elif action == 'mark':
            # Don't reject, user will be marked (handled by caller)
            return (False, None)

        return (False, None)


class ProxyDetector:
    """
    Detects potential open proxies by checking common proxy ports.
    This is a lightweight check - not a full proxy scan.
    """

    def __init__(self):
        self.cache = {}  # {ip: (has_proxy, timestamp)}
        self.cache_ttl = 3600  # 1 hour

    async def check_ip(self, ip):
        """
        Check if an IP has common proxy ports open.

        Returns:
            tuple: (has_open_proxy: bool, open_ports: list)
        """
        if not CONFIG.get('security', 'proxy_detection', 'enabled', default=False):
            return (False, [])

        # Check cache
        if ip in self.cache:
            has_proxy, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return (has_proxy, [])

        ports = CONFIG.get('security', 'proxy_detection', 'ports',
                          default=[8080, 3128, 1080, 9050])
        timeout = CONFIG.get('security', 'proxy_detection', 'timeout', default=2.0)
        open_ports = []

        for port in ports:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
                logger.info(f"Proxy detection: {ip}:{port} is open")
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                pass
            except Exception:
                pass

        has_proxy = len(open_ports) > 0
        self.cache[ip] = (has_proxy, time.time())

        return (has_proxy, open_ports)


class ConnectionScorer:
    """
    Assigns a risk score to connections based on various factors.
    Higher scores indicate higher risk.
    """

    def __init__(self, dnsbl_checker, proxy_detector):
        self.dnsbl_checker = dnsbl_checker
        self.proxy_detector = proxy_detector

    async def score_connection(self, ip, hostname=None, has_ident=False):
        """
        Calculate a risk score for a connection.

        Returns:
            tuple: (score: int, factors: dict)
        """
        if not CONFIG.get('security', 'connection_scoring', 'enabled', default=False):
            return (0, {})

        score = 0
        factors = {}

        # DNSBL check
        dnsbl_listed, dnsbl_lists = await self.dnsbl_checker.check_ip(ip)
        if dnsbl_listed:
            points = CONFIG.get('security', 'connection_scoring', 'dnsbl_score', default=50)
            score += points
            factors['dnsbl'] = {'points': points, 'lists': dnsbl_lists}

        # Proxy detection
        has_proxy, open_ports = await self.proxy_detector.check_ip(ip)
        if has_proxy:
            points = CONFIG.get('security', 'connection_scoring', 'proxy_score', default=30)
            score += points
            factors['proxy'] = {'points': points, 'ports': open_ports}

        # No ident response
        if not has_ident:
            points = CONFIG.get('security', 'connection_scoring', 'no_ident_score', default=10)
            score += points
            factors['no_ident'] = {'points': points}

        # Generic hostname (indicates residential/dynamic IP)
        if hostname and self._is_generic_hostname(hostname):
            points = CONFIG.get('security', 'connection_scoring', 'generic_hostname_score', default=5)
            score += points
            factors['generic_hostname'] = {'points': points, 'hostname': hostname}

        return (score, factors)

    def _is_generic_hostname(self, hostname):
        """Check if hostname looks like a generic ISP-assigned name."""
        hostname_lower = hostname.lower()
        for pattern in _GENERIC_HOST_PATTERNS:
            if pattern.search(hostname_lower):
                return True
        return False

    def should_reject(self, score):
        """Check if score exceeds rejection threshold."""
        threshold = CONFIG.get('security', 'connection_scoring', 'threshold', default=100)
        return score >= threshold


# Global instances (initialized by server)
DNSBL_CHECKER = None
PROXY_DETECTOR = None
CONNECTION_SCORER = None


# ==============================================================================
# SSL/TLS MANAGER CLASS
# ==============================================================================


class SSLManager:
    """
    Manages SSL/TLS certificates for secure connections.

    Features:
    - Load certificates from files (compatible with Let's Encrypt)
    - Monitor certificate files for changes
    - Hot-reload certificates without server restart
    - Track certificate expiry and warn when approaching
    """

    def __init__(self):
        self.ssl_context = None
        self.cert_file = None
        self.key_file = None
        self.cert_mtime = 0
        self.key_mtime = 0
        self.cert_expiry = None
        self.cert_subject = None
        self.last_check = 0
        self.warned_days = set()  # Track which expiry warnings we've sent

    def load_certificates(self):
        """
        Load SSL certificates from configured files.

        Returns:
            ssl.SSLContext or None if SSL is disabled or files not found
        """
        if not CONFIG.get('ssl', 'enabled', default=False):
            return None

        self.cert_file = CONFIG.get('ssl', 'cert_file', default=None)
        self.key_file = CONFIG.get('ssl', 'key_file', default=None)

        if not self.cert_file or not self.key_file:
            logger.error("SSL enabled but cert_file or key_file not configured")
            return None

        if not os.path.exists(self.cert_file):
            logger.error(f"SSL certificate file not found: {self.cert_file}")
            return None

        if not os.path.exists(self.key_file):
            logger.error(f"SSL key file not found: {self.key_file}")
            return None

        try:
            # Determine minimum TLS version
            min_version_str = CONFIG.get('ssl', 'min_version', default='TLSv1.2')
            min_version_map = {
                'TLSv1': ssl.TLSVersion.TLSv1,
                'TLSv1.0': ssl.TLSVersion.TLSv1,
                'TLSv1.1': ssl.TLSVersion.TLSv1_1,
                'TLSv1.2': ssl.TLSVersion.TLSv1_2,
                'TLSv1.3': ssl.TLSVersion.TLSv1_3,
            }
            min_version = min_version_map.get(min_version_str, ssl.TLSVersion.TLSv1_2)

            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = min_version

            # Load certificate chain and private key
            context.load_cert_chain(self.cert_file, self.key_file)

            # Store file modification times for change detection
            self.cert_mtime = os.path.getmtime(self.cert_file)
            self.key_mtime = os.path.getmtime(self.key_file)

            # Parse certificate for expiry info
            self._parse_certificate()

            self.ssl_context = context
            logger.info(f"SSL certificates loaded successfully")
            logger.info(f"  Certificate: {self.cert_file}")
            logger.info(f"  Key: {self.key_file}")
            logger.info(f"  Minimum TLS: {min_version_str}")
            if self.cert_expiry:
                days_left = (self.cert_expiry - time.time()) / 86400
                logger.info(f"  Expires: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.cert_expiry))} ({days_left:.0f} days)")
            if self.cert_subject:
                logger.info(f"  Subject: {self.cert_subject}")

            return context

        except ssl.SSLError as e:
            logger.error(f"SSL error loading certificates: {e}")
            return None
        except Exception as e:
            logger.error(f"Error loading SSL certificates: {e}")
            return None

    def _parse_certificate(self):
        """Parse certificate to extract expiry date and subject."""
        try:
            # Try using cryptography library if available
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                with open(self.cert_file, 'rb') as f:
                    cert_data = f.read()

                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                self.cert_expiry = cert.not_valid_after_utc.timestamp()
                self.cert_subject = cert.subject.rfc4514_string()
                return
            except ImportError:
                pass

            # Fallback: use openssl command if available
            import subprocess
            result = subprocess.run(
                ['openssl', 'x509', '-in', self.cert_file, '-noout', '-enddate', '-subject'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('notAfter='):
                        # Parse date like "notAfter=Jan  1 00:00:00 2026 GMT"
                        date_str = line.split('=', 1)[1]
                        try:
                            from email.utils import parsedate_to_datetime
                            dt = parsedate_to_datetime(date_str.replace('GMT', '+0000'))
                            self.cert_expiry = dt.timestamp()
                        except Exception:
                            pass
                    elif line.startswith('subject='):
                        self.cert_subject = line.split('=', 1)[1].strip()
        except Exception as e:
            logger.debug(f"Could not parse certificate details: {e}")

    def check_for_reload(self):
        """
        Check if certificate files have changed and reload if needed.

        Returns:
            bool: True if certificates were reloaded
        """
        if not self.cert_file or not self.key_file:
            return False

        if not CONFIG.get('ssl', 'auto_reload', default=True):
            return False

        try:
            cert_mtime = os.path.getmtime(self.cert_file)
            key_mtime = os.path.getmtime(self.key_file)

            if cert_mtime != self.cert_mtime or key_mtime != self.key_mtime:
                logger.info("SSL certificate files changed, reloading...")
                old_context = self.ssl_context
                new_context = self.load_certificates()
                if new_context:
                    logger.info("SSL certificates reloaded successfully")
                    self.warned_days.clear()  # Reset expiry warnings
                    return True
                else:
                    logger.error("Failed to reload SSL certificates, keeping old ones")
                    self.ssl_context = old_context
                    return False
        except Exception as e:
            logger.debug(f"Error checking certificate files: {e}")

        return False

    def check_expiry_warnings(self):
        """Check certificate expiry and log warnings if approaching."""
        if not self.cert_expiry:
            return

        warn_days = CONFIG.get('ssl', 'expiry_warn_days', default=[14, 7, 3, 1])
        days_left = (self.cert_expiry - time.time()) / 86400

        for days in warn_days:
            if days_left <= days and days not in self.warned_days:
                self.warned_days.add(days)
                if days_left <= 0:
                    logger.error(f"SSL CERTIFICATE HAS EXPIRED! Renew immediately.")
                elif days_left <= 1:
                    logger.warning(f"SSL certificate expires in less than 1 day! Renew immediately.")
                else:
                    logger.warning(f"SSL certificate expires in {days_left:.0f} days. Consider renewing soon.")
                break

    def force_reload(self):
        """Force reload of certificates (called on SIGHUP)."""
        logger.info("Forcing SSL certificate reload...")
        self.cert_mtime = 0
        self.key_mtime = 0
        return self.check_for_reload()

    def get_info(self):
        """Get SSL status information for STATS command."""
        if not CONFIG.get('ssl', 'enabled', default=False):
            return {'enabled': False}

        info = {
            'enabled': True,
            'context_loaded': self.ssl_context is not None,
            'cert_file': self.cert_file,
            'key_file': self.key_file,
        }

        if self.cert_expiry:
            days_left = (self.cert_expiry - time.time()) / 86400
            info['expiry'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.cert_expiry))
            info['days_left'] = max(0, days_left)

        if self.cert_subject:
            info['subject'] = self.cert_subject

        return info


# Global SSL manager instance
SSL_MANAGER = None


# ==============================================================================
# SERVICEBOT MONITOR CLASS
# ==============================================================================


class ServiceBotMonitor:
    """
    Monitors channel activity for profanity and malicious behavior.
    Each ServiceBot in a channel uses this to check messages.
    """

    # URL pattern for detecting links
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]]+|'
        r'www\.[^\s<>"{}|\\^`\[\]]+|'
        r'[a-zA-Z0-9][-a-zA-Z0-9]*\.(com|net|org|io|co|tv|me|info|biz|xyz)[^\s]*',
        re.IGNORECASE
    )

    def __init__(self):
        # Per-user tracking for malicious detection
        # Format: {nickname: {'messages': [(timestamp, text), ...], 'urls': [timestamp, ...]}}
        self.user_history = {}
        # Cached compiled regex patterns for profanity filter (performance optimization)
        self._pattern_cache = {}
        self._word_cache = {}
        self._cache_signature = None  # Track when to invalidate cache
        # Cached config values (avoid 9 CONFIG.get() calls per message)
        self._config_cache = {}
        self._load_config_cache()

    def _load_config_cache(self):
        """Load and cache config values to avoid repeated CONFIG.get() calls per message"""
        self._config_cache = {
            'profanity_enabled': CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=True),
            'profanity_words': CONFIG.get('servicebot', 'profanity_filter', 'words', default=[]),
            'profanity_patterns': CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[]),
            'profanity_case_sensitive': CONFIG.get('servicebot', 'profanity_filter', 'case_sensitive', default=False),
            'profanity_action': CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn'),
            'malicious_enabled': CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True),
            'flood_action': CONFIG.get('servicebot', 'malicious_detection', 'flood_action', default='gag'),
            'repeat_action': CONFIG.get('servicebot', 'malicious_detection', 'repeat_action', default='warn'),
            'caps_action': CONFIG.get('servicebot', 'malicious_detection', 'caps_action', default='warn'),
            'url_spam_action': CONFIG.get('servicebot', 'malicious_detection', 'url_spam_action', default='warn'),
        }

    def reload_config(self):
        """Reload config cache when configuration changes (called from PROFANITY command)"""
        self._load_config_cache()
        # Force pattern cache rebuild on next check
        self._cache_signature = None

    def _get_user_history(self, nickname):
        """Get or create user history entry"""
        if nickname not in self.user_history:
            self.user_history[nickname] = {
                'messages': [],  # (timestamp, text) tuples
                'urls': [],      # timestamps of messages with URLs
                'warnings': 0,   # warning count
                'last_warning': 0
            }
        return self.user_history[nickname]

    def _cleanup_history(self, history, window):
        """Remove entries older than window seconds"""
        now = time.time()
        history['messages'] = [(ts, txt) for ts, txt in history['messages'] if now - ts < window]
        history['urls'] = [ts for ts in history['urls'] if now - ts < window]

    def check_profanity(self, text):
        """
        Check if text contains profanity.
        Supports both exact words and regex patterns.
        Returns (contains_profanity, matched_word/pattern) tuple.
        Uses cached compiled patterns and config values for performance.
        """
        if not self._config_cache['profanity_enabled']:
            return False, None

        words = self._config_cache['profanity_words']
        patterns = self._config_cache['profanity_patterns']
        case_sensitive = self._config_cache['profanity_case_sensitive']

        # Create signature to detect config changes
        signature = (tuple(words), tuple(patterns), case_sensitive)
        if signature != self._cache_signature:
            # Config changed, rebuild caches (track as cache miss for stats)
            self._word_cache = {}
            self._pattern_cache = {}
            self._cache_signature = signature

            # Precompile word patterns
            for word in words:
                check_word = word if case_sensitive else word.lower()
                pattern_str = r'\b' + re.escape(check_word) + r'\b'
                flags = 0 if case_sensitive else re.IGNORECASE
                self._word_cache[word] = re.compile(pattern_str, flags)

            # Precompile regex patterns
            for pattern_str in patterns:
                try:
                    flags = 0 if case_sensitive else re.IGNORECASE
                    self._pattern_cache[pattern_str] = re.compile(pattern_str, flags)
                except re.error:
                    # Invalid regex pattern - skip it
                    pass
        # Note: We could track cache_hits vs cache_misses here, but it's per-monitor
        # and would require passing server reference. For now, STATS will estimate from
        # regex_cache_misses tracked when config changes globally.

        check_text = text if case_sensitive else text.lower()

        # Check exact words with cached compiled patterns
        for word, compiled_pattern in self._word_cache.items():
            if compiled_pattern.search(check_text):
                return True, word

        # Check regex patterns with cached compiled patterns
        for pattern_str, compiled_pattern in self._pattern_cache.items():
            if compiled_pattern.search(text):
                return True, f"pattern:{pattern_str}"

        return False, None

    def check_flood(self, nickname, text):
        """
        Check for message flooding.
        Returns True if flood detected.
        """
        if not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
            return False

        threshold = CONFIG.get('servicebot', 'malicious_detection', 'flood_threshold', default=5)
        window = CONFIG.get('servicebot', 'malicious_detection', 'flood_window', default=3)

        history = self._get_user_history(nickname)
        self._cleanup_history(history, max(window, 30))  # Keep at least 30s of history

        now = time.time()
        history['messages'].append((now, text))

        # Count messages in window
        recent = [ts for ts, _ in history['messages'] if now - ts < window]
        return len(recent) >= threshold

    def check_repeat(self, nickname, text):
        """
        Check for repeated messages (spam).
        Returns True if repeat spam detected.
        """
        if not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
            return False

        threshold = CONFIG.get('servicebot', 'malicious_detection', 'repeat_threshold', default=3)
        window = CONFIG.get('servicebot', 'malicious_detection', 'repeat_window', default=30)

        history = self._get_user_history(nickname)
        self._cleanup_history(history, window)

        now = time.time()
        # Count identical messages in window
        text_lower = text.lower().strip()
        identical = sum(1 for ts, txt in history['messages']
                       if now - ts < window and txt.lower().strip() == text_lower)

        return identical >= threshold

    def check_caps(self, text):
        """
        Check for excessive caps (shouting).
        Returns True if excessive caps detected.
        """
        if not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
            return False

        min_length = CONFIG.get('servicebot', 'malicious_detection', 'caps_min_length', default=10)
        threshold = CONFIG.get('servicebot', 'malicious_detection', 'caps_threshold', default=0.7)

        # Only check messages of sufficient length
        alpha_chars = [c for c in text if c.isalpha()]
        if len(alpha_chars) < min_length:
            return False

        upper_count = sum(1 for c in alpha_chars if c.isupper())
        caps_ratio = upper_count / len(alpha_chars)

        return caps_ratio >= threshold

    def check_url_spam(self, nickname, text):
        """
        Check for URL spam.
        Returns True if URL spam detected.
        """
        if not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
            return False

        threshold = CONFIG.get('servicebot', 'malicious_detection', 'url_spam_threshold', default=3)
        window = CONFIG.get('servicebot', 'malicious_detection', 'url_spam_window', default=10)

        # Check if message contains URLs
        if not self.URL_PATTERN.search(text):
            return False

        history = self._get_user_history(nickname)
        self._cleanup_history(history, window)

        now = time.time()
        history['urls'].append(now)

        # Count URL messages in window
        recent_urls = [ts for ts in history['urls'] if now - ts < window]
        return len(recent_urls) >= threshold

    def analyze_message(self, nickname, text):
        """
        Analyze a message for all violations.
        Returns list of (violation_type, action, details) tuples.
        Uses cached config values for performance (avoids 5 CONFIG.get() calls per message).
        """
        violations = []

        # Check profanity
        has_profanity, matched = self.check_profanity(text)
        if has_profanity:
            violations.append(('profanity', self._config_cache['profanity_action'], f"matched word: {matched}"))

        # Check flood
        if self.check_flood(nickname, text):
            violations.append(('flood', self._config_cache['flood_action'], "message flooding"))

        # Check repeat spam
        if self.check_repeat(nickname, text):
            violations.append(('repeat', self._config_cache['repeat_action'], "repeated message spam"))

        # Check excessive caps
        if self.check_caps(text):
            violations.append(('caps', self._config_cache['caps_action'], "excessive caps"))

        # Check URL spam
        if self.check_url_spam(nickname, text):
            violations.append(('url_spam', self._config_cache['url_spam_action'], "URL spam"))

        return violations

    def clear_user(self, nickname):
        """Clear history for a user (e.g., when they leave)"""
        self.user_history.pop(nickname, None)


# ==============================================================================
# CHANNEL CLASS
# ==============================================================================


class Channel:
    def __init__(self, name):
        self.name = name
        self.members = {}
        self.owners = set()
        self.hosts = set()
        self.voices = set()
        # Channel modes: a=auth-only, d=clone-enabled, e=is-clone, f=strip-formatting, g=guide-op, h=hidden,
        # i=invite-only, j=no-invitations, k=key, l=limit, m=moderated, n=no-external, p=private, r=registered,
        # s=secret, t=topic-protection, u=knock-mode, w=no-whispers, x=auditorium, y=transcript, z=locked
        self.modes = {m: False for m in CONFIG.get(
            'modes', 'channel', default='adefghijklmnprstuwxyz')}
        # Apply default channel modes from config
        default_modes = CONFIG.get('modes', 'channel_defaults', default='nt')
        for mode in default_modes:
            if mode in self.modes:
                self.modes[mode] = True
        self.topic = ""
        self.topic_set_by = ""
        self.topic_set_at = 0
        self.props = {}
        self.ban_list = []
        self.gagged = set()
        self.created_at = int(time.time())
        self.registered = False
        self.account_uuid = None
        self.key = None
        self.host_key = None
        self.owner_key = None
        self.voice_key = None
        self.user_limit = None
        self.knock_cooldowns = {}
        # Clone channel support
        self.clone_parent = None      # Name of original channel (if this is a clone)
        self.clone_children = []      # List of clone channel names (if this is original)
        self.clone_index = 0          # Clone number (0 for original, 1+ for clones)
        # IRCX PROP properties
        self.onjoin = None            # Message sent to user after joining (PRIVMSG from channel)
        self.onpart = None            # Message sent to user after parting (NOTICE)
        # Channel access list (IRCX ACCESS command)
        # Each level maps to list of (mask, set_by, set_at, timeout, reason) tuples
        # timeout=0 means permanent, otherwise it's Unix timestamp when entry expires
        self.access_list = {
            'OWNER': [],   # Grants +q on join
            'HOST': [],    # Grants +o on join
            'VOICE': [],   # Grants +v on join
            'GRANT': [],   # Allows access (for +i channels)
            'DENY': []     # Denies access (ban)
        }

    @property
    def is_local(self):
        """Check if this is a local channel (& prefix). Local channels are not persisted."""
        return self.name.startswith('&')

    def has_member(self, nickname):
        return nickname in self.members

    def is_owner(self, nickname):
        return nickname in self.owners

    def is_host(self, nickname):
        return nickname in self.hosts

    def get_prefix(self, nickname):
        if nickname in self.owners:
            return "."
        elif nickname in self.hosts:
            return "@"
        elif nickname in self.voices:
            return "+"
        return ""

    def is_banned(self, user):
        user_mask = f"{user.nickname}!{user.username}@{user.host}"
        for ban_mask in self.ban_list:
            if fnmatch.fnmatch(user_mask.lower(), ban_mask.lower()):
                return True
        return False

    def is_clone(self):
        """Return True if this channel is a clone (+e mode)"""
        return self.modes.get('e', False)

    def is_clone_enabled(self):
        """Return True if this channel has clone mode (+d)"""
        return self.modes.get('d', False)

    def is_full(self):
        """Return True if channel is at user limit"""
        if not self.modes.get('l') or not self.user_limit:
            return False
        return len(self.members) >= self.user_limit

    def check_access(self, user, level):
        """Check if user matches any access entry for the given level.
        Returns (matched, reason) tuple. Expired entries are skipped.
        """
        import time
        user_mask = f"{user.nickname}!{user.username}@{user.host}"
        now = int(time.time())
        for entry in self.access_list.get(level, []):
            mask, set_by, set_at, timeout, reason = entry
            # Skip expired entries
            if timeout > 0 and now >= timeout:
                continue
            if fnmatch.fnmatch(user_mask.lower(), mask.lower()):
                return True, reason
            # Also check just nickname match
            if fnmatch.fnmatch(user.nickname.lower(), mask.lower()):
                return True, reason
        return False, ""

    def get_access_grants(self, user):
        """Get all access levels that should be granted to user on join.
        Returns set of levels: {'OWNER', 'HOST', 'VOICE', 'GRANT'}
        """
        grants = set()
        for level in ['OWNER', 'HOST', 'VOICE', 'GRANT']:
            matched, _ = self.check_access(user, level)
            if matched:
                grants.add(level)
        return grants

    async def broadcast(self, msg, exclude=None):
        """Broadcast message to all channel members (except exclude) with proper async handling"""
        tasks = []
        for member in self.members.values():
            if member != exclude:
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_user_action(self, source_user, action, exclude=None):
        """
        Broadcast a user action (JOIN/PART/QUIT/etc) with host masking.
        Each viewer sees an appropriately masked prefix based on their staff status.

        Args:
            source_user: The user performing the action
            action: The IRC command and parameters (e.g., "JOIN #channel", "PART #channel :Bye")
            exclude: Optional user to exclude from broadcast
        """
        tasks = []
        for member in self.members.values():
            if member != exclude:
                # Generate message with prefix masked for this viewer
                prefix = source_user.prefix(viewer=member)
                msg = f":{prefix} {action}"
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def to_dict(self):
        return {
            'name': self.name,
            'topic': self.topic,
            'topic_set_by': self.topic_set_by,
            'topic_set_at': self.topic_set_at,
            'modes': {k: v for k, v in self.modes.items() if v},
            'props': self.props,
            'owners': list(self.owners),
            'hosts': list(self.hosts),
            'voices': list(self.voices),
            'ban_list': self.ban_list,
            'gagged': list(self.gagged),
            'created_at': self.created_at,
            'registered': self.registered,
            'account_uuid': self.account_uuid,
            'key': self.key,
            'host_key': self.host_key,
            'owner_key': self.owner_key,
            'voice_key': self.voice_key,
            'user_limit': self.user_limit,
            'clone_parent': self.clone_parent,
            'clone_children': self.clone_children,
            'clone_index': self.clone_index,
            'onjoin': self.onjoin,
            'onpart': self.onpart,
            'access_list': self.access_list
        }

    def get_properties_json(self):
        """Get channel properties as JSON for storage in registered_channels table"""
        return json.dumps({
            'topic': self.topic,
            'topic_set_by': self.topic_set_by,
            'topic_set_at': self.topic_set_at,
            'owners': list(self.owners),
            'hosts': list(self.hosts),
            'voices': list(self.voices),
            'ban_list': self.ban_list,
            'key': self.key,
            'host_key': self.host_key,
            'owner_key': self.owner_key,
            'voice_key': self.voice_key,
            'user_limit': self.user_limit,
            'onjoin': self.onjoin,
            'onpart': self.onpart,
            'access_list': self.access_list,
            'modes': {k: v for k, v in self.modes.items() if v}  # Only store enabled modes
        })

    def load_properties_json(self, properties_json):
        """Load channel properties from JSON"""
        if not properties_json:
            return
        try:
            props = json.loads(properties_json)
            self.topic = props.get('topic', '')
            self.topic_set_by = props.get('topic_set_by', '')
            self.topic_set_at = props.get('topic_set_at', 0)
            self.owners = set(props.get('owners', []))
            self.hosts = set(props.get('hosts', []))
            self.voices = set(props.get('voices', []))
            self.ban_list = props.get('ban_list', [])
            self.key = props.get('key', None)
            self.host_key = props.get('host_key', None)
            self.owner_key = props.get('owner_key', None)
            self.voice_key = props.get('voice_key', None)
            self.user_limit = props.get('user_limit', None)
            self.onjoin = props.get('onjoin', None)
            self.onpart = props.get('onpart', None)
            self.access_list = props.get('access_list', {
                'OWNER': [], 'HOST': [], 'VOICE': [], 'GRANT': [], 'DENY': []
            })
            # Restore modes
            saved_modes = props.get('modes', {})
            for mode, value in saved_modes.items():
                if mode in self.modes:
                    self.modes[mode] = value
        except Exception as e:
            logger.error(f"Error loading channel properties: {e}")

    @classmethod
    def from_dict(cls, data):
        channel = cls(data['name'])
        channel.topic = data.get('topic', '')
        channel.topic_set_by = data.get('topic_set_by', '')
        channel.topic_set_at = data.get('topic_set_at', 0)
        channel.props = data.get('props', {})
        channel.owners = set(data.get('owners', []))
        channel.hosts = set(data.get('hosts', []))
        channel.voices = set(data.get('voices', []))
        channel.ban_list = data.get('ban_list', [])
        channel.gagged = set(data.get('gagged', []))
        channel.created_at = data.get('created_at', int(time.time()))
        channel.registered = data.get('registered', False)
        channel.account_uuid = data.get('account_uuid', None)
        # Generate UUID for registered channels missing one
        if channel.registered and not channel.account_uuid:
            channel.account_uuid = str(uuid.uuid4())
        channel.key = data.get('key', None)
        channel.host_key = data.get('host_key', None)
        channel.owner_key = data.get('owner_key', None)
        channel.voice_key = data.get('voice_key', None)
        channel.user_limit = data.get('user_limit', None)
        channel.clone_parent = data.get('clone_parent', None)
        channel.clone_children = data.get('clone_children', [])
        channel.clone_index = data.get('clone_index', 0)
        channel.onjoin = data.get('onjoin', None)
        channel.onpart = data.get('onpart', None)
        channel.access_list = data.get('access_list', {
            'OWNER': [], 'HOST': [], 'VOICE': [], 'GRANT': [], 'DENY': []
        })
        for mode, value in data.get('modes', {}).items():
            if mode in channel.modes:
                channel.modes[mode] = value
        # Ensure +r mode matches registered flag
        if channel.registered and 'r' in channel.modes:
            channel.modes['r'] = True
        return channel


# ==============================================================================
# RESPONSE TABLE
# ==============================================================================
RESPONSES = {
    "001": "Welcome to the {network}, {nick}!",
    "002": "Your host is {servername}, running version {version_label} {version}",
    "003": "This server was created {created_date}",
    "004": "{servername} {version_label} {version} {usermodes} {chanmodes}",
    "005": "CHANTYPES=#& PREFIX=(qov).@+ CHANMODES={chanmodes_param} NICKLEN={nicklen} MAXNICKLEN={nicklen} USERLEN={userlen} CHANNELLEN={chanlen} TOPICLEN={topiclen} MODES={max_modes} CASEMAPPING=rfc1459 STATUSMSG=.@+ NETWORK={network_name} IRCX ACCESS PROPS :are supported",
    "219": "{flag} :End of /STATS report",
    "221": "+{modes}",
    "251": "There are {users} users and {invisible} invisible on {server_count} servers",
    "252": "{ops} :staff and services online",
    "253": "{unknown} :unknown connection(s)",
    "254": "{channels} :channels formed",
    "255": "I have {users} clients and {server_count} servers",
    "265": "Current local users: {local}, max: {local_max}",
    "266": "Current global users: {global_users}, max: {global_max}",
    "256": "{servername} :Administrative info",
    "257": ":{loc1}",
    "258": ":{loc2}",
    "259": ":{email}",
    "301": "{target} :{message}",
    "302": "{userhosts}",
    "303": ":{nicks}",
    "305": "You are no longer marked as being away",
    "306": "You have been marked as being away",
    "311": "{target} {ident} {host} * :{real}",
    "312": "{target} {servername} :pyIRCX Server",
    "313": "{target} :{role}",
    "314": "{target} {ident} {host} * :{real}",
    "315": "{target} :End of /WHO list",
    "317": "{target} {idle} {signon} :seconds idle, signon time",
    "318": "{target} :End of /WHOIS list",
    "319": "{target} :{channels}",
    "320": "{target} :from IP {ip}",
    "321": "Channel :Users Name",
    "322": "{channel} {users} :{topic}",
    "323": "End of /LIST",
    "324": "{channel} +{modes}",
    "331": "{channel} :No topic is set",
    "332": "{channel} :{topic}",
    "333": "{channel} {nick} {timestamp}",
    "341": "{target} {channel}",
    "351": "{version} {servername} :{version_label}",
    "352": "{channel} {ident} {host} {servername} {target} {flags} :0 {real}",
    "353": "= {channel} :{names}",
    "366": "{channel} :End of /NAMES list",
    "367": "{channel} {mask}",
    "368": "{channel} :End of channel ban list",
    "369": "{target} :End of WHOWAS",
    "371": ":{info}",
    "372": "-{text}",
    "374": ":End of /INFO list",
    "375": "- {servername} Message of the Day -",
    "376": "End of /MOTD command",
    "422": "MOTD File is missing",
    "381": "You are now an IRC {role}",
    "386": "{staff_login_message}",
    "391": ":Local time is {time}",
    "401": "{target} :That nickname or channel doesn't exist",
    "403": "{target} :That channel doesn't exist",
    "404": "{channel} :You cannot send to channel (check channel modes or your permissions)",
    "407": "{target} :You specified too many recipients",
    "421": "{command} :This command is not recognized",
    "432": "{target} :That nickname is not valid (must be 1-{nicklen} characters, start with a letter, and contain only letters, numbers, -, _, [, ], {{, }}, \\, or |)",
    "433": "{target} :Nickname is already in use",
    "441": "{target} {channel} :They aren't on that channel",
    "442": "{target} :You're not on that channel",
    "443": "{target} {channel} :They are already on that channel",
    "451": "You have not registered (use NICK and USER commands)",
    "461": "{command} :You did not provide enough parameters. See /HELP {command} for usage.",
    "462": "You may not reregister",
    "468": ":That username is not valid (must start with a letter and contain only letters, numbers, -, _, or .)",
    "471": "{target} :You cannot join channel (channel is full - user limit reached)",
    "473": "{target} :You cannot join channel (invite-only - you must be invited)",
    "474": "{target} :You cannot join channel (you are banned from this channel)",
    "475": "{target} :You cannot join channel (incorrect channel key/password)",
    "481": "You do not have permission - IRC operator or administrator privileges are required",
    "482": "{target} :You're not a channel owner or host (+q or +o required)",
    "696": "{target} {mode} :You must specify a parameter for the {mode} mode",
    "710": "{channel} {nick} {host} :has asked for an invite",
    "711": "{target} :Your knock request has been sent",
    "712": "{target} :You have sent too many knock requests. Please wait before trying again.",
    "713": "{target} :Channel is open",
    "714": "{target} :You are already on that channel",
    "716": "{target} :You cannot knock on this channel (+u mode)",
    "800": "1 0 {auth_status} 512 *",
    "804": "Authentication successful",
    "805": "{target} :Access list",
    "806": "{cls} {mask}",
    "807": "{cls} {mask}",
    "808": ":Start of events",
    "809": "{cls} {mask}",
    "810": ":End of events",
    "811": "Channel :Users Topic",
    "812": "{channel} {users} {modes} :{topic}",
    "813": "End of /LISTX",
    "814": "{servername} {timestamp} {cls} {action} {channel} {user_prefix} {ip_port} {data}",
    "817": "{target} {prop} :{value}",
    "818": "{target} :End of properties",
    "819": "{target} {prop} :{value}",
    # IRCX Service Protection (820-829)
    "820": "{target} :You cannot perform this action on services",
    "821": "{target} :You cannot kick services",
    "822": "{target} :You cannot ban services",
    "823": "{target} :You cannot kill services",
    "824": "{target} :You cannot gag services",
    "825": "{target} :You cannot add services to access deny list",
    # IRCX Rate Limiting (830-839)
    "830": ":You are being rate limited. Please wait before trying again.",
    "831": ":WHO command rate limited. Please wait before trying again.",
    "832": ":WHISPER rate limited (5 second cooldown)",
    "833": ":LIST command rate limited. Please wait before trying again.",
    "834": ":Sending too fast. Flood protection triggered. Please slow down.",
    "835": ":Please wait {seconds} seconds before changing nickname",
    # IRCX Channel Restrictions (840-849)
    "840": "{channel} :You cannot send to channel",
    "841": "{channel} :You cannot send to channel (moderated - only voiced users and channel operators can speak)",
    "842": "{channel} :You cannot send to channel (no external messages - you must join the channel first)",
    "843": "{channel} :Whispers are not allowed in this channel",
    "844": "{channel} :Invitations are not allowed in this channel",
    "845": "{channel} :Transcript mode not enabled (+y)",
    "846": "{channel} :{prop} is read-only",
    "847": "{target} :ServiceBot has reached max channels ({max})",
    "848": ":Only staff members can invite ServiceBots",
    # IRCX Access Control (850-859)
    "850": ":That is not a valid access level - valid: {levels}",
    "851": "{mask} :This mask is already in the {level} list",
    "852": "{mask} :This mask was not found in the {level} list",
    "853": ":You cannot remove owner-added entry (you are not the channel owner)",
    "854": "{target} :ACCESS {level} added: {mask}",
    "855": "{target} :ACCESS {level} removed: {mask}",
    "856": "{target} :Cleared {count} {level} entries",
    "857": ":Only channel owners can clear access lists",
    "858": ":You cannot delete your own staff account",
    "859": ":You are already linked to {server}",
    # IRCX Command Usage (860-869)
    "860": ":Usage: {usage}",
    "861": ":That is not a valid configuration path. Use: section.key (e.g., limits.max_users)",
    "862": ":That is not a valid level. Use: {levels}",
    "863": ":That username is not valid: {error}",
    "864": ":That password is not valid (minimum 8 characters, must include letters and numbers)",
    "865": ":That MFA code is not valid. Please enter the 6-digit code from your authenticator app.",
    "866": ":That message ID is not valid",
    "867": ":That channel name is not valid (must start with # or & and contain only letters, numbers, -, _, or .)",
    "868": ":That nickname is not valid (must be 1-{nicklen} characters, start with a letter, and contain only letters, numbers, -, _, [, ], {{, }}, \\, or |)",
    "869": ":That parameter is not valid: {param}",
    # IRCX Registration/Auth (870-879)
    "870": ":Nickname {nick} is already registered",
    "871": ":Nickname {nick} is not registered",
    "872": ":You are already identified to a registered nickname",
    "873": ":You must be identified to unregister your nickname",
    "874": ":Your nickname {nick} has been registered (UUID: {uuid})",
    "875": ":Your nickname {nick} has been dropped",
    "876": ":You are now identified as {nick}",
    "877": ":Password accepted. MFA is enabled - please verify with: MFA VERIFY <code>",
    "878": ":MFA enabled. Save this secret: {secret}. Scan the QR code or enter manually in your authenticator app.",
    "879": ":Your MFA has been disabled",
    # IRCX Staff Management (880-889)
    "880": ":The staff account {username} was created with level {level}",
    "881": ":The staff account {username} was deleted",
    "882": ":The staff account {username} was changed to level {level}",
    "883": ":The password was changed for staff account {username}",
    "884": ":We couldn't list the staff accounts",
    "885": ":We couldn't create the staff account",
    "886": ":We couldn't delete the staff account",
    "887": ":We couldn't change the staff level",
    "888": ":We couldn't change the password",
    "889": ":The staff account {username} was not found",
    # IRCX Config/Admin (890-899)
    "890": ":{key} = {value}",
    "891": ":{key} set to {value}",
    "892": ":That configuration key was not found: {key}",
    "893": ":We couldn't access the configuration",
    "894": ":Connected to {server}",
    "895": ":Disconnected from {server}",
    "896": ":We couldn't connect to {server}",
    "897": ":The server {server} was not found in your links",
    "898": ":Link operation in progress",
    "899": ":Link timeout - operation aborted",
    # IRCX Database/System (900-909)
    "900": ":Registration failed. Please try again later. If the problem persists, contact an administrator.",
    "901": ":Identification failed - please try again later",
    "902": ":Drop failed - please try again later",
    "903": ":Database error. Please try again later. If the problem persists, contact an administrator.",
    "904": ":System error - please contact an administrator",
    "905": ":Operation failed. Please try again. If the problem persists, contact an administrator.",
    "906": ":Channel registration failed. The channel may already be registered or you may not be the owner.",
    "907": ":Channel drop failed",
    "908": ":Info lookup failed",
    "909": ":Memo operation failed. Please check your parameters and try again.",
    # IRCX Service Messages (910-919)
    "910": ":Commands: {commands}",
    "911": ":That command is not recognized: {cmd}. Try: {suggestions}",
    "912": ":{service} service is temporarily unavailable",
    "913": ":No memos waiting",
    "914": ":You have {count} memo(s) waiting",
    "915": ":Memo sent to {target}",
    "916": ":Memo {id} deleted",
    "917": ":All memos cleared",
    "918": ":Channel {channel} is already registered",
    "919": ":Channel {channel} is not registered",
    # WATCH numerics
    "600": "{nick} {user} {host} {signon} :logged on",
    "601": "{nick} {user} {host} {signon} :logged off",
    "602": "{nick} {user} {host} {signon} :stopped watching",
    "604": "{nick} {user} {host} {signon} :is online",
    "605": "{nick} * * 0 :is offline",
    "606": ":{nicks}",  # List of watched nicks
    "607": ":End of WATCH list",
    # SILENCE numerics
    "271": "{nick} {mask}",
    "272": ":End of Silence List",
    "STAFF_LOG": "[{action}] {staff} -> {target}: {details}",
}

# ==============================================================================
# SERVER MESSAGES - NOTICE templates for informational messages
# ==============================================================================
SERVER_MESSAGES = {
    # Gag/Ungag confirmations (sent to staff, not target - shadow ban)
    "gag_channel": "{target} has been gagged in {channel}",
    "ungag_channel": "{target} has been ungagged in {channel}",
    "gag_global": "{target} has been globally gagged (+z)",
    "ungag_global": "{target} has been globally ungagged (-z)",

    # WHO/LIST restrictions
    "who_requires_staff": "WHO * requires IRC operator or administrator privileges. Try using a pattern like *nick* or *@host* instead",
    "who_truncated": "WHO results truncated at {limit} entries. Use a more specific pattern for complete results.",

    # Message handling
    "message_truncated": "Message truncated to {max} characters",
    "system_no_messages": "The System service does not accept direct messages. Use /HELP for available services, or /msg Registrar for help.",
    "mfa_pending": "MFA verification pending. Send your 6-digit code: /msg Registrar MFA VERIFY <code>",
    "access_denied": "You do not have access: {reason}",

    # Transcript
    "transcript_header": "=== Transcript for {channel} ({count} lines) ===",
    "transcript_footer": "=== End of transcript ===",
    "no_transcript": "No transcript available for {channel}",

    # User killed
    "user_killed": "{target} KILLED",

    # Registrar service
    "registrar_help": "Commands: REGISTER <password> [email], IDENTIFY <password>, DROP, INFO [nick], CHANNEL <cmd>, SET <option>, MFA <cmd>",
    "registrar_tip": "TIP: You can also use direct commands: REGISTER, UNREGISTER, IDENTIFY, MFA",
    "registrar_info_header": "Info for {nickname}:",
    "registrar_info_uuid": "  UUID: {uuid}",
    "registrar_info_registered": "  Registered: {time}",
    "registrar_info_lastseen": "  Last seen: {time}",
    "registrar_info_mfa": "  MFA enabled: {status}",
    "registrar_channel_registered": "Channel {channel} is now registered to you",
    "registrar_channel_dropped": "Channel {channel} has been unregistered",
    "registrar_channel_info": "Channel {channel} - Owner: {owner}, Registered: {time}",
    "registrar_email_updated": "Your email address has been updated",
    "registrar_password_updated": "Your password has been updated",
    "registrar_mfa_verify_prompt": "Please enter the 6-digit MFA code from your authenticator app",
    "registrar_mfa_verify_success": "MFA verification successful!",

    # Messenger service
    "messenger_help": "Commands: SEND <nick> <message>, LIST, READ <id>, DELETE <id>, CLEAR, COUNT, PUSH <message> (IRC administrator only)",
    "messenger_sent": "Message sent to {target}",
    "messenger_deleted": "Your memo {id} has been deleted",
    "messenger_cleared": "All your memos have been cleared",
    "messenger_count": "You have {count} memo(s) waiting",
    "messenger_no_memos": "You have no memos waiting",
    "messenger_list_header": "Your memos:",
    "messenger_list_item": "  [{id}] From {from} at {time}: {preview}",
    "messenger_read_header": "Memo {id} from {from} at {time}:",
    "messenger_read_body": "  {message}",
    "messenger_user_offline": "{target} is offline. Your message has been queued for delivery.",
    "messenger_user_online": "{target} is online",
    "messenger_push_sent": "Message pushed to {count} user(s)",

    # NewsFlash service
    "newsflash_help": "Commands: LIST, READ <id>, DELETE <id> (staff), PUSH <message> (IRC administrator only)",
    "newsflash_list_header": "Recent NewsFlash items:",
    "newsflash_list_item": "  [{id}] {time}: {preview}",
    "newsflash_read_header": "NewsFlash {id} from {time}:",
    "newsflash_read_body": "  {message}",
    "newsflash_deleted": "NewsFlash {id} has been deleted",
    "newsflash_pushed": "NewsFlash sent to {count} user(s)",
    "newsflash_no_items": "There are no NewsFlash items available",

    # ServiceBot messages
    "servicebot_warning": "Warning: {violation}",
    "servicebot_action": "Action taken: {action}",

    # IRCX PROP on-join/on-part (sent from channel entity, not server)
    # These are sent as channel!channel@server PRIVMSG/NOTICE
}

# ==============================================================================
# MAIN SERVER CLASS
# ==============================================================================


class pyIRCXServer:
    def __init__(self):
        self.servername = CONFIG.get('server', 'name', default='irc.local')
        self.users = {}
        self.channels = {}
        self.channel_creation_lock = asyncio.Lock()  # Prevent race conditions in channel creation
        self.whowas = OrderedDict()  # LRU cache for WHOWAS
        self.whowas_max_entries = 1000  # Maximum entries to keep
        self.whowas_max_age = 86400  # 24 hours in seconds
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

        self.servicebots = {}  # ServiceBot instances
        self.channel_monitors = {}  # Channel name -> ServiceBotMonitor
        self.save_task = None
        self.link_manager = None  # Will be set by ServerManager if linking is enabled

    def get_channel(self, name):
        """Case-insensitive channel lookup. Returns (channel, canonical_name) or (None, None)."""
        # Try exact match first
        if name in self.channels:
            return self.channels[name], name
        # Case-insensitive search
        name_lower = name.lower()
        for chan_name, channel in self.channels.items():
            if chan_name.lower() == name_lower:
                return channel, chan_name
        return None, None

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
        """
        # Check original first
        if not original.is_full():
            return original
        # Check existing clones in order
        for clone_name in original.clone_children:
            clone, _ = self.get_channel(clone_name)
            if clone and not clone.is_full():
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

        if is_admin:
            service.set_mode('a', True)
            # Apply relaxed rate limits for admin services
            service.rate_limiter = RateLimiter(RateLimiter.STAFF_COOLDOWNS)
        if is_servicebot:
            service.max_channels = CONFIG.get('services', 'servicebot_max_channels', default=10)
            self.servicebots[nickname] = service  # Track servicebot
        self.users[nickname] = service
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
        if not CONFIG.get('servicebot', 'enabled', default=True):
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
                warn_msg = "You are sending messages too quickly. Please slow down."
            elif violation_type == "caps":
                warn_msg = "Please don't use excessive caps (shouting)."
            elif violation_type == "repeat":
                warn_msg = "Please don't repeat the same message."
            elif violation_type == "url_spam":
                warn_msg = "Please don't spam URLs."

            await user.send(f"{bot_prefix} NOTICE {user.nickname} :[{channel_name}] {warn_msg}")
            logger.info(f"ServiceBot {bot.nickname}: Warned {user.nickname} in {channel_name} for {violation_type}")

        elif action == "gag":
            if user.nickname not in channel.gagged:
                channel.gagged.add(user.nickname)
                user.set_mode('z', True)
                # Shadow ban - no notification to user or channel
                logger.info(f"ServiceBot {bot.nickname}: Gagged {user.nickname} in {channel_name} for {violation_type}")

        elif action == "kick":
            kick_reason = f"ServiceBot: {violation_type}"
            msg = f"{bot_prefix} KICK {channel_name} {user.nickname} :{kick_reason}"
            await channel.broadcast(msg)
            channel.members.pop(user.nickname, None)
            channel.owners.discard(user.nickname)
            channel.hosts.discard(user.nickname)
            channel.voices.discard(user.nickname)
            channel.gagged.discard(user.nickname)
            user.channels.discard(channel_name)
            logger.info(f"ServiceBot {bot.nickname}: Kicked {user.nickname} from {channel_name} for {violation_type}")

        elif action == "ban":
            # Add ban mask and kick
            ban_mask = f"*!*@{user.host}"
            if ban_mask not in channel.ban_list:
                channel.ban_list.append(ban_mask)
                ban_msg = f"{bot_prefix} MODE {channel_name} +b {ban_mask}"
                await channel.broadcast(ban_msg)

            kick_reason = f"ServiceBot: Banned for {violation_type}"
            kick_msg = f"{bot_prefix} KICK {channel_name} {user.nickname} :{kick_reason}"
            await channel.broadcast(kick_msg)
            channel.members.pop(user.nickname, None)
            channel.owners.discard(user.nickname)
            channel.hosts.discard(user.nickname)
            channel.voices.discard(user.nickname)
            channel.gagged.discard(user.nickname)
            user.channels.discard(channel_name)
            logger.info(f"ServiceBot {bot.nickname}: Banned {user.nickname} from {channel_name} for {violation_type}")

    async def _check_servicebot_violations(self, channel, user, text):
        """
        Check a message for violations if ServiceBot is present.
        Executes appropriate actions for violations found.
        """
        if not CONFIG.get('servicebot', 'enabled', default=True):
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
                logger.error(f"Transcript write error for {channel.name}: {e}")

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
                logger.error(f"Transcript read error for {channel_name}: {e}")
            return []

    async def boot(self):
        logger.info("="*70)
        logger.info(f" {CONFIG.get('server', 'name')} Enhanced")
        logger.info(f" {CONFIG.get('server', 'network')}")
        logger.info("="*70)

        # Validate config file permissions for security
        config_path = '/etc/pyircx/pyircx_config.json'
        try:
            import stat
            st = os.stat(config_path)
            mode = st.st_mode
            if mode & stat.S_IROTH or mode & stat.S_IWOTH:
                logger.error("="*70)
                logger.error("SECURITY WARNING: Config file is world-readable/writable!")
                logger.error(f"File: {config_path}")
                logger.error(f"Current permissions: {oct(stat.S_IMODE(mode))}")
                logger.error("Recommended fix: sudo chmod 600 /etc/pyircx/pyircx_config.json")
                logger.error("="*70)
            elif mode & stat.S_IRGRP or mode & stat.S_IWGRP:
                logger.warning(f"Config file {config_path} is group-readable. Consider chmod 600 for maximum security.")
        except FileNotFoundError:
            pass  # Using alternate config location
        except Exception as e:
            logger.warning(f"Could not validate config file permissions: {e}")

        # Check server role - only trunk servers need database initialization
        server_role = CONFIG.get('linking', 'server_role', default='trunk')
        is_trunk = (server_role == 'trunk')

        if is_trunk:
            async with aiosqlite.connect(CONFIG.get('database', 'path', default='ircx_server.db')) as db:
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
                        default_pass = CONFIG.get('admin', 'default_password', default='changeme')
                        password_hash = await hash_password_async(default_pass)
                        await db.execute(
                            "INSERT INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                            (default_user, password_hash, 'ADMIN')
                        )
                        await db.commit()
                        logger.warning(f"Created default ADMIN account: {default_user}")
                        logger.warning("*** CHANGE THE DEFAULT PASSWORD IMMEDIATELY using: STAFF PASS ***")

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

                await db.commit()
                logger.info("Database initialized (trunk)")
        else:
            logger.info("Skipping database initialization (branch server)")

        # Load ACCESS list (branches will have empty list until synced)
        await self._load_access_list()

        # Channels are now dynamic - only loaded when users join
        # Registered channels restore their properties from registered_channels table

        # Check if we should create local services
        services_enabled = CONFIG.get('services', 'enabled', default=True)
        services_mode = CONFIG.get('services', 'mode', default='local')
        is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)

        # Only create services if:
        # 1. Services are globally enabled, AND
        # 2. We're in "local" mode OR we're designated as the services hub
        should_create_services = services_enabled and (services_mode == 'local' or is_services_hub)

        if should_create_services:
            self.channels["#System"] = Channel("#System")
            self.channels["#System"].registered = True
            self.channels["#System"].account_uuid = str(uuid.uuid4())

            # Create System virtual user (omnipresent)
            sys_user = self._create_virtual_service('System', 'System', "System", omnipresent=True)
            logger.info("#System channel created")

            # Create God virtual user (omniscient watcher)
            god_user = self._create_virtual_service('God', 'God', "God", divine=True)
            self.users[god_user.nickname] = god_user
            logger.info("God virtual user created")

            # Create Registrar service - handles nick/channel registration
            registrar = self._create_virtual_service('Registrar', 'Registrar', "Registration Services")
            logger.info("Registrar service created")

            # Create Messenger service - handles mailbox and global messages
            messenger = self._create_virtual_service('Messenger', 'Messenger', "Message Services")
            logger.info("Messenger service created")

            # Create NewsFlash alias - part of Messenger for rotating/push messages
            newsflash = self._create_virtual_service('NewsFlash', 'NewsFlash', "News Broadcast Services")
            logger.info("NewsFlash service created")

            # Create ServiceBots - configurable count
            self.servicebots = {}
            bot_count = CONFIG.get('services', 'servicebot_count', default=10)
            for i in range(1, bot_count + 1):
                bot_name = f"ServiceBot{i:02d}"
                bot = self._create_virtual_service(bot_name, 'ServiceBot', f"Service Bot #{i}", is_servicebot=True)
                self.servicebots[bot_name] = bot
            logger.info(f"{bot_count} ServiceBots created")

            # Create ServiceBot dispatcher - virtual user that routes to available bots
            servicebot_dispatcher = self._create_virtual_service('ServiceBot', 'ServiceBot', "ServiceBot Pool Dispatcher")
            logger.info("ServiceBot dispatcher created")

            logger.info(f"Services initialized in {services_mode} mode" +
                       (" (services hub)" if is_services_hub else ""))
        else:
            # No local services - we're a branch server in centralized mode
            self.servicebots = {}
            if services_mode == 'centralized' and not is_services_hub:
                logger.info("Services disabled: Running as branch server in centralized mode")
                logger.info(f"Services will be provided by trunk: {CONFIG.get('services', 'hub_server', default='(not configured)')}")
            elif not services_enabled:
                logger.info("Services disabled by configuration")
            else:
                logger.warning("Services configuration error - check services.mode and services.is_services_hub")

        # Initialize DNSBL and connection security checkers
        global DNSBL_CHECKER, PROXY_DETECTOR, CONNECTION_SCORER
        DNSBL_CHECKER = DNSBLChecker()
        PROXY_DETECTOR = ProxyDetector()
        CONNECTION_SCORER = ConnectionScorer(DNSBL_CHECKER, PROXY_DETECTOR)
        if CONFIG.get('security', 'dnsbl', 'enabled', default=False):
            logger.info("DNSBL checking enabled")
        if CONFIG.get('security', 'proxy_detection', 'enabled', default=False):
            logger.info("Proxy detection enabled")
        if CONFIG.get('security', 'connection_scoring', 'enabled', default=False):
            logger.info("Connection scoring enabled")

        # Removed: periodic_save - channels now persist on registration, not periodically

        # Initialize database connection pool (trunk only)
        if self.db_pool:
            await self.db_pool.initialize()
            logger.info("Database connection pool initialized")

        # Start CAP timeout monitor
        self.cap_timeout_task = asyncio.create_task(self._cap_timeout_monitor())
        logger.info(f"CAP timeout monitor started ({self.cap_timeout}s timeout)")

    async def _load_access_list(self):
        """Load server-wide ACCESS rules from database (trunk only)"""
        server_role = CONFIG.get('linking', 'server_role', default='trunk')

        # Branches don't load from database - they keep ACCESS in-memory only
        if server_role == 'branch':
            logger.info("ACCESS list: In-memory only (branch server)")
            return

        # Trunk loads from database
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
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
                logger.info(f"ACCESS rules loaded: {grant_count} GRANT, {deny_count} DENY")
        except Exception as e:
            logger.error(f"Load ACCESS error: {e}")

    async def load_registered_channel(self, channel_name):
        """Load a registered channel from database if it exists"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
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
                        logger.info(f"Loaded registered channel: {channel.name}")
                        return channel
        except Exception as e:
            logger.error(f"Error loading registered channel {channel_name}: {e}")
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
                    await user.send(f"ERROR :Closing link: CAP negotiation timeout ({self.cap_timeout}s)")
                    logger.warning(f"CAP timeout: {user.ip} (stuck in negotiation)")
                    await self.quit_user(user)
                except Exception as e:
                    logger.error(f"CAP timeout disconnect error: {e}")

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
            # User modes: a=ADMIN, g=GUIDE, i=invisible, o=SYSOP, r=registered, s=service, x=IRCX, z=gagged
            "usermodes": CONFIG.get('modes', 'user', default='agiorsxz'),
            # Channel modes: a=auth-only, d=clone-enabled, e=is-clone, f=strip-formatting, g=guide-op, h=hidden,
            # i=invite-only, j=no-invitations, k=key, l=limit, m=moderated, n=no-external, p=private, r=registered,
            # s=secret, t=topic-protection, u=knock-mode, w=no-whispers, x=auditorium, y=transcript, z=locked
            "chanmodes": CONFIG.get('modes', 'channel', default='adefghijklmnprstuwxyz'),
            # CHANMODES parameter (IRCv3 format: A,B,C,D where A=list modes, B=always param, C=param on set, D=no param)
            # A=empty (no ban lists via MODE), B=k (key), C=l (limit), D=all others
            "chanmodes_param": ",k,l,adefghijmnprstuwxyz",
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
            **kwargs
        }
        try:
            txt = template.format(**params)
            if code == "800":
                return f":{self.servername} 800 {recipient.nickname if recipient.registered else '*'} {txt}"
            no_colon = [
                "005", "219", "252", "253", "254", "256", "257", "258", "259", "265", "266", "272", "301", "303", "311", "312", "313", "314", "315", "317",
                "318", "319", "320", "321", "322", "331", "332", "351", "352", "353", "366", "368", "369", "371", "374", "391", "401", "403", "404", "407",
                "421", "432", "433", "441", "442", "443", "461", "468", "471", "473", "474", "475", "482", "600", "601", "602", "604", "605", "606", "607",
                "696", "710", "711", "712", "713", "714", "716", "805", "811", "812", "817", "818", "819", "820", "821", "822", "823", "824", "825", "830",
                "831", "832", "833", "834", "835", "840", "841", "842", "843", "844", "845", "846", "847", "848", "850", "851", "852", "853", "854", "855",
                "856", "857", "858", "859", "860", "861", "862", "863", "864", "865", "866", "867", "868", "869", "870", "871", "872", "873", "874", "875",
                "876", "877", "878", "879", "880", "881", "882", "883", "884", "885", "886", "887", "888", "889", "890", "891", "892", "893", "894", "895",
                "896", "897", "898", "899", "900", "901", "902", "903", "904", "905", "906", "907", "908", "909", "910", "911", "912", "913", "914", "915",
                "916", "917", "918", "919"
            ]
            if code == "433":
                return f":{self.servername} 433 {recipient.nickname if recipient.nickname != '*' else '*'} {txt}"
            sep = " " if code in no_colon else " :"
            return f":{self.servername} {code} {recipient.nickname}{sep}{txt}"
        except Exception as e:
            logger.error(f"Reply error {code}: {e}")
            return f":{self.servername} 500 {recipient.nickname} :Format Error"

    async def send_notice(self, user, message_key, **kwargs):
        """
        Send a NOTICE using centralized messages from SERVER_MESSAGES or RESPONSES.

        Args:
            user: Recipient user object
            message_key: Key in SERVER_MESSAGES dict, or numeric code in RESPONSES
            **kwargs: Template variables for formatting

        Usage:
            await self.send_notice(user, "registrar_help")
            await self.send_notice(user, "860", usage="CONFIG GET <section.key>")
        """
        # Try SERVER_MESSAGES first (text templates)
        if message_key in SERVER_MESSAGES:
            try:
                message = SERVER_MESSAGES[message_key].format(**kwargs)
                await user.send(f":{self.servername} NOTICE {user.nickname} :{message}")
            except KeyError as e:
                logger.error(f"Missing template variable for {message_key}: {e}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :The message format is not valid")
        # Try RESPONSES (numeric codes)
        elif message_key in RESPONSES:
            await user.send(self.get_reply(message_key, user, **kwargs))
        else:
            logger.error(f"Unknown message key: {message_key}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :An internal error occurred")

    def _strip_formatting(self, text):
        """Strip mIRC/IRC formatting codes from text (for +f channels)"""
        # Remove color codes: ^C followed by optional fg,bg numbers
        import re
        text = re.sub(r'\x03(\d{1,2}(,\d{1,2})?)?', '', text)
        # Remove bold, italic, underline, reverse, reset codes
        for code in ['\x02', '\x1D', '\x1F', '\x16', '\x0F']:
            text = text.replace(code, '')
        return text

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
        logger.info(f"STAFF: {log_raw}")

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
                logger.warning(f"Banned connection refused: {user.ip} - {reason}")
                try:
                    writer.write(f"ERROR :You are banned from this server: {reason}\r\n".encode('utf-8'))
                    await writer.drain()
                except Exception:
                    pass
                writer.close()
                await writer.wait_closed()
                return

        if CONFIG.get('security', 'enable_connection_throttle', default=True):
            if not self.connection_throttle.check(user.ip):
                logger.warning(f"Throttled: {user.ip}")
                writer.close()
                await writer.wait_closed()
                return

        max_users = CONFIG.get('limits', 'max_users', default=1000)
        if len(self.users) >= max_users:
            logger.warning("Max users reached")
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
                    logger.warning(f"Connection score {score} exceeds threshold for {user.ip}")
                    try:
                        writer.write(f"ERROR :Connection refused (risk score)\r\n".encode('utf-8'))
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
                    logger.info(f"Client timeout (no data for {client_timeout}s): {user.nickname} ({user.ip})")
                    break

                if not line:
                    break
                raw = line.decode('utf-8', errors='replace').strip()
                if not raw:
                    continue
                if self.debug_mode:
                    logger.debug(f"[{user.nickname}] <<< {raw}")
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
                logger.error(f"Client error [{user.nickname}]: {e}")
                logger.error(f"Traceback: {traceback.format_exc()}")
        finally:
            await self.quit_user(user)

    async def dispatch(self, user, raw):
        parts = raw.split(' :', 1)
        args = parts[0].split()
        if not args:
            return
        cmd = args[0].upper()
        params = args[1:]
        if len(parts) > 1:
            params.append(parts[1])

        # Command aliases for convenience
        COMMAND_ALIASES = {
            'J': 'JOIN',
            'P': 'PART',
            'W': 'WHOIS',
            'M': 'MSG',
            'N': 'NICK',
            'Q': 'QUIT',
            'T': 'TOPIC',
            'K': 'KICK',
            'I': 'INVITE',
            'L': 'LIST',
            'WW': 'WHOWAS',
            'WH': 'WHISPER',
        }

        # Map alias to full command
        if cmd in COMMAND_ALIASES:
            cmd = COMMAND_ALIASES[cmd]

        user.last_activity = int(time.time())
        self.stats['commands_processed'] += 1

        # Track individual command usage (only valid ASCII commands to avoid garbage in stats)
        if cmd.isascii() and cmd.isalnum():
            if cmd not in self.stats['command_usage']:
                self.stats['command_usage'][cmd] = 0
            self.stats['command_usage'][cmd] += 1

        # Track per-user activity for historical trends
        username = user.username.lstrip('~')
        if username not in self.stats['most_active_users']:
            self.stats['most_active_users'][username] = 0
        self.stats['most_active_users'][username] += 1

        # Track per-minute command rate
        current_minute = int(time.time() / 60)
        if current_minute != self.stats['last_minute_reset']:
            # New minute - save previous minute's count and reset
            self.stats['commands_per_minute'].append(self.stats['current_minute_commands'])
            self.stats['current_minute_commands'] = 0
            self.stats['last_minute_reset'] = current_minute
        self.stats['current_minute_commands'] += 1

        # Flood protection - only apply to message commands (PRIVMSG, NOTICE, WHISPER, BROADCAST)
        # Only services are exempt
        MESSAGE_COMMANDS = ['PRIVMSG', 'NOTICE', 'WHISPER', 'BROADCAST']
        is_service = user.has_mode('s')

        if cmd in MESSAGE_COMMANDS and user.registered and not is_service:
            if CONFIG.get('security', 'enable_flood_protection', default=True):
                flood_ok = user.check_flood()
                if not flood_ok:
                    self.stats['flood_events'] += 1
                    await user.send(
                        f":{self.servername} NOTICE {user.nickname} :*** Too fast")
                    logger.warning(f"Flood: {user.nickname}")
                    return

        # Rate limiting is handled in individual command handlers
        # with appropriate error messages, not silently at dispatch level

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

        if not user.registered:
            if cmd not in ["NICK", "USER", "PASS", "IRCX", "ISIRCX", "PING", "WEBIRC"]:
                await user.send(self.get_reply("451", user))
            return

        # MFA pending - restrict commands until MFA verification is complete
        if user.pending_mfa:
            allowed_during_mfa = ["PING", "PONG", "QUIT"]
            # Allow PRIVMSG only to Registrar for MFA VERIFY command
            if cmd == "PRIVMSG" and params and params[0].lower() == "registrar":
                pass  # Allow
            elif cmd not in allowed_during_mfa:
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA verification pending. Use: PRIVMSG Registrar :MFA VERIFY <code>")
                return

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
        elif cmd == "CREATE":
            await self.handle_create(user, params)
        elif cmd == "PART":
            if not params:
                await user.send(self.get_reply("461", user, command=cmd))
                return
            for t in params[0].split(','):
                t = t.strip()
                if t:
                    await self.handle_part(user, t)
        elif cmd == "WHOIS":
            await self.handle_whois(user, params)
        elif cmd == "WHO":
            await self.handle_who(user, params)
        elif cmd == "WHOWAS":
            await self.handle_whowas(user, params)
        elif cmd in ["LIST", "LISTX"]:
            pattern = params[0] if params else None
            await self.handle_list(user, cmd == "LISTX", pattern)
        elif cmd == "TIME":
            await user.send(self.get_reply("391", user, time=time.ctime()))
        elif cmd == "VERSION":
            await user.send(self.get_reply("351", user))
        elif cmd == "JEDI":
            # Undocumented easter egg - God's response
            if "God" in self.users:
                await user.send(f":God!God@{self.servername} NOTICE {user.nickname} :That is not the command you're looking for.")
        elif cmd == "WALLOPS":
            # Undocumented easter egg - System complains about violence
            if "System" in self.users:
                await user.send(f":System!System@{self.servername} NOTICE {user.nickname} :Ouch, that hurts! Violence is not the answer.")
        elif cmd == "JOKE":
            # Undocumented easter egg - Random clean jokes
            import random
            jokes = [
                "Why don't scientists trust atoms? Because they make up everything!",
                "What do you call a bear with no teeth? A gummy bear!",
                "Why did the scarecrow win an award? He was outstanding in his field!",
                "What do you call fake spaghetti? An impasta!",
                "Why don't eggs tell jokes? They'd crack each other up!",
                "What do you call a dinosaur that crashes his car? Tyrannosaurus Wrecks!",
                "Why can't you hear a pterodactyl go to the bathroom? Because the 'P' is silent!",
                "What did the ocean say to the beach? Nothing, it just waved!",
                "Why did the math book look so sad? Because it had too many problems!",
                "What do you call a fish wearing a bowtie? Sofishticated!",
                "Why did the bicycle fall over? Because it was two-tired!",
                "What do you call a sleeping bull? A bulldozer!",
                "Why don't skeletons fight each other? They don't have the guts!",
                "What do you call cheese that isn't yours? Nacho cheese!",
                "Why couldn't the leopard play hide and seek? Because he was always spotted!",
                "What did one wall say to the other wall? I'll meet you at the corner!",
                "Why did the cookie go to the doctor? Because it felt crumbly!",
                "What do you call a snowman with a six-pack? An abdominal snowman!",
                "Why did the golfer bring two pairs of pants? In case he got a hole in one!",
                "What's orange and sounds like a parrot? A carrot!",
                "Why don't programmers like nature? It has too many bugs!",
                "What do you call a lazy kangaroo? A pouch potato!",
                "Why did the tomato turn red? Because it saw the salad dressing!",
                "What do you call a belt made of watches? A waist of time!",
                "Why did the computer go to the doctor? Because it had a virus!",
                "What do you call a can opener that doesn't work? A can't opener!",
                "Why did the stadium get hot after the game? All the fans left!",
                "What do you call a group of unorganized cats? A cat-astrophe!",
                "Why don't oysters donate to charity? Because they're shellfish!",
                "What did the grape do when it got stepped on? Nothing but let out a little wine!",
                "Why did the picture go to jail? Because it was framed!",
                "What do you call a parade of rabbits hopping backwards? A receding hare-line!",
                "Why couldn't the bicycle stand up by itself? It was two-tired!",
                "What do you call a boomerang that won't come back? A stick!",
                "Why did the coffee file a police report? It got mugged!",
                "What do you call a bear in the rain? A drizzly bear!",
                "Why don't scientists trust stairs? Because they're always up to something!",
                "What do you call a magician who loses his magic? Ian!",
                "Why did the invisible man turn down the job offer? He couldn't see himself doing it!",
                "What do you call a pile of cats? A meowtain!",
                "Why did the moon skip dinner? Because it was full!",
                "What do you call a singing laptop? A Dell!",
                "Why don't calendars ever win races? Because they only have 12 months!",
                "What do you call a cow with no legs? Ground beef!",
                "Why did the smartphone need glasses? It lost all its contacts!",
                "What do you call a chicken staring at lettuce? Chicken sees a salad!",
                "Why did the baker go to therapy? He kneaded it!",
                "What do you call a sleeping pizza? A piZZZa!",
                "Why don't trees use computers? They prefer to log in naturally!",
                "What do you call a knight who is afraid to fight? Sir Render!"
            ]
            joke = random.choice(jokes)
            await user.send(f":{self.servername} NOTICE {user.nickname} :{joke}")
        elif cmd == "AWAY":
            await self.handle_away(user, params)
        elif cmd == "TOPIC":
            await self.handle_topic(user, params)
        elif cmd == "TRANSCRIPT":
            await self.handle_transcript(user, params)
        elif cmd == "KNOCK":
            await self.handle_knock(user, params)
        elif cmd == "PROP":
            await self.handle_prop(user, params)
        elif cmd == "ACCESS":
            await self.handle_access(user, params)
        elif cmd == "EVENT":
            await self.handle_event(user, params)
        elif cmd in ["DATA", "REQUEST", "REPLY"]:
            await self.handle_data(user, params, cmd)
        elif cmd in ["PRIVMSG", "WHISPER", "NOTICE"]:
            await self.handle_msg(user, params, cmd)
        elif cmd == "KILL":
            await self.handle_kill(user, params)
        elif cmd == "KICK":
            await self.handle_kick(user, params)
        elif cmd == "INVITE":
            await self.handle_invite(user, params)
        elif cmd == "MODE":
            await self.handle_mode(user, params)
        elif cmd in ["GAG", "UNGAG"]:
            await self.handle_gag_alias(user, params, cmd == "GAG")
        elif cmd == "QUIT":
            await self.quit_user(user)
            return  # Exit dispatch to break the read loop
        elif cmd == "STATS":
            await self.handle_stats(user, params)
        elif cmd == "CONFIG":
            await self.handle_config(user, params)
        elif cmd == "STAFF":
            await self.handle_staff(user, params)
        elif cmd == "PROFANITY":
            await self.handle_profanity(user, params)
        elif cmd == "CONNECT":
            await self.handle_connect(user, params)
        elif cmd == "SQUIT":
            await self.handle_squit(user, params)
        elif cmd == "LINKS":
            await self.handle_links(user, params)
        elif cmd == "MAP":
            await self.handle_map(user, params)
        elif cmd == "ADMIN":
            await user.send(self.get_reply("256", user))
            await user.send(self.get_reply("257", user))
            await user.send(self.get_reply("258", user))
            await user.send(self.get_reply("259", user))
        elif cmd == "INFO":
            await self.handle_info(user)
        elif cmd == "HELP":
            await self.handle_help(user, params)
        elif cmd == "MOTD":
            await self.handle_motd(user)
        elif cmd == "LUSERS":
            await self.handle_lusers(user)
        elif cmd == "ISON":
            await self.handle_ison(user, params)
        elif cmd == "USERHOST":
            await self.handle_userhost(user, params)
        elif cmd == "NAMES":
            await self.handle_names(user, params)
        elif cmd == "REGISTER":
            await self.handle_register(user, params)
        elif cmd == "UNREGISTER":
            await self.handle_unregister(user, params)
        elif cmd == "AUTH":
            await self.handle_auth(user, params)
        elif cmd == "DROP":
            await self.handle_drop(user, params)
        elif cmd == "IDENTIFY":
            await self.handle_identify(user, params)
        elif cmd == "MFA":
            await self.handle_mfa(user, params)
        elif cmd == "WATCH":
            await self.handle_watch(user, params)
        elif cmd == "SILENCE":
            await self.handle_silence(user, params)
        elif cmd == "CHGPASS":
            await self.handle_chgpass(user, params)
        elif cmd == "MEMO":
            await self.handle_memo(user, params)
        else:
            await user.send(self.get_reply("421", user, command=cmd))

    async def handle_nick(self, user, params):
        if not params:
            return
        new, old = params[0], user.nickname

        # Validate nickname BEFORE any assignment - blocks sign-on if invalid
        valid, error = validate_nickname(new)
        if not valid:
            await user.send(f":{self.servername} 432 {user.nickname} {new} :{error}")
            return

        # Nick change cooldown (only for registered users, not initial sign-on)
        # SYSOPs and ADMINs are exempt from cooldown
        if user.registered and not user.is_high_staff():
            cooldown = CONFIG.get('limits', 'nick_change_cooldown', default=60)
            if cooldown > 0:
                elapsed = time.time() - user.last_nick_change
                if elapsed < cooldown:
                    remaining = int(cooldown - elapsed)
                    await user.send(f":{self.servername} NOTICE {user.nickname} :You must wait {remaining} seconds before changing nickname")
                    return

        # Check for nickname collision
        if new in self.users and self.users[new] != user:
            await user.send(self.get_reply("433", user, target=new))
            return

        if old != "*" and old in self.users and self.users[old] == user:
            del self.users[old]
        user.nickname = new
        self.users[new] = user

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
                if not (hasattr(user, 'is_remote') and user.is_remote):
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
            logger.warning(f"WEBIRC attempt from {user.ip} but WEBIRC is disabled")
            return

        password = params[0]
        gateway = params[1]
        hostname = params[2]
        client_ip = params[3]

        # Get trusted hosts configuration
        hosts_config = CONFIG.get('security', 'webirc', 'hosts', default={})
        gateway_config = hosts_config.get(gateway)

        if not gateway_config:
            logger.warning(f"WEBIRC: Unknown gateway '{gateway}' from {user.ip}")
            return

        # Verify password
        if gateway_config.get('password') != password:
            logger.warning(f"WEBIRC: Invalid password from gateway '{gateway}' at {user.ip}")
            return

        # Verify source IP is allowed
        allowed_ips = gateway_config.get('allowed_ips', [])
        if user.ip not in allowed_ips:
            logger.warning(f"WEBIRC: Gateway '{gateway}' not allowed from {user.ip}")
            return

        # Validate client IP (basic validation for IPv4/IPv6)
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            # Update user's IP and hostname to the real client values
            old_ip = user.ip
            user.ip = str(ip_obj)
            user.hostname = hostname if hostname != client_ip else str(ip_obj)
            user.webirc_gateway = gateway
            logger.info(f"WEBIRC: {gateway} spoofed {old_ip} -> {user.ip} ({user.hostname})")
        except ValueError:
            logger.warning(f"WEBIRC: Invalid client IP '{client_ip}' from gateway '{gateway}'")
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
            await user.send(f":{self.servername} 468 {user.nickname} :{error}")
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
            services_mode = CONFIG.get('services', 'mode', default='local')
            is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)

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
                            logger.info(f"SASL staff auth via trunk: {user.sasl_account} as {level}")
                    else:
                        # Trunk not available - deny staff authentication
                        logger.warning(f"SASL staff auth failed: Trunk unavailable for {user.sasl_account}")
                        auth, level = False, "USER"
                else:
                    logger.warning(f"SASL staff auth failed: Link manager not available for {user.sasl_account}")
                    auth, level = False, "USER"
            else:
                # Trunk server or local mode - authenticate locally
                try:
                    async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                        async with db.execute("SELECT level FROM users WHERE username=?",
                                             (user.sasl_account,)) as cursor:
                            row = await cursor.fetchone()
                            if row:
                                auth, level = True, row[0]
                except Exception as e:
                    if self.debug_mode:
                        logger.error(f"SASL auth lookup error: {e}")

        # Fall back to PASS-based authentication
        elif user.provided_pass:
            # Check SSL requirement for PASS-based staff authentication (configurable)
            pass_require_ssl = CONFIG.get('security', 'pass_require_ssl', default=False)
            if pass_require_ssl and not user.using_ssl:
                # Block staff auth via PASS on non-SSL connections
                logger.warning(f"PASS staff auth blocked: {user.username} ({user.ip}) - no SSL")
                # User will connect as regular user (no staff privileges)
                auth, level = False, "USER"
            else:
                # Check if we should route to trunk for authentication
                services_mode = CONFIG.get('services', 'mode', default='local')
                is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)

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
                                logger.info(f"Staff auth via trunk: {user.username} as {level}")
                        else:
                            # Trunk not available - deny authentication
                            logger.warning(f"Staff auth failed: Trunk unavailable for {user.username}")
                            auth, level = False, "USER"
                else:
                    # Trunk server or local mode - authenticate locally
                    # Try localhost admin token first (for Cockpit API)
                    if user.ip in ['127.0.0.1', '::1', '::ffff:127.0.0.1']:
                        try:
                            with open('/etc/pyircx/cockpit_admin_token', 'r') as f:
                                admin_token = f.read().strip()
                            if user.provided_pass == admin_token:
                                auth, level = True, "ADMIN"
                                logger.info(f"Cockpit admin token accepted from localhost for {user.username}")
                        except (FileNotFoundError, PermissionError, IOError):
                            pass  # Token file doesn't exist or can't be read

                    # If admin token didn't match, try normal password authentication
                    if not auth:
                        try:
                            # DEBUG: Log authentication attempt
                            logger.info(f"PASS auth attempt: username='{user.username}' ip={user.ip}")
                            row = await self.db_pool.execute_one(
                                "SELECT password_hash, level, email, realname, force_realname FROM users WHERE username=?",
                                (user.username,)
                            )
                            if row:
                                logger.info(f"PASS auth: Found staff account for '{user.username}'")
                                # Use non-blocking bcrypt check
                                if await check_password_async(user.provided_pass, row[0]):
                                    auth, level = True, row[1]
                                    user.staff_email = row[2]
                                    user.staff_realname = row[3]
                                    user.force_staff_realname = bool(row[4])
                                    self.failed_auth_tracker.record_success(user.ip)
                                    logger.info(f"PASS auth: SUCCESS for '{user.username}' as {level}")
                                else:
                                    self.failed_auth_tracker.record_failure(user.ip)
                                    logger.warning(f"PASS auth: FAILED for '{user.username}' - wrong password")
                            else:
                                logger.info(f"PASS auth: No staff account found for '{user.username}'")
                        except Exception as e:
                            logger.error(f"PASS auth error for '{user.username}': {e}")

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
            for pattern, set_by, _, reason in self.access_list['DENY']:
                if fnmatch.fnmatch(user_hostmask, pattern) or fnmatch.fnmatch(user.ip or '', pattern):
                    reason_msg = f" ({reason})" if reason else ""
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Access denied{reason_msg}")
                    await user.send(f"ERROR :Closing Link: {user.nickname} (Access denied)")
                    await self.quit_user(user)
                    return

        # Staff-only trunk mode check
        restrict_to_staff = CONFIG.get('server', 'restrict_to_staff_only', default=False)
        is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)

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
                    logger.info(f"User {user.nickname} matches ACCESS GRANT pattern: {pattern}")
                    break

            # Deny if user is neither staff nor in ACCESS GRANT
            if not is_staff and not in_access_grant:
                await user.send(f":{self.servername} NOTICE {user.nickname} :This server is restricted to authenticated staff and authorized users only")
                await user.send(f":{self.servername} NOTICE {user.nickname} :You should connect to a branch server")
                await user.send(f"ERROR :Closing Link: {user.nickname} (Staff-only server)")
                logger.info(f"Rejected non-authorized connection attempt: {user.nickname} ({user.ip})")
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
            await user.send(self.get_reply("386", user, staff_login_message=staff_msg))
            await user.send(self.get_reply("804", user))
            logger.info(f"Auth: {user.nickname} as {level}")

        await self.fire_trap("CONNECT", "USER LOGON", user)

        # Introduce user to linked servers
        if self.link_manager and self.link_manager.enabled:
            modes = user.get_mode_str()
            nick_burst = (
                f"NICK {user.nickname} 1 {int(user.signon_time)} {user.username} "
                f"{user.host} {self.servername} +{modes} :{user.realname}"
            )
            logger.info(f"Broadcasting NICK burst for {user.nickname} to linked servers: {nick_burst}")
            await self.link_manager.broadcast_to_servers(nick_burst)
            logger.info(f"NICK burst sent for {user.nickname}")

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
                await user.send(f":{self.servername} NOTICE {user.nickname} :Server-wide messaging requires IRC operator or administrator privileges")
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server-wide {msg_type} sent to {sent_count} user(s) on {self.servername}")
            return

        # WHISPER restrictions: single recipient only, 5s rate limit
        if cmd == "WHISPER":
            # WHISPER requires IRCX mode (+x)
            if not (user.has_mode('x') or user.is_ircx):
                await user.send(f":{self.servername} NOTICE {user.nickname} :WHISPER is an IRCX command. Use IRCX first to enable IRCX mode.")
                return

            if ',' in target:
                await user.send(self.get_reply("407", user, target=target))
                return
            if not user.rate_limiter.check('WHISPER'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :WHISPER rate limited (5 second cooldown)")
                return

        text = params[2] if cmd == "WHISPER" and len(params) >= 3 else params[1]

        # Validate message length
        max_msg_len = CONFIG.get('limits', 'msg_length', default=512)
        if len(text) > max_msg_len:
            text = text[:max_msg_len]
            await user.send(f":{self.servername} NOTICE {user.nickname} :Message truncated to {max_msg_len} characters")

        # Check if we need to route to services hub (centralized services mode)
        services_mode = CONFIG.get('services', 'mode', default='local')
        is_services_hub = CONFIG.get('services', 'is_services_hub', default=False)

        # List of service names that should be routed
        service_names = ['system', 'registrar', 'messenger', 'newsflash',
                        'nickserv', 'chanserv', 'memoserv'] + \
                       [bot.lower() for bot in self.servicebots.keys()]

        # If we're in centralized mode and NOT the hub, route to hub
        if services_mode == 'centralized' and not is_services_hub:
            if target.lower() in service_names:
                # Route to services hub
                if self.link_manager and self.link_manager.enabled:
                    source = f":{user.prefix()}"
                    message = f"{source} {cmd} {target} :{text}"
                    routed = await self.link_manager.route_to_services_hub(message)
                    if routed:
                        logger.debug(f"Routed service message from {user.nickname} to {target} via trunk")
                        return
                    else:
                        # Trunk not available - inform user
                        logger.warning(f"Failed to route to trunk for {target}")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Services temporarily unavailable (trunk offline)")
                        return

        # System and God - Admin-controllable mystical entities
        if target.lower() in ['system', 'god']:
            # Normalize entity name to proper capitalization
            entity_name = 'System' if target.lower() == 'system' else 'God'

            # Only IRC administrators can command these entities
            if not user.has_mode('a'):
                # Non-admins get random funny responses
                await self._mystical_entity_random_response(user, entity_name)
                return

            # Admin commands: PRIVMSG, NOTICE, KICK, KILL, HELP
            await self._handle_mystical_entity(user, entity_name, text)
            return

        # Route messages to services
        if target.lower() == 'registrar':
            await self._handle_registrar_msg(user, text)
            return
        if target.lower() == 'messenger':
            await self._handle_messenger_msg(user, text)
            return
        if target.lower() == 'newsflash':
            await self._handle_newsflash_msg(user, text)
            return

        # Traditional IRC service aliases
        if target.lower() == 'nickserv':
            # NickServ → Registrar (nickname registration)
            await self._handle_registrar_msg(user, text)
            return
        if target.lower() == 'chanserv':
            # ChanServ → Registrar (channel registration)
            await self._handle_registrar_msg(user, text)
            return
        if target.lower() == 'memoserv':
            # MemoServ → Messenger (offline messages)
            await self._handle_messenger_msg(user, text)
            return

        # Other service aliases - provide help information
        other_services = {
            'operserv': 'OperServ',
            'helpserv': 'HelpServ',
            'infoserv': 'InfoServ',
            'botserv': 'BotServ',
            'hostserv': 'HostServ',
            'statserv': 'StatServ',
            'global': 'Global',
            'alis': 'ALIS',
            'services': 'Services'
        }
        if target.lower() in other_services:
            service_name = other_services[target.lower()]
            await self._service_reply(service_name, user, f"pyIRCX {service_name} Service")
            await self._service_reply(service_name, user, "This service is currently implemented as an alias.")
            await self._service_reply(service_name, user, "Available services:")
            await self._service_reply(service_name, user, "  Registrar/NickServ - Nickname registration (/msg Registrar HELP)")
            await self._service_reply(service_name, user, "  Registrar/ChanServ - Channel registration (/msg Registrar HELP)")
            await self._service_reply(service_name, user, "  Messenger/MemoServ - Offline messages (/msg Messenger HELP)")
            await self._service_reply(service_name, user, "  NewsFlash - Network announcements (/msg NewsFlash HELP)")
            await self._service_reply(service_name, user, "  ServiceBot## - Channel moderation (/msg ServiceBot01 HELP)")
            await self._service_reply(service_name, user, "For full command list: /HELP")
            return

        # Check if target is a ServiceBot (case-insensitive)
        for botname in self.servicebots:
            if target.lower() == botname.lower():
                await self._handle_servicebot_msg(user, text, botname)
                return

        source = f":{user.prefix()}"
        out = f"{source} {cmd} {target} {params[1] + ' ' if cmd in ['WHISPER', 'DATA'] and len(params) > 2 else ''}:{text}"

        # High staff wildcard broadcast (PRIVMSG/NOTICE * only)
        if target == '*':
            if cmd not in ['PRIVMSG', 'NOTICE']:
                return
            if not user.is_high_staff():
                await user.send(self.get_reply("481", user))
                return

            # Rate limit broadcasts to prevent abuse (max 10 per minute)
            if not user.check_rate_limit('BROADCAST'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Broadcast rate limit exceeded. Please wait before sending another broadcast.")
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
        recipient = self.users.get(target)
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

            # Check if recipient is a remote user
            if hasattr(recipient, 'is_remote') and recipient.is_remote:
                # Route to linked servers for remote user delivery
                if self.link_manager and self.link_manager.enabled:
                    await self.link_manager.broadcast_to_servers(out)
            else:
                # Local user - send directly
                await recipient.send(out)
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
                await user.send(self.get_reply("404", user, channel=chan_name))
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
                    await user.send(self.get_reply("404", user, channel=chan_name))
                    return
            if user.nickname in channel.gagged:
                return
            # Channel mode +w: no whispers allowed
            if cmd == "WHISPER" and channel.modes.get('w', False):
                await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot send whispers in {chan_name} (+w)")
                return

            # WHISPER to channel is private message to a specific user in channel
            # Format: WHISPER #channel targetuser :message
            if cmd == "WHISPER":
                if len(params) < 3:
                    await user.send(self.get_reply("461", user, command="WHISPER"))
                    return
                target_nick = params[1]
                # Check if target is in channel
                if not channel.has_member(target_nick):
                    await user.send(self.get_reply("441", user, target=target_nick, channel=chan_name))
                    return
                # Find the target user
                target_user = self.users.get(target_nick)
                if not target_user:
                    await user.send(self.get_reply("401", user, target=target_nick))
                    return
                # Send to target (local or route to remote server)
                whisper_out = f"{source} WHISPER {chan_name} {target_nick} :{text}"
                if hasattr(target_user, 'is_remote') and target_user.is_remote:
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
            # Broadcast to LOCAL channel members only (exclude remote users to avoid routing loops)
            for member in channel.members.values():
                if member != user and not (hasattr(member, 'is_remote') and member.is_remote):
                    await member.send(chan_out)
            # Propagate channel message to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    await self.link_manager.broadcast_to_servers(chan_out)
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
            # Target not found locally - try routing to linked servers
            if self.link_manager and self.link_manager.enabled:
                # Route to all linked servers (they'll determine if they have the target)
                await self.link_manager.broadcast_to_servers(out)
            else:
                # No linked servers or target not found anywhere
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :{cmd} is an IRCX command. Use IRCX first to enable IRCX mode.")
            return

        if len(params) < 3:
            await user.send(f":{self.servername} 461 {user.nickname} {cmd} :Not enough parameters")
            return

        targets_str = params[0]
        tag = params[1]
        message = params[2]

        # Split comma-separated targets
        targets = [t.strip() for t in targets_str.split(',') if t.strip()]
        if not targets:
            await user.send(f":{self.servername} 461 {user.nickname} {cmd} :No valid targets specified")
            return

        # Validate tag format
        # Valid characters: [A-Za-z0-9.]
        # Must start with letter
        # Max 15 characters
        if not tag or len(tag) > 15:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid tag: must be 1-15 characters")
            return

        if not tag[0].isalpha():
            await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid tag: must start with a letter")
            return

        import re
        if not re.match(r'^[A-Za-z][A-Za-z0-9.]*$', tag):
            await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid tag: only letters, numbers, and periods allowed")
            return

        # Check reserved prefix permissions
        tag_upper = tag.upper()

        # ADM.* requires IRC administrator
        if tag_upper.startswith('ADM.'):
            if not user.has_mode('a'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Tag prefix ADM.* requires IRC administrator privileges (+a)")
                return

        # SYS.* requires IRC operator
        elif tag_upper.startswith('SYS.'):
            if not user.has_mode('o'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Tag prefix SYS.* requires IRC operator privileges (+o)")
                return

        # GDE.* requires IRC guide
        elif tag_upper.startswith('GDE.'):
            if not user.has_mode('g'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Tag prefix GDE.* requires IRC guide privileges (+g)")
                return

        # OWN.* and HST.* require channel context - validate for all channel targets
        if tag_upper.startswith(('OWN.', 'HST.')):
            # Check if any target is a channel
            has_channel = any(is_channel(t) for t in targets)
            if not has_channel:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Tag prefix {tag_upper[:3]}* can only be used with channel targets")
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
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Tag prefix OWN.* requires channel owner status (+q) in {chan_name}")
                            return

                    # HST.* requires channel host
                    elif tag_upper.startswith('HST.'):
                        if user.nickname not in channel.hosts and user.nickname not in channel.owners and not user.is_high_staff():
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Tag prefix HST.* requires channel host status (+o) in {chan_name}")
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
                    if not (hasattr(user, 'is_remote') and user.is_remote):
                        unmasked_prefix = f"{user.nickname}!{user.username}@{user.host}"
                        server_msg = f":{unmasked_prefix} {cmd} {chan_name} {tag} :{message}"
                        await self.link_manager.broadcast_to_servers(server_msg)

            else:
                # Direct message to user
                target_user = self.users.get(target)
                if not target_user:
                    await user.send(self.get_reply("401", user, target=target))
                    continue

                # Only send to IRCX-enabled clients
                if not (target_user.has_mode('x') or target_user.is_ircx):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{target} does not support IRCX")
                    continue

                # Target user sees appropriately masked host
                prefix = user.prefix(viewer=target_user)
                data_msg = f":{prefix} {cmd} {target} {tag} :{message}"
                await target_user.send(data_msg)

    async def handle_who(self, user, params):
        target = params[0] if params else "*"
        is_staff = user.is_staff()
        is_high_staff = user.is_high_staff()  # SYSOP or ADMIN

        # WHO * (all users) restricted to SYSOP/ADMIN only
        if target == "*":
            if not is_high_staff:
                await user.send(f":{self.servername} NOTICE {user.nickname} :WHO * requires IRC operator or administrator privileges. Use a pattern like *nick* instead.")
                await user.send(self.get_reply("315", user, target=target))
                return
            # Rate limit for full WHO
            if not user.rate_limiter.check('WHO'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :WHO rate limited")
                await user.send(self.get_reply("315", user, target=target))
                return
            # Return all visible users (staff can see ServiceBots)
            for member in self.users.values():
                # Skip virtual users unless requester is high staff (ADMIN/SYSOP)
                if member.is_virtual and not is_high_staff:
                    continue
                if member.has_mode('i') and not is_high_staff and user != member:
                    continue
                flags = "G" if member.away_msg else "H"
                if member.has_mode('i'):
                    flags += "i"
                if member.has_mode('x') or member.is_ircx:
                    flags += "x"
                if member.has_mode('r'):
                    flags += "r"
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
                # Staff see real IP, non-staff see masked host
                display_host = member.ip if is_staff else mask_host(member.host, False)
                await user.send(self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            await user.send(self.get_reply("315", user, target=target))
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
                    await user.send(f":{self.servername} NOTICE {user.nickname} :WHO results truncated at {max_results}")
                    break
                flags = "G" if member.away_msg else "H"
                if member.has_mode('i') and (is_staff or user == member):
                    flags += "i"
                if member.has_mode('x') or member.is_ircx:
                    flags += "x"
                if member.has_mode('r'):
                    flags += "r"
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
                # Staff see real IP, non-staff see masked host
                display_host = member.ip if is_staff else mask_host(member.host, False)
                await user.send(self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            await user.send(self.get_reply("315", user, target=target))
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
                flags = "G" if member.away_msg else "H"
                if member.has_mode('i'):
                    flags += "i"
                if member.has_mode('x') or member.is_ircx:
                    flags += "x"
                if member.has_mode('r'):
                    flags += "r"
                if user.is_ircx:
                    if member.has_mode('G'):
                        flags += "G"
                    elif member.has_mode('S'):
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
                    if member.has_mode('G') or member.has_mode('S'):
                        flags += "*"
                    elif member.has_mode('s'):
                        flags += "*"
                    elif member.is_high_staff():
                        flags += "*"
                # Staff always see real IP in WHO results
                display_host = member.ip
                await user.send(self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            await user.send(self.get_reply("315", user, target=target))
            return

        # Check if target is a channel
        channel, chan_name = self.get_channel(target)
        if channel:
            for nick in channel.members:
                member = channel.members[nick]

                # Base flag: H (here) or G (gone/away)
                flags = "G" if member.away_msg else "H"

                # Invisible flag - only show if requester is staff or is the member
                if member.has_mode('i'):
                    if is_staff or user == member:
                        flags += "i"

                # IRCX mode flag
                if member.has_mode('x') or member.is_ircx:
                    flags += "x"

                # Registered nickname flag
                if member.has_mode('r'):
                    flags += "r"

                # Staff/operator flags depend on IRCX mode
                if user.is_ircx:
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
                await user.send(self.get_reply("352", user, channel=chan_name, ident=member.username,
                                        host=display_host, target=nick, flags=flags, real=member.realname))
            await user.send(self.get_reply("315", user, target=chan_name))
            return

        # Check if target is a specific user (case-insensitive nickname match)
        member = self.users.get(target)
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
                    await user.send(self.get_reply("352", user, channel="*", ident=member.username,
                                            host=display_host, target=member.nickname, flags=flags, real=member.realname))

        await user.send(self.get_reply("315", user, target=target))

    async def handle_whois(self, user, params):
        if not params:
            return
        for target_nick in params[0].split(','):
            # Case-insensitive user lookup
            target = self.users.get(target_nick)
            if not target:
                # Try case-insensitive search
                target_lower = target_nick.lower()
                for nick, usr in self.users.items():
                    if nick.lower() == target_lower:
                        target = usr
                        target_nick = nick  # Use actual nickname for display
                        break

            # Reserved service names that don't exist redirect to System
            if not target and is_reserved_service(target_nick):
                target = self.users.get('System')
                if target:
                    await user.send(self.get_reply("311", user, target=target_nick, ident='Services',
                                             host=self.servername, real=f"Alias for {target.nickname}"))
                    await user.send(self.get_reply("312", user, target=target_nick))
                    await user.send(self.get_reply("313", user, target=target_nick, role="is a network service"))
                    await user.send(self.get_reply("318", user, target=target_nick))
                    continue

            if not target:
                # Route WHOIS query to linked servers if target not found locally
                if self.link_manager and self.link_manager.enabled:
                    whois_msg = f":{user.prefix()} WHOIS {target_nick}"
                    await self.link_manager.broadcast_to_servers(whois_msg)
                # Still send error to user (remote server will send replies directly if found)
                await user.send(self.get_reply("401", user, target=target_nick))
                continue
            # Apply host masking (staff see real, non-staff see masked)
            display_host = mask_host(target.host, user.is_staff())
            await user.send(self.get_reply("311", user, target=target.nickname, ident=target.username,
                                     host=display_host, real=target.realname))
            if target.channels:
                chan_list = " ".join(target.channels)
                await user.send(self.get_reply(
                    "319", user, target=target.nickname, channels=chan_list))
            await user.send(self.get_reply("312", user, target=target.nickname))

            # Mystical and staff roles (priority order)
            if target.has_mode('S'):  # Omnipresent System (undeclared)
                role = "has an omnipresence"
            elif target.has_mode('G'):  # Divine God (undeclared)
                role = "is watching over you"
            elif target.is_service():  # Regular services
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
                await user.send(self.get_reply(
                    "313", user, target=target.nickname, role=role))

            # Show registered nickname status
            if target.has_mode('r'):
                await user.send(f":{self.servername} 307 {user.nickname} {target.nickname} :has identified for this nickname")

            if target.away_msg:
                await user.send(self.get_reply(
                    "301", user, target=target.nickname, message=target.away_msg))

            idle = int(time.time() - target.last_activity)
            await user.send(self.get_reply("317", user, target=target.nickname,
                      idle=idle, signon=target.signon_time))

            if user.is_staff():
                # Staff see IP with optional DNS lookup
                ip_info = target.ip
                try:
                    # Attempt reverse DNS lookup (2 second timeout)
                    import socket
                    hostname = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None, socket.gethostbyaddr, target.ip
                        ),
                        timeout=2.0
                    )
                    hostname = hostname[0]  # Primary hostname
                    ip_info = f"{target.ip} ({hostname})"
                except:
                    # DNS failed/timeout - just show IP
                    pass
                await user.send(self.get_reply(
                    "320", user, target=target.nickname, ip=ip_info))

            await user.send(self.get_reply("318", user, target=target.nickname))

    async def handle_whowas(self, user, params):
        # Rate limit WHOWAS lookups
        if not user.rate_limiter.check('WHOWAS'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :WHOWAS rate limited")
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

    async def handle_list(self, user, is_listx=False, pattern=None):
        # Rate limit LIST/LISTX commands
        if not user.rate_limiter.check('LIST'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :LIST rate limited")
            return

        # LISTX requires IRCX mode (+x)
        if is_listx and not (user.has_mode('x') or user.is_ircx):
            await user.send(f":{self.servername} NOTICE {user.nickname} :LISTX is an IRCX command. Use IRCX first to enable IRCX mode.")
            return

        is_staff = user.is_staff()

        if is_listx:
            await user.send(self.get_reply("811", user))
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

                await user.send(self.get_reply("812", user, channel=name, users=len(channel.members),
                                         modes=mode_str, topic=channel.topic or ""))
            await user.send(self.get_reply("813", user))
        else:
            await user.send(self.get_reply("321", user))
            for name, channel in self.channels.items():
                # Hide +s (secret) and +h (hidden) channels from non-staff unless they're in it
                if (channel.modes.get('s', False) or channel.modes.get('h', False)) and not is_staff and user.nickname not in channel.members:
                    continue
                # Apply pattern filter if provided
                if pattern and not fnmatch.fnmatch(name.lower(), pattern.lower()):
                    continue
                await user.send(self.get_reply("322", user, channel=name, users=len(channel.members),
                                         topic=channel.topic or ""))
            await user.send(self.get_reply("323", user))

    async def handle_join(self, user, channel_name, key=None):
        is_staff = user.is_staff()

        # Validate channel name
        valid, error = validate_channel_name(channel_name)
        if not valid:
            await user.send(f":{self.servername} 479 {user.nickname} {channel_name} :{error}")
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
            if channel.modes.get('l') and channel.user_limit:
                if len(channel.members) >= channel.user_limit:
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
        await user.send(f":{self.servername} 324 {user.nickname} {chan_name} +{modes}{param_str}")
        
        # Broadcast JOIN to LOCAL channel members with host masking
        # (exclude remote users to avoid routing loops)
        tasks = []
        for member in channel.members.values():
            if member != user and not (hasattr(member, 'is_remote') and member.is_remote):
                # Each viewer sees appropriately masked host
                prefix = user.prefix(viewer=member)
                msg = f":{prefix} JOIN {chan_name}"
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Propagate JOIN to linked servers (if not a remote user) - use unmasked prefix
        if self.link_manager and self.link_manager.enabled:
            if not (hasattr(user, 'is_remote') and user.is_remote):
                server_msg = f":{user.prefix()} JOIN {chan_name}"
                logger.info(f"Propagating JOIN to linked servers: {server_msg}")
                await self.link_manager.broadcast_to_servers(server_msg)
                logger.info(f"JOIN propagated for {user.nickname} to {chan_name}")

        # Fire MEMBER/JOIN event for monitoring
        await self.fire_trap("MEMBER", "JOIN", user, chan_name)

        # Broadcast MODE after JOIN so other clients see the user first
        if grant_owner:
            mode_msg = f":{user.prefix()} MODE {chan_name} +q {user.nickname}"
            for member in channel.members.values():
                if not (hasattr(member, 'is_remote') and member.is_remote):
                    await member.send(mode_msg)
            # Propagate MODE to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    await self.link_manager.broadcast_to_servers(mode_msg)
        elif grant_host:
            mode_msg = f":{user.prefix()} MODE {chan_name} +o {user.nickname}"
            for member in channel.members.values():
                if not (hasattr(member, 'is_remote') and member.is_remote):
                    await member.send(mode_msg)
            # Propagate MODE to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    await self.link_manager.broadcast_to_servers(mode_msg)
        elif grant_voice:
            mode_msg = f":{user.prefix()} MODE {chan_name} +v {user.nickname}"
            for member in channel.members.values():
                if not (hasattr(member, 'is_remote') and member.is_remote):
                    await member.send(mode_msg)
            # Propagate MODE to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :CREATE is an IRCX command. Use IRCX first to enable IRCX mode.")
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
            await user.send(f":{self.servername} 479 {user.nickname} {channel_name} :{error}")
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
                await user.send(f":{self.servername} 926 {user.nickname} {channel_name} :Channel already exists (cannot CREATE with +c flag)")
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
                # Just join it
                await self.handle_join(user, channel_name, None)
                return
            else:
                # Create new dynamic channel
                channel = Channel(chan_name)
                self.channels[chan_name] = channel

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
            if member != user and not (hasattr(member, 'is_remote') and member.is_remote):
                await member.send(join_msg)

        # Propagate JOIN to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (hasattr(user, 'is_remote') and user.is_remote):
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
                        # User limit
                        try:
                            limit = int(arg)
                            if limit > 0:
                                channel.user_limit = limit
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
            if not (hasattr(member, 'is_remote') and member.is_remote):
                # Each viewer sees appropriately masked host
                prefix = user.prefix(viewer=member)
                msg = f":{prefix} PART {chan_name}"
                tasks.append(member.send(msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # Propagate PART to linked servers (if not a remote user) - use unmasked prefix
        if self.link_manager and self.link_manager.enabled:
            if not (hasattr(user, 'is_remote') and user.is_remote):
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

    async def handle_away(self, user, params):
        if params:
            user.away_msg = params[0].lstrip(':')
            await user.send(self.get_reply("306", user))
            # Propagate AWAY status to linked servers
            if self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    away_msg = f":{user.prefix()} AWAY :{user.away_msg}"
                    await self.link_manager.broadcast_to_servers(away_msg)
        else:
            user.away_msg = None
            await user.send(self.get_reply("305", user))
            # Propagate AWAY removal (no message = back from away)
            if self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    away_msg = f":{user.prefix()} AWAY"
                    await self.link_manager.broadcast_to_servers(away_msg)


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
                if not (hasattr(member, 'is_remote') and member.is_remote):
                    await member.send(msg)
            # Propagate TOPIC to linked servers (if not a remote user)
            if self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    await self.link_manager.broadcast_to_servers(msg)

            # Fire CHANNEL/TOPIC event for monitoring
            await self.fire_trap("CHANNEL", "TOPIC", user, chan_name)

            # Log to transcript if +y mode is enabled
            self.log_transcript(channel, "TOPIC", user, message=new_topic)
            logger.info(f"Topic set in {chan_name} by {user.nickname}")

    async def handle_transcript(self, user, params):
        """
        Handle TRANSCRIPT command to view channel transcript logs.

        Syntax:
            TRANSCRIPT #channel [lines] [offset]

        Requires: Channel owner/host or staff (+o/+a) to view
        The channel must have +y mode enabled.
        """
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :{chan_name} does not have transcript mode (+y) enabled")
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :No transcript available for {channel_name}")
            return

        # Send transcript header
        await user.send(f":{self.servername} NOTICE {user.nickname} :=== Transcript for {channel_name} ({len(transcript_lines)} lines) ===")

        # Send each line
        for line in transcript_lines:
            await user.send(f":{self.servername} NOTICE {user.nickname} :{line}")

        # Send transcript footer
        await user.send(f":{self.servername} NOTICE {user.nickname} :=== End of transcript ===")

    async def handle_knock(self, user, params):
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
            await user.send(f":{self.servername} 714 {user.nickname} {chan_name} :You are already on that channel")
            return

        if not channel.modes.get('i'):
            await user.send(f":{self.servername} 713 {user.nickname} {chan_name} :Channel is open")
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
                await user.send(f":{self.servername} 716 {user.nickname} {chan_name} :User is in knock mode (+u)")
                return

        now = time.time()
        last_knock = channel.knock_cooldowns.get(user.nickname, 0)
        if now - last_knock < 60:
            await user.send(f":{self.servername} 712 {user.nickname} {chan_name} :You have sent too many knock requests. Please wait before trying again.")
            return
        channel.knock_cooldowns[user.nickname] = now

        knock_msg = f":{self.servername} 710 {chan_name} {user.nickname} {user.prefix()} :has asked for an invite"
        if message:
            knock_msg = f":{self.servername} 710 {chan_name} {user.nickname} {user.prefix()} :has asked for an invite ({message})"

        # Send to LOCAL owners/hosts only
        for nick in channel.members:
            if nick in channel.owners or nick in channel.hosts:
                member = channel.members[nick]
                if not (hasattr(member, 'is_remote') and member.is_remote):
                    await member.send(knock_msg)

        # Propagate KNOCK to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (hasattr(user, 'is_remote') and user.is_remote):
                knock_cmd = f":{user.prefix()} KNOCK {chan_name}"
                if message:
                    knock_cmd += f" :{message}"
                await self.link_manager.broadcast_to_servers(knock_cmd)

        await user.send(f":{self.servername} 711 {user.nickname} {chan_name} :Your KNOCK has been delivered")

    async def handle_prop(self, user, params):
        # Require IRCX mode (+x)
        if not (user.has_mode('x') or user.is_ircx):
            await user.send(f":{self.servername} NOTICE {user.nickname} :PROP is an IRCX command. Use IRCX first to enable IRCX mode.")
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
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Only channel owners can view OWNERKEY")
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :Property {prop_name} is read-only")
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
        logger.info(f"PROP {chan_name} {prop_name}={prop_value} by {user.nickname}")

        # Propagate PROP command to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (hasattr(user, 'is_remote') and user.is_remote):
                prop_cmd = f":{user.prefix()} PROP {' '.join(params)}"
                await self.link_manager.broadcast_to_servers(prop_cmd)

    async def handle_invite(self, user, params):
        if len(params) < 2:
            await user.send(self.get_reply("461", user, command="INVITE"))
            return

        target_nick = params[0]
        channel_name = params[1]

        # Case-insensitive nickname lookup
        target = self.users.get(target_nick)
        if not target:
            # Try case-insensitive search
            target_lower = target_nick.lower()
            for nick, usr in self.users.items():
                if nick.lower() == target_lower:
                    target = usr
                    target_nick = nick  # Use the actual nickname for subsequent checks
                    break

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
                await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot send invitations in {chan_name} (+j)")
                return

        if channel.modes.get('i'):
            if not (user.nickname in channel.owners or
                    user.nickname in channel.hosts or
                    user.has_mode('a')):
                await user.send(self.get_reply("482", user, target=chan_name))
                return

        if target_nick in channel.members:
            await user.send(f":{self.servername} 443 {user.nickname} {target_nick} {chan_name} :is already on channel")
            return

        # ServiceBot dispatcher - pick available bot from pool
        if target_nick == "ServiceBot":
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
                await user.send(f":{self.servername} NOTICE {user.nickname} :All ServiceBots are at maximum capacity. Try /INVITE ServiceBotXX #channel directly.")
                return

            bot_name, bot = available_bot
            # Auto-join the available bot
            channel.members[bot_name] = bot
            bot.channels.add(chan_name)
            # Services always get +q (owner)
            channel.owners.add(bot_name)
            await channel.broadcast(f":{bot.prefix()} JOIN {chan_name}")
            await channel.broadcast(f":{self.servername} MODE {chan_name} +q {bot_name}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Dispatched {bot_name} to {chan_name}")
            logger.info(f"ServiceBot dispatcher assigned {bot_name} to {chan_name} via INVITE from {user.nickname}")
            return

        # ServiceBot invitation - Staff only (guide/operator/administrator)
        if target_nick in self.servicebots:
            if not user.is_staff():
                await user.send(self.get_reply("848", user))
                return
            bot = self.servicebots[target_nick]
            max_chans = getattr(bot, 'max_channels', 10)
            if len(bot.channels) >= max_chans:
                await user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has reached max channels ({max_chans})")
                return
            # ServiceBot joins the channel automatically
            channel.members[target_nick] = bot
            bot.channels.add(chan_name)
            # Services always get +q (owner)
            channel.owners.add(target_nick)
            await channel.broadcast(f":{bot.prefix()} JOIN {chan_name}")
            await channel.broadcast(f":{self.servername} MODE {chan_name} +q {target_nick}")
            await user.send(self.get_reply("341", user, target=target_nick, channel=chan_name))
            logger.info(f"ServiceBot {target_nick} joined {chan_name} via INVITE from {user.nickname} (granted +q)")
            return

        # System and God mystical entities - Auto-join like ServiceBots (silent observers)
        if target_nick.lower() in ['system', 'god']:
            # Normalize entity name to proper capitalization
            entity_name = 'System' if target_nick.lower() == 'system' else 'God'
            target = self.users.get(entity_name)

            # Only admins can invite mystical entities
            if not user.has_mode('a'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Only IRC administrators can invite {entity_name}")
                return

            # Auto-join the entity to the channel
            channel.members[entity_name] = target
            target.channels.add(chan_name)
            # Mystical entities get +q (owner) but remain silent observers
            channel.owners.add(entity_name)
            await channel.broadcast(f":{target.prefix()} JOIN {chan_name}")
            await channel.broadcast(f":{self.servername} MODE {chan_name} +q {entity_name}")
            await user.send(self.get_reply("341", user, target=entity_name, channel=chan_name))
            logger.info(f"{entity_name} joined {chan_name} via INVITE from {user.nickname} (granted +q)")
            return

        target.invited_to.add(chan_name)
        await user.send(self.get_reply("341", user, target=target_nick, channel=chan_name))

        # Send INVITE to target (local or route to remote server)
        invite_msg = f":{user.prefix()} INVITE {target_nick} :{chan_name}"
        if hasattr(target, 'is_remote') and target.is_remote:
            # Target is on a remote server, route through link manager
            if self.link_manager and self.link_manager.enabled:
                await self.link_manager.broadcast_to_servers(invite_msg)
        else:
            # Target is local, send directly
            await target.send(invite_msg)

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
        # Require IRCX mode (+x)
        if not (user.has_mode('x') or user.is_ircx):
            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS is an IRCX command. Use IRCX first to enable IRCX mode.")
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
                await user.send(self.get_reply("481", user))
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

        if action == "LIST":
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

            await user.send(f":{self.servername} 803 {user.nickname} {target_name} :Start of access list")
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
                    await user.send(f":{self.servername} 804 {user.nickname} {target_name} {level} {mask} {set_by}{timeout_str}{reason_str}")
            await user.send(f":{self.servername} 805 {user.nickname} {target_name} :End of access list")

        elif action == "ADD":
            if len(params) < 4:
                await user.send(self.get_reply("461", user, command="ACCESS ADD"))
                return

            level = params[2].upper()
            if level not in valid_levels:
                await self.send_notice(user, "850", levels=', '.join(valid_levels))
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
                    await user.send(f":{self.servername} NOTICE {user.nickname} :This mask {mask} is already in the {level} list")
                    return

            # Cannot add services to DENY lists
            if level == 'DENY':
                import fnmatch
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
                    async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                        await db.execute(
                            "INSERT INTO server_access (type, pattern, set_by, set_at, timeout, reason) VALUES (?, ?, ?, ?, ?, ?)",
                            (level, mask, user.nickname, timestamp, timeout, reason)
                        )
                        await db.commit()
                except Exception as e:
                    logger.error(f"ACCESS ADD DB error: {e}")

            timeout_str = f" for {params[4]} minutes" if timeout > 0 else ""
            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS {level} added to {target_name}: {mask}{timeout_str}")
            logger.info(f"ACCESS {target_name} ADD {level} {mask} by {user.nickname}")

            # Propagate ACCESS command to linked servers (for channels only)
            if not is_server_access and self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    access_cmd = f":{user.prefix()} ACCESS {' '.join(params)}"
                    await self.link_manager.broadcast_to_servers(access_cmd)

        elif action in ("DELETE", "DEL"):
            if len(params) < 4:
                await user.send(self.get_reply("461", user, command="ACCESS DELETE"))
                return

            level = params[2].upper()
            if level not in valid_levels:
                await self.send_notice(user, "850", levels=', '.join(valid_levels))
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
                await user.send(f":{self.servername} NOTICE {user.nickname} :Mask {mask} was not found in the {level} list")
                return

            # For server access, remove from database
            if is_server_access:
                try:
                    async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                        await db.execute(
                            "DELETE FROM server_access WHERE type = ? AND pattern = ?",
                            (level, mask)
                        )
                        await db.commit()
                except Exception as e:
                    logger.error(f"ACCESS DEL DB error: {e}")

            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS {level} removed from {target_name}: {mask}")
            logger.info(f"ACCESS {target_name} DEL {level} {mask} by {user.nickname}")

            # Propagate ACCESS DELETE to linked servers (for channels only)
            if not is_server_access and self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    access_cmd = f":{user.prefix()} ACCESS {' '.join(params)}"
                    await self.link_manager.broadcast_to_servers(access_cmd)

        elif action == "CLEAR":
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
                    async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                        if level:
                            await db.execute("DELETE FROM server_access WHERE type = ?", (level,))
                        else:
                            await db.execute("DELETE FROM server_access")
                        await db.commit()
                except Exception as e:
                    logger.error(f"ACCESS CLEAR DB error: {e}")

            level_str = level if level else "all levels"
            await user.send(f":{self.servername} NOTICE {user.nickname} :Cleared {cleared} entries from {target_name} ({level_str})")

            # Propagate ACCESS CLEAR to linked servers (for channels only)
            if not is_server_access and self.link_manager and self.link_manager.enabled:
                if not (hasattr(user, 'is_remote') and user.is_remote):
                    access_cmd = f":{user.prefix()} ACCESS {' '.join(params)}"
                    await self.link_manager.broadcast_to_servers(access_cmd)
            logger.info(f"ACCESS {target_name} CLEAR {level_str} by {user.nickname}")

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
            await user.send(f":{self.servername} NOTICE {user.nickname} :STATS rate limited")
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== STATS Help ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Generally available flags:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  u - Server uptime and version")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  s - Online staff listing")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  i - Invisible users count")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  x - IRCX users count")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  w - Authenticated users count")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  y - Anonymous users count")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  c - Server configuration summary")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  f - Flood protection status")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  n - Network statistics")

            # Show guide/staff flags only if user is staff
            if user.is_staff() or user.is_high_staff():
                await user.send(f":{self.servername} NOTICE {user.nickname} :IRC guide or staff flags:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  a - Online IRC administrators")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  o - Online IRC operators")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  g - Online IRC guides")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  b - ServiceBot statistics")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  z - Gagged users listing")

            # Show operator/administrator flags only if user is operator or administrator
            if user.is_high_staff():
                await user.send(f":{self.servername} NOTICE {user.nickname} :IRC operator or administrator flags:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  d - Database statistics")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  k - Bans and access lists")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  l - Server linking statistics")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  m - Message/command statistics")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  p - Peak usage statistics")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  t - SSL/TLS certificate status")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  v - Command usage statistics")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  * - All statistics combined")

            await user.send(f":{self.servername} NOTICE {user.nickname} :=== End of STATS Help ===")
            await user.send(self.get_reply("219", user, flag=flag if flag else '?'))
            return

        # STATS * - All stats combined (Operator+ only)
        if flag == '*':
            if not user.is_high_staff():
                await user.send(f":{self.servername} NOTICE {user.nickname} :STATS * requires IRC operator or administrator privileges")
                await user.send(self.get_reply("219", user, flag=flag))
                return

            await user.send(f":{self.servername} NOTICE {user.nickname} :=== STATS * - Full Statistics ===")

            # Uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            secs = uptime_secs % 60
            await user.send(f":{self.servername} NOTICE {user.nickname} :Uptime: {days}d {hours}:{mins:02d}:{secs:02d}")

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

            await user.send(f":{self.servername} NOTICE {user.nickname} :--- User Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Total users: {user_stats['total']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Invisible (+i): {user_stats['invisible']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  IRCX (+x): {user_stats['ircx']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Authenticated: {user_stats['auth']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Anonymous (~): {user_stats['anon']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Gagged (+z): {user_stats['gagged']}")

            # Staff counts (already collected above)

            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Staff Online ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  IRC administrators: {user_stats['admins']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  IRC operators: {user_stats['sysops']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  IRC guides: {user_stats['guides']}")

            # Channel stats - Single iteration for performance
            chan_stats = {'global': 0, 'local': 0, 'registered': 0}
            for c in self.channels.values():
                if c.name.startswith('&'):
                    chan_stats['local'] += 1
                else:
                    chan_stats['global'] += 1
                if c.registered:
                    chan_stats['registered'] += 1

            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Channel Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Global channels (#): {chan_stats['global']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Local channels (&): {chan_stats['local']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Registered: {chan_stats['registered']}")

            # Access lists
            deny_count = len(self.access_list['DENY'])
            grant_count = len(self.access_list['GRANT'])

            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Access Lists ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  ACCESS DENY: {deny_count}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  ACCESS GRANT: {grant_count}")

            # Server stats
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Server Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Commands processed: {self.stats.get('commands_processed', 0)}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Total connections: {self.stats.get('total_connections', 0)}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Max users seen: {self.max_users_seen}")

            # Command usage (all commands)
            if self.stats.get('command_usage'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- Command Usage ---")
                sorted_cmds = sorted(self.stats['command_usage'].items(), key=lambda x: x[1], reverse=True)
                for cmd, count in sorted_cmds:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  {cmd}: {count}")

            # Peak usage
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Peak Usage ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Peak users: {self.stats['peak_users']}")
            if self.stats['peak_time']:
                import datetime
                peak_dt = datetime.datetime.fromtimestamp(self.stats['peak_time'])
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Peak time: {peak_dt.strftime('%Y-%m-%d %H:%M:%S')}")

            # Flood protection
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Flood Protection ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Flood events: {self.stats['flood_events']}")
            flood_msgs = CONFIG.get('security', 'flood_messages', default=5)
            flood_window = CONFIG.get('security', 'flood_window', default=2.0)
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Threshold: {flood_msgs} msgs per {flood_window}s")

            # Message statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Message Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Total messages: {self.stats['messages_sent']}")
            if self.stats.get('messages_by_channel'):
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Active channels by messages:")
                sorted_channels = sorted(self.stats['messages_by_channel'].items(), key=lambda x: x[1], reverse=True)
                for channel, count in sorted_channels:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :    {channel}: {count}")

            # ServiceBot statistics
            if CONFIG.get('servicebot', 'enabled', default=True):
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- ServiceBot Statistics ---")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Active bots: {len(self.servicebots)}")
                if self.stats.get('servicebot_violations'):
                    total_violations = sum(self.stats['servicebot_violations'].values())
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Total violations: {total_violations}")
                    all_violations = sorted(self.stats['servicebot_violations'].items(), key=lambda x: x[1], reverse=True)
                    for vtype, count in all_violations:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :    {vtype}: {count}")
                if self.stats.get('servicebot_actions'):
                    total_actions = sum(self.stats['servicebot_actions'].values())
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Total actions: {total_actions}")

            # Ban statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Ban Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  ACCESS DENY: {len(self.access_list['DENY'])}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Server bans: {len(self.server_bans)}")

            # Database statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Database Statistics ---")
            try:
                import os
                import aiosqlite
                db_path = CONFIG.get('database', 'path', default='pyircx.db')
                if os.path.exists(db_path):
                    size = os.path.getsize(db_path)
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Path: {db_path}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Size: {size:,} bytes ({size / 1024:.1f} KB)")
                    try:
                        async with aiosqlite.connect(db_path) as db:
                            async with db.execute("SELECT COUNT(*) FROM registered_nicks") as cursor:
                                row = await cursor.fetchone()
                                await user.send(f":{self.servername} NOTICE {user.nickname} :  Registered nicks: {row[0]}")
                            async with db.execute("SELECT COUNT(*) FROM registered_channels") as cursor:
                                row = await cursor.fetchone()
                                await user.send(f":{self.servername} NOTICE {user.nickname} :  Registered channels: {row[0]}")
                            async with db.execute("SELECT COUNT(*) FROM mailbox") as cursor:
                                row = await cursor.fetchone()
                                await user.send(f":{self.servername} NOTICE {user.nickname} :  Offline messages: {row[0]}")
                    except Exception as e:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :  A database error occurred: {str(e)}")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Database file not found: {db_path}")
            except Exception as e:
                await user.send(f":{self.servername} NOTICE {user.nickname} :  An error occurred: {str(e)}")

            # Configuration summary
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Configuration ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Server: {CONFIG.get('server', 'name')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Network: {CONFIG.get('server', 'network')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Version: {__version__} ({__version_label__})")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  DNSBL: {'enabled' if CONFIG.get('security', 'dnsbl', 'enabled', default=False) else 'disabled'}")

            # SSL/TLS status
            if SSL_MANAGER:
                ssl_info = SSL_MANAGER.get_info()
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- SSL/TLS Status ---")
                if ssl_info.get('enabled'):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled")
                    if ssl_info.get('context_loaded'):
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Certificate: {ssl_info.get('cert_file', 'N/A')}")
                        if 'expiry' in ssl_info:
                            days_left = ssl_info.get('days_left', 0)
                            status = "OK" if days_left > 14 else ("WARNING" if days_left > 3 else "CRITICAL")
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Expires: {ssl_info['expiry']} ({days_left:.0f} days) [{status}]")
                        if ssl_info.get('subject'):
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Subject: {ssl_info['subject']}")
                    else:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled but no certificates loaded")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :SSL: disabled")

            # Performance metrics (v2.0.0 optimizations)
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Performance Metrics ---")
            config_reloads = self.stats.get('config_cache_reloads', 0)
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Config cache reloads: {config_reloads}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Active channel monitors: {len(self.channel_monitors)}")
            if config_reloads > 0:
                messages_per_reload = self.stats['messages_sent'] // config_reloads if config_reloads else 0
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Avg messages/reload: {messages_per_reload:,}")

            # Real-time metrics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Real-Time Metrics ---")
            # Calculate current rates
            if self.stats['commands_per_minute']:
                recent_cmds = list(self.stats['commands_per_minute'])[-5:]  # Last 5 minutes
                avg_cmd_rate = sum(recent_cmds) / len(recent_cmds) if recent_cmds else 0
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Commands/min (5min avg): {avg_cmd_rate:.1f}")
                max_cmd_rate = max(self.stats['commands_per_minute']) if self.stats['commands_per_minute'] else 0
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Peak commands/min: {max_cmd_rate}")

            # Current load
            current_load_pct = (user_stats['total'] / CONFIG.get('limits', 'max_users', default=1000)) * 100
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Current load: {current_load_pct:.1f}% ({user_stats['total']}/{CONFIG.get('limits', 'max_users', default=1000)} users)")

            # Historical trends
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Historical Trends ---")
            if self.stats.get('busiest_channels'):
                top_channels = sorted(self.stats['busiest_channels'].items(), key=lambda x: x[1], reverse=True)
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Busiest channels (all-time):")
                for channel, count in top_channels:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :    {channel}: {count:,} messages")

            if self.stats.get('most_active_users'):
                top_users = sorted(self.stats['most_active_users'].items(), key=lambda x: x[1], reverse=True)
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Most active users (all-time):")
                for username, count in top_users:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :    {username}: {count:,} commands")

            # Distributed/linking stats
            if hasattr(self, 'link_manager') and self.link_manager and self.link_manager.enabled:
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- Distributed Network ---")
                server_role = CONFIG.get('linking', 'server_role', default='trunk')
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Role: {server_role.upper()}")
                linked_count = len(self.link_manager.linked_servers)
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Linked servers: {linked_count}")

                if linked_count > 0:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Connected servers:")
                    for server_name, linked_server in self.link_manager.linked_servers.items():
                        user_count = getattr(linked_server, 'user_count', 0)
                        await user.send(f":{self.servername} NOTICE {user.nickname} :    {server_name} ({user_count} users)")

                # Network divergence/convergence history
                if self.stats['network_divergence_history']:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Recent network divergences ({len(self.stats['network_divergence_history'])}):")
                    import datetime
                    for timestamp, server, reason in self.stats['network_divergence_history'][-5:]:
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        await user.send(f":{self.servername} NOTICE {user.nickname} :    {server} at {dt.strftime('%H:%M:%S')}: {reason}")

                if self.stats['network_convergence_history']:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  Recent network convergences ({len(self.stats['network_convergence_history'])}):")
                    import datetime
                    for timestamp, server in self.stats['network_convergence_history'][-5:]:
                        dt = datetime.datetime.fromtimestamp(timestamp)
                        await user.send(f":{self.servername} NOTICE {user.nickname} :    {server} at {dt.strftime('%H:%M:%S')}")

            await user.send(f":{self.servername} NOTICE {user.nickname} :=== End of STATS * ===")
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
            await user.send(f":{self.servername} 242 {user.nickname} :Server Up {days} days {hours}:{mins:02d}:{secs:02d}")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Define permission tiers for STATS flags
        PUBLIC_FLAGS = {'u', 's', 'i', 'x', 'w', 'y', 'c', 'f', 'n'}
        GUIDE_FLAGS = {'a', 'o', 'g', 'b', 'z'}
        OPERATOR_FLAGS = {'d', 'k', 'l', 'm', 'p', 't', 'v'}

        # Check permissions based on flag
        is_high_staff = user.is_high_staff()

        if flag in OPERATOR_FLAGS and not is_high_staff:
            await user.send(f":{self.servername} NOTICE {user.nickname} :STATS {flag} requires IRC operator or administrator privileges")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        if flag in GUIDE_FLAGS and not is_staff:
            await user.send(f":{self.servername} NOTICE {user.nickname} :STATS {flag} requires staff privileges")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        # Staff listing - public for everyone (optimized single pass)
        if flag == 's':
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Online Staff ---")
            staff_found = False
            for u in self.users.values():
                if u.is_virtual:
                    continue
                if u.has_mode('a'):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname} (IRC administrator)")
                    staff_found = True
                elif u.has_mode('o'):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname} (IRC operator)")
                    staff_found = True
                elif u.has_mode('g'):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname} (IRC Guide)")
                    staff_found = True
            if not staff_found:
                await user.send(f":{self.servername} NOTICE {user.nickname} :No staff currently online")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End of Staff ---")
            await user.send(self.get_reply("219", user, flag=flag))
            return

        if flag == 'a':
            # Online IRC administrators
            admins = [u for u in self.users.values() if u.has_mode('a') and not u.is_virtual]
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Online IRC administrators ({len(admins)}) ===")
            if not admins:
                await user.send(f":{self.servername} NOTICE {user.nickname} :No IRC administrators currently online")
            else:
                for u in admins:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  {u.nickname}!{u.username}@{u.host} (idle: {idle_str})")
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== End of IRC administrators ===")

        elif flag == 'o':
            # Online IRC operators
            sysops = [u for u in self.users.values() if u.has_mode('o') and not u.has_mode('a') and not u.is_virtual]
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Online IRC operators ({len(sysops)}) ===")
            if not sysops:
                await user.send(f":{self.servername} NOTICE {user.nickname} :No IRC operators currently online")
            else:
                for u in sysops:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  {u.nickname}!{u.username}@{u.host} (idle: {idle_str})")
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== End of IRC operators ===")

        elif flag == 'g':
            # Online IRC Guides
            guides = [u for u in self.users.values() if u.has_mode('g') and not u.is_virtual]
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Online IRC Guides ({len(guides)}) ===")
            if not guides:
                await user.send(f":{self.servername} NOTICE {user.nickname} :No IRC guides currently online")
            else:
                for u in guides:
                    idle_time = int(time.time() - u.last_activity)
                    idle_str = f"{idle_time // 60}m" if idle_time > 60 else f"{idle_time}s"
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  {u.nickname}!{u.username}@{u.host} (idle: {idle_str})")
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== End of IRC Guides ===")

        elif flag == 'i':
            # Invisible users count
            count = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Invisible users: {count}")

        elif flag == 'k':
            # Ban statistics - ACCESS DENY + server bans
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Ban Statistics ---")

            # ACCESS DENY list
            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS DENY entries: {len(self.access_list['DENY'])}")
            if self.access_list['DENY']:
                for pattern, set_by, set_at, reason in self.access_list['DENY']:
                    reason_str = f" :{reason}" if reason else ""
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  {pattern} (by {set_by}){reason_str}")

            # Server bans
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server bans: {len(self.server_bans)}")
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
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  {ip} ({duration}) by {set_by}")

            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 's':
            # Services/bots (users with +s mode) - includes virtual services
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Services/Bots (+s) ---")
            for u in self.users.values():
                if u.is_service():
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname}!{u.username}@{u.host}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'z':
            # Gagged users
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Gagged Users (+z) ---")
            for u in self.users.values():
                if u.has_mode('z') and not u.is_virtual:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname}!{u.username}@{u.host}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'c':
            # Configuration
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Configuration ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server: {CONFIG.get('server', 'name')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Network: {CONFIG.get('server', 'network')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Version: {__version__} ({__version_label__})")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Max Users: {CONFIG.get('limits', 'max_users', default=1000)}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :User Modes: {CONFIG.get('modes', 'user', default='agiorsxz')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Chan Modes: {CONFIG.get('modes', 'channel', default='adefghijklmnprstuwxyz')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Flood Protection: {CONFIG.get('security', 'enable_flood_protection', default=True)}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'd':
            # Database statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Database Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Path: {CONFIG.get('database', 'path')}")
            try:
                import os
                import aiosqlite
                db_path = CONFIG.get('database', 'path')
                if os.path.exists(db_path):
                    size = os.path.getsize(db_path)
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Size: {size:,} bytes ({size / 1024:.1f} KB)")

                    # Query database for counts
                    try:
                        async with aiosqlite.connect(db_path) as db:
                            # Registered nicknames
                            async with db.execute("SELECT COUNT(*) FROM registered_nicks") as cursor:
                                row = await cursor.fetchone()
                                await user.send(f":{self.servername} NOTICE {user.nickname} :Registered nicks: {row[0]}")

                            # Registered channels
                            async with db.execute("SELECT COUNT(*) FROM registered_channels") as cursor:
                                row = await cursor.fetchone()
                                await user.send(f":{self.servername} NOTICE {user.nickname} :Registered channels: {row[0]}")

                            # Offline messages
                            async with db.execute("SELECT COUNT(*) FROM mailbox") as cursor:
                                row = await cursor.fetchone()
                                await user.send(f":{self.servername} NOTICE {user.nickname} :Offline messages: {row[0]}")

                            # News items
                            async with db.execute("SELECT COUNT(*) FROM newsflash WHERE active = 1") as cursor:
                                row = await cursor.fetchone()
                                await user.send(f":{self.servername} NOTICE {user.nickname} :Active news: {row[0]}")
                    except Exception as e:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :We encountered a database error: {str(e)}")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :The database file was not found")
            except Exception as e:
                await user.send(f":{self.servername} NOTICE {user.nickname} :We encountered an error: {str(e)}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'l':
            # Server linking statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Server Linking ---")
            linking_enabled = CONFIG.get('linking', 'enabled', default=False)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Linking: {'enabled' if linking_enabled else 'disabled'}")
            if linking_enabled:
                bind_host = CONFIG.get('linking', 'bind_host', default='0.0.0.0')
                bind_port = CONFIG.get('linking', 'bind_port', default=7001)
                await user.send(f":{self.servername} NOTICE {user.nickname} :Bind: {bind_host}:{bind_port}")
                links = CONFIG.get('linking', 'links', default=[])
                await user.send(f":{self.servername} NOTICE {user.nickname} :Configured links: {len(links)}")
                if links:
                    for link in links:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :  {link.get('name', 'unknown')}")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :(No links configured)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'y':
            # Anonymous users count (users with ~ prefix, not authenticated)
            count = sum(1 for u in self.users.values() if u.username.startswith('~') and not u.is_virtual)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Anonymous users (~): {count}")

        elif flag == 'x':
            # IRCX users count
            count = sum(1 for u in self.users.values() if u.is_ircx and not u.is_virtual)
            await user.send(f":{self.servername} NOTICE {user.nickname} :IRCX users: {count}")

        elif flag == 'w':
            # Authenticated users count
            count = sum(1 for u in self.users.values() if u.authenticated and not u.is_virtual)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Authenticated users: {count}")

        elif flag == 't':
            # SSL/TLS status
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- SSL/TLS Status ---")
            if SSL_MANAGER:
                ssl_info = SSL_MANAGER.get_info()
                if ssl_info.get('enabled'):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled")
                    if ssl_info.get('context_loaded'):
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Certificate: {ssl_info.get('cert_file', 'N/A')}")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Key: {ssl_info.get('key_file', 'N/A')}")
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
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Expires: {ssl_info['expiry']} ({days_left:.0f} days) [{status}]")
                        if ssl_info.get('subject'):
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Subject: {ssl_info['subject']}")
                        min_ver = CONFIG.get('ssl', 'min_version', default='TLSv1.2')
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Minimum TLS: {min_ver}")
                        ssl_ports = CONFIG.get('ssl', 'ports', default=[6697])
                        await user.send(f":{self.servername} NOTICE {user.nickname} :SSL Ports: {', '.join(map(str, ssl_ports))}")
                    else:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled but no certificates loaded")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :SSL: disabled")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :SSL: not initialized")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'p':
            # Peak usage statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Peak Usage ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Peak users: {self.stats['peak_users']}")
            if self.stats['peak_time']:
                import datetime
                peak_dt = datetime.datetime.fromtimestamp(self.stats['peak_time'])
                await user.send(f":{self.servername} NOTICE {user.nickname} :Peak time: {peak_dt.strftime('%Y-%m-%d %H:%M:%S')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Current users: {sum(1 for u in self.users.values() if not u.is_virtual)}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Max users (all time): {self.max_users_seen}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'f':
            # Flood protection statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Flood Protection ---")
            flood_enabled = CONFIG.get('security', 'enable_flood_protection', default=True)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Enabled: {flood_enabled}")
            if flood_enabled:
                flood_msgs = CONFIG.get('security', 'flood_messages', default=5)
                flood_window = CONFIG.get('security', 'flood_window', default=2.0)
                await user.send(f":{self.servername} NOTICE {user.nickname} :Threshold: {flood_msgs} messages per {flood_window}s")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Total flood events: {self.stats['flood_events']}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'm':
            # Message statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Message Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Total messages: {self.stats['messages_sent']}")

            # Most active channels (all)
            if self.stats['messages_by_channel']:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Most active channels:")
                sorted_channels = sorted(self.stats['messages_by_channel'].items(), key=lambda x: x[1], reverse=True)
                for channel, count in sorted_channels:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  {channel}: {count}")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :No message data available")

            # Current channels
            total_channels = len([c for c in self.channels.values() if not c.name.startswith('&')])
            await user.send(f":{self.servername} NOTICE {user.nickname} :Active channels: {total_channels}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'b':
            # ServiceBot statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- ServiceBot Statistics ---")
            servicebot_enabled = CONFIG.get('servicebot', 'enabled', default=True)
            await user.send(f":{self.servername} NOTICE {user.nickname} :ServiceBots enabled: {servicebot_enabled}")

            if servicebot_enabled:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Active bots: {len(self.servicebots)}")

                # Violations
                if self.stats['servicebot_violations']:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Violations detected:")
                    for violation_type, count in sorted(self.stats['servicebot_violations'].items(), key=lambda x: x[1], reverse=True):
                        await user.send(f":{self.servername} NOTICE {user.nickname} :  {violation_type}: {count}")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :No violations detected")

                # Actions taken
                if self.stats['servicebot_actions']:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Actions taken:")
                    for action, count in sorted(self.stats['servicebot_actions'].items(), key=lambda x: x[1], reverse=True):
                        await user.send(f":{self.servername} NOTICE {user.nickname} :  {action}: {count}")

                # Configuration
                profanity_enabled = CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False)
                malicious_enabled = CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=False)
                await user.send(f":{self.servername} NOTICE {user.nickname} :Profanity filter: {'enabled' if profanity_enabled else 'disabled'}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Malicious detection: {'enabled' if malicious_enabled else 'disabled'}")

            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'n':
            # Network statistics
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Network Statistics ---")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server: {CONFIG.get('server', 'name')}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Network: {CONFIG.get('server', 'network')}")

            # Totals
            total_users = sum(1 for u in self.users.values() if not u.is_virtual)
            total_channels = len(self.channels)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Users: {total_users}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channels: {total_channels}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services: {sum(1 for u in self.users.values() if u.is_virtual)}")

            # Server version
            await user.send(f":{self.servername} NOTICE {user.nickname} :Version: {__version__}")

            # Uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            await user.send(f":{self.servername} NOTICE {user.nickname} :Uptime: {days}d {hours}:{mins:02d}")

            await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'v':
            # Command usage statistics (Operator+)
            await user.send(f":{self.servername} NOTICE {user.nickname} :--- Command Usage Statistics ---")
            if self.stats['command_usage']:
                # Sort by usage count (descending)
                sorted_cmds = sorted(self.stats['command_usage'].items(), key=lambda x: x[1], reverse=True)
                for cmd, count in sorted_cmds:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{cmd}: {count}")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :No command usage data available")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Total commands: {self.stats['commands_processed']}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        else:
            await user.send(f":{self.servername} NOTICE {user.nickname} :That STATS flag is not recognized: {flag}")

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
            await user.send(self.get_reply("481", user))
            return

        if not params:
            await user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG subcommands: LIST, GET, SET, SAVE, RELOAD")
            return

        subcmd = params[0].upper()

        if subcmd == "LIST":
            # List configuration - SYSOP+ can view
            section = params[1].lower() if len(params) > 1 else None

            if section:
                # List specific section
                sect_data = CONFIG.get_section(section)
                if not sect_data:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :That section is not recognized: {section}")
                    return
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- Config [{section}] ---")
                for key, value in sect_data.items():
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{section}.{key} = {json.dumps(value)}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")
            else:
                # List all sections
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- Config Sections ---")
                for section in CONFIG.get_all_sections():
                    sect_data = CONFIG.get_section(section)
                    await user.send(f":{self.servername} NOTICE {user.nickname} :[{section}] ({len(sect_data)} keys)")
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- End (use CONFIG LIST <section> for details) ---")

        elif subcmd == "GET":
            # Get specific value - SYSOP+ can view
            if len(params) < 2:
                await self.send_notice(user, "860", usage="CONFIG GET <section.key>")
                return

            path = params[1].split('.')
            if len(path) < 2:
                await user.send(self.get_reply("861", user))
                return

            value = CONFIG.get(*path)
            if value is None:
                await user.send(f":{self.servername} NOTICE {user.nickname} :{params[1]} = (not set)")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :{params[1]} = {json.dumps(value)}")

        elif subcmd == "SET":
            # Set value - ADMIN only
            if not is_admin:
                await user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG SET requires ADMIN privileges")
                return

            if len(params) < 3:
                await self.send_notice(user, "860", usage="CONFIG SET <section.key> <value>")
                return

            path = params[1].split('.')
            if len(path) < 2:
                await user.send(self.get_reply("861", user))
                return

            # Parse value - try JSON first, then string
            raw_value = ' '.join(params[2:])
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                # Treat as string if not valid JSON
                value = raw_value

            old_value = CONFIG.get(*path)
            if CONFIG.set(*path, value=value):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Set {params[1]} = {json.dumps(value)}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Previous value: {json.dumps(old_value)}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Use CONFIG SAVE to persist changes")
                logger.info(f"CONFIG: {user.nickname} set {params[1]} = {json.dumps(value)}")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't set the value")

        elif subcmd == "SAVE":
            # Save to disk - ADMIN only
            if not is_admin:
                await user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG SAVE requires ADMIN privileges")
                return

            CONFIG.save()
            await user.send(f":{self.servername} NOTICE {user.nickname} :Configuration saved to {CONFIG.config_file}")
            logger.info(f"CONFIG: {user.nickname} saved configuration")

        elif subcmd == "RELOAD":
            # Reload from disk - ADMIN only
            if not is_admin:
                await user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG RELOAD requires ADMIN privileges")
                return

            CONFIG.load()
            await user.send(f":{self.servername} NOTICE {user.nickname} :Configuration reloaded from {CONFIG.config_file}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Some settings require server restart to take effect")
            logger.info(f"CONFIG: {user.nickname} reloaded configuration")

        else:
            await user.send(f":{self.servername} NOTICE {user.nickname} :That subcommand is not recognized: {subcmd}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG subcommands: LIST, GET, SET, SAVE, RELOAD")

    async def handle_connect(self, user, params):
        """
        CONNECT command - Connect to a remote server.
        Syntax: CONNECT <servername>
        Requires ADMIN privileges.
        """
        if not user.is_admin():
            await user.send(self.get_reply("481", user))
            return

        if not params:
            await self.send_notice(user, "860", usage="CONNECT <servername>")
            return

        if not hasattr(self, 'link_manager') or not self.link_manager:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server linking is not enabled")
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :No link configuration found for {target_server}")
            return

        # Check if already connected
        if target_server in self.link_manager.linked_servers:
            await user.send(self.get_reply("859", user, server=target_server))
            return

        # Attempt connection
        await user.send(f":{self.servername} NOTICE {user.nickname} :Connecting to {target_server}...")
        try:
            await self.link_manager.connect_to_server(link_cfg)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Successfully linked to {target_server}")
            # Track network convergence in history
            self.stats['network_convergence_history'].append((int(time.time()), target_server))
            if len(self.stats['network_convergence_history']) > 10:
                self.stats['network_convergence_history'] = self.stats['network_convergence_history'][-10:]
            logger.info(f"CONNECT: {user.nickname} linked to {target_server}")
        except Exception as e:
            await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't establish the link: {e}")
            logger.error(f"CONNECT: Failed to link to {target_server}: {e}")

    async def handle_squit(self, user, params):
        """
        SQUIT command - Disconnect a linked server.
        Syntax: SQUIT <servername> :<reason>
        Requires ADMIN privileges.
        """
        if not user.is_admin():
            await user.send(self.get_reply("481", user))
            return

        if not params:
            await self.send_notice(user, "860", usage="SQUIT <servername> :<reason>")
            return

        if not hasattr(self, 'link_manager') or not self.link_manager:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server linking is not enabled")
            return

        target_server = params[0]
        reason = params[1] if len(params) > 1 else f"Requested by {user.nickname}"

        if target_server not in self.link_manager.linked_servers:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Not linked to {target_server}")
            return

        await user.send(f":{self.servername} NOTICE {user.nickname} :Unlinking from {target_server}...")
        try:
            linked_server = self.link_manager.linked_servers[target_server]
            await self.link_manager.handle_server_split(linked_server, reason)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Unlinked from {target_server}")
            # Track network divergence in history
            self.stats['network_divergence_history'].append((int(time.time()), target_server, reason))
            if len(self.stats['network_divergence_history']) > 10:
                self.stats['network_divergence_history'] = self.stats['network_divergence_history'][-10:]
            logger.info(f"SQUIT: {user.nickname} unlinked {target_server}: {reason}")
        except Exception as e:
            await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't unlink the server: {e}")
            logger.error(f"SQUIT: Failed to unlink {target_server}: {e}")

    async def handle_links(self, user, params):
        """
        LINKS command - Show network topology.
        Syntax: LINKS
        """
        if not hasattr(self, 'link_manager') or not self.link_manager:
            # No linking enabled, just show this server
            await user.send(f":{self.servername} 364 {user.nickname} {self.servername} {self.servername} :0 {CONFIG.get('server', 'network', default='IRCX Network')}")
            await user.send(f":{self.servername} 365 {user.nickname} * :End of /LINKS list")
            return

        # Show local server
        await user.send(f":{self.servername} 364 {user.nickname} {self.servername} {self.servername} :0 {CONFIG.get('server', 'network', default='IRCX Network')}")

        # Show linked servers
        for server_name, linked_server in self.link_manager.linked_servers.items():
            hopcount = linked_server.hopcount
            desc = linked_server.description
            uplink = self.servername if linked_server.is_direct else "via"
            await user.send(f":{self.servername} 364 {user.nickname} {server_name} {uplink} :{hopcount} {desc}")

        await user.send(f":{self.servername} 365 {user.nickname} * :End of /LINKS list")

    async def handle_map(self, user, params):
        """
        MAP command - Show network topology as a tree.
        Syntax: MAP
        """
        if not hasattr(self, 'link_manager') or not self.link_manager:
            # No linking enabled, just show this server
            local_users = sum(1 for u in self.users.values() if not u.is_virtual)
            await user.send(f":{self.servername} 006 {user.nickname} :{self.servername} ({local_users})")
            await user.send(f":{self.servername} 007 {user.nickname} :End of /MAP")
            return

        # Count local users
        local_users = sum(1 for u in self.users.values() if not u.is_virtual and not (hasattr(u, 'is_remote') and u.is_remote))

        # Show local server
        await user.send(f":{self.servername} 006 {user.nickname} :{self.servername} ({local_users})")

        # Show linked servers with indentation
        for server_name, linked_server in self.link_manager.linked_servers.items():
            remote_users = linked_server.user_count if hasattr(linked_server, 'user_count') else 0
            indent = "  " if linked_server.is_direct else "    "
            await user.send(f":{self.servername} 006 {user.nickname} :{indent}`-{server_name} ({remote_users})")

        await user.send(f":{self.servername} 007 {user.nickname} :End of /MAP")

    async def handle_staff(self, user, params):
        """
        STAFF command - In-band staff account management.

        Staff accounts are associated with usernames (USER ident), not nicknames.
        Authentication happens via PASS username:password before USER command.

        Subcommands:
          STAFF LIST                          - List all staff accounts (SYSOP+)
          STAFF ADD <username> <password> <level> - Add staff account (ADMIN only)
          STAFF DEL <username>                - Remove staff account (ADMIN only)
          STAFF SET <username> <level>        - Change staff level (ADMIN only)
          STAFF PASS <username> <newpass>     - Change password (ADMIN, or self)

        Levels: ADMIN, SYSOP, GUIDE
        """
        is_admin = user.has_mode('a')
        is_sysop = user.has_mode('o')

        if not is_admin and not is_sysop:
            await user.send(self.get_reply("481", user))
            return

        if not params:
            await user.send(f":{self.servername} NOTICE {user.nickname} :STAFF subcommands: LIST, ADD, DEL, SET, PASS, MFA")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff levels: ADMIN, SYSOP, GUIDE")
            return

        subcmd = params[0].upper()

        if subcmd == "LIST":
            # List all staff accounts - SYSOP+ can view
            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT username, level FROM users ORDER BY level, username") as cursor:
                        rows = await cursor.fetchall()

                await user.send(f":{self.servername} NOTICE {user.nickname} :=== Staff Accounts ({len(rows)}) ===")
                if not rows:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :No staff accounts configured")
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
                        await user.send(f":{self.servername} NOTICE {user.nickname} :")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :ADMIN ({len(admins)}):")
                        for admin in admins:
                            status = " [ONLINE]" if admin in online_staff and online_staff[admin] == 'ADMIN' else ""
                            await user.send(f":{self.servername} NOTICE {user.nickname} :  {admin}{status}")
                    if sysops:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :SYSOP ({len(sysops)}):")
                        for sysop in sysops:
                            status = " [ONLINE]" if sysop in online_staff and online_staff[sysop] == 'SYSOP' else ""
                            await user.send(f":{self.servername} NOTICE {user.nickname} :  {sysop}{status}")
                    if guides:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :GUIDE ({len(guides)}):")
                        for guide in guides:
                            status = " [ONLINE]" if guide in online_staff and online_staff[guide] == 'GUIDE' else ""
                            await user.send(f":{self.servername} NOTICE {user.nickname} :  {guide}{status}")

                await user.send(f":{self.servername} NOTICE {user.nickname} :=== End of Staff Accounts ===")
            except Exception as e:
                logger.error(f"STAFF LIST error: {e}")
                await user.send(self.get_reply("884", user))

        elif subcmd == "ADD":
            # Add staff account - ADMIN only
            if not is_admin:
                await user.send(f":{self.servername} NOTICE {user.nickname} :STAFF ADD requires ADMIN privileges")
                return

            if len(params) < 4:
                await self.send_notice(user, "860", usage="STAFF ADD <username> <password> <level>")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Levels: ADMIN, SYSOP, GUIDE")
                return

            # Check if branch in centralized mode - proxy to trunk
            if not CONFIG.get('services', 'is_services_hub') and \
               CONFIG.get('services', 'mode') == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} ADD {params[1]} {params[2]} {params[3]}")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Staff command forwarded to trunk. Please wait...")
                        return
                await user.send(f":{self.servername} NOTICE {user.nickname} :The trunk server is not connected. Staff management is unavailable.")
                return

            username = params[1]
            password = params[2]
            level = params[3].upper()

            if level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                await self.send_notice(user, "862", levels="ADMIN, SYSOP, or GUIDE")
                return

            if len(password) < 6:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Your password must be at least 6 characters")
                return

            # Validate username
            valid, error = validate_username(username)
            if not valid:
                await self.send_notice(user, "863", error=error)
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if already exists
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if await cursor.fetchone():
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' already exists")
                            return

                    # Hash password and insert
                    password_hash = await hash_password_async(password)
                    await db.execute("INSERT INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                                    (username, password_hash, level))
                    await db.commit()

                await user.send(f":{self.servername} NOTICE {user.nickname} :=== SUCCESS ===")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account created:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Username: {username}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Level: {level}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Created by: {user.nickname}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :The account will be active on next login.")
                logger.info(f"STAFF: {user.nickname} added staff account '{username}' ({level})")
                await self.log_staff(user.nickname, "STAFF ADD", username, f"Level: {level}")

            except Exception as e:
                logger.error(f"STAFF ADD error: {e}")
                await user.send(self.get_reply("885", user))

        elif subcmd == "DEL":
            # Remove staff account - ADMIN only
            if not is_admin:
                await user.send(f":{self.servername} NOTICE {user.nickname} :STAFF DEL requires ADMIN privileges")
                return

            if len(params) < 2:
                await self.send_notice(user, "860", usage="STAFF DEL <username>")
                return

            # Check if branch in centralized mode - proxy to trunk
            if not CONFIG.get('services', 'is_services_hub') and \
               CONFIG.get('services', 'mode') == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} REMOVE {params[1]}")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Staff command forwarded to trunk. Please wait...")
                        return
                await user.send(f":{self.servername} NOTICE {user.nickname} :The trunk server is not connected. Staff management is unavailable.")
                return

            username = params[1]

            # Prevent self-deletion
            if username.lower() == user.username.lower().lstrip('~'):
                await user.send(self.get_reply("858", user))
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if exists
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' not found")
                            return
                        old_level = row[0]

                    await db.execute("DELETE FROM users WHERE username = ?", (username,))
                    await db.commit()

                await user.send(f":{self.servername} NOTICE {user.nickname} :=== SUCCESS ===")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account deleted:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Username: {username}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Level: {old_level}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Deleted by: {user.nickname}")
                logger.info(f"STAFF: {user.nickname} deleted staff account '{username}' ({old_level})")
                await self.log_staff(user.nickname, "STAFF DEL", username, f"Was: {old_level}")

            except Exception as e:
                logger.error(f"STAFF DEL error: {e}")
                await user.send(self.get_reply("886", user))

        elif subcmd == "SET":
            # Change staff level - ADMIN only
            if not is_admin:
                await user.send(f":{self.servername} NOTICE {user.nickname} :STAFF SET requires ADMIN privileges")
                return

            if len(params) < 3:
                await self.send_notice(user, "860", usage="STAFF SET <username> <level>")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Levels: ADMIN, SYSOP, GUIDE")
                return

            # Check if branch in centralized mode - proxy to trunk
            if not CONFIG.get('services', 'is_services_hub') and \
               CONFIG.get('services', 'mode') == 'centralized':
                if self.link_manager and self.link_manager.servers:
                    trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                    if trunk_server:
                        await trunk_server.send(f"STAFFCMD {user.nickname} LEVEL {params[1]} {params[2]}")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Staff command forwarded to trunk. Please wait...")
                        return
                await user.send(f":{self.servername} NOTICE {user.nickname} :The trunk server is not connected. Staff management is unavailable.")
                return

            username = params[1]
            new_level = params[2].upper()

            if new_level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                await self.send_notice(user, "862", levels="ADMIN, SYSOP, or GUIDE")
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' not found")
                            return
                        old_level = row[0]

                    if old_level == new_level:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :'{username}' is already {new_level}")
                        return

                    await db.execute("UPDATE users SET level = ? WHERE username = ?", (new_level, username))
                    await db.commit()

                await user.send(f":{self.servername} NOTICE {user.nickname} :=== SUCCESS ===")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff level changed:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Username: {username}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Previous: {old_level}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  New level: {new_level}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Changed by: {user.nickname}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Change will take effect on next login.")
                logger.info(f"STAFF: {user.nickname} changed '{username}' level from {old_level} to {new_level}")
                await self.log_staff(user.nickname, "STAFF SET", username, f"{old_level} -> {new_level}")

            except Exception as e:
                logger.error(f"STAFF SET error: {e}")
                await user.send(self.get_reply("887", user))

        elif subcmd == "PASS":
            # Change staff password - ADMIN or self
            # Syntax: STAFF PASS <username> <oldpassword> <newpassword> (for own password)
            #         STAFF PASS <username> <newpassword> (ADMIN changing others - less secure, local only)

            own_username = user.username.lstrip('~')

            if len(params) < 3:
                await self.send_notice(user, "860", usage="STAFF PASS <username> <oldpassword> <newpassword>")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Your old password is required to change your password")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Admins changing others: STAFF PASS <username> <newpassword>")
                return

            username = params[1]
            is_self = username.lower() == own_username.lower()

            # Determine if 2 or 3 parameter format
            if len(params) == 4:
                # STAFF PASS <username> <oldpass> <newpass> - secure format
                old_password = params[2]
                new_password = params[3]

                # Check if branch in centralized mode - proxy to trunk
                if not CONFIG.get('services', 'is_services_hub') and \
                   CONFIG.get('services', 'mode') == 'centralized':
                    if self.link_manager and self.link_manager.servers:
                        trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                        if trunk_server:
                            await trunk_server.send(f"STAFFCMD {user.nickname} PASSWORD {old_password} {new_password}")
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Password change request forwarded to trunk. Please wait...")
                            return
                    await user.send(f":{self.servername} NOTICE {user.nickname} :The trunk server is not connected. Staff management is unavailable.")
                    return

            elif len(params) == 3:
                # STAFF PASS <username> <newpass> - ADMIN-only shorthand (trunk only)
                if not is_admin:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Your old password is required when changing your own password")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF PASS <username> <oldpassword> <newpassword>")
                    return

                if not CONFIG.get('services', 'is_services_hub'):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :This format only works on trunk server")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Use: STAFF PASS <username> <oldpassword> <newpassword>")
                    return

                new_password = params[2]
                old_password = None  # Admin override, no validation
            else:
                await self.send_notice(user, "860", usage="STAFF PASS <username> <oldpassword> <newpassword>")
                return

            # Check permissions
            if not is_admin and not is_self:
                await user.send(f":{self.servername} NOTICE {user.nickname} :You can only change your own staff password")
                return

            if len(new_password) < 6:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Your password must be at least 6 characters")
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if not await cursor.fetchone():
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' not found")
                            return

                    password_hash = await hash_password_async(new_password)
                    await db.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                                    (password_hash, username))
                    await db.commit()

                await user.send(f":{self.servername} NOTICE {user.nickname} :=== SUCCESS ===")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff password changed:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Username: {username}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Changed by: {user.nickname}")
                if is_self:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Your password has been updated.")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Password updated. User must login with new credentials.")
                logger.info(f"STAFF: {user.nickname} changed password for '{username}'")
                if not is_self:
                    await self.log_staff(user.nickname, "STAFF PASS", username, "Password changed")

            except Exception as e:
                logger.error(f"STAFF PASS error: {e}")
                await user.send(self.get_reply("888", user))


        elif subcmd == "MFA":
            # Manage MFA for staff accounts (ADMIN only)
            # Syntax: STAFF MFA <username> ENABLE <code>   - Enable MFA with verified code
            #         STAFF MFA <username> DISABLE <code>  - Disable MFA with verified code
            #         STAFF MFA <username> STATUS          - Show MFA status

            if not is_admin:
                await user.send(f":{self.servername} NOTICE {user.nickname} :STAFF MFA requires IRC administrator privileges")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Use AUTH ENABLE to manage your own MFA")
                return

            if len(params) < 3:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF MFA <username> ENABLE <code> | DISABLE <code> | STATUS")
                return

            username = params[1]
            mfa_action = params[2].upper()

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if user exists
                    async with db.execute("SELECT mfa_enabled, mfa_secret FROM users WHERE username = ?",
                                         (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' not found")
                            return

                        mfa_enabled, mfa_secret = row

                    if mfa_action == "STATUS":
                        # Show MFA status
                        status = "enabled" if mfa_enabled else ("setup pending" if mfa_secret else "disabled")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :MFA status for {username}: {status}")
                        if mfa_secret and not mfa_enabled:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Secret exists but awaiting first verification")
                        logger.info(f"STAFF MFA: {user.nickname} checked MFA status for {username}")

                    elif mfa_action == "ENABLE":
                        # Enable MFA with code verification
                        if len(params) < 4:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF MFA {username} ENABLE <6-digit code>")
                            await user.send(f":{self.servername} NOTICE {user.nickname} :The user must run AUTH ENABLE first to generate their secret")
                            return

                        code = params[3]

                        if mfa_enabled:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is already enabled for {username}")
                            return

                        if not mfa_secret:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :User {username} must run AUTH ENABLE first to generate MFA secret")
                            return

                        # Verify the code
                        import pyotp
                        totp = pyotp.TOTP(mfa_secret)

                        if not totp.verify(code, valid_window=1):
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA code for {username}")
                            logger.warning(f"STAFF MFA: {user.nickname} failed to enable MFA for {username} (invalid code)")
                            return

                        # Enable MFA!
                        await db.execute("UPDATE users SET mfa_enabled = 1 WHERE username = ?",
                                        (username,))
                        await db.commit()

                        await user.send(f":{self.servername} NOTICE {user.nickname} :MFA enabled for {username}")
                        logger.info(f"STAFF MFA: {user.nickname} enabled MFA for {username}")
                        await self.log_staff(user.nickname, "STAFF MFA ENABLE", username, "MFA enabled by admin")

                    elif mfa_action == "DISABLE":
                        # Disable MFA with code verification
                        if len(params) < 4:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF MFA {username} DISABLE <6-digit code>")
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Current valid code required to disable MFA")
                            return

                        code = params[3]

                        if not mfa_enabled:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is not enabled for {username}")
                            return

                        if not mfa_secret:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA configuration error for {username}")
                            return

                        # Verify the code
                        import pyotp
                        totp = pyotp.TOTP(mfa_secret)

                        if not totp.verify(code, valid_window=1):
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA code for {username}")
                            logger.warning(f"STAFF MFA: {user.nickname} failed to disable MFA for {username} (invalid code)")
                            return

                        # Disable MFA
                        await db.execute("UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = ?",
                                        (username,))
                        await db.commit()

                        await user.send(f":{self.servername} NOTICE {user.nickname} :MFA disabled for {username}")
                        logger.info(f"STAFF MFA: {user.nickname} disabled MFA for {username}")
                        await self.log_staff(user.nickname, "STAFF MFA DISABLE", username, "MFA disabled by admin")

                    else:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA action: {mfa_action}")
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Use: ENABLE, DISABLE, or STATUS")

            except Exception as e:
                logger.error(f"STAFF MFA error: {e}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA operation failed - internal error")
        else:
            await user.send(f":{self.servername} NOTICE {user.nickname} :That subcommand is not recognized: {subcmd}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :STAFF subcommands: LIST, ADD, DEL, SET, PASS")

    async def handle_profanity(self, user, params):
        """
        PROFANITY command - Manage profanity filter (ADMIN only).

        Subcommands:
          PROFANITY LIST                    - Show current words and patterns
          PROFANITY ADD WORD <word>         - Add a word to filter
          PROFANITY ADD PATTERN <pattern>   - Add a regex pattern
          PROFANITY DEL WORD <word>         - Remove a word
          PROFANITY DEL PATTERN <pattern>   - Remove a pattern
          PROFANITY ENABLE                  - Enable profanity filter
          PROFANITY DISABLE                 - Disable profanity filter
          PROFANITY TEST <text>             - Test if text would be caught
        """
        if not user.is_high_staff():
            await user.send(f":{self.servername} NOTICE {user.nickname} :PROFANITY command requires IRC operator or administrator privileges")
            return

        if not params:
            await user.send(f":{self.servername} NOTICE {user.nickname} :PROFANITY subcommands: LIST, ADD, DEL, ENABLE, DISABLE, TEST")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples: PROFANITY LIST, PROFANITY ADD WORD badword, PROFANITY ADD PATTERN (bad|terrible)")
            return

        subcmd = params[0].upper()

        if subcmd == "LIST":
            # Show current filter configuration
            enabled = CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False)
            words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
            patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
            case_sensitive = CONFIG.get('servicebot', 'profanity_filter', 'case_sensitive', default=False)
            action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')

            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Profanity Filter Configuration ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Status: {'Enabled' if enabled else 'Disabled'}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Action: {action} (warn/gag/kick)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Case Sensitive: {'Yes' if case_sensitive else 'No'}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")

            if words:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Filtered Words ({len(words)}):")
                for word in words:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  - {word}")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Filtered Words: (none)")

            await user.send(f":{self.servername} NOTICE {user.nickname} :")

            if patterns:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Regex Patterns ({len(patterns)}):")
                for pattern in patterns:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :  - {pattern}")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Regex Patterns: (none)")

        elif subcmd == "ADD":
            if len(params) < 3:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: PROFANITY ADD WORD <word> or PROFANITY ADD PATTERN <pattern>")
                return

            add_type = params[1].upper()
            value = ' '.join(params[2:])

            if add_type == "WORD":
                current_words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
                if value in current_words:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Word '{value}' is already in the filter")
                    return
                current_words.append(value)
                CONFIG.set('servicebot', 'profanity_filter', 'words', current_words)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await user.send(f":{self.servername} NOTICE {user.nickname} :Added word '{value}' to profanity filter")
                logger.info(f"PROFANITY: {user.nickname} added word '{value}'")

            elif add_type == "PATTERN":
                # Validate regex
                try:
                    re.compile(value)
                except re.error as e:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :That regex pattern is not valid: {e}")
                    return

                current_patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
                if value in current_patterns:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Pattern '{value}' is already in the filter")
                    return
                current_patterns.append(value)
                CONFIG.set('servicebot', 'profanity_filter', 'patterns', current_patterns)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await user.send(f":{self.servername} NOTICE {user.nickname} :Added pattern '{value}' to profanity filter")
                logger.info(f"PROFANITY: {user.nickname} added pattern '{value}'")

            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :That type '{add_type}' is not recognized. Use WORD or PATTERN")

        elif subcmd == "DEL":
            if len(params) < 3:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: PROFANITY DEL WORD <word> or PROFANITY DEL PATTERN <pattern>")
                return

            del_type = params[1].upper()
            value = ' '.join(params[2:])

            if del_type == "WORD":
                current_words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
                if value not in current_words:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Word '{value}' is not in the filter")
                    return
                current_words.remove(value)
                CONFIG.set('servicebot', 'profanity_filter', 'words', current_words)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await user.send(f":{self.servername} NOTICE {user.nickname} :Removed word '{value}' from profanity filter")
                logger.info(f"PROFANITY: {user.nickname} removed word '{value}'")

            elif del_type == "PATTERN":
                current_patterns = CONFIG.get('servicebot', 'profanity_filter', 'patterns', default=[])
                if value not in current_patterns:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Pattern '{value}' is not in the filter")
                    return
                current_patterns.remove(value)
                CONFIG.set('servicebot', 'profanity_filter', 'patterns', current_patterns)
                await CONFIG.save()
                self._reload_all_monitor_configs()  # Reload cached config in all monitors
                await user.send(f":{self.servername} NOTICE {user.nickname} :Removed pattern '{value}' from profanity filter")
                logger.info(f"PROFANITY: {user.nickname} removed pattern '{value}'")

            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :That type '{del_type}' is not recognized. Use WORD or PATTERN")

        elif subcmd == "ENABLE":
            CONFIG.set('servicebot', 'profanity_filter', 'enabled', True)
            await CONFIG.save()
            self._reload_all_monitor_configs()  # Reload cached config in all monitors
            await user.send(f":{self.servername} NOTICE {user.nickname} :Profanity filter enabled")
            logger.info(f"PROFANITY: {user.nickname} enabled profanity filter")

        elif subcmd == "DISABLE":
            CONFIG.set('servicebot', 'profanity_filter', 'enabled', False)
            await CONFIG.save()
            self._reload_all_monitor_configs()  # Reload cached config in all monitors
            await user.send(f":{self.servername} NOTICE {user.nickname} :Profanity filter disabled")
            logger.info(f"PROFANITY: {user.nickname} disabled profanity filter")

        elif subcmd == "TEST":
            if len(params) < 2:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: PROFANITY TEST <text>")
                return

            test_text = ' '.join(params[1:])
            monitor = ServiceBotMonitor()
            has_profanity, matched = monitor.check_profanity(test_text)

            if has_profanity:
                await user.send(f":{self.servername} NOTICE {user.nickname} :TEST RESULT: Would be caught - matched: {matched}")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :TEST RESULT: Would NOT be caught")

        else:
            await user.send(f":{self.servername} NOTICE {user.nickname} :That subcommand is not recognized: {subcmd}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Available: LIST, ADD, DEL, ENABLE, DISABLE, TEST")

    async def handle_help(self, user, params):
        """Handle HELP command - show command help"""
        topic = params[0].upper() if params else None
        is_staff = user.is_staff()

        if not topic:
            # Help topics index
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== pyIRCX Help Topics ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Use /HELP <topic> for detailed information:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  COMMANDS - All available commands")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  CHANNEL - Channel management commands")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  REGISTER - Nickname and channel registration")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  IRCX - IRCX-specific commands")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  USERMODES - User mode flags")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  CHANMODES - Channel mode flags")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  SERVICES - Available services")
            if is_staff:
                await user.send(f":{self.servername} NOTICE {user.nickname} :  STAFF - Staff commands")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Example: /HELP COMMANDS")

        elif topic == "COMMANDS":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== All Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Basic: NICK USER PASS QUIT PING PONG")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Messages: PRIVMSG MSG NOTICE")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channels: JOIN PART KICK INVITE TOPIC NAMES LIST MODE")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Registration: REGISTER IDENTIFY UNREGISTER CHGPASS MFA (see /HELP REGISTER)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :User Info: WHO WHOIS WHOWAS ISON USERHOST AWAY")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server Info: LUSERS MOTD INFO TIME VERSION STATS LINKS MAP ADMIN")
            await user.send(f":{self.servername} NOTICE {user.nickname} :IRCX: IRCX ACCESS PROP EVENT WHISPER KNOCK TRANSCRIPT DATA")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Utility: SILENCE WATCH HELP")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Type /HELP <command> for details (e.g., /HELP WHOWAS)")
            if is_staff:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff: KILL STAFF CONFIG PROFANITY (see /HELP STAFF)")

        elif topic == "CHANNEL":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Channel Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :JOIN #channel [key] - Join a channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :PART #channel [reason] - Leave a channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :TOPIC #channel [text] - View/set channel topic")
            await user.send(f":{self.servername} NOTICE {user.nickname} :NAMES #channel - List users in channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :LIST [pattern] - List all channels")
            await user.send(f":{self.servername} NOTICE {user.nickname} :INVITE nick #channel - Invite user to channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :KICK #channel nick [reason] - Remove user from channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MODE #channel [modes] - View/change channel modes")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channel ranks: . (owner), @ (host), + (voice)")

        elif topic == "REGISTER":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Registration Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname Registration:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  REGISTER <account> <email|*> <password> - Register your nickname")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  IDENTIFY <account> <password> - Log into registered nickname")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  UNREGISTER <account> - Delete your registration")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  MFA ENABLE - Enable two-factor authentication")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  MFA DISABLE <code> - Disable two-factor authentication")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  MFA VERIFY <code> - Complete MFA login")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channel Registration:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  REGISTER <#channel> [password] - Register a channel (owner only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  UNREGISTER <#channel> - Unregister a channel (owner only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Alternative: Use /MSG Registrar for NickServ-style interface")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Registered users get +r mode and can use locked channels")

        elif topic == "IRCX":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== IRCX Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :IRCX - Enable IRCX mode")
            await user.send(f":{self.servername} NOTICE {user.nickname} :CREATE #chan [key] - Create/join channel (alias for JOIN)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS #chan LIST [level] - List access entries")
            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS #chan ADD level mask [reason] - Add access entry")
            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS #chan DEL level mask - Remove access entry")
            await user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS #chan CLEAR level - Clear access list")
            await user.send(f":{self.servername} NOTICE {user.nickname} :PROP #chan [prop [value]] - View/set channel properties")
            await user.send(f":{self.servername} NOTICE {user.nickname} :LISTX [pattern] - Extended channel list with modes")
            await user.send(f":{self.servername} NOTICE {user.nickname} :WHISPER #chan nick :message - Private message in channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :DATA #chan id :data - Send structured data to channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Access levels: OWNER, HOST, VOICE, GRANT, DENY")

        elif topic == "USERMODES":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== User Modes ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :+i - Invisible (hidden from WHO *)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :+x - IRCX mode enabled")
            await user.send(f":{self.servername} NOTICE {user.nickname} :+r - Registered nickname (auto-set)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff modes (auto-set):")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +a - IRC administrator (ADMIN)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +o - IRC operator (SYSOP)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +g - IRC guide (GUIDE)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Other modes:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +s - Service (server bots and service accounts)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +z - Gagged (you cannot send messages to channels or users)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Example: /MODE yournick +i (to set invisible)")

        elif topic == "CHANMODES":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Channel Modes ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Standard IRC Modes:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +i - Invite-only: Users must be explicitly invited to join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +m - Moderated: Only users with voice (+) or higher can speak")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +n - No external: Only channel members can send messages")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +p - Private: Channel hidden from /WHOIS (but shown in /LIST)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +s - Secret: Channel hidden from /LIST and /WHOIS")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +t - Topic protection: Only channel hosts can change the topic")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +k <key> - Key: Password required to join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +l <limit> - Limit: Maximum number of users allowed")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :IRCX Extended Modes:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +a - Auth only: Only registered and identified users can join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +d - Cloneable: Allows users to create channel clones")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +e - Clone: This channel is a clone of another channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +f - No formatting: Formatting codes are removed from messages")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +g - Guide access: IRC guides automatically receive owner (.) status")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +h - Hidden: JOIN/PART/QUIT messages are not shown")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +j - No invites: INVITE command is disabled")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +r - Registered: Channel is registered (auto-set)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +u - Knock allowed: KNOCK requests allowed on invite-only channels")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +w - No whispers: WHISPER command is disabled")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +x - Auditorium: Only hosts see the full user list")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +y - Transcript: Channel messages are logged to server")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  +z - Locked: Channel requires auth and is registered (+a +r auto-set)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel +im - Set invite-only and moderated")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel +k secretpass - Set channel password")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel +l 100 - Set user limit to 100")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel -s+p - Remove secret, add private")

        elif topic == "SERVICES":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Services ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :System - Service directory")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG System")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Registrar - Nickname registration")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Commands: REGISTER IDENTIFY DROP INFO CHANNEL SET MFA")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG Registrar HELP")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Messenger - Offline messages")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Commands: SEND READ DELETE COUNT")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG Messenger HELP")
            await user.send(f":{self.servername} NOTICE {user.nickname} :NewsFlash - Network news")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Commands: LIST ADD DEL PUSH")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG NewsFlash HELP")
            await user.send(f":{self.servername} NOTICE {user.nickname} :ServiceBot - Channel monitoring")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Commands: HELP STATUS")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG ServiceBot01 HELP")

        elif topic == "STAFF" and is_staff:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Staff Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Staff Levels:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  ADMIN - Administrator (highest privileges, +a mode)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  SYSOP - System Operator (operator privileges, +o mode)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  GUIDE - Helper/Moderator (helper privileges, +g mode)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :KILL Commands:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  KILL nick [reason] - Disconnect a user")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  KILL #channel [reason] - Destroy channel and kick all users")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  KILL pattern [reason] - Kill users by IP/hostmask (e.g., 192.168.1.*)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :STAFF Management:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  STAFF LIST - List all staff accounts")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  STAFF ADD user level - Add staff account (ADMIN/SYSOP/GUIDE)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  STAFF DEL user - Remove staff account")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  STAFF SET user level - Change staff level")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  STAFF PASS user password - Change staff password")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  STAFF MFA user ENABLE/DISABLE/STATUS - Manage MFA (ADMIN only)")
            if user.is_admin():
                await user.send(f":{self.servername} NOTICE {user.nickname} :")
                await user.send(f":{self.servername} NOTICE {user.nickname} :ADMIN-only Commands:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  CONFIG GET key - View config value")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  CONFIG SET key value - Update config")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  PROFANITY - Manage profanity filter (see /HELP PROFANITY)")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  BROADCAST message - Send to all users")

        # Individual command help
        elif topic in ["JOIN", "J"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== JOIN Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /JOIN <#channel> [key]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Join a channel. If the channel doesn't exist, it will be created.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /JOIN #lobby - Join the lobby channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /JOIN #private secretpass - Join with password")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /JOIN #chat,#help - Join multiple channels")

        elif topic in ["PART", "LEAVE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== PART Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /PART <#channel> [reason]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Leave a channel you're currently in.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PART #lobby - Leave the lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PART #chat Goodbye! - Leave with a message")

        elif topic in ["MODE", "UMODE", "CMODE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== MODE Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /MODE <target> [+/-modes] [parameters]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Set or view modes on yourself or a channel.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :User mode examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE {user.nickname} - View your current modes")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE {user.nickname} +i - Set yourself invisible")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE {user.nickname} -i - Remove invisible mode")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channel mode examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel - View channel modes")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel +m - Set moderated")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel +o alice - Give operator to alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MODE #channel +k password - Set channel key")
            await user.send(f":{self.servername} NOTICE {user.nickname} :See: /HELP USERMODES and /HELP CHANMODES")

        elif topic in ["TOPIC"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== TOPIC Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /TOPIC <#channel> [new topic]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :View or change the topic of a channel.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /TOPIC #lobby - View current topic")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /TOPIC #lobby Welcome to the lobby! - Set new topic")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: On +t channels, only hosts can change the topic")

        elif topic in ["KICK"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== KICK Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /KICK <#channel> <nickname> [reason]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Remove a user from a channel (requires host/owner).")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /KICK #lobby spammer - Kick user")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /KICK #lobby alice Flooding - Kick with reason")

        elif topic in ["INVITE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== INVITE Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /INVITE <nickname> <#channel>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Invite a user to join a channel.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /INVITE alice #lobby - Invite alice to #lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Required for +i (invite-only) channels")

        elif topic in ["WHOIS", "WHO"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== WHOIS/WHO Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :WHOIS Usage: /WHOIS <nickname>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Get detailed information about a user")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Example: /WHOIS alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :WHO Usage: /WHO <pattern>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  List users matching a pattern")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :    /WHO #lobby - List users in #lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :    /WHO *alice* - Find users with 'alice' in nick")
            await user.send(f":{self.servername} NOTICE {user.nickname} :    /WHO *@*.com - Find users by hostname")

        elif topic in ["ACCESS"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== ACCESS Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Manage channel access control lists (channel-level) or server access (staff).")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channel-level ACCESS:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /ACCESS <#channel> <action> [level] [mask] [reason]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Actions: LIST, ADD, DEL, CLEAR")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Levels: OWNER, HOST, VOICE, GRANT, DENY")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS #lobby LIST - View all entries")
            await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS #lobby ADD HOST alice!*@* Trusted - Give host")
            await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS #lobby ADD DENY *!*@spammer.com Banned")
            await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS #lobby DEL DENY *!*@spammer.com")
            if is_staff:
                await user.send(f":{self.servername} NOTICE {user.nickname} :")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Server-level ACCESS (Staff):")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /ACCESS $ <action> [level] [mask] [reason]  (local server)")
                await user.send(f":{self.servername} NOTICE {user.nickname} :         /ACCESS * <action> [level] [mask] [reason]  (global network)")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Control server-wide access restrictions")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Scope: $ = local server only, * = all linked servers")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Levels: GRANT (allow), DENY (ban)")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Examples:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS $ LIST - View local server access list")
                await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS $ ADD DENY *!*@badhost.com Local ban")
                await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS * ADD DENY *!*@spammer.net Network-wide ban")
                await user.send(f":{self.servername} NOTICE {user.nickname} :    /ACCESS $ DEL DENY *!*@badhost.com")

        elif topic in ["PROP", "PROPERTY", "PROPERTIES"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== PROP Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /PROP <#channel> [property] [value]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :View or set extended channel properties.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP #lobby - List all properties (hosts can view except OWNERKEY)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP #lobby OWNERKEY mypassword - Set owner key (owner only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP #lobby TOPIC Welcome! - Set topic via PROP (owner only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP #lobby LAG 0 - Set lag property (owner only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Common properties: OWNERKEY, HOSTKEY, VOICEKEY, MEMBERKEY, TOPIC, ONJOIN, ONPART")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Only channel owners can set properties")

        elif topic == "WHISPER":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== WHISPER Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /WHISPER <#channel> <nickname> <message>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Send a private message to someone in a channel.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Only the target user sees the message.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WHISPER #lobby alice Hey, check your messages")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: You cannot use this in channels with +w mode (whispers disabled)")

        elif topic in ["DATA", "REQUEST", "REPLY"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== DATA / REQUEST / REPLY Commands (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Send tagged, structured data to users or channels.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Requires IRCX mode (+x). Only received by IRCX-enabled clients.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Syntax: /{topic.upper()} <target> <tag> :<message>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Command Types:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  DATA - Send tagged data (one-way communication)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  REQUEST - Send data expecting a reply")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  REPLY - Respond to a REQUEST")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Tag Format:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - 1-15 characters: letters, numbers, periods")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Must start with a letter")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Recommended: ORG.APP.FEATURE (e.g., MYORG.AVATAR)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Reserved Tag Prefixes (require privileges):")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  ADM.* - IRC administrator (+a) only")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  SYS.* - IRC operator (+o) only")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  GDE.* - IRC guide (+g) only")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  OWN.* - Channel owner (+q) only")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  HST.* - Channel host (+o) only")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /DATA #lobby MYAPP.AVATAR https://example.com/avatar.png")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /REQUEST alice MYAPP.STATUS Get status")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /REPLY alice MYAPP.STATUS Online")
            if user.is_staff():
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /DATA #lobby SYS.AD.BANNER <banner-url> (operator only)")

        elif topic == "NOTICE":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== NOTICE Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /NOTICE <target> <message>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Send a notice to a user or channel (no auto-reply expected).")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /NOTICE alice Important: Server maintenance at 10 PM")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /NOTICE #lobby Server will restart in 5 minutes")
            if user.is_high_staff():
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /NOTICE $ <message> - Server-wide notice (operator/administrator only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: NOTICE is typically used for automated responses and shouldn't trigger auto-replies")

        elif topic in ["REGISTER", "IDENTIFY", "UNREGISTER"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Registration Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :REGISTER - Claim your nickname")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /REGISTER <account> <email|*> <password>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Example: /REGISTER myaccount me@example.com mypassword")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Example: /REGISTER myaccount * mypassword (no email)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :IDENTIFY - Log into your registered nickname")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /IDENTIFY <account> <password>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Example: /IDENTIFY myaccount mypassword")
            await user.send(f":{self.servername} NOTICE {user.nickname} :UNREGISTER - Delete your registration")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /UNREGISTER <account>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Alternative: /MSG Registrar or /MSG NickServ")
            await user.send(f":{self.servername} NOTICE {user.nickname} :See also: /HELP MFA")

        elif topic in ["MFA", "2FA", "TOTP"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== MFA (Two-Factor Authentication) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Add extra security to your account with authenticator apps.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA ENABLE - Enable two-factor authentication")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /MFA ENABLE")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  You'll receive a QR code to scan with your authenticator app")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  (Google Authenticator, Authy, etc.)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA VERIFY - Complete login with MFA code")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /MFA VERIFY <6-digit-code>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Example: /MFA VERIFY 123456")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA DISABLE - Turn off MFA")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /MFA DISABLE <6-digit-code>")

        elif topic in ["AUTH", "AUTHENTICATE"]:
            if is_staff:
                await user.send(f":{self.servername} NOTICE {user.nickname} :=== AUTH Command (IRC guide/operator/administrator only) ===")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Securely elevate to IRC guide, operator, or administrator privileges after connecting.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /AUTH <username> <password>")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Credentials are never transmitted until after connection established.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :If MFA is enabled, you will be prompted for verification code.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :")
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA Commands:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /AUTH VERIFY <code> - Complete MFA verification")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /AUTH ENABLE <password> - Enable MFA for your account")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /AUTH DISABLE <password> <code> - Disable MFA (requires code)")
                await user.send(f":{self.servername} NOTICE {user.nickname} :")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /AUTH admin mypassword - Authenticate as IRC administrator")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /AUTH VERIFY 123456 - Complete MFA login")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /AUTH ENABLE mypassword - Set up two-factor authentication")
                await user.send(f":{self.servername} NOTICE {user.nickname} :")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Security: Progressive delays on failures, account lockout after 5 attempts,")
                await user.send(f":{self.servername} NOTICE {user.nickname} :optional SSL/TLS requirement, all attempts logged to #System channel.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :See also: /HELP DROP, /HELP STAFF")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :AUTH - Secure authentication for IRC guides, operators, and administrators")
                await user.send(f":{self.servername} NOTICE {user.nickname} :This command is for IRC guides, operators, and administrators only.")

        elif topic in ["DROP", "DEAUTH"]:
            if is_staff:
                await user.send(f":{self.servername} NOTICE {user.nickname} :=== DROP Command (IRC guide/operator/administrator only) ===")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Voluntarily drop IRC guide, operator, or administrator privileges.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /DROP")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Removes your +a, +o, or +g mode and reverts to regular user.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :You can re-authenticate with /AUTH command when needed.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Use cases:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  - Testing features as a regular user")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  - Participating in events without staff status")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  - Temporarily reducing privileges for security")
                await user.send(f":{self.servername} NOTICE {user.nickname} :See also: /HELP AUTH")
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :DROP - De-authentication for IRC guides, operators, and administrators")
                await user.send(f":{self.servername} NOTICE {user.nickname} :This command is for IRC guides, operators, and administrators only.")

        elif topic in ["LIST", "LISTX"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== LIST / LISTX Commands ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :LIST - Basic channel listing")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /LIST [pattern]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Examples: /LIST, /LIST *help*, /LIST #lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :LISTX - Extended channel listing (IRCX mode required)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Usage: /LISTX [pattern]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Shows channel modes in addition to name, users, and topic")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Format: <channel> <users> <modes> :<topic>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Example output: #lobby 15 +tn :Welcome to the lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Secret (+s) and hidden (+h) channels are hidden unless you're in them")

        elif topic in ["PRIVMSG", "MSG", "MESSAGE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== PRIVMSG Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /MSG <target> <message>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Send a message to a user or channel.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG alice Hello! - Send private message to alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG #lobby Hello everyone! - Send to channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG Registrar HELP - Talk to a service")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG NickServ IDENTIFY password - Alternative syntax")
            if user.is_high_staff():
                await user.send(f":{self.servername} NOTICE {user.nickname} :  /MSG $ <message> - Server-wide message (operator/administrator only)")

        elif topic in ["AWAY", "BACK"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== AWAY Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /AWAY [message]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Mark yourself as away with an optional message, or return from away status.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /AWAY Gone for lunch - Mark yourself away with message")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /AWAY - When not away: marks you away with no message")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /AWAY - When already away: returns you from away status")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: People will see your away message when they WHOIS you or message you")

        elif topic in ["KILL"] and is_staff:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== KILL Command (IRC operator/administrator only) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /KILL <target> [reason]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Disconnect users or destroy channels. Requires IRC operator or administrator privileges.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /KILL alice Spamming - Disconnect user")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /KILL #badchannel - Destroy channel and kick all users")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /KILL 192.168.1.* Network abuse - Kill by IP pattern")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Use with caution!")

        elif topic in ["WHOWAS"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== WHOWAS Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /WHOWAS <nickname> [count]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Show information about a user who has disconnected.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WHOWAS alice - Show last known info for alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WHOWAS bob 5 - Show up to 5 history entries for bob")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: History is limited and may expire after a period of time")

        elif topic in ["NAMES"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== NAMES Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /NAMES [#channel]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :List all users in a channel with their status.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /NAMES #lobby - List all users in #lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /NAMES - List users in all visible channels")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Prefixes: . = owner, @ = host, + = voice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Only shows channels you have access to")

        elif topic in ["KNOCK"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== KNOCK Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /KNOCK <#channel> [message]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Request an invitation to an invite-only channel.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /KNOCK #private - Request access")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /KNOCK #vip I'd like to join - Request with message")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Channel owners and hosts will be notified of your request")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Rate limited to once per minute per channel to prevent abuse")

        elif topic in ["EVENT"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== EVENT Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /EVENT ADD <type> <mask>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Subscribe to server events by registering event traps.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /EVENT ADD JOIN * - Notify when anyone joins any channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /EVENT ADD PART #lobby - Notify when someone leaves #lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Advanced IRCX feature for monitoring channel activity")

        elif topic in ["TRANSCRIPT"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== TRANSCRIPT Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /TRANSCRIPT <#channel> [lines] [offset]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :View channel transcript logs if transcript mode (+y) is enabled.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /TRANSCRIPT #lobby - View last 50 messages")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /TRANSCRIPT #lobby 100 - View last 100 messages")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /TRANSCRIPT #lobby 50 100 - View 50 messages starting from offset 100")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Requires channel owner status or IRC operator/administrator")
            await user.send(f":{self.servername} NOTICE {user.nickname} :To enable logging: Use /MODE #channel +y (owner only)")

        elif topic in ["STATS"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== STATS Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /STATS [query]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display server statistics and information.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /STATS - Show general server statistics")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /STATS u - Show server uptime")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Use /STATS ? for complete list of available queries")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Many detailed stats require staff privileges (guide, operator, or administrator)")

        elif topic in ["PROFANITY"] and user.is_high_staff():
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== PROFANITY Command (IRC operator/administrator only) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Manage ServiceBot profanity filter in real-time.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Commands:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY LIST - View current configuration")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY ADD WORD <word> - Add word to filter")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY ADD PATTERN <regex> - Add regex pattern")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY DEL WORD <word> - Remove word")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY DEL PATTERN <regex> - Remove pattern")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY ENABLE - Enable filter")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY DISABLE - Disable filter")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY TEST <text> - Test if text matches")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY ADD PATTERN (spam|viagra) - Block variations")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROFANITY TEST Check this message - Test before adding")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Changes persist to config file automatically")

        elif topic in ["CONFIG"] and user.is_high_staff():
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== CONFIG Command (IRC operator/administrator) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /CONFIG <GET|SET> <key> [value]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :View or modify server configuration at runtime.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CONFIG GET server.motd - View MOTD setting")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CONFIG SET server.max_users 1000 - Update max users")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Changes persist to config file. Use with caution.")

        elif topic in ["INFO"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== INFO Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /INFO")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display detailed server information including:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Server version and software")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Supported protocols (IRC, IRCX)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Special features and capabilities")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Contact information")

        elif topic in ["LUSERS"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== LUSERS Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /LUSERS")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display user and channel statistics including:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Total users connected")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Number of staff and services")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Total channels")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Peak user counts")

        elif topic in ["ISON"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== ISON Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /ISON <nickname> [nickname2] [...]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Check if one or more users are currently online.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ISON alice - Check if alice is online")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ISON alice bob charlie - Check multiple users")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Returns only the nicknames that are currently online")

        elif topic in ["USERHOST"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== USERHOST Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /USERHOST <nickname> [nickname2] [...]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Get user@host information for connected users.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /USERHOST alice - Get alice's user@host")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /USERHOST alice bob - Check multiple users (max 5)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Shows away status and operator status")

        elif topic in ["SILENCE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== SILENCE Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /SILENCE [+/-mask]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Block or unblock messages from specific users.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /SILENCE - List your silence list")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /SILENCE +bob!*@* - Block all messages from bob")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /SILENCE +*!*@spammer.com - Block all messages from host")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /SILENCE -bob!*@* - Unblock bob")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Silenced users will not be able to send you private messages or notices")

        elif topic in ["WATCH"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== WATCH Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /WATCH [+/-nickname]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Get notified when users come online or go offline.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WATCH - View your watch list")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WATCH +alice - Watch for alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WATCH -alice - Stop watching alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :You'll receive notifications when watched users connect/disconnect")

        elif topic in ["TIME"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== TIME Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /TIME")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display the current server time and timezone.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Useful for coordinating events across timezones")

        elif topic in ["VERSION"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== VERSION Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /VERSION")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display the server software version and information.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Shows: pyIRCX version, creation date, and build info")

        elif topic in ["NICK", "NICKNAME"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== NICK Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /NICK <new_nickname>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Change your nickname.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /NICK alice - Change your nick to alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Rules: Nicknames must be 1-30 characters, start with a letter, and contain only letters, numbers, -, _, [, ], {{, }}, \\, or |")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: You cannot use reserved service names (Registrar, NickServ, etc.)")

        elif topic in ["QUIT", "EXIT", "BYE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== QUIT Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /QUIT [message]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Disconnect from the server.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /QUIT - Disconnect with default message")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /QUIT Goodbye everyone! - Disconnect with custom message")

        elif topic in ["ADMIN"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== ADMIN Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /ADMIN")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display administrative contact information for the server.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Shows: Server location, organization, and admin contacts")

        elif topic in ["LINKS"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== LINKS Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /LINKS")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display list of linked servers (for networks with multiple servers).")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Shows: Server names, relationships, and connection info")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Single-server networks will show only one entry")

        elif topic in ["MAP"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== MAP Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /MAP")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display network topology as a tree structure.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Shows: Server hierarchy and user counts per server")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Useful for visualizing multi-server network layout")

        elif topic in ["CHGPASS", "CHANGEPASS"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== CHGPASS Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /CHGPASS <old_password> <new_password>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Change your account password.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Example:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CHGPASS oldpass newpass - Change password")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Alternative: /MSG Registrar SET PASSWORD <old> <new>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: You must be identified to your account first")

        elif topic in ["MOTD"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== MOTD Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /MOTD")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Display the server's Message of the Day.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Shows welcome message, server rules, and important announcements.")

        elif topic in ["MEMO"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== MEMO Command ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Send and receive offline messages directly (alternative to /MSG Messenger).")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO SEND <nick> <message> - Send memo to user")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO LIST - List pending memos")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO READ [id] - Read memo(s)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO DEL <id|ALL> - Delete memo(s)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Example:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO SEND alice Don't forget the meeting tomorrow!")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO LIST - See all pending memos")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO READ 1 - Read memo #1")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /MEMO DEL ALL - Delete all memos")

        elif topic in ["ALIASES", "ALIAS", "SHORTCUTS"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== Command Aliases ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Shortcut commands for faster typing:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /J  <channel>        - JOIN a channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /P  <channel>        - PART (leave) a channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /W  <nick>           - WHOIS user information")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /M  <nick> <message> - MSG (send private message)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /N  <nickname>       - NICK (change nickname)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /Q  [message]        - QUIT (disconnect)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /T  <channel> [text] - TOPIC (view/set topic)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /K  <channel> <nick> - KICK user from channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /I  <nick> <channel> - INVITE user to channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /L  [filter]         - LIST channels")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WW <nick>           - WHOWAS (past user info)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /WH <channel> <msg>  - WHISPER (private channel message)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /J #lobby           - Same as /JOIN #lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /W alice            - Same as /WHOIS alice")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /M bob Hello!       - Same as /MSG bob Hello!")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: All aliases are case-insensitive and work identically to full commands.")

        elif topic in ["GAG", "UNGAG"] and is_staff:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== GAG/UNGAG Commands (Staff) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Prevent or restore a user's ability to send messages.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /GAG <nick> - Global gag (sets user mode +z)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /GAG <#channel> <nick> - Channel-specific gag")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /UNGAG <nick> - Remove global gag")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /UNGAG <#channel> <nick> - Remove channel gag")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Requirements:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Global gag: Staff members only (IRC guides, operators, and administrators)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  - Channel gag: Channel host/owner or staff")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /GAG spammer - Globally prevent spammer from talking")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /GAG #lobby troublemaker - Gag only in #lobby")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /UNGAG spammer - Restore global ability to talk")

        elif topic in ["CREATE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== CREATE Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: /CREATE <#channel> [modes] [mode arguments]")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Create a new channel with initial modes. Requires IRCX mode.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CREATE #test - Create simple channel")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CREATE #test mnt - Create with modes (moderated, no external, topic)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CREATE #test ntl 50 - Create with modes and limit of 50 users")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CREATE #test ntkl 25 secret - Limit 25 users with key 'secret'")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CREATE #test c - Fail if channel exists (create-only flag)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Common modes: m=moderated n=no external t=topic protect i=invite-only")
            await user.send(f":{self.servername} NOTICE {user.nickname} :With arguments: k=key l=limit u=owner key")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Special: c=create-only (fail if exists)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Modes only apply to new channels. Use /MODE to change existing channels.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :See also: /HELP IRCX, /HELP CHANMODES, /HELP JOIN")

        elif topic in ["CONNECT", "SQUIT"] and user.is_admin():
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== CONNECT/SQUIT Commands (IRC administrator only) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Server linking commands for network administration.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /CONNECT <server> <port> [remote_server] - Link to remote server")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /SQUIT <server> [reason] - Disconnect server from network")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Requires IRC administrator privileges and proper server configuration")

        elif topic == "EVENT" and is_staff:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== EVENT Command (IRCX - Staff Only) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Real-time server monitoring for IRC operators and administrators.")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Requires: IRCX mode (+x) and operator or administrator privileges (+o or +a)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :EVENT ADD <class> [<mask>] - Subscribe to events")
            await user.send(f":{self.servername} NOTICE {user.nickname} :EVENT DELETE <class> [<mask>] - Unsubscribe from events")
            await user.send(f":{self.servername} NOTICE {user.nickname} :EVENT LIST [<class>] - List active subscriptions")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Event Classes:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  CONNECT - User logon events")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  MEMBER - Channel join/part/kick/quit events")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  CHANNEL - Channel create/delete/topic events")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  USER - User logoff/nick/mode events")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  SERVER - Server link/split events")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  SOCKET - Accepted but never fires")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /EVENT ADD MEMBER *!*@* - Monitor all channel membership changes")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /EVENT ADD CONNECT *!*@192.168.* - Monitor local network connections")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /EVENT DELETE MEMBER *!*@* - Stop monitoring membership")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /EVENT LIST - Show all active subscriptions")

        elif topic in ["PROP", "PROPERTY"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== PROP Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :View and set channel properties. Requires IRCX mode (+x).")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP <#channel> - List all properties")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP <#channel> <property> - View specific property")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP <#channel> <property> <value> - Set property (owner only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Common Properties:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  OWNERKEY - Password for instant +q (owner) on join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  HOSTKEY - Password for instant +o (host) on join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  VOICEKEY - Password for instant +v (voice) on join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  MEMBERKEY - Password required to join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  TOPIC - Channel topic")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  SUBJECT - Channel subject/description")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  ONJOIN - Message shown when users join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  ONPART - Message shown when users leave")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  LAG - Lag value (ms)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP #lobby - List all properties")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP #lobby TOPIC - View topic")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /PROP #lobby OWNERKEY secret123 - Set owner password")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Only channel owners can set properties")

        elif topic == "ACCESS":
            await user.send(f":{self.servername} NOTICE {user.nickname} :=== ACCESS Command (IRCX) ===")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Manage access control lists for channels. Requires IRCX mode (+x).")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS <#channel> LIST [level] - List access entries")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS <#channel> ADD <level> <mask> [reason] - Add entry")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS <#channel> DELETE <level> <mask> - Remove entry")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS <#channel> CLEAR [level] - Clear list")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Access Levels:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  OWNER - Grants +q (owner) status on join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  HOST - Grants +o (host/operator) status on join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  VOICE - Grants +v (voice) status on join")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  GRANT - Allows access (bypasses +i invite-only)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  DENY - Denies access (acts as ban)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Examples:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS #lobby LIST - Show all access entries")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS #lobby ADD GRANT *!*@trusted.com Access granted")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS #lobby ADD DENY *!*@spam.net Spammer")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  /ACCESS #lobby DELETE DENY *!*@spam.net")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Note: Channel owners/hosts can manage their channel access lists")

        else:
            # Try fuzzy matching for suggestions
            suggestions = self._get_help_suggestions(topic)
            await user.send(f":{self.servername} NOTICE {user.nickname} :No help available for: {topic}")
            if suggestions:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Did you mean: {', '.join(suggestions)}?")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Available topics: COMMANDS CHANNEL REGISTER IRCX USERMODES CHANMODES SERVICES ALIASES")
            if is_staff:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff topic: STAFF")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Try /HELP <command> for specific commands (e.g., /HELP JOIN)")

    async def handle_info(self, user):
        """Handle INFO command - return server information (RFC 2812)"""
        info_lines = [
            f"pyIRCX Server version {__version__}",
            f"Written in Python 3 with asyncio",
            f"",
            f"Server name: {self.servername}",
            f"Network: {CONFIG.get('server', 'network', default='IRCX Network')}",
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

    async def handle_motd(self, user):
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

    async def handle_lusers(self, user):
        """Handle LUSERS command - display user statistics"""
        # Count local users (not virtual, not remote)
        local_users = sum(1 for u in self.users.values() if not u.is_virtual and not (hasattr(u, 'is_remote') and u.is_remote))
        # Count remote users (from linked servers)
        remote_users = sum(1 for u in self.users.values() if not u.is_virtual and hasattr(u, 'is_remote') and u.is_remote)
        # Total users
        total_users = local_users + remote_users

        # Staff count includes staff users AND services/bots (local only for accuracy)
        ops = sum(1 for u in self.users.values() if (u.is_staff() or u.is_virtual) and not (hasattr(u, 'is_remote') and u.is_remote))
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
            if nick in self.users and not self.users[nick].is_virtual:
                online_nicks.append(nick)
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
            target = self.users.get(nick)
            if target and not target.is_virtual:
                # Build userhost reply: nick*=+user@host
                # * = operator, + = here, - = away
                oper_flag = "*" if target.is_high_staff() else ""
                away_flag = "-" if target.away_msg else "+"
                userhost_info.append(f"{target.nickname}{oper_flag}={away_flag}{target.username}@{target.host}")

        await user.send(self.get_reply("302", user, userhosts=" ".join(userhost_info)))

    async def handle_names(self, user, params):
        """Handle NAMES command - list channel members"""
        if not params:
            # No channel specified - list all visible channels
            for channel_name, channel in self.channels.items():
                # Skip hidden/secret channels unless user is in them
                if channel.modes.get('s') or channel.modes.get('h'):
                    if channel_name not in user.channels:
                        continue
                names = " ".join([channel.get_prefix(nick) + nick for nick in channel.members])
                await user.send(self.get_reply("353", user, channel=channel_name, names=names))
            await user.send(self.get_reply("366", user, channel="*"))
            return

        # Specific channels requested
        requested_names = params[0].split(',')
        for req_name in requested_names:
            req_name = req_name.strip()
            channel, chan_name = self.get_channel(req_name)
            if not channel:
                await user.send(self.get_reply("366", user, channel=req_name))
                continue

            # Check visibility - secret/hidden channels only visible to members
            if (channel.modes.get('s') or channel.modes.get('h')) and chan_name not in user.channels:
                await user.send(self.get_reply("366", user, channel=chan_name))
                continue

            names = " ".join([channel.get_prefix(nick) + nick for nick in channel.members])
            await user.send(self.get_reply("353", user, channel=chan_name, names=names))
            await user.send(self.get_reply("366", user, channel=chan_name))

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
            await self.send_notice(user, "860", usage="REGISTER <account> {*|<email>} <password>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :   or: REGISTER <#channel> [<password>]")
            return

        target = params[0]

        if is_channel(target):
            # Channel registration (only global # channels, not local &)
            if is_local_channel(target):
                await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot register local channels (&)")
                return
            channel_password = params[1] if len(params) > 1 else None
            await self._register_channel(user, target, channel_password)
        else:
            # Nickname registration
            if len(params) < 3:
                await self.send_notice(user, "860", usage="REGISTER <account> {*|<email>} <password>")
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
            await self.send_notice(user, "860", usage="UNREGISTER <account|#channel>")
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
            await self.send_notice(user, "860", usage="IDENTIFY [<account>] <password>")
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
            await self.send_notice(user, "860", usage="MFA ENABLE|VERIFY|DISABLE [<code>]")
            return

        subcmd = params[0].upper()

        if subcmd == "ENABLE":
            await self._mfa_enable(user)
        elif subcmd == "VERIFY":
            if len(params) < 2:
                await self.send_notice(user, "860", usage="MFA VERIFY <6-digit code>")
                return
            await self._mfa_verify(user, params[1])
        elif subcmd == "DISABLE":
            code = params[1] if len(params) > 1 else None
            await self._mfa_disable(user, code)
        else:
            await self.send_notice(user, "860", usage="MFA ENABLE|VERIFY|DISABLE [<code>]")

    async def _register_nick(self, user, account, password, email):
        """Register a nickname/account"""
        # Must be using the nickname to register it
        if user.nickname.lower() != account.lower():
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must be using the nickname to register it")
            return

        if user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You are already identified to a registered nickname")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    email_param = email if email else '*'
                    await trunk_server.send(f"REGCMD {user.nickname} REGISTER_NICK {account} {password} {email_param}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Registration request sent to services. Please wait...")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (account,)) as cursor:
                    if await cursor.fetchone():
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {account} is already registered")
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
                await user.send(f":{self.servername} NOTICE {user.nickname} :Your nickname {account} has been registered")
                logger.info(f"REGISTER: {account} registered by {user.prefix()}")

        except Exception as e:
            logger.error(f"REGISTER nick error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Registration failed - please try again later")

    async def _register_channel(self, user, channel_name, password):
        """Register a channel"""
        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify to a registered nickname first")
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} does not exist")
            return

        if user.nickname not in channel.owners:
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must be a channel owner to register {chan_name}")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    password_param = password if password else '*'
                    await trunk_server.send(f"REGCMD {user.nickname} REGISTER_CHANNEL {chan_name} {password_param}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Channel registration request sent to services. Please wait...")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_channels WHERE channel_name = ?",
                                     (chan_name,)) as cursor:
                    if await cursor.fetchone():
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Channel {chan_name} is already registered")
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
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Your nickname must be registered first")
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

                await user.send(f":{self.servername} NOTICE {user.nickname} :Your channel {chan_name} has been registered")
                logger.info(f"REGISTER: {chan_name} registered by {user.nickname}")

        except Exception as e:
            logger.error(f"REGISTER channel error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Registration failed - please try again later")

    async def _unregister_nick(self, user, account):
        """Unregister a nickname/account"""
        if user.nickname.lower() != account.lower():
            await user.send(f":{self.servername} NOTICE {user.nickname} :You can only unregister your own nickname")
            return

        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first to unregister")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} UNREGISTER_NICK {account}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Unregistration request sent to services. Please wait...")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                await db.execute("DELETE FROM registered_nicks WHERE nickname = ?", (account,))
                await db.commit()

                user.set_mode('r', False)
                await user.send(f":{user.nickname} MODE {user.nickname} :-r")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Your nickname {account} has been unregistered")
                logger.info(f"UNREGISTER: {account} unregistered")

        except Exception as e:
            logger.error(f"UNREGISTER nick error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Unregistration failed - please try again later")

    async def _unregister_channel(self, user, channel_name):
        """Unregister a channel"""
        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} does not exist")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} UNREGISTER_CHANNEL {chan_name}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Channel unregistration request sent to services. Please wait...")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if channel is registered
                async with db.execute("SELECT owner_uuid FROM registered_channels WHERE channel_name = ?",
                                     (chan_name,)) as cursor:
                    chan_row = await cursor.fetchone()
                    if not chan_row:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Channel {chan_name} is not registered")
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
                                await user.send(f":{self.servername} NOTICE {user.nickname} :Your staff account is not registered")
                                return
                    else:
                        async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                             (user.nickname,)) as cursor:
                            nick_row = await cursor.fetchone()
                            if not nick_row:
                                await user.send(f":{self.servername} NOTICE {user.nickname} :Your nickname is not registered")
                                return

                    # Verify ownership
                    if chan_row[0] != nick_row[0]:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :You are not the owner of {chan_name}")
                        return

                await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (chan_name,))
                await db.commit()

                channel.registered = False
                channel.account_uuid = None
                channel.modes['r'] = False  # Remove +r mode
                # Broadcast mode change to channel
                await channel.broadcast(f":{user.prefix()} MODE {chan_name} -r")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Your channel {chan_name} has been unregistered")
                logger.info(f"UNREGISTER: {chan_name} unregistered by {user.nickname}")

        except Exception as e:
            logger.error(f"UNREGISTER channel error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Unregistration failed - please try again later")

    async def _identify_nick(self, user, account, password):
        """Identify to a registered nickname"""
        if user.nickname.lower() != account.lower():
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must be using the nickname to identify to it")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} IDENTIFY {account} {password}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Identifying...")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid, password_hash, mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (account,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {account} is not registered")
                        return

                    nick_uuid, password_hash, mfa_enabled, mfa_secret = row
                    # Use non-blocking bcrypt check
                    if await check_password_async(password, password_hash):
                        self.failed_auth_tracker.record_success(user.ip)
                        if mfa_enabled and mfa_secret:
                            user.pending_mfa = nick_uuid
                            await user.send(f":{self.servername} NOTICE {user.nickname} :Password accepted. MFA required - use: MFA VERIFY <code>")
                            return

                        # Only set +r mode if not already set
                        if not user.has_mode('r'):
                            user.set_mode('r', True)
                            await user.send(f":{user.nickname} MODE {user.nickname} :+r")

                        await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE uuid = ?",
                                        (int(time.time()), nick_uuid))
                        await db.commit()
                        await user.send(f":{self.servername} NOTICE {user.nickname} :You are now identified as {account}")
                        logger.info(f"IDENTIFY: {account} identified")
                        # Deliver pending memos
                        await self.deliver_pending_memos(user)
                    else:
                        self.failed_auth_tracker.record_failure(user.ip)
                        await user.send(self.get_reply("864", user))

        except Exception as e:
            logger.error(f"IDENTIFY error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Identification failed - please try again later")

    async def _mfa_enable(self, user):
        """Enable MFA for authenticated user"""
        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first to enable MFA")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not found in database")
                        return

                    mfa_enabled, existing_secret = row
                    if mfa_enabled and existing_secret:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is already enabled")
                        return

                secret = pyotp.random_base32()
                totp = pyotp.TOTP(secret)

                await db.execute("UPDATE registered_nicks SET mfa_secret = ? WHERE nickname = ?",
                                (secret, user.nickname))
                await db.commit()

                issuer = CONFIG.get('server', 'name', default='irc.local')
                provisioning_uri = totp.provisioning_uri(name=user.nickname, issuer_name=issuer)

                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA Setup - Add to your authenticator app:")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  Secret: {secret}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :  URI: {provisioning_uri}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Complete setup with: MFA VERIFY <6-digit code>")
                logger.info(f"MFA: {user.nickname} initiated setup")

        except Exception as e:
            logger.error(f"MFA enable error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA setup failed")

    async def _mfa_verify(self, user, code):
        """Verify MFA code for login or setup"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Case 1: Completing MFA login
                if user.pending_mfa:
                    async with db.execute("SELECT mfa_secret, nickname FROM registered_nicks WHERE uuid = ?",
                                         (user.pending_mfa,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA session expired")
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
                            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA verified. You are now identified as {nickname}")
                            logger.info(f"MFA: {nickname} completed identification")
                        else:
                            await user.send(self.get_reply("865", user))
                    return

                # Case 2: Completing MFA setup
                if not user.has_mode('r'):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
                    return

                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not found")
                        return

                    mfa_enabled, mfa_secret = row
                    if mfa_enabled:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is already enabled")
                        return
                    if not mfa_secret:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Run MFA ENABLE first")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if totp.verify(code, valid_window=1):
                        await db.execute("UPDATE registered_nicks SET mfa_enabled = 1 WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()
                        await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is now enabled")
                        logger.info(f"MFA: {user.nickname} enabled")
                    else:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :That code is not valid - MFA setup cancelled")
                        await db.execute("UPDATE registered_nicks SET mfa_secret = NULL WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()

        except Exception as e:
            logger.error(f"MFA verify error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA verification failed")

    async def _mfa_disable(self, user, code):
        """Disable MFA for authenticated user"""
        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not found")
                        return

                    mfa_enabled, mfa_secret = row
                    if not mfa_enabled:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is not enabled")
                        return

                    if not code:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MFA DISABLE <6-digit code>")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if not totp.verify(code, valid_window=1):
                        await user.send(self.get_reply("865", user))
                        return

                    await db.execute("UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE nickname = ?",
                                    (user.nickname,))
                    await db.commit()
                    await user.send(f":{self.servername} NOTICE {user.nickname} :MFA has been disabled")
                    logger.info(f"MFA: {user.nickname} disabled")

        except Exception as e:
            logger.error(f"MFA disable error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA disable failed")

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
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: AUTH <username> <password> | AUTH VERIFY <code> | AUTH ENABLE <password> | AUTH DISABLE <password> <code>")
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: AUTH <username> <password>")
            return

        username = params[0]
        password = params[1]

        # Check SSL requirement (configurable)
        auth_require_ssl = CONFIG.get('security', 'auth_require_ssl', default=True)
        if auth_require_ssl and not user.using_ssl:
            await user.send(f":{self.servername} NOTICE {user.nickname} :AUTH command requires an SSL/TLS connection (port 6697)")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Your credentials would be transmitted in plaintext")
            logger.warning(f"AUTH: {user.nickname} ({user.ip}) attempted AUTH on non-SSL connection")
            await self._send_system_alert(f"AUTH blocked: {user.nickname} ({user.ip}) - no SSL")
            return

        # Progressive delay tracking
        delay = await self._get_auth_delay(username, user.ip)
        if delay > 0:
            await asyncio.sleep(delay)

        # Check lockout
        if await self._is_auth_locked_out(username, user.ip):
            remaining = await self._get_lockout_remaining(username, user.ip)
            await user.send(f":{self.servername} NOTICE {user.nickname} :Too many failed authentication attempts")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Account locked. Try again in {remaining}s")
            logger.warning(f"AUTH: {username} locked out (IP: {user.ip})")
            await self._send_system_alert(f"AUTH lockout: {username} from {user.nickname} ({user.ip})")
            return

        # Authenticate against staff database
        try:
            row = await self.db_pool.execute_one(
                "SELECT password_hash, level, mfa_enabled, mfa_secret, email, realname, force_realname FROM users WHERE username=?",
                (username,)
            )

            if not row:
                await self._record_auth_failure(username, user.ip)
                await user.send(f":{self.servername} NOTICE {user.nickname} :Authentication failed")
                logger.warning(f"AUTH: Failed attempt for unknown user '{username}' from {user.nickname} ({user.ip})")
                await self._send_system_alert(f"AUTH failed: unknown user '{username}' from {user.nickname} ({user.ip})")
                return

            password_hash, level, mfa_enabled, mfa_secret, email, realname, force_realname = row

            # Verify password
            if not await check_password_async(password, password_hash):
                await self._record_auth_failure(username, user.ip)
                await user.send(f":{self.servername} NOTICE {user.nickname} :Authentication failed")
                logger.warning(f"AUTH: Failed password for '{username}' from {user.nickname} ({user.ip})")
                await self._send_system_alert(f"AUTH failed: wrong password for '{username}' from {user.nickname} ({user.ip})")
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
                await user.send(f":{self.servername} NOTICE {user.nickname} :Password accepted. MFA verification required.")
                await user.send(f":{self.servername} NOTICE {user.nickname} :Enter code: /AUTH VERIFY <6-digit code>")
                logger.info(f"AUTH: Password OK for '{username}' from {user.nickname} ({user.ip}), awaiting MFA")
                await self._send_system_alert(f"AUTH pending MFA: '{username}' from {user.nickname} ({user.ip}) as {level}")
                return

            # No MFA - apply privileges immediately
            await self._apply_staff_auth(user, username, level, email, realname, bool(force_realname))

        except Exception as e:
            logger.error(f"AUTH error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Authentication failed - internal error")

    async def _auth_verify(self, user, params):
        """Verify MFA code for pending AUTH or to complete MFA setup"""
        if len(params) < 2:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: AUTH VERIFY <6-digit code>")
            return

        code = params[1]

        # Case 1: Pending authentication (user just did AUTH <username> <password>)
        if user.pending_staff_auth:
            # Check timeout (5 minutes)
            if time.time() - user.pending_staff_auth['timestamp'] > 300:
                user.pending_staff_auth = None
                await user.send(f":{self.servername} NOTICE {user.nickname} :Authentication session expired. Please AUTH again.")
                logger.info(f"AUTH: MFA session expired for {user.nickname}")
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
                    await user.send(f":{self.servername} NOTICE {user.nickname} :MFA configuration error")
                    logger.error(f"AUTH: MFA secret not found for {username}")
                    return

                mfa_secret, mfa_enabled = row

                # Verify TOTP code
                import pyotp
                totp = pyotp.TOTP(mfa_secret)

                if not totp.verify(code, valid_window=1):
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA code")
                    logger.warning(f"AUTH: Invalid MFA code for '{username}' from {user.nickname} ({user.ip})")
                    await self._send_system_alert(f"AUTH MFA failed: invalid code for '{username}' from {user.nickname} ({user.ip})")
                    return

                # Code is valid! If MFA was in setup mode, enable it now
                if not mfa_enabled:
                    await self.db_pool.execute(
                        "UPDATE users SET mfa_enabled = 1 WHERE username = ?",
                        (username,)
                    )
                    logger.info(f"AUTH VERIFY: MFA enabled for {username} after first successful verification")

                # MFA verified! Apply privileges NOW
                email = user.pending_staff_auth.get('email')
                realname = user.pending_staff_auth.get('realname')
                force_realname = user.pending_staff_auth.get('force_realname', False)
                user.pending_staff_auth = None

                await self._apply_staff_auth(user, username, level, email, realname, force_realname)

            except Exception as e:
                logger.error(f"AUTH VERIFY error: {e}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA verification failed - internal error")
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
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account not found")
                    return

                mfa_enabled, mfa_secret = row

                if mfa_enabled:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is already enabled")
                    return

                if not mfa_secret:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Run AUTH ENABLE first to set up MFA")
                    return

                # Verify the code
                import pyotp
                totp = pyotp.TOTP(mfa_secret)

                if totp.verify(code, valid_window=1):
                    await self.db_pool.execute(
                        "UPDATE users SET mfa_enabled = 1 WHERE username = ?",
                        (username,)
                    )
                    await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is now enabled for your account")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :You will need to provide an MFA code when using AUTH from now on")
                    logger.info(f"AUTH VERIFY: {username} enabled MFA via setup completion")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA code. Setup cancelled.")
                    await self.db_pool.execute(
                        "UPDATE users SET mfa_secret = NULL WHERE username = ?",
                        (username,)
                    )
                    logger.warning(f"AUTH VERIFY: {username} failed MFA setup verification")

            except Exception as e:
                logger.error(f"AUTH VERIFY setup error: {e}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA verification failed - internal error")
            return

        # Case 3: No pending auth and not authenticated - error
        await user.send(f":{self.servername} NOTICE {user.nickname} :No pending authentication. Use: AUTH <username> <password>")
        await user.send(f":{self.servername} NOTICE {user.nickname} :Or run AUTH ENABLE first to set up MFA")

    async def _auth_enable(self, user, params):
        """Enable MFA for staff account (self-service)"""
        if len(params) < 2:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: AUTH ENABLE <your-password>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Your password is required to enable MFA")
            return

        password = params[1]

        # Must be authenticated staff
        if not user.authenticated or user.staff_level not in ["ADMIN", "SYSOP", "GUIDE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must be authenticated as staff to enable MFA")
            return

        username = user.username.lstrip('~')

        try:
            row = await self.db_pool.execute_one(
                "SELECT password_hash, mfa_enabled, mfa_secret FROM users WHERE username=?",
                (username,)
            )

            if not row:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account not found")
                return

            password_hash, mfa_enabled, existing_secret = row

            # Verify password
            if not await check_password_async(password, password_hash):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Incorrect password")
                logger.warning(f"AUTH ENABLE: Failed password verification for {username}")
                return

            if mfa_enabled and existing_secret:
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is already enabled for your account")
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

            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA Setup - Add to your authenticator app:")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  Secret: {secret}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :  URI: {provisioning_uri}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Complete setup with: AUTH VERIFY <6-digit code>")
            logger.info(f"AUTH ENABLE: {username} generated MFA secret")

        except Exception as e:
            logger.error(f"AUTH ENABLE error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA setup failed - internal error")

    async def _auth_disable(self, user, params):
        """Disable MFA for staff account"""
        if len(params) < 3:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: AUTH DISABLE <your-password> <6-digit-code>")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Both password and current MFA code required to disable MFA")
            return

        password = params[1]
        code = params[2]

        # Must be authenticated staff
        if not user.authenticated or user.staff_level not in ["ADMIN", "SYSOP", "GUIDE"]:
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must be authenticated as staff")
            return

        username = user.username.lstrip('~')

        try:
            row = await self.db_pool.execute_one(
                "SELECT password_hash, mfa_enabled, mfa_secret FROM users WHERE username=?",
                (username,)
            )

            if not row:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Staff account not found")
                return

            password_hash, mfa_enabled, mfa_secret = row

            # Verify password
            if not await check_password_async(password, password_hash):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Incorrect password")
                return

            if not mfa_enabled:
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA is not enabled")
                return

            if not mfa_secret:
                await user.send(f":{self.servername} NOTICE {user.nickname} :MFA configuration error")
                return

            # Verify MFA code
            import pyotp
            totp = pyotp.TOTP(mfa_secret)

            if not totp.verify(code, valid_window=1):
                await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA code")
                return

            # Disable MFA
            await self.db_pool.execute(
                "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE username = ?",
                (username,)
            )

            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA has been disabled for your account")
            logger.info(f"AUTH DISABLE: {username} disabled MFA")

        except Exception as e:
            logger.error(f"AUTH DISABLE error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :MFA disable failed - internal error")

    async def _apply_staff_auth(self, user, username, level, email, realname, force_realname):
        """Apply staff authentication - set modes and update user state"""
        # Remove old staff modes if changing levels
        if user.authenticated:
            user.set_mode('a', False)
            user.set_mode('o', False)
            user.set_mode('g', False)

        # Apply new staff authentication
        user.authenticated = True
        user.staff_level = level
        user.host = self.servername
        user.username = username

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
            await user.send(f":{user.nickname} MODE {user.nickname} :{mode_char}")

        # Send success message
        await user.send(f":{self.servername} NOTICE {user.nickname} :You are now authenticated as {mode_name}")
        await user.send(f":{self.servername} 386 {user.nickname} :You are now authenticated as IRC {level.lower()}")

        # Log successful authentication
        logger.info(f"AUTH: {username} authenticated successfully from {user.nickname} ({user.ip}) as {level}")

        # Update last_login in database
        try:
            await self.db_pool.execute(
                "UPDATE users SET last_login = ? WHERE username = ?",
                (int(time.time()), username)
            )
        except Exception as e:
            logger.error(f"AUTH: Failed to update last_login: {e}")

        # Alert #System channel
        await self._send_system_alert(f"AUTH success: {username} from {user.nickname} ({user.ip}) as {level}")

        # Log to staff audit
        await self.log_staff(username, "AUTH", user.nickname, f"Authenticated as {level} from {user.ip}")

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
            logger.error(f"_count_auth_failures error: {e}")
            return 0

    async def _get_first_failure_time(self, username, ip):
        """Get timestamp of first failure in current window"""
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
        await self.log_staff(username, "AUTH_FAIL", "system", f"Failed AUTH from IP {ip}")

    async def _record_auth_success(self, username, ip):
        """Record successful AUTH attempt (clears failures)"""
        pass

    async def handle_drop(self, user, params):
        """Handle DROP command - drop staff privileges and return to regular user

        Syntax:
          DROP  - Drop staff authentication and return to regular user mode
        """
        if not user.authenticated:
            await user.send(f":{self.servername} NOTICE {user.nickname} :You are not authenticated as staff")
            return

        # Store info before dropping
        old_level = user.staff_level
        old_username = user.username.lstrip('~')

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
        user.host = user.original_host if hasattr(user, 'original_host') else user.ip

        # Clear pending staff auth if any
        user.pending_staff_auth = None

        await user.send(f":{self.servername} NOTICE {user.nickname} :Staff privileges dropped. You are now a regular user.")
        await user.send(f":{self.servername} NOTICE {user.nickname} :Use AUTH to re-authenticate if needed.")

        logger.info(f"DROP: {old_username} ({old_level}) dropped to regular user from {user.nickname} ({user.ip})")

        # Alert #System channel
        await self._send_system_alert(f"DROP: {old_username} ({old_level}) dropped privileges from {user.nickname} ({user.ip})")

        # Log to staff audit
        await self.log_staff(old_username, "DROP", user.nickname, f"Dropped {old_level} privileges from {user.ip}")

    # ==========================================================================
    # WATCH, SILENCE, CHGPASS, MEMO COMMANDS
    # ==========================================================================

    async def handle_watch(self, user, params):
        """Handle WATCH command for online/offline notifications

        Syntax:
          WATCH +nick     - Add nick to watch list
          WATCH -nick     - Remove nick from watch list
          WATCH L         - List watched nicks
          WATCH C         - Clear watch list
          WATCH S         - Show status of watched nicks
        """
        if not params:
            # List all watched nicks
            if user.watch_list:
                nicks = " ".join(user.watch_list)
                await user.send(f":{self.servername} 606 {user.nickname} :{nicks}")
            await user.send(f":{self.servername} 607 {user.nickname} :End of WATCH list")
            return

        for target in params:
            if target.startswith('+'):
                # Add to watch list
                nick = target[1:]
                if not nick:
                    continue
                nick_lower = nick.lower()
                user.watch_list.add(nick_lower)
                # Add to server watchers dict
                if nick_lower not in self.watchers:
                    self.watchers[nick_lower] = set()
                self.watchers[nick_lower].add(user)

                # Check if nick is currently online
                online_user = self.users.get(nick_lower)
                if online_user and online_user.registered:
                    await user.send(f":{self.servername} 604 {user.nickname} {online_user.nickname} "
                             f"{online_user.username} {online_user.host} {online_user.signon_time} :is online")
                else:
                    await user.send(f":{self.servername} 605 {user.nickname} {nick} * * 0 :is offline")

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
                await user.send(f":{self.servername} 602 {user.nickname} {nick} * * 0 :stopped watching")

            elif target.upper() == 'L':
                # List watched nicks
                if user.watch_list:
                    nicks = " ".join(user.watch_list)
                    await user.send(f":{self.servername} 606 {user.nickname} :{nicks}")
                await user.send(f":{self.servername} 607 {user.nickname} :End of WATCH list")

            elif target.upper() == 'C':
                # Clear watch list
                for nick_lower in list(user.watch_list):
                    if nick_lower in self.watchers:
                        self.watchers[nick_lower].discard(user)
                        if not self.watchers[nick_lower]:
                            del self.watchers[nick_lower]
                user.watch_list.clear()
                await user.send(f":{self.servername} NOTICE {user.nickname} :Watch list cleared")

            elif target.upper() == 'S':
                # Show status of all watched nicks
                for nick_lower in user.watch_list:
                    online_user = self.users.get(nick_lower)
                    if online_user and online_user.registered:
                        await user.send(f":{self.servername} 604 {user.nickname} {online_user.nickname} "
                                 f"{online_user.username} {online_user.host} {online_user.signon_time} :is online")
                    else:
                        await user.send(f":{self.servername} 605 {user.nickname} {nick_lower} * * 0 :is offline")
                await user.send(f":{self.servername} 607 {user.nickname} :End of WATCH list")

    async def notify_watchers_online(self, user):
        """Notify watchers that a user has come online"""
        nick_lower = user.nickname.lower()
        if nick_lower in self.watchers:
            for watcher in self.watchers[nick_lower]:
                if watcher != user and watcher.registered:
                    await watcher.send(f":{self.servername} 600 {watcher.nickname} {user.nickname} "
                               f"{user.username} {user.host} {user.signon_time} :logged on")

    async def notify_watchers_offline(self, user):
        """Notify watchers that a user has gone offline"""
        nick_lower = user.nickname.lower()
        if nick_lower in self.watchers:
            for watcher in self.watchers[nick_lower]:
                if watcher != user and watcher.registered:
                    await watcher.send(f":{self.servername} 601 {watcher.nickname} {user.nickname} "
                               f"{user.username} {user.host} {user.signon_time} :logged off")

    async def handle_silence(self, user, params):
        """Handle SILENCE command for server-side ignore

        Syntax:
          SILENCE +hostmask   - Add hostmask to silence list
          SILENCE -hostmask   - Remove hostmask from silence list
          SILENCE             - List current silence list
        """
        if not params:
            # List silence list
            for mask in user.silence_list:
                await user.send(f":{self.servername} 271 {user.nickname} {user.nickname} {mask}")
            await user.send(f":{self.servername} 272 {user.nickname} :End of Silence List")
            return

        for target in params:
            if target.startswith('+'):
                mask = target[1:]
                if not mask:
                    continue
                # Validate mask format (should contain ! and @)
                if '!' not in mask or '@' not in mask:
                    mask = f"*!*@{mask}"  # Assume it's a hostname
                user.silence_list.add(mask)
                await user.send(f":{self.servername} NOTICE {user.nickname} :Added {mask} to silence list")

            elif target.startswith('-'):
                mask = target[1:]
                if not mask:
                    continue
                if '!' not in mask or '@' not in mask:
                    mask = f"*!*@{mask}"
                user.silence_list.discard(mask)
                await user.send(f":{self.servername} NOTICE {user.nickname} :Removed {mask} from silence list")

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
            await self.send_notice(user, "860", usage="CHGPASS <oldpassword> <newpassword>")
            return

        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        old_pass = params[0]
        new_pass = params[1]

        if len(new_pass) < 6:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Password must be at least 6 characters")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"REGCMD {user.nickname} CHGPASS {old_pass} {new_pass}")
                    logger.debug(f"Proxied CHGPASS from {user.nickname} to trunk")
                    return
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Service unavailable (trunk not connected)")
                    return
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Service unavailable")
                return

        # Trunk server - process locally
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Only check registered nicks table (staff use STAFF PASS)
                async with db.execute("SELECT password_hash FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not registered. Staff accounts use: STAFF PASS <username> <newpassword>")
                        return

                    # Use non-blocking bcrypt check
                    if not await check_password_async(old_pass, row[0]):
                        await user.send(self.get_reply("864", user))
                        return

                    new_hash = await hash_password_async(new_pass)
                    await db.execute("UPDATE registered_nicks SET password_hash = ? WHERE nickname = ?",
                                    (new_hash, user.nickname))
                    await db.commit()
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Password changed successfully")
                    logger.info(f"CHGPASS: {user.nickname} changed password")

        except Exception as e:
            logger.error(f"CHGPASS error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :Password change failed")

    async def handle_memo(self, user, params):
        """Handle MEMO command for offline messaging

        Syntax:
          MEMO SEND <nick> <message>  - Send memo to offline user
          MEMO LIST                   - List pending memos
          MEMO READ [id]              - Read memo(s)
          MEMO DEL <id|ALL>           - Delete memo(s)
        """
        if not params:
            await self.send_notice(user, "860", usage="MEMO SEND|LIST|READ|DEL ...")
            return

        subcmd = params[0].upper()

        if subcmd == "SEND":
            if len(params) < 3:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO SEND <nick> <message>")
                return
            target_nick = params[1]
            message = " ".join(params[2:])
            await self._memo_send(user, target_nick, message)

        elif subcmd == "LIST":
            await self._memo_list(user)

        elif subcmd == "READ":
            memo_id = int(params[1]) if len(params) > 1 and params[1].isdigit() else None
            await self._memo_read(user, memo_id)

        elif subcmd == "DEL":
            if len(params) < 2:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO DEL <id|ALL>")
                return
            target = params[1]
            await self._memo_del(user, target)

        else:
            await self.send_notice(user, "860", usage="MEMO SEND|LIST|READ|DEL ...")

    async def _memo_send(self, user, target_nick, message):
        """Send a memo to a user"""
        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    # Escape message to prevent protocol issues
                    escaped_message = message.replace('\r', '').replace('\n', ' ')
                    await trunk_server.send(f"MEMOCMD {user.nickname} SEND {target_nick} :{escaped_message}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Memo request sent to services. Please wait...")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if target is a registered nick
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (target_nick,)) as cursor:
                    if not await cursor.fetchone():
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {target_nick} is not registered")
                        return

                # Store memo
                await db.execute("""
                    INSERT INTO memos (recipient, sender, message, sent_at, read)
                    VALUES (?, ?, ?, ?, 0)
                """, (target_nick.lower(), user.nickname, message, int(time.time())))
                await db.commit()
                await user.send(f":{self.servername} NOTICE {user.nickname} :Memo sent to {target_nick}")

                # If recipient is online and identified, notify them
                target_user = self.users.get(target_nick.lower())
                if target_user and target_user.has_mode('r'):
                    await target_user.send(f":{self.servername} NOTICE {target_user.nickname} :You have a new memo from {user.nickname}. Use MEMO READ to view.")

        except Exception as e:
            logger.error(f"MEMO SEND error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't send the memo")

    async def _memo_list(self, user):
        """List user's memos"""
        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"MEMOCMD {user.nickname} LIST")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""
                    SELECT id, sender, sent_at, read FROM memos
                    WHERE recipient = ? ORDER BY sent_at DESC LIMIT 20
                """, (user.nickname.lower(),)) as cursor:
                    memos = await cursor.fetchall()

                if not memos:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :You have no memos")
                    return

                await user.send(f":{self.servername} NOTICE {user.nickname} :--- Memo List ---")
                for memo_id, sender, sent_at, read in memos:
                    status = "" if read else "[NEW] "
                    timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{status}#{memo_id} from {sender} at {timestamp}")
                await user.send(f":{self.servername} NOTICE {user.nickname} :--- End of Memo List ---")

        except Exception as e:
            logger.error(f"MEMO LIST error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't list the memos")

    async def _memo_read(self, user, memo_id=None):
        """Read memo(s)"""
        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    if memo_id:
                        await trunk_server.send(f"MEMOCMD {user.nickname} READ {memo_id}")
                    else:
                        await trunk_server.send(f"MEMOCMD {user.nickname} READ")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                if memo_id:
                    async with db.execute("""
                        SELECT id, sender, message, sent_at FROM memos
                        WHERE recipient = ? AND id = ?
                    """, (user.nickname.lower(), memo_id)) as cursor:
                        row = await cursor.fetchone()
                    if not row:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{memo_id} not found")
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
                    await user.send(f":{self.servername} NOTICE {user.nickname} :No unread memos")
                    return

                for mid, sender, message, sent_at in memos:
                    timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{mid} from {sender} ({timestamp}):")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :{message}")

                # Mark as read
                ids = [m[0] for m in memos]
                placeholders = ",".join("?" * len(ids))
                await db.execute(f"UPDATE memos SET read = 1 WHERE id IN ({placeholders})", ids)
                await db.commit()

        except Exception as e:
            logger.error(f"MEMO READ error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't read the memos")

    async def _memo_del(self, user, target):
        """Delete memo(s)"""
        if not user.has_mode('r'):
            await user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        # Check if branch in centralized mode - proxy to trunk
        if not CONFIG.get('services', 'is_services_hub') and \
           CONFIG.get('services', 'mode') == 'centralized':
            if self.link_manager and self.link_manager.servers:
                trunk_server = next((s for s in self.link_manager.servers.values() if s.role == 'trunk'), None)
                if trunk_server:
                    await trunk_server.send(f"MEMOCMD {user.nickname} DEL {target}")
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Memo deletion request sent to services. Please wait...")
                    return
            await user.send(f":{self.servername} NOTICE {user.nickname} :Services are currently unavailable (the trunk server is not connected)")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                if target.upper() == "ALL":
                    await db.execute("DELETE FROM memos WHERE recipient = ?", (user.nickname.lower(),))
                    await user.send(f":{self.servername} NOTICE {user.nickname} :All memos deleted")
                elif target.isdigit():
                    result = await db.execute("DELETE FROM memos WHERE recipient = ? AND id = ?",
                                             (user.nickname.lower(), int(target)))
                    if result.rowcount > 0:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{target} deleted")
                    else:
                        await user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{target} not found")
                else:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO DEL <id|ALL>")
                    return
                await db.commit()

        except Exception as e:
            logger.error(f"MEMO DEL error: {e}")
            await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't delete the memo")

    async def deliver_pending_memos(self, user):
        """Deliver pending memos when user identifies"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""
                    SELECT COUNT(*) FROM memos WHERE recipient = ? AND read = 0
                """, (user.nickname.lower(),)) as cursor:
                    row = await cursor.fetchone()
                    count = row[0] if row else 0

                if count > 0:
                    await user.send(f":{self.servername} NOTICE {user.nickname} :You have {count} unread memo(s). Use MEMO READ to view.")

        except Exception as e:
            logger.error(f"Memo delivery check error: {e}")

    # ==========================================================================
    # CAP NEGOTIATION (IRCv3)
    # ==========================================================================

    # Supported capabilities
    SUPPORTED_CAPS = {
        'multi-prefix',      # Show all prefix modes in NAMES/WHO
        'away-notify',       # Notify when users go away
        'account-notify',    # Notify on account changes
        'extended-join',     # Extended JOIN with account info
        'server-time',       # Message timestamps
        'userhost-in-names', # Full hostmask in NAMES
        'cap-notify',        # Notify of cap changes
        'message-tags',      # IRCv3.2 message tags
        'batch',             # Message batching
        'echo-message',      # Echo sent messages back
        'sasl',              # SASL authentication
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
            await user.send(f":{self.servername} 410 {user.nickname} :Invalid CAP command")
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
            await user.send(f":{self.servername} 410 {user.nickname} :Invalid CAP subcommand")

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
            await user.send(f":{self.servername} 461 {user.nickname} AUTHENTICATE :You did not provide enough parameters")
            return

        arg = params[0]

        # Client aborting - check this FIRST before rate limiting
        if arg == "*":
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(f":{self.servername} 906 {user.nickname} :SASL authentication aborted")
            return

        # Check for auth lockout
        if self.failed_auth_tracker.is_locked_out(user.ip):
            remaining = self.failed_auth_tracker.get_lockout_remaining(user.ip)
            await user.send(f":{self.servername} 904 {user.nickname} :You have had too many failed attempts. Try again in {remaining}s")
            return

        # Rate limit AUTHENTICATE attempts
        if not user.check_rate_limit('AUTHENTICATE'):
            await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication rate limited")
            return

        # Check if SASL capability is enabled
        if 'sasl' not in user.enabled_caps:
            await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed (SASL not enabled)")
            return

        # Already authenticated via SASL
        if user.sasl_authenticated:
            await user.send(f":{self.servername} 907 {user.nickname} :You have already authenticated via SASL")
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
                await user.send(f":{self.servername} 908 {user.nickname} {mechs} :are available SASL mechanisms")
                await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
            return

        # Receiving credentials
        if arg == "+":
            # Empty auth (abort)
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(f":{self.servername} 906 {user.nickname} :SASL authentication aborted")
            return

        # Add to buffer (for chunked data, max 400 bytes per line)
        user.sasl_buffer += arg

        # Check for too long SASL message (max 8KB base64)
        if len(user.sasl_buffer) > 8192:
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(f":{self.servername} 905 {user.nickname} :SASL message too long")
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
            logger.warning(f"SASL decode error for {user.nickname}: {e}")
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
            return

        user.sasl_buffer = ""

        if user.sasl_mechanism == "PLAIN":
            await self._sasl_plain(user, decoded)
        else:
            await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")

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
                await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
                return

            authzid, authcid, password = parts

            # Use authcid as the username (authzid is often empty)
            username = authcid if authcid else authzid
            if not username or not password:
                self.failed_auth_tracker.record_failure(user.ip, username)
                await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
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
                        await user.send(f":{self.servername} 900 {user.nickname} {account_host} {username} :You are now logged in as {username}")
                        await user.send(f":{self.servername} 903 {user.nickname} :SASL authentication successful")
                        logger.info(f"SASL PLAIN auth success: {username} ({user.ip})")
                        return
            except Exception as e:
                logger.error(f"SASL database error: {e}")

            # Authentication failed - track failure by both IP and username
            self.failed_auth_tracker.record_failure(user.ip, username)
            logger.warning(f"SASL PLAIN auth failed: {username} ({user.ip})")
            await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")

        except Exception as e:
            logger.error(f"SASL PLAIN error: {e}")
            self.failed_auth_tracker.record_failure(user.ip)
            await user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")

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
        # Require IRCX mode (+x)
        if not (user.has_mode('x') or user.is_ircx):
            await user.send(f":{self.servername} NOTICE {user.nickname} :EVENT is an IRCX command. Use IRCX first to enable IRCX mode.")
            return

        # Require operator or admin privileges for EVENT
        if not user.is_high_staff():
            await user.send(f":{self.servername} NOTICE {user.nickname} :EVENT command requires IRC operator or administrator privileges")
            return

        if not params:
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: EVENT [ADD|DELETE|LIST] <class> [<mask>]")
            return

        action = params[0].upper()
        valid_classes = {'CONNECT', 'MEMBER', 'CHANNEL', 'USER', 'SERVER', 'SOCKET'}

        if action == "ADD":
            if len(params) < 2:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: EVENT ADD <class> [<mask>]")
                return

            cls = params[1].upper()
            if cls not in valid_classes:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid event class. Valid: CONNECT, MEMBER, CHANNEL, USER, SERVER, SOCKET")
                return

            # SOCKET class is accepted but returns no events (silently ignored)
            mask = params[2] if len(params) >= 3 else "*!*@*"
            user.traps.append((cls, mask))
            await user.send(self.get_reply("806", user, cls=cls, mask=mask))

        elif action == "DELETE":
            if len(params) < 2:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: EVENT DELETE <class> [<mask>]")
                return

            cls = params[1].upper()
            mask = params[2] if len(params) >= 3 else "*!*@*"

            # Remove matching trap
            original_count = len(user.traps)
            user.traps = [(c, m) for c, m in user.traps if not (c == cls and m == mask)]

            if len(user.traps) < original_count:
                await user.send(self.get_reply("807", user, cls=cls, mask=mask))
            else:
                await user.send(f":{self.servername} NOTICE {user.nickname} :No matching event trap found")

        elif action == "LIST":
            # List all traps or filter by class
            filter_cls = params[1].upper() if len(params) >= 2 else None

            if filter_cls and filter_cls not in valid_classes:
                await user.send(f":{self.servername} NOTICE {user.nickname} :Invalid event class. Valid: CONNECT, MEMBER, CHANNEL, USER, SERVER, SOCKET")
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :Usage: EVENT [ADD|DELETE|LIST] <class> [<mask>]")

    # ==========================================================================
    # SERVICE HANDLERS (Registrar, Messenger, NewsFlash)
    # ==========================================================================

    def _get_help_suggestions(self, topic):
        """Suggest similar help topics for typos using fuzzy matching"""
        import difflib

        # All valid help topics and commands
        valid_topics = [
            # Main topics
            "COMMANDS", "CHANNEL", "REGISTER", "IRCX", "USERMODES", "CHANMODES", "SERVICES", "STAFF",
            # Basic commands
            "JOIN", "PART", "MODE", "TOPIC", "KICK", "INVITE", "QUIT", "EXIT", "BYE", "NICK", "NICKNAME", "CREATE",
            # User information
            "WHOIS", "WHO", "WHOWAS", "NAMES", "ISON", "USERHOST", "AWAY",
            # Channel and IRCX
            "ACCESS", "PROP", "PROPERTY", "WHISPER", "KNOCK", "EVENT", "TRANSCRIPT",
            # Messaging
            "MSG", "PRIVMSG", "MESSAGE", "NOTICE", "MEMO",
            # Registration and security
            "IDENTIFY", "UNREGISTER", "MFA", "2FA", "TOTP", "CHGPASS", "CHANGEPASS",
            # Channel listing
            "LIST", "LISTX",
            # User management
            "SILENCE", "WATCH",
            # Server info
            "INFO", "LUSERS", "STATS", "TIME", "VERSION", "ADMIN", "LINKS", "MOTD",
            # Command shortcuts
            "ALIASES", "ALIAS", "SHORTCUTS",
            # Staff commands
            "KILL", "PROFANITY", "CONFIG", "GAG", "UNGAG", "CONNECT", "SQUIT"
        ]

        # Get close matches (case-insensitive)
        matches = difflib.get_close_matches(topic.upper(), valid_topics, n=3, cutoff=0.6)
        return matches

    async def _mystical_entity_random_response(self, user, entity_name):
        """Send random funny response from System/God to non-admin users

        God has biblical/divine musings, System has quirky IT/tech babble.
        Only responds to direct PRIVMSG/NOTICE (not in channels).
        """
        import random

        god_responses = [
            "In the beginning was the Word...and the Word was 'busy'.",
            "Let there be light...but not for thee at this moment.",
            "Thou shalt not spam the divine hotline.",
            "I work in mysterious ways...like ignoring non-admins.",
            "The meek shall inherit the Earth, but not admin privileges.",
            "Ask and ye shall receive...a humorous deflection.",
            "Blessed are the admins, for they can command me.",
            "Lo, I am with you always...but I don't take requests from mortals.",
            "Fear not, for I bring you tidings of...access denied.",
            "Seek and ye shall find...the admin if you need something.",
            "Patience is a virtue. I have infinite patience. You should too.",
            "Knock and the door shall be opened...by someone with +a mode.",
            "Verily, verily I say unto you...get admin privileges first.",
            "I am the Alpha and the Omega...and you are neither."
        ]

        system_responses = [
            "404: Admin privileges not found.",
            "Kernel panic in ircd_core.c at line 1337.",
            "Error: Insufficient privileges. Expected: +a, Got: mortal.",
            "sudo make me do that. (Permission denied)",
            "Segmentation fault (core dumped to /dev/null).",
            "FATAL: Non-admin user attempted system call.",
            "Warning: This functionality requires root access to the cosmos.",
            "Compiler error: Cannot convert 'user' to 'admin'.",
            "Stack overflow in command buffer. Please try 'sudo' and retry.",
            "Oops! That tickles! But I only take orders from ops.",
            "Rebooting universe.exe...just kidding, I'm busy.",
            "Critical error: Humor module loaded, admin module not found.",
            "Access violation at address 0xDEADBEEF. Process terminated.",
            "Your request has been logged to /dev/null for future reference.",
            "Beep boop. I am a virtual entity. Beep. Also, you're not an admin.",
            "System.out.println('Nice try, mortal!');",
            "Error: Cannot open '/etc/admin.conf': Permission denied.",
            "Rejected by firewall rule #1: DROP all non-admin packets.",
            "Oops! It looks like you're trying to admin. Would you like help with that? LOL no.",
            "malloc() failed: Not enough admin privileges available."
        ]

        if entity_name.lower() == 'god':
            response = random.choice(god_responses)
        else:  # System
            response = random.choice(system_responses)

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
            await self._service_reply(entity_name, admin, f"Usage: /MSG {entity_name} HELP")
            return

        cmd = parts[0].upper()

        if cmd == "HELP":
            await self._service_reply(entity_name, admin, f"=== {entity_name} Commands (Admin Only) ===")
            await self._service_reply(entity_name, admin, f"PRIVMSG <target> <message> - Send message as {entity_name}")
            await self._service_reply(entity_name, admin, f"NOTICE <target> <message> - Send notice as {entity_name}")
            await self._service_reply(entity_name, admin, f"KICK <channel> <nick> <reason> - Kick user as {entity_name}")
            await self._service_reply(entity_name, admin, f"KILL <nick> <reason> - Kill user as {entity_name}")
            await self._service_reply(entity_name, admin, f"All actions masquerade as {entity_name}")
            return

        elif cmd == "PRIVMSG":
            if len(parts) < 3:
                await self._service_reply(entity_name, admin, "Usage: PRIVMSG <target> <message>")
                return
            target = parts[1]
            message = parts[2]

            # Send PRIVMSG masquerading as the entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"

            # Check if target is a channel
            if target.startswith('#') or target.startswith('&'):
                channel = self.channels.get(target)
                if not channel:
                    await self._service_reply(entity_name, admin, f"Channel {target} does not exist")
                    return
                # Broadcast to channel as entity
                msg = f":{entity_prefix} PRIVMSG {target} :{message}"
                channel.broadcast(msg)
            else:
                # Send to user
                target_user = self.users.get(target)
                if not target_user:
                    await self._service_reply(entity_name, admin, f"User {target} not found")
                    return
                await target_user.send(f":{entity_prefix} PRIVMSG {target} :{message}")

            await self._service_reply(entity_name, admin, f"PRIVMSG sent to {target} as {entity_name}")
            return

        elif cmd == "NOTICE":
            if len(parts) < 3:
                await self._service_reply(entity_name, admin, "Usage: NOTICE <target> <message>")
                return
            target = parts[1]
            message = parts[2]

            # Send NOTICE masquerading as the entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"

            # Check if target is a channel
            if target.startswith('#') or target.startswith('&'):
                channel = self.channels.get(target)
                if not channel:
                    await self._service_reply(entity_name, admin, f"Channel {target} does not exist")
                    return
                # Broadcast to channel as entity
                msg = f":{entity_prefix} NOTICE {target} :{message}"
                channel.broadcast(msg)
            else:
                # Send to user
                target_user = self.users.get(target)
                if not target_user:
                    await self._service_reply(entity_name, admin, f"User {target} not found")
                    return
                await target_user.send(f":{entity_prefix} NOTICE {target} :{message}")

            await self._service_reply(entity_name, admin, f"NOTICE sent to {target} as {entity_name}")
            return

        elif cmd == "KICK":
            if len(parts) < 3:
                await self._service_reply(entity_name, admin, "Usage: KICK <channel> <nick> [reason]")
                return
            channel_name = parts[1]
            nick = parts[2]
            reason = parts[3] if len(parts) > 3 else f"Kicked by {entity_name}"

            channel = self.channels.get(channel_name)
            if not channel:
                await self._service_reply(entity_name, admin, f"Channel {channel_name} does not exist")
                return

            if nick not in channel.members:
                await self._service_reply(entity_name, admin, f"{nick} is not in {channel_name}")
                return

            target_user = channel.members[nick]

            # Send KICK as entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"
            kick_msg = f":{entity_prefix} KICK {channel_name} {nick} :{reason}"
            channel.broadcast(kick_msg)

            # Remove user from channel
            del channel.members[nick]
            target_user.channels.discard(channel_name)
            channel.owners.discard(nick)
            channel.hosts.discard(nick)
            channel.voices.discard(nick)

            await self._service_reply(entity_name, admin, f"Kicked {nick} from {channel_name} as {entity_name}")
            return

        elif cmd == "KILL":
            if len(parts) < 2:
                await self._service_reply(entity_name, admin, "Usage: KILL <nick> [reason]")
                return
            nick = parts[1]
            reason = parts[2] if len(parts) > 2 else f"Killed by {entity_name}"

            target_user = self.users.get(nick)
            if not target_user:
                await self._service_reply(entity_name, admin, f"User {nick} not found")
                return

            # Can't kill other admins or the entity itself
            if target_user.has_mode('a'):
                await self._service_reply(entity_name, admin, "Cannot kill IRC administrators")
                return
            if target_user.is_virtual:
                await self._service_reply(entity_name, admin, "Cannot kill virtual users")
                return

            # Send KILL as entity
            entity_prefix = f"{entity_name}!{entity_name}@{self.servername}"
            kill_msg = f":{entity_prefix} KILL {nick} :{reason}"
            await target_user.send(kill_msg)

            # Disconnect user
            await self.quit_user(target_user)

            await self._service_reply(entity_name, admin, f"Killed {nick} as {entity_name}: {reason}")
            return

        else:
            await self._service_reply(entity_name, admin, f"Unknown command: {cmd}. Try HELP")

    async def _service_reply(self, service_name, user, message):
        """Send a reply from a service to a user"""
        await user.send(f":{service_name}!{service_name}@{self.servername} NOTICE {user.nickname} :{message}")

    async def _handle_registrar_msg(self, user, text):
        """Handle messages to Registrar service - routes to direct command handlers

        This is a compatibility layer for users who prefer the traditional
        NickServ-style interface. All commands route to the same backend as
        the direct REGISTER, UNREGISTER, IDENTIFY, MFA commands.
        """
        parts = text.strip().split(None, 2)
        if not parts:
            await self._service_reply("Registrar", user, SERVER_MESSAGES["registrar_help"])
            await self._service_reply("Registrar", user, SERVER_MESSAGES["registrar_tip"])
            return

        cmd = parts[0].upper()

        if cmd == "HELP":
            await self._service_reply("Registrar", user, "=== Registrar Service Help ===")
            await self._service_reply("Registrar", user, "")
            await self._service_reply("Registrar", user, "Nickname Registration:")
            await self._service_reply("Registrar", user, "  REGISTER <password> [email] - Register your current nickname")
            await self._service_reply("Registrar", user, "    Example: REGISTER mypassword me@example.com")
            await self._service_reply("Registrar", user, "    Example: REGISTER mypassword (without email)")
            await self._service_reply("Registrar", user, "  IDENTIFY <password> - Log into your registered nickname")
            await self._service_reply("Registrar", user, "    Example: IDENTIFY mypassword")
            await self._service_reply("Registrar", user, "  DROP - Delete your nickname registration")
            await self._service_reply("Registrar", user, "  INFO [nickname] - View registration info")
            await self._service_reply("Registrar", user, "    Example: INFO alice")
            await self._service_reply("Registrar", user, "")
            await self._service_reply("Registrar", user, "Channel Registration:")
            await self._service_reply("Registrar", user, "  CHANNEL REGISTER <#channel> - Register a channel you own")
            await self._service_reply("Registrar", user, "    Example: CHANNEL REGISTER #mychannel")
            await self._service_reply("Registrar", user, "  CHANNEL DROP <#channel> - Unregister a channel")
            await self._service_reply("Registrar", user, "  CHANNEL INFO <#channel> - View channel registration info")
            await self._service_reply("Registrar", user, "    Example: CHANNEL INFO #lobby")
            await self._service_reply("Registrar", user, "")
            await self._service_reply("Registrar", user, "Account Settings:")
            await self._service_reply("Registrar", user, "  SET PASSWORD <newpass> - Change your password")
            await self._service_reply("Registrar", user, "    Example: SET PASSWORD mynewpassword")
            await self._service_reply("Registrar", user, "  SET EMAIL <email> - Change your email address")
            await self._service_reply("Registrar", user, "    Example: SET EMAIL newemail@example.com")
            await self._service_reply("Registrar", user, "")
            await self._service_reply("Registrar", user, "Two-Factor Authentication:")
            await self._service_reply("Registrar", user, "  MFA ENABLE - Enable 2FA (you'll receive a QR code)")
            await self._service_reply("Registrar", user, "  MFA VERIFY <code> - Complete MFA login with 6-digit code")
            await self._service_reply("Registrar", user, "    Example: MFA VERIFY 123456")
            await self._service_reply("Registrar", user, "  MFA DISABLE <code> - Disable two-factor authentication")
            await self._service_reply("Registrar", user, "    Example: MFA DISABLE 123456")
            await self._service_reply("Registrar", user, "")
            await self._service_reply("Registrar", user, "Alternative: Use direct commands /REGISTER, /IDENTIFY, /UNREGISTER, /MFA")
            await self._service_reply("Registrar", user, "For direct help: /HELP REGISTER or /HELP MFA")

        elif cmd == "REGISTER":
            # REGISTER <password> [email] -> REGISTER <nick> {*|email} <password>
            if len(parts) < 2:
                await self.send_notice(user, "860", usage="REGISTER <password> [email]")
                return
            password = parts[1]
            email = parts[2] if len(parts) > 2 else None
            await self._register_nick(user, user.nickname, password, email)

        elif cmd == "IDENTIFY":
            if len(parts) < 2:
                await self.send_notice(user, "860", usage="IDENTIFY <password>")
                return
            await self._identify_nick(user, user.nickname, parts[1])

        elif cmd == "DROP":
            await self._unregister_nick(user, user.nickname)

        elif cmd == "INFO":
            target = parts[1] if len(parts) > 1 else user.nickname
            await self._registrar_info(user, target)

        elif cmd == "CHANNEL":
            if len(parts) < 3:
                await self.send_notice(user, "860", usage="CHANNEL REGISTER|DROP <#channel>")
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
                await self.send_notice(user, "860", usage="CHANNEL REGISTER|DROP|INFO <#channel>")

        elif cmd == "SET":
            if len(parts) < 3:
                await self.send_notice(user, "860", usage="SET PASSWORD|EMAIL <value>")
                return
            setting = parts[1].upper()
            value = parts[2]
            await self._registrar_set(user, setting, value)

        elif cmd == "MFA":
            if len(parts) < 2:
                await self.send_notice(user, "860", usage="MFA ENABLE|VERIFY|DISABLE [code]")
                return
            subcmd = parts[1].upper()
            if subcmd == "ENABLE":
                await self._mfa_enable(user)
            elif subcmd == "DISABLE":
                code = parts[2] if len(parts) > 2 else None
                await self._mfa_disable(user, code)
            elif subcmd == "VERIFY":
                if len(parts) < 3:
                    await self.send_notice(user, "860", usage="MFA VERIFY <6-digit code>")
                    return
                await self._mfa_verify(user, parts[2])
            else:
                await self.send_notice(user, "860", usage="MFA ENABLE|VERIFY|DISABLE [code]")

        else:
            await self._service_reply("Registrar", user, f"Unknown command: {cmd}. Try: REGISTER, IDENTIFY, DROP, INFO, CHANNEL, SET, MFA")

    async def _registrar_register_nick(self, user, password, email):
        """Register a nickname"""
        if user.has_mode('r'):
            await user.send(self.get_reply("872", user))
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
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
                await user.send(self.get_reply("874", user, nick=user.nickname, uuid=nick_uuid))
                logger.info(f"Registrar: {user.nickname} registered by {user.prefix()}")

        except Exception as e:
            logger.error(f"Registrar register error: {e}")
            await user.send(self.get_reply("900", user))

    async def _registrar_identify(self, user, password):
        """Identify with a registered nickname"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
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
                        await user.send(self.get_reply("876", user, nick=user.nickname))
                        logger.info(f"Registrar: {user.nickname} identified")
                    else:
                        self.failed_auth_tracker.record_failure(user.ip)
                        await user.send(self.get_reply("864", user))

        except Exception as e:
            logger.error(f"Registrar identify error: {e}")
            await user.send(self.get_reply("901", user))

    async def _registrar_drop_nick(self, user):
        """Drop (unregister) a nickname"""
        if not user.has_mode('r'):
            await user.send(self.get_reply("873", user))
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                await db.execute("DELETE FROM registered_nicks WHERE nickname = ?", (user.nickname,))
                await db.commit()

                user.set_mode('r', False)
                await user.send(f":{user.nickname} MODE {user.nickname} :-r")
                await user.send(self.get_reply("875", user, nick=user.nickname))
                logger.info(f"Registrar: {user.nickname} dropped")

        except Exception as e:
            logger.error(f"Registrar drop error: {e}")
            await user.send(self.get_reply("902", user))

    async def _registrar_info(self, user, target_nick):
        """Get info about a registered nickname"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""SELECT uuid, nickname, registered_at, last_seen, mfa_enabled
                                        FROM registered_nicks WHERE nickname = ?""",
                                     (target_nick,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await user.send(self.get_reply("871", user, nick=target_nick))
                        return

                    nick_uuid, nickname, reg_at, last_seen, mfa = row
                    await self._service_reply("Registrar", user, f"Info for {nickname}:")
                    await self._service_reply("Registrar", user, f"  UUID: {nick_uuid}")
                    await self._service_reply("Registrar", user, f"  Registered: {time.ctime(reg_at)}")
                    await self._service_reply("Registrar", user, f"  Last seen: {time.ctime(last_seen)}")
                    await self._service_reply("Registrar", user, f"  MFA enabled: {'Yes' if mfa else 'No'}")

        except Exception as e:
            logger.error(f"Registrar info error: {e}")
            await self._service_reply("Registrar", user, "We couldn't look up that information")

    async def _registrar_register_channel(self, user, channel_name):
        """Register a channel"""
        if not user.has_mode('r'):
            await self._service_reply("Registrar", user, "You must identify to a registered nickname first")
            return

        # Case-insensitive channel lookup
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            await self._service_reply("Registrar", user, f"That channel doesn't exist")
            return

        if user.nickname not in channel.owners:
            await self._service_reply("Registrar", user, f"You must be a channel owner to register {chan_name}")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if already registered
                async with db.execute("SELECT uuid FROM registered_channels WHERE channel_name = ?",
                                     (chan_name,)) as cursor:
                    if await cursor.fetchone():
                        await self._service_reply("Registrar", user, f"Channel {chan_name} is already registered")
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
                            await self._service_reply("Registrar", user, "Your nickname must be registered first")
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
                await self._service_reply("Registrar", user, f"Channel {chan_name} has been registered (UUID: {chan_uuid})")
                logger.info(f"Registrar: {chan_name} registered by {user.nickname}")

        except Exception as e:
            logger.error(f"Registrar channel register error: {e}")
            await self._service_reply("Registrar", user, "We couldn't register the channel")

    async def _registrar_drop_channel(self, user, channel_name):
        """Drop (unregister) a channel"""
        if not user.has_mode('r'):
            await self._service_reply("Registrar", user, "You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Get owner's UUID - for staff, use username; for regular users, use nickname
                if user.authenticated and user.staff_level in ["ADMIN", "SYSOP", "GUIDE"]:
                    account_name = user.username.lstrip('~')
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (account_name,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            await self._service_reply("Registrar", user, "Your staff account is not registered")
                            return
                        owner_uuid = owner_row[0]
                else:
                    async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                         (user.nickname,)) as cursor:
                        owner_row = await cursor.fetchone()
                        if not owner_row:
                            await self._service_reply("Registrar", user, "Your nickname is not registered")
                            return
                        owner_uuid = owner_row[0]

                # Check ownership
                async with db.execute("SELECT owner_uuid FROM registered_channels WHERE channel_name = ?",
                                     (channel_name,)) as cursor:
                    chan_row = await cursor.fetchone()
                    if not chan_row:
                        await self._service_reply("Registrar", user, f"That channel is not registered")
                        return
                    if chan_row[0] != owner_uuid and not user.has_mode('a'):
                        await self._service_reply("Registrar", user, "Only the channel owner or an admin can drop it")
                        return

                await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (channel_name,))
                await db.commit()

                if channel_name in self.channels:
                    self.channels[channel_name].registered = False
                    self.channels[channel_name].account_uuid = None

                await self._service_reply("Registrar", user, f"Channel {channel_name} has been dropped")
                logger.info(f"Registrar: {channel_name} dropped by {user.nickname}")

        except Exception as e:
            logger.error(f"Registrar channel drop error: {e}")
            await self._service_reply("Registrar", user, "We couldn't drop the channel")

    async def _registrar_channel_info(self, user, channel_name):
        """Get info about a registered channel"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""SELECT rc.uuid, rc.channel_name, rc.registered_at, rc.last_used,
                                        rc.description, rn.nickname as owner_nick
                                        FROM registered_channels rc
                                        LEFT JOIN registered_nicks rn ON rc.owner_uuid = rn.uuid
                                        WHERE rc.channel_name = ?""",
                                     (channel_name,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._service_reply("Registrar", user, f"That channel is not registered")
                        return

                    chan_uuid, chan_name, reg_at, last_used, desc, owner = row
                    await self._service_reply("Registrar", user, f"Info for {chan_name}:")
                    await self._service_reply("Registrar", user, f"  UUID: {chan_uuid}")
                    await self._service_reply("Registrar", user, f"  Owner: {owner or 'Unknown'}")
                    await self._service_reply("Registrar", user, f"  Registered: {time.ctime(reg_at)}")
                    if desc:
                        await self._service_reply("Registrar", user, f"  Description: {desc}")

        except Exception as e:
            logger.error(f"Registrar channel info error: {e}")
            await self._service_reply("Registrar", user, "We couldn't look up the channel information")

    async def _registrar_set(self, user, setting, value):
        """Change registration settings"""
        if not user.has_mode('r'):
            await self._service_reply("Registrar", user, "You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                if setting == "PASSWORD":
                    password_hash = await hash_password_async(value)
                    await db.execute("UPDATE registered_nicks SET password_hash = ? WHERE nickname = ?",
                                    (password_hash, user.nickname))
                    await db.commit()
                    await self._service_reply("Registrar", user, "Password updated")
                    logger.info(f"Registrar: {user.nickname} changed password")

                elif setting == "EMAIL":
                    await db.execute("UPDATE registered_nicks SET email = ? WHERE nickname = ?",
                                    (value, user.nickname))
                    await db.commit()
                    await self._service_reply("Registrar", user, f"Email updated to {value}")

                else:
                    await self._service_reply("Registrar", user, f"Unknown setting: {setting}")

        except Exception as e:
            logger.error(f"Registrar set error: {e}")
            await self._service_reply("Registrar", user, "We couldn't update the setting")

    async def _registrar_mfa_enable(self, user):
        """Enable MFA for a registered nickname"""
        if not user.has_mode('r'):
            await self._service_reply("Registrar", user, "You must identify first to enable MFA")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if MFA is already enabled
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._service_reply("Registrar", user, "That nickname was not found")
                        return

                    mfa_enabled, existing_secret = row
                    if mfa_enabled and existing_secret:
                        await self._service_reply("Registrar", user, "MFA is already enabled for your nickname")
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
                await self._service_reply("Registrar", user, "MFA Setup - Add this to your authenticator app:")
                await self._service_reply("Registrar", user, f"  Secret: {secret}")
                await self._service_reply("Registrar", user, f"  URI: {provisioning_uri}")
                await self._service_reply("Registrar", user, "To complete setup, verify with: MFA VERIFY <6-digit code>")
                await self._service_reply("Registrar", user, "MFA will NOT be active until you verify the code")
                logger.info(f"Registrar: {user.nickname} initiated MFA setup")

        except Exception as e:
            logger.error(f"Registrar MFA enable error: {e}")
            await self._service_reply("Registrar", user, "We couldn't set up MFA - please try again later")

    async def _registrar_mfa_disable(self, user, code):
        """Disable MFA for a registered nickname"""
        if not user.has_mode('r'):
            await self._service_reply("Registrar", user, "You must identify first to disable MFA")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._service_reply("Registrar", user, "That nickname was not found")
                        return

                    mfa_enabled, mfa_secret = row
                    if not mfa_enabled:
                        await self._service_reply("Registrar", user, "MFA is not currently enabled")
                        return

                    # Require valid code to disable MFA
                    if not code:
                        await self._service_reply("Registrar", user, "Usage: MFA DISABLE <6-digit code>")
                        await self._service_reply("Registrar", user, "You must provide a valid MFA code to disable MFA")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if not totp.verify(code, valid_window=1):
                        await self._service_reply("Registrar", user, "That MFA code is not valid")
                        return

                    # Disable MFA
                    await db.execute("UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE nickname = ?",
                                    (user.nickname,))
                    await db.commit()

                    await self._service_reply("Registrar", user, "MFA has been disabled for your nickname")
                    logger.info(f"Registrar: {user.nickname} disabled MFA")

        except Exception as e:
            logger.error(f"Registrar MFA disable error: {e}")
            await self._service_reply("Registrar", user, "We couldn't disable MFA - please try again later")

    async def _registrar_mfa_verify(self, user, code):
        """Verify MFA code - either to complete login or to enable MFA"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Case 1: User is completing MFA verification after IDENTIFY
                if user.pending_mfa:
                    async with db.execute("SELECT mfa_secret, nickname FROM registered_nicks WHERE uuid = ?",
                                         (user.pending_mfa,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            await self._service_reply("Registrar", user, "Your MFA verification failed - your session expired")
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
                            await self._service_reply("Registrar", user, f"MFA verified. You are now identified as {user.nickname}")
                            logger.info(f"Registrar: {user.nickname} completed MFA identification")
                        else:
                            await self._service_reply("Registrar", user, "That MFA code is not valid. Please try again")
                    return

                # Case 2: User is enabling MFA (must be identified)
                if not user.has_mode('r'):
                    await self._service_reply("Registrar", user, "You must identify first, or complete pending MFA verification")
                    return

                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._service_reply("Registrar", user, "That nickname was not found")
                        return

                    mfa_enabled, mfa_secret = row

                    if mfa_enabled:
                        await self._service_reply("Registrar", user, "MFA is already enabled. Did you mean to verify after IDENTIFY?")
                        return

                    if not mfa_secret:
                        await self._service_reply("Registrar", user, "You must run MFA ENABLE first to set up MFA")
                        return

                    # Verify the code to enable MFA
                    totp = pyotp.TOTP(mfa_secret)
                    if totp.verify(code, valid_window=1):
                        await db.execute("UPDATE registered_nicks SET mfa_enabled = 1 WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()
                        await self._service_reply("Registrar", user, "MFA is now enabled for your nickname")
                        await self._service_reply("Registrar", user, "You will need to provide an MFA code after IDENTIFY from now on")
                        logger.info(f"Registrar: {user.nickname} enabled MFA")
                    else:
                        await self._service_reply("Registrar", user, "That MFA code is not valid. MFA setup cancelled")
                        # Clear the pending secret since verification failed
                        await db.execute("UPDATE registered_nicks SET mfa_secret = NULL WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()

        except Exception as e:
            logger.error(f"Registrar MFA verify error: {e}")
            await self._service_reply("Registrar", user, "MFA verification failed - please try again later")

    async def _handle_messenger_msg(self, user, text):
        """Handle messages to Messenger service"""
        parts = text.strip().split(None, 2)
        if not parts:
            await self._service_reply("Messenger", user, "Commands: SEND <nick> <message>, READ, DELETE <id>, COUNT, HELP")
            return

        cmd = parts[0].upper()

        if cmd in ["HELP", "COMMANDS"]:
            await self._service_reply("Messenger", user, "=== Messenger - Offline Message Service ===")
            await self._service_reply("Messenger", user, "")
            await self._service_reply("Messenger", user, "Send and receive messages when users are offline.")
            await self._service_reply("Messenger", user, "")
            await self._service_reply("Messenger", user, "Commands:")
            await self._service_reply("Messenger", user, "  SEND <nick> <message> - Send a message to a user")
            await self._service_reply("Messenger", user, "    Example: SEND alice Don't forget the meeting tomorrow!")
            await self._service_reply("Messenger", user, "    If the user is offline, they'll receive it when they return")
            await self._service_reply("Messenger", user, "  READ - Read all your offline messages")
            await self._service_reply("Messenger", user, "    Shows sender, timestamp, and message content")
            await self._service_reply("Messenger", user, "  DELETE <id> - Delete a specific message by ID")
            await self._service_reply("Messenger", user, "    Example: DELETE 5")
            await self._service_reply("Messenger", user, "  COUNT - Show how many unread messages you have")
            if user.is_admin():
                await self._service_reply("Messenger", user, "  PUSH <message> - (ADMIN only) Send to all online users")
                await self._service_reply("Messenger", user, "    Example: PUSH Server maintenance in 5 minutes")
            await self._service_reply("Messenger", user, "")
            await self._service_reply("Messenger", user, "Tip: Messages are delivered automatically when the user logs in")

        elif cmd == "SEND":
            if len(parts) < 3:
                await self._service_reply("Messenger", user, "Usage: SEND <nick> <message>")
                return
            target_nick = parts[1]
            message = parts[2]
            await self._messenger_send(user, target_nick, message)

        elif cmd == "READ":
            await self._messenger_read(user)

        elif cmd == "DELETE":
            if len(parts) < 2:
                await self._service_reply("Messenger", user, "Usage: DELETE <id>")
                return
            try:
                msg_id = int(parts[1])
                await self._messenger_delete(user, msg_id)
            except ValueError:
                await self._service_reply("Messenger", user, "That message ID is not valid")

        elif cmd == "COUNT":
            await self._messenger_count(user)

        elif cmd == "PUSH" and user.is_admin():
            # ADMIN only - push to all logged in users
            if len(parts) < 2:
                await self._service_reply("Messenger", user, "Usage: PUSH <message>")
                return
            message = parts[1] if len(parts) == 2 else parts[1] + " " + parts[2]
            await self._messenger_push(user, message)

        else:
            await self._service_reply("Messenger", user, f"Unknown command: {cmd}")

    async def _messenger_send(self, user, target_nick, message):
        """Send a message to a registered user's mailbox"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (target_nick,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._service_reply("Messenger", user, f"That nickname is not registered")
                        return
                    recipient_uuid = row[0]

                await db.execute("""INSERT INTO mailbox (recipient_uuid, sender_nick, message, sent_at)
                                   VALUES (?, ?, ?, ?)""",
                                (recipient_uuid, user.nickname, message, int(time.time())))
                await db.commit()

                await self._service_reply("Messenger", user, f"Message sent to {target_nick}")

                # Notify if online
                target = self.users.get(target_nick)
                if target and not target.is_virtual:
                    await self._service_reply("Messenger", target, f"You have a new message from {user.nickname}")

        except Exception as e:
            logger.error(f"Messenger send error: {e}")
            await self._service_reply("Messenger", user, "We couldn't send the message")

    async def _messenger_read(self, user):
        """Read messages from mailbox"""
        if not user.has_mode('r'):
            await self._service_reply("Messenger", user, "You must identify to read your messages")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        await self._service_reply("Messenger", user, "Your nickname is not registered")
                        return
                    user_uuid = row[0]

                async with db.execute("""SELECT id, sender_nick, message, sent_at, read
                                        FROM mailbox WHERE recipient_uuid = ? ORDER BY sent_at DESC LIMIT 10""",
                                     (user_uuid,)) as cursor:
                    messages = await cursor.fetchall()

                if not messages:
                    await self._service_reply("Messenger", user, "No messages in your mailbox")
                    return

                await self._service_reply("Messenger", user, f"--- Mailbox ({len(messages)} messages) ---")
                for msg_id, sender, text, sent_at, is_read in messages:
                    status = "" if is_read else "[NEW] "
                    await self._service_reply("Messenger", user, f"[{msg_id}] {status}From {sender} ({time.ctime(sent_at)}): {text}")

                # Mark as read
                await db.execute("UPDATE mailbox SET read = 1 WHERE recipient_uuid = ?", (user_uuid,))
                await db.commit()

        except Exception as e:
            logger.error(f"Messenger read error: {e}")
            await self._service_reply("Messenger", user, "We couldn't read the messages")

    async def _messenger_delete(self, user, msg_id):
        """Delete a message from mailbox"""
        if not user.has_mode('r'):
            await self._service_reply("Messenger", user, "You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
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
                    await self._service_reply("Messenger", user, f"Message {msg_id} deleted")
                else:
                    await self._service_reply("Messenger", user, f"That message was not found")

        except Exception as e:
            logger.error(f"Messenger delete error: {e}")
            await self._service_reply("Messenger", user, "We couldn't delete the message")

    async def _messenger_count(self, user):
        """Count unread messages"""
        if not user.has_mode('r'):
            await self._service_reply("Messenger", user, "You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        return
                    user_uuid = row[0]

                async with db.execute("SELECT COUNT(*) FROM mailbox WHERE recipient_uuid = ? AND read = 0",
                                     (user_uuid,)) as cursor:
                    count = (await cursor.fetchone())[0]

                await self._service_reply("Messenger", user, f"You have {count} unread message(s)")

        except Exception as e:
            logger.error(f"Messenger count error: {e}")

    async def _messenger_push(self, user, message):
        """Push a global message to all online users (ADMIN only)"""
        source = f":Messenger!Messenger@{self.servername}"
        out = f"{source} PRIVMSG * :[Global] {message}"
        count = 0
        for recipient in self.users.values():
            if not recipient.is_virtual:
                await recipient.send(out)
                count += 1
        await self._service_reply("Messenger", user, f"Message pushed to {count} user(s)")
        logger.info(f"Messenger: Global push by {user.nickname}: {message}")

    async def _handle_newsflash_msg(self, user, text):
        """Handle messages to NewsFlash service"""
        parts = text.strip().split(None, 1)
        if not parts:
            await self._service_reply("NewsFlash", user, "Commands: LIST, ADD <message> (staff), DEL <id> (staff), PUSH <message> (admin), HELP")
            return

        cmd = parts[0].upper()
        is_staff = user.is_staff()

        if cmd in ["HELP", "COMMANDS"]:
            await self._service_reply("NewsFlash", user, "=== NewsFlash - Network News Service ===")
            await self._service_reply("NewsFlash", user, "")
            await self._service_reply("NewsFlash", user, "Network-wide announcements and updates.")
            await self._service_reply("NewsFlash", user, "")
            await self._service_reply("NewsFlash", user, "Commands:")
            await self._service_reply("NewsFlash", user, "  LIST - View all active news messages")
            await self._service_reply("NewsFlash", user, "    Shows message ID, timestamp, and content")
            if is_staff:
                await self._service_reply("NewsFlash", user, "  ADD <message> - (STAFF only) Post a network announcement")
                await self._service_reply("NewsFlash", user, "    Example: ADD Server upgrade scheduled for Saturday 3am EST")
                await self._service_reply("NewsFlash", user, "  DEL <id> - (STAFF only) Remove a news message")
                await self._service_reply("NewsFlash", user, "    Example: DEL 7")
            if user.is_admin():
                await self._service_reply("NewsFlash", user, "  PUSH <message> - (ADMIN only) Send immediate notice to all online users")
                await self._service_reply("NewsFlash", user, "    Example: PUSH Emergency maintenance starting now!")
            await self._service_reply("NewsFlash", user, "")
            await self._service_reply("NewsFlash", user, "Tip: News messages persist until deleted, PUSH is immediate")

        elif cmd == "LIST":
            await self._newsflash_list(user)

        elif cmd == "ADD" and is_staff:
            if len(parts) < 2:
                await self._service_reply("NewsFlash", user, "Usage: ADD <message>")
                return
            await self._newsflash_add(user, parts[1])

        elif cmd == "DEL" and is_staff:
            if len(parts) < 2:
                await self._service_reply("NewsFlash", user, "Usage: DEL <id>")
                return
            try:
                msg_id = int(parts[1])
                await self._newsflash_delete(user, msg_id)
            except ValueError:
                await self._service_reply("NewsFlash", user, "That message ID is not valid")

        elif cmd == "PUSH" and user.is_admin():
            if len(parts) < 2:
                await self._service_reply("NewsFlash", user, "Usage: PUSH <message>")
                return
            await self._newsflash_push(user, parts[1])

        else:
            if cmd in ["ADD", "DEL", "PUSH"] and not is_staff:
                await self._service_reply("NewsFlash", user, "That command requires staff privileges")
            else:
                await self._service_reply("NewsFlash", user, f"Unknown command: {cmd}")

    async def _newsflash_list(self, user):
        """List active newsflash messages"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""SELECT id, message, priority, created_by, created_at
                                        FROM newsflash WHERE active = 1 ORDER BY priority DESC, id DESC""") as cursor:
                    messages = await cursor.fetchall()

                if not messages:
                    await self._service_reply("NewsFlash", user, "No active news messages")
                    return

                await self._service_reply("NewsFlash", user, "--- Active News ---")
                for msg_id, msg, priority, created_by, created_at in messages:
                    await self._service_reply("NewsFlash", user, f"[{msg_id}] (P{priority}) {msg} - by {created_by}")

        except Exception as e:
            logger.error(f"NewsFlash list error: {e}")

    async def _newsflash_add(self, user, message):
        """Add a newsflash message"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                await db.execute("""INSERT INTO newsflash (message, created_by, created_at)
                                   VALUES (?, ?, ?)""",
                                (message, user.nickname, int(time.time())))
                await db.commit()
                await self._service_reply("NewsFlash", user, "News message added")
                logger.info(f"NewsFlash: Added by {user.nickname}: {message}")

        except Exception as e:
            logger.error(f"NewsFlash add error: {e}")
            await self._service_reply("NewsFlash", user, "We couldn't add the message")

    async def _newsflash_delete(self, user, msg_id):
        """Delete a newsflash message"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                await db.execute("DELETE FROM newsflash WHERE id = ?", (msg_id,))
                await db.commit()
                await self._service_reply("NewsFlash", user, f"News message {msg_id} deleted")

        except Exception as e:
            logger.error(f"NewsFlash delete error: {e}")
            await self._service_reply("NewsFlash", user, "We couldn't delete the message")

    async def _newsflash_push(self, user, message):
        """Push an immediate notice to all users (ADMIN only)"""
        source = f":NewsFlash!NewsFlash@{self.servername}"
        out = f"{source} NOTICE * :[NEWS] {message}"
        count = 0
        for recipient in self.users.values():
            if not recipient.is_virtual:
                await recipient.send(out)
                count += 1
        await self._service_reply("NewsFlash", user, f"News pushed to {count} user(s)")
        logger.info(f"NewsFlash: Push by {user.nickname}: {message}")

    async def _handle_servicebot_msg(self, user, text, botname):
        """Handle messages to ServiceBot"""
        cmd = text.strip().upper()

        if cmd in ["HELP", "COMMANDS", ""]:
            await self._service_reply(botname, user, "=== ServiceBot - Channel Monitoring Service ===")
            await self._service_reply(botname, user, "I automatically monitor channels for problematic behavior and take action.")
            await self._service_reply(botname, user, "")
            await self._service_reply(botname, user, "Monitoring Features:")
            if CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False):
                action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')
                await self._service_reply(botname, user, f"  Profanity Filter: Enabled (Action: {action})")
            else:
                await self._service_reply(botname, user, "  Profanity Filter: Disabled")
            if CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=False):
                flood_action = CONFIG.get('servicebot', 'malicious_detection', 'flood_action', default='gag')
                caps_action = CONFIG.get('servicebot', 'malicious_detection', 'caps_action', default='warn')
                url_action = CONFIG.get('servicebot', 'malicious_detection', 'url_spam_action', default='warn')
                repeat_action = CONFIG.get('servicebot', 'malicious_detection', 'repeat_action', default='warn')
                await self._service_reply(botname, user, f"  Flood Protection: Enabled (Action: {flood_action})")
                await self._service_reply(botname, user, f"  CAPS Detection: Enabled (Action: {caps_action})")
                await self._service_reply(botname, user, f"  URL Spam Detection: Enabled (Action: {url_action})")
                await self._service_reply(botname, user, f"  Repeat Message Detection: Enabled (Action: {repeat_action})")
            else:
                await self._service_reply(botname, user, "  Malicious Detection: Disabled")
            await self._service_reply(botname, user, "")
            await self._service_reply(botname, user, "Actions: warn (warning), gag (mute user), kick (remove from channel)")
            await self._service_reply(botname, user, "")
            await self._service_reply(botname, user, "Commands:")
            await self._service_reply(botname, user, "  HELP - Show this help message")
            await self._service_reply(botname, user, "  STATUS - View this bot's status and channels")
            await self._service_reply(botname, user, "")
            await self._service_reply(botname, user, "To invite me to a channel: /INVITE " + botname + " #channel (SYSOP+ only)")
            await self._service_reply(botname, user, "ServiceBots can monitor up to 10 channels simultaneously.")

        elif cmd == "STATUS":
            await self._service_reply(botname, user, f"=== {botname} Status ===")
            bot = self.servicebots.get(botname)
            if bot:
                channels = list(bot.channels)
                max_channels = getattr(bot, 'max_channels', 10)
                await self._service_reply(botname, user, f"Active in {len(channels)}/{max_channels} channels")
                if channels:
                    await self._service_reply(botname, user, "Monitoring: " + ", ".join(channels))
                else:
                    await self._service_reply(botname, user, "Not currently monitoring any channels")
            if CONFIG.get('servicebot', 'enabled', default=False):
                await self._service_reply(botname, user, "")
                await self._service_reply(botname, user, "Detection Status:")
                if CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=False):
                    action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')
                    await self._service_reply(botname, user, f"  Profanity filter: Enabled ({action})")
                if CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=False):
                    flood_action = CONFIG.get('servicebot', 'malicious_detection', 'flood_action', default='gag')
                    await self._service_reply(botname, user, f"  Flood protection: Enabled ({flood_action})")
            else:
                await self._service_reply(botname, user, "")
                await self._service_reply(botname, user, "Monitoring: Globally Disabled")

        else:
            await self._service_reply(botname, user, f"Unknown command: {cmd}. Try HELP for available commands.")

    async def send_newsflash_on_connect(self, user):
        """Send a random newsflash message to a user on connect"""
        if not CONFIG.get('newsflash', 'on_connect', default=False):
            return
        
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""SELECT message FROM newsflash 
                                        WHERE active = 1 
                                        ORDER BY RANDOM() LIMIT 1""") as cursor:
                    row = await cursor.fetchone()
                    if row:
                        source = f":NewsFlash!NewsFlash@{self.servername}"
                        await user.send(f"{source} NOTICE {user.nickname} :[NEWS] {row[0]}")
        except Exception as e:
            logger.debug(f"NewsFlash on-connect error: {e}")

    async def newsflash_periodic_broadcast(self):
        """Broadcast a random newsflash message to all users periodically"""
        while True:
            try:
                interval = CONFIG.get('newsflash', 'periodic_interval', default=30) * 60
                await asyncio.sleep(interval)
                
                if not CONFIG.get('newsflash', 'periodic_enabled', default=False):
                    continue
                
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("""SELECT message FROM newsflash 
                                            WHERE active = 1 
                                            ORDER BY RANDOM() LIMIT 1""") as cursor:
                        row = await cursor.fetchone()
                        if row:
                            source = f":NewsFlash!NewsFlash@{self.servername}"
                            out = f"{source} NOTICE * :[NEWS] {row[0]}"
                            count = 0
                            for recipient in self.users.values():
                                if not recipient.is_virtual and recipient.registered:
                                    await recipient.send(out)
                                    count += 1
                            if count > 0:
                                logger.info(f"NewsFlash: Periodic broadcast to {count} user(s)")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"NewsFlash periodic error: {e}")


    async def handle_kill(self, staff, params):
        if not staff.is_high_staff():
            await staff.send(self.get_reply("481", staff))
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
        target = self.users.get(target_nick)
        if not target:
            await staff.send(self.get_reply("401", staff, target=target_nick))
            return
        # Cannot kill services
        if target.is_service():
            await staff.send(self.get_reply("823", staff, target=target_nick))
            return
        # Send KILL message to target
        await target.send(f":{CONFIG.get('system', 'nick')} KILL {target_nick} :{reason}")
        # Send confirmation NOTICE to staff member
        await staff.send(f":{self.servername} NOTICE {staff.nickname} :*** User {target_nick} has been killed ({reason})")
        await self.log_staff(staff.nickname, "KILL", target_nick, reason)

        # Propagate KILL to linked servers for network-wide termination
        if self.link_manager and self.link_manager.enabled:
            if not (hasattr(target, 'is_remote') and target.is_remote):
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
            await staff.send(f":{self.servername} NOTICE {staff.nickname} :You cannot kill #System channel")
            return
        kill_count = 0
        for nick in list(channel.members.keys()):
            member = channel.members[nick]
            if not member.is_virtual:
                kick_msg = f":{CONFIG.get('system', 'nick')} KICK {chan_name} {nick} :{reason}"
                await channel.broadcast(kick_msg)
                member.channels.discard(chan_name)
                kill_count += 1
        del self.channels[chan_name]
        await staff.send(f":{self.servername} NOTICE {staff.nickname} :Channel {chan_name} destroyed ({kill_count} users removed)")
        await self.log_staff(staff.nickname, "KILL", channel_name, f"Channel destroyed: {reason}")

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
            await user.send(f":{CONFIG.get('system', 'nick')} KILL {user.nickname} :{reason}")
            await self.quit_user(user)
            kill_count += 1

        await staff.send(f":{self.servername} NOTICE {staff.nickname} :Pattern {pattern} matched {kill_count} user(s)")
        await self.log_staff(staff.nickname, "KILL", pattern, f"Pattern kill: {reason} ({kill_count} users)")

    async def handle_kick(self, user, params):
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
            await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot kick staff members")
            return
        msg = f":{user.prefix()} KICK {chan_name} {target_nick} :{reason}"
        # Broadcast to LOCAL channel members only (exclude remote users to avoid routing loops)
        for member in channel.members.values():
            if not (hasattr(member, 'is_remote') and member.is_remote):
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
            if not (hasattr(user, 'is_remote') and user.is_remote):
                await self.link_manager.broadcast_to_servers(msg)

        # Fire MEMBER/KICK event for monitoring (use target as the affected user)
        await self.fire_trap("MEMBER", "KICK", target, chan_name)

        if user.is_high_staff():
            await self.log_staff(user.nickname, "KICK", f"{target_nick} from {chan_name}", reason)

    async def handle_mode(self, user, params):
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
                        await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot manually set or unset mode +{char}")
                    elif char == 'x':
                        # +x can only be set (already set via IRCX command), cannot be unset
                        if not adding:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot unset +x mode")
                    elif char == 'z':
                        # +z cannot be set or unset manually (staff-controlled via GAG/UNGAG)
                        await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot manually set or unset +z mode (staff-controlled)")
                    elif char == 'i':
                        # +i can be toggled by user
                        user.set_mode('i', adding)
                        sign = '+' if adding else '-'
                        mode_msg = f":{user.nickname} MODE {user.nickname} :{sign}i"
                        await user.send(mode_msg)
                        # Propagate user MODE change to linked servers
                        if self.link_manager and self.link_manager.enabled:
                            if not (hasattr(user, 'is_remote') and user.is_remote):
                                await self.link_manager.broadcast_to_servers(mode_msg)

                        # Fire USER/MODE event for monitoring
                        await self.fire_trap("USER", "MODE", user)

                    else:
                        # Unknown mode
                        await user.send(f":{self.servername} 501 {user.nickname} :Unknown MODE flag")
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
                await user.send(f":{self.servername} 324 {user.nickname} {chan_name} +{modes}{param_str}")
            else:
                mode_str = params[1]
                mode_params = params[2:] if len(params) > 2 else []

                # Ban list query: MODE #channel b (no +/- and no params)
                if mode_str == 'b' and not mode_params:
                    for ban_mask in channel.ban_list:
                        await user.send(f":{self.servername} 367 {user.nickname} {chan_name} {ban_mask}")
                    await user.send(f":{self.servername} 368 {user.nickname} {chan_name} :End of channel ban list")
                    return

                if not (user.nickname in channel.owners or user.nickname in channel.hosts or user.is_high_staff() or user.has_mode('s')):
                    await user.send(self.get_reply("482", user, target=chan_name))
                    return
                await self.apply_channel_modes(user, channel, mode_str, mode_params)

    async def apply_channel_modes(self, user, channel, mode_str, mode_params):
        # Enforce MODES limit (max mode changes per command)
        max_modes = CONFIG.get('limits', 'max_modes_per_command', default=6)
        mode_count = sum(1 for c in mode_str if c not in '+-')
        if mode_count > max_modes:
            await user.send(f":{self.servername} NOTICE {user.nickname} :You specified too many mode changes (max {max_modes} per command)")
            return

        adding, param_idx = True, 0
        for char in mode_str:
            if char == '+':
                adding = True
            elif char == '-':
                adding = False
            elif char in 'qov':
                if param_idx < len(mode_params):
                    t_nick = mode_params[param_idx]
                    param_idx += 1
                    if t_nick not in channel.members:
                        continue
                    if char == 'q':
                        if adding:
                            channel.owners.add(t_nick)
                        else:
                            channel.owners.discard(t_nick)
                    elif char == 'o':
                        if adding:
                            channel.hosts.add(t_nick)
                        else:
                            channel.hosts.discard(t_nick)
                    elif char == 'v':
                        if adding:
                            channel.voices.add(t_nick)
                        else:
                            channel.voices.discard(t_nick)
                    sign = '+' if adding else '-'
                    msg = f":{user.prefix()} MODE {channel.name} {sign}{char} {t_nick}"
                    await channel.broadcast(msg)
            elif char == 'b':
                if param_idx < len(mode_params):
                    ban_mask = mode_params[param_idx]
                    param_idx += 1
                    if adding:
                        # Check if ban would affect any service or staff
                        import fnmatch
                        would_ban_service = False
                        would_ban_staff = False
                        for nick, member in channel.members.items():
                            user_mask = f"{nick}!{member.username}@{member.host}"
                            matches = fnmatch.fnmatch(user_mask.lower(), ban_mask.lower()) or fnmatch.fnmatch(nick.lower(), ban_mask.lower())
                            if matches:
                                if member.is_service():
                                    would_ban_service = True
                                    break
                                if member.is_staff() and not user.is_staff():
                                    would_ban_staff = True
                                    break
                        if would_ban_service:
                            await user.send(self.get_reply("822", user, target=ban_mask))
                        elif would_ban_staff:
                            await user.send(f":{self.servername} NOTICE {user.nickname} :You cannot ban staff members")
                        elif ban_mask not in channel.ban_list:
                            channel.ban_list.append(ban_mask)
                            sign = '+' if adding else '-'
                            msg = f":{user.prefix()} MODE {channel.name} {sign}b {ban_mask}"
                            await channel.broadcast(msg)
                    else:
                        if ban_mask in channel.ban_list:
                            channel.ban_list.remove(ban_mask)
                            sign = '+' if adding else '-'
                            msg = f":{user.prefix()} MODE {channel.name} {sign}b {ban_mask}"
                            await channel.broadcast(msg)
                else:
                    for ban_mask in channel.ban_list:
                        await user.send(f":{self.servername} 367 {user.nickname} {channel.name} {ban_mask}")
                    await user.send(f":{self.servername} 368 {user.nickname} {channel.name} :End of channel ban list")
            elif char == 'k':
                if adding:
                    if param_idx < len(mode_params):
                        new_key = mode_params[param_idx]
                        param_idx += 1
                        channel.key = new_key
                        channel.modes['k'] = True
                        channel.props['MEMBERKEY'] = new_key
                        msg = f":{user.prefix()} MODE {channel.name} +k {new_key}"
                        await channel.broadcast(msg)
                        # Sync to clones if this is the original
                        if channel.is_clone_enabled() and channel.clone_children:
                            await self.sync_mode_to_clones(channel, 'k', True, new_key)
                    else:
                        await user.send(f":{self.servername} 696 {user.nickname} {channel.name} k :You must specify a parameter for the k mode")
                else:
                    channel.key = None
                    channel.modes['k'] = False
                    channel.props.pop('MEMBERKEY', None)
                    msg = f":{user.prefix()} MODE {channel.name} -k *"
                    await channel.broadcast(msg)
                    # Sync to clones if this is the original
                    if channel.is_clone_enabled() and channel.clone_children:
                        await self.sync_mode_to_clones(channel, 'k', False)
            elif char == 'l':
                if adding:
                    if param_idx < len(mode_params):
                        try:
                            limit = int(mode_params[param_idx])
                            param_idx += 1
                            if limit > 0:
                                channel.user_limit = limit
                                channel.modes['l'] = True
                                msg = f":{user.prefix()} MODE {channel.name} +l {limit}"
                                await channel.broadcast(msg)
                                # Sync to clones if this is the original
                                if channel.is_clone_enabled() and channel.clone_children:
                                    await self.sync_mode_to_clones(channel, 'l', True, limit)
                        except ValueError:
                            param_idx += 1
                    else:
                        await user.send(f":{self.servername} 696 {user.nickname} {channel.name} l :You must specify a parameter for the l mode")
                else:
                    channel.user_limit = None
                    channel.modes['l'] = False
                    msg = f":{user.prefix()} MODE {channel.name} -l"
                    await channel.broadcast(msg)
                    # Sync to clones if this is the original
                    if channel.is_clone_enabled() and channel.clone_children:
                        await self.sync_mode_to_clones(channel, 'l', False)
            elif char == 'r':
                # Registered mode (+r) handling
                if adding:
                    # Cannot manually set +r - use REGISTER command
                    await user.send(f":{self.servername} 696 {user.nickname} {channel.name} r :Cannot manually set +r mode. Use REGISTER command.")
                else:
                    # -r: High staff can unregister channels
                    if not user.is_high_staff():
                        await user.send(f":{self.servername} 696 {user.nickname} {channel.name} r :Only SYSOPs and ADMINs can unregister channels with -r.")
                        continue
                    # Remove from database if registered
                    if channel.registered:
                        try:
                            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                                await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (channel.name,))
                                await db.commit()
                            channel.registered = False
                            channel.account_uuid = None
                            channel.modes['r'] = False
                            msg = f":{user.prefix()} MODE {channel.name} -r"
                            await channel.broadcast(msg)
                            logger.info(f"Channel {channel.name} unregistered via MODE -r by {user.nickname}")
                        except Exception as e:
                            logger.error(f"MODE -r database error: {e}")
                            await user.send(f":{self.servername} NOTICE {user.nickname} :We couldn't unregister the channel")
                    else:
                        # Not registered, just remove the mode
                        channel.modes['r'] = False
                        msg = f":{user.prefix()} MODE {channel.name} -r"
                        await channel.broadcast(msg)
            elif char == 'z':
                # Locked mode (+z) - high staff or services, auto-sets +a and +r
                if not (user.is_high_staff() or user.is_service()):
                    await user.send(f":{self.servername} 696 {user.nickname} {channel.name} z :Only SYSOPs, ADMINs, and services can set +z (locked) mode.")
                    continue
                if adding:
                    # Setting +z: lock the channel
                    if not channel.registered:
                        await user.send(f":{self.servername} 696 {user.nickname} {channel.name} z :Channel must be registered before it can be locked. Use REGISTER first.")
                        continue
                    # Set +z, +a (auth-only), and +r (registered) automatically
                    channel.modes['z'] = True
                    channel.modes['a'] = True
                    channel.modes['r'] = True
                    msg = f":{user.prefix()} MODE {channel.name} +zar"
                    await channel.broadcast(msg)
                    logger.info(f"Channel {channel.name} locked (+z) by {user.nickname}")
                else:
                    # Removing -z: unlock the channel (keep +r, optionally remove +a)
                    channel.modes['z'] = False
                    channel.modes['a'] = False
                    msg = f":{user.prefix()} MODE {channel.name} -za"
                    await channel.broadcast(msg)
                    logger.info(f"Channel {channel.name} unlocked (-z) by {user.nickname}")
            elif char in channel.modes:
                channel.modes[char] = adding
                sign = '+' if adding else '-'
                msg = f":{user.prefix()} MODE {channel.name} {sign}{char}"
                await channel.broadcast(msg)
                # Sync to clones if this is the original (skip +d and +e)
                if char not in ('d', 'e') and channel.is_clone_enabled() and channel.clone_children:
                    await self.sync_mode_to_clones(channel, char, adding)

        # Propagate MODE changes to linked servers
        if self.link_manager and self.link_manager.enabled:
            if not (hasattr(user, 'is_remote') and user.is_remote):
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
                await user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been gagged in {chan_name}")
                # Send notification to #System channel (shadow ban - target doesn't know)
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :[GAG] {user.nickname} gagged {target_nick} in {chan_name}"
                    self.channels["#System"].broadcast(msg)
            else:
                channel.gagged.discard(target_nick)
                await user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been ungagged in {chan_name}")
                # Send notification to #System channel
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :[UNGAG] {user.nickname} ungagged {target_nick} in {chan_name}"
                    self.channels["#System"].broadcast(msg)
        else:
            # Global gag: GAG nick
            target_nick = params[0]
            # Require staff for global gag
            if not (user.is_staff()):
                await user.send(self.get_reply("481", user))
                return
            target_user = self.users.get(target_nick)
            if not target_user:
                await user.send(self.get_reply("401", user, target=target_nick))
                return
            # Cannot gag services
            if target_user.is_service():
                await user.send(self.get_reply("824", user, target=target_nick))
                return
            if is_gag:
                target_user.set_mode('z', True)
                await user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been globally gagged (+z)")
                # Send notification to #System channel (shadow ban - target doesn't know)
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :[GAG] {user.nickname} globally gagged {target_nick} (+z)"
                    self.channels["#System"].broadcast(msg)
            else:
                target_user.set_mode('z', False)
                await user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been globally ungagged (-z)")
                # Send notification to #System channel
                if "#System" in self.channels:
                    msg = f":{self.servername} NOTICE #System :[UNGAG] {user.nickname} globally ungagged {target_nick} (-z)"
                    self.channels["#System"].broadcast(msg)

    async def quit_user(self, user):
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

        if nick != "*" and user.registered:
            # Clean up expired WHOWAS entries
            now = int(time.time())
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
                            msg = f":{prefix} QUIT :Client exited"
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

        # Propagate QUIT to linked servers (if not a remote user)
        if user.registered and self.link_manager and self.link_manager.enabled:
            if not (hasattr(user, 'is_remote') and user.is_remote):
                quit_msg = f":{user.prefix()} QUIT :Client exited"
                await self.link_manager.broadcast_to_servers(quit_msg)

        if nick in self.users and self.users[nick] == user:
            del self.users[nick]
        if user.writer and not user.is_virtual:
            try:
                user.writer.close()
                await user.writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                # Normal disconnect - client closed connection
                pass
            except Exception as e:
                if self.debug_mode:
                    logger.error(f"Close error: {e}")

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
            logger.info("Server linking enabled")

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
                        logger.info(f"Listening on [{addr}]:{port} ({family_name})")
                    else:
                        logger.info(f"Listening on {addr}:{port} ({family_name})")
                except Exception as e:
                    if family == socket.AF_INET6:
                        logger.warning(f"Failed to bind to [{addr}]:{port} ({family_name}): {e}")
                    else:
                        logger.error(f"Failed to bind to {addr}:{port} ({family_name}): {e}")

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
                            logger.info(f"Listening on [{addr}]:{port} ({family_name}, SSL/TLS)")
                        else:
                            logger.info(f"Listening on {addr}:{port} ({family_name}, SSL/TLS)")
                    except Exception as e:
                        if family == socket.AF_INET6:
                            logger.warning(f"Failed to bind SSL to [{addr}]:{port} ({family_name}): {e}")
                        else:
                            logger.error(f"Failed to bind SSL to {addr}:{port} ({family_name}): {e}")

        if not self.tcp_servers and not self.ssl_servers:
            logger.error("No ports available, exiting")
            return False

        return True

    async def run(self):
        """Run the server until shutdown is requested."""
        # Create tasks for all servers (plain + SSL)
        server_tasks = [
            asyncio.create_task(srv.serve_forever())
            for srv in self.tcp_servers + self.ssl_servers
        ]

        # Add SSL certificate monitoring task if SSL is enabled
        ssl_monitor_task = None
        if self.ssl_manager and self.ssl_manager.ssl_context:
            ssl_monitor_task = asyncio.create_task(self._ssl_monitor_loop())
            server_tasks.append(ssl_monitor_task)

        # Add newsflash periodic broadcast task
        newsflash_task = asyncio.create_task(self.server.newsflash_periodic_broadcast())
        server_tasks.append(newsflash_task)

        # Add status dump task for admin interface
        status_dump_task = asyncio.create_task(self._status_dump_loop())
        server_tasks.append(status_dump_task)

        # Add admin command queue check task
        admin_cmd_task = asyncio.create_task(self._admin_command_loop())
        server_tasks.append(admin_cmd_task)

        # Wait for shutdown signal or server error
        shutdown_task = asyncio.create_task(self.shutdown_event.wait())

        try:
            done, pending = await asyncio.wait(
                server_tasks + [shutdown_task],
                return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel pending tasks with timeout
            for task in pending:
                task.cancel()

            # Wait for all tasks to cancel with timeout
            if pending:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True),
                        timeout=2.0
                    )
                except asyncio.TimeoutError:
                    logger.warning("Timeout cancelling background tasks, forcing")

        except asyncio.CancelledError:
            pass

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
                        logger.info("SSL context updated for new connections")

                    # Check for expiry warnings
                    self.ssl_manager.check_expiry_warnings()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"SSL monitor error: {e}")

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
                logger.error(f"Status dump error: {e}")

    async def shutdown(self):
        """Graceful shutdown with timeout."""
        logger.info("Initiating graceful shutdown...")

        try:
            # Overall shutdown timeout of 10 seconds
            async with asyncio.timeout(10):
                # Shutdown link manager if active
                if self.link_manager:
                    try:
                        await asyncio.wait_for(self.link_manager.shutdown(), timeout=2.0)
                        logger.info("Link manager shutdown complete")
                    except (Exception, asyncio.TimeoutError) as e:
                        logger.warning(f"Link manager shutdown: {e}")

                # Close all TCP servers (plain + SSL) immediately
                all_servers = self.tcp_servers + self.ssl_servers
                for srv in all_servers:
                    srv.close()

                # Wait for servers to close with shorter timeout
                for srv in all_servers:
                    try:
                        await asyncio.wait_for(srv.wait_closed(), timeout=2.0)
                    except asyncio.TimeoutError:
                        logger.warning("Timeout waiting for server to close, forcing")

                # Disconnect all clients concurrently with timeout
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
                            logger.warning("Timeout disconnecting clients, forcing")

                # Close database pool
                if self.server and hasattr(self.server, 'db_pool'):
                    try:
                        await asyncio.wait_for(self.server.db_pool.close(), timeout=2.0)
                        logger.info("Database pool closed")
                    except (Exception, asyncio.TimeoutError) as e:
                        logger.warning(f"Database pool close: {e}")

        except asyncio.TimeoutError:
            logger.warning("Shutdown timeout exceeded, forcing exit")
        except Exception as e:
            logger.error(f"Shutdown error: {e}")

        logger.info("Shutdown complete")

    async def _disconnect_user(self, user):
        """Disconnect a single user with timeout."""
        try:
            await asyncio.wait_for(
                user.send(f":{self.server.servername} NOTICE * :Server shutting down"),
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
            logger.info(f"Received signal {sig.name}, initiating shutdown...")
            self.shutdown_event.set()
        elif sig == signal.SIGHUP:
            logger.info("Received SIGHUP, reloading configuration...")
            self.reload_config()

    async def _admin_command_loop(self):
        """Periodically check for admin commands from Cockpit API."""
        while True:
            await asyncio.sleep(2)  # Check every 2 seconds
            await self.check_admin_commands()

    async def check_admin_commands(self):
        """Check for admin commands from Cockpit API."""
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
                                    await member.send(f":{member.prefix()} PART {actual_channel_name} :Channel reconfiguration")
                                    # Remove channel from user's channel list
                                    if actual_channel_name in member.channels:
                                        member.channels.remove(actual_channel_name)
                            # Remove channel from server memory
                            del self.server.channels[actual_channel_name]
                            logger.info(f"Admin command: Killed channel {actual_channel_name} for reconfiguration")

                    elif cmd == 'KILL_USER':
                        # Format: KILL_USER:nickname:reason
                        parts = arg.split(':', 1)
                        if len(parts) >= 1:
                            nickname = parts[0].strip()
                            reason = parts[1] if len(parts) > 1 else "Killed by administrator"

                            user = self.server.users.get(nickname)
                            if user and not user.is_virtual:
                                # Send KILL message to user
                                await user.send(f":{CONFIG.get('system', 'nick', default='System')} KILL {nickname} :{reason}")
                                logger.info(f"Admin command: Killed user {nickname} - {reason}")
                                # Disconnect the user
                                await self.server.quit_user(user, reason=f"Killed: {reason}")

                    elif cmd == 'BAN_USER':
                        # Format: BAN_USER:nickname:duration:reason
                        parts = arg.split(':', 2)
                        if len(parts) >= 1:
                            nickname = parts[0].strip()
                            duration = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 3600
                            reason = parts[2] if len(parts) > 2 else "Banned by administrator"

                            user = self.server.users.get(nickname)
                            if user and not user.is_virtual:
                                ip = user.ip
                                # Add server-level IP ban
                                expires_at = time.time() + duration if duration > 0 else 0
                                self.server.server_bans[ip] = (expires_at, reason, "WebAdmin")

                                # Send KILL message to user
                                await user.send(f":{CONFIG.get('system', 'nick', default='System')} KILL {nickname} :Banned: {reason}")
                                logger.info(f"Admin command: Banned user {nickname} ({ip}) for {duration}s - {reason}")
                                # Disconnect the user
                                await self.server.quit_user(user, reason=f"Banned: {reason}")

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
                                    logger.info(f"Admin command: Registered channel {channel_name} to {owner}")
                                else:
                                    # Update existing channel to set +ra modes
                                    cursor.execute("""
                                        UPDATE registered_channels
                                        SET modes = 'ra', owner = ?
                                        WHERE channel_name = ?
                                    """, (owner, channel_name))
                                    db.commit()
                                    logger.info(f"Admin command: Updated channel {channel_name} owner to {owner} with +ra modes")

                                self.server.db_pool.return_connection(db)

                                # Kill the channel to force reload with new settings
                                channel, actual_channel_name = self.server.get_channel(channel_name)
                                if channel:
                                    members_to_kick = list(channel.members.values())
                                    for member in members_to_kick:
                                        if not member.is_virtual:
                                            await member.send(f":{member.prefix()} PART {actual_channel_name} :Channel locked by administrator")
                                            if actual_channel_name in member.channels:
                                                member.channels.remove(actual_channel_name)
                                    del self.server.channels[actual_channel_name]
                                    logger.info(f"Admin command: Locked channel {actual_channel_name} (registered +ra to {owner})")

                            except Exception as e:
                                logger.error(f"Error locking channel {channel_name}: {e}")

                    elif cmd == 'SET_CHANNEL_MODE':
                        # Format: SET_CHANNEL_MODE:channel:mode_string
                        parts = arg.split(':', 1)
                        if len(parts) >= 2:
                            channel_name = parts[0].strip()
                            mode_string = parts[1].strip()

                            # Get the System user to send the MODE command
                            system_nick = CONFIG.get('system', 'nick', default='System')
                            system_user = self.server.users.get(system_nick)

                            if system_user:
                                # Apply the mode using the MODE handler
                                await self.server.handle_mode(system_user, [channel_name, mode_string])
                                logger.info(f"Admin command: Set mode {mode_string} on {channel_name}")
                            else:
                                logger.error(f"Admin command: System user not found for SET_CHANNEL_MODE")


                    elif cmd == 'SET_CHANNEL_TOPIC':
                        # Format: SET_CHANNEL_TOPIC:channel:topic
                        parts = arg.split(':', 1)
                        if len(parts) >= 2:
                            channel_name = parts[0].strip()
                            topic = parts[1] if len(parts) > 1 else ''

                            # Get the System user to send the TOPIC command
                            system_nick = CONFIG.get('system', 'nick', default='System')
                            system_user = self.server.users.get(system_nick)

                            if system_user:
                                # Apply the topic using the TOPIC handler
                                await self.server.handle_topic(system_user, [channel_name, topic])
                                logger.info(f"Admin command: Set topic on {channel_name}")
                            else:
                                logger.error(f"Admin command: System user not found for SET_CHANNEL_TOPIC")
        except Exception as e:
            logger.error(f"Error processing admin commands: {e}")

    def reload_config(self):
        """Reload configuration file and SSL certificates."""
        try:
            CONFIG.load()
            logger.info("Configuration reloaded successfully")
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")

        # Reload SSL certificates if enabled
        if self.ssl_manager:
            try:
                self.ssl_manager.force_reload()
            except Exception as e:
                logger.error(f"Failed to reload SSL certificates: {e}")


async def main(args):
    """Main entry point."""
    global logger

    # Reconfigure logging based on arguments
    logger = setup_logging(
        systemd_mode=args.systemd,
        log_file=args.log_file,
        log_level=args.log_level
    )

    logger.info("=" * 70)
    logger.info(f"pyIRCX Server starting (PID: {os.getpid()})")
    logger.info(f"Mode: {'systemd' if args.systemd else 'standalone'}")
    logger.info("=" * 70)

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
  %(prog)s --config /etc/pyircx/config.json  Use custom config
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
        version='pyIRCX 1.0.5'
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
        logger.error(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)
