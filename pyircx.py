#!/usr/bin/env python3
"""
pyIRCX - Python IRCX Server

An async IRC/IRCX server implementation with database-backed authentication,
channel persistence, flood protection, and staff management features.
"""

# Version info - updated with each release
__version__ = "1.0.0"
__version_label__ = "pyIRCX"
__created__ = "Wed Jan 01 2026"

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
    DEFAULT = {
        "server": {
            "name": "irc.local",
            "network": "IRCX Network",
            "staff_login_message": "Welcome to the staff team."
        },
        "network": {
            "listen_addr": "0.0.0.0",
            "listen_ports": [6667, 7000],
            "resolve_hostnames": True  # Resolve IP to hostname
        },
        "database": {
            "path": "pyircx.db"
        },
        "system": {
            "nick": "System",
            "ident": "System",
            "staff_term": "staff and services"
        },
        "modes": {
            "user": "agiorxz",  # Alphabetized: admin, guide, invisible, oper, registered, ircx, gagged
            "channel": "adfhijkmnprstuwxy"  # Alphabetized: admin, auditorium, filter, hidden, invite, no-invitations, key, moderated, no-external, private, registered, secret, topic-lock, user-limit, no-whisper, ircx, transcript
        },
        "limits": {
            "max_users": 1000,
            "msg_length": 512,
            "nick_change_cooldown": 60,
            "max_nick_length": 30,
            "max_user_length": 30,
            "max_channel_length": 50
        },
        "services": {
            "servicebot_count": 10,
            "servicebot_max_channels": 10
        },
        "security": {
            "flood_messages": 5,
            "flood_window": 2.0,
            "connection_throttle": 3,
            "throttle_window": 10.0,
            "enable_flood_protection": True,
            "enable_connection_throttle": True,
            "dnsbl": {
                "enabled": False,  # Enable DNSBL checking
                "action": "reject",  # reject, mark, warn
                "timeout": 3.0,  # DNS query timeout in seconds
                "lists": [
                    # Popular DNS blacklists - enable as needed
                    "dnsbl.dronebl.org",
                    "rbl.efnetrbl.org",
                    "bl.spamcop.net",
                    "dnsbl.sorbs.net"
                ],
                "whitelist": [],  # IPs to skip DNSBL checks (CIDR supported)
                "cache_ttl": 3600,  # Cache results for 1 hour
                "reject_message": "Your IP is listed in a DNS blacklist. Contact staff if you believe this is an error."
            },
            "proxy_detection": {
                "enabled": False,  # Check for known proxy/VPN ports
                "ports": [8080, 3128, 1080, 9050],  # Common proxy ports
                "timeout": 2.0,
                "action": "mark"  # reject, mark, warn
            },
            "connection_scoring": {
                "enabled": False,
                "threshold": 100,  # Score above this = reject
                "dnsbl_score": 50,  # Points for DNSBL listing
                "proxy_score": 30,  # Points for open proxy
                "no_ident_score": 10,  # Points for no ident response
                "generic_hostname_score": 5  # Points for generic ISP hostname
            }
        },
        "persistence": {
            "auto_save": True,
            "save_interval": 300
        },
        "transcript": {
            "enabled": True,
            "directory": "transcripts",
            "max_lines": 10000,  # Max lines per transcript file before rotation
            "format": "[{timestamp}] {event}"  # Log format
        },
        "servicebot": {
            "enabled": True,
            "profanity_filter": {
                "enabled": True,
                "action": "warn",  # warn, gag, kick, ban
                "words": ["badword1", "badword2"],  # Default placeholder list
                "warn_message": "Please watch your language.",
                "case_sensitive": False
            },
            "malicious_detection": {
                "enabled": True,
                "flood_threshold": 5,  # Messages in window
                "flood_window": 3,  # Seconds
                "flood_action": "gag",  # warn, gag, kick, ban
                "caps_threshold": 0.7,  # 70% caps triggers
                "caps_min_length": 10,  # Min message length to check caps
                "caps_action": "warn",
                "url_spam_threshold": 3,  # URLs in window
                "url_spam_window": 10,  # Seconds
                "url_spam_action": "warn",
                "repeat_threshold": 3,  # Same message count
                "repeat_window": 30,  # Seconds
                "repeat_action": "warn"
            }
        },
        "admin": {
            "loc1": "Server Administration",
            "loc2": "Network Operations",
            "email": "admin@irc.local"
        }
    }

    def __init__(self, config_file="pyircx_config.json"):
        self.config_file = config_file
        self.data = self._deep_copy(self.DEFAULT)
        self.load()

    def _deep_copy(self, d):
        if isinstance(d, dict):
            return {k: self._deep_copy(v) for k, v in d.items()}
        return d

    def load(self):
        if Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    self._merge(self.data, loaded)
                logger.info(f"Loaded config from {self.config_file}")
            except Exception as e:
                logger.error(f"Config error: {e}")
        else:
            self.save()

    def save(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info("Config saved")
        except Exception as e:
            logger.error(f"Save error: {e}")

    def _merge(self, base, override):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge(base[key], value)
            else:
                base[key] = value

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
    # IPv4 pattern: digits and dots only, 4 octets
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    # IPv6 pattern: hex digits and colons, with optional :: compression
    # Matches full form, compressed form, and mixed IPv4/IPv6
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::$|^::1$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    # Hostname pattern: word characters with dots (like foo.bar.com)
    hostname_pattern = r'^[\w-]+\.[\w.-]+$'
    # Also check using ipaddress module for robust IPv6 detection
    if ':' in s:
        try:
            import ipaddress
            ipaddress.ip_address(s)
            return True
        except ValueError:
            pass
    return bool(re.match(ipv4_pattern, s) or re.match(ipv6_pattern, s) or re.match(hostname_pattern, s))


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
        'LIST': 5.0,
        'MODE': 0.5,
        'PROP': 1.0,
        'INVITE': 2.0,
        'KICK': 1.0,
        'ACCESS': 2.0,
        'KNOCK': 5.0,
        'TOPIC': 1.0,
        'AUTHENTICATE': 2.0,  # Rate limit SASL auth attempts
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
    """Track failed authentication attempts per IP for lockout"""

    def __init__(self, max_attempts=5, lockout_duration=300, window=600):
        self.max_attempts = max_attempts  # Max failures before lockout
        self.lockout_duration = lockout_duration  # Lockout time in seconds
        self.window = window  # Time window to track failures
        self.failures = defaultdict(deque)  # {ip: deque of timestamps}
        self.lockouts = {}  # {ip: lockout_until_timestamp}

    def record_failure(self, ip):
        """Record a failed auth attempt"""
        now = time.time()
        self._cleanup(ip, now)
        self.failures[ip].append(now)

        # Check if we need to lock out
        if len(self.failures[ip]) >= self.max_attempts:
            self.lockouts[ip] = now + self.lockout_duration
            self.failures[ip].clear()
            logger.warning(f"Auth lockout triggered for {ip} ({self.lockout_duration}s)")
            return True  # Lockout triggered
        return False

    def record_success(self, ip):
        """Clear failures on successful auth"""
        if ip in self.failures:
            del self.failures[ip]
        if ip in self.lockouts:
            del self.lockouts[ip]

    def is_locked_out(self, ip):
        """Check if IP is currently locked out"""
        if ip not in self.lockouts:
            return False
        now = time.time()
        if now >= self.lockouts[ip]:
            del self.lockouts[ip]
            return False
        return True

    def get_lockout_remaining(self, ip):
        """Get remaining lockout time in seconds"""
        if ip not in self.lockouts:
            return 0
        remaining = self.lockouts[ip] - time.time()
        return max(0, int(remaining))

    def _cleanup(self, ip, now):
        """Remove old entries outside the window"""
        while self.failures[ip] and self.failures[ip][0] < now - self.window:
            self.failures[ip].popleft()


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
        """Get a connection from the pool"""
        if not self._initialized:
            await self.initialize()
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

        self.is_virtual = is_virtual
        self.modes = {m: False for m in CONFIG.get(
            'modes', 'user', default='aioxzg')}
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
        self.watch_list = set()  # Nicknames this user is watching
        self.silence_list = set()  # Hostmask patterns to ignore

        # DNSBL and connection security
        self.dnsbl_listed = []  # List of DNSBLs this IP is on (if any)
        self.connection_score = 0  # Risk score for this connection
        self.connection_factors = {}  # Factors contributing to score

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

    def prefix(self):
        return f"{self.nickname}!{self.username}@{self.host}"

    def check_flood(self):
        return self.flood_protection.check()

    def check_rate_limit(self, cmd):
        return self.rate_limiter.check(cmd)

    def send(self, msg):
        if self.is_virtual or not self.writer:
            return
        max_len = CONFIG.get('limits', 'msg_length', default=512)
        if len(msg) > max_len:
            msg = msg[:max_len]
        out = msg if msg.endswith("\r\n") else msg + "\r\n"
        try:
            self.writer.write(out.encode('utf-8', errors='replace'))
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
        generic_patterns = [
            r'\d+[-\.]\d+[-\.]\d+[-\.]\d+',  # IP in hostname
            r'^(dsl|cable|dial|dynamic|dhcp|pool|client|user|host|node)',
            r'\.(dsl|cable|dynamic|dhcp)\.',
            r'(comcast|verizon|charter|cox|att|centurylink|frontier).*\d',
        ]
        hostname_lower = hostname.lower()
        for pattern in generic_patterns:
            if re.search(pattern, hostname_lower):
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
        Returns (contains_profanity, matched_word) tuple.
        """
        if not CONFIG.get('servicebot', 'profanity_filter', 'enabled', default=True):
            return False, None

        words = CONFIG.get('servicebot', 'profanity_filter', 'words', default=[])
        case_sensitive = CONFIG.get('servicebot', 'profanity_filter', 'case_sensitive', default=False)

        check_text = text if case_sensitive else text.lower()

        for word in words:
            check_word = word if case_sensitive else word.lower()
            # Word boundary matching to avoid false positives
            pattern = r'\b' + re.escape(check_word) + r'\b'
            if re.search(pattern, check_text, re.IGNORECASE if not case_sensitive else 0):
                return True, word

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
        """
        violations = []

        # Check profanity
        has_profanity, matched = self.check_profanity(text)
        if has_profanity:
            action = CONFIG.get('servicebot', 'profanity_filter', 'action', default='warn')
            violations.append(('profanity', action, f"matched word: {matched}"))

        # Check flood
        if self.check_flood(nickname, text):
            action = CONFIG.get('servicebot', 'malicious_detection', 'flood_action', default='gag')
            violations.append(('flood', action, "message flooding"))

        # Check repeat spam
        if self.check_repeat(nickname, text):
            action = CONFIG.get('servicebot', 'malicious_detection', 'repeat_action', default='warn')
            violations.append(('repeat', action, "repeated message spam"))

        # Check excessive caps
        if self.check_caps(text):
            action = CONFIG.get('servicebot', 'malicious_detection', 'caps_action', default='warn')
            violations.append(('caps', action, "excessive caps"))

        # Check URL spam
        if self.check_url_spam(nickname, text):
            action = CONFIG.get('servicebot', 'malicious_detection', 'url_spam_action', default='warn')
            violations.append(('url_spam', action, "URL spam"))

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
        self.modes = {m: False for m in CONFIG.get(
            'modes', 'channel', default='adfimnprstuwxz')}
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

    def broadcast(self, msg, exclude=None):
        for member in self.members.values():
            if member != exclude:
                member.send(msg)

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
            'user_limit': self.user_limit,
            'clone_parent': self.clone_parent,
            'clone_children': self.clone_children,
            'clone_index': self.clone_index,
            'onjoin': self.onjoin,
            'onpart': self.onpart,
            'access_list': self.access_list
        }

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
        return channel


# ==============================================================================
# RESPONSE TABLE
# ==============================================================================
RESPONSES = {
    "001": "Welcome to the {network}, {nick}",
    "002": "Your host is {servername}, running version {version_label} {version}",
    "003": "This server was created {created_date}",
    "004": "{servername} {version_label} {version} {usermodes} {chanmodes}",
    "005": "CHANTYPES=#& PREFIX=(qov).@+ CHANMODES={chanmodes} NICKLEN={nicklen} USERLEN={userlen} CHANNELLEN={chanlen} MODES=20 NETWORK={network_name} IRCX ACCESS PROPS :are supported",
    "219": "{flag} :End of /STATS report",
    "221": "+{modes}",
    "251": "There are {users} users and {invisible} invisible on {server_count} servers",
    "252": "{ops} :{staff_term} online",
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
    "312": "{target} {servername} :{version} {version_label}",
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
    "366": "{channel} :End of /NAMES list.",
    "367": "{channel} {mask}",
    "368": "{channel} :End of channel ban list",
    "369": "{target} :End of WHOWAS",
    "371": ":{info}",
    "372": "- {text}",
    "374": ":End of /INFO list",
    "375": "- {servername} Message of the Day -",
    "376": "End of /MOTD command",
    "422": "MOTD File is missing",
    "381": "You are now an IRC {role}",
    "386": "{staff_login_message}",
    "391": ":Local time is {time}",
    "401": "{target} :No such nick/channel",
    "403": "{target} :No such channel",
    "404": "{channel} :Cannot send to channel",
    "407": "{target} :Too many recipients",
    "421": "{command} :Unknown command",
    "432": "{target} :Erroneous nickname",
    "433": "{target} :Nickname is already in use",
    "441": "{target} {channel} :They aren't on that channel",
    "442": "{target} :You're not on that channel",
    "443": "{target} {channel} :is already on channel",
    "451": "You have not registered",
    "461": "{command} :Not enough parameters",
    "462": "You may not reregister",
    "468": ":Invalid username",
    "471": "{target} :Cannot join channel (+l)",
    "473": "{target} :Cannot join channel (+i)",
    "474": "{target} :Cannot join channel (+b)",
    "475": "{target} :Cannot join channel (+k)",
    "481": "Permission Denied - You're not an IRC operator",
    "482": "{target} :You're not a channel owner or host",
    "696": "{target} {mode} :You must specify a parameter for the {mode} mode",
    "710": "{channel} {nick} {host} :has asked for an invite",
    "711": "{target} :Your KNOCK has been delivered",
    "712": "{target} :Too many KNOCKs",
    "713": "{target} :Channel is open",
    "714": "{target} :You are already on that channel",
    "716": "{target} :User is in knock mode (+u)",
    "800": "1 0 * 512 *",
    "804": "Authentication successful",
    "805": "{target} :Access list",
    "806": "{cls} {mask}",
    "811": "Channel :Users Topic",
    "812": "{channel} {users} :{topic}",
    "813": "End of /LISTX",
    "817": "{target} {prop} :{value}",
    "818": "{target} :End of properties",
    "819": "{target} {prop} :{value}",
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
# MAIN SERVER CLASS
# ==============================================================================


class pyIRCXServer:
    def __init__(self):
        self.servername = CONFIG.get('server', 'name', default='irc.local')
        self.users = {}
        self.channels = {}
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

        # Database connection pool
        self.db_pool = DatabasePool(
            CONFIG.get('database', 'path', default='pyircx.db'),
            pool_size=CONFIG.get('database', 'pool_size', default=5)
        )

        # CAP negotiation timeout (seconds)
        self.cap_timeout = CONFIG.get('security', 'cap_timeout', default=60)

        self.stats = {
            'total_connections': 0,
            'messages_sent': 0,
            'commands_processed': 0
        }

        self.access_list = {
            'GRANT': [],  # [(mask, set_by, set_at, timeout, reason), ...]
            'DENY': []    # timeout=0 means permanent, else Unix timestamp when entry expires
        }

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
        import re
        # Check if name ends with digits (potential clone pattern)
        match = re.match(r'^(.+?)(\d+)$', channel_name)
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

    def sync_mode_to_clones(self, original, mode, value, param=None):
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
                clone.broadcast(msg)

    def _create_virtual_service(self, nickname, ident, realname, is_admin=False, is_servicebot=False):
        """Create a virtual service user"""
        service = User(None, None, is_virtual=True)
        service.nickname = nickname
        service.username = ident
        service.host = self.servername
        service.realname = realname
        service.staff_level = "ADMIN" if is_admin else "SERVICE"
        service.registered = True
        service.set_mode('s', True)  # Service mode
        if is_admin:
            service.set_mode('a', True)
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

            user.send(f"{bot_prefix} NOTICE {user.nickname} :[{channel_name}] {warn_msg}")
            logger.info(f"ServiceBot {bot.nickname}: Warned {user.nickname} in {channel_name} for {violation_type}")

        elif action == "gag":
            if user.nickname not in channel.gagged:
                channel.gagged.add(user.nickname)
                user.set_mode('z', True)
                msg = f"{bot_prefix} MODE {channel_name} +z {user.nickname}"
                channel.broadcast(msg)
                user.send(f"{bot_prefix} NOTICE {user.nickname} :You have been gagged in {channel_name} for {violation_type}")
                logger.info(f"ServiceBot {bot.nickname}: Gagged {user.nickname} in {channel_name} for {violation_type}")

        elif action == "kick":
            kick_reason = f"ServiceBot: {violation_type}"
            msg = f"{bot_prefix} KICK {channel_name} {user.nickname} :{kick_reason}"
            channel.broadcast(msg)
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
                channel.broadcast(ban_msg)

            kick_reason = f"ServiceBot: Banned for {violation_type}"
            kick_msg = f"{bot_prefix} KICK {channel_name} {user.nickname} :{kick_reason}"
            channel.broadcast(kick_msg)
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
        if user.has_mode('o') or user.has_mode('a') or user.has_mode('g') or user.has_mode('s'):
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

        async with aiosqlite.connect(CONFIG.get('database', 'path', default='ircx_server.db')) as db:
            # Staff users table
            await db.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, level TEXT)")

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
                FOREIGN KEY (owner_uuid) REFERENCES registered_nicks(uuid)
            )""")

            # Legacy channel data (for backwards compat)
            await db.execute("CREATE TABLE IF NOT EXISTS reg_chans (name TEXT PRIMARY KEY, data TEXT, registered_at INTEGER)")

            # Server access rules
            await db.execute("""CREATE TABLE IF NOT EXISTS server_access (
                id INTEGER PRIMARY KEY,
                type TEXT,
                pattern TEXT,
                set_by TEXT,
                set_at INTEGER,
                reason TEXT
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

            await db.commit()
        logger.info("Database initialized")

        await self._load_access_list()

        await self.load_channels()

        self.channels["#System"] = Channel("#System")
        self.channels["#System"].registered = True
        self.channels["#System"].account_uuid = str(uuid.uuid4())

        # Create System virtual user
        sys_user = self._create_virtual_service('System', 'System', "Network Services", is_admin=True)
        self.channels["#System"].members[sys_user.nickname] = sys_user
        self.channels["#System"].owners.add(sys_user.nickname)
        logger.info("#System channel created")

        # Create Registrar service - handles nick/channel registration
        registrar = self._create_virtual_service('Registrar', 'Registrar', "Registration Services")
        self.channels["#System"].members[registrar.nickname] = registrar
        logger.info("Registrar service created")

        # Create Messenger service - handles mailbox and global messages
        messenger = self._create_virtual_service('Messenger', 'Messenger', "Message Services")
        self.channels["#System"].members[messenger.nickname] = messenger
        logger.info("Messenger service created")

        # Create NewsFlash alias - part of Messenger for rotating/push messages
        newsflash = self._create_virtual_service('NewsFlash', 'NewsFlash', "News Broadcast Services")
        self.channels["#System"].members[newsflash.nickname] = newsflash
        logger.info("NewsFlash service created")

        # Create ServiceBots - configurable count
        self.servicebots = {}
        bot_count = CONFIG.get('services', 'servicebot_count', default=10)
        for i in range(1, bot_count + 1):
            bot_name = f"ServiceBot{i:02d}"
            bot = self._create_virtual_service(bot_name, 'ServiceBot', f"Service Bot #{i}", is_servicebot=True)
            self.servicebots[bot_name] = bot
        logger.info(f"{bot_count} ServiceBots created")

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

        if CONFIG.get('persistence', 'auto_save', default=True):
            interval = CONFIG.get('persistence', 'save_interval', default=300)
            self.save_task = asyncio.create_task(self.periodic_save(interval))
            logger.info(f"Auto-save enabled ({interval}s)")

        # Initialize database connection pool
        await self.db_pool.initialize()

        # Start CAP timeout monitor
        self.cap_timeout_task = asyncio.create_task(self._cap_timeout_monitor())
        logger.info(f"CAP timeout monitor started ({self.cap_timeout}s timeout)")

    async def _load_access_list(self):
        """Load server-wide ACCESS rules from database"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Ensure timeout column exists (migration)
                try:
                    await db.execute("ALTER TABLE server_access ADD COLUMN timeout INTEGER DEFAULT 0")
                    await db.commit()
                except:
                    pass  # Column already exists
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

    async def load_channels(self):
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT name, data FROM reg_chans") as cursor:
                    async for row in cursor:
                        try:
                            data = json.loads(row[1])
                            channel = Channel.from_dict(data)
                            self.channels[channel.name] = channel
                            logger.info(f"Loaded: {channel.name}")
                        except Exception as e:
                            logger.error(f"Load error {row[0]}: {e}")
        except Exception as e:
            logger.error(f"Load channels error: {e}")

    async def save_channels(self):
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                saved = 0
                for name, channel in self.channels.items():
                    # Skip local channels (&), #System, and unregistered channels
                    if channel.registered and name != "#System" and not channel.is_local:
                        data = json.dumps(channel.to_dict())
                        await db.execute("INSERT OR REPLACE INTO reg_chans VALUES (?, ?, ?)",
                                       (name, data, int(time.time())))
                        saved += 1
                await db.commit()
            logger.info(f"Saved {saved} channels")
        except Exception as e:
            logger.error(f"Save error: {e}")

    async def periodic_save(self, interval):
        while True:
            await asyncio.sleep(interval)
            await self.save_channels()

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
                    user.send(f"ERROR :Closing link: CAP negotiation timeout ({self.cap_timeout}s)")
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
            "usermodes": CONFIG.get('modes', 'user', default='agiorxz'),
            "chanmodes": CONFIG.get('modes', 'channel', default='adfikmnprstuwxy'),
            "staff_term": CONFIG.get('system', 'staff_term', default='staff and services'),
            "uptime": int(time.time() - self.boot_time),
            "loc1": CONFIG.get('admin', 'loc1', default=''),
            "loc2": CONFIG.get('admin', 'loc2', default=''),
            "email": CONFIG.get('admin', 'email', default=''),
            "server_count": 1,
            "max_users": self.max_users_seen,
            "nicklen": CONFIG.get('limits', 'max_nick_length', default=30),
            "userlen": CONFIG.get('limits', 'max_user_length', default=30),
            "chanlen": CONFIG.get('limits', 'max_channel_length', default=50),
            **kwargs
        }
        try:
            txt = template.format(**params)
            if code == "800":
                return f":{self.servername} 800 {recipient.nickname if recipient.registered else '*'} {txt}"
            no_colon = ["004", "005", "311", "312",
                "315", "317", "319", "352", "353", "324", "433"]
            if code == "433":
                return f":{self.servername} 433 {recipient.nickname if recipient.nickname != '*' else '*'} {txt}"
            sep = " " if code in no_colon else " :"
            return f":{self.servername} {code} {recipient.nickname}{sep}{txt}"
        except Exception as e:
            logger.error(f"Reply error {code}: {e}")
            return f":{self.servername} 500 {recipient.nickname} :Format Error"

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
        ts = int(time.time())
        msg = f":{self.servername} EVENT {ts} {cls} {action} {channel_name or ''} {user.prefix()} {user.ip}:{user.port} 0.0.0.0:0"
        for admin in self.users.values():
            if admin.has_mode('a'):
                for t_cls, t_mask in admin.traps:
                    if t_cls == cls and fnmatch.fnmatch(user.prefix(), t_mask):
                        admin.send(msg)
                        break

    async def log_staff(self, staff_nick, action, target, details="None"):
        """Log staff actions to the server log only (no #System relay)"""
        log_raw = RESPONSES['STAFF_LOG'].format(
            action=action, staff=staff_nick, target=target, details=details)
        logger.info(f"STAFF: {log_raw}")

# Continuing pyIRCXServer class...

    async def handle_client(self, reader, writer):
        user = User(reader, writer)

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

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                raw = line.decode('utf-8', errors='replace').strip()
                if not raw:
                    continue
                if self.debug_mode:
                    logger.debug(f"[{user.nickname}] <<< {raw}")
                await self.dispatch(user, raw)
                # Flush write buffer to prevent backpressure
                try:
                    await writer.drain()
                except ConnectionResetError:
                    break
        except Exception as e:
            if self.debug_mode:
                logger.error(f"Client error [{user.nickname}]: {e}")
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

        user.last_activity = int(time.time())
        self.stats['commands_processed'] += 1

        # Flood protection for all users (staff get higher limits but not bypass)
        if user.registered:
            if CONFIG.get('security', 'enable_flood_protection', default=True):
                is_staff = user.has_mode('o') or user.has_mode('a')
                # Staff get 3x the normal flood limit before being throttled
                flood_ok = user.check_flood()
                if not flood_ok:
                    # Staff still get throttled at 3x the limit
                    if not is_staff or len(user.flood_protection.messages) >= 15:
                        user.send(
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
            user.send(self.get_reply("800", user))
            return
        elif cmd == "PING":
            user.send(
                f":{self.servername} PONG {self.servername} :{params[0] if params else ''}")
            return
        elif cmd == "NICK":
            await self.handle_nick(user, params)
            return
        elif cmd == "USER":
            await self.handle_user(user, params)
            return

        if not user.registered:
            if cmd not in ["NICK", "USER", "PASS", "IRCX", "ISIRCX", "PING"]:
                user.send(self.get_reply("451", user))
            return

        # MFA pending - restrict commands until MFA verification is complete
        if user.pending_mfa:
            allowed_during_mfa = ["PING", "PONG", "QUIT"]
            # Allow PRIVMSG only to Registrar for MFA VERIFY command
            if cmd == "PRIVMSG" and params and params[0].lower() == "registrar":
                pass  # Allow
            elif cmd not in allowed_during_mfa:
                user.send(f":{self.servername} NOTICE {user.nickname} :MFA verification pending. Use: PRIVMSG Registrar :MFA VERIFY <code>")
                return

        if cmd in ["JOIN", "CREATE"]:
            if not params:
                user.send(self.get_reply("461", user, command=cmd))
                return
            channels = params[0].split(',')
            keys = params[1].split(',') if len(params) > 1 else []
            for idx, channel_name in enumerate(channels):
                channel_name = channel_name.strip()
                if channel_name:
                    key = keys[idx].strip() if idx < len(keys) else None
                    await self.handle_join(user, channel_name, key)
        elif cmd == "PART":
            if not params:
                user.send(self.get_reply("461", user, command=cmd))
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
            user.send(self.get_reply("391", user, time=time.ctime()))
        elif cmd == "VERSION":
            user.send(self.get_reply("351", user))
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
        elif cmd in ["PRIVMSG", "WHISPER", "DATA", "NOTICE"]:
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
        elif cmd == "STATS":
            await self.handle_stats(user, params)
        elif cmd == "CONFIG":
            await self.handle_config(user, params)
        elif cmd == "STAFF":
            await self.handle_staff(user, params)
        elif cmd == "CONNECT":
            await self.handle_connect(user, params)
        elif cmd == "SQUIT":
            await self.handle_squit(user, params)
        elif cmd == "LINKS":
            await self.handle_links(user, params)
        elif cmd == "ADMIN":
            user.send(self.get_reply("256", user))
            user.send(self.get_reply("257", user))
            user.send(self.get_reply("258", user))
            user.send(self.get_reply("259", user))
        elif cmd == "INFO":
            await self.handle_info(user)
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
            user.send(self.get_reply("421", user, command=cmd))

    async def handle_nick(self, user, params):
        if not params:
            return
        new, old = params[0], user.nickname

        # Validate nickname BEFORE any assignment - blocks sign-on if invalid
        valid, error = validate_nickname(new)
        if not valid:
            user.send(f":{self.servername} 432 {user.nickname} {new} :{error}")
            return

        # Nick change cooldown (only for registered users, not initial sign-on)
        # SYSOPs and ADMINs are exempt from cooldown
        if user.registered and not (user.has_mode('o') or user.has_mode('a')):
            cooldown = CONFIG.get('limits', 'nick_change_cooldown', default=60)
            if cooldown > 0:
                elapsed = time.time() - user.last_nick_change
                if elapsed < cooldown:
                    remaining = int(cooldown - elapsed)
                    user.send(f":{self.servername} NOTICE {user.nickname} :You must wait {remaining} seconds before changing nickname")
                    return

        # Check for nickname collision
        if new in self.users and self.users[new] != user:
            user.send(self.get_reply("433", user, target=new))
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
            user.send(nick_msg)
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
                            member.send(nick_msg)
                            notified.add(member.nickname)
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

    async def handle_user(self, user, params):
        if len(params) < 4:
            user.send(self.get_reply("461", user, command="USER"))
            return
        if user.registered:
            user.send(self.get_reply("462", user))
            return

        username = params[0]

        # Validate username BEFORE any assignment - blocks sign-on if invalid
        valid, error = validate_username(username)
        if not valid:
            user.send(f":{self.servername} 468 {user.nickname} :{error}")
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
            try:
                row = await self.db_pool.execute_one(
                    "SELECT password_hash, level FROM users WHERE username=?",
                    (user.username,)
                )
                if row:
                    # Use non-blocking bcrypt check
                    if await check_password_async(user.provided_pass, row[0]):
                        auth, level = True, row[1]
                        self.failed_auth_tracker.record_success(user.ip)
                    else:
                        self.failed_auth_tracker.record_failure(user.ip)
            except Exception as e:
                if self.debug_mode:
                    logger.error(f"Auth error: {e}")

        if auth and level in ["ADMIN", "SYSOP", "GUIDE"]:
            user.host = self.servername
            user.authenticated = True
            user.staff_level = level
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
                    user.send(f":{self.servername} NOTICE {user.nickname} :Access denied{reason_msg}")
                    user.send(f"ERROR :Closing Link: {user.nickname} (Access denied)")
                    await self.quit_user(user)
                    return

        user.send(self.get_reply("001", user))
        user.send(self.get_reply("002", user))
        user.send(self.get_reply("003", user))
        user.send(self.get_reply("004", user))
        user.send(self.get_reply("005", user))

        # Staff count includes staff users AND services/bots
        ops = sum(1 for u in self.users.values() if u.has_mode('o') or u.has_mode('a') or u.has_mode('g') or u.is_virtual)
        # User count excludes services/bots
        real_users = sum(1 for u in self.users.values() if not u.is_virtual)
        # Only show invisible count to staff users
        if auth:
            invisible = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
        else:
            invisible = 0  # Hide from non-staff
        user.send(self.get_reply("251", user, users=real_users, invisible=invisible))
        user.send(self.get_reply("252", user, ops=ops))
        user.send(self.get_reply("255", user, users=real_users))
        user.send(self.get_reply("375", user))
        user.send(self.get_reply("376", user))

        if auth:
            mode = 'a' if level == "ADMIN" else 'o' if level == "SYSOP" else 'g'
            user.set_mode(mode, True)
            user.set_mode('r', True)  # Set registered mode
            if level == "ADMIN":
                user.set_mode('o', True)
            user.send(f":{user.nickname} MODE {user.nickname} :+{mode}r")
            # Dynamic role name for 381
            role = "administrator" if level == "ADMIN" else "operator" if level == "SYSOP" else "guide"
            user.send(self.get_reply("381", user, role=role))
            # Configurable staff login message
            staff_msg = CONFIG.get('server', 'staff_login_message',
                                   default='Welcome to the staff team.')
            user.send(self.get_reply("386", user, staff_login_message=staff_msg))
            user.send(self.get_reply("804", user))
            logger.info(f"Auth: {user.nickname} as {level}")

        await self.fire_trap("CONNECT", "USER LOGON", user)

        # Notify watchers that this user has come online
        self.notify_watchers_online(user)

    async def handle_msg(self, user, params, cmd):
        if user.has_mode('z'):
            return
        if len(params) < 2:
            user.send(self.get_reply("461", user, command=cmd))
            return
        target = params[0]

        # WHISPER restrictions: single recipient only, 5s rate limit
        if cmd == "WHISPER":
            if ',' in target:
                user.send(self.get_reply("407", user, target=target))
                return
            if not user.rate_limiter.check('WHISPER'):
                user.send(f":{self.servername} NOTICE {user.nickname} :WHISPER rate limited (5 second cooldown)")
                return

        text = params[2] if cmd in ["WHISPER", "DATA"] and len(
            params) >= 3 else params[1]

        # Validate message length
        max_msg_len = CONFIG.get('limits', 'msg_length', default=512)
        if len(text) > max_msg_len:
            text = text[:max_msg_len]
            user.send(f":{self.servername} NOTICE {user.nickname} :Message truncated to {max_msg_len} characters")

        # System service doesn't accept direct messages
        if target.lower() == CONFIG.get('system', 'nick', default='System').lower():
            user.send(f":{CONFIG.get('system', 'nick')}!{CONFIG.get('system', 'ident')}@{self.servername} NOTICE {user.nickname} :System does not accept messages. Use /HELP for available services.")
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

        source = f":{user.prefix()}"
        out = f"{source} {cmd} {target} {params[1] + ' ' if cmd in ['WHISPER', 'DATA'] and len(params) > 2 else ''}:{text}"

        # ADMIN wildcard broadcast (PRIVMSG/NOTICE * only)
        if target == '*':
            if cmd not in ['PRIVMSG', 'NOTICE']:
                return
            if not user.has_mode('a'):
                user.send(self.get_reply("481", user))
                return
            broadcast_out = f"{source} {cmd} * :{text}"
            broadcast_count = 0
            for recipient in self.users.values():
                if not recipient.is_virtual:
                    recipient.send(broadcast_out)
                    broadcast_count += 1
            self.stats['messages_sent'] += broadcast_count
            return

        if target in self.users:
            recipient = self.users[target]
            # Check if sender is silenced by recipient
            if self.is_silenced(user, recipient):
                return  # Silently drop the message
            recipient.send(out)
            self.stats['messages_sent'] += 1
        elif is_channel(target):
            channel, chan_name = self.get_channel(target)
            if not channel:
                user.send(self.get_reply("403", user, target=target))
                return
            # Check +n (no external messages) - non-members cannot send
            if not channel.has_member(user.nickname) and channel.modes.get('n', False):
                user.send(self.get_reply("404", user, channel=chan_name))
                return
            # Check +m (moderated) - only voiced/host/owner can send
            if channel.modes.get('m', False) and channel.has_member(user.nickname):
                # Staff can always speak, as can voiced/host/owner
                is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')
                is_privileged = (user.nickname in channel.owners or
                                user.nickname in channel.hosts or
                                user.nickname in channel.voices)
                can_speak = is_staff or is_privileged
                if not can_speak:
                    user.send(self.get_reply("404", user, channel=chan_name))
                    return
            if user.nickname in channel.gagged:
                return
            # Channel mode +w: no whispers allowed
            if cmd == "WHISPER" and channel.modes.get('w', False):
                user.send(f":{self.servername} NOTICE {user.nickname} :Whispers are not allowed in {chan_name} (+w)")
                return

            # WHISPER to channel is private message to a specific user in channel
            # Format: WHISPER #channel targetuser :message
            if cmd == "WHISPER":
                if len(params) < 3:
                    user.send(self.get_reply("461", user, command="WHISPER"))
                    return
                target_nick = params[1]
                # Check if target is in channel
                if not channel.has_member(target_nick):
                    user.send(self.get_reply("441", user, target=target_nick, channel=chan_name))
                    return
                # Find the target user
                target_user = self.users.get(target_nick)
                if not target_user:
                    user.send(self.get_reply("401", user, target=target_nick))
                    return
                # Send only to target
                whisper_out = f"{source} WHISPER {chan_name} {target_nick} :{text}"
                target_user.send(whisper_out)
                self.stats['messages_sent'] += 1
                return

            # Rebuild output with canonical channel name
            chan_out = f"{source} {cmd} {chan_name} {params[1] + ' ' if cmd in ['DATA'] and len(params) > 2 else ''}:{text}"
            # Channel mode +f: strip formatting codes
            if channel.modes.get('f', False):
                text = self._strip_formatting(text)
                chan_out = f"{source} {cmd} {chan_name} {params[1] + ' ' if cmd in ['DATA'] and len(params) > 2 else ''}:{text}"
            channel.broadcast(chan_out, exclude=user)
            self.stats['messages_sent'] += 1

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

    async def handle_who(self, user, params):
        target = params[0] if params else "*"
        is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')
        is_high_staff = user.has_mode('o') or user.has_mode('a')  # SYSOP or ADMIN

        # WHO * (all users) restricted to SYSOP/ADMIN only
        if target == "*":
            if not is_high_staff:
                user.send(f":{self.servername} NOTICE {user.nickname} :WHO * requires SYSOP or ADMIN privileges. Use a pattern like *nick* instead.")
                user.send(self.get_reply("315", user, target=target))
                return
            # Rate limit for full WHO
            if not user.rate_limiter.check('WHO'):
                user.send(f":{self.servername} NOTICE {user.nickname} :WHO rate limited")
                user.send(self.get_reply("315", user, target=target))
                return
            # Return all visible users
            for member in self.users.values():
                if member.is_virtual:
                    continue
                if member.has_mode('i') and not is_staff and user != member:
                    continue
                flags = "G" if member.away_msg else "H"
                if member.has_mode('i'):
                    flags += "i"
                if member.has_mode('x') or member.is_ircx:
                    flags += "x"
                if user.is_ircx:
                    if member.has_mode('a'):
                        flags += "a"
                    elif member.has_mode('o'):
                        flags += "o"
                    elif member.has_mode('g'):
                        flags += "g"
                else:
                    if member.has_mode('o') or member.has_mode('a'):
                        flags += "*"
                # Staff see IP address, others see hostname
                display_host = member.ip if is_staff else member.host
                user.send(self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            user.send(self.get_reply("315", user, target=target))
            return

        # Pattern matching for nicknames (e.g., *pattern*, %pattern%)
        if '*' in target or '%' in target:
            # Convert % to * for fnmatch
            pattern = target.replace('%', '*')
            match_count = 0
            max_results = 50  # Limit results for non-staff
            for member in self.users.values():
                if member.is_virtual:
                    continue
                if not fnmatch.fnmatch(member.nickname.lower(), pattern.lower()):
                    continue
                if member.has_mode('i') and not is_staff and user != member:
                    continue
                match_count += 1
                if not is_staff and match_count > max_results:
                    user.send(f":{self.servername} NOTICE {user.nickname} :WHO results truncated at {max_results}")
                    break
                flags = "G" if member.away_msg else "H"
                if member.has_mode('i') and (is_staff or user == member):
                    flags += "i"
                if member.has_mode('x') or member.is_ircx:
                    flags += "x"
                if user.is_ircx:
                    if member.has_mode('a'):
                        flags += "a"
                    elif member.has_mode('o'):
                        flags += "o"
                    elif member.has_mode('g'):
                        flags += "g"
                else:
                    if member.has_mode('o') or member.has_mode('a'):
                        flags += "*"
                # Staff see IP address, others see hostname
                display_host = member.ip if is_staff else member.host
                user.send(self.get_reply("352", user, channel="*", ident=member.username,
                                        host=display_host, target=member.nickname, flags=flags, real=member.realname))
            user.send(self.get_reply("315", user, target=target))
            return

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

                # Staff/operator flags depend on IRCX mode
                if user.is_ircx:
                    # IRCX mode - show specific staff letters
                    if member.has_mode('a'):
                        flags += "a"
                    elif member.has_mode('o'):
                        flags += "o"
                    elif member.has_mode('g'):
                        flags += "g"
                else:
                    # Non-IRCX mode - show * for any IRC operator
                    if member.has_mode('o') or member.has_mode('a'):
                        flags += "*"

                # Channel rank flags (., @, +)
                if nick in channel.owners:
                    flags += "."
                elif nick in channel.hosts:
                    flags += "@"
                elif nick in channel.voices:
                    flags += "+"

                # NOTE: Never expose 'z' (gagged) to non-staff users

                # Staff see IP address, others see hostname
                display_host = member.ip if is_staff else member.host
                user.send(self.get_reply("352", user, channel=chan_name, ident=member.username,
                                        host=display_host, target=nick, flags=flags, real=member.realname))
        user.send(self.get_reply("315", user, target=chan_name if channel else target))

    async def handle_whois(self, user, params):
        if not params:
            return
        for target_nick in params[0].split(','):
            target = self.users.get(target_nick)

            # Reserved service names that don't exist redirect to System
            if not target and is_reserved_service(target_nick):
                target = self.users.get('System')
                if target:
                    user.send(self.get_reply("311", user, target=target_nick, ident='Services',
                                             host=self.servername, real=f"Alias for {target.nickname}"))
                    user.send(self.get_reply("312", user, target=target_nick))
                    user.send(self.get_reply("313", user, target=target_nick, role="is a network service"))
                    user.send(self.get_reply("318", user, target=target_nick))
                    continue

            if not target:
                user.send(self.get_reply("401", user, target=target_nick))
                continue
            user.send(self.get_reply("311", user, target=target.nickname, ident=target.username,
                                     host=target.host, real=target.realname))
            if target.channels:
                chan_list = " ".join(target.channels)
                user.send(self.get_reply(
                    "319", user, target=target.nickname, channels=chan_list))
            user.send(self.get_reply("312", user, target=target.nickname))

            if target.has_mode('a'):
                role = "is an IRC administrator"
            elif target.has_mode('o'):
                role = "is an IRC operator"
            elif target.has_mode('g'):
                role = "is an IRC guide"
            else:
                role = None
            if role:
                user.send(self.get_reply(
                    "313", user, target=target.nickname, role=role))

            if target.away_msg:
                user.send(self.get_reply(
                    "301", user, target=target.nickname, message=target.away_msg))

            idle = int(time.time() - target.last_activity)
            user.send(self.get_reply("317", user, target=target.nickname,
                      idle=idle, signon=target.signon_time))

            if user.has_mode('o') or user.has_mode('a') or user.has_mode('g'):
                user.send(self.get_reply(
                    "320", user, target=target.nickname, ip=target.ip))

            user.send(self.get_reply("318", user, target=target.nickname))

    async def handle_whowas(self, user, params):
        if not params:
            return
        target_nick = params[0]
        if target_nick in self.whowas:
            info = self.whowas[target_nick]
            user.send(self.get_reply("314", user, target=target_nick,
                                     ident=info.get('username', 'unknown'),
                                     host=info.get('host', 'unknown'),
                                     real=info.get('realname', 'unknown')))
        user.send(self.get_reply("369", user, target=target_nick))

    async def handle_list(self, user, is_listx=False, pattern=None):
        # Rate limit LIST/LISTX commands
        if not user.rate_limiter.check('LIST'):
            user.send(f":{self.servername} NOTICE {user.nickname} :LIST rate limited")
            return

        is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')

        if is_listx:
            user.send(self.get_reply("811", user))
            for name, channel in self.channels.items():
                # Hide +s (secret) and +h (hidden) channels from non-staff unless they're in it
                if (channel.modes.get('s', False) or channel.modes.get('h', False)) and not is_staff and user.nickname not in channel.members:
                    continue
                # Apply pattern filter if provided
                if pattern and not fnmatch.fnmatch(name.lower(), pattern.lower()):
                    continue
                user.send(self.get_reply("812", user, channel=name, users=len(channel.members),
                                         topic=channel.topic or ""))
            user.send(self.get_reply("813", user))
        else:
            user.send(self.get_reply("321", user))
            for name, channel in self.channels.items():
                # Hide +s (secret) and +h (hidden) channels from non-staff unless they're in it
                if (channel.modes.get('s', False) or channel.modes.get('h', False)) and not is_staff and user.nickname not in channel.members:
                    continue
                # Apply pattern filter if provided
                if pattern and not fnmatch.fnmatch(name.lower(), pattern.lower()):
                    continue
                user.send(self.get_reply("322", user, channel=name, users=len(channel.members),
                                         topic=channel.topic or ""))
            user.send(self.get_reply("323", user))

    async def handle_join(self, user, channel_name, key=None):
        is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')

        # Validate channel name
        valid, error = validate_channel_name(channel_name)
        if not valid:
            user.send(f":{self.servername} 479 {user.nickname} {channel_name} :{error}")
            return

        # Case-insensitive #System check
        if channel_name.lower() == "#system" and not is_staff:
            user.send(self.get_reply("473", user, target="#System"))
            return

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
            channel = Channel(chan_name)
            self.channels[chan_name] = channel

        used_owner_key = key and channel.owner_key and key == channel.owner_key
        used_host_key = key and channel.host_key and key == channel.host_key

        # Check channel ACCESS lists for grants
        access_grants = channel.get_access_grants(user)
        has_access_grant = 'GRANT' in access_grants or 'OWNER' in access_grants or 'HOST' in access_grants or 'VOICE' in access_grants

        if not is_staff and not used_owner_key and not used_host_key:
            # Check ACCESS DENY (works like ban)
            denied, deny_reason = channel.check_access(user, 'DENY')
            if denied or channel.is_banned(user):
                user.send(self.get_reply("474", user, target=chan_name))
                return
            # Check invite-only (ACCESS GRANT or access levels bypass this)
            if channel.modes.get('i') and chan_name not in user.invited_to and not has_access_grant:
                user.send(self.get_reply("473", user, target=chan_name))
                return
            if channel.modes.get('k') and channel.key:
                if key != channel.key:
                    user.send(self.get_reply("475", user, target=chan_name))
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
                        user.send(self.get_reply("471", user, target=chan_name))
                        return

        user.invited_to.discard(chan_name)
        channel.members[user.nickname] = user
        user.channels.add(chan_name)  # Store canonical name

        # ADMINs, SYSOPs, and services/bots always get +q, owner key grants +q
        # First user gets +q ONLY for unregistered (dynamic) channels
        # ACCESS OWNER/HOST/VOICE entries also grant modes
        is_high_staff = user.has_mode('o') or user.has_mode('a')
        is_first_in_dynamic = len(channel.members) == 1 and not channel.registered
        grant_owner = is_high_staff or user.is_virtual or is_first_in_dynamic or used_owner_key or 'OWNER' in access_grants
        grant_host = (used_host_key or 'HOST' in access_grants) and not grant_owner
        grant_voice = 'VOICE' in access_grants and not grant_owner and not grant_host

        # Track mode to grant (applied after JOIN broadcast so clients see it)
        if grant_owner:
            channel.owners.add(user.nickname)
        elif grant_host:
            channel.hosts.add(user.nickname)
        elif grant_voice:
            channel.voices.add(user.nickname)

        user.send(f":{user.prefix()} JOIN {chan_name}")
        if channel.topic:
            user.send(self.get_reply(
                "332", user, channel=chan_name, topic=channel.topic))
        else:
            user.send(self.get_reply("331", user, channel=chan_name))
        names = " ".join([channel.get_prefix(nick) + nick for nick in channel.members])
        user.send(self.get_reply("353", user, channel=chan_name, names=names))
        user.send(self.get_reply("366", user, channel=chan_name))
        msg = f":{user.prefix()} JOIN {chan_name}"
        channel.broadcast(msg, exclude=user)

        # Broadcast MODE after JOIN so other clients see the user first
        if grant_owner:
            mode_msg = f":{user.prefix()} MODE {chan_name} +q {user.nickname}"
            channel.broadcast(mode_msg)
        elif grant_host:
            mode_msg = f":{user.prefix()} MODE {chan_name} +o {user.nickname}"
            channel.broadcast(mode_msg)
        elif grant_voice:
            mode_msg = f":{user.prefix()} MODE {chan_name} +v {user.nickname}"
            channel.broadcast(mode_msg)

        # Log to transcript if +y mode is enabled
        self.log_transcript(channel, "JOIN", user)

        # Send ONJOIN message if set (IRCX PROP ONJOIN)
        if channel.onjoin:
            # ONJOIN supports \n for multiple lines
            for line in channel.onjoin.replace('\\n', '\n').split('\n'):
                if line.strip():
                    user.send(f":{chan_name}!{chan_name}@{self.servername} PRIVMSG {user.nickname} :{line}")

    async def handle_part(self, user, channel_name):
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            user.send(self.get_reply("403", user, target=channel_name))
            return
        if chan_name not in user.channels:
            user.send(self.get_reply("442", user, target=chan_name))
            return
        msg = f":{user.prefix()} PART {chan_name}"
        channel.broadcast(msg)
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
                    user.send(f":{chan_name}!{chan_name}@{self.servername} NOTICE {user.nickname} :{line}")

        # Delete dynamic (unregistered) channels when empty
        # Registered channels and #System persist even when empty
        if len(channel.members) == 0 and not channel.registered and chan_name.lower() != "#system":
            # If this is a clone, remove from parent's clone_children list
            if channel.is_clone() and channel.clone_parent:
                parent, _ = self.get_channel(channel.clone_parent)
                if parent and chan_name in parent.clone_children:
                    parent.clone_children.remove(chan_name)
            del self.channels[chan_name]

    async def handle_away(self, user, params):
        if params:
            user.away_msg = params[0].lstrip(':')
            user.send(self.get_reply("306", user))
        else:
            user.away_msg = None
            user.send(self.get_reply("305", user))


    async def handle_topic(self, user, params):
        if not params:
            user.send(self.get_reply("461", user, command="TOPIC"))
            return

        channel, chan_name = self.get_channel(params[0])
        if not channel:
            user.send(self.get_reply("403", user, target=params[0]))
            return

        if user.nickname not in channel.members:
            user.send(self.get_reply("442", user, target=chan_name))
            return

        if len(params) == 1:
            if channel.topic:
                user.send(self.get_reply(
                    "332", user, channel=chan_name, topic=channel.topic))
                if channel.topic_set_by:
                    user.send(self.get_reply("333", user,
                        channel=chan_name,
                        nick=channel.topic_set_by,
                        timestamp=channel.topic_set_at
                    ))
            else:
                user.send(self.get_reply("331", user, channel=chan_name))
        else:
            new_topic = params[1]
            if channel.modes.get('t'):
                if not (user.nickname in channel.owners or
                       user.nickname in channel.hosts or
                       user.has_mode('a')):
                    user.send(self.get_reply("482", user, target=chan_name))
                    return

            channel.topic = new_topic
            channel.topic_set_by = user.nickname
            channel.topic_set_at = int(time.time())

            msg = f":{user.prefix()} TOPIC {chan_name} :{new_topic}"
            channel.broadcast(msg)
            user.send(msg)
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
            user.send(self.get_reply("461", user, command="TRANSCRIPT"))
            return

        channel_name = params[0]
        if not is_channel(channel_name):
            user.send(self.get_reply("403", user, target=channel_name))
            return

        if channel_name not in self.channels:
            user.send(self.get_reply("403", user, target=channel_name))
            return

        channel = self.channels[channel_name]

        # Check permissions - must be channel owner/op or staff
        is_chanop = user.nickname in channel.owners or user.nickname in channel.hosts
        is_staff = user.has_mode('o') or user.has_mode('a')
        if not (is_chanop or is_staff):
            user.send(self.get_reply("482", user, target=channel_name))
            return

        # Check if transcript mode is enabled
        if not channel.modes.get('y', False):
            user.send(f":{self.servername} NOTICE {user.nickname} :{channel_name} does not have transcript mode (+y) enabled")
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
            user.send(f":{self.servername} NOTICE {user.nickname} :No transcript available for {channel_name}")
            return

        # Send transcript header
        user.send(f":{self.servername} NOTICE {user.nickname} :=== Transcript for {channel_name} ({len(transcript_lines)} lines) ===")

        # Send each line
        for line in transcript_lines:
            user.send(f":{self.servername} NOTICE {user.nickname} :{line}")

        # Send transcript footer
        user.send(f":{self.servername} NOTICE {user.nickname} :=== End of transcript ===")

    async def handle_knock(self, user, params):
        if not params:
            user.send(self.get_reply("461", user, command="KNOCK"))
            return

        channel_name = params[0]
        message = params[1] if len(params) > 1 else ""

        if channel_name not in self.channels:
            user.send(self.get_reply("403", user, target=channel_name))
            return

        channel = self.channels[channel_name]

        if user.nickname in channel.members:
            user.send(f":{self.servername} 714 {user.nickname} {channel_name} :You are already on that channel")
            return

        if not channel.modes.get('i'):
            user.send(f":{self.servername} 713 {user.nickname} {channel_name} :Channel is open")
            return

        if channel.is_banned(user):
            user.send(self.get_reply("474", user, target=channel_name))
            return

        now = time.time()
        last_knock = channel.knock_cooldowns.get(user.nickname, 0)
        if now - last_knock < 60:
            user.send(f":{self.servername} 712 {user.nickname} {channel_name} :Too many KNOCKs")
            return
        channel.knock_cooldowns[user.nickname] = now

        knock_msg = f":{self.servername} 710 {channel_name} {user.nickname} {user.prefix()} :has asked for an invite"
        if message:
            knock_msg = f":{self.servername} 710 {channel_name} {user.nickname} {user.prefix()} :has asked for an invite ({message})"

        for nick in channel.members:
            if nick in channel.owners or nick in channel.hosts:
                channel.members[nick].send(knock_msg)

        user.send(f":{self.servername} 711 {user.nickname} {channel_name} :Your KNOCK has been delivered")

    async def handle_prop(self, user, params):
        if not params:
            user.send(self.get_reply("461", user, command="PROP"))
            return

        channel_name = params[0]

        if channel_name not in self.channels:
            user.send(self.get_reply("403", user, target=channel_name))
            return

        channel = self.channels[channel_name]

        if len(params) == 1:
            for prop_name, prop_value in channel.props.items():
                user.send(self.get_reply("817", user, target=channel_name,
                                         prop=prop_name, value=prop_value))
            user.send(self.get_reply("818", user, target=channel_name))
            return

        prop_name = params[1]
        prop_upper = prop_name.upper()

        # Handle read-only properties
        READ_ONLY_PROPS = {'CREATION', 'ACCOUNT'}

        if len(params) == 2:
            # Query mode - handle special properties
            if prop_upper == 'CREATION':
                user.send(self.get_reply("817", user, target=channel_name,
                                         prop='CREATION', value=str(channel.created_at)))
                return
            elif prop_upper == 'ACCOUNT':
                value = channel.account_uuid if channel.account_uuid else ""
                user.send(self.get_reply("817", user, target=channel_name,
                                         prop='ACCOUNT', value=value))
                return
            elif prop_upper == 'TOPIC':
                value = channel.topic or ""
                user.send(self.get_reply("817", user, target=channel_name,
                                         prop='TOPIC', value=value))
                return
            elif prop_upper == 'ONJOIN':
                value = channel.onjoin or ""
                user.send(self.get_reply("817", user, target=channel_name,
                                         prop='ONJOIN', value=value))
                return
            elif prop_upper == 'ONPART':
                value = channel.onpart or ""
                user.send(self.get_reply("817", user, target=channel_name,
                                         prop='ONPART', value=value))
                return
            prop_value = channel.props.get(prop_name, "")
            user.send(self.get_reply("817", user, target=channel_name,
                                     prop=prop_name, value=prop_value))
            return

        # Check for write attempts to read-only props
        if prop_upper in READ_ONLY_PROPS:
            user.send(f":{self.servername} NOTICE {user.nickname} :Property {prop_name} is read-only")
            return

        if not (user.nickname in channel.owners or
                user.nickname in channel.hosts or
                user.has_mode('a')):
            user.send(self.get_reply("482", user, target=channel_name))
            return

        prop_value = params[2] if len(params) > 2 else ""

        if prop_value:
            if prop_upper == 'TOPIC':
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

        user.send(self.get_reply("819", user, target=channel_name,
                                 prop=prop_name, value=prop_value))
        logger.info(f"PROP {channel_name} {prop_name}={prop_value} by {user.nickname}")

    async def handle_invite(self, user, params):
        if len(params) < 2:
            user.send(self.get_reply("461", user, command="INVITE"))
            return

        target_nick = params[0]
        channel_name = params[1]

        target = self.users.get(target_nick)
        if not target:
            user.send(self.get_reply("401", user, target=target_nick))
            return

        if channel_name not in self.channels:
            user.send(self.get_reply("403", user, target=channel_name))
            return

        channel = self.channels[channel_name]

        if user.nickname not in channel.members:
            user.send(self.get_reply("442", user, target=channel_name))
            return

        # Channel mode +j: no invitations allowed (staff and services can bypass)
        if channel.modes.get('j', False):
            is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')
            is_service = user.nickname in self.servicebots
            if not is_staff and not is_service:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invitations are not allowed in {channel_name} (+j)")
                return

        if channel.modes.get('i'):
            if not (user.nickname in channel.owners or
                    user.nickname in channel.hosts or
                    user.has_mode('a')):
                user.send(self.get_reply("482", user, target=channel_name))
                return

        if target_nick in channel.members:
            user.send(f":{self.servername} 443 {user.nickname} {target_nick} {channel_name} :is already on channel")
            return

        # ServiceBot invitation - ADMIN/SYSOP only, not GUIDE
        if target_nick in self.servicebots:
            if not (user.has_mode('a') or (user.has_mode('o') and not user.has_mode('g'))):
                user.send(f":{self.servername} NOTICE {user.nickname} :Only ADMINs and SYSOPs can invite ServiceBots")
                return
            bot = self.servicebots[target_nick]
            max_chans = getattr(bot, 'max_channels', 10)
            if len(bot.channels) >= max_chans:
                user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has reached max channels ({max_chans})")
                return
            # ServiceBot joins the channel automatically
            channel.members[target_nick] = bot
            bot.channels.add(channel_name)
            channel.broadcast(f":{bot.prefix()} JOIN {channel_name}")
            user.send(self.get_reply("341", user, target=target_nick, channel=channel_name))
            logger.info(f"ServiceBot {target_nick} joined {channel_name} via INVITE from {user.nickname}")
            return

        target.invited_to.add(channel_name)
        user.send(self.get_reply("341", user, target=target_nick, channel=channel_name))
        target.send(f":{user.prefix()} INVITE {target_nick} :{channel_name}")

    async def handle_access(self, user, params):
        """
        IRCX ACCESS command - manage access lists for channels or server.

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
        if len(params) < 2:
            user.send(self.get_reply("461", user, command="ACCESS"))
            return

        obj = params[0]
        action = params[1].upper()

        # Determine if this is server or channel access
        is_server_access = obj in ('$', '*')
        channel = None
        chan_name = None

        if is_server_access:
            # Server access requires staff
            if not (user.has_mode('o') or user.has_mode('a')):
                user.send(self.get_reply("481", user))
                return
            valid_levels = ['GRANT', 'DENY']
        else:
            # Channel access
            channel, chan_name = self.get_channel(obj)
            if not channel:
                user.send(self.get_reply("403", user, target=obj))
                return
            # Require channel owner/host or staff
            if not (user.nickname in channel.owners or user.nickname in channel.hosts or
                    user.has_mode('o') or user.has_mode('a')):
                user.send(self.get_reply("482", user, target=chan_name))
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

            user.send(f":{self.servername} 803 {user.nickname} {target_name} :Start of access list")
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
                    user.send(f":{self.servername} 804 {user.nickname} {target_name} {level} {mask} {set_by}{timeout_str}{reason_str}")
            user.send(f":{self.servername} 805 {user.nickname} {target_name} :End of access list")

        elif action == "ADD":
            if len(params) < 4:
                user.send(self.get_reply("461", user, command="ACCESS ADD"))
                return

            level = params[2].upper()
            if level not in valid_levels:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invalid access level. Valid: {', '.join(valid_levels)}")
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
                    user.send(f":{self.servername} NOTICE {user.nickname} :Mask {mask} already in {level} list")
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
            user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS {level} added to {target_name}: {mask}{timeout_str}")
            logger.info(f"ACCESS {target_name} ADD {level} {mask} by {user.nickname}")

        elif action in ("DELETE", "DEL"):
            if len(params) < 4:
                user.send(self.get_reply("461", user, command="ACCESS DELETE"))
                return

            level = params[2].upper()
            if level not in valid_levels:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invalid access level. Valid: {', '.join(valid_levels)}")
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
                        if set_by in channel.owners and not (user.has_mode('o') or user.has_mode('a')):
                            user.send(f":{self.servername} NOTICE {user.nickname} :Cannot remove owner-added entry")
                            return
                    access_data[level].pop(i)
                    found = True
                    break

            if not found:
                user.send(f":{self.servername} NOTICE {user.nickname} :Mask {mask} not found in {level} list")
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

            user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS {level} removed from {target_name}: {mask}")
            logger.info(f"ACCESS {target_name} DEL {level} {mask} by {user.nickname}")

        elif action == "CLEAR":
            level = params[2].upper() if len(params) > 2 else None

            if is_server_access:
                access_data = self.access_list
                target_name = "server"
            else:
                # Only owners can CLEAR (not hosts)
                if user.nickname not in channel.owners and not (user.has_mode('o') or user.has_mode('a')):
                    user.send(f":{self.servername} NOTICE {user.nickname} :Only channel owners can clear access lists")
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
            user.send(f":{self.servername} NOTICE {user.nickname} :Cleared {cleared} entries from {target_name} ({level_str})")
            logger.info(f"ACCESS {target_name} CLEAR {level_str} by {user.nickname}")

        else:
            user.send(self.get_reply("461", user, command="ACCESS"))

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
        if not params:
            user.send(self.get_reply("219", user, flag="*"))
            return

        flag = params[0].lower() if params[0] not in ('?', '*') else params[0]
        is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')
        is_admin = user.has_mode('a')

        # STATS ? - Help menu
        if flag == '?':
            user.send(f":{self.servername} NOTICE {user.nickname} :=== STATS Help ===")
            user.send(f":{self.servername} NOTICE {user.nickname} :Public flags:")
            user.send(f":{self.servername} NOTICE {user.nickname} :  u - Server uptime")
            user.send(f":{self.servername} NOTICE {user.nickname} :  s - Online staff listing")
            user.send(f":{self.servername} NOTICE {user.nickname} :Staff flags (GUIDE+):")
            user.send(f":{self.servername} NOTICE {user.nickname} :  a - Online ADMINs")
            user.send(f":{self.servername} NOTICE {user.nickname} :  o - Online SYSOPs")
            user.send(f":{self.servername} NOTICE {user.nickname} :  g - Online GUIDEs")
            user.send(f":{self.servername} NOTICE {user.nickname} :  i - Invisible users count")
            user.send(f":{self.servername} NOTICE {user.nickname} :  k - ACCESS DENY list")
            user.send(f":{self.servername} NOTICE {user.nickname} :  z - Gagged users")
            user.send(f":{self.servername} NOTICE {user.nickname} :  c - Configuration")
            user.send(f":{self.servername} NOTICE {user.nickname} :  d - Database info")
            user.send(f":{self.servername} NOTICE {user.nickname} :  x - IRCX users count")
            user.send(f":{self.servername} NOTICE {user.nickname} :  y - Anonymous users count")
            user.send(f":{self.servername} NOTICE {user.nickname} :  w - Authenticated users count")
            user.send(f":{self.servername} NOTICE {user.nickname} :  t - SSL/TLS certificate status")
            user.send(f":{self.servername} NOTICE {user.nickname} :ADMIN only:")
            user.send(f":{self.servername} NOTICE {user.nickname} :  * - All statistics combined")
            user.send(f":{self.servername} NOTICE {user.nickname} :=== End of STATS Help ===")
            user.send(self.get_reply("219", user, flag=flag))
            return

        # STATS * - All stats combined (ADMIN only)
        if flag == '*':
            if not is_admin:
                user.send(f":{self.servername} NOTICE {user.nickname} :STATS * requires ADMIN privileges")
                user.send(self.get_reply("219", user, flag=flag))
                return

            user.send(f":{self.servername} NOTICE {user.nickname} :=== STATS * - Full Statistics ===")

            # Uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            secs = uptime_secs % 60
            user.send(f":{self.servername} NOTICE {user.nickname} :Uptime: {days}d {hours}:{mins:02d}:{secs:02d}")

            # User counts
            total_users = sum(1 for u in self.users.values() if not u.is_virtual)
            invisible = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
            ircx_users = sum(1 for u in self.users.values() if u.is_ircx and not u.is_virtual)
            auth_users = sum(1 for u in self.users.values() if u.authenticated and not u.is_virtual)
            anon_users = sum(1 for u in self.users.values() if u.username.startswith('~') and not u.is_virtual)
            gagged = sum(1 for u in self.users.values() if u.has_mode('z') and not u.is_virtual)

            user.send(f":{self.servername} NOTICE {user.nickname} :--- User Statistics ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :Total users: {total_users}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Invisible (+i): {invisible}")
            user.send(f":{self.servername} NOTICE {user.nickname} :IRCX (+x): {ircx_users}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Authenticated: {auth_users}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Anonymous (~): {anon_users}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Gagged (+z): {gagged}")

            # Staff counts
            admins = sum(1 for u in self.users.values() if u.has_mode('a') and not u.is_virtual)
            sysops = sum(1 for u in self.users.values() if u.has_mode('o') and not u.has_mode('a') and not u.is_virtual)
            guides = sum(1 for u in self.users.values() if u.has_mode('g') and not u.is_virtual)

            user.send(f":{self.servername} NOTICE {user.nickname} :--- Staff Online ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :ADMINs: {admins}")
            user.send(f":{self.servername} NOTICE {user.nickname} :SYSOPs: {sysops}")
            user.send(f":{self.servername} NOTICE {user.nickname} :GUIDEs: {guides}")

            # Channel stats
            total_channels = len([c for c in self.channels.values() if not c.name.startswith('&')])
            local_channels = len([c for c in self.channels.values() if c.name.startswith('&')])
            registered_channels = sum(1 for c in self.channels.values() if c.registered)

            user.send(f":{self.servername} NOTICE {user.nickname} :--- Channel Statistics ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :Global channels (#): {total_channels}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Local channels (&): {local_channels}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Registered: {registered_channels}")

            # Access lists
            deny_count = len(self.access_list['DENY'])
            grant_count = len(self.access_list['GRANT'])

            user.send(f":{self.servername} NOTICE {user.nickname} :--- Access Lists ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS DENY: {deny_count}")
            user.send(f":{self.servername} NOTICE {user.nickname} :ACCESS GRANT: {grant_count}")

            # Server stats
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Server Statistics ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :Commands processed: {self.stats.get('commands_processed', 0)}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Total connections: {self.stats.get('total_connections', 0)}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Max users seen: {self.max_users_seen}")

            # Configuration summary
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Configuration ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :Server: {CONFIG.get('server', 'name')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Network: {CONFIG.get('server', 'network')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Version: {__version__} ({__version_label__})")
            user.send(f":{self.servername} NOTICE {user.nickname} :DNSBL: {'enabled' if CONFIG.get('security', 'dnsbl', 'enabled', default=False) else 'disabled'}")

            # SSL/TLS status
            if SSL_MANAGER:
                ssl_info = SSL_MANAGER.get_info()
                user.send(f":{self.servername} NOTICE {user.nickname} :--- SSL/TLS Status ---")
                if ssl_info.get('enabled'):
                    user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled")
                    if ssl_info.get('context_loaded'):
                        user.send(f":{self.servername} NOTICE {user.nickname} :Certificate: {ssl_info.get('cert_file', 'N/A')}")
                        if 'expiry' in ssl_info:
                            days_left = ssl_info.get('days_left', 0)
                            status = "OK" if days_left > 14 else ("WARNING" if days_left > 3 else "CRITICAL")
                            user.send(f":{self.servername} NOTICE {user.nickname} :Expires: {ssl_info['expiry']} ({days_left:.0f} days) [{status}]")
                        if ssl_info.get('subject'):
                            user.send(f":{self.servername} NOTICE {user.nickname} :Subject: {ssl_info['subject']}")
                    else:
                        user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled but no certificates loaded")
                else:
                    user.send(f":{self.servername} NOTICE {user.nickname} :SSL: disabled")

            user.send(f":{self.servername} NOTICE {user.nickname} :=== End of STATS * ===")
            user.send(self.get_reply("219", user, flag=flag))
            return

        # Public stats - available to all users
        if flag == 'u':
            # System uptime
            uptime_secs = int(time.time() - self.boot_time)
            days = uptime_secs // 86400
            hours = (uptime_secs % 86400) // 3600
            mins = (uptime_secs % 3600) // 60
            secs = uptime_secs % 60
            user.send(f":{self.servername} 242 {user.nickname} :Server Up {days} days {hours}:{mins:02d}:{secs:02d}")
            user.send(self.get_reply("219", user, flag=flag))
            return

        # Staff listing for regular users (combined a/o/g)
        if flag == 's' and not is_staff:
            # Show combined staff listing to regular users
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Online Staff ---")
            for u in self.users.values():
                if u.is_virtual:
                    continue
                if u.has_mode('a'):
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname} (ADMIN)")
                elif u.has_mode('o'):
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname} (SYSOP)")
                elif u.has_mode('g'):
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname} (GUIDE)")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End of Staff ---")
            user.send(self.get_reply("219", user, flag=flag))
            return

        # Staff-only stats from here on
        if not is_staff:
            user.send(f":{self.servername} NOTICE {user.nickname} :STATS {flag} requires staff privileges")
            user.send(self.get_reply("219", user, flag=flag))
            return

        if flag == 'a':
            # Online ADMINs
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Online ADMINs ---")
            for u in self.users.values():
                if u.has_mode('a') and not u.is_virtual:
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname}!{u.username}@{u.host}")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'o':
            # Online SYSOPs
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Online SYSOPs ---")
            for u in self.users.values():
                if u.has_mode('o') and not u.has_mode('a') and not u.is_virtual:
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname}!{u.username}@{u.host}")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'g':
            # Online GUIDEs
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Online GUIDEs ---")
            for u in self.users.values():
                if u.has_mode('g') and not u.is_virtual:
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname}!{u.username}@{u.host}")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'i':
            # Invisible users count
            count = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
            user.send(f":{self.servername} NOTICE {user.nickname} :Invisible users: {count}")

        elif flag == 'k':
            # ACCESS DENY list
            user.send(f":{self.servername} NOTICE {user.nickname} :--- ACCESS DENY ---")
            if not self.access_list['DENY']:
                user.send(f":{self.servername} NOTICE {user.nickname} :(empty)")
            else:
                for pattern, set_by, set_at, reason in self.access_list['DENY']:
                    reason_str = f" :{reason}" if reason else ""
                    user.send(f":{self.servername} NOTICE {user.nickname} :{pattern} (by {set_by}){reason_str}")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 's':
            # Services/bots (users with +s mode)
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Services/Bots (+s) ---")
            for u in self.users.values():
                if u.has_mode('s') and not u.is_virtual:
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname}!{u.username}@{u.host}")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'z':
            # Gagged users
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Gagged Users (+z) ---")
            for u in self.users.values():
                if u.has_mode('z') and not u.is_virtual:
                    user.send(f":{self.servername} NOTICE {user.nickname} :{u.nickname}!{u.username}@{u.host}")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'c':
            # Configuration
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Configuration ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :Server: {CONFIG.get('server', 'name')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Network: {CONFIG.get('server', 'network')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Version: {CONFIG.get('server', 'version')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Max Users: {CONFIG.get('limits', 'max_users')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :User Modes: {CONFIG.get('modes', 'user')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Chan Modes: {CONFIG.get('modes', 'channel')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Flood Protection: {CONFIG.get('security', 'enable_flood_protection')}")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'd':
            # Database info
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Database ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :Path: {CONFIG.get('database', 'path')}")
            try:
                import os
                db_path = CONFIG.get('database', 'path')
                if os.path.exists(db_path):
                    size = os.path.getsize(db_path)
                    user.send(f":{self.servername} NOTICE {user.nickname} :Size: {size} bytes")
            except Exception:
                pass
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'l':
            # Links (placeholder)
            user.send(f":{self.servername} NOTICE {user.nickname} :--- Server Links ---")
            user.send(f":{self.servername} NOTICE {user.nickname} :(No links configured)")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        elif flag == 'y':
            # Anonymous users count (users with ~ prefix, not authenticated)
            count = sum(1 for u in self.users.values() if u.username.startswith('~') and not u.is_virtual)
            user.send(f":{self.servername} NOTICE {user.nickname} :Anonymous users (~): {count}")

        elif flag == 'x':
            # IRCX users count
            count = sum(1 for u in self.users.values() if u.is_ircx and not u.is_virtual)
            user.send(f":{self.servername} NOTICE {user.nickname} :IRCX users: {count}")

        elif flag == 'w':
            # Authenticated users count
            count = sum(1 for u in self.users.values() if u.authenticated and not u.is_virtual)
            user.send(f":{self.servername} NOTICE {user.nickname} :Authenticated users: {count}")

        elif flag == 't':
            # SSL/TLS status
            user.send(f":{self.servername} NOTICE {user.nickname} :--- SSL/TLS Status ---")
            if SSL_MANAGER:
                ssl_info = SSL_MANAGER.get_info()
                if ssl_info.get('enabled'):
                    user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled")
                    if ssl_info.get('context_loaded'):
                        user.send(f":{self.servername} NOTICE {user.nickname} :Certificate: {ssl_info.get('cert_file', 'N/A')}")
                        user.send(f":{self.servername} NOTICE {user.nickname} :Key: {ssl_info.get('key_file', 'N/A')}")
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
                            user.send(f":{self.servername} NOTICE {user.nickname} :Expires: {ssl_info['expiry']} ({days_left:.0f} days) [{status}]")
                        if ssl_info.get('subject'):
                            user.send(f":{self.servername} NOTICE {user.nickname} :Subject: {ssl_info['subject']}")
                        min_ver = CONFIG.get('ssl', 'min_version', default='TLSv1.2')
                        user.send(f":{self.servername} NOTICE {user.nickname} :Minimum TLS: {min_ver}")
                        ssl_ports = CONFIG.get('ssl', 'ports', default=[6697])
                        user.send(f":{self.servername} NOTICE {user.nickname} :SSL Ports: {', '.join(map(str, ssl_ports))}")
                    else:
                        user.send(f":{self.servername} NOTICE {user.nickname} :SSL: enabled but no certificates loaded")
                else:
                    user.send(f":{self.servername} NOTICE {user.nickname} :SSL: disabled")
            else:
                user.send(f":{self.servername} NOTICE {user.nickname} :SSL: not initialized")
            user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")

        else:
            user.send(f":{self.servername} NOTICE {user.nickname} :Unknown STATS flag: {flag}")

        user.send(self.get_reply("219", user, flag=flag))

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
            user.send(self.get_reply("481", user))
            return

        if not params:
            user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG subcommands: LIST, GET, SET, SAVE, RELOAD")
            return

        subcmd = params[0].upper()

        if subcmd == "LIST":
            # List configuration - SYSOP+ can view
            section = params[1].lower() if len(params) > 1 else None

            if section:
                # List specific section
                sect_data = CONFIG.get_section(section)
                if not sect_data:
                    user.send(f":{self.servername} NOTICE {user.nickname} :Unknown section: {section}")
                    return
                user.send(f":{self.servername} NOTICE {user.nickname} :--- Config [{section}] ---")
                for key, value in sect_data.items():
                    user.send(f":{self.servername} NOTICE {user.nickname} :{section}.{key} = {json.dumps(value)}")
                user.send(f":{self.servername} NOTICE {user.nickname} :--- End ---")
            else:
                # List all sections
                user.send(f":{self.servername} NOTICE {user.nickname} :--- Config Sections ---")
                for section in CONFIG.get_all_sections():
                    sect_data = CONFIG.get_section(section)
                    user.send(f":{self.servername} NOTICE {user.nickname} :[{section}] ({len(sect_data)} keys)")
                user.send(f":{self.servername} NOTICE {user.nickname} :--- End (use CONFIG LIST <section> for details) ---")

        elif subcmd == "GET":
            # Get specific value - SYSOP+ can view
            if len(params) < 2:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: CONFIG GET <section.key>")
                return

            path = params[1].split('.')
            if len(path) < 2:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invalid path. Use: section.key (e.g., limits.max_users)")
                return

            value = CONFIG.get(*path)
            if value is None:
                user.send(f":{self.servername} NOTICE {user.nickname} :{params[1]} = (not set)")
            else:
                user.send(f":{self.servername} NOTICE {user.nickname} :{params[1]} = {json.dumps(value)}")

        elif subcmd == "SET":
            # Set value - ADMIN only
            if not is_admin:
                user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG SET requires ADMIN privileges")
                return

            if len(params) < 3:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: CONFIG SET <section.key> <value>")
                return

            path = params[1].split('.')
            if len(path) < 2:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invalid path. Use: section.key (e.g., limits.max_users)")
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
                user.send(f":{self.servername} NOTICE {user.nickname} :Set {params[1]} = {json.dumps(value)}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Previous value: {json.dumps(old_value)}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Use CONFIG SAVE to persist changes")
                logger.info(f"CONFIG: {user.nickname} set {params[1]} = {json.dumps(value)}")
            else:
                user.send(f":{self.servername} NOTICE {user.nickname} :Failed to set value")

        elif subcmd == "SAVE":
            # Save to disk - ADMIN only
            if not is_admin:
                user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG SAVE requires ADMIN privileges")
                return

            CONFIG.save()
            user.send(f":{self.servername} NOTICE {user.nickname} :Configuration saved to {CONFIG.config_file}")
            logger.info(f"CONFIG: {user.nickname} saved configuration")

        elif subcmd == "RELOAD":
            # Reload from disk - ADMIN only
            if not is_admin:
                user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG RELOAD requires ADMIN privileges")
                return

            CONFIG.load()
            user.send(f":{self.servername} NOTICE {user.nickname} :Configuration reloaded from {CONFIG.config_file}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Note: Some settings require server restart to take effect")
            logger.info(f"CONFIG: {user.nickname} reloaded configuration")

        else:
            user.send(f":{self.servername} NOTICE {user.nickname} :Unknown subcommand: {subcmd}")
            user.send(f":{self.servername} NOTICE {user.nickname} :CONFIG subcommands: LIST, GET, SET, SAVE, RELOAD")

    async def handle_connect(self, user, params):
        """
        CONNECT command - Connect to a remote server.
        Syntax: CONNECT <servername>
        Requires ADMIN or SYSOP privileges.
        """
        if not (user.has_mode('a') or user.has_mode('o')):
            user.send(self.get_reply("481", user))
            return

        if not params:
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: CONNECT <servername>")
            return

        if not hasattr(self, 'link_manager') or not self.link_manager:
            user.send(f":{self.servername} NOTICE {user.nickname} :Server linking is not enabled")
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
            user.send(f":{self.servername} NOTICE {user.nickname} :No link configuration found for {target_server}")
            return

        # Check if already connected
        if target_server in self.link_manager.linked_servers:
            user.send(f":{self.servername} NOTICE {user.nickname} :Already linked to {target_server}")
            return

        # Attempt connection
        user.send(f":{self.servername} NOTICE {user.nickname} :Connecting to {target_server}...")
        try:
            await self.link_manager.connect_to_server(link_cfg)
            user.send(f":{self.servername} NOTICE {user.nickname} :Successfully linked to {target_server}")
            logger.info(f"CONNECT: {user.nickname} linked to {target_server}")
        except Exception as e:
            user.send(f":{self.servername} NOTICE {user.nickname} :Failed to link: {e}")
            logger.error(f"CONNECT: Failed to link to {target_server}: {e}")

    async def handle_squit(self, user, params):
        """
        SQUIT command - Disconnect a linked server.
        Syntax: SQUIT <servername> :<reason>
        Requires ADMIN or SYSOP privileges.
        """
        if not (user.has_mode('a') or user.has_mode('o')):
            user.send(self.get_reply("481", user))
            return

        if not params:
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: SQUIT <servername> :<reason>")
            return

        if not hasattr(self, 'link_manager') or not self.link_manager:
            user.send(f":{self.servername} NOTICE {user.nickname} :Server linking is not enabled")
            return

        target_server = params[0]
        reason = params[1] if len(params) > 1 else f"Requested by {user.nickname}"

        if target_server not in self.link_manager.linked_servers:
            user.send(f":{self.servername} NOTICE {user.nickname} :Not linked to {target_server}")
            return

        user.send(f":{self.servername} NOTICE {user.nickname} :Unlinking from {target_server}...")
        try:
            linked_server = self.link_manager.linked_servers[target_server]
            await self.link_manager.handle_server_split(linked_server, reason)
            user.send(f":{self.servername} NOTICE {user.nickname} :Unlinked from {target_server}")
            logger.info(f"SQUIT: {user.nickname} unlinked {target_server}: {reason}")
        except Exception as e:
            user.send(f":{self.servername} NOTICE {user.nickname} :Failed to unlink: {e}")
            logger.error(f"SQUIT: Failed to unlink {target_server}: {e}")

    async def handle_links(self, user, params):
        """
        LINKS command - Show network topology.
        Syntax: LINKS
        """
        if not hasattr(self, 'link_manager') or not self.link_manager:
            # No linking enabled, just show this server
            user.send(f":{self.servername} 364 {user.nickname} {self.servername} {self.servername} :0 {CONFIG.get('server', 'network', default='IRCX Network')}")
            user.send(f":{self.servername} 365 {user.nickname} * :End of /LINKS list")
            return

        # Show local server
        user.send(f":{self.servername} 364 {user.nickname} {self.servername} {self.servername} :0 {CONFIG.get('server', 'network', default='IRCX Network')}")

        # Show linked servers
        for server_name, linked_server in self.link_manager.linked_servers.items():
            hopcount = linked_server.hopcount
            desc = linked_server.description
            uplink = self.servername if linked_server.is_direct else "via"
            user.send(f":{self.servername} 364 {user.nickname} {server_name} {uplink} :{hopcount} {desc}")

        user.send(f":{self.servername} 365 {user.nickname} * :End of /LINKS list")

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
            user.send(self.get_reply("481", user))
            return

        if not params:
            user.send(f":{self.servername} NOTICE {user.nickname} :STAFF subcommands: LIST, ADD, DEL, SET, PASS")
            user.send(f":{self.servername} NOTICE {user.nickname} :Staff levels: ADMIN, SYSOP, GUIDE")
            return

        subcmd = params[0].upper()

        if subcmd == "LIST":
            # List all staff accounts - SYSOP+ can view
            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT username, level FROM users ORDER BY level, username") as cursor:
                        rows = await cursor.fetchall()

                user.send(f":{self.servername} NOTICE {user.nickname} :--- Staff Accounts ---")
                if not rows:
                    user.send(f":{self.servername} NOTICE {user.nickname} :No staff accounts configured")
                else:
                    # Group by level
                    admins = [r[0] for r in rows if r[1] == 'ADMIN']
                    sysops = [r[0] for r in rows if r[1] == 'SYSOP']
                    guides = [r[0] for r in rows if r[1] == 'GUIDE']

                    if admins:
                        user.send(f":{self.servername} NOTICE {user.nickname} :ADMIN: {', '.join(admins)}")
                    if sysops:
                        user.send(f":{self.servername} NOTICE {user.nickname} :SYSOP: {', '.join(sysops)}")
                    if guides:
                        user.send(f":{self.servername} NOTICE {user.nickname} :GUIDE: {', '.join(guides)}")

                user.send(f":{self.servername} NOTICE {user.nickname} :--- End ({len(rows)} accounts) ---")
            except Exception as e:
                logger.error(f"STAFF LIST error: {e}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Error listing staff accounts")

        elif subcmd == "ADD":
            # Add staff account - ADMIN only
            if not is_admin:
                user.send(f":{self.servername} NOTICE {user.nickname} :STAFF ADD requires ADMIN privileges")
                return

            if len(params) < 4:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF ADD <username> <password> <level>")
                user.send(f":{self.servername} NOTICE {user.nickname} :Levels: ADMIN, SYSOP, GUIDE")
                return

            username = params[1]
            password = params[2]
            level = params[3].upper()

            if level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invalid level. Use: ADMIN, SYSOP, or GUIDE")
                return

            if len(password) < 6:
                user.send(f":{self.servername} NOTICE {user.nickname} :Password must be at least 6 characters")
                return

            # Validate username
            valid, error = validate_username(username)
            if not valid:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invalid username: {error}")
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if already exists
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if await cursor.fetchone():
                            user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' already exists")
                            return

                    # Hash password and insert
                    password_hash = await hash_password_async(password)
                    await db.execute("INSERT INTO users (username, password_hash, level) VALUES (?, ?, ?)",
                                    (username, password_hash, level))
                    await db.commit()

                user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' created with level {level}")
                logger.info(f"STAFF: {user.nickname} added staff account '{username}' ({level})")
                await self.log_staff(user.nickname, "STAFF ADD", username, f"Level: {level}")

            except Exception as e:
                logger.error(f"STAFF ADD error: {e}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Error creating staff account")

        elif subcmd == "DEL":
            # Remove staff account - ADMIN only
            if not is_admin:
                user.send(f":{self.servername} NOTICE {user.nickname} :STAFF DEL requires ADMIN privileges")
                return

            if len(params) < 2:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF DEL <username>")
                return

            username = params[1]

            # Prevent self-deletion
            if username.lower() == user.username.lower().lstrip('~'):
                user.send(f":{self.servername} NOTICE {user.nickname} :Cannot delete your own staff account")
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    # Check if exists
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' not found")
                            return
                        old_level = row[0]

                    await db.execute("DELETE FROM users WHERE username = ?", (username,))
                    await db.commit()

                user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' ({old_level}) deleted")
                logger.info(f"STAFF: {user.nickname} deleted staff account '{username}' ({old_level})")
                await self.log_staff(user.nickname, "STAFF DEL", username, f"Was: {old_level}")

            except Exception as e:
                logger.error(f"STAFF DEL error: {e}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Error deleting staff account")

        elif subcmd == "SET":
            # Change staff level - ADMIN only
            if not is_admin:
                user.send(f":{self.servername} NOTICE {user.nickname} :STAFF SET requires ADMIN privileges")
                return

            if len(params) < 3:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF SET <username> <level>")
                user.send(f":{self.servername} NOTICE {user.nickname} :Levels: ADMIN, SYSOP, GUIDE")
                return

            username = params[1]
            new_level = params[2].upper()

            if new_level not in ['ADMIN', 'SYSOP', 'GUIDE']:
                user.send(f":{self.servername} NOTICE {user.nickname} :Invalid level. Use: ADMIN, SYSOP, or GUIDE")
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT level FROM users WHERE username = ?", (username,)) as cursor:
                        row = await cursor.fetchone()
                        if not row:
                            user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' not found")
                            return
                        old_level = row[0]

                    if old_level == new_level:
                        user.send(f":{self.servername} NOTICE {user.nickname} :'{username}' is already {new_level}")
                        return

                    await db.execute("UPDATE users SET level = ? WHERE username = ?", (new_level, username))
                    await db.commit()

                user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' changed from {old_level} to {new_level}")
                logger.info(f"STAFF: {user.nickname} changed '{username}' level from {old_level} to {new_level}")
                await self.log_staff(user.nickname, "STAFF SET", username, f"{old_level} -> {new_level}")

            except Exception as e:
                logger.error(f"STAFF SET error: {e}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Error changing staff level")

        elif subcmd == "PASS":
            # Change staff password - ADMIN or self
            if len(params) < 3:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: STAFF PASS <username> <newpassword>")
                return

            username = params[1]
            new_password = params[2]

            # Check permissions: ADMIN can change anyone's, others can only change their own
            own_username = user.username.lstrip('~')
            is_self = username.lower() == own_username.lower()

            if not is_admin and not is_self:
                user.send(f":{self.servername} NOTICE {user.nickname} :You can only change your own staff password")
                return

            if len(new_password) < 6:
                user.send(f":{self.servername} NOTICE {user.nickname} :Password must be at least 6 characters")
                return

            try:
                async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                    async with db.execute("SELECT username FROM users WHERE username = ?", (username,)) as cursor:
                        if not await cursor.fetchone():
                            user.send(f":{self.servername} NOTICE {user.nickname} :Staff account '{username}' not found")
                            return

                    password_hash = await hash_password_async(new_password)
                    await db.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                                    (password_hash, username))
                    await db.commit()

                user.send(f":{self.servername} NOTICE {user.nickname} :Password changed for staff account '{username}'")
                logger.info(f"STAFF: {user.nickname} changed password for '{username}'")
                if not is_self:
                    await self.log_staff(user.nickname, "STAFF PASS", username, "Password changed")

            except Exception as e:
                logger.error(f"STAFF PASS error: {e}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Error changing password")

        else:
            user.send(f":{self.servername} NOTICE {user.nickname} :Unknown subcommand: {subcmd}")
            user.send(f":{self.servername} NOTICE {user.nickname} :STAFF subcommands: LIST, ADD, DEL, SET, PASS")

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
            user.send(self.get_reply("371", user, info=line))
        user.send(self.get_reply("374", user))

    async def handle_motd(self, user):
        """Handle MOTD command - display message of the day"""
        user.send(self.get_reply("375", user))
        # Read MOTD from config or file
        motd_lines = CONFIG.get('server', 'motd', default=[
            "Welcome to the IRCX Network",
            "Please be respectful of other users.",
            "Type /help for available commands."
        ])
        if isinstance(motd_lines, str):
            motd_lines = [motd_lines]
        for line in motd_lines:
            user.send(self.get_reply("372", user, text=line))
        user.send(self.get_reply("376", user))

    async def handle_lusers(self, user):
        """Handle LUSERS command - display user statistics"""
        total_users = sum(1 for u in self.users.values() if not u.is_virtual)
        # Staff count includes staff users AND services/bots
        ops = sum(1 for u in self.users.values() if u.has_mode('o') or u.has_mode('a') or u.has_mode('g') or u.is_virtual)
        unknown = 0  # Connections not yet registered
        channels = len(self.channels)

        # Only show invisible count to staff
        is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')
        if is_staff:
            invisible = sum(1 for u in self.users.values() if u.has_mode('i') and not u.is_virtual)
        else:
            invisible = 0  # Hide from non-staff

        user.send(self.get_reply("251", user, users=total_users, invisible=invisible, server_count=1))
        user.send(self.get_reply("252", user, ops=ops))
        if unknown > 0:
            user.send(self.get_reply("253", user, unknown=unknown))
        user.send(self.get_reply("254", user, channels=channels))
        user.send(self.get_reply("255", user, users=total_users))
        user.send(self.get_reply("265", user, local=total_users, local_max=self.max_users_seen))
        user.send(self.get_reply("266", user, global_users=total_users, global_max=self.max_users_seen))

    async def handle_ison(self, user, params):
        """Handle ISON command - check if nicknames are online"""
        if not params:
            user.send(self.get_reply("461", user, command="ISON"))
            return
        # ISON can take multiple nicknames separated by spaces
        nicks_to_check = params[0].split() if len(params) == 1 else params
        online_nicks = []
        for nick in nicks_to_check:
            if nick in self.users and not self.users[nick].is_virtual:
                online_nicks.append(nick)
        user.send(self.get_reply("303", user, nicks=" ".join(online_nicks)))

    async def handle_userhost(self, user, params):
        """Handle USERHOST command - get user@host for nicknames (RFC 2812)

        Returns RPL_USERHOST (302) with format:
        :server 302 nick :nick1*=+user1@host1 nick2=+user2@host2 ...

        The * indicates an IRC operator.
        The + or - indicates away status (+ = here, - = away).
        """
        if not params:
            user.send(self.get_reply("461", user, command="USERHOST"))
            return

        # USERHOST can check up to 5 nicknames
        nicks_to_check = params[:5]
        userhost_info = []

        for nick in nicks_to_check:
            target = self.users.get(nick)
            if target and not target.is_virtual:
                # Build userhost reply: nick*=+user@host
                # * = oper, + = here, - = away
                oper_flag = "*" if target.has_mode('o') or target.has_mode('a') else ""
                away_flag = "-" if target.away_msg else "+"
                userhost_info.append(f"{target.nickname}{oper_flag}={away_flag}{target.username}@{target.host}")

        user.send(self.get_reply("302", user, userhosts=" ".join(userhost_info)))

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
                user.send(self.get_reply("353", user, channel=channel_name, names=names))
            user.send(self.get_reply("366", user, channel="*"))
            return

        # Specific channels requested
        requested_names = params[0].split(',')
        for req_name in requested_names:
            req_name = req_name.strip()
            channel, chan_name = self.get_channel(req_name)
            if not channel:
                user.send(self.get_reply("366", user, channel=req_name))
                continue

            # Check visibility - secret/hidden channels only visible to members
            if (channel.modes.get('s') or channel.modes.get('h')) and chan_name not in user.channels:
                user.send(self.get_reply("366", user, channel=chan_name))
                continue

            names = " ".join([channel.get_prefix(nick) + nick for nick in channel.members])
            user.send(self.get_reply("353", user, channel=chan_name, names=names))
            user.send(self.get_reply("366", user, channel=chan_name))

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
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: REGISTER <account> {{*|<email>}} <password>")
            user.send(f":{self.servername} NOTICE {user.nickname} :   or: REGISTER <#channel> [<password>]")
            return

        target = params[0]

        if is_channel(target):
            # Channel registration (only global # channels, not local &)
            if is_local_channel(target):
                user.send(f":{self.servername} NOTICE {user.nickname} :Local channels (&) cannot be registered")
                return
            channel_password = params[1] if len(params) > 1 else None
            await self._register_channel(user, target, channel_password)
        else:
            # Nickname registration
            if len(params) < 3:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: REGISTER <account> {{*|<email>}} <password>")
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
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: UNREGISTER <account|#channel>")
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
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: IDENTIFY [<account>] <password>")
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
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MFA ENABLE|VERIFY|DISABLE [<code>]")
            return

        subcmd = params[0].upper()

        if subcmd == "ENABLE":
            await self._mfa_enable(user)
        elif subcmd == "VERIFY":
            if len(params) < 2:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MFA VERIFY <6-digit code>")
                return
            await self._mfa_verify(user, params[1])
        elif subcmd == "DISABLE":
            code = params[1] if len(params) > 1 else None
            await self._mfa_disable(user, code)
        else:
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MFA ENABLE|VERIFY|DISABLE [<code>]")

    async def _register_nick(self, user, account, password, email):
        """Register a nickname/account"""
        # Must be using the nickname to register it
        if user.nickname.lower() != account.lower():
            user.send(f":{self.servername} NOTICE {user.nickname} :You must be using the nickname to register it")
            return

        if user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You are already identified to a registered nickname")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (account,)) as cursor:
                    if await cursor.fetchone():
                        user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {account} is already registered")
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
                user.send(f":{user.nickname} MODE {user.nickname} :+r")
                user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {account} has been registered")
                logger.info(f"REGISTER: {account} registered by {user.prefix()}")

        except Exception as e:
            logger.error(f"REGISTER nick error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Registration failed - please try again later")

    async def _register_channel(self, user, channel_name, password):
        """Register a channel"""
        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify to a registered nickname first")
            return

        if channel_name not in self.channels:
            user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} does not exist")
            return

        channel = self.channels[channel_name]
        if user.nickname not in channel.owners:
            user.send(f":{self.servername} NOTICE {user.nickname} :You must be a channel owner to register {channel_name}")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_channels WHERE channel_name = ?",
                                     (channel_name,)) as cursor:
                    if await cursor.fetchone():
                        user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} is already registered")
                        return

                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    owner_row = await cursor.fetchone()
                    if not owner_row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Your nickname must be registered first")
                        return
                    owner_uuid = owner_row[0]

                chan_uuid = str(uuid.uuid4())
                now = int(time.time())

                await db.execute("""INSERT INTO registered_channels
                    (uuid, channel_name, owner_uuid, registered_at)
                    VALUES (?, ?, ?, ?)""",
                    (chan_uuid, channel_name, owner_uuid, now))
                await db.commit()

                channel.registered = True
                channel.account_uuid = chan_uuid
                if password:
                    channel.owner_key = password

                user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} has been registered")
                logger.info(f"REGISTER: {channel_name} registered by {user.nickname}")

        except Exception as e:
            logger.error(f"REGISTER channel error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Registration failed - please try again later")

    async def _unregister_nick(self, user, account):
        """Unregister a nickname/account"""
        if user.nickname.lower() != account.lower():
            user.send(f":{self.servername} NOTICE {user.nickname} :You can only unregister your own nickname")
            return

        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first to unregister")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                await db.execute("DELETE FROM registered_nicks WHERE nickname = ?", (account,))
                await db.commit()

                user.set_mode('r', False)
                user.send(f":{user.nickname} MODE {user.nickname} :-r")
                user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {account} has been unregistered")
                logger.info(f"UNREGISTER: {account} unregistered")

        except Exception as e:
            logger.error(f"UNREGISTER nick error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Unregistration failed - please try again later")

    async def _unregister_channel(self, user, channel_name):
        """Unregister a channel"""
        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        if channel_name not in self.channels:
            user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} does not exist")
            return

        channel = self.channels[channel_name]

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Verify ownership
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    nick_row = await cursor.fetchone()
                    if not nick_row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Your nickname is not registered")
                        return

                async with db.execute("SELECT owner_uuid FROM registered_channels WHERE channel_name = ?",
                                     (channel_name,)) as cursor:
                    chan_row = await cursor.fetchone()
                    if not chan_row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} is not registered")
                        return
                    if chan_row[0] != nick_row[0] and not user.has_mode('a'):
                        user.send(f":{self.servername} NOTICE {user.nickname} :You are not the owner of {channel_name}")
                        return

                await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (channel_name,))
                await db.commit()

                channel.registered = False
                channel.account_uuid = None
                user.send(f":{self.servername} NOTICE {user.nickname} :Channel {channel_name} has been unregistered")
                logger.info(f"UNREGISTER: {channel_name} unregistered by {user.nickname}")

        except Exception as e:
            logger.error(f"UNREGISTER channel error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Unregistration failed - please try again later")

    async def _identify_nick(self, user, account, password):
        """Identify to a registered nickname"""
        if user.nickname.lower() != account.lower():
            user.send(f":{self.servername} NOTICE {user.nickname} :You must be using the nickname to identify to it")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid, password_hash, mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (account,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {account} is not registered")
                        return

                    nick_uuid, password_hash, mfa_enabled, mfa_secret = row
                    # Use non-blocking bcrypt check
                    if await check_password_async(password, password_hash):
                        self.failed_auth_tracker.record_success(user.ip)
                        if mfa_enabled and mfa_secret:
                            user.pending_mfa = nick_uuid
                            user.send(f":{self.servername} NOTICE {user.nickname} :Password accepted. MFA required - use: MFA VERIFY <code>")
                            return

                        user.set_mode('r', True)
                        user.send(f":{user.nickname} MODE {user.nickname} :+r")
                        await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE uuid = ?",
                                        (int(time.time()), nick_uuid))
                        await db.commit()
                        user.send(f":{self.servername} NOTICE {user.nickname} :You are now identified as {account}")
                        logger.info(f"IDENTIFY: {account} identified")
                        # Deliver pending memos
                        await self.deliver_pending_memos(user)
                    else:
                        self.failed_auth_tracker.record_failure(user.ip)
                        user.send(f":{self.servername} NOTICE {user.nickname} :Invalid password")

        except Exception as e:
            logger.error(f"IDENTIFY error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Identification failed - please try again later")

    async def _mfa_enable(self, user):
        """Enable MFA for authenticated user"""
        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first to enable MFA")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not found in database")
                        return

                    mfa_enabled, existing_secret = row
                    if mfa_enabled and existing_secret:
                        user.send(f":{self.servername} NOTICE {user.nickname} :MFA is already enabled")
                        return

                secret = pyotp.random_base32()
                totp = pyotp.TOTP(secret)

                await db.execute("UPDATE registered_nicks SET mfa_secret = ? WHERE nickname = ?",
                                (secret, user.nickname))
                await db.commit()

                issuer = CONFIG.get('server', 'name', default='irc.local')
                provisioning_uri = totp.provisioning_uri(name=user.nickname, issuer_name=issuer)

                user.send(f":{self.servername} NOTICE {user.nickname} :MFA Setup - Add to your authenticator app:")
                user.send(f":{self.servername} NOTICE {user.nickname} :  Secret: {secret}")
                user.send(f":{self.servername} NOTICE {user.nickname} :  URI: {provisioning_uri}")
                user.send(f":{self.servername} NOTICE {user.nickname} :Complete setup with: MFA VERIFY <6-digit code>")
                logger.info(f"MFA: {user.nickname} initiated setup")

        except Exception as e:
            logger.error(f"MFA enable error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :MFA setup failed")

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
                            user.send(f":{self.servername} NOTICE {user.nickname} :MFA session expired")
                            user.pending_mfa = None
                            return

                        mfa_secret, nickname = row
                        totp = pyotp.TOTP(mfa_secret)

                        if totp.verify(code, valid_window=1):
                            user.pending_mfa = None
                            user.set_mode('r', True)
                            user.send(f":{user.nickname} MODE {user.nickname} :+r")
                            await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE nickname = ?",
                                            (int(time.time()), nickname))
                            await db.commit()
                            user.send(f":{self.servername} NOTICE {user.nickname} :MFA verified. You are now identified as {nickname}")
                            logger.info(f"MFA: {nickname} completed identification")
                        else:
                            user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA code")
                    return

                # Case 2: Completing MFA setup
                if not user.has_mode('r'):
                    user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
                    return

                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not found")
                        return

                    mfa_enabled, mfa_secret = row
                    if mfa_enabled:
                        user.send(f":{self.servername} NOTICE {user.nickname} :MFA is already enabled")
                        return
                    if not mfa_secret:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Run MFA ENABLE first")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if totp.verify(code, valid_window=1):
                        await db.execute("UPDATE registered_nicks SET mfa_enabled = 1 WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()
                        user.send(f":{self.servername} NOTICE {user.nickname} :MFA is now enabled")
                        logger.info(f"MFA: {user.nickname} enabled")
                    else:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Invalid code - MFA setup cancelled")
                        await db.execute("UPDATE registered_nicks SET mfa_secret = NULL WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()

        except Exception as e:
            logger.error(f"MFA verify error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :MFA verification failed")

    async def _mfa_disable(self, user, code):
        """Disable MFA for authenticated user"""
        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not found")
                        return

                    mfa_enabled, mfa_secret = row
                    if not mfa_enabled:
                        user.send(f":{self.servername} NOTICE {user.nickname} :MFA is not enabled")
                        return

                    if not code:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MFA DISABLE <6-digit code>")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if not totp.verify(code, valid_window=1):
                        user.send(f":{self.servername} NOTICE {user.nickname} :Invalid MFA code")
                        return

                    await db.execute("UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE nickname = ?",
                                    (user.nickname,))
                    await db.commit()
                    user.send(f":{self.servername} NOTICE {user.nickname} :MFA has been disabled")
                    logger.info(f"MFA: {user.nickname} disabled")

        except Exception as e:
            logger.error(f"MFA disable error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :MFA disable failed")

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
                user.send(f":{self.servername} 606 {user.nickname} :{nicks}")
            user.send(f":{self.servername} 607 {user.nickname} :End of WATCH list")
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
                    user.send(f":{self.servername} 604 {user.nickname} {online_user.nickname} "
                             f"{online_user.username} {online_user.host} {online_user.signon_time} :is online")
                else:
                    user.send(f":{self.servername} 605 {user.nickname} {nick} * * 0 :is offline")

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
                user.send(f":{self.servername} 602 {user.nickname} {nick} * * 0 :stopped watching")

            elif target.upper() == 'L':
                # List watched nicks
                if user.watch_list:
                    nicks = " ".join(user.watch_list)
                    user.send(f":{self.servername} 606 {user.nickname} :{nicks}")
                user.send(f":{self.servername} 607 {user.nickname} :End of WATCH list")

            elif target.upper() == 'C':
                # Clear watch list
                for nick_lower in list(user.watch_list):
                    if nick_lower in self.watchers:
                        self.watchers[nick_lower].discard(user)
                        if not self.watchers[nick_lower]:
                            del self.watchers[nick_lower]
                user.watch_list.clear()
                user.send(f":{self.servername} NOTICE {user.nickname} :Watch list cleared")

            elif target.upper() == 'S':
                # Show status of all watched nicks
                for nick_lower in user.watch_list:
                    online_user = self.users.get(nick_lower)
                    if online_user and online_user.registered:
                        user.send(f":{self.servername} 604 {user.nickname} {online_user.nickname} "
                                 f"{online_user.username} {online_user.host} {online_user.signon_time} :is online")
                    else:
                        user.send(f":{self.servername} 605 {user.nickname} {nick_lower} * * 0 :is offline")
                user.send(f":{self.servername} 607 {user.nickname} :End of WATCH list")

    def notify_watchers_online(self, user):
        """Notify watchers that a user has come online"""
        nick_lower = user.nickname.lower()
        if nick_lower in self.watchers:
            for watcher in self.watchers[nick_lower]:
                if watcher != user and watcher.registered:
                    watcher.send(f":{self.servername} 600 {watcher.nickname} {user.nickname} "
                               f"{user.username} {user.host} {user.signon_time} :logged on")

    def notify_watchers_offline(self, user):
        """Notify watchers that a user has gone offline"""
        nick_lower = user.nickname.lower()
        if nick_lower in self.watchers:
            for watcher in self.watchers[nick_lower]:
                if watcher != user and watcher.registered:
                    watcher.send(f":{self.servername} 601 {watcher.nickname} {user.nickname} "
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
                user.send(f":{self.servername} 271 {user.nickname} {user.nickname} {mask}")
            user.send(f":{self.servername} 272 {user.nickname} :End of Silence List")
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
                user.send(f":{self.servername} NOTICE {user.nickname} :Added {mask} to silence list")

            elif target.startswith('-'):
                mask = target[1:]
                if not mask:
                    continue
                if '!' not in mask or '@' not in mask:
                    mask = f"*!*@{mask}"
                user.silence_list.discard(mask)
                user.send(f":{self.servername} NOTICE {user.nickname} :Removed {mask} from silence list")

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
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: CHGPASS <oldpassword> <newpassword>")
            return

        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        old_pass = params[0]
        new_pass = params[1]

        if len(new_pass) < 6:
            user.send(f":{self.servername} NOTICE {user.nickname} :Password must be at least 6 characters")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Only check registered nicks table (staff use STAFF PASS)
                async with db.execute("SELECT password_hash FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Nickname not registered. Staff accounts use: STAFF PASS <username> <newpassword>")
                        return

                    # Use non-blocking bcrypt check
                    if not await check_password_async(old_pass, row[0]):
                        user.send(f":{self.servername} NOTICE {user.nickname} :Invalid current password")
                        return

                    new_hash = await hash_password_async(new_pass)
                    await db.execute("UPDATE registered_nicks SET password_hash = ? WHERE nickname = ?",
                                    (new_hash, user.nickname))
                    await db.commit()
                    user.send(f":{self.servername} NOTICE {user.nickname} :Password changed successfully")
                    logger.info(f"CHGPASS: {user.nickname} changed password")

        except Exception as e:
            logger.error(f"CHGPASS error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Password change failed")

    async def handle_memo(self, user, params):
        """Handle MEMO command for offline messaging

        Syntax:
          MEMO SEND <nick> <message>  - Send memo to offline user
          MEMO LIST                   - List pending memos
          MEMO READ [id]              - Read memo(s)
          MEMO DEL <id|ALL>           - Delete memo(s)
        """
        if not params:
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO SEND|LIST|READ|DEL ...")
            return

        subcmd = params[0].upper()

        if subcmd == "SEND":
            if len(params) < 3:
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO SEND <nick> <message>")
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
                user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO DEL <id|ALL>")
                return
            target = params[1]
            await self._memo_del(user, target)

        else:
            user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO SEND|LIST|READ|DEL ...")

    async def _memo_send(self, user, target_nick, message):
        """Send a memo to a user"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if target is a registered nick
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (target_nick,)) as cursor:
                    if not await cursor.fetchone():
                        user.send(f":{self.servername} NOTICE {user.nickname} :Nickname {target_nick} is not registered")
                        return

                # Store memo
                await db.execute("""
                    INSERT INTO memos (recipient, sender, message, sent_at, read)
                    VALUES (?, ?, ?, ?, 0)
                """, (target_nick.lower(), user.nickname, message, int(time.time())))
                await db.commit()
                user.send(f":{self.servername} NOTICE {user.nickname} :Memo sent to {target_nick}")

                # If recipient is online and identified, notify them
                target_user = self.users.get(target_nick.lower())
                if target_user and target_user.has_mode('r'):
                    target_user.send(f":{self.servername} NOTICE {target_user.nickname} :You have a new memo from {user.nickname}. Use MEMO READ to view.")

        except Exception as e:
            logger.error(f"MEMO SEND error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Failed to send memo")

    async def _memo_list(self, user):
        """List user's memos"""
        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""
                    SELECT id, sender, sent_at, read FROM memos
                    WHERE recipient = ? ORDER BY sent_at DESC LIMIT 20
                """, (user.nickname.lower(),)) as cursor:
                    memos = await cursor.fetchall()

                if not memos:
                    user.send(f":{self.servername} NOTICE {user.nickname} :You have no memos")
                    return

                user.send(f":{self.servername} NOTICE {user.nickname} :--- Memo List ---")
                for memo_id, sender, sent_at, read in memos:
                    status = "" if read else "[NEW] "
                    timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                    user.send(f":{self.servername} NOTICE {user.nickname} :{status}#{memo_id} from {sender} at {timestamp}")
                user.send(f":{self.servername} NOTICE {user.nickname} :--- End of Memo List ---")

        except Exception as e:
            logger.error(f"MEMO LIST error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Failed to list memos")

    async def _memo_read(self, user, memo_id=None):
        """Read memo(s)"""
        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
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
                        user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{memo_id} not found")
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
                    user.send(f":{self.servername} NOTICE {user.nickname} :No unread memos")
                    return

                for mid, sender, message, sent_at in memos:
                    timestamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(sent_at))
                    user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{mid} from {sender} ({timestamp}):")
                    user.send(f":{self.servername} NOTICE {user.nickname} :{message}")

                # Mark as read
                ids = [m[0] for m in memos]
                placeholders = ",".join("?" * len(ids))
                await db.execute(f"UPDATE memos SET read = 1 WHERE id IN ({placeholders})", ids)
                await db.commit()

        except Exception as e:
            logger.error(f"MEMO READ error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Failed to read memos")

    async def _memo_del(self, user, target):
        """Delete memo(s)"""
        if not user.has_mode('r'):
            user.send(f":{self.servername} NOTICE {user.nickname} :You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                if target.upper() == "ALL":
                    await db.execute("DELETE FROM memos WHERE recipient = ?", (user.nickname.lower(),))
                    user.send(f":{self.servername} NOTICE {user.nickname} :All memos deleted")
                elif target.isdigit():
                    result = await db.execute("DELETE FROM memos WHERE recipient = ? AND id = ?",
                                             (user.nickname.lower(), int(target)))
                    if result.rowcount > 0:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{target} deleted")
                    else:
                        user.send(f":{self.servername} NOTICE {user.nickname} :Memo #{target} not found")
                else:
                    user.send(f":{self.servername} NOTICE {user.nickname} :Usage: MEMO DEL <id|ALL>")
                    return
                await db.commit()

        except Exception as e:
            logger.error(f"MEMO DEL error: {e}")
            user.send(f":{self.servername} NOTICE {user.nickname} :Failed to delete memo")

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
                    user.send(f":{self.servername} NOTICE {user.nickname} :You have {count} unread memo(s). Use MEMO READ to view.")

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
            user.send(f":{self.servername} 410 {user.nickname} :Invalid CAP command")
            return

        subcmd = params[0].upper()

        if subcmd == "LS":
            user.cap_negotiating = True
            user.cap_start_time = time.time()  # Track when CAP started for timeout
            version = params[1] if len(params) > 1 else "301"
            caps = " ".join(self.SUPPORTED_CAPS)
            # Multi-line if needed (CAP * LS * for continuation)
            user.send(f":{self.servername} CAP {user.nickname} LS :{caps}")

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
                user.send(f":{self.servername} CAP {user.nickname} NAK :{' '.join(nak)}")
            if ack:
                user.send(f":{self.servername} CAP {user.nickname} ACK :{' '.join(ack)}")

        elif subcmd == "END":
            user.cap_negotiating = False
            user.cap_start_time = None  # Clear timeout tracker
            # Registration may proceed if NICK/USER already received
            if user.nickname != "*" and user.username != "unknown" and not user.registered:
                await self.check_reg(user)

        elif subcmd == "LIST":
            caps = " ".join(user.enabled_caps) if user.enabled_caps else ""
            user.send(f":{self.servername} CAP {user.nickname} LIST :{caps}")

        else:
            user.send(f":{self.servername} 410 {user.nickname} :Invalid CAP subcommand")

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
            user.send(f":{self.servername} 461 {user.nickname} AUTHENTICATE :Not enough parameters")
            return

        arg = params[0]

        # Client aborting - check this FIRST before rate limiting
        if arg == "*":
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            user.send(f":{self.servername} 906 {user.nickname} :SASL authentication aborted")
            return

        # Check for auth lockout
        if self.failed_auth_tracker.is_locked_out(user.ip):
            remaining = self.failed_auth_tracker.get_lockout_remaining(user.ip)
            user.send(f":{self.servername} 904 {user.nickname} :Too many failed attempts. Try again in {remaining}s")
            return

        # Rate limit AUTHENTICATE attempts
        if not user.check_rate_limit('AUTHENTICATE'):
            user.send(f":{self.servername} 904 {user.nickname} :SASL authentication rate limited")
            return

        # Check if SASL capability is enabled
        if 'sasl' not in user.enabled_caps:
            user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed (SASL not enabled)")
            return

        # Already authenticated via SASL
        if user.sasl_authenticated:
            user.send(f":{self.servername} 907 {user.nickname} :You have already authenticated via SASL")
            return

        # Client requesting mechanism list or starting auth
        if arg.upper() in self.SASL_MECHANISMS:
            user.sasl_mechanism = arg.upper()
            user.sasl_buffer = ""
            # Send + to indicate ready for credentials
            user.send("AUTHENTICATE +")
            return

        # Unknown mechanism
        if user.sasl_mechanism is None:
            # Check if it's an unsupported mechanism
            if arg.upper() not in self.SASL_MECHANISMS and not arg.startswith('+') and arg != "*":
                mechs = ",".join(self.SASL_MECHANISMS)
                user.send(f":{self.servername} 908 {user.nickname} {mechs} :are available SASL mechanisms")
                user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
            return

        # Receiving credentials
        if arg == "+":
            # Empty auth (abort)
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            user.send(f":{self.servername} 906 {user.nickname} :SASL authentication aborted")
            return

        # Add to buffer (for chunked data, max 400 bytes per line)
        user.sasl_buffer += arg

        # Check for too long SASL message (max 8KB base64)
        if len(user.sasl_buffer) > 8192:
            user.sasl_mechanism = None
            user.sasl_buffer = ""
            user.send(f":{self.servername} 905 {user.nickname} :SASL message too long")
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
            user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
            return

        user.sasl_buffer = ""

        if user.sasl_mechanism == "PLAIN":
            await self._sasl_plain(user, decoded)
        else:
            user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")

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
                user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
                return

            authzid, authcid, password = parts

            # Use authcid as the username (authzid is often empty)
            username = authcid if authcid else authzid
            if not username or not password:
                self.failed_auth_tracker.record_failure(user.ip)
                user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")
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
                        self.failed_auth_tracker.record_success(user.ip)

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
                        user.send(f":{self.servername} 900 {user.nickname} {account_host} {username} :You are now logged in as {username}")
                        user.send(f":{self.servername} 903 {user.nickname} :SASL authentication successful")
                        logger.info(f"SASL PLAIN auth success: {username} ({user.ip})")
                        return
            except Exception as e:
                logger.error(f"SASL database error: {e}")

            # Authentication failed - track failure
            self.failed_auth_tracker.record_failure(user.ip)
            logger.warning(f"SASL PLAIN auth failed: {username} ({user.ip})")
            user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")

        except Exception as e:
            logger.error(f"SASL PLAIN error: {e}")
            self.failed_auth_tracker.record_failure(user.ip)
            user.send(f":{self.servername} 904 {user.nickname} :SASL authentication failed")

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
        if params and params[0].upper() == "ADD" and len(params) >= 3:
            user.traps.append((params[1].upper(), params[2]))
            user.send(self.get_reply("806", user, cls=params[1].upper(), mask=params[2]))

    # ==========================================================================
    # SERVICE HANDLERS (Registrar, Messenger, NewsFlash)
    # ==========================================================================

    def _service_reply(self, service_name, user, message):
        """Send a reply from a service to a user"""
        user.send(f":{service_name}!{service_name}@{self.servername} NOTICE {user.nickname} :{message}")

    async def _handle_registrar_msg(self, user, text):
        """Handle messages to Registrar service - routes to direct command handlers

        This is a compatibility layer for users who prefer the traditional
        NickServ-style interface. All commands route to the same backend as
        the direct REGISTER, UNREGISTER, IDENTIFY, MFA commands.
        """
        parts = text.strip().split(None, 2)
        if not parts:
            self._service_reply("Registrar", user, "Commands: REGISTER <password> [email], IDENTIFY <password>, "
                               "DROP, INFO [nick], CHANNEL REGISTER|DROP <#channel>, "
                               "SET PASSWORD|EMAIL <value>, MFA ENABLE|VERIFY|DISABLE")
            self._service_reply("Registrar", user, "TIP: You can also use direct commands: REGISTER, UNREGISTER, IDENTIFY, MFA")
            return

        cmd = parts[0].upper()

        if cmd == "REGISTER":
            # REGISTER <password> [email] -> REGISTER <nick> {*|email} <password>
            if len(parts) < 2:
                self._service_reply("Registrar", user, "Usage: REGISTER <password> [email]")
                return
            password = parts[1]
            email = parts[2] if len(parts) > 2 else None
            await self._register_nick(user, user.nickname, password, email)

        elif cmd == "IDENTIFY":
            if len(parts) < 2:
                self._service_reply("Registrar", user, "Usage: IDENTIFY <password>")
                return
            await self._identify_nick(user, user.nickname, parts[1])

        elif cmd == "DROP":
            await self._unregister_nick(user, user.nickname)

        elif cmd == "INFO":
            target = parts[1] if len(parts) > 1 else user.nickname
            await self._registrar_info(user, target)

        elif cmd == "CHANNEL":
            if len(parts) < 3:
                self._service_reply("Registrar", user, "Usage: CHANNEL REGISTER|DROP <#channel>")
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
                self._service_reply("Registrar", user, "Usage: CHANNEL REGISTER|DROP|INFO <#channel>")

        elif cmd == "SET":
            if len(parts) < 3:
                self._service_reply("Registrar", user, "Usage: SET PASSWORD|EMAIL <value>")
                return
            setting = parts[1].upper()
            value = parts[2]
            await self._registrar_set(user, setting, value)

        elif cmd == "MFA":
            if len(parts) < 2:
                self._service_reply("Registrar", user, "Usage: MFA ENABLE|VERIFY|DISABLE [code]")
                return
            subcmd = parts[1].upper()
            if subcmd == "ENABLE":
                await self._mfa_enable(user)
            elif subcmd == "DISABLE":
                code = parts[2] if len(parts) > 2 else None
                await self._mfa_disable(user, code)
            elif subcmd == "VERIFY":
                if len(parts) < 3:
                    self._service_reply("Registrar", user, "Usage: MFA VERIFY <6-digit code>")
                    return
                await self._mfa_verify(user, parts[2])
            else:
                self._service_reply("Registrar", user, "Usage: MFA ENABLE|VERIFY|DISABLE [code]")

        else:
            self._service_reply("Registrar", user, f"Unknown command: {cmd}. Try: REGISTER, IDENTIFY, DROP, INFO, CHANNEL, SET, MFA")

    async def _registrar_register_nick(self, user, password, email):
        """Register a nickname"""
        if user.has_mode('r'):
            self._service_reply("Registrar", user, "You are already identified to a registered nickname")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if nick already registered
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    if await cursor.fetchone():
                        self._service_reply("Registrar", user, f"Nickname {user.nickname} is already registered")
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
                user.send(f":{user.nickname} MODE {user.nickname} :+r")
                self._service_reply("Registrar", user, f"Nickname {user.nickname} has been registered (UUID: {nick_uuid})")
                logger.info(f"Registrar: {user.nickname} registered by {user.prefix()}")

        except Exception as e:
            logger.error(f"Registrar register error: {e}")
            self._service_reply("Registrar", user, "Registration failed - please try again later")

    async def _registrar_identify(self, user, password):
        """Identify with a registered nickname"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid, password_hash, mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        self._service_reply("Registrar", user, f"Nickname {user.nickname} is not registered")
                        return

                    nick_uuid, password_hash, mfa_enabled, mfa_secret = row
                    # Use non-blocking bcrypt check
                    if await check_password_async(password, password_hash):
                        self.failed_auth_tracker.record_success(user.ip)
                        # Check if MFA is enabled
                        if mfa_enabled and mfa_secret:
                            # Set pending MFA state - user must complete MFA verification
                            user.pending_mfa = nick_uuid
                            self._service_reply("Registrar", user, "Password accepted. MFA is enabled - please verify with: MFA VERIFY <6-digit code>")
                            return

                        # No MFA required - complete identification
                        user.set_mode('r', True)
                        user.send(f":{user.nickname} MODE {user.nickname} :+r")
                        await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE uuid = ?",
                                        (int(time.time()), nick_uuid))
                        await db.commit()
                        self._service_reply("Registrar", user, f"You are now identified as {user.nickname}")
                        logger.info(f"Registrar: {user.nickname} identified")
                    else:
                        self.failed_auth_tracker.record_failure(user.ip)
                        self._service_reply("Registrar", user, "Invalid password")

        except Exception as e:
            logger.error(f"Registrar identify error: {e}")
            self._service_reply("Registrar", user, "Identification failed - please try again later")

    async def _registrar_drop_nick(self, user):
        """Drop (unregister) a nickname"""
        if not user.has_mode('r'):
            self._service_reply("Registrar", user, "You must identify first to drop your nickname")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                await db.execute("DELETE FROM registered_nicks WHERE nickname = ?", (user.nickname,))
                await db.commit()

                user.set_mode('r', False)
                user.send(f":{user.nickname} MODE {user.nickname} :-r")
                self._service_reply("Registrar", user, f"Nickname {user.nickname} has been dropped")
                logger.info(f"Registrar: {user.nickname} dropped")

        except Exception as e:
            logger.error(f"Registrar drop error: {e}")
            self._service_reply("Registrar", user, "Drop failed - please try again later")

    async def _registrar_info(self, user, target_nick):
        """Get info about a registered nickname"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""SELECT uuid, nickname, registered_at, last_seen, mfa_enabled
                                        FROM registered_nicks WHERE nickname = ?""",
                                     (target_nick,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        self._service_reply("Registrar", user, f"Nickname {target_nick} is not registered")
                        return

                    nick_uuid, nickname, reg_at, last_seen, mfa = row
                    self._service_reply("Registrar", user, f"Info for {nickname}:")
                    self._service_reply("Registrar", user, f"  UUID: {nick_uuid}")
                    self._service_reply("Registrar", user, f"  Registered: {time.ctime(reg_at)}")
                    self._service_reply("Registrar", user, f"  Last seen: {time.ctime(last_seen)}")
                    self._service_reply("Registrar", user, f"  MFA enabled: {'Yes' if mfa else 'No'}")

        except Exception as e:
            logger.error(f"Registrar info error: {e}")
            self._service_reply("Registrar", user, "Info lookup failed")

    async def _registrar_register_channel(self, user, channel_name):
        """Register a channel"""
        if not user.has_mode('r'):
            self._service_reply("Registrar", user, "You must identify to a registered nickname first")
            return

        if channel_name not in self.channels:
            self._service_reply("Registrar", user, f"Channel {channel_name} does not exist")
            return

        channel = self.channels[channel_name]
        if user.nickname not in channel.owners:
            self._service_reply("Registrar", user, f"You must be a channel owner to register {channel_name}")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if already registered
                async with db.execute("SELECT uuid FROM registered_channels WHERE channel_name = ?",
                                     (channel_name,)) as cursor:
                    if await cursor.fetchone():
                        self._service_reply("Registrar", user, f"Channel {channel_name} is already registered")
                        return

                # Get owner's UUID
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    owner_row = await cursor.fetchone()
                    if not owner_row:
                        self._service_reply("Registrar", user, "Your nickname must be registered first")
                        return
                    owner_uuid = owner_row[0]

                # Register the channel
                chan_uuid = str(uuid.uuid4())
                now = int(time.time())

                await db.execute("""INSERT INTO registered_channels
                    (uuid, channel_name, owner_uuid, registered_at, last_used)
                    VALUES (?, ?, ?, ?, ?)""",
                    (chan_uuid, channel_name, owner_uuid, now, now))
                await db.commit()

                channel.registered = True
                channel.account_uuid = chan_uuid
                self._service_reply("Registrar", user, f"Channel {channel_name} has been registered (UUID: {chan_uuid})")
                logger.info(f"Registrar: {channel_name} registered by {user.nickname}")

        except Exception as e:
            logger.error(f"Registrar channel register error: {e}")
            self._service_reply("Registrar", user, "Channel registration failed")

    async def _registrar_drop_channel(self, user, channel_name):
        """Drop (unregister) a channel"""
        if not user.has_mode('r'):
            self._service_reply("Registrar", user, "You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Get owner's UUID
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    owner_row = await cursor.fetchone()
                    if not owner_row:
                        self._service_reply("Registrar", user, "Your nickname is not registered")
                        return
                    owner_uuid = owner_row[0]

                # Check ownership
                async with db.execute("SELECT owner_uuid FROM registered_channels WHERE channel_name = ?",
                                     (channel_name,)) as cursor:
                    chan_row = await cursor.fetchone()
                    if not chan_row:
                        self._service_reply("Registrar", user, f"Channel {channel_name} is not registered")
                        return
                    if chan_row[0] != owner_uuid and not user.has_mode('a'):
                        self._service_reply("Registrar", user, "Only the channel owner or an admin can drop it")
                        return

                await db.execute("DELETE FROM registered_channels WHERE channel_name = ?", (channel_name,))
                await db.commit()

                if channel_name in self.channels:
                    self.channels[channel_name].registered = False
                    self.channels[channel_name].account_uuid = None

                self._service_reply("Registrar", user, f"Channel {channel_name} has been dropped")
                logger.info(f"Registrar: {channel_name} dropped by {user.nickname}")

        except Exception as e:
            logger.error(f"Registrar channel drop error: {e}")
            self._service_reply("Registrar", user, "Channel drop failed")

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
                        self._service_reply("Registrar", user, f"Channel {channel_name} is not registered")
                        return

                    chan_uuid, chan_name, reg_at, last_used, desc, owner = row
                    self._service_reply("Registrar", user, f"Info for {chan_name}:")
                    self._service_reply("Registrar", user, f"  UUID: {chan_uuid}")
                    self._service_reply("Registrar", user, f"  Owner: {owner or 'Unknown'}")
                    self._service_reply("Registrar", user, f"  Registered: {time.ctime(reg_at)}")
                    if desc:
                        self._service_reply("Registrar", user, f"  Description: {desc}")

        except Exception as e:
            logger.error(f"Registrar channel info error: {e}")
            self._service_reply("Registrar", user, "Channel info lookup failed")

    async def _registrar_set(self, user, setting, value):
        """Change registration settings"""
        if not user.has_mode('r'):
            self._service_reply("Registrar", user, "You must identify first")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                if setting == "PASSWORD":
                    password_hash = await hash_password_async(value)
                    await db.execute("UPDATE registered_nicks SET password_hash = ? WHERE nickname = ?",
                                    (password_hash, user.nickname))
                    await db.commit()
                    self._service_reply("Registrar", user, "Password updated")
                    logger.info(f"Registrar: {user.nickname} changed password")

                elif setting == "EMAIL":
                    await db.execute("UPDATE registered_nicks SET email = ? WHERE nickname = ?",
                                    (value, user.nickname))
                    await db.commit()
                    self._service_reply("Registrar", user, f"Email updated to {value}")

                else:
                    self._service_reply("Registrar", user, f"Unknown setting: {setting}")

        except Exception as e:
            logger.error(f"Registrar set error: {e}")
            self._service_reply("Registrar", user, "Setting update failed")

    async def _registrar_mfa_enable(self, user):
        """Enable MFA for a registered nickname"""
        if not user.has_mode('r'):
            self._service_reply("Registrar", user, "You must identify first to enable MFA")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                # Check if MFA is already enabled
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        self._service_reply("Registrar", user, "Nickname not found in database")
                        return

                    mfa_enabled, existing_secret = row
                    if mfa_enabled and existing_secret:
                        self._service_reply("Registrar", user, "MFA is already enabled for your nickname")
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
                self._service_reply("Registrar", user, "MFA Setup - Add this to your authenticator app:")
                self._service_reply("Registrar", user, f"  Secret: {secret}")
                self._service_reply("Registrar", user, f"  URI: {provisioning_uri}")
                self._service_reply("Registrar", user, "To complete setup, verify with: MFA VERIFY <6-digit code>")
                self._service_reply("Registrar", user, "MFA will NOT be active until you verify the code")
                logger.info(f"Registrar: {user.nickname} initiated MFA setup")

        except Exception as e:
            logger.error(f"Registrar MFA enable error: {e}")
            self._service_reply("Registrar", user, "MFA setup failed - please try again later")

    async def _registrar_mfa_disable(self, user, code):
        """Disable MFA for a registered nickname"""
        if not user.has_mode('r'):
            self._service_reply("Registrar", user, "You must identify first to disable MFA")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        self._service_reply("Registrar", user, "Nickname not found in database")
                        return

                    mfa_enabled, mfa_secret = row
                    if not mfa_enabled:
                        self._service_reply("Registrar", user, "MFA is not currently enabled")
                        return

                    # Require valid code to disable MFA
                    if not code:
                        self._service_reply("Registrar", user, "Usage: MFA DISABLE <6-digit code>")
                        self._service_reply("Registrar", user, "You must provide a valid MFA code to disable MFA")
                        return

                    totp = pyotp.TOTP(mfa_secret)
                    if not totp.verify(code, valid_window=1):
                        self._service_reply("Registrar", user, "Invalid MFA code")
                        return

                    # Disable MFA
                    await db.execute("UPDATE registered_nicks SET mfa_enabled = 0, mfa_secret = NULL WHERE nickname = ?",
                                    (user.nickname,))
                    await db.commit()

                    self._service_reply("Registrar", user, "MFA has been disabled for your nickname")
                    logger.info(f"Registrar: {user.nickname} disabled MFA")

        except Exception as e:
            logger.error(f"Registrar MFA disable error: {e}")
            self._service_reply("Registrar", user, "MFA disable failed - please try again later")

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
                            self._service_reply("Registrar", user, "MFA verification failed - session expired")
                            user.pending_mfa = None
                            return

                        mfa_secret, nickname = row
                        totp = pyotp.TOTP(mfa_secret)

                        if totp.verify(code, valid_window=1):
                            # MFA verified - complete identification
                            user.pending_mfa = None
                            user.set_mode('r', True)
                            user.send(f":{user.nickname} MODE {user.nickname} :+r")
                            await db.execute("UPDATE registered_nicks SET last_seen = ? WHERE nickname = ?",
                                            (int(time.time()), nickname))
                            await db.commit()
                            self._service_reply("Registrar", user, f"MFA verified. You are now identified as {user.nickname}")
                            logger.info(f"Registrar: {user.nickname} completed MFA identification")
                        else:
                            self._service_reply("Registrar", user, "Invalid MFA code. Please try again")
                    return

                # Case 2: User is enabling MFA (must be identified)
                if not user.has_mode('r'):
                    self._service_reply("Registrar", user, "You must identify first, or complete pending MFA verification")
                    return

                async with db.execute("SELECT mfa_enabled, mfa_secret FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        self._service_reply("Registrar", user, "Nickname not found in database")
                        return

                    mfa_enabled, mfa_secret = row

                    if mfa_enabled:
                        self._service_reply("Registrar", user, "MFA is already enabled. Did you mean to verify after IDENTIFY?")
                        return

                    if not mfa_secret:
                        self._service_reply("Registrar", user, "You must run MFA ENABLE first to set up MFA")
                        return

                    # Verify the code to enable MFA
                    totp = pyotp.TOTP(mfa_secret)
                    if totp.verify(code, valid_window=1):
                        await db.execute("UPDATE registered_nicks SET mfa_enabled = 1 WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()
                        self._service_reply("Registrar", user, "MFA is now enabled for your nickname")
                        self._service_reply("Registrar", user, "You will need to provide an MFA code after IDENTIFY from now on")
                        logger.info(f"Registrar: {user.nickname} enabled MFA")
                    else:
                        self._service_reply("Registrar", user, "Invalid MFA code. MFA setup cancelled")
                        # Clear the pending secret since verification failed
                        await db.execute("UPDATE registered_nicks SET mfa_secret = NULL WHERE nickname = ?",
                                        (user.nickname,))
                        await db.commit()

        except Exception as e:
            logger.error(f"Registrar MFA verify error: {e}")
            self._service_reply("Registrar", user, "MFA verification failed - please try again later")

    async def _handle_messenger_msg(self, user, text):
        """Handle messages to Messenger service"""
        parts = text.strip().split(None, 2)
        if not parts:
            self._service_reply("Messenger", user, "Commands: SEND <nick> <message>, READ, DELETE <id>, COUNT")
            return

        cmd = parts[0].upper()

        if cmd == "SEND":
            if len(parts) < 3:
                self._service_reply("Messenger", user, "Usage: SEND <nick> <message>")
                return
            target_nick = parts[1]
            message = parts[2]
            await self._messenger_send(user, target_nick, message)

        elif cmd == "READ":
            await self._messenger_read(user)

        elif cmd == "DELETE":
            if len(parts) < 2:
                self._service_reply("Messenger", user, "Usage: DELETE <id>")
                return
            try:
                msg_id = int(parts[1])
                await self._messenger_delete(user, msg_id)
            except ValueError:
                self._service_reply("Messenger", user, "Invalid message ID")

        elif cmd == "COUNT":
            await self._messenger_count(user)

        elif cmd == "PUSH" and user.has_mode('a'):
            # ADMIN only - push to all logged in users
            if len(parts) < 2:
                self._service_reply("Messenger", user, "Usage: PUSH <message>")
                return
            message = parts[1] if len(parts) == 2 else parts[1] + " " + parts[2]
            await self._messenger_push(user, message)

        else:
            self._service_reply("Messenger", user, f"Unknown command: {cmd}")

    async def _messenger_send(self, user, target_nick, message):
        """Send a message to a registered user's mailbox"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (target_nick,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        self._service_reply("Messenger", user, f"Nickname {target_nick} is not registered")
                        return
                    recipient_uuid = row[0]

                await db.execute("""INSERT INTO mailbox (recipient_uuid, sender_nick, message, sent_at)
                                   VALUES (?, ?, ?, ?)""",
                                (recipient_uuid, user.nickname, message, int(time.time())))
                await db.commit()

                self._service_reply("Messenger", user, f"Message sent to {target_nick}")

                # Notify if online
                target = self.users.get(target_nick)
                if target and not target.is_virtual:
                    self._service_reply("Messenger", target, f"You have a new message from {user.nickname}")

        except Exception as e:
            logger.error(f"Messenger send error: {e}")
            self._service_reply("Messenger", user, "Failed to send message")

    async def _messenger_read(self, user):
        """Read messages from mailbox"""
        if not user.has_mode('r'):
            self._service_reply("Messenger", user, "You must identify to read your messages")
            return

        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("SELECT uuid FROM registered_nicks WHERE nickname = ?",
                                     (user.nickname,)) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        self._service_reply("Messenger", user, "Your nickname is not registered")
                        return
                    user_uuid = row[0]

                async with db.execute("""SELECT id, sender_nick, message, sent_at, read
                                        FROM mailbox WHERE recipient_uuid = ? ORDER BY sent_at DESC LIMIT 10""",
                                     (user_uuid,)) as cursor:
                    messages = await cursor.fetchall()

                if not messages:
                    self._service_reply("Messenger", user, "No messages in your mailbox")
                    return

                self._service_reply("Messenger", user, f"--- Mailbox ({len(messages)} messages) ---")
                for msg_id, sender, text, sent_at, is_read in messages:
                    status = "" if is_read else "[NEW] "
                    self._service_reply("Messenger", user, f"[{msg_id}] {status}From {sender} ({time.ctime(sent_at)}): {text}")

                # Mark as read
                await db.execute("UPDATE mailbox SET read = 1 WHERE recipient_uuid = ?", (user_uuid,))
                await db.commit()

        except Exception as e:
            logger.error(f"Messenger read error: {e}")
            self._service_reply("Messenger", user, "Failed to read messages")

    async def _messenger_delete(self, user, msg_id):
        """Delete a message from mailbox"""
        if not user.has_mode('r'):
            self._service_reply("Messenger", user, "You must identify first")
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
                    self._service_reply("Messenger", user, f"Message {msg_id} deleted")
                else:
                    self._service_reply("Messenger", user, f"Message {msg_id} not found")

        except Exception as e:
            logger.error(f"Messenger delete error: {e}")
            self._service_reply("Messenger", user, "Failed to delete message")

    async def _messenger_count(self, user):
        """Count unread messages"""
        if not user.has_mode('r'):
            self._service_reply("Messenger", user, "You must identify first")
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

                self._service_reply("Messenger", user, f"You have {count} unread message(s)")

        except Exception as e:
            logger.error(f"Messenger count error: {e}")

    async def _messenger_push(self, user, message):
        """Push a global message to all online users (ADMIN only)"""
        source = f":Messenger!Messenger@{self.servername}"
        out = f"{source} PRIVMSG * :[Global] {message}"
        count = 0
        for recipient in self.users.values():
            if not recipient.is_virtual:
                recipient.send(out)
                count += 1
        self._service_reply("Messenger", user, f"Message pushed to {count} user(s)")
        logger.info(f"Messenger: Global push by {user.nickname}: {message}")

    async def _handle_newsflash_msg(self, user, text):
        """Handle messages to NewsFlash service"""
        parts = text.strip().split(None, 1)
        if not parts:
            self._service_reply("NewsFlash", user, "Commands: LIST, ADD <message> (staff), DEL <id> (staff), PUSH <message> (admin)")
            return

        cmd = parts[0].upper()
        is_staff = user.has_mode('o') or user.has_mode('a') or user.has_mode('g')

        if cmd == "LIST":
            await self._newsflash_list(user)

        elif cmd == "ADD" and is_staff:
            if len(parts) < 2:
                self._service_reply("NewsFlash", user, "Usage: ADD <message>")
                return
            await self._newsflash_add(user, parts[1])

        elif cmd == "DEL" and is_staff:
            if len(parts) < 2:
                self._service_reply("NewsFlash", user, "Usage: DEL <id>")
                return
            try:
                msg_id = int(parts[1])
                await self._newsflash_delete(user, msg_id)
            except ValueError:
                self._service_reply("NewsFlash", user, "Invalid message ID")

        elif cmd == "PUSH" and user.has_mode('a'):
            if len(parts) < 2:
                self._service_reply("NewsFlash", user, "Usage: PUSH <message>")
                return
            await self._newsflash_push(user, parts[1])

        else:
            if cmd in ["ADD", "DEL", "PUSH"] and not is_staff:
                self._service_reply("NewsFlash", user, "That command requires staff privileges")
            else:
                self._service_reply("NewsFlash", user, f"Unknown command: {cmd}")

    async def _newsflash_list(self, user):
        """List active newsflash messages"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                async with db.execute("""SELECT id, message, priority, created_by, created_at
                                        FROM newsflash WHERE active = 1 ORDER BY priority DESC, id DESC""") as cursor:
                    messages = await cursor.fetchall()

                if not messages:
                    self._service_reply("NewsFlash", user, "No active news messages")
                    return

                self._service_reply("NewsFlash", user, "--- Active News ---")
                for msg_id, msg, priority, created_by, created_at in messages:
                    self._service_reply("NewsFlash", user, f"[{msg_id}] (P{priority}) {msg} - by {created_by}")

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
                self._service_reply("NewsFlash", user, "News message added")
                logger.info(f"NewsFlash: Added by {user.nickname}: {message}")

        except Exception as e:
            logger.error(f"NewsFlash add error: {e}")
            self._service_reply("NewsFlash", user, "Failed to add message")

    async def _newsflash_delete(self, user, msg_id):
        """Delete a newsflash message"""
        try:
            async with aiosqlite.connect(CONFIG.get('database', 'path')) as db:
                await db.execute("DELETE FROM newsflash WHERE id = ?", (msg_id,))
                await db.commit()
                self._service_reply("NewsFlash", user, f"News message {msg_id} deleted")

        except Exception as e:
            logger.error(f"NewsFlash delete error: {e}")
            self._service_reply("NewsFlash", user, "Failed to delete message")

    async def _newsflash_push(self, user, message):
        """Push an immediate notice to all users (ADMIN only)"""
        source = f":NewsFlash!NewsFlash@{self.servername}"
        out = f"{source} NOTICE * :[NEWS] {message}"
        count = 0
        for recipient in self.users.values():
            if not recipient.is_virtual:
                recipient.send(out)
                count += 1
        self._service_reply("NewsFlash", user, f"News pushed to {count} user(s)")
        logger.info(f"NewsFlash: Push by {user.nickname}: {message}")

    async def handle_kill(self, staff, params):
        if not (staff.has_mode('o') or staff.has_mode('a')):
            staff.send(self.get_reply("481", staff))
            return
        if not params:
            staff.send(self.get_reply("461", staff, command="KILL"))
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
            staff.send(self.get_reply("401", staff, target=target_nick))
            return
        target.send(f":{CONFIG.get('system', 'nick')} KILL {target_nick} :{reason}")
        staff.send(f":{target_nick} KILLED")
        await self.log_staff(staff.nickname, "KILL", target_nick, reason)
        await self.quit_user(target)

    async def _kill_channel(self, staff, channel_name, reason):
        """Kill a channel - kick all users and destroy it"""
        channel, chan_name = self.get_channel(channel_name)
        if not channel:
            staff.send(self.get_reply("403", staff, target=channel_name))
            return
        if chan_name.lower() == "#system":
            staff.send(f":{self.servername} NOTICE {staff.nickname} :Cannot kill #System channel")
            return
        kill_count = 0
        for nick in list(channel.members.keys()):
            member = channel.members[nick]
            if not member.is_virtual:
                kick_msg = f":{CONFIG.get('system', 'nick')} KICK {chan_name} {nick} :{reason}"
                channel.broadcast(kick_msg)
                member.channels.discard(chan_name)
                kill_count += 1
        del self.channels[chan_name]
        staff.send(f":{self.servername} NOTICE {staff.nickname} :Channel {chan_name} destroyed ({kill_count} users removed)")
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
            user.send(f":{CONFIG.get('system', 'nick')} KILL {user.nickname} :{reason}")
            await self.quit_user(user)
            kill_count += 1

        staff.send(f":{self.servername} NOTICE {staff.nickname} :Pattern {pattern} matched {kill_count} user(s)")
        await self.log_staff(staff.nickname, "KILL", pattern, f"Pattern kill: {reason} ({kill_count} users)")

    async def handle_kick(self, user, params):
        if len(params) < 2:
            user.send(self.get_reply("461", user, command="KICK"))
            return
        target_nick = params[1]
        reason = params[2].lstrip(':') if len(params) > 2 else user.nickname
        channel, chan_name = self.get_channel(params[0])
        if not channel:
            user.send(self.get_reply("403", user, target=params[0]))
            return
        if not (user.nickname in channel.owners or user.nickname in channel.hosts or user.has_mode('a')):
            user.send(self.get_reply("482", user, target=chan_name))
            return
        if target_nick not in channel.members:
            user.send(self.get_reply("441", user, target=target_nick, channel=chan_name))
            return
        target = channel.members[target_nick]
        msg = f":{user.prefix()} KICK {chan_name} {target_nick} :{reason}"
        channel.broadcast(msg)
        # Log to transcript if +y mode is enabled (before removing member)
        self.log_transcript(channel, "KICK", user, message=reason, target=target)
        channel.members.pop(target_nick, None)
        channel.owners.discard(target_nick)
        channel.hosts.discard(target_nick)
        channel.voices.discard(target_nick)
        channel.gagged.discard(target_nick)
        target.channels.discard(chan_name)
        if user.has_mode('o') or user.has_mode('a'):
            await self.log_staff(user.nickname, "KICK", f"{target_nick} from {chan_name}", reason)

    async def handle_mode(self, user, params):
        if not params:
            return
        target = params[0]
        if target == user.nickname:
            if len(params) == 1:
                modes = user.get_mode_str()
                user.send(self.get_reply("221", user, modes=modes))
        elif is_channel(target):
            channel, chan_name = self.get_channel(target)
            if not channel:
                user.send(self.get_reply("403", user, target=target))
                return
            if len(params) == 1:
                modes = "".join([k for k, v in channel.modes.items() if v])
                mode_params = []
                if channel.modes.get('l') and channel.user_limit:
                    mode_params.append(str(channel.user_limit))
                # Only show key to channel hosts/owners or staff
                can_see_key = (user.nickname in channel.owners or
                              user.nickname in channel.hosts or
                              user.has_mode('o') or user.has_mode('a'))
                if channel.modes.get('k') and channel.key:
                    if can_see_key:
                        mode_params.append(channel.key)
                    else:
                        mode_params.append("*")  # Hide actual key
                param_str = " " + " ".join(mode_params) if mode_params else ""
                user.send(f":{self.servername} 324 {user.nickname} {chan_name} +{modes}{param_str}")
            else:
                mode_str = params[1]
                mode_params = params[2:] if len(params) > 2 else []

                # Ban list query: MODE #channel b (no +/- and no params)
                if mode_str == 'b' and not mode_params:
                    for ban_mask in channel.ban_list:
                        user.send(f":{self.servername} 367 {user.nickname} {chan_name} {ban_mask}")
                    user.send(f":{self.servername} 368 {user.nickname} {chan_name} :End of channel ban list")
                    return

                if not (user.nickname in channel.owners or user.nickname in channel.hosts or user.has_mode('a')):
                    user.send(self.get_reply("482", user, target=chan_name))
                    return
                await self.apply_channel_modes(user, channel, mode_str, mode_params)

    async def apply_channel_modes(self, user, channel, mode_str, mode_params):
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
                    channel.broadcast(msg)
            elif char == 'b':
                if param_idx < len(mode_params):
                    ban_mask = mode_params[param_idx]
                    param_idx += 1
                    if adding:
                        if ban_mask not in channel.ban_list:
                            channel.ban_list.append(ban_mask)
                    else:
                        if ban_mask in channel.ban_list:
                            channel.ban_list.remove(ban_mask)
                    sign = '+' if adding else '-'
                    msg = f":{user.prefix()} MODE {channel.name} {sign}b {ban_mask}"
                    channel.broadcast(msg)
                else:
                    for ban_mask in channel.ban_list:
                        user.send(f":{self.servername} 367 {user.nickname} {channel.name} {ban_mask}")
                    user.send(f":{self.servername} 368 {user.nickname} {channel.name} :End of channel ban list")
            elif char == 'k':
                if adding:
                    if param_idx < len(mode_params):
                        new_key = mode_params[param_idx]
                        param_idx += 1
                        channel.key = new_key
                        channel.modes['k'] = True
                        channel.props['MEMBERKEY'] = new_key
                        msg = f":{user.prefix()} MODE {channel.name} +k {new_key}"
                        channel.broadcast(msg)
                        # Sync to clones if this is the original
                        if channel.is_clone_enabled() and channel.clone_children:
                            self.sync_mode_to_clones(channel, 'k', True, new_key)
                    else:
                        user.send(f":{self.servername} 696 {user.nickname} {channel.name} k :You must specify a parameter for the k mode")
                else:
                    channel.key = None
                    channel.modes['k'] = False
                    channel.props.pop('MEMBERKEY', None)
                    msg = f":{user.prefix()} MODE {channel.name} -k *"
                    channel.broadcast(msg)
                    # Sync to clones if this is the original
                    if channel.is_clone_enabled() and channel.clone_children:
                        self.sync_mode_to_clones(channel, 'k', False)
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
                                channel.broadcast(msg)
                                # Sync to clones if this is the original
                                if channel.is_clone_enabled() and channel.clone_children:
                                    self.sync_mode_to_clones(channel, 'l', True, limit)
                        except ValueError:
                            param_idx += 1
                    else:
                        user.send(f":{self.servername} 696 {user.nickname} {channel.name} l :You must specify a parameter for the l mode")
                else:
                    channel.user_limit = None
                    channel.modes['l'] = False
                    msg = f":{user.prefix()} MODE {channel.name} -l"
                    channel.broadcast(msg)
                    # Sync to clones if this is the original
                    if channel.is_clone_enabled() and channel.clone_children:
                        self.sync_mode_to_clones(channel, 'l', False)
            elif char in channel.modes:
                channel.modes[char] = adding
                sign = '+' if adding else '-'
                msg = f":{user.prefix()} MODE {channel.name} {sign}{char}"
                channel.broadcast(msg)
                # Sync to clones if this is the original (skip +d and +e)
                if char not in ('d', 'e') and channel.is_clone_enabled() and channel.clone_children:
                    self.sync_mode_to_clones(channel, char, adding)

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
            user.send(self.get_reply("461", user, command="GAG" if is_gag else "UNGAG"))
            return

        # Determine if this is a channel gag or global gag
        if params[0].startswith('#') or params[0].startswith('&'):
            # Channel gag: GAG #channel nick
            if len(params) < 2:
                user.send(self.get_reply("461", user, command="GAG" if is_gag else "UNGAG"))
                return
            channel_name, target_nick = params[0], params[1]
            channel, chan_name = self.get_channel(channel_name)
            if not channel:
                user.send(self.get_reply("403", user, target=channel_name))
                return
            # Require channel host/owner or staff
            if not (user.nickname in channel.owners or user.nickname in channel.hosts or
                    user.has_mode('o') or user.has_mode('a')):
                user.send(self.get_reply("482", user, target=chan_name))
                return
            if target_nick not in channel.members:
                user.send(self.get_reply("441", user, target=target_nick, channel=chan_name))
                return
            if is_gag:
                channel.gagged.add(target_nick)
                user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been gagged in {chan_name}")
            else:
                channel.gagged.discard(target_nick)
                user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been ungagged in {chan_name}")
        else:
            # Global gag: GAG nick
            target_nick = params[0]
            # Require staff for global gag
            if not (user.has_mode('o') or user.has_mode('a') or user.has_mode('g')):
                user.send(self.get_reply("481", user))
                return
            target_user = self.users.get(target_nick)
            if not target_user:
                user.send(self.get_reply("401", user, target=target_nick))
                return
            if is_gag:
                target_user.set_mode('z', True)
                user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been globally gagged (+z)")
            else:
                target_user.set_mode('z', False)
                user.send(f":{self.servername} NOTICE {user.nickname} :{target_nick} has been globally ungagged (-z)")

    async def quit_user(self, user):
        nick = user.nickname

        # Notify watchers that this user has gone offline
        if user.registered:
            self.notify_watchers_offline(user)

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
                    msg = f":{user.prefix()} QUIT :Client exited"
                    c.broadcast(msg, exclude=user)
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
        if nick in self.users and self.users[nick] == user:
            del self.users[nick]
        if user.writer and not user.is_virtual:
            try:
                user.writer.close()
                await user.writer.wait_closed()
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

        # Add status dump task for admin interface
        status_dump_task = asyncio.create_task(self._status_dump_loop())
        server_tasks.append(status_dump_task)

        # Wait for shutdown signal or server error
        shutdown_task = asyncio.create_task(self.shutdown_event.wait())

        try:
            done, pending = await asyncio.wait(
                server_tasks + [shutdown_task],
                return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel pending tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

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
        status_file = Path('pyircx_status.json')

        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(dump_interval)

                if self.server:
                    # Collect runtime statistics
                    status_data = {
                        'timestamp': time.time(),
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
                            channel_data = {
                                'name': chan_name,
                                'topic': channel.topic,
                                'member_count': len(real_members),
                                'members': real_members[:50],  # Limit to first 50 for brevity
                                'registered': channel.registered,
                                'modes': ''.join(k for k, v in channel.modes.items() if v),
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
        """Graceful shutdown."""
        logger.info("Initiating graceful shutdown...")

        # Shutdown link manager if active
        if self.link_manager:
            try:
                await self.link_manager.shutdown()
                logger.info("Link manager shutdown complete")
            except Exception as e:
                logger.error(f"Error shutting down link manager: {e}")

        # Save state before shutdown
        if self.server:
            try:
                await self.server.save_channels()
                logger.info("Channel state saved")
            except Exception as e:
                logger.error(f"Error saving state: {e}")

        # Close all TCP servers (plain + SSL)
        all_servers = self.tcp_servers + self.ssl_servers
        for srv in all_servers:
            srv.close()

        # Wait for servers to close
        for srv in all_servers:
            try:
                await asyncio.wait_for(srv.wait_closed(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for server to close")

        # Disconnect all clients gracefully
        if self.server:
            for user in list(self.server.users.values()):
                if not user.is_virtual:
                    try:
                        user.send(f":{self.server.servername} NOTICE * :Server shutting down")
                        if user.writer:
                            user.writer.close()
                    except Exception:
                        pass

        logger.info("Shutdown complete")

    def handle_signal(self, sig):
        """Handle Unix signals."""
        if sig == signal.SIGTERM or sig == signal.SIGINT:
            logger.info(f"Received signal {sig.name}, initiating shutdown...")
            self.shutdown_event.set()
        elif sig == signal.SIGHUP:
            logger.info("Received SIGHUP, reloading configuration...")
            self.reload_config()

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
        version='pyIRCX 1.0.0'
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
