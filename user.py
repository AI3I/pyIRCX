#!/usr/bin/env python3
"""
User class and related utilities for pyIRCX Server

This module contains the User class representing an IRC client connection,
along with FloodProtection and RateLimiter utilities.
"""

import time
import logging
from collections import deque

# Will be set by pyircx.py after CONFIG is initialized
CONFIG = None

logger = logging.getLogger('pyIRCX')


# ==============================================================================
# FLOOD PROTECTION
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


# ==============================================================================
# RATE LIMITER
# ==============================================================================

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
        mode_chars = CONFIG.get('modes', 'user', default='agiorsxz') if CONFIG else 'agiorsxz'
        self.modes = {m: False for m in mode_chars}
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
        flood_messages = CONFIG.get('security', 'flood_messages', default=5) if CONFIG else 5
        flood_window = CONFIG.get('security', 'flood_window', default=2.0) if CONFIG else 2.0
        self.flood_protection = FloodProtection(
            max_messages=flood_messages,
            window=flood_window
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
        # Import here to avoid circular import
        from validation import mask_host
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
        max_len = CONFIG.get('limits', 'msg_length', default=512) if CONFIG else 512
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
