#!/usr/bin/env python3
"""
Security classes for pyIRCX Server

This module contains security-related classes including:
- ConnectionThrottle: Rate limiting for new connections
- FailedAuthTracker: Tracks and locks out failed authentication attempts
- DNSBLChecker: Checks IPs against DNS blacklists
- ProxyDetector: Detects common proxy ports
- ConnectionScorer: Assigns risk scores to connections
"""

import asyncio
import logging
import re
import socket
import time
from collections import defaultdict, deque

from responses import get_log_message

# Will be set by pyircx.py after CONFIG is initialized
CONFIG = None

logger = logging.getLogger('pyIRCX')

# Compiled regex patterns for generic hostname detection
_GENERIC_HOST_PATTERNS = [
    re.compile(r'\d+[-\.]\d+[-\.]\d+[-\.]\d+'),  # IP in hostname
    re.compile(r'^(dsl|cable|dial|dynamic|dhcp|pool|client|user|host|node)'),
    re.compile(r'\.(dsl|cable|dynamic|dhcp)\.'),
    re.compile(r'(comcast|verizon|charter|cox|att|centurylink|frontier).*\d'),
]


class ConnectionThrottle:
    """Rate limiting for new connections per IP."""

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
            logger.warning(get_log_message("auth_lockout_ip", ip=ip, duration=self.lockout_duration))

        # Track by username if provided
        if username:
            self._cleanup_username(username, now)
            self.username_failures[username].append(now)
            if len(self.username_failures[username]) >= self.max_attempts:
                self.username_lockouts[username] = now + self.lockout_duration
                self.username_failures[username].clear()
                logger.warning(get_log_message("auth_lockout_user", username=username, duration=self.lockout_duration))

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
        self.cache_ttl = CONFIG.get('security', 'dnsbl', 'cache_ttl', default=3600) if CONFIG else 3600

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
        whitelist = CONFIG.get('security', 'dnsbl', 'whitelist', default=[]) if CONFIG else []

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
        if not CONFIG or not CONFIG.get('security', 'dnsbl', 'enabled', default=False):
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
            query = f"{reversed_ip}.{dnsbl}"

            try:
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(
                    loop.getaddrinfo(query, None, family=socket.AF_INET),
                    timeout=timeout
                )
                if result:
                    rcode = result[0][4][0]
                    # 127.255.255.x = DNSBL operator error/policy response, not a real hit
                    # (Spamhaus returns 127.255.255.254 for public-resolver queries)
                    if rcode.startswith('127.') and not rcode.startswith('127.255.255.'):
                        listed_on.append(dnsbl)
                        logger.info(get_log_message("dnsbl_listed", ip=ip, dnsbl=dnsbl))
            except (socket.gaierror, asyncio.TimeoutError, OSError):
                # Not listed or timeout - this is normal
                pass
            except Exception as e:
                logger.debug(get_log_message("dnsbl_check_error", dnsbl=dnsbl, error=e))

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

        action = CONFIG.get('security', 'dnsbl', 'action', default='reject') if CONFIG else 'reject'
        reject_msg = CONFIG.get('security', 'dnsbl', 'reject_message',
                                default='Connection refused (DNSBL)') if CONFIG else 'Connection refused (DNSBL)'

        logger.warning(get_log_message("dnsbl_action", ip=ip, dnsbls=', '.join(listed_on), action=action))

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
        if not CONFIG or not CONFIG.get('security', 'proxy_detection', 'enabled', default=False):
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
                logger.info(get_log_message("proxy_detected", ip=ip, port=port))
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
        if not CONFIG or not CONFIG.get('security', 'connection_scoring', 'enabled', default=False):
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
        threshold = CONFIG.get('security', 'connection_scoring', 'threshold', default=100) if CONFIG else 100
        return score >= threshold
