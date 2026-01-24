#!/usr/bin/env python3
"""
ServiceBot Monitor for pyIRCX Server

This module monitors channel activity for profanity and malicious behavior.
Each ServiceBot in a channel uses this to check messages.
"""

import logging
import re
import time

from responses import SERVER_MESSAGES

# Will be set by pyircx.py after CONFIG is initialized
CONFIG = None

logger = logging.getLogger('pyIRCX')


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
        if not CONFIG:
            self._config_cache = {
                'profanity_enabled': True,
                'profanity_words': [],
                'profanity_patterns': [],
                'profanity_case_sensitive': False,
                'profanity_action': 'warn',
                'malicious_enabled': True,
                'flood_action': 'gag',
                'repeat_action': 'warn',
                'caps_action': 'warn',
                'url_spam_action': 'warn',
            }
            return

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
        if not CONFIG or not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
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
        if not CONFIG or not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
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
        if not CONFIG or not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
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
        if not CONFIG or not CONFIG.get('servicebot', 'malicious_detection', 'enabled', default=True):
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
            violations.append(('profanity', self._config_cache['profanity_action'], SERVER_MESSAGES['violation_profanity'].format(matched=matched)))

        # Check flood
        if self.check_flood(nickname, text):
            violations.append(('flood', self._config_cache['flood_action'], SERVER_MESSAGES['violation_flood']))

        # Check repeat spam
        if self.check_repeat(nickname, text):
            violations.append(('repeat', self._config_cache['repeat_action'], SERVER_MESSAGES['violation_repeat']))

        # Check excessive caps
        if self.check_caps(text):
            violations.append(('caps', self._config_cache['caps_action'], SERVER_MESSAGES['violation_caps']))

        # Check URL spam
        if self.check_url_spam(nickname, text):
            violations.append(('url_spam', self._config_cache['url_spam_action'], SERVER_MESSAGES['violation_url_spam']))

        return violations

    def clear_user(self, nickname):
        """Clear history for a user (e.g., when they leave)"""
        self.user_history.pop(nickname, None)
