#!/usr/bin/env python3
"""
SSL/TLS Manager for pyIRCX Server

This module manages SSL/TLS certificates for secure connections:
- Load certificates from files (compatible with Let's Encrypt)
- Monitor certificate files for changes
- Hot-reload certificates without server restart
- Track certificate expiry and warn when approaching
"""

import logging
import os
import ssl
import time

from responses import get_log_message

# Will be set by pyircx.py after CONFIG is initialized
CONFIG = None

logger = logging.getLogger('pyIRCX')


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
        if not CONFIG or not CONFIG.get('ssl', 'enabled', default=False):
            return None

        self.cert_file = CONFIG.get('ssl', 'cert_file', default=None)
        self.key_file = CONFIG.get('ssl', 'key_file', default=None)

        if not self.cert_file or not self.key_file:
            logger.error(get_log_message("ssl_missing_config"))
            return None

        if not os.path.exists(self.cert_file):
            logger.error(get_log_message("ssl_cert_not_found", file=self.cert_file))
            return None

        if not os.path.exists(self.key_file):
            logger.error(get_log_message("ssl_key_not_found", file=self.key_file))
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
            logger.info(get_log_message("ssl_loaded"))
            logger.info(get_log_message("ssl_cert_file", file=self.cert_file))
            logger.info(get_log_message("ssl_key_file", file=self.key_file))
            logger.info(get_log_message("ssl_min_tls", version=min_version_str))
            if self.cert_expiry:
                days_left = (self.cert_expiry - time.time()) / 86400
                logger.info(get_log_message("ssl_expiry", expiry=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.cert_expiry)), days=f"{days_left:.0f}"))
            if self.cert_subject:
                logger.info(get_log_message("ssl_subject", subject=self.cert_subject))

            return context

        except ssl.SSLError as e:
            logger.error(get_log_message("ssl_load_error", error=e))
            return None
        except Exception as e:
            logger.error(get_log_message("ssl_load_generic_error", error=e))
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
            logger.debug(get_log_message("ssl_parse_error", error=e))

    def check_for_reload(self):
        """
        Check if certificate files have changed and reload if needed.

        Returns:
            bool: True if certificates were reloaded
        """
        if not self.cert_file or not self.key_file:
            return False

        if not CONFIG or not CONFIG.get('ssl', 'auto_reload', default=True):
            return False

        try:
            cert_mtime = os.path.getmtime(self.cert_file)
            key_mtime = os.path.getmtime(self.key_file)

            if cert_mtime != self.cert_mtime or key_mtime != self.key_mtime:
                logger.info(get_log_message("ssl_files_changed"))
                old_context = self.ssl_context
                new_context = self.load_certificates()
                if new_context:
                    logger.info(get_log_message("ssl_reloaded"))
                    self.warned_days.clear()  # Reset expiry warnings
                    return True
                else:
                    logger.error(get_log_message("ssl_reload_failed"))
                    self.ssl_context = old_context
                    return False
        except Exception as e:
            logger.debug(get_log_message("ssl_check_error", error=e))

        return False

    def check_expiry_warnings(self):
        """Check certificate expiry and log warnings if approaching."""
        if not self.cert_expiry:
            return

        warn_days = CONFIG.get('ssl', 'expiry_warn_days', default=[14, 7, 3, 1]) if CONFIG else [14, 7, 3, 1]
        days_left = (self.cert_expiry - time.time()) / 86400

        for days in warn_days:
            if days_left <= days and days not in self.warned_days:
                self.warned_days.add(days)
                if days_left <= 0:
                    logger.error(get_log_message("ssl_expired"))
                elif days_left <= 1:
                    logger.warning(get_log_message("ssl_expires_soon"))
                else:
                    logger.warning(get_log_message("ssl_expires_warning", days=f"{days_left:.0f}"))
                break

    def force_reload(self):
        """Force reload of certificates (called on SIGHUP)."""
        logger.info(get_log_message("ssl_force_reload"))
        self.cert_mtime = 0
        self.key_mtime = 0
        return self.check_for_reload()

    def get_info(self):
        """Get SSL status information for STATS command."""
        if not CONFIG or not CONFIG.get('ssl', 'enabled', default=False):
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
