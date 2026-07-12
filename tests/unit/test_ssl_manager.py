from unittest.mock import MagicMock, patch

import ssl_manager
from ssl_manager import SSLManager


class FakeConfig:
    def get(self, section, key, default=None):
        values = {
            ("ssl", "enabled"): True,
            ("ssl", "cert_file"): "/etc/letsencrypt/live/example/fullchain.pem",
            ("ssl", "key_file"): "/etc/letsencrypt/live/example/privkey.pem",
            ("ssl", "auto_reload"): True,
            ("ssl", "min_version"): "TLSv1.2",
        }
        return values.get((section, key), default)


def test_ssl_reload_updates_existing_context_in_place():
    manager = SSLManager()
    manager.cert_file = "/etc/letsencrypt/live/example/fullchain.pem"
    manager.key_file = "/etc/letsencrypt/live/example/privkey.pem"
    manager.cert_mtime = 1
    manager.key_mtime = 1

    live_context = MagicMock(name="live_context")
    validation_context = MagicMock(name="validation_context")
    manager.ssl_context = live_context

    with patch.object(ssl_manager, "CONFIG", FakeConfig()), \
            patch("ssl_manager.os.path.getmtime", return_value=2), \
            patch("ssl_manager.ssl.SSLContext", return_value=validation_context), \
            patch.object(manager, "_parse_certificate"):
        assert manager.check_for_reload() is True

    assert manager.ssl_context is live_context
    validation_context.load_cert_chain.assert_called_once_with(manager.cert_file, manager.key_file)
    live_context.load_cert_chain.assert_called_once_with(manager.cert_file, manager.key_file)
    assert manager.cert_mtime == 2
    assert manager.key_mtime == 2
