#!/usr/bin/env python3
"""Tests for shared version metadata."""

import json
from pathlib import Path

from version import (
    VERSION,
    VERSION_LABEL,
    CREATED,
    LINKING_PROTOCOL_VERSION,
    MIN_COMPATIBLE_VERSION,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_version_module_matches_version_json():
    data = json.loads((PROJECT_ROOT / "version.json").read_text(encoding="utf-8"))

    assert VERSION == data["version"]
    assert VERSION_LABEL == data["label"]
    assert CREATED == data["created"]
    assert LINKING_PROTOCOL_VERSION == data["linking_protocol_version"]
    assert MIN_COMPATIBLE_VERSION == data["min_compatible_version"]


def test_runtime_and_tooling_reference_shared_version_metadata():
    pyircx_text = (PROJECT_ROOT / "pyircx.py").read_text(encoding="utf-8")
    linking_text = (PROJECT_ROOT / "linking.py").read_text(encoding="utf-8")
    bump_script = (PROJECT_ROOT / "utils" / "bump_version.sh").read_text(encoding="utf-8")
    version_check = (PROJECT_ROOT / "utils" / "version_check.sh").read_text(encoding="utf-8")
    upgrade_script = (PROJECT_ROOT / "upgrade.sh").read_text(encoding="utf-8")

    assert 'from version import VERSION as __version__' in pyircx_text
    assert 'from version import VERSION as PYIRCX_VERSION' in linking_text
    assert 'version.json' in bump_script
    assert 'version.json' in version_check
    assert 'version.json' in upgrade_script
    assert 'version.py' in upgrade_script


def test_upgrade_script_fails_loudly_and_preserves_runtime_config_state():
    upgrade_script = (PROJECT_ROOT / "upgrade.sh").read_text(encoding="utf-8")
    service_unit = (PROJECT_ROOT / "pyircx.service").read_text(encoding="utf-8")
    install_script = (PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")
    repair_script = (PROJECT_ROOT / "repair.sh").read_text(encoding="utf-8")

    assert 'print_service_diagnostics() {' in upgrade_script
    assert 'require_service_active() {' in upgrade_script
    assert 'runtime_pyircx_config.json' in upgrade_script
    assert 'ln -sfn "$CONFIG_DIR/pyircx_config.json" "$INSTALL_DIR/pyircx_config.json"' in upgrade_script
    assert 'chown root:"$SERVICE_GROUP" "$CONFIG_DIR/pyircx_config.json"' in upgrade_script
    assert 'chown root:"$SERVICE_GROUP" "$CONFIG_DIR/pyircx_config.json"' in install_script
    assert 'chown root:"$SERVICE_GROUP" "$CONFIG_DIR/pyircx_config.json"' in repair_script
    assert '--config /etc/pyircx/pyircx_config.json' in service_unit
    assert 'systemctl reset-failed pyircx' in upgrade_script
    assert 'systemctl reset-failed pyircx-webchat' in upgrade_script
    assert 'cp "$SCRIPT_DIR/version.json" /var/www/html/webchat/' in upgrade_script
    assert 'cp "$SCRIPT_DIR/version.json" "$WEBCHAT_WEB_DIR/"' in install_script


def test_management_scripts_detect_web_user_instead_of_hardcoding_apache():
    install_script = (PROJECT_ROOT / "install.sh").read_text(encoding="utf-8")
    upgrade_script = (PROJECT_ROOT / "upgrade.sh").read_text(encoding="utf-8")
    repair_script = (PROJECT_ROOT / "repair.sh").read_text(encoding="utf-8")

    for script in (install_script, upgrade_script, repair_script):
        assert "detect_web_user() {" in script

    assert 'chown -R "$WEB_USER:$WEB_USER" "$WEB_ADMIN_DIR"' in install_script
    assert 'usermod -a -G systemd-journal "$WEB_USER"' in install_script
    assert 'chown -R "$WEB_USER:$WEB_USER" "$WEB_ADMIN_DIR"' in repair_script
    assert 'usermod -a -G systemd-journal "$WEB_USER"' in repair_script
    assert 'usermod -a -G systemd-journal "$WEB_USER"' in upgrade_script


def test_active_docs_do_not_hardcode_current_release_number():
    active_docs = [
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "docs" / "INDEX.md",
        PROJECT_ROOT / "docs" / "api" / "API_REFERENCE.md",
        PROJECT_ROOT / "docs" / "user" / "MANUAL.md",
        PROJECT_ROOT / "docs" / "admin" / "WEBADMIN_API.md",
        PROJECT_ROOT / "docs" / "admin" / "CONFIG_REFERENCE.md",
    ]

    for path in active_docs:
        text = path.read_text(encoding="utf-8")
        assert "**Version:** 2.0.0" not in text
        assert "**Version:** 1.2.0" not in text


def test_timestamp_refresh_script_exists_and_targets_version_json():
    script = (PROJECT_ROOT / "utils" / "touch_version_timestamp.sh").read_text(encoding="utf-8")
    assert 'version.json' in script
    assert 'data["created"]' in script
