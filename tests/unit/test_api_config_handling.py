#!/usr/bin/env python3
"""
Unit tests for API config persistence behavior.
"""

import json
from pathlib import Path


def test_load_config_returns_raw_dict_without_api_metadata(api_module):
    config = api_module.load_config()

    assert config["server"]["name"] == "Test"
    assert "success" not in config


def test_set_config_does_not_persist_success_flag(api_module):
    result = api_module.set_config('{"server": {"name": "Updated", "network": "TestNet"}}')

    assert result["success"] is True

    reloaded = api_module.load_config()
    assert reloaded["server"]["name"] == "Updated"
    assert "success" not in reloaded


def test_get_db_path_resolves_relative_to_config_file(api_module, tmp_path):
    config_dir = tmp_path / "nested"
    config_dir.mkdir()
    config_path = config_dir / "custom-config.json"
    db_rel = "data/custom.db"
    config_path.write_text(json.dumps({"database": {"path": db_rel}}), encoding="utf-8")

    api_module.DEFAULT_CONFIG = str(config_path)

    resolved = api_module.get_db_path()

    assert resolved == str((config_dir / db_rel).resolve())


def test_get_db_path_uses_system_install_for_relative_system_config(api_module, tmp_path):
    system_config = tmp_path / "etc" / "pyircx_config.json"
    system_config.parent.mkdir(parents=True)
    system_config.write_text(json.dumps({"database": {"path": "pyircx.db"}}), encoding="utf-8")

    api_module.SYSTEM_CONFIG = str(system_config)
    api_module.DEFAULT_CONFIG = str(system_config)
    api_module.SYSTEM_INSTALL = str(tmp_path / "opt" / "pyircx")

    resolved = api_module.get_db_path()

    assert resolved == str((tmp_path / "opt" / "pyircx" / "pyircx.db").resolve())
