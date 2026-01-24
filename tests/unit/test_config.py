#!/usr/bin/env python3
"""
Unit tests for config.py ServerConfig class

Tests load, get, set, save, get_section, and get_all_sections methods.
"""

import pytest
import sys
import os
import json
import tempfile

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


@pytest.fixture
def valid_config_file(tmp_path):
    """Create a valid config JSON file"""
    config_data = {
        "server": {
            "name": "test.server.local",
            "network": "TestNet",
            "motd": ["Welcome to test server"]
        },
        "network": {
            "listen_ports": [6667]
        },
        "limits": {
            "max_nick_length": 30,
            "max_users": 1000
        },
        "servicebot": {
            "enabled": True,
            "profanity_filter": {
                "enabled": True,
                "words": ["badword"]
            }
        }
    }
    config_path = str(tmp_path / "test_config.json")
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=2)
    return config_path


@pytest.fixture
def invalid_json_file(tmp_path):
    """Create an invalid JSON file"""
    config_path = str(tmp_path / "bad_config.json")
    with open(config_path, 'w') as f:
        f.write("{invalid json content here!!!")
    return config_path


@pytest.fixture
def server_config(valid_config_file):
    """Create a ServerConfig instance with valid config"""
    from config import ServerConfig
    return ServerConfig(valid_config_file)


# =============================================================================
# LOAD TESTS
# =============================================================================

@pytest.mark.unit
class TestConfigLoad:
    """Test ServerConfig.load()"""

    def test_load_from_valid_json_file(self, valid_config_file):
        """Test load from valid JSON file"""
        from config import ServerConfig
        config = ServerConfig(valid_config_file)
        assert config.data is not None
        assert "server" in config.data

    def test_load_raises_file_not_found(self, tmp_path):
        """Test load raises FileNotFoundError for missing file"""
        from config import ServerConfig
        with pytest.raises(FileNotFoundError):
            ServerConfig(str(tmp_path / "nonexistent.json"))

    def test_load_raises_on_invalid_json(self, invalid_json_file):
        """Test load raises on invalid JSON"""
        from config import ServerConfig
        with pytest.raises(Exception):
            ServerConfig(invalid_json_file)


# =============================================================================
# GET TESTS
# =============================================================================

@pytest.mark.unit
class TestConfigGet:
    """Test ServerConfig.get()"""

    def test_get_single_key(self, server_config):
        """Test get() single key"""
        result = server_config.get("server")
        assert isinstance(result, dict)
        assert result["name"] == "test.server.local"

    def test_get_nested_path(self, server_config):
        """Test get() nested path"""
        result = server_config.get("server", "name")
        assert result == "test.server.local"

    def test_get_deep_nested_path(self, server_config):
        """Test get() deeply nested path"""
        result = server_config.get("servicebot", "profanity_filter", "enabled")
        assert result is True

    def test_get_with_default_for_missing_key(self, server_config):
        """Test get() with default for missing key"""
        result = server_config.get("nonexistent", default="fallback")
        assert result == "fallback"

    def test_get_with_default_for_missing_nested(self, server_config):
        """Test get() with default for missing nested key"""
        result = server_config.get("server", "nonexistent_key", default=42)
        assert result == 42

    def test_get_returns_none_when_no_default(self, server_config):
        """Test get() returns None when no default specified"""
        result = server_config.get("missing_key")
        assert result is None


# =============================================================================
# SET TESTS
# =============================================================================

@pytest.mark.unit
class TestConfigSet:
    """Test ServerConfig.set()"""

    def test_set_single_key(self, server_config):
        """Test set() single key"""
        result = server_config.set("new_key", value="new_value")
        assert result is True
        assert server_config.get("new_key") == "new_value"

    def test_set_nested_path(self, server_config):
        """Test set() nested path creates intermediate dicts"""
        result = server_config.set("new_section", "nested_key", value="nested_value")
        assert result is True
        assert server_config.get("new_section", "nested_key") == "nested_value"

    def test_set_overwrites_existing(self, server_config):
        """Test set() overwrites existing values"""
        server_config.set("server", "name", value="new.server.name")
        assert server_config.get("server", "name") == "new.server.name"

    def test_set_with_empty_path_returns_false(self, server_config):
        """Test set() with empty path returns False"""
        result = server_config.set(value="something")
        assert result is False


# =============================================================================
# SAVE TESTS
# =============================================================================

@pytest.mark.unit
class TestConfigSave:
    """Test ServerConfig.save()"""

    def test_save_writes_valid_json(self, server_config, valid_config_file):
        """Test save() writes valid JSON"""
        server_config.set("test_key", value="test_value")
        server_config.save()

        # Read back and verify
        with open(valid_config_file, 'r') as f:
            saved_data = json.load(f)
        assert saved_data["test_key"] == "test_value"
        # Original data should still be present
        assert saved_data["server"]["name"] == "test.server.local"


# =============================================================================
# SECTION TESTS
# =============================================================================

@pytest.mark.unit
class TestConfigSections:
    """Test get_section() and get_all_sections()"""

    def test_get_section_returns_section_dict(self, server_config):
        """Test get_section() returns section dict"""
        section = server_config.get_section("server")
        assert isinstance(section, dict)
        assert "name" in section

    def test_get_section_missing_returns_empty(self, server_config):
        """Test get_section() for missing section returns empty dict"""
        section = server_config.get_section("nonexistent")
        assert section == {}

    def test_get_all_sections_returns_section_names(self, server_config):
        """Test get_all_sections() returns section names"""
        sections = server_config.get_all_sections()
        assert isinstance(sections, list)
        assert "server" in sections
        assert "network" in sections
        assert "limits" in sections
        assert "servicebot" in sections


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
