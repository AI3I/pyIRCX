#!/usr/bin/env python3
"""
Server Configuration for pyIRCX Server

This module contains the ServerConfig class for loading and managing
server configuration from JSON files.
"""

import json
import logging
from pathlib import Path

from responses import get_log_message

logger = logging.getLogger('pyIRCX')


class ServerConfig:
    """Server configuration manager that loads settings from a JSON file."""

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
                logger.info(get_log_message("config_loaded", file=self.config_file))
            except Exception as e:
                logger.error(get_log_message("config_error", error=e))
                raise
        else:
            logger.error(get_log_message("config_not_found", file=self.config_file))
            raise FileNotFoundError(f"Configuration file '{self.config_file}' is required but not found. Please run the installation script or create the config file.")

    def save(self):
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info(get_log_message("config_saved"))
        except Exception as e:
            logger.error(get_log_message("config_save_error", error=e))

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
