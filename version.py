#!/usr/bin/env python3
"""Shared project version metadata."""

import json
from pathlib import Path


_VERSION_FILE = Path(__file__).with_name("version.json")

with _VERSION_FILE.open("r", encoding="utf-8") as f:
    _VERSION_DATA = json.load(f)

VERSION = _VERSION_DATA["version"]
VERSION_LABEL = _VERSION_DATA["label"]
CREATED = _VERSION_DATA["created"]
LINKING_PROTOCOL_VERSION = _VERSION_DATA["linking_protocol_version"]
MIN_COMPATIBLE_VERSION = _VERSION_DATA["min_compatible_version"]


def get_version_data():
    """Return a copy of the loaded version metadata."""
    return dict(_VERSION_DATA)
