#!/usr/bin/env python3
"""Install, upgrade, and repair must deploy every module the WebChat gateway imports."""

import re
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
WEBCHAT_DIR = PROJECT_ROOT / "webchat"


def gateway_local_modules():
    """Modules gateway.py imports from its own directory (e.g. validators)."""
    text = (WEBCHAT_DIR / "gateway.py").read_text(encoding="utf-8")
    names = set(re.findall(r"^\s*(?:from|import)\s+(\w+)", text, re.MULTILINE))
    return sorted(name for name in names if (WEBCHAT_DIR / f"{name}.py").exists())


def test_gateway_imports_validators():
    assert "validators" in gateway_local_modules()


@pytest.mark.parametrize("script", ["install.sh", "upgrade.sh"])
def test_scripts_install_gateway_modules(script):
    text = (PROJECT_ROOT / script).read_text(encoding="utf-8")
    for module in gateway_local_modules():
        copy = f'cp "$SCRIPT_DIR/webchat/{module}.py" "$INSTALL_DIR/webchat/"'
        assert copy in text, f"{script} does not install webchat/{module}.py"


def test_repair_checks_gateway_modules():
    text = (PROJECT_ROOT / "repair.sh").read_text(encoding="utf-8")
    for module in gateway_local_modules():
        assert f'"$INSTALL_DIR/webchat/{module}.py"' in text, f"repair.sh does not check webchat/{module}.py"
