#!/usr/bin/env python3
"""Landing page links: releases for downloads, rendered GitHub pages for docs."""

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INDEX = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
HREFS = re.findall(r'href="([^"]+)"', INDEX)
LATEST_RELEASE = "https://github.com/AI3I/pyIRCX/releases/latest"


def test_no_relative_markdown_links():
    # Docs aren't deployed next to the page; link to GitHub's rendered view instead
    relative_md = [h for h in HREFS if h.endswith(".md") and not h.startswith("https://")]
    assert not relative_md, f"relative Markdown links: {relative_md}"


def test_downloads_point_at_latest_release():
    assert LATEST_RELEASE in HREFS
    assert "git clone" not in INDEX


def test_relative_links_are_deployed_site_assets():
    relative = [h for h in HREFS if not re.match(r"(https?:|#|mailto:|irc:)", h)]
    missing = [h for h in relative if not h.startswith("images/") and not (PROJECT_ROOT / h).exists()]
    assert not missing, f"relative links to files not in the site: {missing}"
