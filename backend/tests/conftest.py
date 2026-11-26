"""
Shared test fixtures. Run with `pytest` from backend/ (venv activated).

These tests never touch the network or a real nmap binary - they mock the
boundary (requests.Session, nmap.PortScanner) and check our own logic:
file parsing, finding detection, and failure handling.
"""
import json
import os
import sys

import pytest

# Let tests import "modules.xxx" and "storage" the same way app.py does,
# regardless of which directory pytest is invoked from.
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


@pytest.fixture
def target_path(tmp_path):
    """A throwaway target folder, isolated from backend/targets/."""
    meta = {"name": "Test Target", "domain": "example.test"}
    with open(tmp_path / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f)
    return str(tmp_path)
