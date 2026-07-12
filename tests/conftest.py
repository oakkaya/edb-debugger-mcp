import sys
import os
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from edb_debugger_mcp.gdb_backend import GDBBackend


@pytest.fixture
def mi_parser():
    """Fixture that provides a backend instance for testing the MI parser."""
    return GDBBackend()
