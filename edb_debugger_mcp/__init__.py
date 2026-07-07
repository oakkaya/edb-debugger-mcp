"""EDB Debugger MCP - AI-powered GDB debugging via MCP protocol."""

from edb_debugger_mcp._mcp import mcp, backend, GDBBackendError
from edb_models import *  # noqa: F403 - re-export models for backwards compat

# Import tools module to register all tools on the mcp instance
import edb_debugger_mcp.tools  # noqa: F401

try:
    import pwntools_mcp  # noqa: F401
except ImportError:
    pass


def main():
    try:
        mcp.run()
    finally:
        import asyncio
        try:
            asyncio.run(backend.quit())
        except Exception:
            pass


import sys as _sys
_sys.modules.setdefault("edb_debugger_mcp", _sys.modules["__main__"])

if __name__ == "__main__":
    main()
