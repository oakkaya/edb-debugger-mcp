"""EDB Debugger MCP - AI-powered GDB debugging via MCP protocol."""

from edb_debugger_mcp._mcp import mcp, backend, GDBBackendError as GDBBackendError
from edb_models import *  # noqa: F403 - re-export models for backwards compat

import edb_debugger_mcp.composite_tools  # noqa: F401 — 26 composite tools replacing 207 flat tools
import edb_debugger_mcp.prompts  # noqa: F401 — MCP prompt for model guidance


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
