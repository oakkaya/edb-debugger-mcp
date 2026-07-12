
from mcp.server.fastmcp import FastMCP

from edb_debugger_mcp.gdb_backend import GDBBackend, GDBBackendError  # noqa: F401

mcp = FastMCP("edb_debugger_mcp")
backend = GDBBackend.get_instance()
