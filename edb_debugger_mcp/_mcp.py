import json

from mcp.server.fastmcp import FastMCP

from gdb_backend import GDBBackend, GDBBackendError
from edb_models import *

mcp = FastMCP("edb_debugger_mcp")
backend = GDBBackend.get_instance()
