#!/usr/bin/env python3
"""EDB Debugger MCP — Split-Screen Demo (Option 2)"""
import sys
import os
import time
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import importlib
spec = importlib.util.spec_from_file_location("mcp_client",
    os.path.join(os.path.dirname(__file__), "..", "binaryninja_mcp", "mcp_client.py"))
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)
MCPClient = mcp.MCPClient
BIN = os.path.join(os.path.dirname(__file__), "demo_bin")
W = 68

def show(cmd, label, args=None):
    result = client.call_tool(cmd, args or {})
    text = result["result"].strip() or "(empty)"
    lines = text.split("\n")[:4]
    print(f"  TOOL: {cmd}")
    if args:
        print(f"  ARGS: {json.dumps(args)}")
    print(f"  ── {label} ──")
    for l in lines:
        print(f"  {l}")
    if len(text.split("\n")) > 4:
        print(f"  ... ({len(text.split(chr(10)))} lines)")
    print(f"  {'─'*W}")
    time.sleep(0.5)

client = MCPClient()
client.start()
print("\n" + "╔" + "═" * W + "╗")
print("║" + " EDB Debugger MCP — Tool → Result ".center(W) + "║")
print("╚" + "═" * W + "╝")
print()

show("edb_load_program", "Load binary", {"path": BIN, "args": "hello"})
show("edb_list_functions", "Functions", {"filter_str": "main"})
show("edb_disassemble", "Disassemble main", {"location": "main", "count": 8})
show("edb_set_breakpoint", "Set BP @ main", {"location": "main"})
show("edb_list_breakpoints", "List breakpoints")
show("edb_run", "Run to BP")
show("edb_get_registers", "Registers")
show("edb_read_memory", "Stack @ RSP", {"address": "$rsp", "count": 32})
show("edb_get_backtrace", "Backtrace")
show("edb_find_rop_gadgets", "ROP gadgets", {"depth": 2, "count": 5})
show("pwntools_shellcraft", "Shellcode", {"purpose": "sh", "arch": "amd64"})
show("pwntools_cyclic", "Cyclic 64b", {"count": 64})

print(f"  {'─'*W}")
print("  147 tools | pip install edb-debugger-mcp")
print()
client.stop()
