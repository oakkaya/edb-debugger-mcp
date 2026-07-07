#!/usr/bin/env python3
"""EDB Debugger MCP — Workflow Demo (Option 1)"""
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import importlib
spec = importlib.util.spec_from_file_location("mcp_client",
    os.path.join(os.path.dirname(__file__), "..", "binaryninja_mcp", "mcp_client.py"))
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)
MCPClient = mcp.MCPClient
BIN = os.path.join(os.path.dirname(__file__), "demo_bin")

def call(cmd, args=None):
    result = client.call_tool(cmd, args or {})
    text = result["result"].strip()
    lines = text.split("\n")
    for line in lines[:12]:
        print(f"  {line}")
    if len(lines) > 12:
        print(f"  ... ({len(lines)} lines total)")
    time.sleep(0.4)

client = MCPClient()
client.start()
print("\n  [EDB Debugger MCP — Workflow Demo]\n")

print("── 1. Load program ──")
call("edb_load_program", {"path": BIN, "args": "hello"})

print("── 2. List functions (filter: main) ──")
call("edb_list_functions", {"filter_str": "main"})

print("── 3. Disassemble main() ──")
call("edb_disassemble", {"location": "main", "count": 15})

print("── 4. Find ROP gadgets ──")
call("edb_find_rop_gadgets", {"depth": 2, "count": 5})

print("── 5. Set breakpoint @ main ──")
call("edb_set_breakpoint", {"location": "main"})

print("── 6. List breakpoints ──")
call("edb_list_breakpoints")

print("── 7. Run to breakpoint ──")
call("edb_run")

print("── 8. Inspect registers ──")
call("edb_get_registers")

print("── 9. Read stack (RSP, 64 bytes) ──")
call("edb_read_memory", {"address": "$rsp", "count": 64})

print("── 10. Backtrace ──")
call("edb_get_backtrace")

print("── 11. Generate cyclic pattern ──")
call("pwntools_cyclic", {"count": 64})

print("── 12. Shellcode: execve /bin/sh ──")
call("pwntools_shellcraft", {"purpose": "sh", "arch": "amd64"})

print(f"\n  {'='*40}\n  Complete — 147 tools available\n{'-'*40}\n")
client.stop()
