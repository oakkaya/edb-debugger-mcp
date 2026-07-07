#!/usr/bin/env python3
"""
Reverse Engineering Analysis of /bin/ls using EDB Debugger MCP.

Phases:
  1. Binary Reconnaissance
  2. Disassembly (capped)
  3. ROP Gadgets
  4. Static Analysis with pwntools
  5. Dynamic Analysis
  6. Cleanup
"""

import json
import os
import subprocess
import sys
import time

BINARY_PATH = "/bin/ls"
SERVER_SCRIPT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "edb_debugger_mcp.py"
))

_next_id = 0

def next_id():
    global _next_id
    _next_id += 1
    return _next_id

def send_msg(stdin, msg: str) -> None:
    stdin.write((msg + "\n").encode("utf-8"))
    stdin.flush()

def read_msg(stdout, timeout: float = 15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = b""
        while time.monotonic() < deadline:
            ch = stdout.read(1)
            if not ch:
                return None
            if ch == b"\n":
                break
            line += ch
        if not line:
            return None
        try:
            obj = json.loads(line.decode("utf-8", errors="replace"))
            if "id" not in obj and "method" in obj:
                continue
            return obj
        except json.JSONDecodeError:
            continue
    return None

def call_tool(proc, tool_name: str, arguments: dict = None, timeout: float = 30.0):
    mid = next_id()
    params = {"name": tool_name}
    if arguments is not None:
        params["arguments"] = {"params": arguments}
    msg = json.dumps({
        "jsonrpc": "2.0", "id": mid,
        "method": "tools/call", "params": params,
    })
    send_msg(proc.stdin, msg)
    return read_msg(proc.stdout, timeout)

def show(resp):
    if resp is None:
        return "  [no response / tool not available]"
    lines = []
    for c in resp.get("result", {}).get("content", []):
        text = c.get("text", "")
        if text:
            if isinstance(text, str):
                lines.append(text)
    return "\n".join(lines) if lines else "  [empty response]"

def header(num, title):
    return (
        f"\n{'#' * 72}\n"
        f"#  PHASE {num}: {title}\n"
        f"{'#' * 72}\n"
    )

def subhead(title):
    return f"\n{'─' * 50}\n  [{title}]\n{'─' * 50}"

def run():
    # ══════════════════════════════════════════════════════════════
    # Phase 0: Start MCP server
    # ══════════════════════════════════════════════════════════════
    print(header(0, "INIT — Start MCP Server & Initialize"))

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    server = subprocess.Popen(
        [sys.executable, SERVER_SCRIPT],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, bufsize=0,
    )
    time.sleep(1.5)

    if server.poll() is not None:
        err = server.stderr.read(2000).decode(errors="replace")
        print(f"ERROR: Server died:\n{err}")
        sys.exit(1)

    print(f"  MCP server PID: {server.pid}")

    # Initialize MCP
    send_msg(server.stdin, json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "re-analyze-ls", "version": "1.0"},
        },
    }))
    resp = read_msg(server.stdout, timeout=10.0)
    if resp is None:
        print("ERROR: no initialize response")
        server.kill()
        sys.exit(1)

    si = resp.get("result", {}).get("serverInfo", {})
    print(f"  Server: {si.get('name')} v{si.get('version')}")

    send_msg(server.stdin, json.dumps({
        "jsonrpc": "2.0", "method": "notifications/initialized",
    }))
    time.sleep(0.3)
    print("  Connection established")

    # ══════════════════════════════════════════════════════════════
    # Phase 1: Binary Reconnaissance
    # ══════════════════════════════════════════════════════════════
    print(header(1, "BINARY RECONNAISSANCE"))

    # 1a. Load /bin/ls
    print(subhead("Load /bin/ls"))
    resp = call_tool(server, "edb_load_program", {"path": BINARY_PATH})
    print(show(resp))

    # 1b. Binary info
    print(subhead("Binary Info (edb_get_binary_info)"))
    resp = call_tool(server, "edb_get_binary_info")
    print(show(resp))

    # 1c. Entry point
    print(subhead("Entry Point (edb_get_entry_point)"))
    resp = call_tool(server, "edb_get_entry_point")
    print(show(resp))

    # 1d. List functions (filter by common patterns)
    print(subhead("Functions containing 'main' (edb_list_functions)"))
    resp = call_tool(server, "edb_list_functions", {"filter_str": "main"})
    print(show(resp))

    print(subhead("Functions containing 'sort' (edb_list_functions)"))
    resp = call_tool(server, "edb_list_functions", {"filter_str": "sort"})
    print(show(resp))

    # 1e. Section info
    print(subhead("Section Info (edb_get_section_info)"))
    resp = call_tool(server, "edb_get_section_info", {"module": ""})
    print(show(resp))

    # 1f. Disable ASLR for predictable addresses (PIE binary)
    print(subhead("Disable ASLR for analysis"))
    resp = call_tool(server, "edb_disable_aslr", {"disable": True})
    print(show(resp))

    # 1g. List modules
    print(subhead("Loaded Modules (edb_list_modules)"))
    resp = call_tool(server, "edb_list_modules")
    print(show(resp))

    # 1g. Memory map (proxy for protected memory regions)
    print(subhead("Memory Map (edb_get_memory_map)"))
    resp = call_tool(server, "edb_get_memory_map")
    print(show(resp))

    # 1h. Lookup key symbols
    print(subhead("Symbol Lookups (edb_lookup_symbol)"))
    for sym in ("main", "_start", "strlen", "printf", "opendir", "readdir"):
        resp = call_tool(server, "edb_lookup_symbol", {"name": sym})
        text = show(resp)
        if text and "Error" not in text:
            print(f"  {sym}: {text}")

    # ══════════════════════════════════════════════════════════════
    # Phase 2: Disassembly (capped)
    # ══════════════════════════════════════════════════════════════
    print(header(2, "DISASSEMBLY (CAPPED)"))

    # 2a. Disassemble main
    print(subhead("main function (first 30 instructions)"))
    resp = call_tool(server, "edb_disassemble", {"location": "main", "count": 30})
    print(show(resp))

    # 2b. Disassemble _start
    print(subhead("_start function (first 20 instructions)"))
    resp = call_tool(server, "edb_disassemble", {"location": "_start", "count": 20})
    print(show(resp))

    # 2c. Find strings in the binary
    print(subhead("Find Strings (edb_find_strings)"))
    resp = call_tool(server, "edb_find_strings")
    print(show(resp))

    # 2d. Search for specific strings
    print(subhead("Searching for specific strings via edb_search_memory"))
    for pattern in ["Usage", "total", "."]:
        try:
            hexpat = pattern.encode().hex()
            spaced = " ".join(hexpat[i:i+2] for i in range(0, len(hexpat), 2))
            resp = call_tool(server, "edb_search_memory", {
                "pattern": spaced,
                "address": "",
                "length": "",
            })
            text = show(resp)
            if text and "Error" not in text:
                print(f"  '{pattern}' found: {text[:200]}")
        except Exception:
            pass

    # 2e. Analyze region around main
    print(subhead("Analyze Region at main (edb_analyze_region)"))
    resp = call_tool(server, "edb_analyze_region", {"address": "main", "size": 256})
    print(show(resp))

    # ══════════════════════════════════════════════════════════════
    # Phase 3: ROP Gadgets
    # ══════════════════════════════════════════════════════════════
    print(header(3, "ROP GADGETS"))

    print(subhead("EDB ROP Gadgets (depth=2, count=20)"))
    resp = call_tool(server, "edb_find_rop_gadgets", {
        "address": "",
        "depth": 2,
        "count": 20,
    })
    print(show(resp))

    print(subhead("EDB ROP Gadgets (depth=3, count=15)"))
    resp = call_tool(server, "edb_find_rop_gadgets", {
        "address": "",
        "depth": 3,
        "count": 15,
    })
    print(show(resp))

    print(subhead("pwntools ROP Analysis (pwntools_find_rop)"))
    resp = call_tool(server, "pwntools_find_rop", {
        "path": BINARY_PATH,
        "grep": "",
        "depth": 6,
        "count": 30,
    })
    print(show(resp))

    print(subhead("pwntools ROP — filter 'pop rdi'"))
    resp = call_tool(server, "pwntools_find_rop", {
        "path": BINARY_PATH,
        "grep": "pop rdi",
        "depth": 6,
        "count": 10,
    })
    print(show(resp))

    print(subhead("pwntools ROP — filter 'ret'"))
    resp = call_tool(server, "pwntools_find_rop", {
        "path": BINARY_PATH,
        "grep": "ret",
        "depth": 6,
        "count": 10,
    })
    print(show(resp))

    # ══════════════════════════════════════════════════════════════
    # Phase 4: Static Analysis with pwntools
    # ══════════════════════════════════════════════════════════════
    print(header(4, "STATIC ANALYSIS WITH PWNTOOLS"))

    print(subhead("pwntools ELF Analysis (pwntools_analyze_elf)"))
    resp = call_tool(server, "pwntools_analyze_elf", {"path": BINARY_PATH})
    print(show(resp))

    print(subhead("pwntools: pack/unpack demo on addresses"))
    resp = call_tool(server, "pwntools_pack", {
        "value": "0x400000",
        "size": 8,
        "endian": "little",
    })
    print(f"  p64(0x400000): {show(resp)}")

    resp = call_tool(server, "pwntools_pack", {
        "value": "0xdeadbeef",
        "size": 4,
        "endian": "little",
    })
    print(f"  p32(0xdeadbeef): {show(resp)}")

    resp = call_tool(server, "pwntools_unpack", {
        "hex_bytes": "ef be ad de",
        "size": 4,
        "endian": "little",
    })
    print(f"  u32('ef be ad de'): {show(resp)}")

    print(subhead("pwntools: disassemble ROP gadget bytes"))
    resp = call_tool(server, "pwntools_disasm", {
        "hex_data": "5f c3",
        "arch": "amd64",
    })
    print(f"  pop rdi; ret disasm: {show(resp)}")

    resp = call_tool(server, "pwntools_disasm", {
        "hex_data": "90 90 90 90 cc",
        "arch": "amd64",
    })
    print(f"  NOP sled + int3: {show(resp)}")

    # ══════════════════════════════════════════════════════════════
    # Phase 5: Dynamic Analysis
    # ══════════════════════════════════════════════════════════════
    print(header(5, "DYNAMIC ANALYSIS"))

    print(subhead("Set breakpoint at _start (entry point)"))
    resp = call_tool(server, "edb_set_breakpoint", {"location": "_start"})
    print(show(resp))

    print(subhead("Set breakpoint at strlen (PLT symbol)"))
    resp = call_tool(server, "edb_set_breakpoint", {"location": "strlen"})
    print(show(resp))

    print(subhead("List breakpoints"))
    resp = call_tool(server, "edb_list_breakpoints")
    print(show(resp))

    print(subhead("Run program (stops at _start)"))
    resp = call_tool(server, "edb_run", timeout=10.0)
    print(show(resp))

    print(subhead("Dump registers (stopped at _start)"))
    resp = call_tool(server, "edb_dump_registers")
    print(show(resp))

    print(subhead("Get registers JSON (edb_get_registers)"))
    resp = call_tool(server, "edb_get_registers")
    text = show(resp)
    print(text[:800] if len(text) > 800 else text)

    print(subhead("Current instruction"))
    resp = call_tool(server, "edb_get_current_instruction")
    print(show(resp))

    print(subhead("Stack dump"))
    resp = call_tool(server, "edb_get_stack")
    print(show(resp))

    print(subhead("Backtrace"))
    resp = call_tool(server, "edb_get_backtrace")
    print(show(resp))

    print(subhead("Memory map (while stopped at _start)"))
    resp = call_tool(server, "edb_get_memory_map")
    text = show(resp)
    for line in text.split("\n")[:25]:
        if line.strip():
            print(f"  {line}")

    print(subhead("Disassemble at current RIP"))
    resp = call_tool(server, "edb_disassemble", {"location": "$rip", "count": 15})
    print(show(resp))

    # ══════════════════════════════════════════════════════════════
    # Phase 6: Cleanup
    # ══════════════════════════════════════════════════════════════
    print(header(6, "CLEANUP"))

    print(subhead("Kill process"))
    resp = call_tool(server, "edb_kill_process")
    print(show(resp))

    print(subhead("Detach"))
    resp = call_tool(server, "edb_detach_process")
    print(show(resp))

    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait()

    print("\n  Server stopped")
    print(f"\n{'=' * 72}")
    print("  RE ANALYSIS COMPLETE — /bin/ls fully analyzed")
    print(f"{'=' * 72}")

if __name__ == "__main__":
    run()
