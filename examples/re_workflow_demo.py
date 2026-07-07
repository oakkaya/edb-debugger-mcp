#!/usr/bin/env python3
"""
Complete Reverse Engineering Workflow Demo using EDB Debugger MCP.
Communicates via MCP JSON-RPC protocol over stdio (newline-delimited JSON).

Steps:
  1. Compile test binary (ret2win buffer overflow)
  2. Start MCP server as subprocess
  3. Initialize MCP protocol
  4. Load binary (edb_load_program)
  5. Disassemble (edb_disassemble) — win, vuln, main
  6. List functions & symbols (edb_lookup_symbol, edb_list_functions)
  7. Set breakpoint at vuln + run (edb_set_breakpoint, edb_run)
  8. Inspect registers while stopped (edb_dump_registers, edb_get_registers)
  9. Read stack, backtrace, memory map (edb_get_stack, edb_get_backtrace, edb_get_memory_map)
  10. Continue to win (edb_continue_to) — simulate exploitation
  11. ROP gadgets & pwntools shellcode (edb_find_rop_gadgets, pwntools)
  12. Memory patching (edb_write_memory_bytes, edb_nop_range)
  13. Clean up
"""

import json
import os
import subprocess
import sys
import time

BINARY_PATH = "/tmp/re_demo_bin"
SOURCE_PATH = "/tmp/re_demo.c"
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


def call_tool(proc, tool_name: str, arguments: dict = None,
              timeout: float = 30.0):
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


def step(msg):
    print(f"\n{'=' * 70}")
    print(f"  STEP: {msg}")
    print(f"{'=' * 70}")


def show(resp):
    if resp is None:
        print("  [no response]")
        return
    for c in resp.get("result", {}).get("content", []):
        text = c.get("text", "")
        if text:
            for line in text.split("\n"):
                print(f"  {line}")


# ═══════════════════════════════════════════════════════════════════════
# Step 1 — compile test binary
# ═══════════════════════════════════════════════════════════════════════

step("1/13  Compile test binary (ret2win buffer overflow)")

with open(SOURCE_PATH, "w") as f:
    f.write(r"""
#include <stdio.h>
#include <string.h>

void win(void) {
    printf("You win!\n");
}

void vuln(char *input) {
    char buf[64];
    strcpy(buf, input);
}

int main(void) {
    vuln("AAAA");
    return 0;
}
""")

ret = os.system(
    f"gcc -fno-stack-protector -no-pie -o {BINARY_PATH} {SOURCE_PATH} 2>&1"
)
if ret != 0:
    print("ERROR: compilation failed"); sys.exit(1)

os.system(f"file {BINARY_PATH}")
print(f"  Compiled: {BINARY_PATH}")

# ═══════════════════════════════════════════════════════════════════════
# Step 2 — start MCP server
# ═══════════════════════════════════════════════════════════════════════

step("2/13  Start EDB Debugger MCP server")

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
    print(f"Server died:\n{err}"); sys.exit(1)

print(f"  MCP server PID {server.pid}")

# ═══════════════════════════════════════════════════════════════════════
# Step 3 — initialize MCP protocol
# ═══════════════════════════════════════════════════════════════════════

step("3/13  Initialize MCP protocol")

send_msg(server.stdin, json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "re-demo", "version": "1.0"},
    },
}))
resp = read_msg(server.stdout, timeout=10.0)
if resp is None:
    print("ERROR: no initialize response"); server.kill(); sys.exit(1)

si = resp.get("result", {}).get("serverInfo", {})
print(f"  Server: {si.get('name')} v{si.get('version')}")

send_msg(server.stdin, json.dumps({
    "jsonrpc": "2.0", "method": "notifications/initialized",
}))
time.sleep(0.3)
print("  Connection established")

# ═══════════════════════════════════════════════════════════════════════
# Step 4 — load binary
# ═══════════════════════════════════════════════════════════════════════

step("4/13  Load binary (edb_load_program)")

show(call_tool(server, "edb_load_program", {"path": BINARY_PATH}))

# ═══════════════════════════════════════════════════════════════════════
# Step 5 — disassemble key functions
# ═══════════════════════════════════════════════════════════════════════

step("5/13  Disassemble win, vuln, main")

for func in ("win", "vuln", "main"):
    print(f"\n  -> {func}:")
    show(call_tool(server, "edb_disassemble",
                   {"location": func, "count": 15}))

# ═══════════════════════════════════════════════════════════════════════
# Step 6 — symbol lookup
# ═══════════════════════════════════════════════════════════════════════

step("6/13  Symbol lookup (edb_lookup_symbol)")

for sym in ("main", "win", "vuln", "printf", "puts"):
    print(f"\n  -> {sym}:")
    show(call_tool(server, "edb_lookup_symbol", {"name": sym}))

# ═══════════════════════════════════════════════════════════════════════
# Step 7 — breakpoint at vuln + run
# ═══════════════════════════════════════════════════════════════════════

step("7/13  Set breakpoint at vuln + run")

show(call_tool(server, "edb_set_breakpoint", {"location": "vuln"}))
show(call_tool(server, "edb_list_breakpoints"))
show(call_tool(server, "edb_run"))

# ═══════════════════════════════════════════════════════════════════════
# Step 8 — inspect registers (stopped at breakpoint)
# ═══════════════════════════════════════════════════════════════════════

step("8/13  Inspect CPU registers (stopped at vuln)")

show(call_tool(server, "edb_dump_registers"))

resp = call_tool(server, "edb_get_registers")
if resp:
    for c in resp.get("result", {}).get("content", []):
        try:
            regs = json.loads(c.get("text", "{}"))
            print("\n  Key registers:")
            for r in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                      "rbp", "rsp", "rip"):
                print(f"    {r:>4s} = {regs.get(r, '?'):>20s}")
        except json.JSONDecodeError:
            pass

# ═══════════════════════════════════════════════════════════════════════
# Step 9 — stack + backtrace + memory map
# ═══════════════════════════════════════════════════════════════════════

step("9/13  Read stack, backtrace, memory map")

print("\n  -> Stack (edb_get_stack):")
show(call_tool(server, "edb_get_stack"))

print("\n  -> Backtrace (edb_get_backtrace):")
show(call_tool(server, "edb_get_backtrace"))

print("\n  -> Memory map (edb_get_memory_map):")
resp = call_tool(server, "edb_get_memory_map")
if resp:
    for c in resp.get("result", {}).get("content", []):
        for line in c.get("text", "").split("\n")[:15]:
            if line.strip():
                print(f"    {line}")

# ═══════════════════════════════════════════════════════════════════════
# Step 10 — continue to win (simulate exploitation)
# ═══════════════════════════════════════════════════════════════════════

step("10/13  Continue to win function (simulate exploitation)")

print("\n  -> Continuing execution to reach win:")
show(call_tool(server, "edb_continue_to", {"address": "win"}))

print("\n  -> Current instruction at win:")
show(call_tool(server, "edb_get_current_instruction"))

print("\n  -> Registers after reaching win:")
show(call_tool(server, "edb_dump_registers"))

# ═══════════════════════════════════════════════════════════════════════
# Step 11 — ROP gadgets
# ═══════════════════════════════════════════════════════════════════════

step("11/13  ROP gadgets + pwntools shellcode")

print("\n  -> ROP gadgets (edb_find_rop_gadgets; depth=2, count=15):")
show(call_tool(server, "edb_find_rop_gadgets",
               {"address": "", "depth": 2, "count": 15}))

print("\n  -> Shellcode via pwntools:")
import pwn
pwn.context.log_level = "error"
pwn.context.arch = "amd64"
pwn.context.os = "linux"
sc = pwn.asm(pwn.shellcraft.amd64.linux.sh())
print(f"    execve('/bin/sh') shellcode: {len(sc)} bytes")
print(f"    Hex: {sc.hex()}")

# ═══════════════════════════════════════════════════════════════════════
# Step 12 — memory patching demo
# ═══════════════════════════════════════════════════════════════════════

step("12/13  Memory patching demo")

print("\n  -> Read current instruction at RIP:")
show(call_tool(server, "edb_get_current_instruction"))

print("\n  -> Write NOP bytes (memory patch):")
show(call_tool(server, "edb_write_memory_bytes",
               {"address": "$rip", "hex_bytes": "90 90 90 90"}))

print("\n  -> Verify patch:")
show(call_tool(server, "edb_disassemble",
               {"location": "$pc", "count": 4}))

# ═══════════════════════════════════════════════════════════════════════
# Step 13 — clean up
# ═══════════════════════════════════════════════════════════════════════

step("13/13  Clean up — kill process, detach, stop server")

call_tool(server, "edb_kill_process")
call_tool(server, "edb_detach_process")

server.terminate()
try:
    server.wait(timeout=3)
except subprocess.TimeoutExpired:
    server.kill()
    server.wait()

for f in (SOURCE_PATH, BINARY_PATH):
    try:
        os.unlink(f)
    except FileNotFoundError:
        pass

print("\n  Server stopped, temp files removed")
print("\n" + "=" * 70)
print("  RE WORKFLOW DEMO COMPLETE")
print("=" * 70)
