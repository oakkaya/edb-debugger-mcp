"""
Test Binary Ninja plugin's MCP client against the real edb_debugger_mcp server.
Verifies JSON-RPC protocol, Content-Length framing, tool calls, error handling.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Import MCPClient directly (avoid binaryninja import chain)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "binaryninja_mcp"))
import importlib.util
spec = importlib.util.spec_from_file_location(
    "mcp_client",
    os.path.join(os.path.dirname(__file__), "..", "binaryninja_mcp", "mcp_client.py"),
)
mcp_client_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp_client_mod)
MCPClient = mcp_client_mod.MCPClient

BIN = "/tmp/edb_vuln"
passed = 0; failed = 0

def ok(name): global passed; passed += 1; print(f"  \033[32m\u2713\033[0m {name}")
def fail(name, msg=""): global failed; failed += 1; print(f"  \033[31m\u2717\033[0m {name}: {msg[:120]}")

def main():
    client = MCPClient()

    # Test: start (spawns edb_debugger_mcp.py subprocess internally)
    r = client.start(python=sys.executable)
    connected = "Connected" in r and "unknown" not in r
    ok("start() -> connected") if connected else fail("start failed", r)
    print(f"     {r}")

    if not client.is_running:
        fail("is_running after start")
        return
    ok("is_running=True")

    try:
        # Test: list_tools
        tools = client.list_tools()
        count = len(tools)
        ok(f"list_tools() -> {count} tools") if count >= 147 else fail("count < 147", str(count))

        tool_names = [t["name"] for t in tools]
        for required in ["edb_load_program", "edb_set_breakpoint", "edb_run",
                         "edb_get_registers", "edb_disassemble",
                         "pwntools_analyze_elf", "pwntools_shellcraft"]:
            ok(f"has tool: {required}") if required in tool_names else fail(f"missing: {required}")

        # Test: call_tool (load binary)
        r = client.call_tool("edb_load_program", {"path": BIN})
        ok("edb_load_program -> ok") if not r["isError"] else fail("load failed", r["result"][:60])

        r = client.call_tool("edb_get_binary_info", {})
        ok("get_binary_info -> !isError") if not r["isError"] else fail("info failed")
        if "amd64" in r["result"]:
            ok("  arch=amd64 confirmed")

        r = client.call_tool("edb_set_breakpoint", {"location": "main"})
        ok("set breakpoint at main") if not r["isError"] else fail("bp failed")

        r = client.call_tool("edb_list_breakpoints", {})
        ok("list breakpoints") if not r["isError"] else fail("list bp failed")
        if "main" in r["result"]:
            ok("  breakpoint at main confirmed")

        # Test: tool with no params (client sends {})
        r = client.call_tool("edb_list_functions")
        ok("list_functions (no params dict)") if not r["isError"] else fail("list funcs failed")

        # Test: error handling for non-existent tool
        r = client.call_tool("nonexistent_tool", {})
        ok("nonexistent tool -> isError=True") if r.get("isError") else fail("no error for bad tool")
        if "ERROR" in r.get("result", ""):
            ok("  error message contains 'ERROR'")

        # Test: call_tool on a pwntools tool
        r = client.call_tool("pwntools_analyze_elf", {"path": BIN})
        ok("pwntools_analyze_elf") if not r["isError"] else fail("pwntools failed")

        # Test: stop + reconnect
        client.stop()
        ok("stop()") if not client.is_running else fail("still running")

        # Restart
        r = client.start(python=sys.executable)
        ok("reconnect after stop") if client.is_running else fail("reconnect failed")
        tools2 = client.list_tools()
        ok(f"re-listed {len(tools2)} tools") if len(tools2) >= 147 else fail("reconnect tools")

    finally:
        client.stop()

    total = passed + failed
    print(f"\n{'='*40}")
    print(f"  {passed}/{total} passed", end="")
    if failed: print(f"  \033[31m{failed} failed\033[0m")
    else: print("")
    print(f"{'='*40}")

if __name__ == "__main__":
    main()
