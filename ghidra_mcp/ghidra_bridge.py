"""Ghidra MCP bridge — pyhidra script for EDB debugger integration.

When loaded via pyhidra (File → Run Script), this script registers
actions in the Ghidra UI that communicate with edb_debugger_mcp
over MCP stdio protocol.

The bridge starts the MCP subprocess, connects to GDB via MI2,
and exposes debugger control as Ghidra menu/toolbar actions.
"""

import atexit
import os
import sys
from typing import Optional

# Ghidra is available at module scope when pyhidra has finished bootstrapping.
# pylint: disable=import-error,undefined-variable
try:
    from ghidra.app.context import ProgramActionContext
    from ghidra.app.plugin.core.osgi import GhidraBundle
    from docking import DockingWindowManager, ActionContext
    from docking.action import DockingAction, MenuData
    from ghidra.util import Msg
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.util import ProgramLocation
except ImportError:
    _GHIDRA_AVAILABLE = False
else:
    _GHIDRA_AVAILABLE = True

from mcp_client import MCPClient


_client: Optional[MCPClient] = None
_tool = None


# ── MCP lifecycle ─────────────────────────────────────

def start_bridge() -> str:
    """Start the MCP subprocess and connect to GDB."""
    global _client

    if _client and _client.is_running:
        return "Bridge already running"

    python_path = "python3"
    if sys.platform == "win32":
        python_path = "python"

    _client = MCPClient()
    try:
        result = _client.start(python=python_path)
    except Exception as e:
        _client = None
        return f"Failed: {e}"

    atexit.register(stop_bridge)

    tools = _client.list_tools()
    result += f"\n{len(tools)} tools available"

    # Log via Ghidra's logger if running inside Ghidra
    if _GHIDRA_AVAILABLE:
        Msg.info(_client, f"EDB bridge connected with {len(tools)} tools")
    return result


def stop_bridge():
    """Stop the MCP subprocess and disconnect."""
    global _client
    if _client:
        _client.stop()
        _client = None
    if _GHIDRA_AVAILABLE:
        Msg.info(None, "EDB bridge stopped")


def _get_client() -> MCPClient:
    if _client is None:
        raise RuntimeError("MCP client not initialized. Start the bridge first.")
    return _client


# ── Helper: read current address from UI state ────────

def _current_address():
    """Return the address at the cursor as an int."""
    if not _GHIDRA_AVAILABLE:
        return 0
    if _tool is None:
        return 0
    ctx = _tool.getActiveContext()
    if ctx is None:
        return 0
    loc = ctx.getLocation()
    if loc is None:
        return 0
    addr = loc.getAddress()
    if addr is None:
        return 0
    return addr.getOffset()


def _get_current_program():
    if not _GHIDRA_AVAILABLE or _tool is None:
        return None
    ctx = _tool.getActiveContext()
    if ctx is None:
        return None
    if hasattr(ctx, "getProgram"):
        return ctx.getProgram()
    return None


# ── Ghidra action wrappers ────────────────────────────

def toggle_breakpoint():
    addr = _current_address()
    if addr == 0:
        _show_msg("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_set_breakpoint", {"location": hex(addr)})
    if result["isError"]:
        _show_msg(f"EDB Error: {result['result']}")
    else:
        _show_msg(f"Breakpoint toggled at {hex(addr)}")


def clear_all_breakpoints():
    c = _get_client()
    bps = c.call_tool("edb_list_breakpoints", {})
    if bps["isError"]:
        _show_msg(f"EDB Error: {bps['result']}")
        return
    count = 0
    for line in bps["result"].split("\n"):
        parts = line.strip().split()
        if parts and parts[0].isdigit():
            c.call_tool("edb_remove_breakpoint", {"number": int(parts[0])})
            count += 1
    _show_msg(f"Cleared {count} breakpoints")


def nop_at():
    addr = _current_address()
    if addr == 0:
        _show_msg("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_nop_range", {
        "start_address": hex(addr),
        "end_address": hex(addr + 1),
    })
    if result["isError"]:
        _show_msg(f"EDB Error: {result['result']}")
    else:
        _show_msg(f"NOPed 1 byte at {hex(addr)}")


def assemble_at():
    if not _GHIDRA_AVAILABLE:
        return
    addr = _current_address()
    if addr == 0:
        _show_msg("No address selected")
        return
    # Prompt via Ghidra's input dialog
    from ghidra.util import Swing
    code = Swing.showInputDialog("Assemble", "Instruction:")
    if code is None:
        return
    c = _get_client()
    result = c.call_tool("edb_assemble", {
        "address": hex(addr),
        "instruction": code,
    })
    if result["isError"]:
        _show_msg(f"EDB Error: {result['result']}")
    else:
        _show_msg(f"Assembled '{code}' at {hex(addr)}")


def step_into():
    _get_client().call_tool("edb_step_into", {})


def step_over():
    _get_client().call_tool("edb_step_over", {})


def step_out():
    _get_client().call_tool("edb_step_out", {})


def run_continue():
    _get_client().call_tool("edb_run", {})


def pause():
    _get_client().call_tool("edb_pause", {})


def show_registers():
    c = _get_client()
    result = c.call_tool("edb_get_registers", {})
    if result["isError"]:
        _show_msg(f"EDB Error: {result['result']}")
        return
    _show_msg(f"Registers:\n{result['result']}")


def show_memory():
    if not _GHIDRA_AVAILABLE:
        return
    addr = _current_address()
    if addr == 0:
        _show_msg("No address selected")
        return
    from ghidra.util import Swing
    length_str = Swing.showInputDialog("Memory", "Length (bytes):", "256")
    if length_str is None:
        return
    try:
        length = int(length_str)
    except ValueError:
        _show_msg("Invalid length")
        return
    c = _get_client()
    result = c.call_tool("edb_read_memory", {
        "address": hex(addr),
        "length": length,
    })
    if result["isError"]:
        _show_msg(f"EDB Error: {result['result']}")
    else:
        _show_msg(f"Memory at {hex(addr)} ({length} bytes):\n{result['result']}")


# ── UI helpers ────────────────────────────────────────

def _show_msg(text: str, title: str = "EDB Debugger"):
    """Show a message dialog inside Ghidra (fallback to print)."""
    if _GHIDRA_AVAILABLE:
        try:
            from ghidra.util import Swing
            Swing.showMessageDialog(None, text, title, Swing.INFORMATION_MESSAGE)
        except Exception:
            Msg.info(None, f"{title}: {text}")
    else:
        print(f"[{title}] {text}")


# ── Action registration ───────────────────────────────

def _register_action(name: str, description: str, callback, menu_path: list[str],
                     key_binding: Optional[str] = None):
    """Register a DockingAction in the active Ghidra tool."""
    global _tool
    if not _GHIDRA_AVAILABLE:
        return

    action = DockingAction(name, "EDBDebuggerBridge")
    action.setDescription(description)
    action.setMenuBarData(MenuData(menu_path, key_binding))

    class _ActionListener:
        def actionPerformed(self, action_context):
            callback()

    action.addActionListener(_ActionListener())
    _tool.addAction(action)


def register_actions():
    """Register all EDB debugger actions as Ghidra menu items."""
    global _tool

    if not _GHIDRA_AVAILABLE:
        print("Ghidra API not available — running standalone mode")
        return

    _tool = DockingWindowManager.getActiveInstance().getTool()

    # Start/Stop at top level
    _register_action("Start Bridge", "Launch edb_debugger_mcp subprocess",
                      start_bridge, ["EDB", "Start Bridge"])
    _register_action("Stop Bridge", "Disconnect from debugger",
                      stop_bridge, ["EDB", "Stop Bridge"])

    # Breakpoints
    _register_action("Toggle Breakpoint", "Set/remove software breakpoint",
                      toggle_breakpoint, ["EDB", "Toggle Breakpoint"])
    _register_action("Clear All Breakpoints", "Remove all breakpoints",
                      clear_all_breakpoints, ["EDB", "Clear All Breakpoints"])

    # Patching
    _register_action("NOP at Address", "Replace 1 byte with 0x90",
                      nop_at, ["EDB", "NOP at Address"])
    _register_action("Assemble at Address...", "Write an assembled instruction",
                      assemble_at, ["EDB", "Assemble at Address..."])

    # Step / Run
    _register_action("Step Into", "Execute one instruction (step into)",
                      step_into, ["EDB", "Step Into"], "F11")
    _register_action("Step Over", "Execute one instruction (step over)",
                      step_over, ["EDB", "Step Over"], "F10")
    _register_action("Step Out", "Run until function returns",
                      step_out, ["EDB", "Step Out"], "Shift F11")
    _register_action("Run / Continue", "Start or continue execution",
                      run_continue, ["EDB", "Run / Continue"], "F5")
    _register_action("Pause", "Interrupt the running process",
                      pause, ["EDB", "Pause"])

    # Inspection
    _register_action("Show Registers", "Display CPU register values",
                      show_registers, ["EDB", "Show Registers"])
    _register_action("Show Memory at Address...", "Read and display memory",
                      show_memory, ["EDB", "Show Memory at Address..."])

    Msg.info(None, "EDB Debugger Bridge plugin loaded — %d actions registered" % 14)


# ── Entry point ───────────────────────────────────────

def main():
    """Called when this script is run via pyhidra (File → Run Script)."""
    register_actions()
    _show_msg("EDB Debugger Bridge loaded. Use EDB → Start Bridge to connect.")


if __name__ == "__main__":
    main()
