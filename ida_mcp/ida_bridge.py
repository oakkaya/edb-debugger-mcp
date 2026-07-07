"""IDAPython bridge — EDB Debugger MCP integration plugin for IDA Pro.

Registers actions under Edit → EDB Debugger that communicate with
edb_debugger_mcp over MCP stdio protocol.
"""

import atexit
import os
import sys
from typing import Optional

try:
    import idaapi
    import idc
    import idautils
except ImportError:
    IDAPYTHON_AVAILABLE = False
else:
    IDAPYTHON_AVAILABLE = True

from .mcp_client import MCPClient


_client: Optional[MCPClient] = None


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

    idaapi.msg(f"[EDB] Bridge connected with {len(tools)} tools\n")
    return result


def stop_bridge():
    """Stop the MCP subprocess and disconnect."""
    global _client
    if _client:
        _client.stop()
        _client = None
    idaapi.msg("[EDB] Bridge stopped\n")


def _get_client() -> MCPClient:
    if _client is None:
        raise RuntimeError("MCP client not initialized. Start the bridge first.")
    return _client


# ── Helper: UI feedback ────────────────────────────────


def _show_msg(text: str):
    """Print to IDA output window and show as an informational dialog."""
    idaapi.msg(f"[EDB] {text}\n")
    idaapi.info(f"EDB Debugger: {text}")


def _show_error(text: str):
    """Print to IDA output window and show as a warning dialog."""
    idaapi.msg(f"[EDB ERROR] {text}\n")
    idaapi.warning(f"EDB Debugger Error:\n{text}")


# ── Action handler functions ───────────────────────────


def _action_toggle_breakpoint():
    addr = idaapi.get_screen_ea()
    if addr == idaapi.BADADDR:
        _show_error("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_set_breakpoint", {"location": hex(addr)})
    if result["isError"]:
        _show_error(result["result"])
    else:
        _show_msg(f"Breakpoint toggled at {hex(addr)}")


def _action_clear_all_breakpoints():
    c = _get_client()
    bps = c.call_tool("edb_list_breakpoints", {})
    if bps["isError"]:
        _show_error(bps["result"])
        return
    count = 0
    for line in bps["result"].split("\n"):
        parts = line.strip().split()
        if parts and parts[0].isdigit():
            c.call_tool("edb_remove_breakpoint", {"number": int(parts[0])})
            count += 1
    _show_msg(f"Cleared {count} breakpoints")


def _action_nop_at():
    addr = idaapi.get_screen_ea()
    if addr == idaapi.BADADDR:
        _show_error("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_nop_range", {
        "start_address": hex(addr),
        "end_address": hex(addr + 1),
    })
    if result["isError"]:
        _show_error(result["result"])
    else:
        _show_msg(f"NOPed 1 byte at {hex(addr)}")


def _action_assemble_at():
    addr = idaapi.get_screen_ea()
    if addr == idaapi.BADADDR:
        _show_error("No address selected")
        return
    code = idaapi.ask_str("", 0, "Assemble instruction at %s:" % hex(addr))
    if not code:
        return
    c = _get_client()
    result = c.call_tool("edb_assemble", {
        "address": hex(addr),
        "instruction": code,
    })
    if result["isError"]:
        _show_error(result["result"])
    else:
        _show_msg(f"Assembled '{code}' at {hex(addr)}")


def _action_step_into():
    try:
        _get_client().call_tool("edb_step_into", {})
    except Exception as e:
        _show_error(str(e))


def _action_step_over():
    try:
        _get_client().call_tool("edb_step_over", {})
    except Exception as e:
        _show_error(str(e))


def _action_step_out():
    try:
        _get_client().call_tool("edb_step_out", {})
    except Exception as e:
        _show_error(str(e))


def _action_run_continue():
    try:
        _get_client().call_tool("edb_run", {})
    except Exception as e:
        _show_error(str(e))


def _action_pause():
    try:
        _get_client().call_tool("edb_pause", {})
    except Exception as e:
        _show_error(str(e))


def _action_show_registers():
    c = _get_client()
    result = c.call_tool("edb_get_registers", {})
    if result["isError"]:
        _show_error(result["result"])
        return
    _show_msg(f"Registers:\n{result['result']}")


def _action_show_memory():
    addr = idaapi.get_screen_ea()
    if addr == idaapi.BADADDR:
        _show_error("No address selected")
        return
    length_str = idaapi.ask_str("256", 0, "Memory length (bytes) at %s:" % hex(addr))
    if not length_str:
        return
    try:
        length = int(length_str)
    except ValueError:
        _show_error("Invalid length")
        return
    c = _get_client()
    result = c.call_tool("edb_read_memory", {
        "address": hex(addr),
        "length": length,
    })
    if result["isError"]:
        _show_error(result["result"])
    else:
        _show_msg(f"Memory at {hex(addr)} ({length} bytes):\n{result['result']}")


# ── Action registration ───────────────────────────────


class _ActionHandler(idaapi.action_handler_t):
    """Generic action handler that delegates to a callable."""

    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def activate(self, ctx):
        self._callback()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


def _register_action(name: str, label: str, shortcut: str, tooltip: str, callback):
    if not IDAPYTHON_AVAILABLE:
        return
    action_desc = idaapi.action_desc_t(
        name,
        label,
        _ActionHandler(callback),
        shortcut,
        tooltip,
    )
    idaapi.register_action(action_desc)


def register_actions():
    """Register all EDB debugger actions in the Edit → EDB Debugger menu hierarchy."""
    if not IDAPYTHON_AVAILABLE:
        print("IDAPython not available — cannot register actions")
        return

    menu_parent = "Edit/EDB Debugger/"

    _register_action("edb:start_bridge", "Start Bridge", "", "Launch edb_debugger_mcp subprocess", start_bridge)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Start Bridge", "edb:start_bridge", idaapi.SETMENU_APP)

    _register_action("edb:stop_bridge", "Stop Bridge", "", "Disconnect from debugger", stop_bridge)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Stop Bridge", "edb:stop_bridge", idaapi.SETMENU_APP)

    # Breakpoints
    _register_action("edb:toggle_bp", "Toggle Breakpoint", "F2",
                     "Set or remove a software breakpoint at the current address",
                     _action_toggle_breakpoint)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Toggle Breakpoint", "edb:toggle_bp", idaapi.SETMENU_APP)

    _register_action("edb:clear_bps", "Clear All Breakpoints", "",
                     "Remove all breakpoints set in the debugger",
                     _action_clear_all_breakpoints)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Clear All Breakpoints", "edb:clear_bps", idaapi.SETMENU_APP)

    # Patching
    _register_action("edb:nop_at", "NOP at Current Address", "",
                     "Replace 1 byte at the cursor with 0x90",
                     _action_nop_at)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/NOP at Current Address", "edb:nop_at", idaapi.SETMENU_APP)

    _register_action("edb:assemble_at", "Assemble at Current Address...", "",
                     "Write an assembled instruction at the current address",
                     _action_assemble_at)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Assemble at Current Address", "edb:assemble_at", idaapi.SETMENU_APP)

    # Step / Run
    _register_action("edb:step_into", "Step Into", "F11",
                     "Execute one instruction (step into)",
                     _action_step_into)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Step Into", "edb:step_into", idaapi.SETMENU_APP)

    _register_action("edb:step_over", "Step Over", "F10",
                     "Execute one instruction (step over)",
                     _action_step_over)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Step Over", "edb:step_over", idaapi.SETMENU_APP)

    _register_action("edb:step_out", "Step Out", "Shift+F11",
                     "Run until the current function returns",
                     _action_step_out)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Step Out", "edb:step_out", idaapi.SETMENU_APP)

    _register_action("edb:run", "Run / Continue", "F5",
                     "Start or continue execution",
                     _action_run_continue)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Run / Continue", "edb:run", idaapi.SETMENU_APP)

    _register_action("edb:pause", "Pause", "",
                     "Interrupt the running process",
                     _action_pause)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Pause", "edb:pause", idaapi.SETMENU_APP)

    # Inspection
    _register_action("edb:show_regs", "Show Registers", "",
                     "Display current CPU register values",
                     _action_show_registers)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Show Registers", "edb:show_regs", idaapi.SETMENU_APP)

    _register_action("edb:show_memory", "Show Memory at Current Address...", "",
                     "Read and display memory at the current address",
                     _action_show_memory)
    idaapi.attach_action_to_menu(
        "Edit/EDB Debugger/Show Memory at Current Address", "edb:show_memory", idaapi.SETMENU_APP)

    idaapi.msg("[EDB] Debugger Bridge plugin loaded — 13 actions registered\n")
