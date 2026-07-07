"""x64dbg bridge plugin — connects x64dbg to edb_debugger_mcp via MCP stdio transport."""

import sys

from x64dbgpy.pluginsdk import menu, message
import x64dbg

from .mcp_client import MCPClient


MCP_CLIENT: MCPClient = None
MENU_PARENT = None
MENU_ITEMS = []


def _get_client() -> MCPClient:
    global MCP_CLIENT
    if MCP_CLIENT is None:
        message.showError("MCP client not initialized. Start the bridge first.")
        raise RuntimeError("MCP client not initialized")
    return MCP_CLIENT


def _get_current_addr() -> int:
    try:
        sel = x64dbg.getCurrentSelection()
        if sel:
            return sel[0]
    except Exception:
        pass
    return 0


# ── Bridge lifecycle ──────────────────────────────

def start_bridge():
    global MCP_CLIENT
    if MCP_CLIENT and MCP_CLIENT.is_running:
        message.showWarning("Bridge already running")
        return
    python_path = sys.executable or "python"
    MCP_CLIENT = MCPClient()
    try:
        result = MCP_CLIENT.start(python=python_path)
        message.showInfo(result)
    except Exception as e:
        message.showError(f"Failed to start bridge: {e}")
        MCP_CLIENT = None


def stop_bridge():
    global MCP_CLIENT
    if MCP_CLIENT:
        MCP_CLIENT.stop()
        MCP_CLIENT = None
        message.showInfo("Bridge stopped")


# ── Breakpoints ───────────────────────────────────

def toggle_breakpoint():
    addr = _get_current_addr()
    if not addr:
        message.showError("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_set_breakpoint", {"location": hex(addr)})
    if result["isError"]:
        message.showError(result["result"])


def clear_all_breakpoints():
    c = _get_client()
    bps = c.call_tool("edb_list_breakpoints", {})
    if bps["isError"]:
        message.showError(bps["result"])
        return
    count = 0
    for line in bps["result"].split("\n"):
        parts = line.strip().split()
        if parts and parts[0].isdigit():
            c.call_tool("edb_remove_breakpoint", {"number": int(parts[0])})
            count += 1
    message.showInfo(f"Cleared {count} breakpoints")


# ── Patching ──────────────────────────────────────

def nop_at_address():
    addr = _get_current_addr()
    if not addr:
        message.showError("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_nop_range", {
        "start_address": hex(addr),
        "end_address": hex(addr + 1),
    })
    if result["isError"]:
        message.showError(result["result"])


def assemble_at_address():
    addr = _get_current_addr()
    if not addr:
        message.showError("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_assemble", {
        "address": hex(addr),
        "instruction": "",
    })
    if result["isError"]:
        message.showError(result["result"])


# ── Step / Run / Pause ────────────────────────────

def step_into():
    c = _get_client()
    c.call_tool("edb_step_into", {})


def step_over():
    c = _get_client()
    c.call_tool("edb_step_over", {})


def run_continue():
    c = _get_client()
    c.call_tool("edb_run", {})


def pause():
    c = _get_client()
    c.call_tool("edb_pause", {})


# ── Inspection ────────────────────────────────────

def show_registers():
    c = _get_client()
    result = c.call_tool("edb_get_registers", {})
    if result["isError"]:
        message.showError(result["result"])
    else:
        message.showInfo(result["result"])


def show_memory_at_selection():
    addr = _get_current_addr()
    if not addr:
        message.showError("No address selected")
        return
    c = _get_client()
    result = c.call_tool("edb_read_memory", {
        "address": hex(addr),
        "size": 64,
    })
    if result["isError"]:
        message.showError(result["result"])
    else:
        message.showInfo(result["result"])


# ── Plugin entry point ────────────────────────────

def _create_menu():
    global MENU_PARENT, MENU_ITEMS
    MENU_PARENT = menu.createMenu(menu.MenuType.PLUGINS, "EDB Bridge")

    entries = [
        ("Start Bridge", start_bridge),
        ("Stop Bridge", stop_bridge),
        ("---", None),
        ("Toggle Breakpoint", toggle_breakpoint),
        ("Clear All Breakpoints", clear_all_breakpoints),
        ("---", None),
        ("NOP at Address", nop_at_address),
        ("Assemble at Address", assemble_at_address),
        ("---", None),
        ("Step Into", step_into),
        ("Step Over", step_over),
        ("Run / Continue", run_continue),
        ("Pause", pause),
        ("---", None),
        ("Show Registers", show_registers),
        ("Show Memory at Selection", show_memory_at_selection),
    ]

    for label, callback in entries:
        if label == "---":
            menu.addSeparator(MENU_PARENT)
        else:
            _add_menu_entry(MENU_PARENT, label, callback)


def _add_menu_entry(hparent, title, callback):
    hentry = menu.addMenuEntry(hparent, title, callback)
    MENU_ITEMS.append(hentry)
    return hentry


class PluginMain:
    def __init__(self):
        self._initialized = False

    def setup(self):
        if self._initialized:
            return
        _create_menu()
        self._initialized = True


PLUGIN = PluginMain()
PLUGIN.setup()
