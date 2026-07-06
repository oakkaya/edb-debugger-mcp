"""Binary Ninja UI actions for EDB debugger integration."""

from binaryninja import (
    BinaryView, PluginCommand, Interaction, get_choice_input,
    get_text_line_input, function_at,
)
from .mcp_client import MCPClient


_client: MCPClient = None


def set_client(c: MCPClient):
    global _client
    _client = c


def _get_client() -> MCPClient:
    if _client is None:
        raise RuntimeError("MCP client not initialized. Start the bridge first.")
    return _client


# ── Breakpoints ──────────────────────────────────────

def toggle_breakpoint(bv: BinaryView, addr: int):
    c = _get_client()
    result = c.call_tool("edb_set_breakpoint", {"location": hex(addr)})
    if result["isError"]:
        Interaction.show_message_box("EDB Error", result["result"])
    else:
        bv.set_comment_at(addr, f"BP")
        bv.mark_dirty()


def toggle_hardware_breakpoint(bv: BinaryView, addr: int):
    c = _get_client()
    result = c.call_tool("edb_set_hardware_breakpoint", {"location": hex(addr)})
    if result["isError"]:
        Interaction.show_message_box("EDB Error", result["result"])


def clear_all_breakpoints(bv: BinaryView):
    c = _get_client()
    bps = c.call_tool("edb_list_breakpoints", {})
    if bps["isError"]:
        Interaction.show_message_box("EDB Error", bps["result"])
        return
    count = 0
    for line in bps["result"].split("\n"):
        parts = line.strip().split()
        if parts and parts[0].isdigit():
            c.call_tool("edb_remove_breakpoint", {"number": int(parts[0])})
            count += 1
    Interaction.show_message_box("EDB", f"Cleared {count} breakpoints")


# ── Patching ─────────────────────────────────────────

def nop_at(bv: BinaryView, addr: int):
    c = _get_client()
    result = c.call_tool("edb_nop_range", {
        "start_address": hex(addr),
        "end_address": hex(addr + 1),
    })
    if result["isError"]:
        Interaction.show_message_box("EDB Error", result["result"])


def nop_range(bv: BinaryView, addr: int):
    end_str = get_text_line_input("End address (exclusive):", "NOP Range")
    if not end_str:
        return
    try:
        end = int(end_str, 0)
    except ValueError:
        Interaction.show_message_box("Error", "Invalid address")
        return
    c = _get_client()
    result = c.call_tool("edb_nop_range", {
        "start_address": hex(addr),
        "end_address": hex(end),
    })
    if result["isError"]:
        Interaction.show_message_box("EDB Error", result["result"])


def assemble_at(bv: BinaryView, addr: int):
    code = get_text_line_input("Assembly instruction:", "Assemble")
    if not code:
        return
    c = _get_client()
    result = c.call_tool("edb_assemble", {
        "address": hex(addr),
        "instruction": code,
    })
    if result["isError"]:
        Interaction.show_message_box("EDB Error", result["result"])


# ── Step / Run ───────────────────────────────────────

def step_into(_bv: BinaryView):
    c = _get_client()
    c.call_tool("edb_step_into", {})


def step_over(_bv: BinaryView):
    c = _get_client()
    c.call_tool("edb_step_over", {})


def step_out(_bv: BinaryView):
    c = _get_client()
    c.call_tool("edb_step_out", {})


def run_continue(_bv: BinaryView):
    c = _get_client()
    c.call_tool("edb_run", {})


def pause(_bv: BinaryView):
    c = _get_client()
    c.call_tool("edb_pause", {})


# ── Register inspection ──────────────────────────────

def show_registers(_bv: BinaryView):
    c = _get_client()
    result = c.call_tool("edb_get_registers", {})
    if result["isError"]:
        Interaction.show_message_box("EDB Error", result["result"])
        return
    Interaction.show_message_box("EDB Registers", result["result"])


# ── Register all UI actions ──────────────────────────

def register_all():
    PluginCommand.register_for_address(
        "EDB: Toggle Breakpoint",
        "Set or toggle a software breakpoint at the selected address",
        toggle_breakpoint,
    )
    PluginCommand.register_for_address(
        "EDB: Toggle Hardware Breakpoint",
        "Set a hardware breakpoint at the selected address",
        toggle_hardware_breakpoint,
    )
    PluginCommand.register_for_address(
        "EDB: NOP 1 byte",
        "Replace the instruction at the cursor with NOP (0x90)",
        nop_at,
    )
    PluginCommand.register_for_address(
        "EDB: NOP Range...",
        "Replace a range of addresses with NOP instructions",
        nop_range,
    )
    PluginCommand.register_for_address(
        "EDB: Assemble at Address...",
        "Assemble and write an instruction at the selected address",
        assemble_at,
    )
    PluginCommand.register(
        "EDB: Clear All Breakpoints",
        "Remove all breakpoints set in the debugger",
        clear_all_breakpoints,
    )
    PluginCommand.register(
        "EDB: Step Into",
        "Execute one source-level step into",
        step_into,
    )
    PluginCommand.register(
        "EDB: Step Over",
        "Execute one source-level step over",
        step_over,
    )
    PluginCommand.register(
        "EDB: Step Out",
        "Execute until the current function returns",
        step_out,
    )
    PluginCommand.register(
        "EDB: Run / Continue",
        "Start or continue execution",
        run_continue,
    )
    PluginCommand.register(
        "EDB: Pause",
        "Interrupt the running process",
        pause,
    )
    PluginCommand.register(
        "EDB: Show Registers",
        "Display current CPU register values",
        show_registers,
    )
