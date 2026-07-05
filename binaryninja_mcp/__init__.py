"""EDB Debugger Bridge — Binary Ninja plugin entry point.

Connects Binary Ninja to the edb_debugger_mcp GDB MI backend.
Provides:
  - Sidebar widget with live register values
  - HLIL overlay with register annotations
  - Right-click actions: breakpoint, NOP, assemble
  - Plugin menu: step, run, pause, registers
"""

import atexit
import os
import sys
from typing import Optional

from binaryninja import (
    BinaryView, PluginCommand, UIContext, log_info, log_error,
    execute_on_main_thread,
)

from .actions import register_all as register_actions, set_client as set_actions_client
from .mcp_client import MCPClient
from .sidebar_widget import register_sidebar
from .overlay_renderer import RegisterOverlay, CurrentAddressHighlighter


_client: Optional[MCPClient] = None
_sidebar_widget_type = None
_overlay: Optional[RegisterOverlay] = None
_highlighter: Optional[CurrentAddressHighlighter] = None


def start_bridge(bv: BinaryView) -> str:
    """Start the MCP bridge: launch the edb_debugger_mcp subprocess and connect."""
    global _client, _sidebar_widget_type, _overlay, _highlighter

    if _client and _client.is_running:
        return "Bridge already running"

    python_path = "python3"
    if sys.platform == "win32":
        python_path = "python"

    _client = MCPClient()
    try:
        result = _client.start(python=python_path)
    except Exception as e:
        log_error(f"EDB bridge failed to start: {e}")
        _client = None
        return f"Failed: {e}"

    set_actions_client(_client)

    atexit.register(stop_bridge)

    tools = _client.list_tools()
    log_info(f"EDB bridge connected with {len(tools)} tools")

    _sidebar_widget_type = register_sidebar(_client)
    _overlay = RegisterOverlay(_client, bv)
    _highlighter = CurrentAddressHighlighter(_client)

    result += f"\n{len(tools)} tools available"
    return result


def stop_bridge():
    """Stop the MCP bridge and clean up."""
    global _client, _sidebar_widget_type, _overlay, _highlighter
    if _overlay:
        _overlay.disable()
        _overlay = None
    _highlighter = None
    if _client:
        _client.stop()
        _client = None
    if _sidebar_widget_type:
        try:
            UIContext.unregisterSidebarWidgetType(_sidebar_widget_type)
        except Exception:
            pass
        _sidebar_widget_type = None


def toggle_overlay(bv: BinaryView):
    """Toggle the live register overlay on/off."""
    global _overlay
    if _overlay is None:
        return
    if _overlay.enabled:
        _overlay.disable()
    else:
        _overlay.enable()


def refresh_all(_bv: BinaryView):
    """Manually refresh register overlay and highlight."""
    global _overlay, _highlighter
    if _overlay:
        _overlay.refresh()
    if _highlighter:
        _highlighter.refresh()


# ── Plugin entry point ───────────────────────────────

def plugin_entry_point():
    """Called by Binary Ninja when the plugin is loaded."""

    PluginCommand.register(
        "EDB: Start Bridge",
        "Launch the edb_debugger_mcp subprocess and connect to GDB",
        lambda bv: execute_on_main_thread(lambda: start_bridge(bv)),
    )
    PluginCommand.register(
        "EDB: Stop Bridge",
        "Disconnect from the debugger and clean up",
        lambda _bv: stop_bridge(),
    )
    PluginCommand.register(
        "EDB: Toggle Register Overlay",
        "Show/hide live register values as HLIL comments",
        toggle_overlay,
    )
    PluginCommand.register(
        "EDB: Refresh",
        "Manually refresh register overlay and PC highlight",
        refresh_all,
    )

    register_actions()
    log_info("EDB Debugger Bridge plugin loaded")


plugin_entry_point()
