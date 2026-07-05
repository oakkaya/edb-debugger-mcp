"""Binary Ninja sidebar widget for live register/stack/memory inspection."""

from typing import Optional

from binaryninja import (
    BinaryView, SidebarWidget, SidebarWidgetType, SidebarWidgetLocation,
    UIContext, UIActionHandler, log_info,
)

from .mcp_client import MCPClient


class DebuggerSidebarWidget(SidebarWidget):
    """Sidebar widget showing live register values, stack, and quick actions."""

    def __init__(self, name: str, bv: Optional[BinaryView], client: MCPClient):
        super().__init__(name, bv)
        self._client = client
        self._register_values: list[tuple[str, str]] = []

    def render(self):
        lines = [
            "=== EDB Debugger ===",
            "",
            "Registers:",
        ]
        for name, val in self._register_values:
            lines.append(f"  {name.upper():6s} = {val}")
        lines.append("")
        lines.append("[Right-click in disassembly]")
        lines.append("  EDB: Toggle Breakpoint")
        lines.append("  EDB: NOP 1 byte / Range")
        lines.append("  EDB: Assemble")
        lines.append("")
        lines.append("Actions → Plugins → EDB")
        self.setText("\n".join(lines))

    def refresh(self):
        try:
            regs_result = self._client.call_tool("edb_get_registers", {})
            if not regs_result["isError"]:
                self._register_values = self._parse_registers(regs_result["result"])
        except Exception:
            pass
        self.render()

    def _parse_registers(self, raw: str) -> list[tuple[str, str]]:
        import re
        pairs = []
        for line in raw.split("\n"):
            m = re.match(r"(\w+)\s*[:=]\s*(0x[0-9a-fA-F]+)", line)
            if m:
                pairs.append((m.group(1), m.group(2)))
        return pairs


class DebuggerSidebarWidgetType(SidebarWidgetType):
    """Widget type registration for the debugger sidebar."""

    def __init__(self, client: MCPClient):
        super().__init__("EDB Debugger", "EDB Debugger Panel")
        self._client = client

    def createWidget(self, frame, data):
        bv = data if isinstance(data, BinaryView) else None
        return DebuggerSidebarWidget(self.name, bv, self._client)


def register_sidebar(client: MCPClient) -> Optional[DebuggerSidebarWidgetType]:
    try:
        widget_type = DebuggerSidebarWidgetType(client)
        UIContext.registerSidebarWidgetType(widget_type)
        return widget_type
    except Exception as e:
        log_info(f"EDB sidebar registration failed (non-fatal): {e}")
        return None
