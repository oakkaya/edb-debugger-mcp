"""HLIL overlay renderer — annotates the disassembly with live register values."""

import re
from typing import Optional

from binaryninja import BinaryView, UIContext, log_info, log_error
from binaryninja.enums import SymbolType
from binaryninja.function import Function

from .mcp_client import MCPClient


class RegisterOverlay:
    """Periodically fetches register values and renders them as HLIL comments."""

    def __init__(self, client: MCPClient, bv: BinaryView):
        self._client = client
        self._bv = bv
        self._regs: dict[str, str] = {}
        self._current_pc: Optional[int] = None
        self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    def enable(self):
        self._enabled = True
        self.refresh()

    def disable(self):
        self._enabled = False
        self._clear_overlay()

    def refresh(self):
        """Fetch registers from debugger and update the overlay."""
        if not self._enabled:
            return
        try:
            regs_result = self._client.call_tool("edb_get_registers", {})
            if regs_result["isError"]:
                return
            self._parse_registers(regs_result["result"])
            self._render_overlay()
        except Exception as e:
            log_error(f"EDB overlay refresh failed: {e}")

    def _parse_registers(self, raw: str):
        self._regs = {}
        for line in raw.split("\n"):
            m = re.match(r"(\w+)\s*[:=]\s*(0x[0-9a-fA-F]+)", line)
            if m:
                self._regs[m.group(1).lower()] = m.group(2)
        pc_key = next((k for k in ("rip", "eip", "pc") if k in self._regs), None)
        if pc_key:
            self._current_pc = int(self._regs[pc_key], 16)

    def _render_overlay(self):
        if not self._regs:
            return
        reg_lines = []
        for name, val in sorted(self._regs.items()):
            reg_lines.append(f"  {name.upper():6s} = {val}")
        reg_text = "\n".join(reg_lines)

        for func in self._bv.functions:
            self._annotate_function(func, reg_text)

    def _annotate_function(self, func: Function, reg_text: str):
        func.set_auto_comment(
            func.start,
            f"[EDB Live Registers]\n{reg_text}",
        )

    def _clear_overlay(self):
        for func in self._bv.functions:
            func.set_auto_comment(func.start, "")


class CurrentAddressHighlighter:
    """Highlights the current instruction address in the disassembly view."""

    def __init__(self, client: MCPClient):
        self._client = client
        self._current_pc: Optional[int] = None

    def refresh(self):
        try:
            pc_result = self._client.call_tool("edb_get_current_instruction", {})
            if pc_result["isError"]:
                return
            raw = pc_result["result"]
            m = re.search(r"(0x[0-9a-fA-F]+)", raw)
            if m:
                self._current_pc = int(m.group(1), 16)
                self._scroll_to_pc()
        except Exception:
            pass

    def _scroll_to_pc(self):
        """Navigate the active view to the current PC."""
        if self._current_pc is None:
            return
        ctx = UIContext.activeContext()
        if ctx is None:
            return
        view_frame = ctx.getCurrentViewFrame()
        if view_frame is None:
            return
        view = view_frame.getCurrentView()
        if view is None:
            return
        view.navigate("Linear:", self._current_pc)
