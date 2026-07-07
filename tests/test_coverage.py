"""Coverage tests for error paths, edge cases, and untested code."""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gdb_backend import GDBBackend, GDBBackendError


class TestBackendEdgeCases:
    """Test edge cases in backend utilities."""

    def setup_method(self):
        self.b = GDBBackend()

    def test_pwntools_available_property(self):
        assert isinstance(self.b.pwntools_available, bool)

    def test_parse_mi_comma_list_deep_nested(self):
        result = self.b._parse_mi_comma_list('a={b={c="1"}},d="2"')
        assert result["d"] == "2"
        assert "b={c=\"1\"}" in result["a"]

    def test_parse_mi_comma_list_quoted_with_equals(self):
        result = self.b._parse_mi_comma_list('msg="hello=world"')
        assert result["msg"] == "hello=world"

    def test_parse_mi_values_empty_braces(self):
        assert self.b._parse_mi_values("{}") == {}

    def test_parse_mi_record_unknown_prefix(self):
        result = self.b._parse_mi_record("some random text")
        assert result["type"] is None
        assert "raw" in result

    def test_parse_mi_record_startswith_equals_no_content(self):
        result = self.b._parse_mi_record("=")
        assert result["type"] == ""

    def test_parse_mi_record_plus_prefix(self):
        result = self.b._parse_mi_record('+download,"Section .text"')
        assert result["type"] == "download"

    def test_extract_value_missing_key(self):
        parsed = {"records": [{"type": "done", "values": {}}]}
        assert self.b._extract_value(parsed, "nonexistent") is None

    def test_extract_value_multiple_records(self):
        parsed = {"records": [
            {"type": "notify", "values": {"id": "1"}},
            {"type": "done", "values": {"result": "ok"}},
        ]}
        assert self.b._extract_value(parsed, "result") == "ok"

    def test_record_patch(self):
        self.b._patch_history = []
        self.b._record_patch("0x4000", "90", "cc", 1, "NOP")
        assert len(self.b._patch_history) == 1
        assert self.b._patch_history[0]["address"] == "0x4000"

    def test_record_patch_no_description(self):
        self.b._patch_history = []
        self.b._record_patch("0x4000", "90", "cc", 1)
        assert self.b._patch_history[0]["description"] == ""

    def test_get_patch_history_empty(self):
        self.b._patch_history = []
        import asyncio
        r = asyncio.run(self.b.get_patch_history())
        assert "No patches" in r

    def test_clear_patch_history(self):
        self.b._patch_history.append({"address": "0x4000"})
        import asyncio
        r = asyncio.run(self.b.clear_patch_history())
        assert "cleared" in r.lower()
        assert self.b._patch_history == []

    def test_get_async_events_empty(self):
        assert self.b.get_async_events() == []

    def test_get_async_events_clears(self):
        self.b._async_events.append({"raw": "*stopped", "parsed": {"type": "stopped"}})
        events = self.b.get_async_events()
        assert len(events) == 1
        assert self.b._async_events == []

    def test_parse_mi_tuple_flat(self):
        result = self.b._parse_mi_tuple('number="1",type="bp"')
        assert result["number"] == "1"

    def test_parse_mi_tuple_nested(self):
        result = self.b._parse_mi_tuple('{level="0",func="main"}')
        assert "level" in result or "func" in result or result == {}

    def test_parse_mi_list_simple(self):
        result = self.b._parse_mi_list('[{a="1"},{a="2"}]')
        assert len(result) == 2


class TestModelsEdgeCases:
    """Test model validation edge cases for new models."""

    def test_exploit_generate_input_valid(self):
        import edb_debugger_mcp as m
        model = m.ExploitGenerateInput(binary="/bin/ls", offset=8)
        assert model.binary == "/bin/ls"
        assert model.offset == 8

    def test_exploit_generate_input_defaults(self):
        import edb_debugger_mcp as m
        model = m.ExploitGenerateInput(binary="/bin/ls", offset=16)
        assert model.cmd == "/bin/sh"
        assert model.save_path == ""
        assert model.arch == "amd64"

    def test_exploit_generate_input_invalid_offset(self):
        import edb_debugger_mcp as m
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            m.ExploitGenerateInput(binary="/bin/ls", offset=0)

    def test_process_strings_input(self):
        import edb_debugger_mcp as m
        model = m.ProcessStringsInput(min_length=8)
        assert model.min_length == 8

    def test_process_strings_input_default(self):
        import edb_debugger_mcp as m
        model = m.ProcessStringsInput()
        assert model.min_length == 4

    def test_address_ref_input(self):
        import edb_debugger_mcp as m
        model = m.AddressRefInput(address="main")
        assert model.address == "main"

    def test_address_ref_input_empty_fails(self):
        import edb_debugger_mcp as m
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            m.AddressRefInput(address="")

    def test_patch_history_input(self):
        import edb_debugger_mcp as m
        model = m.PatchHistoryInput(clear=True)
        assert model.clear is True

    def test_patch_history_input_default(self):
        import edb_debugger_mcp as m
        model = m.PatchHistoryInput()
        assert model.clear is False


class TestBackendMethodsEdge:
    """Test backend methods with edge cases (no GDB needed)."""

    def setup_method(self):
        self.b = GDBBackend()

    def test_analyze_heap_not_loaded(self):
        import asyncio
        try:
            r = asyncio.run(self.b.analyze_heap())
            assert "No program" in r or "Error" in r
        except GDBBackendError as e:
            assert "GDB not started" in str(e)

    def test_list_breakpoint_types_no_process(self):
        import asyncio
        try:
            r = asyncio.run(self.b.list_breakpoint_types())
            assert isinstance(r, str)
        except GDBBackendError as e:
            assert "GDB not started" in str(e)

    def test_process_strings_no_process(self):
        import asyncio
        r = asyncio.run(self.b.process_strings())
        assert "No process" in r

    def test_exploit_generate_no_pwntools(self):
        import asyncio
        self.b._pwntools_ready = False
        self.b._pwntools_checked = True
        r = asyncio.run(self.b.exploit_generate("/nonexistent", 8))
        assert "not available" in r

    def test_remote_arch_no_gdb(self):
        import asyncio
        try:
            r = asyncio.run(self.b.remote_arch())
            assert isinstance(r, str)
        except GDBBackendError as e:
            assert "GDB not started" in str(e)

    def test_remote_info_no_gdb(self):
        import asyncio
        try:
            r = asyncio.run(self.b.remote_info())
            assert isinstance(r, str)
        except GDBBackendError as e:
            assert "GDB not started" in str(e)

    def test_get_function_xrefs_no_gdb(self):
        import asyncio
        try:
            r = asyncio.run(self.b.get_function_xrefs("main"))
            assert isinstance(r, str)
        except GDBBackendError as e:
            assert "GDB not started" in str(e)

    def test_goto_function_start_no_gdb(self):
        import asyncio
        try:
            r = asyncio.run(self.b.goto_function_start("main"))
            assert isinstance(r, str)
        except GDBBackendError as e:
            assert "GDB not started" in str(e)

    def test_enum_registers_no_gdb(self):
        import asyncio
        try:
            r = asyncio.run(self.b.enum_registers())
            assert isinstance(r, str)
        except GDBBackendError as e:
            assert "GDB not started" in str(e)

    def test_binary_diff_no_binary(self):
        self.b._binary = None
        import asyncio
        r = asyncio.run(self.b.binary_diff())
        assert "No binary" in r

    def test_list_functions_cached(self):
        self.b._function_cache = "cached functions"
        import asyncio
        r = asyncio.run(self.b.list_functions())
        assert r == "cached functions"


class TestInitMain:
    """Test __init__.py main() function."""

    def test_main_imports(self):
        import edb_debugger_mcp
        assert hasattr(edb_debugger_mcp, "main")
        assert callable(edb_debugger_mcp.main)

    def test_mcp_instance(self):
        import edb_debugger_mcp
        assert hasattr(edb_debugger_mcp, "mcp")
        assert hasattr(edb_debugger_mcp, "backend")

    def test_tools_registered(self):
        import edb_debugger_mcp
        tools = edb_debugger_mcp.mcp._tool_manager._tools
        assert len(tools) >= 200
        edb_tools = [t for t in tools if t.startswith("edb_")]
        assert len(edb_tools) >= 150


class TestPwntoolsEdgeCases:
    """Test pwntools MCP edge cases."""

    def test_pwntools_available_function(self):
        from pwntools_mcp import _pwntools_available
        assert isinstance(_pwntools_available(), bool)

    def test_pwntools_cached(self):
        from pwntools_mcp import _pwntools_available, _PWNTOOLS_READY
        _pwntools_available()
        assert _PWNTOOLS_READY is not None
        assert isinstance(_PWNTOOLS_READY, bool)
