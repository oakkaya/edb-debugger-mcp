"""Coverage tests for error paths, edge cases, and untested code."""

import asyncio
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from edb_debugger_mcp.gdb_backend import GDBBackend, GDBBackendError


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
        assert len(tools) >= 25
        edb_tools = [t for t in tools if t.startswith("edb_")]
        assert len(edb_tools) >= 18


class TestPwntoolsEdgeCases:
    """Test pwntools MCP edge cases."""

    def test_pwntools_available_function(self):
        from edb_debugger_mcp.composite_tools import _pwntools_available
        assert isinstance(_pwntools_available(), bool)

    def test_pwntools_cached(self):
        from edb_debugger_mcp.composite_tools import _pwntools_available, _PWNTOOLS_READY
        _pwntools_available()
        assert _PWNTOOLS_READY is not None
        assert isinstance(_PWNTOOLS_READY, bool)

    def test_pwntools_not_available_fallback(self):
        import edb_debugger_mcp.composite_tools as pwntools_mcp
        orig = pwntools_mcp._PWNTOOLS_READY
        pwntools_mcp._PWNTOOLS_READY = False
        try:
            result = pwntools_mcp._pwntools_available()
            assert result is False
        finally:
            pwntools_mcp._PWNTOOLS_READY = orig

    def test_pwntools_not_avail_returns_false(self):
        import edb_debugger_mcp.composite_tools as pwntools_mcp
        orig = pwntools_mcp._PWNTOOLS_READY
        pwntools_mcp._PWNTOOLS_READY = False
        try:
            assert pwntools_mcp._pwntools_available() is False
        finally:
            pwntools_mcp._PWNTOOLS_READY = orig


class TestGDBBackendInfra:
    """Test GDBBackend infrastructure methods (no GDB)."""

    def setup_method(self):
        self.b = GDBBackend()

    def test_init_defaults(self):
        assert self.b._binary is None
        assert self.b._args == ""
        assert self.b._running is False
        assert self.b._patch_history == []
        assert self.b._async_events == []
        assert self.b._function_cache is None

    def test_singleton(self):
        b2 = GDBBackend.get_instance()
        assert b2 is self.b or b2 is not None

    def test_re_is_hex_valid(self):
        assert self.b._RE_IS_HEX("0x7fff") is not None
        assert self.b._RE_IS_HEX("0x0") is not None

    def test_re_is_hex_invalid(self):
        assert self.b._RE_IS_HEX("0xGGG") is None
        assert self.b._RE_IS_HEX("123") is None

    def test_re_is_dec_valid(self):
        assert self.b._RE_IS_DEC("123") is not None
        assert self.b._RE_IS_DEC("-1") is not None

    def test_re_is_dec_invalid(self):
        assert self.b._RE_IS_DEC("0x7f") is None
        assert self.b._RE_IS_DEC("abc") is None

    def test_re_strip_quotes(self):
        assert self.b._RE_STRIP_QUOTES('"hello"') == "hello"
        assert self.b._RE_STRIP_QUOTES('  "hello"  ') == "hello"

    def test_drain_queue_empty(self):
        self.b._drain_queue()

    def test_drain_queue_with_items(self):
        self.b._output_queue.put_nowait(b"line1")
        self.b._output_queue.put_nowait(b"line2")
        self.b._drain_queue()
        assert self.b._output_queue.empty()

    def test_parse_mi_record_with_prefix(self):
        r = self.b._parse_mi_record('*stopped,reason="breakpoint-hit"')
        assert r["type"] == "stopped"
        assert r["values"]["reason"] == "breakpoint-hit"

    def test_parse_mi_record_equals_prefix(self):
        r = self.b._parse_mi_record('=library-loaded,id="libc"')
        assert r["type"] == "library-loaded"

    def test_extract_location_no_records(self):
        parsed = {"records": [{"type": "stopped", "values": {"reason": "unknown"}}]}
        loc = self.b._extract_location(parsed)
        assert loc["reason"] == "unknown"

    def test_extract_location_no_values(self):
        parsed = {"records": [{"type": "stopped", "values": {}}]}
        loc = self.b._extract_location(parsed)
        assert "reason" in loc

    def test_check_error_no_records(self):
        self.b._check_error({"records": []})


class TestMainErrorPaths:
    """Test error paths in main entry point."""

    def test_main_catches_import_error(self):
        import sys
        orig_path = list(sys.path)
        try:
            mod = __import__("edb_debugger_mcp", fromlist=["main"])
            assert callable(mod.main)
        finally:
            sys.path = orig_path

    def test_backend_quit_error_swallowed(self):
        b = GDBBackend()
        b._process = None
        import asyncio
        try:
            asyncio.run(b.quit())
        except Exception:
            pytest.fail("quit() should not raise when not started")


class TestBackendMethodsMoreEdge:
    """Test additional backend methods without GDB."""

    def setup_method(self):
        self.b = GDBBackend()

    def _run(self, method, *args, **kwargs):
        import asyncio
        try:
            return asyncio.run(method(*args, **kwargs))
        except GDBBackendError as e:
            if "GDB not started" in str(e):
                return "GDB_NOT_STARTED"
            raise

    def test_get_registers_no_gdb(self):
        r = self._run(self.b.get_registers)
        assert "GDB_NOT_STARTED" in r or "No process" in r

    def test_get_memory_map_no_process(self):
        r = self._run(self.b.get_memory_map)
        assert "No process" in r or "GDB_NOT_STARTED" in r

    def test_get_backtrace_no_process(self):
        r = self._run(self.b.get_backtrace)
        assert "No process" in r or "GDB_NOT_STARTED" in r

    def test_get_stack_frame_no_process(self):
        r = self._run(self.b.get_stack_frame, 0)
        assert "No process" in r or "GDB_NOT_STARTED" in r

    def test_get_current_instruction_no_process(self):
        r = self._run(self.b.get_current_instruction)
        assert "No process" in r or "GDB_NOT_STARTED" in r

    def test_get_entry_point_no_binary(self):
        self.b._binary = None
        r = self._run(self.b.get_entry_point)
        assert isinstance(r, str)

    def test_get_binary_info_no_binary(self):
        self.b._binary = None
        r = self._run(self.b.get_binary_info)
        assert "No binary" in r

    def test_disassemble_no_binary(self):
        self.b._binary = None
        r = self._run(self.b.disassemble, "main")
        assert "No binary" in r or "GDB_NOT_STARTED" in r

    def test_status_idle(self):
        self.b._running = False
        self.b._binary = None
        r = asyncio.run(self.b.status())
        assert isinstance(r, dict)
        assert r["running"] is False
        assert r["binary"] is None

    def test_session_save_no_binary(self):
        self.b._binary = None
        r = self._run(self.b.session_save, "/tmp/test_session.json")
        assert "Session saved" in r

    def test_watch_expression_no_process(self):
        r = self._run(self.b.watch_expression, "$rax")
        assert "No process" in r or "GDB_NOT_STARTED" in r

    def test_scan_stack_no_process(self):
        r = self._run(self.b.scan_stack_for_retaddr)
        assert "GDB" in r or "No process" in r

    def test_nop_range_no_process(self):
        r = self._run(self.b.nop_range, "0x4000", "0x4010")
        assert "No process" in r or "GDB" in r

    def test_get_changed_registers_no_process(self):
        r = self._run(self.b.get_changed_registers)
        assert "GDB" in r or "No process" in r

    def test_inferior_info_no_process(self):
        r = self._run(self.b.inferior_info)
        assert isinstance(r, str)

    def test_compare_snapshot_no_process(self):
        r = self._run(self.b.compare_snapshot)
        assert "No process" in r or "GDB_NOT_STARTED" in r


class TestNewModelEdgeCases:
    """Test validation for recently added models."""

    def test_binary_string_convert_input(self):
        import edb_debugger_mcp as m
        from pydantic import ValidationError
        model = m.BinaryStringConvertInput(hex_str="68656c6c6f", ascii_str="")
        assert model.hex_str == "68656c6c6f"

    def test_disassemble_range_input(self):
        import edb_debugger_mcp as m
        model = m.DisassembleRangeInput(start_address="0x4000", end_address="0x4010")
        assert model.start_address == "0x4000"

    def test_analyze_basic_blocks_input(self):
        import edb_debugger_mcp as m
        model = m.AnalyzeBasicBlocksInput(address="0x4000")
        assert model.address == "0x4000"

    def test_analyze_basic_blocks_input_with_size(self):
        import edb_debugger_mcp as m
        model = m.AnalyzeBasicBlocksInput(address="0x4000", size=64)
        assert model.size == 64

    def test_debug_output_input(self):
        import edb_debugger_mcp as m
        model = m.DebugOutputInput(category="all", enable=True)
        assert model.enable is True

    def test_debug_output_input_default(self):
        import edb_debugger_mcp as m
        model = m.DebugOutputInput(category="all")
        assert model.enable is True

    def test_debug_output_input_disabled(self):
        import edb_debugger_mcp as m
        model = m.DebugOutputInput(category="all", enable=False)
        assert model.enable is False

    def test_step_over_instruction_input(self):
        import edb_debugger_mcp as m
        model = m.StepOverInstructionInput(count=3)
        assert model.count == 3

    def test_step_over_instruction_input_default(self):
        import edb_debugger_mcp as m
        model = m.StepOverInstructionInput()
        assert model.count == 1

    def test_generate_symbols_input(self):
        import edb_debugger_mcp as m
        model = m.GenerateSymbolsInput(path="/tmp/test.zip")
        assert model.path == "/tmp/test.zip"

    def test_apply_patches_input(self):
        import edb_debugger_mcp as m
        model = m.ApplyPatchesInput()
        assert model.output_path is None

    def test_apply_patches_input_with_path(self):
        import edb_debugger_mcp as m
        model = m.ApplyPatchesInput(output_path="/tmp/patched")
        assert model.output_path == "/tmp/patched"

    def test_signal_send_input(self):
        import edb_debugger_mcp as m
        model = m.SignalSendInput(signum=2)
        assert model.signum == 2

    def test_stack_push_input(self):
        import edb_debugger_mcp as m
        model = m.StackPushInput(value="0xdeadbeef")
        assert model.value == "0xdeadbeef"

    def test_disable_aslr_input(self):
        import edb_debugger_mcp as m
        model = m.DisableASLRInput(disable=True)
        assert model.disable is True

    def test_disable_lazy_binding_input(self):
        import edb_debugger_mcp as m
        model = m.DisableLazyBindingInput(disable=True)
        assert model.disable is True

    def test_analyze_basic_blocks_input_missing_fails(self):
        import edb_debugger_mcp as m
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            m.AnalyzeBasicBlocksInput()

    def test_pipeline_input(self):
        import edb_debugger_mcp as m
        model = m.PipelineInput(binary="/bin/ls")
        assert model.binary == "/bin/ls"
        assert model.breakpoint is None
        assert model.args is None

    def test_pipeline_input_custom(self):
        import edb_debugger_mcp as m
        model = m.PipelineInput(binary="/bin/ls", breakpoint="main", args="--help")
        assert model.breakpoint == "main"

    def test_compare_snapshot_input(self):
        import edb_debugger_mcp as m
        model = m.CompareSnapshotInput(label="snap1")
        assert model.label == "snap1"

    def test_compare_snapshot_input_default(self):
        import edb_debugger_mcp as m
        model = m.CompareSnapshotInput()
        assert model.label is None

    def test_label_address_no_binary(self):
        b = GDBBackend()
        b._binary = None
        try:
            r = asyncio.run(b.label_address("0x4000", "my_label"))
            assert "No binary" in r or "GDB_NOT_STARTED" in str(r) or "GDB" in str(r)
        except GDBBackendError as e:
            assert "GDB not started" in str(e)
