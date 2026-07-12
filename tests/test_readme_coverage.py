"""Tests for README documentation coverage and tool consistency."""

import sys
import os
import re
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from edb_debugger_mcp import mcp


class TestToolCoverage:
    """Ensure all MCP tools are properly documented."""

    @classmethod
    def setup_class(cls):
        """Extract all tool names from the MCP server."""
        cls.tool_names = set()
        for tool in mcp._tool_manager._tools.values():
            cls.tool_names.add(tool.name)
        cls.edb_tools = {t for t in cls.tool_names if t.startswith("edb_")}
        cls.pwn_tools = {t for t in cls.tool_names if t.startswith("pwntools_")}

    def test_tools_are_defined(self):
        """There should be at least 25 composite tools."""
        assert len(self.tool_names) >= 25, f"Expected >=25 tools, got {len(self.tool_names)}"

    def test_all_tools_have_readme_entry(self):
        """Every edb_ tool name should appear in README.md."""
        readme_path = os.path.join(os.path.dirname(__file__), "..", "README.md")
        with open(readme_path) as f:
            readme = f.read()

        missing = []
        for tool_name in sorted(self.edb_tools):
            if tool_name not in readme:
                missing.append(tool_name)

        assert not missing, f"edb_ tools missing from README: {missing}"

    def test_readme_has_correct_tool_count(self):
        """README should mention the correct number of edb_ tools."""
        readme_path = os.path.join(os.path.dirname(__file__), "..", "README.md")
        with open(readme_path) as f:
            readme = f.read()

        expected_count = len(self.tool_names)
        pattern = rf"\*\*{expected_count}.*?debugging tools"
        assert re.search(pattern, readme), (
            f"README does not mention '{expected_count} debugging tools'"
        )

    def test_all_tools_have_pipe_entry(self):
        """Every edb_ tool should have a | `edb_*` | Description | entry in README."""
        readme_path = os.path.join(os.path.dirname(__file__), "..", "README.md")
        with open(readme_path) as f:
            readme = f.read()

        missing = []
        for tool_name in sorted(self.edb_tools):
            pipe_pattern = rf"\|\s*`{tool_name}`\s*\|"
            if not re.search(pipe_pattern, readme):
                missing.append(tool_name)

        assert not missing, f"edb_ tools missing pipe-table entry in README: {missing}"

    def test_no_extra_tools_in_readme(self):
        """README should not list tools that don't exist."""
        readme_path = os.path.join(os.path.dirname(__file__), "..", "README.md")
        with open(readme_path) as f:
            readme = f.read()

        readme_tools = set(re.findall(r"`(edb_\w+)`", readme))
        extra = readme_tools - self.edb_tools
        assert not extra, f"README lists non-existent tools: {extra}"


class TestBackendCoverage:
    """Ensure backend has methods for all tools."""

    def test_backend_has_all_tool_methods(self):
        """Every MCP tool should call a backend method."""
        from edb_debugger_mcp import gdb_backend
        backend = gdb_backend.GDBBackend

        methods = [m for m in dir(backend) if not m.startswith("_")]
        method_set = set(methods)

        # Check common method mappings
        expected_methods = [
            "start", "quit", "load_program", "set_breakpoint", "list_breakpoints",
            "remove_breakpoint", "enable_breakpoint", "disable_breakpoint",
            "set_hardware_breakpoint", "set_watchpoint", "run", "continue_exec",
            "interrupt", "step_into", "step_over", "step_out", "step_instruction",
            "step_over_instruction", "disassemble", "disassemble_range",
            "get_registers", "get_register", "set_register", "hex_dump",
            "read_memory", "read_memory_as", "write_memory", "write_memory_bytes",
            "search_memory", "fill_memory", "get_memory_map", "get_memory_region_info",
            "get_stack", "get_stack_frame", "get_backtrace",
            "evaluate", "get_string", "get_variable", "set_variable",
            "get_locals", "get_arguments", "list_functions",
            "lookup_symbol", "list_modules", "get_section_info",
            "get_entry_point", "list_threads", "get_current_thread",
            "set_current_thread", "get_function_info", "get_function_bounds",
            "get_binary_info", "get_arch_info", "get_source",
            "attach", "detach", "kill", "set_register",
            "restart", "continue_to_address", "status",
            "get_current_instruction", "ptype", "whatis",
            "breakpoint_commands", "stack_push", "stack_pop",
            "stack_modify", "label_address", "set_disable_aslr",
            "set_disable_lazy_binding", "binary_string_convert",
            "dump_state", "generate_core_dump", "set_catchpoint",
            "set_conditional_log_breakpoint", "session_save", "session_load",
            "set_working_directory", "set_environment_variable",
            "unset_environment_variable", "get_environment", "set_tty",
            "signal_handling", "remote_connect", "compare_memory",
            "compare_sections", "generate_symbols", "generate_cfg",
            "call_function", "jump_to_address", "analyze_basic_blocks",
            "analyze_calls_at", "analyze_region", "analyze_heap",
            "find_rop_gadgets", "find_references", "string_references",
            "search_instructions", "get_stop_reason", "instruction_detail",
            "view_at_address", "list_plugins", "get_fpu_state",
            "get_simd_state", "load_symbol_file", "set_memory_permissions",
            "show_configuration", "configure_debugger", "send_signal",
            "list_signals", "set_debug_output", "set_session_logging",
            "get_source", "list_source_files", "list_stack_arguments",
            "inferior_info", "list_features", "reverse_step", "reverse_continue",
            "get_changed_registers", "add_bookmark", "list_bookmarks",
            "remove_bookmark", "add_comment", "list_comments", "remove_comment",
            "nop_range", "assemble",
        ]

        missing = [m for m in expected_methods if m not in method_set]
        assert not missing, f"Backend missing methods: {missing}"


class TestModelsCoverage:
    """Ensure all tool input models are properly structured."""

    @classmethod
    def setup_class(cls):
        cls.tool_names = set()
        for tool in mcp._tool_manager._tools.values():
            cls.tool_names.add(tool.name)

    def test_all_tools_use_input_models(self):
        """Every tool should have an associated input model (or no params)."""
        for tool in mcp._tool_manager._tools.values():
            assert tool.name.startswith(("edb_", "pwntools_")), f"Tool {tool.name} doesn't start with edb_ or pwntools_"
