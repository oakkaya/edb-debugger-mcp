"""
Tool Table Auto-Generator
Generates the Tool Reference markdown tables for README.md by
introspecting the FastMCP server's registered tools.

Usage: python3 scripts/generate_tool_table.py
Output: prints markdown to stdout (redirect to update README)
"""

import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edb_debugger_mcp import mcp

tm = mcp._tool_manager

CATEGORIES: list[tuple[str, str, list[str]]] = [
    ("Program Control", "load,run,continue,pause,restart,attach,detach,kill,remote", [
        "edb_load_program", "edb_run", "edb_continue", "edb_continue_to",
        "edb_pause", "edb_restart", "edb_attach_process", "edb_detach_process",
        "edb_kill_process", "edb_remote_connect", "edb_send_signal", "edb_call_function",
    ]),
    ("Step Operations", "step,reverse", [
        "edb_step_instruction", "edb_step_into", "edb_step_over", "edb_step_out",
        "edb_step_over_instruction", "edb_reverse_step", "edb_reverse_continue",
        "edb_jump_to_address",
    ]),
    ("Breakpoints", "break,watch,catch,trace,enable,disable", [
        "edb_set_breakpoint", "edb_set_hardware_breakpoint", "edb_set_watchpoint",
        "edb_set_catchpoint", "edb_set_trace_point", "edb_set_breakpoint_condition",
        "edb_set_breakpoint_ignore_count", "edb_breakpoint_commands",
        "edb_enable_breakpoint", "edb_disable_breakpoint", "edb_remove_breakpoint",
        "edb_list_breakpoints", "edb_breakpoint_export", "edb_breakpoint_import",
        "edb_trace_start", "edb_trace_stop", "edb_trace_show",
        "edb_list_breakpoint_types",
    ]),
    ("Register Operations", "register,fpu,simd,dump,eflags,enum", [
        "edb_get_registers", "edb_get_register", "edb_set_register",
        "edb_dump_registers", "edb_get_changed_registers",
        "edb_get_fpu_state", "edb_get_simd_state", "edb_get_arch_info",
        "edb_get_eflags", "edb_enum_registers",
    ]),
    ("Memory Operations", "memory,hex,dump,write,search,compare", [
        "edb_read_memory", "edb_read_memory_as", "edb_write_memory",
        "edb_write_memory_bytes", "edb_fill_memory", "edb_search_memory",
        "edb_compare_memory", "edb_compare_sections", "edb_get_memory_map",
        "edb_get_memory_region_info", "edb_set_memory_permissions",
        "edb_dump_memory_to_file",
    ]),
    ("Disassembly", "disassemble,instruction", [
        "edb_disassemble", "edb_disassemble_range", "edb_get_current_instruction",
        "edb_instruction_detail", "edb_search_instructions",
        "edb_analyze_basic_blocks", "edb_analyze_calls_at",
    ]),
    ("Stack & Frames", "stack,frame,backtrace,local,argument,retaddr", [
        "edb_get_stack", "edb_get_backtrace", "edb_get_frame_info",
        "edb_get_locals", "edb_get_arguments", "edb_list_stack_arguments",
        "edb_stack_push", "edb_stack_pop", "edb_stack_modify",
        "edb_get_stack_frame", "edb_scan_stack_for_retaddr",
    ]),
    ("Symbol Analysis", "symbol,function,module,string,xrefs", [
        "edb_lookup_symbol", "edb_list_functions", "edb_get_function_info",
        "edb_get_function_bounds", "edb_list_modules", "edb_get_section_info",
        "edb_get_entry_point", "edb_find_references", "edb_find_strings",
        "edb_get_function_xrefs", "edb_goto_function_start",
    ]),
    ("Thread & Process", "thread,process,inferior,fork", [
        "edb_list_threads", "edb_get_current_thread", "edb_set_current_thread",
        "edb_get_process_properties", "edb_inferior_info", "edb_follow_fork",
    ]),
    ("Expression & Data", "expression,ptype,whatis,variable,string,watch", [
        "edb_evaluate_expression", "edb_ptype", "edb_whatis",
        "edb_get_variable", "edb_set_variable", "edb_get_string",
        "edb_string_references", "edb_watch_expression",
    ]),
    ("Code Analysis", "analysis,calls,cfg,region,source,strings", [
        "edb_analyze_region", "edb_analyze_heap", "edb_generate_cfg",
        "edb_generate_symbols", "edb_list_source", "edb_list_source_files",
        "edb_binary_string_convert", "edb_process_strings",
    ]),
    ("Patching & Annotations", "nop,assemble,bookmark,comment,label,patch", [
        "edb_nop_range", "edb_assemble", "edb_add_bookmark",
        "edb_list_bookmarks", "edb_remove_bookmark", "edb_add_comment",
        "edb_list_comments", "edb_remove_comment", "edb_apply_patches_to_file",
    ]),
    ("Session & Environment", "session,env,binary,file", [
        "edb_session_save", "edb_session_load", "edb_set_environment_variable",
        "edb_get_environment", "edb_unset_environment_variable",
        "edb_set_working_directory", "edb_set_tty", "edb_set_debug_output",
        "edb_set_session_logging", "edb_signal_handling", "edb_list_signals",
        "edb_get_stop_reason",
    ]),
    ("Debugger Control", "config,aslr,disable,status,feature,misc,command,snapshot,diff", [
        "edb_configure_debugger", "edb_show_configuration", "edb_disable_aslr",
        "edb_disable_lazy_binding", "edb_get_status",
        "edb_get_binary_info", "edb_list_features", "edb_list_plugins",
        "edb_load_symbol_file", "edb_view_at_address",
        "edb_find_rop_gadgets", "edb_label_address",
        "edb_dump_state", "edb_generate_core_dump",
        "edb_execute_gdb_command", "edb_compare_snapshot",
        "edb_pipeline", "edb_export_state",
        "edb_binary_diff", "edb_exploit_generate", "edb_patch_history",
        "edb_remote_arch", "edb_remote_info",
    ]),
    ("File Utils", "va,offset,file", [
        "edb_va_to_file_offset", "edb_file_offset_to_va",
    ]),
]

DESCRIPTIONS: dict[str, str] = {}

def _collect_descriptions():
    for name, tool in tm._tools.items():
        sig = inspect.signature(tool.fn)
        doc = (tool.fn.__doc__ or "").strip()
        if doc:
            DESCRIPTIONS[name] = doc.split("\n")[0][:80]
        else:
            DESCRIPTIONS[name] = ""

_collect_descriptions()

def generate_table(tools: list[str]) -> str:
    lines = ["| Tool | Description |", "|------|-------------|"]
    for name in tools:
        desc = DESCRIPTIONS.get(name, "") or ""
        lines.append(f"| `{name}` | {desc} |")
    return "\n".join(lines)

def main():
    print("<!-- Auto-generated by scripts/generate_tool_table.py -->\n")
    for cat, tag_hint, tools in CATEGORIES:
        count = len(tools)
        print(f"### {cat} ({count} tool{'s' if count > 1 else ''})\n")
        print(generate_table(tools))
        print()

    # Pwntools section
    pwntools_names = sorted(n for n in tm._tools if n.startswith("pwntools"))
    print(f"### pwntools ({len(pwntools_names)} tools)\n")
    print(generate_table(pwntools_names))
    print()

    # Verify coverage
    all_listed = set()
    for _, _, tools in CATEGORIES:
        all_listed.update(tools)
    all_listed.update(pwntools_names)
    all_tools = set(tm._tools.keys())
    missing = all_tools - all_listed
    extra = all_listed - all_tools
    if missing:
        print(f"<!-- WARNING: {len(missing)} tools not listed: {', '.join(sorted(missing))} -->")
    if extra:
        print(f"<!-- WARNING: {len(extra)} extra entries not found: {', '.join(sorted(extra))} -->")
    print(f"<!-- Total tools: {len(all_tools)} listed: {len(all_listed)} -->")

if __name__ == "__main__":
    main()
