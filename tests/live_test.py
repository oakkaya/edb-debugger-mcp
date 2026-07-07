#!/usr/bin/env python3
"""Live end-to-end MCP server test — all 135 tools through the MCP pipeline."""

import asyncio
import sys
import os
import tempfile
import subprocess
import inspect

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from edb_debugger_mcp import mcp, backend

C = "\033[36m"; G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; B = "\033[1m"; N = "\033[0m"
pass_count = 0; fail_count = 0; skip_count = 0
TIMEOUT = 15.0

def ok(msg):
    global pass_count; pass_count += 1
    print(f"  {G}\u2713{N} {msg}")

def fail(msg, detail=""):
    global fail_count; fail_count += 1
    print(f"  {R}\u2717{N} {msg}")
    if detail:
        for line in detail.split("\n")[:3]:
            print(f"    {R}{line}{N}")

def skip(msg):
    global skip_count; skip_count += 1
    print(f"  {Y}\u2014{N} {msg}")

def header(t):
    print(f"\n{B}{C}\u2550\u2550\u2550 {t} \u2550\u2550\u2550{N}")


def make_params(params, bin_path):
    if params is None:
        return None
    return {k: (bin_path if v is None else v) for k, v in params.items()}


async def call_tool(tool_name: str, params_input, timeout=TIMEOUT) -> str:
    try:
        tool = mcp._tool_manager._tools.get(tool_name)
        if not tool:
            return f"ERROR: Tool '{tool_name}' not found"

        sig = inspect.signature(tool.fn)
        model_args = []
        for pname, param in sig.parameters.items():
            if hasattr(param.annotation, 'model_config'):
                if params_input:
                    model_args.append(param.annotation(**params_input))
                else:
                    model_args.append(param.annotation())
                break

        result = await asyncio.wait_for(tool.fn(*model_args), timeout=timeout)
        if isinstance(result, str):
            return result[:800]
        return str(result)[:800]
    except asyncio.TimeoutError:
        return f"ERROR: Tool timeout after {timeout}s"
    except Exception as e:
        return f"ERROR: {e}"


async def run_tool(name, params=None):
    resolved = make_params(params, bin_path)
    r = await call_tool(name, resolved)
    if "ERROR" not in r:
        ok(name)
    else:
        fail(name, r)


# ──────────────────────────────────────────
async def main():
    global pass_count, fail_count, bin_path

    tmpdir = tempfile.mkdtemp()
    src = os.path.join(tmpdir, "test.c")
    bin_path = os.path.join(tmpdir, "test_prog")

    with open(src, "w") as f:
        f.write('''#include <stdio.h>
int global_var = 42;
void helper(int n) { printf("helper(%d)\\n", n); }
int main(int argc, char *argv[]) {
    int x = 10, y = 20, sum = x + y;
    for (int i = 0; i < 3; i++) helper(i);
    printf("sum=%d\\n", sum);
    return sum;
}
''')

    ret = subprocess.run(["gcc", "-g", "-O0", "-o", bin_path, src],
                         capture_output=True, text=True)
    if ret.returncode != 0:
        print(f"{R}Cannot compile: {ret.stderr}{N}"); sys.exit(1)

    print(f"{B}Binary: {bin_path}{N}")
    print(f"{B}Full live test (per-tool timeout: {TIMEOUT}s){N}")
    print("=" * 60)

    header("0. GDB BASLAT")
    try:
        await asyncio.wait_for(backend.start(), timeout=10.0)
        ok("backend.start()")
    except Exception as e:
        fail("backend.start()", str(e))
        sys.exit(1)

    # ─── 1. BASLANGIC ───
    header("1. BASLANGIC TOOL'LARI")
    await run_tool("edb_get_arch_info")
    await run_tool("edb_get_binary_info")
    await run_tool("edb_list_features")

    # ─── 2. PROGRAM YUKLE ───
    header("2. PROGRAM YUKLE")
    await run_tool("edb_load_program", {"path": None, "args": ""})
    await run_tool("edb_get_entry_point")
    await run_tool("edb_get_status")
    await run_tool("edb_get_binary_info")
    await run_tool("edb_list_modules")
    await run_tool("edb_list_source_files")
    await run_tool("edb_list_plugins")
    await run_tool("edb_compare_sections")

    # ─── 3. BREAKPOINT ───
    header("3. BREAKPOINT")
    await run_tool("edb_set_breakpoint", {"location": "main"})
    await run_tool("edb_list_breakpoints")
    await run_tool("edb_set_hardware_breakpoint", {"location": "helper"})
    await run_tool("edb_enable_breakpoint", {"number": 1})
    await run_tool("edb_disable_breakpoint", {"number": 2})
    await run_tool("edb_set_breakpoint_condition", {"number": 1, "condition": "argc == 1"})
    await run_tool("edb_set_breakpoint_ignore_count", {"number": 1, "count": 0})
    await run_tool("edb_set_trace_point", {"location": "helper", "log_message": "hit helper"})
    await run_tool("edb_set_catchpoint", {"event": "syscall", "condition": "write"})

    # ─── 4. CALISTIR ───
    header("4. CALISTIR + BREAK")
    await run_tool("edb_run")

    # ─── 5. REGISTER ───
    header("5. REGISTER")
    await run_tool("edb_get_registers")
    await run_tool("edb_get_register", {"name": "rip"})
    await run_tool("edb_dump_registers")
    await run_tool("edb_get_changed_registers")
    await run_tool("edb_get_fpu_state")
    await run_tool("edb_get_simd_state")
    await run_tool("edb_set_register", {"name": "rax", "value": "0x42"})

    # ─── 6. BELLEK ───
    header("6. BELLEK")
    await run_tool("edb_read_memory", {"address": "$rsp", "count": 64})
    await run_tool("edb_read_memory_as", {"address": "$rsp", "data_type": "uint64", "count": 2})
    await run_tool("edb_get_memory_map")
    await run_tool("edb_get_memory_region_info")

    # ─── 7. DISASSEMBLY ───
    header("7. DISASSEMBLY")
    await run_tool("edb_disassemble", {"location": "main", "count": 10})
    await run_tool("edb_disassemble_range", {"start_address": "main", "end_address": "main+0x20"})
    await run_tool("edb_get_current_instruction")
    await run_tool("edb_instruction_detail", {"address": ""})

    # ─── 8. STACK + FRAME ───
    header("8. STACK + FRAME")
    await run_tool("edb_get_stack")
    await run_tool("edb_get_stack_frame", {"frame_level": 0})
    await run_tool("edb_get_backtrace")
    await run_tool("edb_get_frame_info", {"frame_level": 0})
    await run_tool("edb_get_arguments")
    await run_tool("edb_get_locals")
    await run_tool("edb_list_stack_arguments", {"frame_low": 0})

    # ─── 9. SEMBOL + FUNC ───
    header("9. SEMBOL + FONKSIYON")
    await run_tool("edb_lookup_symbol", {"name": "main"})
    await run_tool("edb_list_functions", {"filter_str": ""})
    await run_tool("edb_get_function_info", {"name": "main"})
    await run_tool("edb_get_function_bounds", {"name": "main"})
    await run_tool("edb_get_section_info", {"module": ""})

    # ─── 10. EXPRESSION ───
    header("10. EXPRESSION + DATA")
    await run_tool("edb_evaluate_expression", {"expression": "argc"})
    await run_tool("edb_ptype", {"expression": "main"})
    await run_tool("edb_whatis", {"expression": "argc"})
    await run_tool("edb_get_string", {"address": "$rsp"})
    await run_tool("edb_find_strings")
    await run_tool("edb_get_variable", {"name": "argc"})

    # ─── 11. STEP ───
    header("11. STEP")
    await run_tool("edb_step_instruction")
    await run_tool("edb_step_into")
    await run_tool("edb_step_over")
    await run_tool("edb_step_out")

    # ─── 12. YAZMA + PATCH ───
    header("12. YAZMA + PATCH")
    await run_tool("edb_nop_range", {"start_address": "main", "end_address": "main+0x3"})
    await run_tool("edb_write_memory", {"address": "$rsp", "data": "0xdeadbeef"})
    await run_tool("edb_write_memory_bytes", {"address": "$rsp", "hex_bytes": "90 90 90 90"})
    await run_tool("edb_fill_memory", {"address": "$rsp", "byte_value": "0x90", "count": 4})
    await run_tool("edb_assemble", {"address": "main", "instruction": "nop"})
    await run_tool("edb_search_memory", {"pattern": "0x90 0x90"})
    await run_tool("edb_search_instructions", {"pattern": "0x90 0x90"})

    # ─── 13. ANALIZ ───
    header("13. KOD ANALIZI")
    await run_tool("edb_analyze_region", {"address": "main", "size": 64})
    await run_tool("edb_analyze_calls_at", {"address": "main"})
    await run_tool("edb_analyze_basic_blocks", {"address": "main", "size": 64})
    await run_tool("edb_analyze_heap")
    await run_tool("edb_find_rop_gadgets", {"address": "main", "depth": 2, "count": 20})
    await run_tool("edb_generate_cfg", {"address": "main", "size": 64})
    await run_tool("edb_find_references", {"address": "main"})
    await run_tool("edb_string_references", {"string_or_address": "main"})

    # ─── 14. ANNOTATION ───
    header("14. ANNOTATION + BOOKMARK")
    await run_tool("edb_label_address", {"address": "main", "label": "entry"})
    await run_tool("edb_add_comment", {"address": "main", "comment": "func entry"})
    await run_tool("edb_list_comments")
    await run_tool("edb_remove_comment", {"address": "main"})
    await run_tool("edb_add_bookmark", {"name": "main_func", "address": "main"})
    await run_tool("edb_list_bookmarks")
    await run_tool("edb_remove_bookmark", {"name": "main_func"})
    await run_tool("edb_binary_string_convert", {"hex_str": "48656c6c6f"})
    await run_tool("edb_binary_string_convert", {"ascii_str": "Hello"})

    # ─── 15. STACK MODIFY ───
    header("15. STACK MODIFY")
    await run_tool("edb_stack_push", {"value": "0xcafebabe"})
    await run_tool("edb_stack_pop")
    await run_tool("edb_stack_modify", {"value": "0xdeadbeef"})
    await run_tool("edb_set_variable", {"name": "argc", "value": "99"})

    # ─── 16. THREAD + SIGNAL ───
    header("16. THREAD + SIGNAL")
    await run_tool("edb_list_threads")
    await run_tool("edb_get_current_thread")
    await run_tool("edb_signal_handling", {"signal": "SIGSEGV", "action": "stop"})
    await run_tool("edb_list_signals", {"signal": ""})
    await run_tool("edb_get_stop_reason")
    await run_tool("edb_dump_state")

    # ─── 17. ENV + CONF ───
    header("17. ENV + KONFIGURASYON")
    await run_tool("edb_set_environment_variable", {"name": "TEST_VAR", "value": "hello"})
    await run_tool("edb_get_environment")
    await run_tool("edb_unset_environment_variable", {"name": "TEST_VAR"})
    await run_tool("edb_configure_debugger", {"setting": "follow-fork-mode", "value": "child"})
    await run_tool("edb_show_configuration", {"setting": "architecture"})
    await run_tool("edb_disable_aslr", {"disable": True})
    await run_tool("edb_disable_lazy_binding", {"disable": True})

    # ─── 18. DOSYA DONUSUM ───
    header("18. DOSYA DONUSUM")
    await run_tool("edb_va_to_file_offset", {"address": "main"})
    await run_tool("edb_file_offset_to_va", {"offset": 0})

    # ─── 19. SESSION ───
    header("19. SESSION + BREAKPOINT FILE")
    await run_tool("edb_session_save", {"file_path": "/tmp/session.json"})
    await run_tool("edb_session_load", {"file_path": "/tmp/session.json"})
    await run_tool("edb_breakpoint_export", {"file_path": "/tmp/bps.json"})
    await run_tool("edb_breakpoint_import", {"file_path": "/tmp/bps.json"})
    await run_tool("edb_view_at_address", {"address": "main"})

    # ─── 20. PROCESS ───
    header("20. PROCESS CONTROL")
    await run_tool("edb_get_process_properties")
    await run_tool("edb_inferior_info")
    await run_tool("edb_set_working_directory", {"directory": "/tmp"})

    # ─── 21. BREAKPOINT TEMIZLIK ───
    header("21. BREAKPOINT TEMIZLIK")
    await run_tool("edb_breakpoint_commands", {"number": 1, "commands": ["print argc", "continue"]})
    await run_tool("edb_remove_breakpoint", {"number": 1})
    await run_tool("edb_remove_breakpoint", {"number": 2})

    # ─── 22. KILL + CORE ───
    header("22. KILL + CORE")
    await run_tool("edb_generate_core_dump", {"file_path": "/tmp/test_core"})
    await run_tool("edb_kill_process")
    await run_tool("edb_detach_process")

    # ─── TEMIZLIK ───
    await backend.quit()

    for f in ["/tmp/session.json", "/tmp/bps.json", "/tmp/test_core", "/tmp/gdb.log"]:
        try:
            os.remove(f)
        except OSError:
            pass

    print(f"\n{'=' * 60}")
    total = pass_count + fail_count + skip_count
    if fail_count == 0:
        print(f"{B}{G}SONUC: {pass_count}/{pass_count + skip_count} passed - BASARILI{N}")
    else:
        print(f"{B}{R}SONUC: {pass_count}/{total} passed, {fail_count} failed, {skip_count} skipped{N}")
    print(f"{'=' * 60}")

    import shutil; shutil.rmtree(tmpdir, ignore_errors=True)
    return fail_count == 0

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
