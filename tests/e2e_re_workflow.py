"""
Comprehensive E2E reverse engineering workflow via MCP tools.
Tests ALL 135 edb_ + 12 pwntools_ tools with a real GDB backend.
"""

import asyncio
import inspect
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from edb_debugger_mcp import mcp
from edb_debugger_mcp.gdb_backend import GDBBackend

BIN = "/tmp/edb_vuln"
R = "\033[31m"; G = "\033[32m"; B = "\033[34m"; C = "\033[36m"; N = "\033[0m"

passed = 0; failed = 0

async def call_it(name, params=None):
    t = mcp._tool_manager._tools.get(name)
    if not t:
        return f"ERROR: Tool '{name}' not found"
    sig = inspect.signature(t.fn)
    kwargs = {}
    for pname, param in sig.parameters.items():
        if pname == "params":
            if params is not None:
                kwargs["params"] = param.annotation(**params)
            break
        if pname == "ctx":
            continue
        if params and pname in params:
            kwargs[pname] = params[pname]
    try:
        return await t.fn(**kwargs)
    except Exception as e:
        return f"ERROR: {e}"

async def tool(name, params=None, label=None):
    global passed, failed
    desc = label or name
    r = await call_it(name, params)
    err = "ERROR" in str(r) or "Traceback" in str(r)
    if not err:
        passed += 1
        print(f"  {G}\u2713{N} {desc}")
    else:
        failed += 1
        print(f"  {R}\u2717{N} {desc}: {str(r)[:160]}")
    return r

async def main():
    backend = GDBBackend()
    print("Starting GDB backend...")
    try:
        await asyncio.wait_for(backend.start(), timeout=10.0)
        print(f"  {G}\u2713{N} GDB backend started")
    except Exception as e:
        print(f"  {R}\u2717{N} GDB backend: {e}")
        return

    try:
        # 1. LOAD + DISASSEMBLE
        print(f"\n{B}===== 1. LOAD + DISASSEMBLE ====={N}")
        await tool("edb_load_program", {"path": BIN})
        await tool("edb_get_binary_info")
        r = await tool("edb_disassemble", {"location": "main", "count": 15})
        if isinstance(r, str) and "ERROR" not in r:
            for l in r.strip().split("\n")[:6]:
                print(f"     {l}")
        await tool("edb_list_functions")

        # 2. SYMBOLS
        print(f"\n{B}===== 2. SYMBOL ANALYSIS ====={N}")
        await tool("edb_lookup_symbol", {"name": "main"})
        await tool("edb_lookup_symbol", {"name": "vuln"})
        await tool("edb_lookup_symbol", {"name": "secret_function"})
        await tool("edb_list_modules")
        await tool("edb_get_entry_point")
        await tool("edb_get_section_info")

        # 3. BREAKPOINTS
        print(f"\n{B}===== 3. BREAKPOINTS ====={N}")
        await tool("edb_set_breakpoint", {"location": "main"})
        await tool("edb_set_breakpoint", {"location": "vuln"})
        await tool("edb_set_breakpoint", {"location": "secret_function"})
        await tool("edb_set_hardware_breakpoint", {"location": "main"})
        await tool("edb_set_watchpoint", {"expression": "i", "type": "write"})
        await tool("edb_set_breakpoint_condition", {"location": "vuln", "condition": "1"})
        await tool("edb_disable_breakpoint", {"location": "main"})
        await tool("edb_enable_breakpoint", {"location": "main"})
        await tool("edb_list_breakpoints")

        # 4. RUN + BREAK
        print(f"\n{B}===== 4. RUN + BREAK ====={N}")
        await tool("edb_run")
        await asyncio.sleep(1.5)
        await tool("edb_get_stop_reason")
        await tool("edb_get_current_instruction")
        await tool("edb_get_status")

        # 5. REGISTERS
        print(f"\n{B}===== 5. REGISTERS ====={N}")
        await tool("edb_get_registers")
        r = await tool("edb_dump_registers")
        if isinstance(r, str) and "ERROR" not in r:
            for l in r.strip().split("\n")[:8]:
                print(f"     {l}")
        await tool("edb_get_register", {"name": "rip"})
        await tool("edb_get_register", {"name": "rsp"})
        await tool("edb_get_register", {"name": "rbp"})
        await tool("edb_get_register", {"name": "rax"})
        await tool("edb_get_changed_registers")
        await tool("edb_get_fpu_state")
        await tool("edb_get_simd_state")

        # 6. DISASSEMBLY ANALYSIS
        print(f"\n{B}===== 6. DISASSEMBLY ====={N}")
        r = await tool("edb_disassemble", {"location": "$pc", "count": 10})
        if isinstance(r, str) and "ERROR" not in r:
            for l in r.strip().split("\n")[:6]:
                print(f"     {l}")
        await tool("edb_disassemble_range", {"address": "$pc", "count": 20})
        await tool("edb_search_instructions", {"pattern": "call|jmp"})
        await tool("edb_instruction_detail", {"address": "$pc"})

        # 7. STEP
        print(f"\n{B}===== 7. STEP ====={N}")
        await tool("edb_step_instruction")
        await tool("edb_get_registers")
        await tool("edb_step_instruction")
        await tool("edb_step_instruction", {"count": 3})
        await tool("edb_get_current_instruction")
        await tool("edb_step_over")
        await tool("edb_step_into")
        await tool("edb_step_out")
        await tool("edb_step_over_instruction")
        await tool("edb_reverse_step")
        await tool("edb_reverse_continue")

        # 8. STACK
        print(f"\n{B}===== 8. STACK ====={N}")
        r = await tool("edb_get_stack", {"count": 24})
        if isinstance(r, str) and "ERROR" not in r:
            for l in r.strip().split("\n")[:6]:
                print(f"     {l}")
        await tool("edb_get_backtrace")
        await tool("edb_get_frame_info", {"level": 0})
        await tool("edb_get_locals")
        await tool("edb_get_arguments")
        await tool("edb_stack_push", {"value": "0xdeadbeef"})
        await tool("edb_stack_pop")
        await tool("edb_stack_modify", {"offset": 8, "value": "0xcafebabe"})
        await tool("edb_list_stack_arguments")

        # 9. MEMORY
        print(f"\n{B}===== 9. MEMORY ====={N}")
        r = await tool("edb_read_memory", {"address": "$rsp", "count": 32})
        if isinstance(r, str) and "ERROR" not in r:
            for l in r.strip().split("\n")[:4]:
                print(f"     {l}")
        await tool("edb_read_memory_as", {"address": "$rsp", "format": "hex", "count": 16})
        await tool("edb_write_memory", {"address": "$rsp", "data": "41414141"})
        await tool("edb_write_memory_bytes", {"address": "$rsp", "bytes": [0x41, 0x42, 0x43, 0x44]})
        await tool("edb_search_memory", {"pattern": "41"})
        await tool("edb_get_memory_map")
        await tool("edb_get_memory_region_info", {"address": "$rsp"})
        await tool("edb_compare_memory", {"address1": "$rsp", "address2": "$rsp+16", "length": 16})
        await tool("edb_set_memory_permissions", {"address": "$rsp", "permissions": "rwx"})
        await tool("edb_fill_memory", {"address": "$rsp", "value": 0x90, "count": 16})
        await tool("edb_dump_memory_to_file", {"address": "$pc", "size": 256, "filepath": "/tmp/edb_dump.bin"})

        # 10. EXPRESSION
        print(f"\n{B}===== 10. EXPRESSION ====={N}")
        await tool("edb_evaluate_expression", {"expression": "$rip"})
        await tool("edb_evaluate_expression", {"expression": "$rsp + 8"})
        await tool("edb_get_variable", {"name": "i"})
        await tool("edb_set_variable", {"name": "i", "value": "99"})
        await tool("edb_ptype", {"expression": "buf"})
        await tool("edb_whatis", {"expression": "main"})
        await tool("edb_get_string", {"address": "$rsp"})
        await tool("edb_call_function", {"function": "secret_function"})

        # 11. ROP + PWNTools
        print(f"\n{B}===== 11. ROP + PWNTools ====={N}")
        r = await tool("edb_find_rop_gadgets", {"count": 10})
        if isinstance(r, str) and "ERROR" not in r:
            for l in r.strip().split("\n")[:5]:
                print(f"     {l}")
        await tool("edb_generate_symbols")
        await tool("edb_find_references", {"address": "main"})
        await tool("edb_find_strings")
        await tool("edb_string_references", {"string": "SECRET"})
        await tool("edb_analyze_heap")

        await tool("pwntools_analyze_elf", {"path": BIN})
        await tool("pwntools_find_rop", {"path": BIN, "regex": "pop rdi"})
        await tool("pwntools_shellcraft", {"arch": "amd64", "os": "linux", "shellcode_type": "execve"})
        await tool("pwntools_cyclic", {"length": 256})
        await tool("pwntools_cyclic_find", {"value": "aaaa"})
        await tool("pwntools_pack", {"value": 0xdeadbeef, "size": 8, "endian": "little"})
        await tool("pwntools_unpack", {"data": b'\xef\xbe\xad\xde', "size": 4, "endian": "little"})
        await tool("pwntools_asm", {"assembly": "mov rax, 0x3b; syscall", "arch": "amd64"})
        await tool("pwntools_disasm", {"bytes": b'\x48\x31\xc0\xb0\x3b\x0f\x05', "arch": "amd64"})
        await tool("pwntools_fmtstr_payload", {"offset": 6, "writes": {"0x404000": 0xdeadbeef}})
        await tool("pwntools_hexdump", {"data": b'AAAA\x00\x01\x02\x03'})
        await tool("pwntools_build_rop_chain", {"path": BIN, "actions": [{"type": "call", "function": "secret_function"}]})

        # 12. PATCHING
        print(f"\n{B}===== 12. PATCHING ====={N}")
        await tool("edb_nop_range", {"start_address": "$pc", "end_address": "$pc+4"})
        await tool("edb_assemble", {"address": "$pc", "instructions": "nop; nop; nop"})
        await tool("edb_get_current_instruction")

        # 13. CODE ANALYSIS
        print(f"\n{B}===== 13. ANALYSIS ====={N}")
        await tool("edb_analyze_basic_blocks", {"address": "main", "size": 512})
        await tool("edb_analyze_calls_at", {"address": "main"})
        await tool("edb_analyze_region", {"address": "$pc", "size": 256})
        await tool("edb_generate_cfg", {"address": "main", "size": 512})
        await tool("edb_list_source_files")
        await tool("edb_list_source", {"filepath": "/tmp/edb_demo_vuln.c"})
        await tool("edb_compare_sections")
        await tool("edb_load_symbol_file", {"filepath": BIN})

        # 14. BOOKMARKS + COMMENTS
        print(f"\n{B}===== 14. BOOKMARKS ====={N}")
        await tool("edb_add_bookmark", {"address": "$pc", "name": "main_entry"})
        await tool("edb_add_comment", {"address": "$pc", "text": "Entry point main"})
        await tool("edb_list_bookmarks")
        await tool("edb_list_comments")
        await tool("edb_label_address", {"address": "$pc", "name": "HERE"})

        # 15. SESSION
        print(f"\n{B}===== 15. SESSION ====={N}")
        await tool("edb_session_save", {"file_path": "/tmp/edb_session.json"})
        await tool("edb_session_load", {"file_path": "/tmp/edb_session.json"})
        await tool("edb_breakpoint_export", {"filepath": "/tmp/edb_bp.json"})
        await tool("edb_breakpoint_import", {"filepath": "/tmp/edb_bp.json"})

        # 16. ENV
        print(f"\n{B}===== 16. ENVIRONMENT ====={N}")
        await tool("edb_set_environment_variable", {"name": "MYVAR", "value": "test123"})
        await tool("edb_get_environment")
        await tool("edb_unset_environment_variable", {"name": "MYVAR"})
        await tool("edb_set_working_directory", {"path": "/tmp"})
        await tool("edb_set_tty", {"tty": "/dev/pts/0"})

        # 17. CONFIG
        print(f"\n{B}===== 17. CONFIGURATION ====={N}")
        await tool("edb_configure_debugger", {"setting": "print pretty", "value": "on"})
        await tool("edb_show_configuration")
        await tool("edb_disable_aslr")
        await tool("edb_disable_lazy_binding")
        await tool("edb_set_debug_output", {"enable": True})
        await tool("edb_set_session_logging", {"enable": True})

        # 18. SIGNALS + THREADS
        print(f"\n{B}===== 18. SIGNALS + THREADS ====={N}")
        await tool("edb_list_signals")
        await tool("edb_signal_handling", {"signal": "SIGALRM", "action": "pass"})
        await tool("edb_list_threads")
        await tool("edb_get_current_thread")
        await tool("edb_set_current_thread", {"id": 1})

        # 19. MISC
        print(f"\n{B}===== 19. MISC ====={N}")
        await tool("edb_get_arch_info")
        await tool("edb_get_process_properties")
        await tool("edb_inferior_info")
        await tool("edb_list_features")
        await tool("edb_list_plugins")
        await tool("edb_binary_string_convert", {"input": "Hello", "from": "ascii", "to": "hex"})
        await tool("edb_view_at_address", {"address": "$pc", "view": "disassembly"})
        await tool("edb_jump_to_address", {"address": "main"})
        await tool("edb_continue_to", {"location": "vuln"})
        await tool("edb_remote_connect", {"host": "localhost", "port": 1234})
        await tool("edb_send_signal", {"signal": "SIGCONT"})
        await tool("edb_pause")
        await tool("edb_restart")
        await tool("edb_attach_process", {"pid": -1})
        await tool("edb_set_breakpoint_ignore_count", {"location": "main", "count": 2})
        await tool("edb_set_catchpoint", {"event": "syscall"})
        await tool("edb_set_trace_point", {"location": "main"})
        await tool("edb_va_to_file_offset", {"address": "0x401000"})
        await tool("edb_file_offset_to_va", {"offset": 0x1000})
        await tool("edb_remove_bookmark", {"name": "main_entry"})
        await tool("edb_remove_comment", {"address": "$pc"})
        await tool("edb_remove_breakpoint", {"location": "vuln"})

        # 20. KILL
        print(f"\n{B}===== 20. CLEANUP ====={N}")
        await tool("edb_generate_core_dump", {"filepath": "/tmp/edb_core.dump"})
        await tool("edb_kill_process")

    finally:
        if backend.proc:
            backend.proc.kill()

    total = passed + failed
    print(f"\n{'='*60}")
    print(f"  {G}{passed}/{total} passed{N}", end="")
    if failed:
        print(f"  {R}{failed} failed{N}")
    else:
        print("")
    print(f"{'='*60}")

if __name__ == "__main__":
    asyncio.run(main())
