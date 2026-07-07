"""
EDB MCP Reverse Engineering Workflow Demo
Shows a realistic RE scenario: analyzing a vulnerable binary with buffer overflow,
finding secret function, generating exploit components.
"""

import asyncio
import inspect
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from edb_debugger_mcp import mcp
from gdb_backend import GDBBackend

BIN = "/tmp/edb_vuln"
R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; B = "\033[34m"; C = "\033[36m"; N = "\033[0m"

async def call(name, params=None):
    t = mcp._tool_manager._tools.get(name)
    if not t:
        return "ERROR"
    sig = inspect.signature(t.fn)
    kwargs = {}
    for pname, param in sig.parameters.items():
        if pname == "params" and params:
            kwargs["params"] = param.annotation(**params)
            break
        if pname == "ctx": continue
        if params and pname in params: kwargs[pname] = params[pname]
    try: return await t.fn(**kwargs)
    except Exception as e: return f"ERROR: {e}"

def section(n):
    print(f"\n{B}{'='*60}{N}\n{C}  {n}{N}\n{B}{'='*60}{N}")

async def main():
    backend = GDBBackend()
    print("Starting GDB backend..."); await backend.start()

    try:
        # ── ACT 1: Recon ──
        section("ACT 1: RECON — Load binary + discover")
        await call("edb_load_program", {"path": BIN})

        r = await call("edb_get_binary_info")
        print(f"  Binary info: {str(r)[:80]}")

        r = await call("edb_list_functions")
        print(f"  Functions: {len(str(r).split(chr(10)))} entries")
        if "secret_function" in str(r):
            print(f"  {Y}FOUND: secret_function — hidden function!{N}")

        r = await call("edb_lookup_symbol", {"name": "secret_function"})
        print(f"  secret_function at: {str(r)[:60]}")

        r = await call("edb_get_entry_point")
        print(f"  Entry point: {str(r)[:40]}")

        # ── ACT 2: Analyze vuln function ──
        section("ACT 2: ANALYZE — Disassemble vuln + find buffer")
        r = await call("edb_disassemble", {"location": "vuln", "count": 20})
        print("  Disassembly of vuln:")
        for l in str(r).strip().split("\n")[:10]:
            print(f"    {l}")

        r = await call("edb_get_function_bounds", {"name": "vuln"})
        print(f"  vuln bounds: {str(r)[:80]}")

        r = await call("edb_analyze_basic_blocks", {"address": "vuln", "size": 64})
        print(f"  Basic blocks: {str(r)[:80]}")

        r = await call("edb_find_strings")
        if "SECRET" in str(r):
            print(f"  {Y}Strings: found 'SECRET' reference{N}")

        # ── ACT 3: Set breakpoint + Run ──
        section("ACT 3: EXECUTE — Breakpoint at vuln, run with overflow payload")
        await call("edb_set_breakpoint", {"location": "vuln"})
        print("  Breakpoint set at vuln")

        r = await call("edb_run")
        await asyncio.sleep(1.5)

        r = await call("edb_get_stop_reason")
        print(f"  Stopped: {str(r)[:60]}")

        r = await call("edb_get_current_instruction")
        print(f"  At: {str(r).strip()[:60]}")

        # ── ACT 4: Register state ──
        section("ACT 4: REGISTER STATE")
        r = await call("edb_get_registers")
        regs = str(r).strip().split("\n")[:8]
        print("  Registers:")
        for l in regs:
            print(f"    {l}")

        r = await call("edb_get_stack", {"count": 16})
        print("  Stack (first 8):")
        for l in str(r).strip().split("\n")[:8]:
            print(f"    {l}")

        r = await call("edb_get_backtrace")
        print(f"  Backtrace: {str(r)[:80]}")

        # ── ACT 5: Step through overflow ──
        section("ACT 5: STEP THROUGH — Watch buffer overflow")
        for i in range(5):
            await call("edb_step_instruction")
            r = await call("edb_get_current_instruction")
            insn = str(r).strip().split("\n")[0] if str(r).strip() else "?"
            print(f"  step {i+1}: {insn[:70]}")

        r = await call("edb_get_stack", {"count": 16})
        print("  Stack after strcpy (AAAA landed):")
        for l in str(r).strip().split("\n")[:6]:
            print(f"    {l}")

        # ── ACT 6: ROP + Exploit components ──
        section("ACT 6: EXPLOIT — ROP + shellcode + cyclic")
        r = await call("edb_find_rop_gadgets", {"count": 5})
        print("  ROP gadgets:")
        for l in str(r).strip().split("\n")[:5]:
            print(f"    {l}")

        r = await call("pwntools_analyze_elf", {"path": BIN})
        print(f"  ELF security: {str(r)[:120]}")

        r = await call("pwntools_find_rop", {"path": BIN, "grep": "pop rdi|ret"})
        print("  Pwntools ROP:")
        for l in str(r).strip().split("\n")[:3]:
            print(f"    {l}")

        r = await call("pwntools_shellcraft", {"arch": "amd64", "purpose": "execve"})
        print(f"  Shellcode: {str(r)[:100]}")

        r = await call("pwntools_cyclic", {"length": 128})
        print(f"  Cyclic ({len(str(r))} chars)")

        r = await call("pwntools_fmtstr_payload", {"offset": 6, "writes": {"0x601000": 0x401196}})
        print(f"  Fmtstr payload: {str(r)[:80]}")

        # ── ACT 7: Continue to secret ──
        section("ACT 7: REVERSE PAYLOAD — Continue to secret_function")
        r = await call("edb_set_breakpoint", {"location": "secret_function"})
        print("  Breakpoint at secret_function")

        r = await call("edb_continue")
        await asyncio.sleep(1)

        r = await call("edb_get_stop_reason")
        print(f"  Stopped: {str(r)[:60]}")

        r = await call("edb_get_current_instruction")
        print(f"  {G}Reached secret_function!{N}")
        print(f"  At: {str(r).strip()[:60]}")

        r = await call("edb_get_register", {"name": "rip"})
        print(f"  RIP = {str(r)[:40]}")

        # ── ACT 8: Cleanup ──
        section("ACT 8: CLEANUP")
        r = await call("edb_generate_core_dump", {"file_path": "/tmp/edb_demo_core"})
        print(f"  Core dump: {str(r)[:60]}")
        await call("edb_kill_process")
        print(f"  {G}Process killed{N}")

    finally:
        await backend.quit()

    print(f"\n{'='*60}")
    print(f"  {G}Workflow complete — all tools operational{N}")
    print(f"{'='*60}")

if __name__ == "__main__":
    asyncio.run(main())
