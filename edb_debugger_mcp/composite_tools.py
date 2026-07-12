"""Composite MCP tools for pwntools — 7 tools replacing all 50+ flat functions."""

from typing import Literal, Optional

from edb_debugger_mcp._mcp import mcp
from pwntools_mcp import (
    pwntools_analyze_elf, pwntools_checksec,
    pwntools_elf_read, pwntools_elf_sections, pwntools_elf_symbols,
    pwntools_elf_strings, pwntools_elf_deps,
    pwntools_elf_got, pwntools_elf_plt, pwntools_elf_segments,
    pwntools_elf_relocs, pwntools_elf_notes,
    pwntools_elf_diff, pwntools_elf_search, pwntools_elf_patch,
    pwntools_make_elf, pwntools_entropy,
    pwntools_find_rop, pwntools_erope, pwntools_build_rop_chain,
    pwntools_sigreturn, pwntools_fmtstr_payload,
    pwntools_shellcraft, pwntools_enc,
    pwntools_disasm_bytes, pwntools_asm_instructions,
    pwntools_pack, pwntools_unpack,
    pwntools_enhex, pwntools_unhex, pwntools_flat, pwntools_hexdump_data,
    pwntools_cyclic, pwntools_cyclic_find,
    pwntools_rol, pwntools_ror, pwntools_bits, pwntools_align,
    pwntools_constgrep, pwntools_context, pwntools_log_level,
    pwntools_process, pwntools_remote,
    pwntools_tube_send, pwntools_tube_sendline,
    pwntools_tube_recv, pwntools_tube_recvline, pwntools_tube_recvuntil,
    pwntools_tube_close, pwntools_tube_list,
    # Models
    ElfPath, ChecksecParams,
    ElfReadParams, ElfSectionsParams, ElfSymbolsParams,
    ElfStringsParams, ElfDepsParams,
    ElfRelocsParams, ElfDiffParams, ElfSearchParams, ElfPatchParams,
    MakeElfParams, EntropyParams,
    RopSearchParams, ERopSearchParams, BuildRopChainParams,
    SigreturnFrameParams, FmtStrPayloadParams,
    ShellcodeParams, ShellcodeEncodeParams,
    DisasmParams, AsmParams,
    PackParams, UnpackParams,
    EncodeHexParams, DecodeHexParams, FlatParams, HexDumpParams,
    CyclicParams, CyclicFindParams,
    BitOpParams, AlignParams, BitsParams,
    ConstGrepParams, ContextParams,
    TubeProcessParams, TubeRemoteParams,
    TubeSendParams, TubeRecvParams, TubeRecvUntilParams, TubeBaseParams,
)

# ---------------------------------------------------------------------------
# 1. pwntools_elf — ELF analysis (17 actions)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pwntools_elf(
    action: Literal[
        "analyze", "checksec", "read", "sections", "symbols",
        "strings", "deps", "got", "plt", "segments",
        "relocs", "notes", "diff", "search", "patch",
        "make", "entropy",
    ],
    path: str = "",
    path_b: str = "",
    section: Optional[str] = None,
    offset: Optional[int] = None,
    size: int = 256,
    filter_name: str = "",
    pattern: str = "",
    type_filter: str = "",
    min_length: int = 4,
    resolve_versions: bool = True,
    sections_only: bool = False,
    start: Optional[int] = None,
    end: Optional[int] = None,
    hex_bytes: str = "",
    output: str = "",
    code: str = "",
    arch: str = "amd64",
) -> str:
    """ELF binary analysis — analyze, checksec, read, sections, symbols, strings, deps, GOT, PLT, segments, relocs, notes, diff, search, patch, make-elf, entropy."""
    if action == "analyze":
        return await pwntools_analyze_elf(ElfPath(path=path))
    elif action == "checksec":
        return await pwntools_checksec(ChecksecParams(path=path))
    elif action == "read":
        return await pwntools_elf_read(ElfReadParams(
            path=path, section=section, offset=offset, size=size,
        ))
    elif action == "sections":
        return await pwntools_elf_sections(ElfSectionsParams(
            path=path, filter_name=filter_name,
        ))
    elif action == "symbols":
        return await pwntools_elf_symbols(ElfSymbolsParams(
            path=path, pattern=pattern, type_filter=type_filter,
        ))
    elif action == "strings":
        return await pwntools_elf_strings(ElfStringsParams(
            path=path, min_length=min_length, section=section,
        ))
    elif action == "deps":
        return await pwntools_elf_deps(ElfDepsParams(
            path=path, resolve_versions=resolve_versions,
        ))
    elif action == "got":
        return await pwntools_elf_got(ElfPath(path=path))
    elif action == "plt":
        return await pwntools_elf_plt(ElfPath(path=path))
    elif action == "segments":
        return await pwntools_elf_segments(ElfPath(path=path))
    elif action == "relocs":
        return await pwntools_elf_relocs(ElfRelocsParams(
            path=path, type_filter=type_filter,
        ))
    elif action == "notes":
        return await pwntools_elf_notes(ElfPath(path=path))
    elif action == "diff":
        return await pwntools_elf_diff(ElfDiffParams(
            path_a=path, path_b=path_b, sections_only=sections_only,
        ))
    elif action == "search":
        return await pwntools_elf_search(ElfSearchParams(
            path=path, pattern=pattern, start=start, end=end,
        ))
    elif action == "patch":
        return await pwntools_elf_patch(ElfPatchParams(
            path=path, offset=offset or 0, **{"bytes": hex_bytes},
        ))
    elif action == "make":
        return await pwntools_make_elf(MakeElfParams(
            code=code, arch=arch, output=output or None,
        ))
    elif action == "entropy":
        return await pwntools_entropy(EntropyParams(
            path=path, offset=offset or 0, size=size,
        ))
    return f"Unknown action: {action}"


# ---------------------------------------------------------------------------
# 2. pwntools_rop — ROP operations (5 actions)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pwntools_rop(
    action: Literal[
        "find", "erope", "build_chain", "sigreturn", "fmtstr_payload",
    ],
    path: str = "",
    grep: str = "",
    depth: int = 6,
    count: int = 50,
    gadget_type: str = "syscall",
    target: str = "",
    args: str = "",
    arch: str = "amd64",
    rax: Optional[str] = None,
    rdi: Optional[str] = None,
    rsi: Optional[str] = None,
    rdx: Optional[str] = None,
    rip: Optional[str] = None,
    offset: int = 1,
    writes: str = "",
    numbwritten: int = 0,
) -> str:
    """ROP gadget search and chain building — find, erope, build_chain, sigreturn, fmtstr_payload."""
    if action == "find":
        return await pwntools_find_rop(RopSearchParams(
            path=path, grep=grep, depth=depth, count=count,
        ))
    elif action == "erope":
        return await pwntools_erope(ERopSearchParams(
            path=path, gadget_type=gadget_type,
        ))
    elif action == "build_chain":
        return await pwntools_build_rop_chain(BuildRopChainParams(
            path=path, target=target, args=args,
        ))
    elif action == "sigreturn":
        return await pwntools_sigreturn(SigreturnFrameParams(
            arch=arch, rax=rax, rdi=rdi, rsi=rsi, rdx=rdx, rip=rip,
        ))
    elif action == "fmtstr_payload":
        return await pwntools_fmtstr_payload(FmtStrPayloadParams(
            offset=offset, writes=writes, numbwritten=numbwritten,
        ))
    return f"Unknown action: {action}"


# ---------------------------------------------------------------------------
# 3. pwntools_shellcode — Shellcode (2 actions)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pwntools_shellcode(
    action: Literal["generate", "encode"],
    arch: str = "amd64",
    purpose: str = "sh",
    args: str = "",
    hex_bytes: str = "",
    encoder: str = "alphanumeric",
) -> str:
    """Shellcode generation and encoding — generate, encode."""
    if action == "generate":
        return await pwntools_shellcraft(ShellcodeParams(
            arch=arch, purpose=purpose, args=args,
        ))
    elif action == "encode":
        return await pwntools_enc(ShellcodeEncodeParams(
            hex_bytes=hex_bytes, arch=arch, encoder=encoder,
        ))
    return f"Unknown action: {action}"


# ---------------------------------------------------------------------------
# 4. pwntools_asm — Assembly/disassembly (2 actions)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pwntools_asm(
    action: Literal["disassemble", "assemble"],
    data: str = "",
    arch: str = "amd64",
) -> str:
    """Assembly and disassembly — disassemble, assemble."""
    if action == "disassemble":
        return await pwntools_disasm_bytes(DisasmParams(
            hex_data=data, arch=arch,
        ))
    elif action == "assemble":
        return await pwntools_asm_instructions(AsmParams(
            code=data, arch=arch,
        ))
    return f"Unknown action: {action}"


# ---------------------------------------------------------------------------
# 5. pwntools_pack — Pack/encode (6 actions)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pwntools_pack(
    action: Literal["pack", "unpack", "enhex", "unhex", "flat", "hexdump"],
    value: str = "",
    size: int = 8,
    endian: str = "little",
    data: str = "",
    hex_bytes: str = "",
    hex_str: str = "",
    hex_data: str = "",
    arch: str = "amd64",
    pack_size: int = 8,
) -> str:
    """Pack, unpack, hex encode/decode, flat, hexdump."""
    if action == "pack":
        return await pwntools_pack(PackParams(
            value=value, size=size, endian=endian,
        ))
    elif action == "unpack":
        return await pwntools_unpack(UnpackParams(
            hex_bytes=hex_bytes, size=size, endian=endian,
        ))
    elif action == "enhex":
        return await pwntools_enhex(EncodeHexParams(data=data))
    elif action == "unhex":
        return await pwntools_unhex(DecodeHexParams(hex_str=hex_str))
    elif action == "flat":
        return await pwntools_flat(FlatParams(
            values=value, arch=arch, endian=endian, pack_size=pack_size,
        ))
    elif action == "hexdump":
        return await pwntools_hexdump_data(HexDumpParams(hex_data=hex_data))
    return f"Unknown action: {action}"


# ---------------------------------------------------------------------------
# 6. pwntools_util — Utilities (9 actions)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pwntools_util(
    action: Literal[
        "cyclic", "cyclic_find", "rol", "ror", "bits", "align",
        "constgrep", "context", "log_level",
    ],
    value: str = "",
    count: int = 256,
    length: int = 256,
    shift: int = 1,
    bits: int = 64,
    bit: int = 0,
    set_to: int = -1,
    alignment: int = 0x1000,
    search: str = "",
    arch: str = "amd64",
    limit: int = 20,
    target_os: str = "",
    endian: str = "",
    log_level: str = "",
    level: str = "",
) -> str:
    """Utility operations — cyclic, cyclic_find, rol, ror, bits, align, constgrep, context, log_level."""
    if action == "cyclic":
        return await pwntools_cyclic(CyclicParams(count=count))
    elif action == "cyclic_find":
        return await pwntools_cyclic_find(CyclicFindParams(
            value=value, length=length,
        ))
    elif action == "rol":
        return await pwntools_rol(BitOpParams(
            value=int(value, 0) if isinstance(value, str) and value else 0,
            shift=shift, bits=bits,
        ))
    elif action == "ror":
        return await pwntools_ror(BitOpParams(
            value=int(value, 0) if isinstance(value, str) and value else 0,
            shift=shift, bits=bits,
        ))
    elif action == "bits":
        return await pwntools_bits(BitsParams(
            value=int(value, 0) if isinstance(value, str) and value else 0,
            bit=bit, set_to=set_to,
        ))
    elif action == "align":
        return await pwntools_align(AlignParams(
            value=int(value, 0) if isinstance(value, str) and value else 0,
            alignment=alignment,
        ))
    elif action == "constgrep":
        return await pwntools_constgrep(ConstGrepParams(
            search=search, arch=arch, limit=limit,
        ))
    elif action == "context":
        return await pwntools_context(ContextParams(
            arch=arch, os=target_os, endian=endian,
            log_level=log_level, bits=bits,
        ))
    elif action == "log_level":
        return await pwntools_log_level(level)
    return f"Unknown action: {action}"


# ---------------------------------------------------------------------------
# 7. pwntools_tube — Tubes (9 actions)
# ---------------------------------------------------------------------------
@mcp.tool()
async def pwntools_tube(
    action: Literal[
        "process", "remote", "send", "sendline",
        "recv", "recvline", "recvuntil", "close", "list",
    ],
    binary: str = "",
    args: str = "",
    host: str = "",
    port: int = 0,
    tube_id: str = "default",
    timeout: int = 30,
    data: str = "",
    nbytes: int = 4096,
    pattern: str = "",
    drop: bool = False,
) -> str:
    """Tube management — process, remote, send, sendline, recv, recvline, recvuntil, close, list."""
    if action == "process":
        return await pwntools_process(TubeProcessParams(
            binary=binary, args=args, tube_id=tube_id, timeout=timeout,
        ))
    elif action == "remote":
        return await pwntools_remote(TubeRemoteParams(
            host=host, port=port, tube_id=tube_id, timeout=timeout,
        ))
    elif action == "send":
        return await pwntools_tube_send(TubeSendParams(
            data=data, tube_id=tube_id,
        ))
    elif action == "sendline":
        return await pwntools_tube_sendline(TubeSendParams(
            data=data, tube_id=tube_id,
        ))
    elif action == "recv":
        return await pwntools_tube_recv(TubeRecvParams(
            nbytes=nbytes, tube_id=tube_id, timeout=timeout,
        ))
    elif action == "recvline":
        return await pwntools_tube_recvline(TubeRecvParams(
            nbytes=nbytes, tube_id=tube_id, timeout=timeout,
        ))
    elif action == "recvuntil":
        return await pwntools_tube_recvuntil(TubeRecvUntilParams(
            pattern=pattern, tube_id=tube_id, timeout=timeout, drop=drop,
        ))
    elif action == "close":
        return await pwntools_tube_close(TubeBaseParams(tube_id=tube_id))
    elif action == "list":
        return await pwntools_tube_list()
    return f"Unknown action: {action}"




import json
from typing import Literal, Optional

from edb_debugger_mcp._mcp import mcp, backend, GDBBackendError


@mcp.tool(name="edb_exec")
async def edb_exec(
    action: Literal[
        "load_program", "attach", "detach", "kill", "run",
        "continue_exec", "interrupt", "restart", "continue_to_address", "follow_fork",
    ],
    path: str = "",
    args: str = "",
    pid: int = 0,
    address: str = "",
    mode: str = "",
) -> str:
    try:
        if action == "load_program":
            return await backend.load_program(path, args)
        elif action == "attach":
            return await backend.attach(pid)
        elif action == "detach":
            return await backend.detach()
        elif action == "kill":
            return await backend.kill()
        elif action == "run":
            return await backend.run()
        elif action == "continue_exec":
            return await backend.continue_exec()
        elif action == "interrupt":
            return await backend.interrupt()
        elif action == "restart":
            return await backend.restart()
        elif action == "continue_to_address":
            loc = await backend.continue_to_address(address)
            return json.dumps(loc, indent=2)
        elif action == "follow_fork":
            return await backend.follow_fork(mode)
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_step")
async def edb_step(
    action: Literal[
        "step_into", "step_over", "step_out",
        "step_instruction", "step_over_instruction",
        "reverse_step", "reverse_continue",
    ],
    count: int = 1,
) -> str:
    try:
        if action == "step_into":
            loc = await backend.step_into()
            return json.dumps(loc, indent=2)
        elif action == "step_over":
            loc = await backend.step_over()
            return json.dumps(loc, indent=2)
        elif action == "step_out":
            loc = await backend.step_out()
            return json.dumps(loc, indent=2)
        elif action == "step_instruction":
            loc = await backend.step_instruction(count)
            return json.dumps(loc, indent=2) if isinstance(loc, dict) else str(loc)
        elif action == "step_over_instruction":
            loc = await backend.step_over_instruction(count)
            return json.dumps(loc, indent=2) if isinstance(loc, dict) else str(loc)
        elif action == "reverse_step":
            return await backend.reverse_step(count)
        elif action == "reverse_continue":
            return await backend.reverse_continue()
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_trace")
async def edb_trace(
    action: Literal["trace_start", "trace_stop", "trace_show"],
    address: str = "",
    max_size: int = 1024,
) -> str:
    try:
        if action == "trace_start":
            return await backend.trace_start(address, max_size)
        elif action == "trace_stop":
            return await backend.trace_stop()
        elif action == "trace_show":
            return await backend.trace_show()
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_breakpoint")
async def edb_breakpoint(
    action: Literal[
        "set", "set_hardware", "set_watchpoint",
        "remove", "enable", "disable", "list",
        "set_condition", "set_ignore_count", "set_log",
        "export", "import", "commands", "list_types",
    ],
    location: str = "",
    condition: str = "",
    expression: str = "",
    watch_type: str = "write",
    number: int = 0,
    count: int = 0,
    log_message: str = "",
    file_path: str = "",
    commands: Optional[list[str]] = None,
) -> str:
    try:
        if action == "set":
            bkpt = await backend.set_breakpoint(location, condition)
            num = bkpt.get("number", "?")
            addr = bkpt.get("addr", location)
            func = f" at {bkpt['func']}" if bkpt.get("func") else ""
            return f"Breakpoint {num} at {addr}{func}"
        elif action == "set_hardware":
            bkpt = await backend.set_hardware_breakpoint(location)
            num = bkpt.get("number", "?")
            addr = bkpt.get("addr", location)
            return f"Hardware breakpoint {num} at {addr}"
        elif action == "set_watchpoint":
            wp = await backend.set_watchpoint(expression, watch_type)
            return json.dumps(wp) if wp else f"Watchpoint set on {expression}"
        elif action == "remove":
            return await backend.remove_breakpoint(number)
        elif action == "enable":
            return await backend.enable_breakpoint(number)
        elif action == "disable":
            return await backend.disable_breakpoint(number)
        elif action == "list":
            return await backend.list_breakpoints()
        elif action == "set_condition":
            return await backend.set_breakpoint_condition(number, condition)
        elif action == "set_ignore_count":
            return await backend.set_breakpoint_ignore_count(number, count)
        elif action == "set_log":
            return await backend.set_conditional_log_breakpoint(location, log_message)
        elif action == "export":
            return await backend.breakpoint_export(file_path)
        elif action == "import":
            return await backend.breakpoint_import(file_path)
        elif action == "commands":
            cmds = commands or []
            return await backend.breakpoint_commands(number, cmds)
        elif action == "list_types":
            return await backend.list_breakpoint_types()
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_register")
async def edb_register(
    action: Literal[
        "get_all", "get", "set", "dump",
        "fpu", "simd", "eflags", "enum",
    ],
    name: str = "",
    value: str = "",
) -> str:
    try:
        if action == "get_all":
            regs = await backend.get_registers()
            return json.dumps(regs, indent=2)
        elif action == "get":
            val = await backend.get_register(name)
            return f"{name} = {val}"
        elif action == "set":
            return await backend.set_register(name, value)
        elif action == "dump":
            regs = await backend.get_registers()
            lines = ["| Register | Value |", "|----------|-------|"]
            for rname in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "cs", "ss", "ds", "es", "fs", "gs"):
                val = regs.get(rname, "")
                if val:
                    lines.append(f"| {rname} | {val} |")
            return "\n".join(lines)
        elif action == "fpu":
            return await backend.get_fpu_state()
        elif action == "simd":
            return await backend.get_simd_state()
        elif action == "eflags":
            return await backend.get_eflags()
        elif action == "enum":
            return await backend.enum_registers()
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_memory")
async def edb_memory(
    action: Literal[
        "read", "write", "write_bytes",
        "search", "search_instructions",
        "get_map", "get_section_info", "read_as",
        "fill", "compare", "dump_to_file",
        "set_permissions", "get_region_info",
        "compare_sections", "apply_patches",
    ],
    address: str = "",
    count: int = 128,
    data: str = "",
    hex_bytes: str = "",
    pattern: str = "",
    length: str = "",
    range_start: str = "",
    range_end: str = "",
    module_name: str = "",
    data_type: str = "uint32",
    byte_value: str = "",
    address1: str = "",
    address2: str = "",
    size: int = 4096,
    file_path: str = "",
    permissions: str = "",
    output_path: str = "",
) -> str:
    try:
        if action == "read":
            return await backend.hex_dump(address, count)
        elif action == "write":
            return await backend.write_memory(address, data)
        elif action == "write_bytes":
            return await backend.write_memory_bytes(address, hex_bytes)
        elif action == "search":
            return await backend.search_memory(pattern, address, length)
        elif action == "search_instructions":
            return await backend.search_instructions(pattern, range_start, range_end)
        elif action == "get_map":
            return await backend.get_memory_map()
        elif action == "get_section_info":
            return await backend.get_section_info(module_name)
        elif action == "read_as":
            return await backend.read_memory_as(address, data_type, count)
        elif action == "fill":
            return await backend.fill_memory(address, byte_value, count)
        elif action == "compare":
            return await backend.compare_memory(address1, address2, count)
        elif action == "dump_to_file":
            return await backend.dump_memory_to_file(address, size, file_path)
        elif action == "set_permissions":
            return await backend.set_memory_permissions(address, permissions, size)
        elif action == "get_region_info":
            return await backend.get_memory_region_info()
        elif action == "compare_sections":
            return await backend.compare_sections()
        elif action == "apply_patches":
            return await backend.apply_patches_to_file(output_path)
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_disassemble")
async def edb_disassemble(
    action: Literal[
        "disassemble", "disassemble_range",
        "get_current", "instruction_detail",
        "assemble", "analyze_calls",
    ],
    location: str = "",
    count: int = 10,
    start: str = "",
    end: str = "",
    address: str = "",
    instruction: str = "",
) -> str:
    try:
        if action == "disassemble":
            return await backend.disassemble(location, count)
        elif action == "disassemble_range":
            return await backend.disassemble_range(start, end)
        elif action == "get_current":
            inst = await backend.get_current_instruction()
            return inst if inst else "No instruction at current PC"
        elif action == "instruction_detail":
            return await backend.instruction_detail(address)
        elif action == "assemble":
            return await backend.assemble(address, instruction)
        elif action == "analyze_calls":
            return await backend.analyze_calls_at(address)
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_stack")
async def edb_stack(
    action: Literal[
        "get", "get_frame", "backtrace",
        "push", "pop", "modify", "scan_retaddr",
    ],
    count: int = 16,
    frame_level: int = 0,
    value: str = "",
    depth: int = 64,
) -> str:
    try:
        if action == "get":
            return await backend.get_stack(count)
        elif action == "get_frame":
            return await backend.get_stack_frame(frame_level)
        elif action == "backtrace":
            return await backend.get_backtrace(count)
        elif action == "push":
            return await backend.stack_push(value)
        elif action == "pop":
            return await backend.stack_pop()
        elif action == "modify":
            return await backend.stack_modify(value)
        elif action == "scan_retaddr":
            return await backend.scan_stack_for_retaddr(depth)
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_symbol")
async def edb_symbol(
    action: Literal[
        "lookup", "function_info", "function_bounds",
        "list_functions", "find_references", "string_references",
        "get_xrefs", "goto_start", "entry_point",
        "generate_symbols", "binary_info",
    ],
    name: str = "",
    address: str = "",
    string_or_address: str = "",
    path: str = "",
) -> str:
    try:
        if action == "lookup":
            return await backend.lookup_symbol(name)
        elif action == "function_info":
            return await backend.get_function_info(name)
        elif action == "function_bounds":
            return await backend.get_function_bounds(name)
        elif action == "list_functions":
            return await backend.list_functions()
        elif action == "find_references":
            return await backend.find_references(address)
        elif action == "string_references":
            return await backend.string_references(string_or_address)
        elif action == "get_xrefs":
            return await backend.get_function_xrefs(address)
        elif action == "goto_start":
            return await backend.goto_function_start(address)
        elif action == "entry_point":
            ep = await backend.get_entry_point()
            return f"Entry point: {ep}"
        elif action == "generate_symbols":
            return await backend.generate_symbols(path)
        elif action == "binary_info":
            return await backend.get_binary_info()
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_expression")
async def edb_expression(
    action: Literal[
        "evaluate", "get_string", "find_strings",
        "get_variable", "set_variable",
        "get_arguments", "get_locals", "watch",
    ],
    expression: str = "",
    address: str = "",
    max_len: int = 256,
    length: str = "",
    name: str = "",
    value: str = "",
) -> str:
    try:
        if action == "evaluate":
            return await backend.evaluate(expression)
        elif action == "get_string":
            return await backend.get_string(address, max_len)
        elif action == "find_strings":
            return await backend.find_strings(address, length)
        elif action == "get_variable":
            val = await backend.get_variable(name)
            return f"{name} = {val}"
        elif action == "set_variable":
            return await backend.set_variable(name, value)
        elif action == "get_arguments":
            return await backend.get_arguments()
        elif action == "get_locals":
            return await backend.get_locals()
        elif action == "watch":
            return await backend.watch_expression(expression)
        return f"Unknown action: {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"

import json
from typing import Literal, Optional

from edb_debugger_mcp._mcp import mcp, backend, GDBBackendError


@mcp.tool(name="edb_debug_info")
async def edb_debug_info(
    action: Literal["list_source", "list_source_files", "ptype", "whatis", "frame_info"],
    file: Optional[str] = None,
    line: int = 1,
    count: int = 20,
    expression: Optional[str] = None,
    frame_level: int = 0,
) -> str:
    try:
        if action == "list_source":
            if file is None:
                return "Error (list_source): file argument is required"
            return await backend.get_source(file, line, count)
        elif action == "list_source_files":
            return await backend.list_source_files()
        elif action == "ptype":
            if expression is None:
                return "Error (ptype): expression argument is required"
            return await backend.ptype(expression)
        elif action == "whatis":
            if expression is None:
                return "Error (whatis): expression argument is required"
            return await backend.whatis(expression)
        elif action == "frame_info":
            return await backend.get_frame_info(frame_level)
        else:
            return f"Error (edb_debug_info): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_thread")
async def edb_thread(
    action: Literal["list", "get_current", "set_current", "inferior_info"],
    thread_id: Optional[int] = None,
) -> str:
    try:
        if action == "list":
            return await backend.list_threads()
        elif action == "get_current":
            info = await backend.get_current_thread()
            return json.dumps(info, indent=2) if info else "No thread info"
        elif action == "set_current":
            if thread_id is None:
                return "Error (set_current): thread_id argument is required"
            return await backend.set_current_thread(thread_id)
        elif action == "inferior_info":
            return await backend.inferior_info()
        else:
            return f"Error (edb_thread): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_module")
async def edb_module(
    action: Literal["list_modules", "arch_info", "list_plugins", "list_features"],
) -> str:
    try:
        if action == "list_modules":
            return await backend.list_modules()
        elif action == "arch_info":
            return await backend.get_arch_info()
        elif action == "list_plugins":
            return await backend.list_plugins()
        elif action == "list_features":
            return await backend.list_features()
        else:
            return f"Error (edb_module): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_analysis")
async def edb_analysis(
    action: Literal["analyze_region", "analyze_heap", "find_rop_gadgets", "analyze_basic_blocks", "generate_cfg", "exploit_generate", "process_strings"],
    address: str = "",
    size: int = 256,
    depth: int = 2,
    count: int = 100,
    binary_path: Optional[str] = None,
    offset: int = 0,
    cmd: str = "/bin/sh",
    save_path: str = "",
    arch: str = "amd64",
    min_length: int = 4,
) -> str:
    try:
        if action == "analyze_region":
            if not address:
                return "Error (analyze_region): address argument is required"
            return await backend.analyze_region(address, size)
        elif action == "analyze_heap":
            return await backend.analyze_heap()
        elif action == "find_rop_gadgets":
            return await backend.find_rop_gadgets(address, depth, count)
        elif action == "analyze_basic_blocks":
            if not address:
                return "Error (analyze_basic_blocks): address argument is required"
            return await backend.analyze_basic_blocks(address, size)
        elif action == "generate_cfg":
            if not address:
                return "Error (generate_cfg): address argument is required"
            return await backend.generate_cfg(address, size)
        elif action == "exploit_generate":
            if not binary_path:
                return "Error (exploit_generate): binary_path argument is required"
            return await backend.exploit_generate(binary_path, offset, cmd, save_path, arch)
        elif action == "process_strings":
            return await backend.process_strings(min_length)
        else:
            return f"Error (edb_analysis): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_annotation")
async def edb_annotation(
    action: Literal["add_comment", "list_comments", "remove_comment", "add_bookmark", "list_bookmarks", "remove_bookmark", "label_address"],
    address: Optional[str] = None,
    comment: Optional[str] = None,
    name: Optional[str] = None,
    label: Optional[str] = None,
) -> str:
    try:
        if action == "add_comment":
            if address is None or comment is None:
                return "Error (add_comment): address and comment arguments are required"
            return await backend.add_comment(address, comment)
        elif action == "list_comments":
            return await backend.list_comments()
        elif action == "remove_comment":
            if address is None:
                return "Error (remove_comment): address argument is required"
            return await backend.remove_comment(address)
        elif action == "add_bookmark":
            if name is None or address is None:
                return "Error (add_bookmark): name and address arguments are required"
            return await backend.add_bookmark(name, address)
        elif action == "list_bookmarks":
            return await backend.list_bookmarks()
        elif action == "remove_bookmark":
            if name is None:
                return "Error (remove_bookmark): name argument is required"
            return await backend.remove_bookmark(name)
        elif action == "label_address":
            if address is None or label is None:
                return "Error (label_address): address and label arguments are required"
            return await backend.label_address(address, label)
        else:
            return f"Error (edb_annotation): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_session")
async def edb_session(
    action: Literal["status", "properties", "stop_reason", "dump_state", "export_state", "session_save", "session_load", "set_working_directory", "send_signal", "core_dump", "remote_connect", "remote_arch", "remote_info", "patch_history"],
    file_path: Optional[str] = None,
    directory: Optional[str] = None,
    signum: Optional[int] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    extended: bool = False,
    clear: bool = False,
) -> str:
    try:
        if action == "status":
            status = await backend.status()
            return json.dumps(status, indent=2)
        elif action == "properties":
            return await backend.get_process_properties()
        elif action == "stop_reason":
            return await backend.get_stop_reason()
        elif action == "dump_state":
            return await backend.dump_state()
        elif action == "export_state":
            return await backend.export_state()
        elif action == "session_save":
            if file_path is None:
                return "Error (session_save): file_path argument is required"
            return await backend.session_save(file_path)
        elif action == "session_load":
            if file_path is None:
                return "Error (session_load): file_path argument is required"
            return await backend.session_load(file_path)
        elif action == "set_working_directory":
            if directory is None:
                return "Error (set_working_directory): directory argument is required"
            return await backend.set_working_directory(directory)
        elif action == "send_signal":
            if signum is None:
                return "Error (send_signal): signum argument is required"
            return await backend.send_signal(signum)
        elif action == "core_dump":
            return await backend.generate_core_dump(file_path or "")
        elif action == "remote_connect":
            if host is None or port is None:
                return "Error (remote_connect): host and port arguments are required"
            return await backend.remote_connect(host, port, extended)
        elif action == "remote_arch":
            return await backend.remote_arch()
        elif action == "remote_info":
            return await backend.remote_info()
        elif action == "patch_history":
            if clear:
                return await backend.clear_patch_history()
            else:
                return await backend.get_patch_history()
        else:
            return f"Error (edb_session): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_patch")
async def edb_patch(
    action: Literal["file_offset_to_va", "va_to_file_offset", "nop_range", "jump_to_address", "call_function", "view_at_address", "binary_diff", "binary_string_convert", "compare_snapshot", "pipeline_run"],
    offset: Optional[int] = None,
    address: Optional[str] = None,
    start_address: Optional[str] = None,
    end_address: Optional[str] = None,
    function_expr: Optional[str] = None,
    hex_str: str = "",
    ascii_str: str = "",
    utf16_str: str = "",
    label: str = "",
    binary: Optional[str] = None,
    breakpoint: str = "",
    args: str = "",
    dump_registers: bool = True,
) -> str:
    try:
        if action == "file_offset_to_va":
            if offset is None:
                return "Error (file_offset_to_va): offset argument is required"
            return await backend.file_offset_to_va(offset)
        elif action == "va_to_file_offset":
            if address is None:
                return "Error (va_to_file_offset): address argument is required"
            return await backend.va_to_file_offset(address)
        elif action == "nop_range":
            if start_address is None or end_address is None:
                return "Error (nop_range): start_address and end_address arguments are required"
            return await backend.nop_range(start_address, end_address)
        elif action == "jump_to_address":
            if address is None:
                return "Error (jump_to_address): address argument is required"
            return await backend.jump_to_address(address)
        elif action == "call_function":
            if function_expr is None:
                return "Error (call_function): function_expr argument is required"
            return await backend.call_function(function_expr)
        elif action == "view_at_address":
            if address is None:
                return "Error (view_at_address): address argument is required"
            return await backend.view_at_address(address)
        elif action == "binary_diff":
            return await backend.binary_diff()
        elif action == "binary_string_convert":
            return await backend.binary_string_convert(hex_str, ascii_str, utf16_str)
        elif action == "compare_snapshot":
            return await backend.compare_snapshot(label)
        elif action == "pipeline_run":
            if binary is None:
                return "Error (pipeline_run): binary argument is required"
            return await backend.pipeline_run(binary, breakpoint, args, dump_registers)
        else:
            return f"Error (edb_patch): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_config")
async def edb_config(
    action: Literal["configure", "show", "disable_aslr", "disable_lazy_binding", "signal_handling", "list_signals", "set_catchpoint", "set_tty", "set_debug_output", "load_symbol_file", "get_changed_registers"],
    setting: str = "",
    value: str = "",
    disable: bool = True,
    signal: str = "",
    action_param: str = "",
    event: str = "",
    condition: str = "",
    tty_path: Optional[str] = None,
    category: str = "",
    enable: bool = True,
    file_path: Optional[str] = None,
    address: str = "",
) -> str:
    try:
        if action == "configure":
            if not setting:
                return "Error (configure): setting argument is required"
            return await backend.configure_debugger(setting, value)
        elif action == "show":
            return await backend.show_configuration(setting)
        elif action == "disable_aslr":
            return await backend.set_disable_aslr(disable)
        elif action == "disable_lazy_binding":
            return await backend.set_disable_lazy_binding(disable)
        elif action == "signal_handling":
            if not signal:
                return "Error (signal_handling): signal argument is required"
            return await backend.signal_handling(signal, action_param)
        elif action == "list_signals":
            return await backend.list_signals(signal)
        elif action == "set_catchpoint":
            if not event:
                return "Error (set_catchpoint): event argument is required"
            return await backend.set_catchpoint(event, condition)
        elif action == "set_tty":
            if tty_path is None:
                return "Error (set_tty): tty_path argument is required"
            return await backend.set_tty(tty_path)
        elif action == "set_debug_output":
            return await backend.set_debug_output(category, enable)
        elif action == "load_symbol_file":
            if file_path is None:
                return "Error (load_symbol_file): file_path argument is required"
            return await backend.load_symbol_file(file_path, address)
        elif action == "get_changed_registers":
            return await backend.get_changed_registers()
        else:
            return f"Error (edb_config): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"


@mcp.tool(name="edb_environment")
async def edb_environment(
    action: Literal["set_env", "unset_env", "get_env", "set_logging", "execute_gdb_command"],
    name: Optional[str] = None,
    value: Optional[str] = None,
    file_path: Optional[str] = None,
    enable: bool = True,
    command: Optional[str] = None,
    timeout: int = 10,
) -> str:
    try:
        if action == "set_env":
            if name is None or value is None:
                return "Error (set_env): name and value arguments are required"
            return await backend.set_environment_variable(name, value)
        elif action == "unset_env":
            if name is None:
                return "Error (unset_env): name argument is required"
            return await backend.unset_environment_variable(name)
        elif action == "get_env":
            return await backend.get_environment()
        elif action == "set_logging":
            if file_path is None:
                return "Error (set_logging): file_path argument is required"
            return await backend.set_session_logging(file_path, enable)
        elif action == "execute_gdb_command":
            if command is None:
                return "Error (execute_gdb_command): command argument is required"
            return await backend.execute_gdb_command(command, timeout)
        else:
            return f"Error (edb_environment): Unknown action {action}"
    except GDBBackendError as e:
        return f"Error ({action}): {e}"
    except Exception as e:
        return f"Error ({action}): Unexpected error: {e}"
