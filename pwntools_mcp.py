"""Pwntools integration for EDB MCP — binary analysis, ROP, shellcode, packing, cyclic patterns."""

import json
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict

from edb_debugger_mcp import mcp


def _pwntools_available() -> bool:
    try:
        import pwn  # noqa: F401
        return True
    except ImportError:
        return False


class ElfPath(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)


class RopSearchParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    grep: Optional[str] = Field(default="", description="Filter gadgets (e.g. 'pop rdi', 'syscall')")
    depth: int = Field(default=6, description="Max instruction depth", ge=1, le=20)
    count: int = Field(default=50, description="Max results", ge=1, le=500)


class ShellcodeParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    arch: str = Field(default="amd64", description="Architecture: amd64, i386, aarch64, arm")
    purpose: str = Field(default="sh", description="Shellcode type: sh, execve, bind_shell, reverse_shell, read_file, write_file")
    args: Optional[str] = Field(default="", description="Args for shellcode (e.g., /bin/sh, port)")


class PackParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    value: str = Field(..., description="Value to pack (int like 0xdeadbeef or hex string)")
    size: int = Field(default=8, description="Byte size: 1, 2, 4, or 8", ge=1, le=8)
    endian: str = Field(default="little", description="Endianness: little or big")


class UnpackParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hex_bytes: str = Field(..., description="Hex bytes to unpack (e.g., 'ef be ad de')")
    size: int = Field(default=8, description="Byte size: 1, 2, 4, or 8", ge=1, le=8)
    endian: str = Field(default="little", description="Endianness: little or big")


class CyclicParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    count: int = Field(default=256, description="Number of bytes to generate", ge=1, le=10000)


class CyclicFindParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    value: str = Field(..., description="Value to find (hex address like 0x61616162 or sub-pattern)")
    length: int = Field(default=256, description="Cyclic pattern length to search", ge=1, le=10000)


class HexDumpParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hex_data: str = Field(..., description="Hex string of bytes to dump (e.g., 'deadbeef0102')")


class FmtStrPayloadParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    offset: int = Field(..., description="Format string offset on stack", ge=1)
    writes: str = Field(..., description="Writes as JSON dict: {addr: value, ...} or {addr: (value, size), ...}")
    numbwritten: int = Field(default=0, description="Bytes already written by printf")


class DisasmParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hex_data: str = Field(..., description="Hex bytes to disassemble (e.g., '90 90 cc')")
    arch: str = Field(default="amd64", description="Architecture: amd64, i386, arm, aarch64, mips")


class AsmParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    code: str = Field(..., description="Assembly instructions (e.g., 'mov eax, 0; ret')")
    arch: str = Field(default="amd64", description="Architecture: amd64, i386, arm, aarch64")


class BuildRopChainParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    target: str = Field(..., description="Target address or function (e.g., 'system', '0x401234')")
    args: Optional[str] = Field(default="", description="Arguments for the target call (e.g., '/bin/sh')")


def _import_pwn():
    import pwn
    pwn.context.log_level = "error"
    return pwn


@mcp.tool(
    name="pwntools_analyze_elf",
    annotations={"title": "Analyze ELF Binary", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_analyze_elf(params: ElfPath) -> str:
    '''Analyze an ELF binary using pwntools — entry point, PIE/NX/RELRO/Canary, sections, symbols, PLT/GOT, segments.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        lines = [f"=== ELF Analysis: {params.path} ===", ""]

        lines.append(f"  Arch:     {elf.arch}")
        lines.append(f"  Bits:     {elf.bits}")
        lines.append(f"  Endian:   {elf.endian}")
        lines.append(f"  Entry:    {hex(elf.entry)}")
        lines.append(f"  PIE:      {elf.pie}")
        lines.append(f"  NX:       {elf.execstack}")
        relro = elf.relro if elf.relro else "None"
        lines.append(f"  RELRO:    {relro}")
        lines.append(f"  Canary:   {elf.canary}")
        lines.append(f"  ASLR:     {'Dangerous (no PIE)' if not elf.pie else 'Enabled (PIE)'}")
        lines.append("")

        lines.append(f"  Sections ({len(list(elf.sections))}):")
        for sec in elf.sections[:20]:
            name = sec.name if sec.name else "(unnamed)"
            if sec.header.sh_addr:
                lines.append(f"    {name:20s} {hex(sec.header.sh_addr):18s} size={hex(sec.header.sh_size)}")
        if len(list(elf.sections)) > 20:
            lines.append(f"    ... and {len(list(elf.sections)) - 20} more")

        lines.append("")
        lines.append(f"  Segments ({len(list(elf.segments))}):")
        for seg in elf.segments:
            try:
                ptype = seg.header.p_type
                p_vaddr = seg.header.p_vaddr
                p_memsz = seg.header.p_memsz
                p_flags = seg.header.p_flags
            except AttributeError:
                continue
            if ptype == "PT_LOAD":
                f = ""
                if p_flags & 4: f += "R"
                if p_flags & 2: f += "W"
                if p_flags & 1: f += "X"
                lines.append(f"    LOAD {hex(p_vaddr):18s} size={hex(p_memsz):10s} flags={f}")
            elif ptype == "PT_GNU_STACK":
                lines.append(f"    GNU_STACK flags={'RWE' if p_flags & 1 else 'RW'}")

        lines.append("")
        plt_names = list(elf.plt.keys())
        if plt_names:
            lines.append(f"  PLT entries ({len(plt_names)}):")
            for name in sorted(plt_names)[:15]:
                lines.append(f"    {name:20s} @ {hex(elf.plt[name])}")
            if len(plt_names) > 15:
                lines.append(f"    ... and {len(plt_names) - 15} more")

        got_names = list(elf.got.keys())
        if got_names:
            lines.append(f"  GOT entries ({len(got_names)}):")
            for name in sorted(got_names)[:15]:
                lines.append(f"    {name:20s} @ {hex(elf.got[name])}")
            if len(got_names) > 15:
                lines.append(f"    ... and {len(got_names) - 15} more")

        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_find_rop",
    annotations={"title": "Find ROP Gadgets", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_find_rop(params: RopSearchParams) -> str:
    '''Search for ROP gadgets in an ELF binary using pwntools ROP engine.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        rop = pwn.ROP(elf)
        gadgets = rop.gadgets

        if not gadgets:
            return "No ROP gadgets found (binary might be statically stripped or too small)"

        gadget_list = list(gadgets.items())
        filtered = []
        for addr, g in gadget_list:
            insns = "; ".join(g.insns)
            if params.grep:
                if params.grep.lower() in insns.lower():
                    filtered.append((addr, insns))
            else:
                filtered.append((addr, insns))

        count = min(len(filtered), params.count)
        result = [f"ROP gadgets in {params.path} (showing {count}/{len(filtered)}):", ""]
        for i, (addr, insns) in enumerate(filtered[:count]):
            result.append(f"  {hex(addr)}: {insns}")

        result.append("")
        result.append(f"Total gadgets: {len(gadgets)}, filtered: {len(filtered)}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_shellcraft",
    annotations={"title": "Generate Shellcode", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_shellcraft(params: ShellcodeParams) -> str:
    '''Generate shellcode using pwntools shellcraft module.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch, os="linux")
        sc = pwn.shellcraft

        def _to_bytes(val):
            if isinstance(val, bytes):
                return val
            return val.encode("latin-1")

        purpose = params.purpose
        if purpose == "sh":
            code = _to_bytes(sc.sh())
            desc = "execve('/bin/sh', 0, 0)"
        elif purpose == "execve":
            cmd = params.args or "/bin/sh"
            code = _to_bytes(sc.execve(cmd))
            desc = f"execve('{cmd}', 0, 0)"
        elif purpose == "bind_shell":
            port = int(params.args) if params.args else 4444
            code = _to_bytes(sc.bindsh(port))
            desc = f"bind shell on port {port}"
        elif purpose == "reverse_shell":
            host_port = params.args.split() if params.args else ["127.0.0.1", "4444"]
            host = host_port[0] if len(host_port) > 0 else "127.0.0.1"
            port = int(host_port[1]) if len(host_port) > 1 else 4444
            code = _to_bytes(sc.connect(host, port))
            desc = f"reverse shell to {host}:{port}"
        elif purpose == "read_file":
            fpath = params.args or "/etc/passwd"
            code = _to_bytes(sc.cat(fpath))
            desc = f"read file: {fpath}"
        elif purpose == "write_file":
            parts = params.args.split(maxsplit=1) if params.args else ["/tmp/out", "data"]
            fpath = parts[0]
            data = parts[1] if len(parts) > 1 else "pwned"
            code = _to_bytes(sc.writeto(fpath, data))
            desc = f"write '{data}' to {fpath}"
        else:
            code = _to_bytes(sc.sh())
            desc = f"unknown purpose '{purpose}', defaulting to /bin/sh"

        hex_str = code.hex()
        asm_lines = pwn.disasm(code)
        result = [
            f"=== Shellcode ({desc}) ===",
            f"  Architecture: {params.arch}",
            f"  Length: {len(code)} bytes",
            "",
            "  Hex:",
            f"    {hex_str}",
            "",
            "  Disassembly:",
        ]
        for line in asm_lines.split("\n")[:20]:
            result.append(f"    {line}")
        remaining = len(asm_lines.split("\n")) - 20
        if remaining > 0:
            result.append(f"    ... ({remaining} more lines)")

        result.append("")
        hex_bytes = " ".join(f"\\x{b:02x}" for b in code)
        result.append(f'  C-array: unsigned char code[] = {{" \\\n    {hex_bytes}"}};')
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_pack",
    annotations={"title": "Pack Integer", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_pack(params: PackParams) -> str:
    '''Pack an integer into bytes (e.g., p64, p32, p16).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        val = int(params.value, 0)
        pack_map = {1: pwn.p8, 2: pwn.p16, 4: pwn.p32, 8: pwn.p64}
        fn = pack_map.get(params.size)
        if not fn:
            return f"Error: unsupported size {params.size}, use 1, 2, 4, or 8"
        packed = fn(val, endian=params.endian)
        hex_str = packed.hex()
        return json.dumps({
            "value": params.value,
            "int": val,
            "size": params.size,
            "endian": params.endian,
            "packed_hex": hex_str,
            "packed_repr": " ".join(f"{b:02x}" for b in packed),
            "length": len(packed),
        }, indent=2)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_unpack",
    annotations={"title": "Unpack Bytes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_unpack(params: UnpackParams) -> str:
    '''Unpack bytes into an integer (e.g., u64, u32, u16).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        data = bytes.fromhex(params.hex_bytes.replace(" ", "").replace("\\x", ""))
        unpack_map = {1: pwn.u8, 2: pwn.u16, 4: pwn.u32, 8: pwn.u64}
        fn = unpack_map.get(params.size)
        if not fn:
            return f"Error: unsupported size {params.size}"
        val = fn(data, endian=params.endian)
        return json.dumps({
            "hex_bytes": params.hex_bytes,
            "int": val,
            "hex": hex(val),
            "size": params.size,
            "endian": params.endian,
        }, indent=2)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_cyclic",
    annotations={"title": "Generate Cyclic Pattern", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_cyclic(params: CyclicParams) -> str:
    '''Generate a cyclic pattern for buffer overflow offset discovery.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        pattern = pwn.cyclic(params.count)
        result = [
            f"=== Cyclic pattern ({params.count} bytes) ===",
            "",
            pattern.decode("latin-1"),
            "",
            "Usage:",
            "  Inject this pattern into the program.",
            "  When it crashes, find the value at $rip (or the overwritten return address).",
            "  Use pwntools_cyclic_find with that value to get the offset.",
        ]
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_cyclic_find",
    annotations={"title": "Find Cyclic Offset", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_cyclic_find(params: CyclicFindParams) -> str:
    '''Find the offset of a value within a cyclic pattern.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        val = int(params.value, 0) if params.value.startswith("0x") else params.value
        offset = pwn.cyclic_find(val, n=params.length)
        if offset == -1:
            return f"Value {params.value} not found in cyclic pattern (length={params.length})"
        return json.dumps({
            "value": params.value,
            "offset": offset,
            "meaning": f"Buffer overflow offset is {offset} bytes (before return address overwrite)"
        }, indent=2)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_hexdump",
    annotations={"title": "Hex Dump", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_hexdump_data(params: HexDumpParams) -> str:
    '''Display a formatted hex dump using pwntools hexdump styling.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        data = bytes.fromhex(params.hex_data.replace(" ", "").replace("\\x", ""))
        dump = pwn.hexdump(data)
        return f"=== Hex dump ({len(data)} bytes) ===\n\n{dump}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_fmtstr_payload",
    annotations={"title": "Generate Format String Payload", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_fmtstr_payload(params: FmtStrPayloadParams) -> str:
    '''Generate a format string exploit payload for arbitrary writes.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        writes = json.loads(params.writes)
        converted = {}
        for k, v in writes.items():
            if isinstance(k, str):
                try:
                    k = int(k, 0)
                except ValueError:
                    pass
            converted[k] = v
        writes = converted
        payload = pwn.fmtstr_payload(params.offset, writes, numbwritten=params.numbwritten)
        return json.dumps({
            "offset": params.offset,
            "writes": writes,
            "numbwritten": params.numbwritten,
            "payload_hex": payload.hex(),
            "payload_bytes": " ".join(f"{b:02x}" for b in payload),
            "payload_length": len(payload),
        }, indent=2)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_disasm",
    annotations={"title": "Disassemble Bytes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_disasm_bytes(params: DisasmParams) -> str:
    '''Disassemble raw hex bytes into assembly instructions using pwntools + capstone.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch, os="linux")
        data = bytes.fromhex(params.hex_data.replace(" ", "").replace("\\x", ""))
        asm = pwn.disasm(data)
        return f"=== Disassembly ({params.arch}) ===\n\n{asm}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_asm",
    annotations={"title": "Assemble Instructions", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_asm_instructions(params: AsmParams) -> str:
    '''Assemble assembly instructions into hex bytes using pwntools + keystone.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch, os="linux")
        code = pwn.asm(params.code)
        hex_str = code.hex()
        asm_result = pwn.disasm(code)
        return json.dumps({
            "code": params.code,
            "arch": params.arch,
            "hex": hex_str,
            "bytes": " ".join(f"{b:02x}" for b in code),
            "length": len(code),
            "disassembly": asm_result.strip(),
        }, indent=2)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_build_rop_chain",
    annotations={"title": "Build ROP Chain", "readOnlyHint": True, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_build_rop_chain(params: BuildRopChainParams) -> str:
    '''Build a ROP chain to call a target function with arguments using pwntools ROP.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        rop = pwn.ROP(elf)

        target = int(params.target, 0) if params.target.startswith("0x") else elf.symbols.get(params.target)
        if target is None:
            return f"Error: target '{params.target}' not found in symbols. Use pwntools_analyze_elf to list available symbols."

        if params.args:
            for arg in params.args.split(","):
                arg_val = int(arg.strip(), 0) if arg.strip().startswith("0x") else arg.strip()
                rop.call(target, [arg_val])
        else:
            rop.call(target)

        chain = rop.chain()
        rop_text = str(rop)
        return json.dumps({
            "path": params.path,
            "target": params.target,
            "args": params.args or "(none)",
            "chain_hex": chain.hex(),
            "chain_bytes": " ".join(f"{b:02x}" for b in chain),
            "chain_length": len(chain),
            "rop_dump": rop_text,
        }, indent=2)
    except Exception as e:
        return f"Error: {e}"


class ChecksecParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)


class ERopSearchParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    gadget_type: str = Field(default="all", description="Gadget category: all, syscall, stack_pivot, call, jump")


class ShellcodeEncodeParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hex_bytes: str = Field(..., description="Hex bytes of shellcode to encode (e.g. '31c048bb...')")
    arch: str = Field(default="amd64", description="Architecture: amd64, i386, arm, aarch64")
    encoder: str = Field(default="alphanumeric", description="Encoder: alphanumeric, null_free, xor")


class ElfReadParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    section: Optional[str] = Field(default=None, description="Section name to read from (e.g. '.text')")
    offset: Optional[int] = Field(default=None, description="Offset within section (if section given) or virtual address to read from")
    size: int = Field(default=64, description="Number of bytes to read", ge=1, le=4096)


class ConstGrepParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    search: str = Field(..., description="Search term for constant name or value", min_length=1)
    arch: str = Field(default="amd64", description="Architecture: amd64, i386, arm, aarch64")
    limit: int = Field(default=20, description="Maximum number of results", ge=1, le=100)


@mcp.tool(
    name="pwntools_checksec",
    annotations={"title": "Check Binary Security Properties", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_checksec(params: ChecksecParams) -> str:
    '''Check security properties of an ELF binary: RELRO, Canary, NX, PIE, RPATH/RUNPATH, FORTIFY.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        nx = not elf.execstack
        relro_map = {"Full": "GOT is read-only", "Partial": "GOT still writable", "None": "No RELRO"}
        relro_detail = relro_map.get(str(elf.relro), "")
        rpath = getattr(elf, "rpath", None)
        runpath = getattr(elf, "runpath", None)
        fortify = getattr(elf, "fortify", None)
        lines = [
            f"Security properties for: {params.path}",
            "",
            f"  {'Property':20s} {'Status':15s} {'Detail':35s}",
            f"  {'-'*20} {'-'*15} {'-'*35}",
            f"  {'Arch':20s} {'':15s} {elf.arch}",
            f"  {'Bits':20s} {'':15s} {elf.bits}",
            f"  {'Endian':20s} {'':15s} {elf.endian}",
            f"  {'RELRO':20s} {str(elf.relro):15s} {relro_detail:35s}",
            f"  {'Stack Canary':20s} {str(elf.canary):15s} {'Canary present → resists stack overflow':35s}",
            f"  {'NX (No-Execute)':20s} {str(nx):15s} {'Non-executable stack':35s}",
            f"  {'PIE':20s} {str(elf.pie):15s} {'Position-Independent Executable':35s}",
        ]
        if rpath is not None:
            lines.append(f"  {'RPATH':20s} {'SET':15s} {rpath}")
        else:
            lines.append(f"  {'RPATH':20s} {'Not set':15s} {'':35s}")
        if runpath is not None:
            lines.append(f"  {'RUNPATH':20s} {'SET':15s} {runpath}")
        else:
            lines.append(f"  {'RUNPATH':20s} {'Not set':15s} {'':35s}")
        if fortify is not None:
            lines.append(f"  {'FORTIFY':20s} {str(fortify):15s} {'Source fortification (_chk)':35s}")
        lines.append("")
        lines.append("  True  → Protection enabled     False → Protection disabled")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_erope",
    annotations={"title": "Extended ROP Gadget Search", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_erope(params: ERopSearchParams) -> str:
    '''Search ROP gadgets grouped by type: syscall, stack_pivot, call, jump.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        rop = pwn.ROP(elf)
        gadgets = rop.gadgets
        if not gadgets:
            return "No ROP gadgets found"

        valid_types = ("all", "syscall", "stack_pivot", "call", "jump")
        if params.gadget_type not in valid_types:
            return f"Error: invalid gadget_type '{params.gadget_type}'. Valid: {', '.join(valid_types)}"

        categorized = {"syscall": [], "stack_pivot": [], "call": [], "jump": []}
        for addr, g in gadgets.items():
            insns = "; ".join(g.insns)
            if "syscall" in insns or "int 0x80" in insns or "sysenter" in insns:
                categorized["syscall"].append((addr, insns))
            if ("xchg" in insns and "rsp" in insns) or "leave; ret" in insns or "pop rsp" in insns:
                categorized["stack_pivot"].append((addr, insns))
            if "call" in insns:
                categorized["call"].append((addr, insns))
            if "jmp" in insns:
                categorized["jump"].append((addr, insns))

        tags = {
            "syscall": "[SYSCALL]",
            "stack_pivot": "[STACK_PIVOT]",
            "call": "[CALL]",
            "jump": "[JUMP]",
        }

        result = [f"Extended ROP gadgets in {params.path} (type: {params.gadget_type})", ""]
        show_all = params.gadget_type == "all"
        shown_total = 0
        for cat_name in ("syscall", "stack_pivot", "call", "jump"):
            if not show_all and cat_name != params.gadget_type:
                continue
            items = categorized[cat_name]
            if not items:
                continue
            result.append(f"  {tags[cat_name]} ({len(items)} gadgets):")
            for addr, insns in items[:20]:
                result.append(f"    {hex(addr)}: {insns}")
                shown_total += 1
            if len(items) > 20:
                result.append(f"    ... ({len(items) - 20} more)")
            result.append("")

        if not any(categorized.values()):
            return f"No gadgets found matching type '{params.gadget_type}'"
        result.append(f"Total matching: {shown_total}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_enc",
    annotations={"title": "Encode Shellcode", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_enc(params: ShellcodeEncodeParams) -> str:
    '''Encode shellcode using pwntools encoders (alphanumeric, null_free, xor).'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch, os="linux")

        data = bytes.fromhex(params.hex_bytes.replace(" ", "").replace("\\x", ""))
        if not data:
            return "Error: empty or invalid hex bytes"

        valid_encoders = ("alphanumeric", "null_free", "xor")
        if params.encoder not in valid_encoders:
            return f"Error: invalid encoder '{params.encoder}'. Valid: {', '.join(valid_encoders)}"

        encoded = None
        decoder_bytes = None

        encoders_found = False
        for src in (pwn.encoders.encoder,):
            try:
                enc_mod = getattr(src, params.encoder, None)
                if enc_mod is None:
                    continue
                if callable(enc_mod):
                    encoded = enc_mod(data)
                else:
                    encoded = enc_mod.encode(data)
                try:
                    if callable(getattr(enc_mod, "decoder", None)):
                        decoder_bytes = enc_mod.decoder()
                    else:
                        decoder_bytes = getattr(enc_mod, "decoder", None)
                except AttributeError:
                    decoder_bytes = None
                encoders_found = True
                break
            except (AttributeError, TypeError):
                continue

        if not encoders_found or encoded is None:
            return (f"Encoder '{params.encoder}' not available in this pwntools version.\n"
                    "The pwntools encoders API has changed across versions.\n"
                    "Try upgrading: pip install -U pwntools\n"
                    "Or check available encoders with: python -c \"from pwn import *; print(dir(encoders.encoder))\"")

        result = [
            f"=== Shellcode Encoding ({params.encoder}) ===",
            f"  Architecture: {params.arch}",
            "",
            f"  Original ({len(data)} bytes):",
            f"    {data.hex()}",
            "",
            f"  Encoded ({len(encoded)} bytes):",
            f"    {encoded.hex()}",
            "",
            f"  Length change: {len(data)} → {len(encoded)} "
            f"({'+' if len(encoded) > len(data) else ''}{len(encoded) - len(data)} bytes)",
            "",
        ]

        if decoder_bytes:
            result.append("  Decoder assembly:")
            try:
                dasm = pwn.disasm(decoder_bytes)
                for line in dasm.split("\n"):
                    result.append(f"    {line}")
            except Exception:
                result.append(f"    (decoder hex: {decoder_bytes.hex()})")
        else:
            result.append("  Decoder assembly: (not available for this encoder)")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_read",
    annotations={"title": "Read ELF Binary Bytes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_read(params: ElfReadParams) -> str:
    '''Read bytes from an ELF binary at a section or address, with hex dump output.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)

        if params.section:
            sec = elf.get_section_by_name(params.section)
            if sec is None:
                return (f"Error: section '{params.section}' not found.\n"
                        f"Available sections: {', '.join(s.name for s in elf.sections if s.name)}")
            base = sec.header.sh_addr
            read_addr = base + (params.offset or 0)
            sec_size = sec.header.sh_size
            if (params.offset or 0) + params.size > sec_size:
                return (f"Error: read would exceed section bounds.\n"
                        f"  Section '{params.section}' base={hex(base)} size={hex(sec_size)}\n"
                        f"  Requested offset={params.offset or 0} size={params.size} "
                        f"exceeds {hex(sec_size)}")
            location_desc = f"section '{params.section}'"
            if params.offset:
                location_desc += f" + {params.offset}"
            location_desc += f" (addr {hex(read_addr)})"
        elif params.offset is not None:
            read_addr = params.offset
            location_desc = f"virtual address {hex(read_addr)}"
        else:
            return "Error: provide either 'section' or 'offset'"

        data = elf.read(read_addr, params.size)
        dump = pwn.hexdump(data)

        result = [
            f"=== ELF Read: {params.path} ===",
            f"  Location: {location_desc}",
            f"  Bytes: {len(data)}",
            "",
            dump,
        ]
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_constgrep",
    annotations={"title": "Search Constants", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_constgrep(params: ConstGrepParams) -> str:
    '''Search pwntools/ELF constants by name or value.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch)

        search_lower = params.search.lower()

        # Try pwn.constgrep (newer pwntools API)
        try:
            constgrep = getattr(pwn, "constgrep", None)
            if constgrep:
                results = constgrep(search_lower, arch=params.arch)
                matches = []
                for item in list(results)[:params.limit]:
                    if hasattr(item, "_asdict"):
                        d = item._asdict()
                        name = d.get("name") or d.get("symbol", "?")
                        val = d.get("value") or d.get("val", "?")
                    elif isinstance(item, dict):
                        name = item.get("name") or item.get("symbol", "?")
                        val = item.get("value") or item.get("val", "?")
                    elif isinstance(item, (list, tuple)) and len(item) >= 2:
                        if isinstance(item[0], str):
                            name, val = item[0], item[1]
                        else:
                            val, name = item[0], item[1]
                    else:
                        name, val = str(item), "?"
                    matches.append((name, val))

                if matches:
                    result = [f"Constants matching '{params.search}' ({params.arch}):", ""]
                    for name, val in matches:
                        if isinstance(val, int):
                            result.append(f"  {name:45s} = {hex(val)} ({val})")
                        else:
                            result.append(f"  {name:45s} = {val}")
                    result.append("")
                    result.append(f"Total: {len(matches)} / {len(results)} matching (limited to {params.limit})")
                    return "\n".join(result)
        except (AttributeError, TypeError, ImportError):
            pass

        # Fallback: manual dir() search over constants module
        try:
            from pwnlib.constants import constant as const_mod
        except ImportError:
            try:
                const_mod = pwn.elf.constant
            except AttributeError:
                # Try generic constant search via pwn.constants
                try:
                    const_mod = pwn.constants
                except AttributeError:
                    return ("Constants search not available in this pwntools version.\n"
                            "Try upgrading: pip install -U pwntools\n"
                            "Or provide a specific constant name.")

        matches = []
        for name in sorted(dir(const_mod)):
            if search_lower in name.lower():
                val = getattr(const_mod, name, None)
                if val is not None and not name.startswith("_"):
                    matches.append((name, val))
                    if len(matches) >= params.limit:
                        break

        if matches:
            result = [f"Constants matching '{params.search}' ({params.arch}):", ""]
            for name, val in matches:
                if isinstance(val, int):
                    result.append(f"  {name:45s} = {hex(val)} ({val})")
                else:
                    result.append(f"  {name:45s} = {val}")
            result.append("")
            result.append(f"Total: {len(matches)} (limited to {params.limit})")
            return "\n".join(result)
        else:
            return f"No constants found matching '{params.search}'"
    except Exception as e:
        return f"Error: {e}"
