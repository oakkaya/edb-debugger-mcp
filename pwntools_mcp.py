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


class EncodeHexParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    data: str = Field(..., description="Raw bytes or hex string to encode (use \\x escapes for non-printable)", min_length=1)


class DecodeHexParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hex_str: str = Field(..., description="Hex string to decode (e.g., 'deadbeef' or 'de ad be ef')", min_length=1)


class AlignParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    value: int = Field(..., description="Value to align (address or size)")
    alignment: int = Field(default=0x1000, description="Alignment boundary (default: 0x1000/page)", ge=2, le=0x1000000)


class BitOpParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    value: int = Field(..., description="Integer value to rotate")
    shift: int = Field(..., description="Number of bits to rotate (1-63)", ge=1, le=63)
    bits: int = Field(default=64, description="Bit width: 8, 16, 32, or 64", ge=8, le=64)


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


class FlatParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    values: str = Field(..., description="JSON array of values to flatten: [addr_or_int, ...] or flat dict")
    arch: str = Field(default="amd64", description="Architecture: amd64, i386, arm, aarch64")
    endian: str = Field(default="little", description="Endianness: little or big")
    pack_size: int = Field(default=8, description="Default pack size for integers: 4 (i386) or 8 (amd64)", ge=4, le=8)


class SigreturnFrameParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    arch: str = Field(default="amd64", description="Architecture: amd64 or i386")
    rax: Optional[str] = Field(default=None, description="RAX value (syscall number for SROP)")
    rdi: Optional[str] = Field(default=None, description="RDI value (arg1)")
    rsi: Optional[str] = Field(default=None, description="RSI value (arg2)")
    rdx: Optional[str] = Field(default=None, description="RDX value (arg3)")
    rip: Optional[str] = Field(default=None, description="RIP value (return address after sigreturn)")


class ElfPatchParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    offset: int = Field(..., description="File offset (not virtual address) to patch", ge=0)
    bytes: str = Field(..., description="Hex bytes to write (e.g. '90 90' or '9090')")


class ElfSearchParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    pattern: str = Field(..., description="Hex pattern to search for (e.g. '48 31 c0' or '4831c0')")
    start: Optional[int] = Field(default=None, description="Start offset (file offset, default: 0)")
    end: Optional[int] = Field(default=None, description="End offset (file offset, default: file size)")


class MakeElfParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    code: str = Field(..., description="Assembly code (e.g. 'mov rax, 60; xor rdi, rdi; syscall')")
    arch: str = Field(default="amd64", description="Architecture: amd64, i386, arm, aarch64")
    output: Optional[str] = Field(default=None, description="Output path (default: temp file)")


@mcp.tool(
    name="pwntools_flat",
    annotations={"title": "Flat / Pack Values", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_flat(params: FlatParams) -> str:
    '''Pack a list of values/addresses into flat bytes using pwntools flat().'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch, os="linux", endian=params.endian, log_level="error")
        if params.pack_size == 4:
            pwn.context.bits = 32

        try:
            values = json.loads(params.values)
        except (json.JSONDecodeError, TypeError):
            import ast
            values = ast.literal_eval(params.values)
        packed = pwn.flat(values)
        result = [
            f"=== Flat ({len(packed)} bytes) ===",
            f"  Values: {params.values[:200]}{'...' if len(params.values) > 200 else ''}",
            f"  Arch: {params.arch}  Endian: {params.endian}",
            "",
            "  Hex:",
        ]
        for i in range(0, len(packed), 16):
            chunk = packed[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            result.append(f"    {i:04x}: {hex_str:48s} {ascii_str}")
        result.append("")
        c_bytes = "".join(f"\\x{b:02x}" for b in packed)
        result.append(f"  C-array: unsigned char payload[] = {{")
        result.append(f"    {c_bytes}")
        result.append(f"  }};")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_sigreturn",
    annotations={"title": "Generate SROP Frame", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_sigreturn(params: SigreturnFrameParams) -> str:
    '''Generate a Sigreturn-Oriented Programming (SROP) frame using pwntools SigreturnFrame.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch, os="linux", log_level="error")

        frame = pwn.SigreturnFrame()
        reg_map = {
            "amd64": {"rax": "rax", "rdi": "rdi", "rsi": "rsi", "rdx": "rdx", "rip": "rip"},
            "i386": {"rax": "eax", "rdi": "edi", "rsi": "esi", "rdx": "edx", "rip": "eip"},
        }
        regs = reg_map.get(params.arch, reg_map["amd64"])

        if params.rax:
            setattr(frame, regs["rax"], int(params.rax, 0))
        if params.rdi:
            setattr(frame, regs["rdi"], int(params.rdi, 0))
        if params.rsi:
            setattr(frame, regs["rsi"], int(params.rsi, 0))
        if params.rdx:
            setattr(frame, regs["rdx"], int(params.rdx, 0))
        if params.rip:
            setattr(frame, regs["rip"], int(params.rip, 0))

        packed = bytes(frame)
        result = [
            f"=== SROP Frame ({params.arch}) ===",
            f"  Size: {len(packed)} bytes",
            "",
            "  Register layout:",
        ]
        if params.arch == "amd64":
            result.append(f"    rax = {hex(getattr(frame, 'rax', 0))}")
            result.append(f"    rdi = {hex(getattr(frame, 'rdi', 0))}")
            result.append(f"    rsi = {hex(getattr(frame, 'rsi', 0))}")
            result.append(f"    rdx = {hex(getattr(frame, 'rdx', 0))}")
            result.append(f"    r10 = {hex(getattr(frame, 'r10', 0))}")
            result.append(f"    r8  = {hex(getattr(frame, 'r8', 0))}")
            result.append(f"    r9  = {hex(getattr(frame, 'r9', 0))}")
            result.append(f"    rip = {hex(getattr(frame, 'rip', 0))}")
            result.append(f"    cs  = {hex(getattr(frame, 'cs', 0))}")
            result.append(f"    rflags = {hex(getattr(frame, 'rflags', 0))}")
            result.append(f"    rsp = {hex(getattr(frame, 'rsp', 0))}")
            result.append(f"    ss  = {hex(getattr(frame, 'ss', 0))}")
        else:
            result.append(f"    eax = {hex(getattr(frame, 'eax', 0))}")
            result.append(f"    ebx = {hex(getattr(frame, 'ebx', 0))}")
            result.append(f"    ecx = {hex(getattr(frame, 'ecx', 0))}")
            result.append(f"    edx = {hex(getattr(frame, 'edx', 0))}")
            result.append(f"    esi = {hex(getattr(frame, 'esi', 0))}")
            result.append(f"    edi = {hex(getattr(frame, 'edi', 0))}")
            result.append(f"    eip = {hex(getattr(frame, 'eip', 0))}")

        result.append("")
        result.append("  Hex bytes:")
        for i in range(0, len(packed), 16):
            chunk = packed[i:i+16]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            result.append(f"    {i:04x}: {hex_str}")
        result.append("")
        result.append("  Usage: Place frame on stack, set RAX=15 (sigreturn), then syscall")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_patch",
    annotations={"title": "Patch ELF Binary", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_elf_patch(params: ElfPatchParams) -> str:
    '''Patch bytes in an ELF binary at a given file offset. Creates a backup.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        data = bytes.fromhex(params.bytes.replace(" ", "").replace("\\x", ""))

        with open(params.path, "rb") as f:
            original = f.read()

        if params.offset + len(data) > len(original):
            return (f"Error: patch at offset {params.offset} with {len(data)} bytes "
                    f"exceeds file size ({len(original)})")

        patched = bytearray(original)
        old_bytes = bytes(patched[params.offset:params.offset + len(data)])
        patched[params.offset:params.offset + len(data)] = data

        backup_path = params.path + ".bak"
        with open(backup_path, "wb") as f:
            f.write(original)

        with open(params.path, "wb") as f:
            f.write(patched)

        result = [
            f"=== ELF Patched: {params.path} ===",
            f"  Offset: {hex(params.offset)}",
            f"  Size: {len(data)} bytes",
            f"  Backup: {backup_path}",
            "",
            f"  Old: {' '.join(f'{b:02x}' for b in old_bytes)}",
            f"  New: {' '.join(f'{b:02x}' for b in data)}",
        ]

        if old_bytes != data:
            val = pwn.hexdump(old_bytes)
            result.append(f"\n  Old hexdump:\n{val}")
            val = pwn.hexdump(data)
            result.append(f"\n  New hexdump:\n{val}")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_search",
    annotations={"title": "Search ELF Binary", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_search(params: ElfSearchParams) -> str:
    '''Search for a byte pattern in an ELF binary.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        pattern_bytes = bytes.fromhex(params.pattern.replace(" ", "").replace("\\x", ""))

        with open(params.path, "rb") as f:
            data = f.read()

        start = params.start or 0
        end = params.end or len(data)
        search_region = data[start:end]

        matches = []
        pos = 0
        while True:
            pos = search_region.find(pattern_bytes, pos)
            if pos == -1:
                break
            matches.append(start + pos)
            pos += 1

        elf = pwn.ELF(params.path, checksec=False)
        result = [
            f"=== Search in {params.path} ===",
            f"  Pattern: {' '.join(f'{b:02x}' for b in pattern_bytes)} ({len(pattern_bytes)} bytes)",
            f"  Range: {hex(start)} - {hex(end)} ({end - start} bytes)",
            f"  Matches: {len(matches)}",
            "",
        ]

        # Group matches by section
        section_hits = {}
        for sec in elf.sections:
            sec_start = sec.header.sh_offset if hasattr(sec.header, 'sh_offset') else 0
            sec_end = sec_start + (sec.header.sh_size if hasattr(sec.header, 'sh_size') else 0)
            if sec.name:
                hits = [m for m in matches if sec_start <= m < sec_end]
                if hits:
                    section_hits[sec.name] = hits

        if section_hits:
            result.append("  By section:")
            for sec_name, hits in section_hits.items():
                sample = ", ".join(hex(m) for m in hits[:5])
                more = f" ... (+{len(hits) - 5} more)" if len(hits) > 5 else ""
                result.append(f"    {sec_name:20s}: {sample}{more}")

        if matches:
            result.append(f"\n  All matches ({min(20, len(matches))} shown):")
            for m in matches[:20]:
                context_start = max(0, m - 4)
                context_end = min(len(data), m + len(pattern_bytes) + 4)
                context = data[context_start:context_end]
                prefix = " ".join(f"{b:02x}" for b in context[:m - context_start])
                match_hex = " ".join(f"{b:02x}" for b in context[m - context_start:m - context_start + len(pattern_bytes)])
                suffix = " ".join(f"{b:02x}" for b in context[m - context_start + len(pattern_bytes):])
                result.append(f"    {hex(m)}: {prefix} [{match_hex}] {suffix}")

        if len(matches) > 20:
            result.append(f"    ... ({len(matches) - 20} more)")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_make_elf",
    annotations={"title": "Create ELF from Assembly", "readOnlyHint": True, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_make_elf(params: MakeElfParams) -> str:
    '''Compile assembly code into an ELF binary using pwntools make_elf.'''
    if not _pwntools_available():
        return "Error: pwntools not installed. Run: pip install pwntools"
    try:
        pwn = _import_pwn()
        pwn.context.clear()
        pwn.context.update(arch=params.arch, os="linux", log_level="error")

        output = params.output
        if not output:
            import tempfile
            output = tempfile.mktemp(suffix=".elf")

        pwn.make_elf(
            pwn.asm(params.code),
            extract=False,
            path=output,
        )

        import os as os_mod
        st = os_mod.stat(output)

        elf = pwn.ELF(output, checksec=False) if os_mod.path.getsize(output) > 0 else None
        result = [
            f"=== ELF Created ===",
            f"  Path: {output}",
            f"  Size: {st.st_size} bytes",
            "",
            f"  Assembly source ({params.arch}):",
        ]
        for line in params.code.split(";"):
            result.append(f"    {line.strip()}")
        result.append("")

        if elf:
            result.append(f"  Entry: {hex(elf.entry)}")
            result.append(f"  Arch: {elf.arch}")
            result.append(f"  Sections: {len(list(elf.sections))}")
            for sec in elf.sections[:10]:
                if sec.name:
                    size = sec.header.sh_size if hasattr(sec.header, 'sh_size') else 0
                    result.append(f"    {sec.name:15s} size={hex(size or 0)}")

        result.append("")
        result.append(f"  Run: chmod +x {output} && ./{output}")
        result.append(f"  Analyze: {output} (use pwntools_analyze_elf)")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


class ElfSectionsParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    filter_name: Optional[str] = Field(default=None, description="Filter sections by name substring")


class ElfSymbolsParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    pattern: str = Field(default="", description="Regex pattern to match symbol names")
    type_filter: str = Field(default="all", description="Symbol type: all, function, object, file")


class ElfStringsParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    min_length: int = Field(default=4, description="Minimum string length", ge=3, le=100)
    section: Optional[str] = Field(default=None, description="Limit to specific section (default: all loadable)")


class ElfDepsParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    resolve_versions: bool = Field(default=False, description="Try to resolve library versions from system")


class EntropyParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the binary/region", min_length=1)
    offset: int = Field(default=0, description="Start offset", ge=0)
    size: Optional[int] = Field(default=None, description="Size in bytes (default: entire file)")


class ElfRelocsParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the ELF binary", min_length=1)
    type_filter: str = Field(default="all", description="Relocation type: all, got, plt, absolute, relative")


class TubeBaseParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    tube_id: str = Field(default="last", description="Tube identifier ('last' for most recent)")


class TubeProcessParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    binary: str = Field(..., description="Binary path to execute", min_length=1)
    args: str = Field(default="", description="Command-line arguments")
    tube_id: str = Field(default="last", description="Optional tube identifier")
    timeout: int = Field(default=30, description="Timeout in seconds", ge=1, le=300)


class TubeRemoteParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    host: str = Field(..., description="Remote hostname or IP", min_length=1)
    port: int = Field(..., description="Remote port", ge=1, le=65535)
    tube_id: str = Field(default="last", description="Optional tube identifier")
    timeout: int = Field(default=30, description="Timeout in seconds", ge=1, le=300)


class TubeSendParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    data: str = Field(..., description="Data to send (bytes)")
    tube_id: str = Field(default="last", description="Tube identifier")


class TubeRecvParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    nbytes: int = Field(default=4096, description="Number of bytes to receive", ge=1, le=65536)
    tube_id: str = Field(default="last", description="Tube identifier")
    timeout: int = Field(default=5, description="Receive timeout in seconds", ge=1, le=60)


class TubeRecvUntilParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    pattern: str = Field(..., description="Pattern to receive until (e.g., ':')")
    tube_id: str = Field(default="last", description="Tube identifier")
    timeout: int = Field(default=5, description="Receive timeout in seconds", ge=1, le=60)
    drop: bool = Field(default=True, description="Drop the matched pattern from result")


class ElfDiffParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path_a: str = Field(..., description="First ELF binary path", min_length=1)
    path_b: str = Field(..., description="Second ELF binary path", min_length=1)
    sections_only: bool = Field(default=False, description="Only compare section headers")


class BitsParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    value: int = Field(..., description="Integer value")
    bit: int = Field(default=0, description="Bit position to get/set (0-indexed, LSB)", ge=0, le=63)
    set_to: int = Field(default=-1, description="Set to 0 or 1, or -1 to just get")


class ContextParams(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    arch: str = Field(default="", description="Set architecture (amd64, i386, arm, aarch64, mips)")
    os: str = Field(default="", description="Set OS (linux, windows)")
    endian: str = Field(default="", description="Set endianness (little, big)")
    log_level: str = Field(default="", description="Set log level (debug, info, warning, error)")
    bits: int = Field(default=0, description="Set CPU bits (32, 64)")


@mcp.tool(
    name="pwntools_elf_sections",
    annotations={"title": "Detailed ELF Sections", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_sections(params: ElfSectionsParams) -> str:
    '''List all ELF sections with detailed info: type, flags, address, offset, size, alignment.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)

        type_names = {
            0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
            5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
            10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
            16: "PREINIT_ARRAY", 17: "GROUP", 18: "SYMTAB_SHNDX",
        }
        flag_names = {1: "W", 2: "A", 4: "X", 0x10: "T"}

        result = [f"Sections in {params.path}:", "",
                  f"  {'Nr':3s} {'Name':22s} {'Type':14s} {'Addr':18s} {'Off':8s} {'Size':8s} {'Flags':6s} {'Align':5s}",
                  f"  {'--':3s} {'----':22s} {'----':14s} {'----':18s} {'---':8s} {'----':8s} {'-----':6s} {'-----':5s}"]

        shown = 0
        for i, sec in enumerate(elf.sections):
            name = sec.name or "(unnamed)"
            if params.filter_name and params.filter_name.lower() not in name.lower():
                continue
            sh = sec.header
            stype = type_names.get(sh.sh_type, hex(sh.sh_type) if isinstance(sh.sh_type, int) else str(sh.sh_type))
            vaddr = sh.sh_addr if isinstance(sh.sh_addr, int) else 0
            off = sh.sh_offset if isinstance(sh.sh_offset, int) else 0
            size = sh.sh_size if isinstance(sh.sh_size, int) else 0
            flags = sh.sh_flags if isinstance(sh.sh_flags, int) else 0
            align = sh.sh_addralign if isinstance(sh.sh_addralign, int) else 0
            flag_str = "".join(f for v, f in flag_names.items() if flags & v)
            result.append(f"  [{i:3d}] {name:22s} {stype:14s} {hex(vaddr) if vaddr else '':18s} {hex(off) if off else '':8s} {hex(size) if size else '':8s} {flag_str:6s} {str(align):5s}")
            shown += 1

        result.append("")
        result.append(f"Total: {shown} section{'s' if shown != 1 else ''}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_symbols",
    annotations={"title": "Search ELF Symbols", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_symbols(params: ElfSymbolsParams) -> str:
    '''Search symbols in an ELF binary by regex pattern and type.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        import re as re_mod
        pattern_re = re_mod.compile(params.pattern if params.pattern else ".")

        matches = []
        for sym_name, addr in elf.symbols.items():
            if not pattern_re.search(sym_name):
                continue
            if not isinstance(addr, int):
                continue
            matches.append((sym_name, addr))

        matches.sort(key=lambda x: x[1])
        result = [f"Symbols in {params.path} matching /{params.pattern}/:", "",
                  f"  {'Name':35s} {'Address':18s}",
                  f"  {'----':35s} {'-------':18s}"]

        for name, addr in matches[:50]:
            result.append(f"  {name:35s} {hex(addr):18s}")

        if len(matches) > 50:
            result.append(f"  ... ({len(matches) - 50} more)")

        result.append("")
        result.append(f"Total: {len(matches)} symbol{'s' if len(matches) != 1 else ''}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_strings",
    annotations={"title": "Extract ELF Strings", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_strings(params: ElfStringsParams) -> str:
    '''Extract printable strings from an ELF binary, optionally filtered by section.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)

        if params.section:
            sec = elf.get_section_by_name(params.section)
            if sec is None:
                available = [s.name for s in elf.sections if s.name]
                return (f"Error: section '{params.section}' not found.\n"
                        f"Available: {', '.join(available)}")
            data = sec.data()
            offset_base = sec.header.sh_addr
            section_label = f"section '{params.section}'"
        else:
            data = elf.data
            offset_base = 0
            section_label = "entire binary"

        import re as re_mod
        pattern = re_mod.compile(rb"[\x20-\x7e]{" + str(params.min_length).encode() + rb",}")
        matches = [(m.start() + offset_base, m.group().decode("ascii")) for m in pattern.finditer(data)]

        if not matches:
            return f"No strings found in {section_label} (min_length={params.min_length})"

        result = [f"Strings in {params.path} ({section_label}):", "",
                  f"  {'Address':16s} {'String':50s}",
                  f"  {'-------':16s} {'------':50s}"]
        for addr, s in matches[:100]:
            s_trim = s[:80]
            addr_str = hex(addr) if addr else "?" * 16
            result.append(f"  {addr_str:16s} {s_trim}")

        if len(matches) > 100:
            result.append(f"  ... ({len(matches) - 100} more strings)")

        result.append("")
        result.append(f"Total: {len(matches)} string{'s' if len(matches) != 1 else ''} in {section_label}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_deps",
    annotations={"title": "ELF Dependencies", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_deps(params: ElfDepsParams) -> str:
    '''List shared library dependencies of an ELF binary (DT_NEEDED entries).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)

        result = [f"Dependencies for {params.path}:", ""]

        needed = list(elf.dependencies) if hasattr(elf, "dependencies") else []
        if not needed:
            result.append("  (no dynamic dependencies - statically linked or stripped)")
        else:
            result.append(f"  DT_NEEDED ({len(needed)} entries):")
            for dep in needed:
                result.append(f"    {dep}")

        if params.resolve_versions:
            result.append("")
            result.append("  Resolving library versions from system...")
            import subprocess as sp
            try:
                r = sp.run(["ldd", params.path], capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    for line in r.stdout.strip().split("\n"):
                        result.append(f"    {line.strip()}")
                else:
                    result.append(f"    (ldd failed: {r.stderr.strip()})")
            except FileNotFoundError:
                result.append("    (ldd not found)")
            except sp.TimeoutExpired:
                result.append("    (ldd timed out)")

        result.append("")
        rpath = getattr(elf, "rpath", None)
        runpath = getattr(elf, "runpath", None)
        interp = elf.get_section_by_name(".interp")
        if interp:
            interp_data = interp.data()
            interp_str = interp_data[:interp_data.index(b"\x00")].decode("utf-8", errors="replace")
            result.append(f"  Interpreter: {interp_str}")
        if rpath:
            result.append(f"  RPATH: {rpath}")
        if runpath:
            result.append(f"  RUNPATH: {runpath}")

        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_entropy",
    annotations={"title": "Byte Entropy Analysis", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_entropy(params: EntropyParams) -> str:
    '''Calculate byte entropy (Shannon) of a file or memory region. Useful for detecting encryption, packing, or embedded data.'''
    try:
        with open(params.path, "rb") as f:
            if params.offset > 0:
                f.seek(params.offset)
            data = f.read(params.size) if params.size else f.read()

        if not data:
            return "Error: no data to analyze (empty file or region)"

        import math as math_mod
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        total = len(data)
        entropy = -sum(c / total * math_mod.log2(c / total) for c in byte_counts if c > 0)

        high_entropy = sum(1 for c in byte_counts if c > 0)
        top_bytes = sorted(
            [(i, c / total * 100) for i, c in enumerate(byte_counts)],
            key=lambda x: -x[1]
        )[:8]

        if entropy < 2.0:
            hint = "Low entropy — likely plain text, code, or structured data"
        elif entropy < 5.0:
            hint = "Medium entropy — mixed content or compressed"
        else:
            hint = "High entropy — likely encrypted, compressed, or packed"

        null_pct = byte_counts[0] / total * 100
        printable_pct = sum(byte_counts[b] for b in range(32, 127)) / total * 100

        result = [
            f"=== Entropy Analysis: {params.path} ===",
            f"  Offset: {hex(params.offset)}",
            f"  Size: {total} bytes ({total / 1024:.1f} KB)",
            "",
            f"  Shannon Entropy: {entropy:.4f} / 8.0",
            f"  Classification:   {hint}",
            "",
            f"  Null bytes: {null_pct:.1f}%",
            f"  Printable ASCII: {printable_pct:.1f}%",
            f"  Unique bytes: {high_entropy}/256",
            "",
            "  Most frequent bytes:",
        ]
        for val, pct in top_bytes:
            ch = chr(val) if 32 <= val < 127 else "."
            result.append(f"    0x{val:02x} ({ch:3s}): {pct:5.1f}%")

        if total >= 1024:
            block_size = 256
            result.append(f"\n  Per-block entropy (256B blocks):")
            max_blocks = min(total // block_size, 64)
            for i in range(max_blocks):
                block = data[i * block_size:(i + 1) * block_size]
                counts = [0] * 256
                for b in block:
                    counts[b] += 1
                be = -sum(c / block_size * math_mod.log2(c / block_size) for c in counts if c > 0)
                marker = " !" if be > 7.0 else "  "
                result.append(f"    [{i * block_size:06x}]: {be:.2f}{marker}")
            if total // block_size > max_blocks:
                result.append(f"    ... ({total // block_size - max_blocks} more blocks)")

        return "\n".join(result)
    except FileNotFoundError:
        return f"Error: file not found: {params.path}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_got",
    annotations={"title": "Parse ELF GOT Entries", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_got(params: ElfPath) -> str:
    '''Parse Global Offset Table (GOT) entries from an ELF binary.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        got = elf.got
        if not got:
            return f"No GOT entries found in {params.path}"
        result = [f"GOT entries in {params.path}:", "",
                  f"  {'Symbol':25s} {'Address':18s}",
                  f"  {'-'*25} {'-'*18}"]
        for name, addr in sorted(got.items(), key=lambda x: x[1]):
            result.append(f"  {name:25s} {hex(addr):18s}")
        result.append("")
        result.append(f"Total: {len(got)} entries")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_plt",
    annotations={"title": "Parse ELF PLT Entries", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_plt(params: ElfPath) -> str:
    '''Parse Procedure Linkage Table (PLT) entries from an ELF binary.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        plt = elf.plt
        if not plt:
            return f"No PLT entries found in {params.path}"
        result = [f"PLT entries in {params.path}:", "",
                  f"  {'Symbol':25s} {'Address':18s}",
                  f"  {'-'*25} {'-'*18}"]
        for name, addr in sorted(plt.items(), key=lambda x: x[1]):
            result.append(f"  {name:25s} {hex(addr):18s}")
        result.append("")
        result.append(f"Total: {len(plt)} entries")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_segments",
    annotations={"title": "List ELF Program Headers", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_segments(params: ElfPath) -> str:
    '''List ELF program headers (segments): type, flags, offset, vaddr, filesz, memsz.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        seg_types = {
            0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
            5: "SHLIB", 6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME",
            0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO",
            0x6474e553: "GNU_PROPERTY",
        }
        result = [f"Program headers in {params.path}:", "",
                  f"  {'Type':16s} {'Flags':8s} {'Offset':12s} {'VAddr':18s} {'FileSz':10s} {'MemSz':10s} {'Align':10s}",
                  f"  {'-'*16} {'-'*8} {'-'*12} {'-'*18} {'-'*10} {'-'*10} {'-'*10}"]
        for seg in elf.segments:
            h = seg.header
            stype = seg_types.get(h.p_type if isinstance(h.p_type, int) else 0, hex(h.p_type) if isinstance(h.p_type, int) else str(h.p_type))
            flags = ""
            if h.p_flags & 4: flags += "R"
            if h.p_flags & 2: flags += "W"
            if h.p_flags & 1: flags += "X"
            result.append(f"  {stype:16s} {flags:8s} {hex(h.p_offset):12s} {hex(h.p_vaddr):18s} {hex(h.p_filesz):10s} {hex(h.p_memsz):10s} {hex(h.p_align):10s}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_relocs",
    annotations={"title": "Show ELF Relocations", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_relocs(params: ElfRelocsParams) -> str:
    '''Show ELF relocation entries (GOT/PLT fixups and absolute relocations).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        relocs = list(elf.relocs) if hasattr(elf, "relocs") and elf.relocs else []
        if not relocs:
            return f"No relocations found in {params.path}"
        filtered = []
        for r in relocs:
            rtype = str(r.type)
            if params.type_filter == "got" and "GLOB_DAT" not in rtype and "JUMP_SLOT" not in rtype:
                continue
            if params.type_filter == "plt" and "JUMP_SLOT" not in rtype:
                continue
            if params.type_filter == "absolute" and "RELATIVE" not in rtype:
                continue
            if params.type_filter == "relative" and "RELATIVE" not in rtype:
                continue
            filtered.append(r)
        if not filtered:
            return f"No matching relocations for filter '{params.type_filter}'"
        result = [f"Relocations in {params.path}:", "",
                  f"  {'Address':18s} {'Type':30s} {'Symbol':25s} {'Addend':12s}",
                  f"  {'-'*18} {'-'*30} {'-'*25} {'-'*12}"]
        for r in filtered:
            sym = r.symbol if hasattr(r, "symbol") else r.symbolname if hasattr(r, "symbolname") else ""
            addend = hex(r.addend) if hasattr(r, "addend") and r.addend else ""
            result.append(f"  {hex(r.address):18s} {str(r.type):30s} {str(sym):25s} {addend:12s}")
        result.append("")
        result.append(f"Total: {len(filtered)} relocation{'s' if len(filtered) != 1 else ''}")
        return "\n".join(result)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_elf_notes",
    annotations={"title": "Show ELF Notes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_notes(params: ElfPath) -> str:
    '''Show ELF notes: build ID, ABI tag, property notes.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        elf = pwn.ELF(params.path, checksec=False)
        notes = elf.notes if hasattr(elf, "notes") else []
        if notes:
            result = [f"ELF notes in {params.path}:", ""]
            for n in notes:
                ntype = str(n.n_type) if hasattr(n, "n_type") else ""
                ndesc = str(n.n_desc) if hasattr(n, "n_desc") else ""
                result.append(f"  Type: {ntype}")
                result.append(f"  Desc: {ndesc}")
                result.append("")
            return "\n".join(result)
        else:
            return f"No notes found in {params.path}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_enhex",
    annotations={"title": "Hex Encode Bytes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_enhex(params: EncodeHexParams) -> str:
    '''Encode raw bytes to hexadecimal string. Supports \\x escapes.'''
    try:
        data = params.data.encode("latin-1") if "\\x" in params.data else params.data.encode()
        hex_str = data.hex()
        formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        return f"Raw ({len(data)} bytes): {params.data}\nHex ({len(hex_str)//2} bytes): {formatted}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_unhex",
    annotations={"title": "Hex Decode to Bytes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_unhex(params: DecodeHexParams) -> str:
    '''Decode hexadecimal string back to raw bytes.'''
    try:
        clean = params.hex_str.replace(" ", "").replace("0x", "").replace("\\x", "")
        data = bytes.fromhex(clean)
        printable = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in data)
        return f"Hex: {params.hex_str}\nDecoded ({len(data)} bytes): {data!r}\nPrintable: {printable}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_align",
    annotations={"title": "Calculate Alignment", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_align(params: AlignParams) -> str:
    '''Calculate aligned value (up/down) for a given alignment boundary.'''
    try:
        aligned_down = params.value & ~(params.alignment - 1)
        aligned_up = (params.value + params.alignment - 1) & ~(params.alignment - 1)
        pages_used = (params.value + params.alignment - 1) // params.alignment
        return (
            f"Alignment calculation for {hex(params.value)} (alignment: {hex(params.alignment)}):\n"
            f"  Original:     {hex(params.value)} ({params.value})\n"
            f"  Aligned down: {hex(aligned_down)} ({aligned_down})\n"
            f"  Aligned up:   {hex(aligned_up)} ({aligned_up})\n"
            f"  Pages used:   {pages_used}"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_rol",
    annotations={"title": "Rotate Left (ROL)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_rol(params: BitOpParams) -> str:
    '''Rotate an integer value left by N bits.'''
    try:
        mask = (1 << params.bits) - 1
        result_val = ((params.value << params.shift) | (params.value >> (params.bits - params.shift))) & mask
        return (
            f"ROL {params.bits}-bit, shift {params.shift}:\n"
            f"  Input:  {hex(params.value)} ({params.value})\n"
            f"  Output: {hex(result_val)} ({result_val})"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_ror",
    annotations={"title": "Rotate Right (ROR)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_ror(params: BitOpParams) -> str:
    '''Rotate an integer value right by N bits.'''
    try:
        mask = (1 << params.bits) - 1
        result_val = ((params.value >> params.shift) | (params.value << (params.bits - params.shift))) & mask
        return (
            f"ROR {params.bits}-bit, shift {params.shift}:\n"
            f"  Input:  {hex(params.value)} ({params.value})\n"
            f"  Output: {hex(result_val)} ({result_val})"
        )
    except Exception as e:
        return f"Error: {e}"


# --- Tube management ---
_tubes: dict = {}


def _get_tube(tube_id: str = "last"):
    if tube_id == "last":
        if not _tubes:
            raise RuntimeError("No active tubes. Start one with pwntools_process or pwntools_remote")
        return list(_tubes.values())[-1]
    if tube_id not in _tubes:
        raise RuntimeError(f"Tube '{tube_id}' not found")
    return _tubes[tube_id]


@mcp.tool(
    name="pwntools_process",
    annotations={"title": "Start Local Process", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_process(params: TubeProcessParams) -> str:
    '''Start a local process for interaction (pwntools tube).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        args = [params.binary] + (params.args.split() if params.args else [])
        tube = pwn.process(args, timeout=params.timeout)
        tid = params.tube_id
        _tubes[tid] = tube
        return f"Process started: {params.binary}\n  PID: {tube.pid}\n  Tube ID: '{tid}'\n  Connected: {tube.connected()}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_remote",
    annotations={"title": "Connect to Remote Service", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_remote(params: TubeRemoteParams) -> str:
    '''Connect to a remote TCP service (pwntools tube).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        tube = pwn.remote(params.host, params.port, timeout=params.timeout)
        tid = params.tube_id
        _tubes[tid] = tube
        return f"Connected to {params.host}:{params.port}\n  Tube ID: '{tid}'\n  Connected: {tube.connected()}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_tube_send",
    annotations={"title": "Send Data to Tube", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_tube_send(params: TubeSendParams) -> str:
    '''Send raw data to an active tube (process or remote).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        tube = _get_tube(params.tube_id)
        data = params.data.encode("latin-1") if "\\x" in params.data else params.data.encode()
        tube.send(data)
        return f"Sent {len(data)} bytes to tube '{params.tube_id}'"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_tube_sendline",
    annotations={"title": "Send Line to Tube", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_tube_sendline(params: TubeSendParams) -> str:
    '''Send a line (with newline) to an active tube.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        tube = _get_tube(params.tube_id)
        data = params.data.encode("latin-1") if "\\x" in params.data else params.data.encode()
        tube.sendline(data)
        return f"Sent line ({len(data)}+1 bytes) to tube '{params.tube_id}'"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_tube_recv",
    annotations={"title": "Receive from Tube", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_tube_recv(params: TubeRecvParams) -> str:
    '''Receive data from an active tube.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        tube = _get_tube(params.tube_id)
        data = tube.recv(params.nbytes, timeout=params.timeout)
        hex_repr = data.hex()
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return (
            f"Received {len(data)} bytes from tube '{params.tube_id}':\n"
            f"  Raw: {data!r}\n"
            f"  Hex: {' '.join(hex_repr[i:i+2] for i in range(0, len(hex_repr), 2))}\n"
            f"  ASCII: {ascii_repr}"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_tube_recvline",
    annotations={"title": "Receive Line from Tube", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_tube_recvline(params: TubeRecvParams) -> str:
    '''Receive a single line from an active tube.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        tube = _get_tube(params.tube_id)
        data = tube.recvline(timeout=params.timeout)
        hex_repr = data.hex()
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return (
            f"Received line ({len(data)} bytes) from tube '{params.tube_id}':\n"
            f"  Raw: {data!r}\n"
            f"  Hex: {' '.join(hex_repr[i:i+2] for i in range(0, len(hex_repr), 2))}\n"
            f"  ASCII: {ascii_repr}"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_tube_recvuntil",
    annotations={"title": "Receive Until Pattern", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_tube_recvuntil(params: TubeRecvUntilParams) -> str:
    '''Receive data from a tube until a pattern is found.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        tube = _get_tube(params.tube_id)
        data = tube.recvuntil(params.pattern.encode(), drop=params.drop, timeout=params.timeout)
        hex_repr = data.hex()
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return (
            f"Received until '{params.pattern}' ({len(data)} bytes) from tube '{params.tube_id}':\n"
            f"  Raw: {data!r}\n"
            f"  Hex: {' '.join(hex_repr[i:i+2] for i in range(0, len(hex_repr), 2))}\n"
            f"  ASCII: {ascii_repr}"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_tube_close",
    annotations={"title": "Close Active Tube", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def pwntools_tube_close(params: TubeBaseParams) -> str:
    '''Close an active tube connection.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        tube = _get_tube(params.tube_id)
        tube.close()
        tid = params.tube_id if params.tube_id != "last" else next(
            (k for k, v in _tubes.items() if v is tube), "last"
        )
        if tid in _tubes:
            del _tubes[tid]
        return f"Tube '{params.tube_id}' closed"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_tube_list",
    annotations={"title": "List Active Tubes", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_tube_list() -> str:
    '''List all active tube connections.'''
    if not _tubes:
        return "No active tubes"
    lines = ["Active tubes:", ""]
    for tid, tube in _tubes.items():
        conn = tube.connected()
        pid = getattr(tube, "pid", "N/A")
        lines.append(f"  [{tid}] PID={pid} connected={conn}")
    return "\n".join(lines)


@mcp.tool(
    name="pwntools_elf_diff",
    annotations={"title": "Diff Two ELF Binaries", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_elf_diff(params: ElfDiffParams) -> str:
    '''Compare two ELF binaries: sections, segments, symbols.'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        a = pwn.ELF(params.path_a, checksec=False)
        b = pwn.ELF(params.path_b, checksec=False)
        lines = [f"Diff: {params.path_a} vs {params.path_b}", ""]

        a_secs = {s.name: s for s in a.sections if s.name}
        b_secs = {s.name: s for s in b.sections if s.name}
        a_only = set(a_secs) - set(b_secs)
        b_only = set(b_secs) - set(a_secs)
        common = set(a_secs) & set(b_secs)

        if a_only:
            lines.append(f"Sections only in A ({len(a_only)}): {', '.join(sorted(a_only))}")
        if b_only:
            lines.append(f"Sections only in B ({len(b_only)}): {', '.join(sorted(b_only))}")

        diff_count = 0
        for name in sorted(common):
            sa, sb = a_secs[name], b_secs[name]
            ha, hb = sa.header, sb.header
            if ha.sh_addr != hb.sh_addr or ha.sh_size != hb.sh_size:
                lines.append(f"  {name}: addr {hex(ha.sh_addr)}->{hex(hb.sh_addr)}, size {hex(ha.sh_size)}->{hex(hb.sh_size)}")
                diff_count += 1

        if diff_count == 0 and not a_only and not b_only:
            lines.append("  No differences found")

        lines.append("")
        a_syms = {s.name for s in a.symbols if s.name}
        b_syms = {s.name for s in b.symbols if s.name}
        sym_diff = a_syms ^ b_syms
        if sym_diff:
            lines.append(f"Symbol differences: {len(sym_diff)} unique")
            for s in sorted(sym_diff)[:20]:
                side = "A" if s in a_syms else "B"
                lines.append(f"  [{side}] {s}")
            if len(sym_diff) > 20:
                lines.append(f"  ... and {len(sym_diff) - 20} more")

        lines.append("")
        lines.append(f"A: {params.path_a} ({a.arch} {a.bits}-bit)")
        lines.append(f"B: {params.path_b} ({b.arch} {b.bits}-bit)")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_bits",
    annotations={"title": "Get/Set Integer Bits", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_bits(params: BitsParams) -> str:
    '''Get or set a specific bit in an integer.'''
    try:
        current = (params.value >> params.bit) & 1
        if params.set_to == -1:
            return (
                f"Bit inspection of {hex(params.value)} ({params.value}):\n"
                f"  Bit {params.bit}: {current} ({'set' if current else 'clear'})"
            )
        new = params.value
        if params.set_to:
            new |= (1 << params.bit)
        else:
            new &= ~(1 << params.bit)
        changed = "changed" if new != params.value else "unchanged"
        return (
            f"Bit {params.bit} set to {params.set_to} ({changed}):\n"
            f"  Before: {hex(params.value)} ({params.value})\n"
            f"  After:  {hex(new)} ({new})"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_context",
    annotations={"title": "View/Set Pwntools Context", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_context(params: ContextParams) -> str:
    '''View or modify pwntools global context (arch, os, endian, log_level).'''
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        changed = []
        if params.arch:
            pwn.context.arch = params.arch
            changed.append(f"arch={params.arch}")
        if params.os:
            pwn.context.os = params.os
            changed.append(f"os={params.os}")
        if params.endian:
            pwn.context.endian = params.endian
            changed.append(f"endian={params.endian}")
        if params.log_level:
            pwn.context.log_level = params.log_level
            changed.append(f"log_level={params.log_level}")
        if params.bits:
            pwn.context.bits = params.bits
            changed.append(f"bits={params.bits}")

        ctx = pwn.context
        header = "Context updated" if changed else "Current context"
        return (
            f"{header}:\n"
            f"  Arch:      {ctx.arch}\n"
            f"  Bits:      {ctx.bits}\n"
            f"  Endian:    {ctx.endian}\n"
            f"  OS:        {ctx.os}\n"
            f"  Log Level: {ctx.log_level}\n"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(
    name="pwntools_log_level",
    annotations={"title": "Set Pwntools Log Level", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def pwntools_log_level(level: str) -> str:
    '''Set pwntools log verbosity. Levels: debug, info, warning, error.'''
    valid = {"debug", "info", "warning", "error"}
    if level not in valid:
        return f"Error: invalid level '{level}'. Valid: {', '.join(sorted(valid))}"
    if not _pwntools_available():
        return "Error: pwntools not installed"
    try:
        pwn = _import_pwn()
        pwn.context.log_level = level
        return f"Log level set to: {level}"
    except Exception as e:
        return f"Error: {e}"
