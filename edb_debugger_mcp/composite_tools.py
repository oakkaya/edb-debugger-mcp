"""Composite MCP tools for pwntools — 7 tools replacing all 50+ flat functions."""

import json
from typing import Literal, Optional

from edb_debugger_mcp._mcp import mcp, backend, GDBBackendError


_PWNTOOLS_READY = None


def _pwntools_available() -> bool:
    global _PWNTOOLS_READY
    if _PWNTOOLS_READY is None:
        try:
            import pwn  # noqa: F401
            _PWNTOOLS_READY = True
        except ImportError:
            _PWNTOOLS_READY = False
    return _PWNTOOLS_READY


def _import_pwn():
    import pwn
    pwn.context.log_level = "error"
    return pwn


_tubes: dict = {}


def _get_tube(tube_id: str = "last"):
    if tube_id == "last":
        if not _tubes:
            raise RuntimeError("No active tubes. Start one with pwntools_process or pwntools_remote")
        return list(_tubes.values())[-1]
    if tube_id not in _tubes:
        raise RuntimeError(f"Tube '{tube_id}' not found")
    return _tubes[tube_id]


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
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            lines = [f"=== ELF Analysis: {path} ===", ""]

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


    elif action == "checksec":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            nx = not elf.execstack
            relro_map = {"Full": "GOT is read-only", "Partial": "GOT still writable", "None": "No RELRO"}
            relro_detail = relro_map.get(str(elf.relro), "")
            rpath = getattr(elf, "rpath", None)
            runpath = getattr(elf, "runpath", None)
            fortify = getattr(elf, "fortify", None)
            lines = [
                f"Security properties for: {path}",
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


    elif action == "read":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)

            if section:
                sec = elf.get_section_by_name(section)
                if sec is None:
                    return (f"Error: section '{section}' not found.\n"
                            f"Available sections: {', '.join(s.name for s in elf.sections if s.name)}")
                base = sec.header.sh_addr
                read_addr = base + (offset or 0)
                sec_size = sec.header.sh_size
                if (offset or 0) + size > sec_size:
                    return (f"Error: read would exceed section bounds.\n"
                            f"  Section '{section}' base={hex(base)} size={hex(sec_size)}\n"
                            f"  Requested offset={offset or 0} size={size} "
                            f"exceeds {hex(sec_size)}")
                location_desc = f"section '{section}'"
                if offset:
                    location_desc += f" + {offset}"
                location_desc += f" (addr {hex(read_addr)})"
            elif offset is not None:
                read_addr = offset
                location_desc = f"virtual address {hex(read_addr)}"
            else:
                return "Error: provide either 'section' or 'offset'"

            data = elf.read(read_addr, size)
            dump = pwn.hexdump(data)

            result = [
                f"=== ELF Read: {path} ===",
                f"  Location: {location_desc}",
                f"  Bytes: {len(data)}",
                "",
                dump,
            ]
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"


    elif action == "sections":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)

            type_names = {
                0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
                5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
                10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
                16: "PREINIT_ARRAY", 17: "GROUP", 18: "SYMTAB_SHNDX",
            }
            flag_names = {1: "W", 2: "A", 4: "X", 0x10: "T"}

            result = [f"Sections in {path}:", "",
                      f"  {'Nr':3s} {'Name':22s} {'Type':14s} {'Addr':18s} {'Off':8s} {'Size':8s} {'Flags':6s} {'Align':5s}",
                      f"  {'--':3s} {'----':22s} {'----':14s} {'----':18s} {'---':8s} {'----':8s} {'-----':6s} {'-----':5s}"]

            shown = 0
            for i, sec in enumerate(elf.sections):
                name = sec.name or "(unnamed)"
                if filter_name and filter_name.lower() not in name.lower():
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


    elif action == "symbols":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            import re as re_mod
            pattern_re = re_mod.compile(pattern if pattern else ".")

            matches = []
            for sym_name, addr in elf.symbols.items():
                if not pattern_re.search(sym_name):
                    continue
                if not isinstance(addr, int):
                    continue
                matches.append((sym_name, addr))

            matches.sort(key=lambda x: x[1])
            result = [f"Symbols in {path} matching /{pattern}/:", "",
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


    elif action == "strings":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)

            if section:
                sec = elf.get_section_by_name(section)
                if sec is None:
                    available = [s.name for s in elf.sections if s.name]
                    return (f"Error: section '{section}' not found.\n"
                            f"Available: {', '.join(available)}")
                data = sec.data()
                offset_base = sec.header.sh_addr
                section_label = f"section '{section}'"
            else:
                data = elf.data
                offset_base = 0
                section_label = "entire binary"

            import re as re_mod
            pattern = re_mod.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
            matches = [(m.start() + offset_base, m.group().decode("ascii")) for m in pattern.finditer(data)]

            if not matches:
                return f"No strings found in {section_label} (min_length={min_length})"

            result = [f"Strings in {path} ({section_label}):", "",
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


    elif action == "deps":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)

            result = [f"Dependencies for {path}:", ""]

            needed = list(elf.dependencies) if hasattr(elf, "dependencies") else []
            if not needed:
                result.append("  (no dynamic dependencies - statically linked or stripped)")
            else:
                result.append(f"  DT_NEEDED ({len(needed)} entries):")
                for dep in needed:
                    result.append(f"    {dep}")

            if resolve_versions:
                result.append("")
                result.append("  Resolving library versions from system...")
                import subprocess as sp
                try:
                    r = sp.run(["ldd", path], capture_output=True, text=True, timeout=10)
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


    elif action == "got":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            got = elf.got
            if not got:
                return f"No GOT entries found in {path}"
            result = [f"GOT entries in {path}:", "",
                      f"  {'Symbol':25s} {'Address':18s}",
                      f"  {'-'*25} {'-'*18}"]
            for name, addr in sorted(got.items(), key=lambda x: x[1]):
                result.append(f"  {name:25s} {hex(addr):18s}")
            result.append("")
            result.append(f"Total: {len(got)} entries")
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"


    elif action == "plt":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            plt = elf.plt
            if not plt:
                return f"No PLT entries found in {path}"
            result = [f"PLT entries in {path}:", "",
                      f"  {'Symbol':25s} {'Address':18s}",
                      f"  {'-'*25} {'-'*18}"]
            for name, addr in sorted(plt.items(), key=lambda x: x[1]):
                result.append(f"  {name:25s} {hex(addr):18s}")
            result.append("")
            result.append(f"Total: {len(plt)} entries")
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"


    elif action == "segments":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            seg_types = {
                0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
                5: "SHLIB", 6: "PHDR", 7: "TLS", 0x6474e550: "GNU_EH_FRAME",
                0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO",
                0x6474e553: "GNU_PROPERTY",
            }
            result = [f"Program headers in {path}:", "",
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


    elif action == "relocs":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            relocs = list(elf.relocs) if hasattr(elf, "relocs") and elf.relocs else []
            if not relocs:
                return f"No relocations found in {path}"
            filtered = []
            for r in relocs:
                rtype = str(r.type)
                if type_filter == "got" and "GLOB_DAT" not in rtype and "JUMP_SLOT" not in rtype:
                    continue
                if type_filter == "plt" and "JUMP_SLOT" not in rtype:
                    continue
                if type_filter == "absolute" and "RELATIVE" not in rtype:
                    continue
                if type_filter == "relative" and "RELATIVE" not in rtype:
                    continue
                filtered.append(r)
            if not filtered:
                return f"No matching relocations for filter '{type_filter}'"
            result = [f"Relocations in {path}:", "",
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


    elif action == "notes":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            notes = elf.notes if hasattr(elf, "notes") else []
            if notes:
                result = [f"ELF notes in {path}:", ""]
                for n in notes:
                    ntype = str(n.n_type) if hasattr(n, "n_type") else ""
                    ndesc = str(n.n_desc) if hasattr(n, "n_desc") else ""
                    result.append(f"  Type: {ntype}")
                    result.append(f"  Desc: {ndesc}")
                    result.append("")
                return "\n".join(result)
            else:
                return f"No notes found in {path}"
        except Exception as e:
            return f"Error: {e}"


    elif action == "diff":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            a = pwn.ELF(path, checksec=False)
            b = pwn.ELF(path_b, checksec=False)
            lines = [f"Diff: {path} vs {path_b}", ""]

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
            lines.append(f"A: {path} ({a.arch} {a.bits}-bit)")
            lines.append(f"B: {path_b} ({b.arch} {b.bits}-bit)")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {e}"


    elif action == "search":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            pattern_bytes = bytes.fromhex(pattern.replace(" ", "").replace("\\x", ""))

            with open(path, "rb") as f:
                data = f.read()

            start = start or 0
            end = end or len(data)
            search_region = data[start:end]

            matches = []
            pos = 0
            while True:
                pos = search_region.find(pattern_bytes, pos)
                if pos == -1:
                    break
                matches.append(start + pos)
                pos += 1

            elf = pwn.ELF(path, checksec=False)
            result = [
                f"=== Search in {path} ===",
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


    elif action == "patch":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            data = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))

            with open(path, "rb") as f:
                original = f.read()

            if offset + len(data) > len(original):
                return (f"Error: patch at offset {offset} with {len(data)} bytes "
                        f"exceeds file size ({len(original)})")

            patched = bytearray(original)
            old_bytes = bytes(patched[offset:offset + len(data)])
            patched[offset:offset + len(data)] = data

            backup_path = path + ".bak"
            with open(backup_path, "wb") as f:
                f.write(original)

            with open(path, "wb") as f:
                f.write(patched)

            result = [
                f"=== ELF Patched: {path} ===",
                f"  Offset: {hex(offset)}",
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


    elif action == "make":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch, os="linux", log_level="error")

            output = output
            if not output:
                import tempfile
                output = tempfile.mktemp(suffix=".elf")

            pwn.make_elf(
                pwn.asm(code),
                extract=False,
                path=output,
            )

            import os as os_mod
            st = os_mod.stat(output)

            elf = pwn.ELF(output, checksec=False) if os_mod.path.getsize(output) > 0 else None
            result = [
                "=== ELF Created ===",
                f"  Path: {output}",
                f"  Size: {st.st_size} bytes",
                "",
                f"  Assembly source ({arch}):",
            ]
            for line in code.split(";"):
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


    elif action == "entropy":
        try:
            with open(path, "rb") as f:
                off = offset or 0
                if off > 0:
                    f.seek(off)
                data = f.read(size) if size else f.read()

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
                f"=== Entropy Analysis: {path} ===",
                f"  Offset: {hex(off)}",
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
                result.append("\n  Per-block entropy (256B blocks):")
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
            return f"Error: file not found: {path}"
        except Exception as e:
            return f"Error: {e}"


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
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            rop = pwn.ROP(elf)
            gadgets = rop.gadgets

            if not gadgets:
                return "No ROP gadgets found (binary might be statically stripped or too small)"

            gadget_list = list(gadgets.items())
            filtered = []
            for addr, g in gadget_list:
                insns = "; ".join(g.insns)
                if grep:
                    if grep.lower() in insns.lower():
                        filtered.append((addr, insns))
                else:
                    filtered.append((addr, insns))

            count = min(len(filtered), count)
            result = [f"ROP gadgets in {path} (showing {count}/{len(filtered)}):", ""]
            for i, (addr, insns) in enumerate(filtered[:count]):
                result.append(f"  {hex(addr)}: {insns}")

            result.append("")
            result.append(f"Total gadgets: {len(gadgets)}, filtered: {len(filtered)}")
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"


    elif action == "erope":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            rop = pwn.ROP(elf)
            gadgets = rop.gadgets
            if not gadgets:
                return "No ROP gadgets found"

            valid_types = ("all", "syscall", "stack_pivot", "call", "jump")
            if gadget_type not in valid_types:
                return f"Error: invalid gadget_type '{gadget_type}'. Valid: {', '.join(valid_types)}"

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

            result = [f"Extended ROP gadgets in {path} (type: {gadget_type})", ""]
            show_all = gadget_type == "all"
            shown_total = 0
            for cat_name in ("syscall", "stack_pivot", "call", "jump"):
                if not show_all and cat_name != gadget_type:
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
                return f"No gadgets found matching type '{gadget_type}'"
            result.append(f"Total matching: {shown_total}")
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"


    elif action == "build_chain":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            elf = pwn.ELF(path, checksec=False)
            rop = pwn.ROP(elf)

            target = int(target, 0) if target.startswith("0x") else elf.symbols.get(target)
            if target is None:
                return f"Error: target '{target}' not found in symbols. Use pwntools_analyze_elf to list available symbols."

            if args:
                for arg in args.split(","):
                    arg_val = int(arg.strip(), 0) if arg.strip().startswith("0x") else arg.strip()
                    rop.call(target, [arg_val])
            else:
                rop.call(target)

            chain = rop.chain()
            rop_text = str(rop)
            return json.dumps({
                "path": path,
                "target": target,
                "args": args or "(none)",
                "chain_hex": chain.hex(),
                "chain_bytes": " ".join(f"{b:02x}" for b in chain),
                "chain_length": len(chain),
                "rop_dump": rop_text,
            }, indent=2)
        except Exception as e:
            return f"Error: {e}"


    elif action == "sigreturn":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch, os="linux", log_level="error")

            frame = pwn.SigreturnFrame()
            reg_map = {
                "amd64": {"rax": "rax", "rdi": "rdi", "rsi": "rsi", "rdx": "rdx", "rip": "rip"},
                "i386": {"rax": "eax", "rdi": "edi", "rsi": "esi", "rdx": "edx", "rip": "eip"},
            }
            regs = reg_map.get(arch, reg_map["amd64"])

            if rax:
                setattr(frame, regs["rax"], int(rax, 0))
            if rdi:
                setattr(frame, regs["rdi"], int(rdi, 0))
            if rsi:
                setattr(frame, regs["rsi"], int(rsi, 0))
            if rdx:
                setattr(frame, regs["rdx"], int(rdx, 0))
            if rip:
                setattr(frame, regs["rip"], int(rip, 0))

            packed = bytes(frame)
            result = [
                f"=== SROP Frame ({arch}) ===",
                f"  Size: {len(packed)} bytes",
                "",
                "  Register layout:",
            ]
            if arch == "amd64":
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


    elif action == "fmtstr_payload":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            writes = json.loads(writes)
            converted = {}
            for k, v in writes.items():
                if isinstance(k, str):
                    try:
                        k = int(k, 0)
                    except ValueError:
                        pass
                converted[k] = v
            writes = converted
            payload = pwn.fmtstr_payload(offset, writes, numbwritten=numbwritten)
            return json.dumps({
                "offset": offset,
                "writes": writes,
                "numbwritten": numbwritten,
                "payload_hex": payload.hex(),
                "payload_bytes": " ".join(f"{b:02x}" for b in payload),
                "payload_length": len(payload),
            }, indent=2)
        except Exception as e:
            return f"Error: {e}"


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
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch, os="linux")
            sc = pwn.shellcraft

            def _to_bytes(val):
                if isinstance(val, bytes):
                    return val
                return val.encode("latin-1")

            purpose = purpose
            if purpose == "sh":
                code = _to_bytes(sc.sh())
                desc = "execve('/bin/sh', 0, 0)"
            elif purpose == "execve":
                cmd = args or "/bin/sh"
                code = _to_bytes(sc.execve(cmd))
                desc = f"execve('{cmd}', 0, 0)"
            elif purpose == "bind_shell":
                port = int(args) if args else 4444
                code = _to_bytes(sc.bindsh(port))
                desc = f"bind shell on port {port}"
            elif purpose == "reverse_shell":
                host_port = args.split() if args else ["127.0.0.1", "4444"]
                host = host_port[0] if len(host_port) > 0 else "127.0.0.1"
                port = int(host_port[1]) if len(host_port) > 1 else 4444
                code = _to_bytes(sc.connect(host, port))
                desc = f"reverse shell to {host}:{port}"
            elif purpose == "read_file":
                fpath = args or "/etc/passwd"
                code = _to_bytes(sc.cat(fpath))
                desc = f"read file: {fpath}"
            elif purpose == "write_file":
                parts = args.split(maxsplit=1) if args else ["/tmp/out", "data"]
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
                f"  Architecture: {arch}",
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


    elif action == "encode":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch, os="linux")

            data = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))
            if not data:
                return "Error: empty or invalid hex bytes"

            valid_encoders = ("alphanumeric", "null_free", "xor")
            if encoder not in valid_encoders:
                return f"Error: invalid encoder '{encoder}'. Valid: {', '.join(valid_encoders)}"

            encoded = None
            decoder_bytes = None

            encoders_found = False
            for src in (pwn.encoders.encoder,):
                try:
                    enc_mod = getattr(src, encoder, None)
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
                return (f"Encoder '{encoder}' not available in this pwntools version.\n"
                        "The pwntools encoders API has changed across versions.\n"
                        "Try upgrading: pip install -U pwntools\n"
                        "Or check available encoders with: python -c \"from pwn import *; print(dir(encoders.encoder))\"")

            result = [
                f"=== Shellcode Encoding ({encoder}) ===",
                f"  Architecture: {arch}",
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
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch, os="linux")
            data = bytes.fromhex(data.replace(" ", "").replace("\\x", ""))
            asm = pwn.disasm(data)
            return f"=== Disassembly ({arch}) ===\n\n{asm}"
        except Exception as e:
            return f"Error: {e}"


    elif action == "assemble":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch, os="linux")
            code = pwn.asm(data)
            hex_str = code.hex()
            asm_result = pwn.disasm(code)
            return json.dumps({
                "code": data,
                "arch": arch,
                "hex": hex_str,
                "bytes": " ".join(f"{b:02x}" for b in code),
                "length": len(code),
                "disassembly": asm_result.strip(),
            }, indent=2)
        except Exception as e:
            return f"Error: {e}"


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
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            val = int(value, 0)
            pack_map = {1: pwn.p8, 2: pwn.p16, 4: pwn.p32, 8: pwn.p64}
            fn = pack_map.get(size)
            if not fn:
                return f"Error: unsupported size {size}, use 1, 2, 4, or 8"
            packed = fn(val, endian=endian)
            hex_str = packed.hex()
            return json.dumps({
                "value": value,
                "int": val,
                "size": size,
                "endian": endian,
                "packed_hex": hex_str,
                "packed_repr": " ".join(f"{b:02x}" for b in packed),
                "length": len(packed),
            }, indent=2)
        except Exception as e:
            return f"Error: {e}"


    elif action == "unpack":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            data = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))
            unpack_map = {1: pwn.u8, 2: pwn.u16, 4: pwn.u32, 8: pwn.u64}
            fn = unpack_map.get(size)
            if not fn:
                return f"Error: unsupported size {size}"
            val = fn(data, endian=endian)
            return json.dumps({
                "hex_bytes": hex_bytes,
                "int": val,
                "hex": hex(val),
                "size": size,
                "endian": endian,
            }, indent=2)
        except Exception as e:
            return f"Error: {e}"


    elif action == "enhex":
        try:
            data = data.encode("latin-1") if "\\x" in data else data.encode()
            hex_str = data.hex()
            formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            return f"Raw ({len(data)} bytes): {data}\nHex ({len(hex_str)//2} bytes): {formatted}"
        except Exception as e:
            return f"Error: {e}"


    elif action == "unhex":
        try:
            clean = hex_str.replace(" ", "").replace("0x", "").replace("\\x", "")
            data = bytes.fromhex(clean)
            printable = "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in data)
            return f"Hex: {hex_str}\nDecoded ({len(data)} bytes): {data!r}\nPrintable: {printable}"
        except Exception as e:
            return f"Error: {e}"


    elif action == "flat":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch, os="linux", endian=endian, log_level="error")
            if pack_size == 4:
                pwn.context.bits = 32

            try:
                values = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                import ast
                values = ast.literal_eval(value)
            packed = pwn.flat(values)
            result = [
                f"=== Flat ({len(packed)} bytes) ===",
                f"  Values: {value[:200]}{'...' if len(value) > 200 else ''}",
                f"  Arch: {arch}  Endian: {endian}",
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
            result.append("  C-array: unsigned char payload[] = {")
            result.append(f"    {c_bytes}")
            result.append("  };")
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"


    elif action == "hexdump":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            data = bytes.fromhex(hex_data.replace(" ", "").replace("\\x", ""))
            dump = pwn.hexdump(data)
            return f"=== Hex dump ({len(data)} bytes) ===\n\n{dump}"
        except Exception as e:
            return f"Error: {e}"


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
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            pattern = pwn.cyclic(count)
            result = [
                f"=== Cyclic pattern ({count} bytes) ===",
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


    elif action == "cyclic_find":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            val = int(value, 0) if value.startswith("0x") else value
            offset = pwn.cyclic_find(val, n=length)
            if offset == -1:
                return f"Value {value} not found in cyclic pattern (length={length})"
            return json.dumps({
                "value": value,
                "offset": offset,
                "meaning": f"Buffer overflow offset is {offset} bytes (before return address overwrite)"
            }, indent=2)
        except Exception as e:
            return f"Error: {e}"


    elif action == "rol":
        _value = int(value, 0) if isinstance(value, str) and value else 0
        try:
            mask = (1 << bits) - 1
            result_val = ((_value << shift) | (_value >> (bits - shift))) & mask
            return (
                f"ROL {bits}-bit, shift {shift}:\n"
                f"  Input:  {hex(_value)} ({_value})\n"
                f"  Output: {hex(result_val)} ({result_val})"
            )
        except Exception as e:
            return f"Error: {e}"


    elif action == "ror":
        _value = int(value, 0) if isinstance(value, str) and value else 0
        try:
            mask = (1 << bits) - 1
            result_val = ((_value >> shift) | (_value << (bits - shift))) & mask
            return (
                f"ROR {bits}-bit, shift {shift}:\n"
                f"  Input:  {hex(_value)} ({_value})\n"
                f"  Output: {hex(result_val)} ({result_val})"
            )
        except Exception as e:
            return f"Error: {e}"


    elif action == "bits":
        _value = int(value, 0) if isinstance(value, str) and value else 0
        try:
            current = (_value >> bit) & 1
            if set_to == -1:
                return (
                    f"Bit inspection of {hex(_value)} ({_value}):\n"
                    f"  Bit {bit}: {current} ({'set' if current else 'clear'})"
                )
            new = _value
            if set_to:
                new |= (1 << bit)
            else:
                new &= ~(1 << bit)
            changed = "changed" if new != _value else "unchanged"
            return (
                f"Bit {bit} set to {set_to} ({changed}):\n"
                f"  Before: {hex(_value)} ({_value})\n"
                f"  After:  {hex(new)} ({new})"
            )
        except Exception as e:
            return f"Error: {e}"


    elif action == "align":
        _value = int(value, 0) if isinstance(value, str) and value else 0
        try:
            aligned_down = _value & ~(alignment - 1)
            aligned_up = (_value + alignment - 1) & ~(alignment - 1)
            pages_used = (_value + alignment - 1) // alignment
            return (
                f"Alignment calculation for {hex(_value)} (alignment: {hex(alignment)}):\n"
                f"  Original:     {hex(_value)} ({_value})\n"
                f"  Aligned down: {hex(aligned_down)} ({aligned_down})\n"
                f"  Aligned up:   {hex(aligned_up)} ({aligned_up})\n"
                f"  Pages used:   {pages_used}"
            )
        except Exception as e:
            return f"Error: {e}"


    elif action == "constgrep":
        if not _pwntools_available():
            return "Error: pwntools not installed. Run: pip install pwntools"
        try:
            pwn = _import_pwn()
            pwn.context.clear()
            pwn.context.update(arch=arch)

            search_lower = search.lower()

            # Try pwn.constgrep (newer pwntools API)
            try:
                constgrep = getattr(pwn, "constgrep", None)
                if constgrep:
                    results = constgrep(search_lower, arch=arch)
                    matches = []
                    for item in list(results)[:limit]:
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
                        result = [f"Constants matching '{search}' ({arch}):", ""]
                        for name, val in matches:
                            if isinstance(val, int):
                                result.append(f"  {name:45s} = {hex(val)} ({val})")
                            else:
                                result.append(f"  {name:45s} = {val}")
                        result.append("")
                        result.append(f"Total: {len(matches)} / {len(results)} matching (limited to {limit})")
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
                        if len(matches) >= limit:
                            break

            if matches:
                result = [f"Constants matching '{search}' ({arch}):", ""]
                for name, val in matches:
                    if isinstance(val, int):
                        result.append(f"  {name:45s} = {hex(val)} ({val})")
                    else:
                        result.append(f"  {name:45s} = {val}")
                result.append("")
                result.append(f"Total: {len(matches)} (limited to {limit})")
                return "\n".join(result)
            else:
                return f"No constants found matching '{search}'"
        except Exception as e:
            return f"Error: {e}"


    elif action == "context":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            changed = []
            if arch:
                pwn.context.arch = arch
                changed.append(f"arch={arch}")
            if target_os:
                pwn.context.os = target_os
                changed.append(f"os={target_os}")
            if endian:
                pwn.context.endian = endian
                changed.append(f"endian={endian}")
            if log_level:
                pwn.context.log_level = log_level
                changed.append(f"log_level={log_level}")
            if bits:
                pwn.context.bits = bits
                changed.append(f"bits={bits}")

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


    elif action == "log_level":
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
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            args = [binary] + (args.split() if args else [])
            tube = pwn.process(args, timeout=timeout)
            tid = tube_id
            _tubes[tid] = tube
            return f"Process started: {binary}\n  PID: {tube.pid}\n  Tube ID: '{tid}'\n  Connected: {tube.connected()}"
        except Exception as e:
            return f"Error: {e}"


    elif action == "remote":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            pwn = _import_pwn()
            tube = pwn.remote(host, port, timeout=timeout)
            tid = tube_id
            _tubes[tid] = tube
            return f"Connected to {host}:{port}\n  Tube ID: '{tid}'\n  Connected: {tube.connected()}"
        except Exception as e:
            return f"Error: {e}"


    elif action == "send":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            tube = _get_tube(tube_id)
            data = data.encode("latin-1") if "\\x" in data else data.encode()
            tube.send(data)
            return f"Sent {len(data)} bytes to tube '{tube_id}'"
        except Exception as e:
            return f"Error: {e}"


    elif action == "sendline":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            tube = _get_tube(tube_id)
            data = data.encode("latin-1") if "\\x" in data else data.encode()
            tube.sendline(data)
            return f"Sent line ({len(data)}+1 bytes) to tube '{tube_id}'"
        except Exception as e:
            return f"Error: {e}"


    elif action == "recv":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            tube = _get_tube(tube_id)
            data = tube.recv(nbytes, timeout=timeout)
            hex_repr = data.hex()
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            return (
                f"Received {len(data)} bytes from tube '{tube_id}':\n"
                f"  Raw: {data!r}\n"
                f"  Hex: {' '.join(hex_repr[i:i+2] for i in range(0, len(hex_repr), 2))}\n"
                f"  ASCII: {ascii_repr}"
            )
        except Exception as e:
            return f"Error: {e}"


    elif action == "recvline":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            tube = _get_tube(tube_id)
            data = tube.recvline(timeout=timeout)
            hex_repr = data.hex()
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            return (
                f"Received line ({len(data)} bytes) from tube '{tube_id}':\n"
                f"  Raw: {data!r}\n"
                f"  Hex: {' '.join(hex_repr[i:i+2] for i in range(0, len(hex_repr), 2))}\n"
                f"  ASCII: {ascii_repr}"
            )
        except Exception as e:
            return f"Error: {e}"


    elif action == "recvuntil":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            tube = _get_tube(tube_id)
            data = tube.recvuntil(pattern.encode(), drop=drop, timeout=timeout)
            hex_repr = data.hex()
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            return (
                f"Received until '{pattern}' ({len(data)} bytes) from tube '{tube_id}':\n"
                f"  Raw: {data!r}\n"
                f"  Hex: {' '.join(hex_repr[i:i+2] for i in range(0, len(hex_repr), 2))}\n"
                f"  ASCII: {ascii_repr}"
            )
        except Exception as e:
            return f"Error: {e}"


    elif action == "close":
        if not _pwntools_available():
            return "Error: pwntools not installed"
        try:
            tube = _get_tube(tube_id)
            tube.close()
            tid = tube_id if tube_id != "last" else next(
                (k for k, v in _tubes.items() if v is tube), "last"
            )
            if tid in _tubes:
                del _tubes[tid]
            return f"Tube '{tube_id}' closed"
        except Exception as e:
            return f"Error: {e}"


    elif action == "list":
        if not _tubes:
            return "No active tubes"
        lines = ["Active tubes:", ""]
        for tid, tube in _tubes.items():
            conn = tube.connected()
            pid = getattr(tube, "pid", "N/A")
            lines.append(f"  [{tid}] PID={pid} connected={conn}")
        return "\n".join(lines)


    return f"Unknown action: {action}"


# ====================================================================
# edb_* tools (unchanged)
# ====================================================================

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
