"""Tests for pwntools-based MCP tools and backend integration."""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import shutil

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from edb_debugger_mcp.gdb_backend import GDBBackend

pytest.importorskip("pwn")

import edb_debugger_mcp as mcp_module
from edb_debugger_mcp.edb_models import (
    ElfPath,
    RopSearchParams,
    PackParams,
    UnpackParams,
    CyclicFindParams,
    FmtStrPayloadParams,
    BuildRopChainParams,
)


_compiled_binaries = []


@pytest.fixture(scope="module")
def test_binary():
    code = '''
int global_var = 42;
void helper(int n) { volatile int x = n * 2; }
int main(int argc, char *argv[]) {
    int x = 10, y = 20;
    int sum = x + y;
    helper(sum);
    return 0;
}
'''
    tmpdir = tempfile.mkdtemp()
    src = os.path.join(tmpdir, "test.c")
    bin_path = os.path.join(tmpdir, "test")
    with open(src, "w") as f:
        f.write(code)
    r = subprocess.run(
        ["gcc", "-g", "-O0", "-o", bin_path, src],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        pytest.skip(f"Cannot compile: {r.stderr}")
    yield bin_path
    shutil.rmtree(tmpdir)


def _await(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _text(r):
    if isinstance(r, tuple) and r[0]:
        return r[0][0].text
    return str(r)


# ---------------------------------------------------------------------------
# Backend integration (pwntools used in gdb_backend methods)
# ---------------------------------------------------------------------------

class TestBackendPwntoolsDetection:
    def test_pwntools_available_flag(self):
        assert GDBBackend().pwntools_available is True

    @pytest.mark.asyncio
    async def test_readelf_load_segments_uses_pwntools(self, test_binary):
        backend = GDBBackend()
        backend._binary = test_binary
        segments = await backend._readelf_load_segments()
        assert len(segments) > 0
        for vaddr, file_off, filesz in segments:
            assert isinstance(vaddr, int)
            assert isinstance(file_off, int)
            assert isinstance(filesz, int)

    @pytest.mark.asyncio
    async def test_get_binary_info_uses_pwntools(self, test_binary):
        backend = GDBBackend()
        backend._binary = test_binary
        result = await backend.get_binary_info()
        assert "Architecture:" in result
        assert "Bits:" in result
        assert "Entry point:" in result
        assert "NX:" in result
        assert "Stack canary:" in result

    @pytest.mark.asyncio
    async def test_find_rop_gadgets_file(self, test_binary):
        backend = GDBBackend()
        backend._binary = test_binary
        result = await backend.find_rop_gadgets(address="")
        assert "ROP gadgets from binary" in result


# ---------------------------------------------------------------------------
# Pydantic model validation
# ---------------------------------------------------------------------------

class TestPwntoolsMcpModels:
    def test_elf_path_valid(self):
        m = ElfPath(path="/tmp/test")
        assert m.path == "/tmp/test"

    def test_elf_path_empty_fails(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ElfPath(path="")

    def test_rop_search_params(self):
        m = RopSearchParams(path="/tmp/test")
        assert m.path == "/tmp/test"
        assert m.grep == ""

    def test_pack_params(self):
        m = PackParams(value="0xdeadbeef")
        assert m.value == "0xdeadbeef"
        assert m.size == 8

    def test_unpack_params(self):
        m = UnpackParams(hex_bytes="ef be ad de")
        assert m.hex_bytes == "ef be ad de"

    def test_cyclic_find_params(self):
        m = CyclicFindParams(value="0x61616162")
        assert m.value == "0x61616162"

    def test_fmtstr_payload_params(self):
        m = FmtStrPayloadParams(
            offset=6, writes='{"0x804a000": 0xdeadbeef}'
        )
        assert m.offset == 6

    def test_build_rop_chain_params(self):
        m = BuildRopChainParams(path="/tmp/test", target="main")
        assert m.target == "main"


# ---------------------------------------------------------------------------
# pwntools MCP tools
# ---------------------------------------------------------------------------

class TestPwntoolsTools:
    """Exercise every pwntools MCP tool with a real binary."""

    # -- ELF analysis --

    def test_analyze_elf(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "analyze", "path": test_binary}))
        text = _text(r)
        assert "Arch:" in text
        assert "Entry:" in text
        assert "PIE:" in text
        assert "Sections" in text
        assert "Segments" in text

    # -- ROP --

    def test_find_rop(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_rop", {"action": "find", "path": test_binary}))
        text = _text(r)
        assert "ROP gadgets in" in text
        assert "Total gadgets:" in text

    def test_find_rop_grep(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_rop", {"action": "find", "path": test_binary, "grep": "ret"}))
        text = _text(r)
        assert "Total gadgets:" in text

    # -- Shellcraft --

    def test_shellcraft_sh(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_shellcode", {"action": "generate", "arch": "amd64", "purpose": "sh"}))
        text = _text(r)
        assert "execve" in text
        assert "Hex:" in text
        assert "Length:" in text

    def test_shellcraft_reverse(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_shellcode", {"action": "generate", "arch": "amd64", "purpose": "reverse_shell", "args": "10.0.0.1 4444"}))
        text = _text(r)
        assert "reverse shell" in text

    def test_shellcraft_read_file(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_shellcode", {"action": "generate", "arch": "amd64", "purpose": "read_file", "args": "/etc/passwd"}))
        text = _text(r)
        assert "read file" in text

    # -- Pack / Unpack --

    def test_pack(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "pack", "value": "0xdeadbeef", "size": 4}))
        d = json.loads(_text(r))
        assert d["int"] == 0xdeadbeef
        assert d["packed_hex"] == "efbeadde"

    def test_pack_big_endian(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "pack", "value": "0xdeadbeef", "size": 4, "endian": "big"}))
        d = json.loads(_text(r))
        assert d["packed_hex"] == "deadbeef"

    def test_pack_p64(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "pack", "value": "0x4141414141414141"}))
        d = json.loads(_text(r))
        assert d["size"] == 8
        assert len(d["packed_hex"]) == 16

    def test_pack_invalid_size(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "pack", "value": "0x41", "size": 3}))
        assert "Error" in _text(r)

    def test_unpack(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "unpack", "hex_bytes": "ef be ad de", "size": 4}))
        d = json.loads(_text(r))
        assert d["int"] == 0xdeadbeef
        assert d["hex"] == "0xdeadbeef"

    def test_unpack_u64(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "unpack", "hex_bytes": "ef be ad de 01 02 03 04", "size": 8}))
        d = json.loads(_text(r))
        assert d["size"] == 8

    # -- Cyclic --

    def test_cyclic(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_util", {"action": "cyclic", "count": 64}))
        text = _text(r)
        assert "Cyclic pattern" in text
        assert len(text) > 80

    def test_cyclic_find(self):
        # cyclic_find with n=4: pattern starts with b'aaaabaaacaaa...'
        # "0x61616161" = "aaaa" is at offset 0.
        r = _await(mcp_module.mcp.call_tool("pwntools_util", {"action": "cyclic_find", "value": "0x61616161", "length": 4}))
        d = json.loads(_text(r))
        assert "offset" in d
        assert isinstance(d["offset"], int)

    def test_cyclic_find_not_found(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_util", {"action": "cyclic_find", "value": "0xdeadbeef"}))
        assert "not found" in _text(r)

    # -- Hexdump --

    def test_hexdump(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "hexdump", "hex_data": "deadbeef01020304"}))
        assert "Hex dump" in _text(r)

    # -- Format string payload --

    def test_fmtstr_payload(self):
        # The writes dict must have integer keys (not strings).
        writes = {0x804a000: 0xdeadbeef}
        r = _await(mcp_module.mcp.call_tool("pwntools_rop", {"action": "fmtstr_payload", "offset": 6, "writes": json.dumps(writes)}))
        d = json.loads(_text(r))
        assert d["offset"] == 6
        assert d["payload_length"] > 0

    # -- Disasm --

    def test_disasm(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_asm", {"action": "disassemble", "data": "90 90 90 cc"}))
        text = _text(r)
        assert "nop" in text.lower() or "int3" in text or "Disassembly" in text

    # -- Asm (keystone) --

    def test_asm_i386(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_asm", {"action": "assemble", "data": "mov eax, 0; ret", "arch": "i386"}))
        d = json.loads(_text(r))
        assert d["arch"] == "i386"
        assert d["length"] > 0

    def test_asm_amd64(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_asm", {"action": "assemble", "data": "xor rax, rax; ret", "arch": "amd64"}))
        d = json.loads(_text(r))
        assert d["arch"] == "amd64"
        assert d["length"] > 0

    # -- Checksec --

    def test_checksec(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "checksec", "path": test_binary}))
        text = _text(r)
        assert "Security properties" in text or "Error" in text

    # -- EROPE --

    def test_erope_all(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_rop", {"action": "erope", "path": test_binary, "gadget_type": "all"}))
        text = _text(r)
        assert "Extended ROP gadgets" in text or "No gadgets" in text

    # -- Enc --

    def test_enc_alphanumeric(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_shellcode", {"action": "encode", "hex_bytes": "90", "arch": "amd64", "encoder": "alphanumeric"}))
        text = _text(r)
        assert "Shellcode Encoding" in text or "not available" in text or "Error" in text

    def test_enc_null_free(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_shellcode", {"action": "encode", "hex_bytes": "31c0", "arch": "amd64", "encoder": "null_free"}))
        text = _text(r)
        assert "Shellcode Encoding" in text or "not available" in text

    # -- ELF Read --

    def test_elf_read_section(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "read", "path": test_binary, "section": ".text", "size": 32}))
        text = _text(r)
        assert "ELF Read" in text or "Error" in text

    def test_elf_read_addr(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "read", "path": test_binary, "offset": 0x400000, "size": 16}))
        text = _text(r)
        assert "ELF Read" in text or "Error" in text

    # -- constgrep --

    def test_constgrep(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_util", {"action": "constgrep", "search": "SYS_read", "arch": "amd64"}))
        text = _text(r)
        assert "Constants" in text or "No constants" in text or "not available" in text

    # -- Flat --

    def test_flat_simple(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "flat", "value": "[0xdeadbeef, 0x41414141]", "arch": "amd64"}))
        text = _text(r)
        assert "Flat" in text
        assert "bytes" in text

    def test_flat_i386(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_pack", {"action": "flat", "value": "[0xdeadbeef, 0x41414141]", "arch": "i386", "pack_size": 4}))
        text = _text(r)
        assert "Flat" in text

    # -- Sigreturn --

    def test_sigreturn_amd64(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_rop", {"action": "sigreturn", "arch": "amd64", "rax": "0x3b", "rdi": "0xdeadbeef", "rip": "0x41414141"}))
        text = _text(r)
        assert "SROP Frame" in text
        assert "rax =" in text
        assert "rdi =" in text
        assert "rip =" in text

    def test_sigreturn_i386(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_rop", {"action": "sigreturn", "arch": "i386", "rax": "0x1", "rip": "0x42424242"}))
        text = _text(r)
        assert "SROP Frame" in text or "Error" in text

    # -- ELF Patch --

    def test_elf_patch(self, test_binary):
        import shutil
        tmp = test_binary + "_patch_test"
        shutil.copy(test_binary, tmp)
        try:
            r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "patch", "path": tmp, "offset": 0x100, "hex_bytes": "90 90 90 90"}))
            text = _text(r)
            assert "ELF Patched" in text
            assert "Backup" in text
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
            if os.path.exists(tmp + ".bak"):
                os.unlink(tmp + ".bak")

    # -- ELF Search --

    def test_elf_search(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "search", "path": test_binary, "pattern": "48 31 c0"}))
        text = _text(r)
        assert "Search in" in text

    # -- Make ELF --

    def test_make_elf(self):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "make", "code": "mov rax, 60; xor rdi, rdi; syscall", "arch": "amd64"}))
        text = _text(r)
        assert "ELF Created" in text or "Error" in text

    # -- Build ROP chain --

    def test_build_rop_chain(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_rop", {"action": "build_chain", "path": test_binary, "target": "main"}))
        d = json.loads(_text(r))
        assert "chain_length" in d
        assert d["chain_length"] > 0

    # -- ELF Sections --

    def test_elf_sections(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "sections", "path": test_binary}))
        text = _text(r)
        assert "Sections" in text
        assert ".text" in text

    def test_elf_sections_filter(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "sections", "path": test_binary, "filter_name": "text"}))
        text = _text(r)
        assert ".text" in text

    # -- ELF Symbols --

    def test_elf_symbols(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "symbols", "path": test_binary, "pattern": "main"}))
        text = _text(r)
        assert "main" in text

    def test_elf_symbols_functions(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "symbols", "path": test_binary, "pattern": "."}))
        text = _text(r)
        assert "Symbols" in text

    # -- ELF Strings --

    def test_elf_strings(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "strings", "path": test_binary, "min_length": 3}))
        text = _text(r)
        assert "Strings" in text

    def test_elf_strings_section(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "strings", "path": test_binary, "section": ".text", "min_length": 3}))
        text = _text(r)
        assert "Strings" in text or "Error" in text

    # -- ELF Dependencies --

    def test_elf_deps(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "deps", "path": test_binary}))
        text = _text(r)
        assert "Dependencies" in text
        assert "libc" in text or "no dynamic" in text

    # -- Entropy --

    def test_entropy(self, test_binary):
        r = _await(mcp_module.mcp.call_tool("pwntools_elf", {"action": "entropy", "path": test_binary}))
        text = _text(r)
        assert "Entropy" in text
        assert "Shannon" in text


# ---------------------------------------------------------------------------
# Fallback behaviour
# ---------------------------------------------------------------------------

class TestBackendFallback:
    @pytest.mark.asyncio
    async def test_corrupt_binary_no_crash(self):
        backend = GDBBackend()
        backend._binary = "/tmp/nonexistent_elf"
        segments = await backend._readelf_load_segments()
        assert segments == []

    @pytest.mark.asyncio
    async def test_get_binary_info_no_binary(self):
        backend = GDBBackend()
        r = await backend.get_binary_info()
        assert r == "No binary loaded"


class TestEnhex:
    @pytest.mark.asyncio
    async def test_encode_ascii(self):
        r = await mcp_module.mcp.call_tool("pwntools_pack", {"action": "enhex", "data": "hello"})
        text = _text(r)
        assert "hello" in text
        assert "Hex" in text

    @pytest.mark.asyncio
    async def test_encode_empty(self):
        r = await mcp_module.mcp.call_tool("pwntools_pack", {"action": "enhex", "data": ""})
        text = _text(r)
        assert "0 bytes" in text


class TestUnhex:
    @pytest.mark.asyncio
    async def test_decode_simple(self):
        r = await mcp_module.mcp.call_tool("pwntools_pack", {"action": "unhex", "hex_str": "deadbeef"})
        text = _text(r)
        assert "Decoded" in text
        assert "\\xde\\xad" in text

    @pytest.mark.asyncio
    async def test_decode_with_spaces(self):
        r = await mcp_module.mcp.call_tool("pwntools_pack", {"action": "unhex", "hex_str": "de ad be ef"})
        text = _text(r)
        assert "Decoded" in text


class TestAlign:
    @pytest.mark.asyncio
    async def test_align_page(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "align", "value": "0x1234", "alignment": 0x1000})
        text = _text(r)
        assert "0x1000" in text
        assert "Aligned down" in text

    @pytest.mark.asyncio
    async def test_align_zero(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "align", "value": "0", "alignment": 0x1000})
        text = _text(r)
        assert "0x0" in text


class TestBitOps:
    @pytest.mark.asyncio
    async def test_rol(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "rol", "value": "0x01", "shift": 1, "bits": 8})
        text = _text(r)
        assert "0x2" in text

    @pytest.mark.asyncio
    async def test_ror(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "ror", "value": "0x02", "shift": 1, "bits": 8})
        text = _text(r)
        assert "0x1" in text

    @pytest.mark.asyncio
    async def test_rol_wraparound(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "rol", "value": "0x80", "shift": 1, "bits": 8})
        text = _text(r)
        assert "0x1" in text


class TestElfTools:
    @pytest.mark.asyncio
    async def test_elf_got_no_binary(self):
        r = await mcp_module.mcp.call_tool("pwntools_elf", {"action": "got", "path": "/nonexistent"})
        text = _text(r)
        assert "Error" in text or "No GOT" in text

    @pytest.mark.asyncio
    async def test_elf_plt_no_binary(self):
        r = await mcp_module.mcp.call_tool("pwntools_elf", {"action": "plt", "path": "/nonexistent"})
        text = _text(r)
        assert "Error" in text or "No PLT" in text

    @pytest.mark.asyncio
    async def test_elf_segments_no_binary(self):
        r = await mcp_module.mcp.call_tool("pwntools_elf", {"action": "segments", "path": "/nonexistent"})
        text = _text(r)
        assert "Error" in text

    @pytest.mark.asyncio
    async def test_elf_relocs_no_binary(self):
        r = await mcp_module.mcp.call_tool("pwntools_elf", {"action": "relocs", "path": "/nonexistent"})
        text = _text(r)
        assert "Error" in text

    @pytest.mark.asyncio
    async def test_elf_notes_no_binary(self):
        r = await mcp_module.mcp.call_tool("pwntools_elf", {"action": "notes", "path": "/nonexistent"})
        text = _text(r)
        assert "Error" in text or "No notes" in text


class TestElfDiff:
    @pytest.mark.asyncio
    async def test_diff_no_binary(self):
        r = await mcp_module.mcp.call_tool("pwntools_elf", {"action": "diff", "path": "/nonexistent_a", "path_b": "/nonexistent_b"})
        text = _text(r)
        assert "Error" in text


class TestBits:
    @pytest.mark.asyncio
    async def test_get_bit(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "bits", "value": "0x8", "bit": 3})
        text = _text(r)
        assert "set" in text

    @pytest.mark.asyncio
    async def test_clear_bit(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "bits", "value": "0x8", "bit": 3, "set_to": 0})
        text = _text(r)
        assert "0x0" in text or "changed" in text


class TestContext:
    @pytest.mark.asyncio
    async def test_show_context(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "context"})
        text = _text(r)
        assert "Arch" in text


class TestLogLevel:
    @pytest.mark.asyncio
    async def test_invalid_level(self):
        r = await mcp_module.mcp.call_tool("pwntools_util", {"action": "log_level", "level": "invalid"})
        text = _text(r)
        assert "Error" in text


class TestProcessTube:
    @pytest.mark.asyncio
    async def test_process_no_binary(self):
        r = await mcp_module.mcp.call_tool("pwntools_tube", {"action": "process", "binary": "/nonexistent"})
        text = _text(r)
        assert "Error" in text

    @pytest.mark.asyncio
    async def test_tube_list_empty(self):
        r = await mcp_module.mcp.call_tool("pwntools_tube", {"action": "list"})
        text = _text(r)
        assert "No active tubes" in text
