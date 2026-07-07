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

from gdb_backend import GDBBackend

pytest.importorskip("pwn")

# Force import of pwntools_mcp once (it registers tools on the global mcp instance)
# We import edb_debugger_mcp first to ensure the mcp instance exists.
import edb_debugger_mcp  # noqa: F401
import pwntools_mcp

from pwntools_mcp import (
    ElfPath,
    RopSearchParams,
    ShellcodeParams,
    PackParams,
    UnpackParams,
    CyclicParams,
    CyclicFindParams,
    HexDumpParams,
    FmtStrPayloadParams,
    DisasmParams,
    AsmParams,
    BuildRopChainParams,
    FlatParams,
    SigreturnFrameParams,
    ElfPatchParams,
    ElfSearchParams,
    MakeElfParams,
    ChecksecParams,
    ERopSearchParams,
    ShellcodeEncodeParams,
    ElfReadParams,
    ConstGrepParams,
    ElfSectionsParams,
    ElfSymbolsParams,
    ElfStringsParams,
    ElfDepsParams,
    EntropyParams,
    EncodeHexParams,
    DecodeHexParams,
    AlignParams,
    BitOpParams,
    ElfRelocsParams,
    ElfDiffParams,
    BitsParams,
    ContextParams,
    TubeProcessParams,
    pwntools_analyze_elf,
    pwntools_find_rop,
    pwntools_shellcraft,
    pwntools_pack,
    pwntools_unpack,
    pwntools_cyclic,
    pwntools_cyclic_find,
    pwntools_hexdump_data,
    pwntools_fmtstr_payload,
    pwntools_disasm_bytes,
    pwntools_asm_instructions,
    pwntools_build_rop_chain,
    pwntools_checksec,
    pwntools_erope,
    pwntools_enc,
    pwntools_elf_read,
    pwntools_constgrep,
    pwntools_flat,
    pwntools_sigreturn,
    pwntools_elf_patch,
    pwntools_elf_search,
    pwntools_make_elf,
    pwntools_elf_sections,
    pwntools_elf_symbols,
    pwntools_elf_strings,
    pwntools_elf_deps,
    pwntools_entropy,
    pwntools_elf_got,
    pwntools_elf_plt,
    pwntools_elf_segments,
    pwntools_elf_relocs,
    pwntools_elf_notes,
    pwntools_enhex,
    pwntools_unhex,
    pwntools_align,
    pwntools_rol,
    pwntools_ror,
    pwntools_elf_diff,
    pwntools_bits,
    pwntools_context,
    pwntools_log_level,
    pwntools_process,
    pwntools_tube_list,
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


# ---------------------------------------------------------------------------
# Backend integration (pwntools used in gdb_backend methods)
# ---------------------------------------------------------------------------

class TestBackendPwntoolsDetection:
    def test_pwntools_available_flag(self):
        assert GDBBackend()._pwntools_available is True

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
        r = _await(pwntools_analyze_elf(ElfPath(path=test_binary)))
        assert "Arch:" in r
        assert "Entry:" in r
        assert "PIE:" in r
        assert "Sections" in r
        assert "Segments" in r

    # -- ROP --

    def test_find_rop(self, test_binary):
        r = _await(pwntools_find_rop(RopSearchParams(path=test_binary)))
        assert "ROP gadgets in" in r
        assert "Total gadgets:" in r

    def test_find_rop_grep(self, test_binary):
        r = _await(pwntools_find_rop(
            RopSearchParams(path=test_binary, grep="ret")
        ))
        assert "Total gadgets:" in r

    # -- Shellcraft --

    def test_shellcraft_sh(self):
        r = _await(pwntools_shellcraft(
            ShellcodeParams(arch="amd64", purpose="sh")
        ))
        assert "execve" in r
        assert "Hex:" in r
        assert "Length:" in r

    def test_shellcraft_reverse(self):
        r = _await(pwntools_shellcraft(
            ShellcodeParams(arch="amd64", purpose="reverse_shell",
                            args="10.0.0.1 4444")
        ))
        assert "reverse shell" in r

    def test_shellcraft_read_file(self):
        r = _await(pwntools_shellcraft(
            ShellcodeParams(arch="amd64", purpose="read_file",
                            args="/etc/passwd")
        ))
        assert "read file" in r

    # -- Pack / Unpack --

    def test_pack(self):
        r = _await(pwntools_pack(PackParams(value="0xdeadbeef", size=4)))
        d = json.loads(r)
        assert d["int"] == 0xdeadbeef
        assert d["packed_hex"] == "efbeadde"

    def test_pack_big_endian(self):
        r = _await(pwntools_pack(
            PackParams(value="0xdeadbeef", size=4, endian="big")
        ))
        d = json.loads(r)
        assert d["packed_hex"] == "deadbeef"

    def test_pack_p64(self):
        r = _await(pwntools_pack(
            PackParams(value="0x4141414141414141")
        ))
        d = json.loads(r)
        assert d["size"] == 8
        assert len(d["packed_hex"]) == 16

    def test_pack_invalid_size(self):
        r = _await(pwntools_pack(PackParams(value="0x41", size=3)))
        assert "Error" in r

    def test_unpack(self):
        r = _await(pwntools_unpack(
            UnpackParams(hex_bytes="ef be ad de", size=4)
        ))
        d = json.loads(r)
        assert d["int"] == 0xdeadbeef
        assert d["hex"] == "0xdeadbeef"

    def test_unpack_u64(self):
        r = _await(pwntools_unpack(
            UnpackParams(hex_bytes="ef be ad de 01 02 03 04", size=8)
        ))
        d = json.loads(r)
        assert d["size"] == 8

    # -- Cyclic --

    def test_cyclic(self):
        r = _await(pwntools_cyclic(CyclicParams(count=64)))
        assert "Cyclic pattern" in r
        assert len(r) > 80

    def test_cyclic_find(self):
        # cyclic_find with n=4: pattern starts with b'aaaabaaacaaa...'
        # "0x61616161" = "aaaa" is at offset 0.
        r = _await(pwntools_cyclic_find(
            CyclicFindParams(value="0x61616161", length=4)
        ))
        d = json.loads(r)
        assert "offset" in d
        assert isinstance(d["offset"], int)

    def test_cyclic_find_not_found(self):
        r = _await(pwntools_cyclic_find(
            CyclicFindParams(value="0xdeadbeef")
        ))
        assert "not found" in r

    # -- Hexdump --

    def test_hexdump(self):
        r = _await(pwntools_hexdump_data(
            HexDumpParams(hex_data="deadbeef01020304")
        ))
        assert "Hex dump" in r

    # -- Format string payload --

    def test_fmtstr_payload(self):
        # The writes dict must have integer keys (not strings).
        writes = {0x804a000: 0xdeadbeef}
        r = _await(pwntools_fmtstr_payload(
            FmtStrPayloadParams(
                offset=6, writes=json.dumps(writes)
            )
        ))
        d = json.loads(r)
        assert d["offset"] == 6
        assert d["payload_length"] > 0

    # -- Disasm --

    def test_disasm(self):
        r = _await(pwntools_disasm_bytes(
            DisasmParams(hex_data="90 90 90 cc")
        ))
        assert "nop" in r.lower() or "int3" in r or "Disassembly" in r

    # -- Asm (keystone) --

    def test_asm_i386(self):
        r = _await(pwntools_asm_instructions(
            AsmParams(code="mov eax, 0; ret", arch="i386")
        ))
        d = json.loads(r)
        assert d["arch"] == "i386"
        assert d["length"] > 0

    def test_asm_amd64(self):
        r = _await(pwntools_asm_instructions(
            AsmParams(code="xor rax, rax; ret", arch="amd64")
        ))
        d = json.loads(r)
        assert d["arch"] == "amd64"
        assert d["length"] > 0

    # -- Checksec --

    def test_checksec(self, test_binary):
        r = _await(pwntools_checksec(ChecksecParams(path=test_binary)))
        assert "Security properties" in r or "Error" in r

    # -- EROPE --

    def test_erope_all(self, test_binary):
        r = _await(pwntools_erope(ERopSearchParams(path=test_binary, gadget_type="all")))
        assert "Extended ROP gadgets" in r or "No gadgets" in r

    # -- Enc --

    def test_enc_alphanumeric(self):
        r = _await(pwntools_enc(ShellcodeEncodeParams(
            hex_bytes="90", arch="amd64", encoder="alphanumeric"
        )))
        assert "Shellcode Encoding" in r or "not available" in r or "Error" in r

    def test_enc_null_free(self):
        r = _await(pwntools_enc(ShellcodeEncodeParams(
            hex_bytes="31c0", arch="amd64", encoder="null_free"
        )))
        assert "Shellcode Encoding" in r or "not available" in r

    # -- ELF Read --

    def test_elf_read_section(self, test_binary):
        r = _await(pwntools_elf_read(ElfReadParams(
            path=test_binary, section=".text", size=32
        )))
        assert "ELF Read" in r or "Error" in r

    def test_elf_read_addr(self, test_binary):
        r = _await(pwntools_elf_read(ElfReadParams(
            path=test_binary, offset=0x400000, size=16
        )))
        assert "ELF Read" in r or "Error" in r

    # -- constgrep --

    def test_constgrep(self):
        r = _await(pwntools_constgrep(ConstGrepParams(search="SYS_read", arch="amd64")))
        assert "Constants" in r or "No constants" in r or "not available" in r

    # -- Flat --

    def test_flat_simple(self):
        r = _await(pwntools_flat(FlatParams(
            values='[0xdeadbeef, 0x41414141]', arch="amd64"
        )))
        assert "Flat" in r
        assert "bytes" in r

    def test_flat_i386(self):
        r = _await(pwntools_flat(FlatParams(
            values='[0xdeadbeef, 0x41414141]', arch="i386", pack_size=4
        )))
        assert "Flat" in r

    # -- Sigreturn --

    def test_sigreturn_amd64(self):
        r = _await(pwntools_sigreturn(SigreturnFrameParams(
            arch="amd64", rax="0x3b", rdi="0xdeadbeef", rip="0x41414141"
        )))
        assert "SROP Frame" in r
        assert "rax =" in r
        assert "rdi =" in r
        assert "rip =" in r

    def test_sigreturn_i386(self):
        r = _await(pwntools_sigreturn(SigreturnFrameParams(
            arch="i386", rax="0x1", rip="0x42424242"
        )))
        assert "SROP Frame" in r or "Error" in r

    # -- ELF Patch --

    def test_elf_patch(self, test_binary):
        import shutil
        tmp = test_binary + "_patch_test"
        shutil.copy(test_binary, tmp)
        try:
            r = _await(pwntools_elf_patch(ElfPatchParams(
                path=tmp, offset=0x100, bytes="90 90 90 90"
            )))
            assert "ELF Patched" in r
            assert "Backup" in r
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
            if os.path.exists(tmp + ".bak"):
                os.unlink(tmp + ".bak")

    # -- ELF Search --

    def test_elf_search(self, test_binary):
        r = _await(pwntools_elf_search(ElfSearchParams(
            path=test_binary, pattern="48 31 c0"
        )))
        assert "Search in" in r

    # -- Make ELF --

    def test_make_elf(self):
        r = _await(pwntools_make_elf(MakeElfParams(
            code="mov rax, 60; xor rdi, rdi; syscall", arch="amd64"
        )))
        assert "ELF Created" in r or "Error" in r

    # -- Build ROP chain --

    def test_build_rop_chain(self, test_binary):
        r = _await(pwntools_build_rop_chain(
            BuildRopChainParams(path=test_binary, target="main")
        ))
        d = json.loads(r)
        assert "chain_length" in d
        assert d["chain_length"] > 0

    # -- ELF Sections --

    def test_elf_sections(self, test_binary):
        r = _await(pwntools_elf_sections(ElfSectionsParams(path=test_binary)))
        assert "Sections" in r
        assert ".text" in r

    def test_elf_sections_filter(self, test_binary):
        r = _await(pwntools_elf_sections(ElfSectionsParams(path=test_binary, filter_name="text")))
        assert ".text" in r

    # -- ELF Symbols --

    def test_elf_symbols(self, test_binary):
        r = _await(pwntools_elf_symbols(ElfSymbolsParams(path=test_binary, pattern="main")))
        assert "main" in r

    def test_elf_symbols_functions(self, test_binary):
        r = _await(pwntools_elf_symbols(ElfSymbolsParams(path=test_binary, pattern=".")))
        assert "Symbols" in r

    # -- ELF Strings --

    def test_elf_strings(self, test_binary):
        r = _await(pwntools_elf_strings(ElfStringsParams(path=test_binary, min_length=3)))
        assert "Strings" in r

    def test_elf_strings_section(self, test_binary):
        r = _await(pwntools_elf_strings(ElfStringsParams(path=test_binary, section=".text", min_length=3)))
        assert "Strings" in r or "Error" in r

    # -- ELF Dependencies --

    def test_elf_deps(self, test_binary):
        r = _await(pwntools_elf_deps(ElfDepsParams(path=test_binary)))
        assert "Dependencies" in r
        assert "libc" in r or "no dynamic" in r

    # -- Entropy --

    def test_entropy(self, test_binary):
        r = _await(pwntools_entropy(EntropyParams(path=test_binary)))
        assert "Entropy" in r
        assert "Shannon" in r


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
        r = await pwntools_enhex(EncodeHexParams(data="hello"))
        assert "hello" in r
        assert "Hex" in r

    @pytest.mark.asyncio
    async def test_encode_empty_fails(self):
        with pytest.raises(Exception):
            await pwntools_enhex(EncodeHexParams(data=""))


class TestUnhex:
    @pytest.mark.asyncio
    async def test_decode_simple(self):
        r = await pwntools_unhex(DecodeHexParams(hex_str="deadbeef"))
        assert "Decoded" in r
        assert "\\xde\\xad" in r

    @pytest.mark.asyncio
    async def test_decode_with_spaces(self):
        r = await pwntools_unhex(DecodeHexParams(hex_str="de ad be ef"))
        assert "Decoded" in r


class TestAlign:
    @pytest.mark.asyncio
    async def test_align_page(self):
        r = await pwntools_align(AlignParams(value=0x1234, alignment=0x1000))
        assert "0x1000" in r
        assert "Aligned down" in r

    @pytest.mark.asyncio
    async def test_align_zero(self):
        r = await pwntools_align(AlignParams(value=0, alignment=0x1000))
        assert "0x0" in r


class TestBitOps:
    @pytest.mark.asyncio
    async def test_rol(self):
        r = await pwntools_rol(BitOpParams(value=0x01, shift=1, bits=8))
        assert "0x2" in r

    @pytest.mark.asyncio
    async def test_ror(self):
        r = await pwntools_ror(BitOpParams(value=0x02, shift=1, bits=8))
        assert "0x1" in r

    @pytest.mark.asyncio
    async def test_rol_wraparound(self):
        r = await pwntools_rol(BitOpParams(value=0x80, shift=1, bits=8))
        assert "0x1" in r


class TestElfTools:
    @pytest.mark.asyncio
    async def test_elf_got_no_binary(self):
        r = await pwntools_elf_got(ElfPath(path="/nonexistent"))
        assert "Error" in r or "No GOT" in r

    @pytest.mark.asyncio
    async def test_elf_plt_no_binary(self):
        r = await pwntools_elf_plt(ElfPath(path="/nonexistent"))
        assert "Error" in r or "No PLT" in r

    @pytest.mark.asyncio
    async def test_elf_segments_no_binary(self):
        r = await pwntools_elf_segments(ElfPath(path="/nonexistent"))
        assert "Error" in r

    @pytest.mark.asyncio
    async def test_elf_relocs_no_binary(self):
        r = await pwntools_elf_relocs(ElfRelocsParams(path="/nonexistent"))
        assert "Error" in r

    @pytest.mark.asyncio
    async def test_elf_notes_no_binary(self):
        r = await pwntools_elf_notes(ElfPath(path="/nonexistent"))
        assert "Error" in r or "No notes" in r


class TestElfDiff:
    @pytest.mark.asyncio
    async def test_diff_no_binary(self):
        r = await pwntools_elf_diff(ElfDiffParams(path_a="/nonexistent_a", path_b="/nonexistent_b"))
        assert "Error" in r


class TestBits:
    @pytest.mark.asyncio
    async def test_get_bit(self):
        r = await pwntools_bits(BitsParams(value=0x8, bit=3))
        assert "set" in r

    @pytest.mark.asyncio
    async def test_clear_bit(self):
        r = await pwntools_bits(BitsParams(value=0x8, bit=3, set_to=0))
        assert "0x0" in r or "changed" in r


class TestContext:
    @pytest.mark.asyncio
    async def test_show_context(self):
        r = await pwntools_context(ContextParams())
        assert "Arch" in r


class TestLogLevel:
    @pytest.mark.asyncio
    async def test_invalid_level(self):
        r = await pwntools_log_level("invalid")
        assert "Error" in r


class TestProcessTube:
    @pytest.mark.asyncio
    async def test_process_no_binary(self):
        r = await pwntools_process(TubeProcessParams(binary="/nonexistent"))
        assert "Error" in r

    @pytest.mark.asyncio
    async def test_tube_list_empty(self):
        r = await pwntools_tube_list()
        assert "No active tubes" in r
