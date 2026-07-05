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

    # -- Build ROP chain --

    def test_build_rop_chain(self, test_binary):
        r = _await(pwntools_build_rop_chain(
            BuildRopChainParams(path=test_binary, target="main")
        ))
        d = json.loads(r)
        assert "chain_length" in d
        assert d["chain_length"] > 0


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
