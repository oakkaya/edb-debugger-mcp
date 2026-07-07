"""Full integration tests with real GDB subprocess."""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gdb_backend import GDBBackend


# Mark all tests in this module as integration
pytestmark = [pytest.mark.integration]


@pytest.fixture(scope="module")
def test_binary():
    """Compile a test C program for debugging."""
    import tempfile
    import subprocess

    code = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int global_var = 42;

void helper_func(int n) {
    int local = n * 2;
    printf("helper: %d\\n", local);
}

int main(int argc, char *argv[]) {
    int x = 10;
    int y = 20;
    int sum = x + y;
    char *msg = "Hello, World!";

    printf("x=%d, y=%d, sum=%d\\n", x, y, sum);

    for (int i = 0; i < 5; i++) {
        helper_func(i);
    }

    global_var = sum;
    return 0;
}
'''

    tmpdir = tempfile.mkdtemp()
    src_path = os.path.join(tmpdir, "test_prog.c")
    bin_path = os.path.join(tmpdir, "test_prog")

    with open(src_path, "w") as f:
        f.write(code)

    result = subprocess.run(
        ["gcc", "-g", "-O0", "-o", bin_path, src_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        pytest.skip(f"Cannot compile test binary: {result.stderr}")

    yield bin_path

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir)


@pytest.fixture
async def gdb():
    """Start GDB backend, yield it, then quit."""
    backend = GDBBackend()
    await backend.start()
    yield backend
    await backend.quit()


class TestGDBBackendIntegration:
    """Integration tests using a real GDB process."""

    @pytest.mark.asyncio
    async def test_start_and_version(self, gdb):
        """GDB starts and responds."""
        output = await gdb._send_command("-gdb-version")
        assert "GNU gdb" in output or "gdb" in output.lower()

    @pytest.mark.asyncio
    async def test_load_program(self, gdb, test_binary):
        """Load a binary for debugging."""
        result = await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_set_breakpoint(self, gdb, test_binary):
        """Set a breakpoint at main."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        result = await gdb._send_command("-break-insert main")
        assert "^done" in result
        assert "bkpt=" in result

    @pytest.mark.asyncio
    async def test_list_breakpoints(self, gdb, test_binary):
        """List breakpoints."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        result = await gdb._send_command("-break-list")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_run_and_break(self, gdb, test_binary):
        """Run program and hit breakpoint."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        result = await gdb._send_exec_command("-exec-run")
        assert "*stopped" in result
        assert "breakpoint-hit" in result

    @pytest.mark.asyncio
    async def test_read_registers(self, gdb, test_binary):
        """Read registers after hitting breakpoint."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_command("info registers rax rbx rcx rdx")
        assert "rax" in result

    @pytest.mark.asyncio
    async def test_evaluate_expression(self, gdb, test_binary):
        """Evaluate C expression."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_command("print argc")
        assert "^done" in result or "argc" in result

    @pytest.mark.asyncio
    async def test_step_instruction(self, gdb, test_binary):
        """Step one instruction."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_exec_command("-exec-step-instruction")
        assert "*stopped" in result

    @pytest.mark.asyncio
    async def test_backtrace(self, gdb, test_binary):
        """Get backtrace."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_command("-stack-info-depth")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_pause_and_continue(self, gdb, test_binary):
        """Pause and continue execution."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_exec_command("-exec-continue")
        assert "*stopped" in result or "^running" in result

    @pytest.mark.asyncio
    async def test_disable_aslr(self, gdb, test_binary):
        """Disable ASLR via GDB."""
        result = await gdb._send_command("set disable-randomization on")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_info_sources(self, gdb, test_binary):
        """List source files."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        result = await gdb._send_command("info sources")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_list_functions(self, gdb, test_binary):
        """List functions in binary."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        result = await gdb._send_command("info functions")
        assert "^done" in result
        assert "main" in result

    @pytest.mark.asyncio
    async def test_disassemble(self, gdb, test_binary):
        """Disassemble a function."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        result = await gdb._send_command("disassemble main")
        assert "^done" in result
        assert "main" in result or "Dump of" in result

    @pytest.mark.asyncio
    async def test_ptype(self, gdb, test_binary):
        """Run ptype command."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_command("ptype argc")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_whatis(self, gdb, test_binary):
        """Run whatis command."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_command("whatis argc")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_set_breakpoint_commands(self, gdb, test_binary):
        """Set breakpoint commands."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        gdb_cmd = "commands 1\nprint argc\ncontinue\nend\n"
        result = await gdb._send_command(gdb_cmd, timeout=5.0)
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_stack_push_pop(self, gdb, test_binary):
        """Test stack push and pop via GDB."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")

        rsp_before = await gdb._send_command("print/x $rsp")

        await gdb._send_command("set $rsp = $rsp - 8")
        await gdb._send_command("set {void*}$rsp = 0xdeadbeef")

        result = await gdb._send_command("print/x *(void**)$rsp")
        assert "0xdeadbeef" in result or "deadbeef" in result

        # pop: read then restore
        await gdb._send_command("set $rsp = $rsp + 8")

    @pytest.mark.asyncio
    async def test_generate_core(self, gdb, test_binary):
        """Generate core dump."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        await gdb._send_command("-break-insert main")
        await gdb._send_exec_command("-exec-run")
        result = await gdb._send_command("gcore /tmp/test_core", timeout=10.0)
        assert "Saved" in result or "^done" in result
        if os.path.exists("/tmp/test_core"):
            os.remove("/tmp/test_core")

    @pytest.mark.asyncio
    async def test_info_inferiors(self, gdb, test_binary):
        """Get inferior info."""
        await gdb._send_command(f"-file-exec-and-symbols {test_binary}")
        result = await gdb._send_command("info inferiors")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_environment_vars(self, gdb):
        """Set and get environment variables."""
        result = await gdb._send_command("set environment TEST_VAR hello")
        assert "^done" in result
        result = await gdb._send_command("show environment TEST_VAR")
        assert "TEST_VAR" in result or "^done" in result
        result = await gdb._send_command("unset environment TEST_VAR")
        assert "^done" in result

    @pytest.mark.asyncio
    async def test_disassembly_flavor(self, gdb):
        """Change disassembly flavor."""
        result = await gdb._send_command("set disassembly-flavor intel")
        assert "^done" in result
        result = await gdb._send_command("set disassembly-flavor att")
        assert "^done" in result


class TestGDBBackendErrorHandling:
    """Test error handling without GDB."""

    @pytest.mark.asyncio
    async def test_send_without_start(self):
        """Sending command without starting GDB raises error."""
        backend = GDBBackend()
        with pytest.raises(Exception):
            await backend._send_command("-gdb-version")

    @pytest.mark.asyncio
    async def test_double_start(self):
        """Starting GDB twice does not crash."""
        backend = GDBBackend()
        await backend.start()
        await backend.start()
        await backend.quit()
