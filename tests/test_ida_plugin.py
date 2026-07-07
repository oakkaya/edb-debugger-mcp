"""
Tests for the IDA Pro MCP plugin (ida_mcp).

Categories:
  1. Module imports — work anywhere without IDA
  2. IDAPython import — requires IDA runtime, skips if unavailable
  3. MCPClient connection logic — mocked, no IDA needed
  4. Headless IDA — manual / separate script only
"""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# ── Path helpers ─────────────────────────────────────────────

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
IDA_ROOT = "/home/kali/ida-pro-9.3"
IDA_PYTHON = os.path.join(IDA_ROOT, "python", "3")

sys.path.insert(0, PROJECT_ROOT)


# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture(scope="session")
def ida_path() -> str:
    return IDA_ROOT


@pytest.fixture
def mcp_client_mod():
    """Import mcp_client via importlib (avoids ida_bridge dependency)."""
    spec = importlib.util.spec_from_file_location(
        "mcp_client",
        os.path.join(PROJECT_ROOT, "ida_mcp", "mcp_client.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def MCPClient(mcp_client_mod):
    return mcp_client_mod.MCPClient


# ── Tests: module imports (no IDA needed) ────────────────────


class TestModuleImports:
    """Verify every module can be imported / inspected without IDA Pro."""

    def test_mcp_client_imports(self, mcp_client_mod):
        assert hasattr(mcp_client_mod, "MCPClient")
        assert hasattr(mcp_client_mod, "MCP_ROOT")
        assert os.path.isdir(mcp_client_mod.MCP_ROOT)

    def test_mcp_client_class(self, MCPClient):
        inst = MCPClient()
        assert hasattr(inst, "start")
        assert hasattr(inst, "stop")
        assert hasattr(inst, "is_running")
        assert hasattr(inst, "call_tool")
        assert hasattr(inst, "list_tools")
        assert inst.is_running is False
        assert inst._process is None

    def test_ida_bridge_constants_load_with_mock(self):
        """ida_bridge can be imported when idaapi is mocked."""
        import sys

        idaapi_mock = MagicMock()
        idaapi_mock.action_handler_t = MagicMock
        idaapi_mock.ast_enable_always = 1
        idaapi_mock.AST_ENABLE_ALWAYS = 1
        idaapi_mock.SETMENU_APP = 1
        idaapi_mock.BADADDR = -1
        idaapi_mock.action_desc_t = MagicMock
        idaapi_mock.register_action = MagicMock()
        idaapi_mock.attach_action_to_menu = MagicMock()
        idaapi_mock.msg = MagicMock()
        idaapi_mock.warning = MagicMock()
        idaapi_mock.info = MagicMock()

        for name in ("idaapi", "idc", "idautils"):
            if name in sys.modules:
                del sys.modules[name]
            sys.modules[name] = idaapi_mock if name == "idaapi" else MagicMock()

        import importlib
        for key in list(sys.modules):
            if "ida_mcp" in key:
                del sys.modules[key]

        import ida_mcp.ida_bridge as ib

        assert ib.IDAPYTHON_AVAILABLE is True
        assert callable(ib.start_bridge)
        assert callable(ib.stop_bridge)
        assert callable(ib.register_actions)
        import ida_mcp
        assert hasattr(ida_mcp, "PLUGIN_ENTRY")
        assert callable(ida_mcp.PLUGIN_ENTRY)

        for mod_name in ("idaapi", "idc", "idautils"):
            if mod_name in sys.modules:
                del sys.modules[mod_name]

    def test_ida_bridge_constants_without_ida(self):
        """ida_bridge cannot be imported when idaapi is absent (class defs need it)."""
        import sys

        for name in ("idaapi", "idc", "idautils"):
            sys.modules.pop(name, None)
        for key in list(sys.modules):
            if "ida_mcp" in key:
                del sys.modules[key]

        with pytest.raises((NameError, ImportError)):
            import ida_mcp.ida_bridge


# ── Tests: IDAPython import (requires IDA) ──────────────────


def _ida_python_available():
    if not os.path.isdir(IDA_PYTHON):
        return False
    try:
        loader = importlib.machinery.ExtensionFileLoader
        return True
    except Exception:
        return False


ida_available = pytest.mark.skipif(
    not _ida_python_available(),
    reason="IDAPython not found — requires IDA Pro runtime",
)


class TestIDAPythonAvailable:
    """These tests only run when IDA Python is importable."""

    @ida_available
    def test_import_idaapi(self):
        spec = importlib.util.spec_from_file_location(
            "idaapi", os.path.join(IDA_PYTHON, "idaapi.py")
        )
        if spec is None:
            pytest.skip("idaapi.py not found")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "get_inf_structure")
        assert hasattr(mod, "msg")

    @ida_available
    def test_import_idc(self):
        spec = importlib.util.spec_from_file_location(
            "idc", os.path.join(IDA_PYTHON, "idc.py")
        )
        if spec is None:
            pytest.skip("idc.py not found")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "get_wide_byte")

    @ida_available
    def test_import_idautils(self):
        spec = importlib.util.spec_from_file_location(
            "idautils", os.path.join(IDA_PYTHON, "idautils.py")
        )
        if spec is None:
            pytest.skip("idautils.py not found")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

    @ida_available
    def test_import_ida_pro(self):
        expected_path = os.path.join(IDA_PYTHON, "ida_pro.py")
        assert os.path.isfile(expected_path), f"ida_pro.py not found at {expected_path}"

    @ida_available
    def test_all_ida_modules_importable(self):
        names = ["idaapi", "idc", "idautils", "ida_pro",
                 "ida_bytes", "ida_dbg", "ida_nalt", "ida_segregs",
                 "ida_funcs", "ida_ua", "ida_xref", "ida_idp",
                 "ida_hexrays", "ida_ida", "ida_auto", "ida_kernwin"]
        for name in names:
            path = os.path.join(IDA_PYTHON, f"{name}.py")
            assert os.path.isfile(path), f"Missing IDA module: {name} at {path}"


# ── Tests: MCPClient connection logic (mocked) ──────────────


class TestMCPClientConnection:
    """Test MCPClient start/stop with mocked subprocess."""

    def test_initial_state(self, MCPClient):
        c = MCPClient()
        assert c.is_running is False
        assert c._process is None
        assert c._request_id == 0
        assert c._capabilities == {}

    def test_is_running_property(self, MCPClient):
        c = MCPClient()
        assert c.is_running is False
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        c._process = mock_proc
        assert c.is_running is True
        mock_proc.poll.return_value = 0
        assert c.is_running is False

    def test_is_running_no_process(self, MCPClient):
        c = MCPClient()
        assert c.is_running is False
        c._process = None
        assert c.is_running is False

    def test_start_already_running(self, MCPClient):
        c = MCPClient()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        c._process = mock_proc
        result = c.start(python="python3")
        assert result == "Already running"

    @patch("subprocess.Popen")
    def test_start_invokes_popen(self, mock_popen, MCPClient):
        c = MCPClient()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()
        mock_proc.stdout.readline.return_value = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "serverInfo": {"name": "edb-test", "version": "1.0"},
                "capabilities": {},
            },
        }).encode()
        mock_popen.return_value = mock_proc

        result = c.start(python="python3")

        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        assert "python3" in args[0]
        assert "edb_debugger_mcp.py" in args[0][1] or args[0][1].endswith("edb_debugger_mcp.py")
        assert kwargs.get("cwd") is not None
        assert "Connected" in result

    @patch("subprocess.Popen")
    def test_start_failure_raises(self, mock_popen, MCPClient):
        c = MCPClient()
        mock_popen.side_effect = FileNotFoundError("No such file or directory: 'nonexistent'")
        with pytest.raises(FileNotFoundError, match="nonexistent"):
            c.start(python="python3")

    def test_stop_no_process(self, MCPClient):
        c = MCPClient()
        c.stop()
        assert c._process is None

    @patch("subprocess.Popen")
    def test_stop_normal(self, mock_popen, MCPClient):
        c = MCPClient()
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.stdin = MagicMock()
        mock_proc.stdout = MagicMock()

        init_resp = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "serverInfo": {"name": "edb-test", "version": "1.0"},
                "capabilities": {},
            },
        }).encode("utf-8")
        mock_proc.stdout.readline.return_value = init_resp
        mock_popen.return_value = mock_proc

        c.start(python="python3")
        assert c.is_running is True
        c.stop()
        assert c._process is None

    def test_call_tool_no_process(self, MCPClient):
        c = MCPClient()
        with pytest.raises(ConnectionError, match="MCP server not running"):
            c.call_tool("edb_pause", {})

    def test_list_tools_no_process(self, MCPClient):
        c = MCPClient()
        with pytest.raises(ConnectionError, match="MCP server not running"):
            c.list_tools()


# ── Tests: ida_bridge lifecycle (mocked IDA) ──────────────


class TestBridgeLifecycle:
    """Test start_bridge / stop_bridge with idaapi and MCPClient mocked."""

    @pytest.fixture(autouse=True)
    def _mock_deps(self):
        idaapi_mock = MagicMock()
        idaapi_mock.action_handler_t = MagicMock
        idaapi_mock.BADADDR = -1
        idaapi_mock.msg = MagicMock()
        idaapi_mock.warning = MagicMock()
        idaapi_mock.info = MagicMock()
        idaapi_mock.ask_str = MagicMock(return_value="")
        idaapi_mock.get_screen_ea = MagicMock(return_value=0x400000)
        idaapi_mock.AST_ENABLE_ALWAYS = 1
        idaapi_mock.SETMENU_APP = 1
        idaapi_mock.action_desc_t = MagicMock()
        idaapi_mock.register_action = MagicMock()
        idaapi_mock.attach_action_to_menu = MagicMock()

        patcher_mods = patch.dict("sys.modules", {
            "idaapi": idaapi_mock,
            "idc": MagicMock(),
            "idautils": MagicMock(),
        })
        patcher_mods.start()

        for key in list(sys.modules):
            if "ida_mcp" in key:
                del sys.modules[key]

        patcher_mcp = patch("ida_mcp.ida_bridge.MCPClient", autospec=True)
        self._mock_mcp_cls = patcher_mcp.start()
        self._mock_instance = self._mock_mcp_cls.return_value
        self._mock_instance.start.return_value = "Connected: mock-server (mock)"
        self._mock_instance.is_running = True
        self._mock_instance.list_tools.return_value = []

        import ida_mcp.ida_bridge as ib
        self._ib = ib

        yield

        patcher_mcp.stop()
        patcher_mods.stop()

    def test_start_bridge_returns_string(self):
        result = self._ib.start_bridge()
        assert isinstance(result, str)
        assert "Connected" in result

    def test_start_bridge_called_mcp_start(self):
        self._ib.start_bridge()
        self._mock_instance.start.assert_called_once()

    def test_stop_bridge_cleans_up(self):
        self._ib.start_bridge()
        assert self._ib._client is self._mock_instance
        self._ib.stop_bridge()
        assert self._ib._client is None

    def test_stop_bridge_before_start(self):
        self._ib.stop_bridge()
        assert self._ib._client is None

    def test_start_bridge_already_running(self):
        self._ib.start_bridge()
        result = self._ib.start_bridge()
        assert "already" in result.lower() or result == "Bridge already running"

    def test_start_bridge_failure_resets_client(self):
        self._mock_instance.start.side_effect = RuntimeError("connection refused")
        result = self._ib.start_bridge()
        assert "Failed" in result
        assert self._ib._client is None

    def test_register_actions_runs(self):
        self._ib.register_actions()
        assert self._ib.IDAPYTHON_AVAILABLE is True

    def test_register_actions_no_ida(self):
        self._ib.IDAPYTHON_AVAILABLE = False
        self._ib.register_actions()

    def test_get_client_raises_if_not_started(self):
        with pytest.raises(RuntimeError, match="not initialized"):
            self._ib._get_client()

    def test_get_client_after_start(self):
        self._ib.start_bridge()
        client = self._ib._get_client()
        assert client is self._mock_instance


class TestMCPClientSubprocess:
    """Integration-style: spawn real subprocess without actual EDB binary."""

    def test_mcp_root_is_correct(self, mcp_client_mod):
        root = mcp_client_mod.MCP_ROOT
        assert os.path.isdir(root)
        server = os.path.join(root, "edb_debugger_mcp.py")
        assert os.path.isfile(server), f"Server script not found: {server}"

    def test_spawn_fails_with_garbage_python(self, MCPClient):
        c = MCPClient()
        with pytest.raises(Exception):
            c.start(python="/nonexistent/python_binary")


# ── Headless IDA execution (separate script, not pytest) ────


@pytest.mark.skip(reason="Run manually: python3 tests/run_headless_ida_test.py")
def test_headless_ida():
    """Run IDA in headless mode to verify the plugin loads without errors.
    Usage:
        xvfb-run -a python3 tests/run_headless_ida_test.py
    """
    pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
