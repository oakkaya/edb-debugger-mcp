"""Unit tests for MCP Pydantic model validation."""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pydantic import ValidationError
import edb_debugger_mcp as mcp_module


class TestModelDiscovery:
    """Dynamically test all models in the MCP module."""

    @classmethod
    def setup_class(cls):
        cls.models = {}
        for name in dir(mcp_module):
            obj = getattr(mcp_module, name)
            if isinstance(obj, type) and hasattr(obj, 'model_config'):
                cls.models[name] = obj

    def test_all_models_have_config(self):
        """All models should have ConfigDict with extra='forbid'."""
        for name, model_cls in self.models.items():
            if name == 'BaseModel':
                continue
            config = getattr(model_cls, 'model_config', {})
            assert config.get('extra') == 'forbid', f"{name} missing extra='forbid'"

    def test_at_least_80_models(self):
        """There should be at least 80 models defined."""
        assert len(self.models) >= 80, f"Expected >=80 models, got {len(self.models)}"


class TestBinaryPath:
    def test_valid(self):
        m = mcp_module.BinaryPath(path="/tmp/test_bin")
        assert m.path == "/tmp/test_bin"
        assert m.args == ""

    def test_with_args(self):
        m = mcp_module.BinaryPath(path="/tmp/test_bin", args="--verbose")
        assert m.args == "--verbose"

    def test_empty_path_fails(self):
        with pytest.raises(ValidationError):
            mcp_module.BinaryPath(path="")


class TestAttachPid:
    def test_valid(self):
        m = mcp_module.AttachPid(pid=1234)
        assert m.pid == 1234

    def test_zero_fails(self):
        with pytest.raises(ValidationError):
            mcp_module.AttachPid(pid=0)


class TestAddressInput:
    def test_valid(self):
        m = mcp_module.AddressInput(address="0x7fff0000")
        assert m.address == "0x7fff0000"
        assert m.count == 128

    def test_custom_count(self):
        m = mcp_module.AddressInput(address="0x7fff0000", count=64)
        assert m.count == 64

    def test_negative_count_fails(self):
        with pytest.raises(ValidationError):
            mcp_module.AddressInput(address="0x7fff0000", count=-1)

    def test_excessive_count_fails(self):
        with pytest.raises(ValidationError):
            mcp_module.AddressInput(address="0x7fff0000", count=9999)


class TestMemoryWriteInput:
    def test_valid(self):
        m = mcp_module.MemoryWriteInput(address="0x7fff0000", data="0x90")
        assert m.address == "0x7fff0000"


class TestMemoryWriteBytesInput:
    def test_valid(self):
        m = mcp_module.MemoryWriteBytesInput(address="0x7fff0000", hex_bytes="90 90 90")
        assert m.hex_bytes == "90 90 90"


class TestBreakpointInput:
    def test_function(self):
        m = mcp_module.BreakpointInput(location="main")
        assert m.location == "main"
        assert m.condition == ""

    def test_with_condition(self):
        m = mcp_module.BreakpointInput(location="main", condition="x == 5")
        assert m.condition == "x == 5"

    def test_empty_location_allowed(self):
        m = mcp_module.BreakpointInput(location="test.c:42")
        assert m.location == "test.c:42"

    def test_extra_field_rejected(self):
        with pytest.raises(ValidationError):
            mcp_module.BreakpointInput(location="main", invalid="x")


class TestBreakpointNumber:
    def test_valid(self):
        m = mcp_module.BreakpointNumber(number=1)
        assert m.number == 1

    def test_zero_fails(self):
        with pytest.raises(ValidationError):
            mcp_module.BreakpointNumber(number=0)


class TestWatchpointInput:
    def test_write(self):
        m = mcp_module.WatchpointInput(expression="x")
        assert m.watch_type == "write"

    def test_read(self):
        m = mcp_module.WatchpointInput(expression="*0x7fff0000", watch_type="read")
        assert m.watch_type == "read"

    def test_access(self):
        m = mcp_module.WatchpointInput(expression="x", watch_type="access")
        assert m.watch_type == "access"

    def test_invalid_type(self):
        with pytest.raises(ValidationError):
            mcp_module.WatchpointInput(expression="x", watch_type="invalid")


class TestRegisterName:
    def test_valid(self):
        m = mcp_module.RegisterName(name="rax")
        assert m.name == "rax"


class TestRegisterSetInput:
    def test_valid(self):
        m = mcp_module.RegisterSetInput(name="rax", value="0x1234")
        assert m.name == "rax"
        assert m.value == "0x1234"


class TestSearchMemoryInput:
    def test_valid(self):
        m = mcp_module.SearchMemoryInput(pattern="41414141")
        assert m.pattern == "41414141"

    def test_with_address(self):
        m = mcp_module.SearchMemoryInput(pattern="9090", address="0x7fff0000")
        assert m.address == "0x7fff0000"


class TestSearchInstructionsInput:
    def test_valid(self):
        m = mcp_module.SearchInstructionsInput(pattern="0x90 0x90")
        assert m.pattern == "0x90 0x90"


class TestDisassembleInput:
    def test_function(self):
        m = mcp_module.DisassembleInput(location="main")
        assert m.location == "main"
        assert m.count == 10


class TestContinueToAddress:
    def test_valid(self):
        m = mcp_module.ContinueToAddress(address="0x401000")
        assert m.address == "0x401000"


class TestSymbolLookup:
    def test_valid(self):
        m = mcp_module.SymbolLookup(name="main")
        assert m.name == "main"


class TestEvaluateExpr:
    def test_valid(self):
        m = mcp_module.EvaluateExpr(expression="argc + 1")
        assert m.expression == "argc + 1"


class TestFillMemoryInput:
    def test_valid(self):
        m = mcp_module.FillMemoryInput(address="0x7fff0000", byte_value="0x90", count=1024)
        assert m.count == 1024
        assert m.byte_value == "0x90"


class TestStackPushInput:
    def test_valid(self):
        m = mcp_module.StackPushInput(value="0xdeadbeef")
        assert m.value == "0xdeadbeef"


class TestLabelAddressInput:
    def test_valid(self):
        m = mcp_module.LabelAddressInput(address="0x401000", label="my_func")
        assert m.address == "0x401000"
        assert m.label == "my_func"


class TestDisableASLRInput:
    def test_valid(self):
        m = mcp_module.DisableASLRInput(disable=True)
        assert m.disable is True


class TestBinaryStringConvertInput:
    def test_hex(self):
        m = mcp_module.BinaryStringConvertInput(hex_str="48656c6c6f")
        assert m.hex_str == "48656c6c6f"

    def test_ascii(self):
        m = mcp_module.BinaryStringConvertInput(ascii_str="Hello")
        assert m.ascii_str == "Hello"

    def test_all_none_allowed(self):
        m = mcp_module.BinaryStringConvertInput()
        assert m.hex_str is None


class TestCatchpointInput:
    def test_signal(self):
        m = mcp_module.CatchpointInput(event="signal")
        assert m.event == "signal"

    def test_syscall(self):
        m = mcp_module.CatchpointInput(event="syscall")
        assert m.event == "syscall"

    def test_any_event_allowed(self):
        m = mcp_module.CatchpointInput(event="invalid")
        assert m.event == "invalid"


class TestSignalHandlingInput:
    def test_valid(self):
        m = mcp_module.SignalHandlingInput(signal="SIGSEGV")
        assert m.signal == "SIGSEGV"
        assert m.action == ""

    def test_with_action(self):
        m = mcp_module.SignalHandlingInput(signal="SIGSEGV", action="pass")
        assert m.action == "pass"


class TestRemoteConnectInput:
    def test_valid(self):
        m = mcp_module.RemoteConnectInput(host="localhost", port=1234)
        assert m.host == "localhost"
        assert m.port == 1234


class TestViewAddressInput:
    def test_valid(self):
        m = mcp_module.ViewAddressInput(address="0x401000")
        assert m.address == "0x401000"


class TestSessionFileInput:
    def test_valid(self):
        m = mcp_module.SessionFileInput(file_path="/tmp/session.json")
        assert m.file_path == "/tmp/session.json"


class TestWorkingDirectoryInput:
    def test_valid(self):
        m = mcp_module.WorkingDirectoryInput(directory="/tmp")
        assert m.directory == "/tmp"


class TestMemoryPermissionsInput:
    def test_valid(self):
        m = mcp_module.MemoryPermissionsInput(address="0x7fff0000", permissions="rwx")
        assert m.permissions == "rwx"

    def test_read_only(self):
        m = mcp_module.MemoryPermissionsInput(address="0x7fff0000", permissions="r--")
        assert m.permissions == "r--"


class TestScopeGuard:
    """Ensure extra fields are rejected across all models."""

    @pytest.mark.parametrize("model_cls,valid_kwargs", [
        (mcp_module.BinaryPath, {"path": "/tmp/x"}),
        (mcp_module.AttachPid, {"pid": 42}),
        (mcp_module.AddressInput, {"address": "0x0"}),
        (mcp_module.MemoryWriteInput, {"address": "0x0", "data": "0x90"}),
        (mcp_module.MemoryWriteBytesInput, {"address": "0x0", "hex_bytes": "90"}),
        (mcp_module.BreakpointInput, {"location": "main"}),
        (mcp_module.BreakpointNumber, {"number": 1}),
        (mcp_module.WatchpointInput, {"expression": "x"}),
        (mcp_module.RegisterName, {"name": "rax"}),
        (mcp_module.RegisterSetInput, {"name": "rax", "value": "0x0"}),
        (mcp_module.EvaluateExpr, {"expression": "1+1"}),
        (mcp_module.DisassembleInput, {"location": "main"}),
        (mcp_module.ContinueToAddress, {"address": "0x0"}),
        (mcp_module.SymbolLookup, {"name": "main"}),
        (mcp_module.SearchMemoryInput, {"pattern": "90"}),
        (mcp_module.FillMemoryInput, {"address": "0x0", "value": "0x90", "length": 16}),
        (mcp_module.StackPushInput, {"value": "0x0"}),
        (mcp_module.LabelAddressInput, {"address": "0x0", "label": "x"}),
        (mcp_module.DisableASLRInput, {"disable": True}),
        (mcp_module.CatchpointInput, {"event": "signal"}),
        (mcp_module.SignalHandlingInput, {"signal": "SIGINT"}),
        (mcp_module.RemoteConnectInput, {"host": "localhost", "port": 1234}),
        (mcp_module.ViewAddressInput, {"address": "0x0", "view": "cpu"}),
        (mcp_module.SessionFileInput, {"file_path": "/tmp/x.json"}),
        (mcp_module.WorkingDirectoryInput, {"directory": "/tmp"}),
        (mcp_module.MemoryPermissionsInput, {"address": "0x0", "permissions": "rwx"}),
        (mcp_module.TTYInput, {"tty_path": "/dev/pts/0"}),

    ])
    def test_extra_fields_rejected(self, model_cls, valid_kwargs):
        with pytest.raises(ValidationError):
            model_cls(**valid_kwargs, extra_field="should_reject")
