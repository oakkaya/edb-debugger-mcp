"""Unit tests for GDB MI parser."""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from edb_debugger_mcp.gdb_backend import GDBBackend


class TestMIParser:
    """Test the GDB MI output parser."""

    def setup_method(self):
        self.b = GDBBackend()

    def test_parse_done(self):
        result = self.b._parse_mi_result('^done\n(gdb) ')
        assert len(result["records"]) == 1
        assert result["records"][0]["type"] == "done"
        assert result["records"][0]["values"] == {}

    def test_parse_done_with_values(self):
        result = self.b._parse_mi_result('^done,bkpt={number="1",type="breakpoint"}\n(gdb) ')
        assert result["records"][0]["type"] == "done"
        assert 'number="1"' in result["records"][0]["values"]["bkpt"]

    def test_parse_error(self):
        result = self.b._parse_mi_result('^error,msg="No symbol table is loaded"\n(gdb) ')
        assert result["records"][0]["type"] == "error"
        assert result["records"][0]["values"]["msg"] == "No symbol table is loaded"

    def test_parse_running(self):
        result = self.b._parse_mi_result('^running\n*running,thread-id="all"\n(gdb) ')
        assert result["records"][0]["type"] == "running"
        assert result["records"][1]["type"] == "running"
        assert result["records"][1]["values"]["thread-id"] == "all"

    def test_parse_stopped(self):
        output = '*stopped,reason="breakpoint-hit",disp="keep",bkptno="1",frame={addr="0x55555555514e",func="main"}\n(gdb) '
        result = self.b._parse_mi_result(output)
        assert result["records"][0]["type"] == "stopped"
        assert result["records"][0]["values"]["reason"] == "breakpoint-hit"
        assert result["records"][0]["values"]["bkptno"] == "1"

    def test_parse_console_output(self):
        result = self.b._parse_mi_result('~"Hello world\\n"\n^done\n(gdb) ')
        assert len(result["console"]) == 1
        assert "Hello world" in result["console"][0]

    def test_parse_target_output(self):
        result = self.b._parse_mi_result('@"target output\\n"\n^done\n(gdb) ')
        assert len(result["target"]) == 1

    def test_parse_log_output(self):
        result = self.b._parse_mi_result('&"log entry\\n"\n^done\n(gdb) ')
        assert len(result["log"]) == 1

    def test_parse_empty(self):
        result = self.b._parse_mi_result("")
        assert result == {"records": [], "console": [], "log": [], "target": []}

    def test_parse_only_prompt(self):
        result = self.b._parse_mi_result("(gdb) ")
        assert result == {"records": [], "console": [], "log": [], "target": []}

    def test_parse_breakpoint_info(self):
        output = '^done,bkpt={number="1",type="breakpoint",disp="keep",enabled="y",addr="0x555555555149",func="main",file="test.c",fullname="/tmp/test.c",line="3",thread-groups=["i1"],times="0"}\n(gdb) '
        result = self.b._parse_mi_result(output)
        bkpt = result["records"][0]["values"]["bkpt"]
        assert 'number="1"' in bkpt
        assert 'addr="0x555555555149"' in bkpt
        assert 'enabled="y"' in bkpt

    def test_parse_stack(self):
        output = '^done,stack=[frame={level="0",addr="0x55555555514e",func="main",file="test.c"},frame={level="1",addr="0x7ffff7dbc29a",func="__libc_start_call_main"}]\n(gdb) '
        result = self.b._parse_mi_result(output)
        stack_val = result["records"][0]["values"].get("stack", "")
        assert 'level="0"' in stack_val
        assert 'func="main"' in stack_val

    def test_parse_memory(self):
        output = '^done,memory=[{begin="0x7fffffffdc00",offset="0x0",end="0x7fffffffde00",contents="000000000000000000000000000000000000"}]\n(gdb) '
        result = self.b._parse_mi_result(output)
        mem_val = result["records"][0]["values"].get("memory", "")
        assert 'begin="0x7fffffffdc00"' in mem_val

    def test_parse_multi_record(self):
        output = '^done,bkpt={number="1"}\n=breakpoint-modified,bkpt={number="1"}\n(gdb) '
        result = self.b._parse_mi_result(output)
        assert len(result["records"]) == 2

    def test_parse_exit(self):
        result = self.b._parse_mi_result('^exit\n(gdb) ')
        assert result["records"][0]["type"] == "exit"

    def test_parse_mi_comma_list_simple(self):
        result = self.b._parse_mi_comma_list('number="1",type="breakpoint"')
        assert result["number"] == "1"
        assert result["type"] == "breakpoint"

    def test_parse_mi_comma_list_braces(self):
        result = self.b._parse_mi_comma_list('addr="0x5555",func="main"')
        assert result["addr"] == "0x5555"
        assert result["func"] == "main"

    def test_parse_mi_comma_list_empty(self):
        result = self.b._parse_mi_comma_list("")
        assert result == {}

    def test_parse_mi_values_braces(self):
        result = self.b._parse_mi_values('{number="1",type="breakpoint"}')
        assert result["number"] == "1"

    def test_parse_mi_values_no_braces(self):
        result = self.b._parse_mi_values('number="1"')
        assert result["number"] == "1"

    def test_parse_mi_values_empty(self):
        assert self.b._parse_mi_values("") == {}

    def test_check_error_raises(self):
        parsed = {"records": [{"type": "error", "values": {"msg": "No symbol table"}}]}
        with pytest.raises(Exception, match="No symbol table"):
            self.b._check_error(parsed)

    def test_check_error_ok(self):
        parsed = {"records": [{"type": "done", "values": {}}]}
        self.b._check_error(parsed)

    def test_extract_value_found(self):
        parsed = {"records": [{"type": "done", "values": {"number": "1"}}]}
        assert self.b._extract_value(parsed, "number") == "1"

    def test_extract_value_not_found(self):
        parsed = {"records": [{"type": "done", "values": {}}]}
        assert self.b._extract_value(parsed, "number") is None


class TestBackendMethods:
    """Unit tests for backend helper methods."""

    def test_parse_mi_result_complex(self):
        b = GDBBackend()
        output = '''~"rax            0x7f                127\\n"
~"rbx            0x0                 0\\n"
^done
(gdb) '''
        result = b._parse_mi_result(output)
        assert len(result["console"]) == 2
        assert "rax" in result["console"][0]
        assert "rbx" in result["console"][1]
        assert result["records"][0]["type"] == "done"

    def test_parse_mi_thread_info(self):
        b = GDBBackend()
        output = '''^done,threads=[{id="1",target-id="Thread 0x7ffff7fbc740 (LWP 1234)",frame={level="0",addr="0x7ffff7dbc29a",func="__libc_start_call_main",args=[]},state="stopped"}],current-thread-id="1"
(gdb) '''
        result = b._parse_mi_result(output)
        threads_val = result["records"][0]["values"].get("threads", "")
        assert 'id="1"' in threads_val
        assert 'state="stopped"' in threads_val

    def test_parse_mi_var_list(self):
        b = GDBBackend()
        output = '^done,variables=[{name="argc",value="1"},{name="argv",value="0x7fffffffdea0"}]\n(gdb) '
        result = b._parse_mi_result(output)
        vars_val = result["records"][0]["values"].get("variables", "")
        assert 'name="argc"' in vars_val
        assert 'value="1"' in vars_val

    def test_parse_mi_nested_dict(self):
        """Test parsing of deeply nested MI structures."""
        b = GDBBackend()
        output = '^done,frame={level="0",addr="0x5555",func="main",args=[{name="argc",value="1"},{name="argv",value="0x7fff"}],arch="i386:x86-64"}\n(gdb) '
        result = b._parse_mi_result(output)
        frame_val = result["records"][0]["values"].get("frame", "")
        assert 'level="0"' in frame_val
        assert 'args=[' in frame_val


class TestAsyncEvents:
    """Test the new async event handling infrastructure."""

    def setup_method(self):
        self.b = GDBBackend()

    def test_extract_async_events_empty(self):
        self.b._extract_async_events("^done\n(gdb) ")
        assert self.b._async_events == []

    def test_extract_async_events_stopped(self):
        self.b._extract_async_events('*stopped,reason="breakpoint-hit"\n(gdb) ')
        assert len(self.b._async_events) == 1
        assert self.b._async_events[0]["parsed"]["type"] == "stopped"

    def test_extract_async_events_running(self):
        self.b._extract_async_events('*running,thread-id="all"\n(gdb) ')
        assert len(self.b._async_events) == 1
        assert self.b._async_events[0]["parsed"]["type"] == "running"

    def test_extract_async_events_notify(self):
        self.b._extract_async_events('=library-loaded,id="libc.so.6"\n(gdb) ')
        assert len(self.b._async_events) == 1
        assert self.b._async_events[0]["parsed"]["type"] == "library-loaded"

    def test_extract_async_events_status(self):
        self.b._extract_async_events('+download,"Section .text"\n(gdb) ')
        assert len(self.b._async_events) == 1

    def test_extract_async_events_multiple(self):
        self.b._extract_async_events(
            '=thread-created,id="1"\n*running,thread-id="all"\n*stopped,reason="breakpoint-hit"\n(gdb) '
        )
        assert len(self.b._async_events) == 3
        assert self.b._async_events[0]["parsed"]["type"] == "thread-created"
        assert self.b._async_events[1]["parsed"]["type"] == "running"
        assert self.b._async_events[2]["parsed"]["type"] == "stopped"

    def test_get_async_events_clears(self):
        self.b._async_events.append({"raw": "*stopped", "parsed": {"type": "stopped"}})
        events = self.b.get_async_events()
        assert len(events) == 1
        assert self.b._async_events == []

    def test_get_async_events_empty(self):
        assert self.b.get_async_events() == []


class TestMIParserEdgeCases:
    """Test edge cases in the MI parser."""

    def setup_method(self):
        self.b = GDBBackend()

    def test_escaped_quotes_in_string(self):
        output = '^done,msg="hello \\"world\\""\n(gdb) '
        result = self.b._parse_mi_result(output)
        # The backslash-escaped quote inside an MI string is tricky.
        # MI2 uses C-style escaping in string values.
        msg = result["records"][0]["values"].get("msg", "")
        assert "hello" in msg

    def test_mi_value_with_spaces(self):
        result = self.b._parse_mi_result('^done,arch="i386:x86-64"\n(gdb) ')
        assert result["records"][0]["values"]["arch"] == "i386:x86-64"

    def test_empty_brace_list(self):
        result = self.b._parse_mi_result('^done,args=[]\n(gdb) ')
        assert result["records"][0]["type"] == "done"

    def test_multi_line_console(self):
        output = '~"line1\\n"\n~"line2\\n"\n^done\n(gdb) '
        result = self.b._parse_mi_result(output)
        assert len(result["console"]) == 2

    def test_mi_list_in_value(self):
        output = '^done,thread-groups=["i1","i2"]\n(gdb) '
        result = self.b._parse_mi_result(output)
        groups = result["records"][0]["values"].get("thread-groups", "")
        assert "i1" in groups

    def test_notify_record_with_equals(self):
        output = '=breakpoint-modified,bkpt={number="1",enabled="y"}\n(gdb) '
        result = self.b._parse_mi_result(output)
        assert len(result["records"]) == 1
        assert result["records"][0]["type"] == "breakpoint-modified"

    def test_target_output_with_prompt_text(self):
        output = '@"(gdb) is not a prompt here\\n"\n^done\n(gdb) '
        result = self.b._parse_mi_result(output)
        assert len(result["target"]) == 1
        assert "(gdb)" in result["target"][0]
        assert result["records"][0]["type"] == "done"

    def test_parse_mi_tuple_nested(self):
        self.b._parse_mi_tuple('{level="0",func="main",args=[{name="x"}]}')
        # Should not raise an exception
        assert True

    def test_parse_mi_list_complex(self):
        result = self.b._parse_mi_list('[{begin="0x0",contents="00"},{begin="0x10",contents="ff"}]')
        assert len(result) == 2
        assert isinstance(result[0], dict)
        assert result[0].get("begin", "") == "0x0"

    def test_extract_location_full(self):
        parsed = {
            "records": [{
                "type": "stopped",
                "values": {
                    "reason": "breakpoint-hit",
                    "frame": '{addr="0x5555",func="main",file="test.c"}',
                    "bkptno": "1",
                }
            }]
        }
        loc = self.b._extract_location(parsed)
        assert loc.get("reason") == "breakpoint-hit"
        assert loc.get("breakpoint") == "1"

    def test_parse_mi_result_status_records(self):
        output = '+download="Section .text"\n^done\n(gdb) '
        result = self.b._parse_mi_result(output)
        assert len(result["records"]) == 2
        assert result["records"][0]["type"] == "download"
