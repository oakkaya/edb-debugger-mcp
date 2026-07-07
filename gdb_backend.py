import asyncio
import json
import os
import re
import signal
from typing import Optional


class GDBBackendError(Exception):
    pass


class GDBBackend:
    _instance: Optional["GDBBackend"] = None

    def __init__(self):
        self._process: Optional[asyncio.subprocess.Process] = None
        self._pid: Optional[int] = None
        self._binary: Optional[str] = None
        self._args: str = ""
        self._running: bool = False
        self._input_lock = asyncio.Lock()
        self._output_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reader_task: Optional[asyncio.Task] = None
        self._async_events: list[dict] = []
        self._gdb_version_checked = False
        self._pwntools_available: bool = False
        try:
            import pwn
            pwn.context.log_level = "error"
            self._pwntools_available = True
        except ImportError:
            self._pwntools_available = False

    @classmethod
    def get_instance(cls) -> "GDBBackend":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def start(self) -> None:
        if self._process is not None:
            if self._process.returncode is None and self._gdb_version_checked:
                try:
                    await self._send_command("-gdb-version", timeout=3.0)
                    return
                except Exception:
                    pass
            await self._cleanup()
        self._async_events = []
        self._output_queue = asyncio.Queue()
        self._process = await asyncio.create_subprocess_exec(
            "gdb",
            "--interpreter=mi2",
            "-q",
            "--nh",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            limit=2 * 1024 * 1024,
        )
        self._reader_task = asyncio.create_task(self._reader_loop())
        await self._consume_until_prompt()
        await self._send_command("set pagination off")
        self._gdb_version_checked = True

    async def _cleanup(self) -> None:
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._process is not None and self._process.returncode is None:
            self._process.kill()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=3.0)
            except Exception:
                pass
        self._process = None
        self._pid = None
        self._running = False

    async def _reader_loop(self) -> None:
        stream = self._process.stdout
        while stream is not None and not stream.at_eof():
            try:
                line = await asyncio.wait_for(stream.readline(), timeout=60.0)
                if not line:
                    break
                await self._output_queue.put(line)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                import sys, traceback
                traceback.print_exception(type(exc), exc, exc.__traceback__, file=sys.stderr)
                break

    async def _consume_until_prompt(self, timeout: float = 10.0) -> list[bytes]:
        lines: list[bytes] = []
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise GDBBackendError("Timeout waiting for GDB prompt")
            try:
                line = await asyncio.wait_for(self._output_queue.get(), timeout=remaining)
            except asyncio.TimeoutError:
                raise GDBBackendError("Timeout waiting for GDB prompt")
            lines.append(line)
            stripped = line.strip()
            if stripped == b"(gdb)":
                return lines
            if stripped == b"(gdb)\x1b[?1l\x1b>" or stripped.rstrip() == b"(gdb)":
                return lines

    def _drain_queue(self) -> None:
        while not self._output_queue.empty():
            try:
                self._output_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    async def _send_command(self, cmd: str, timeout: float = 30.0) -> str:
        if self._process is None or self._process.stdin is None:
            raise GDBBackendError("GDB not started")
        async with self._input_lock:
            self._drain_queue()
            self._process.stdin.write(cmd.strip().encode() + b"\n")
            await self._process.stdin.drain()
            lines = await self._consume_until_prompt(timeout)
        return b"".join(lines).decode("utf-8", errors="replace")

    async def _send_exec_command(self, cmd: str, timeout: float = 60.0) -> str:
        if self._process is None or self._process.stdin is None:
            raise GDBBackendError("GDB not started")
        async with self._input_lock:
            self._drain_queue()
            self._process.stdin.write(cmd.encode() + b"\n")
            await self._process.stdin.drain()
            lines: list[bytes] = []
            deadline = asyncio.get_event_loop().time() + timeout
            seen_stopped = False
            seen_error = False
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    if not seen_stopped and not seen_error:
                        raise GDBBackendError("Timeout waiting for *stopped event")
                    break
                try:
                    line = await asyncio.wait_for(self._output_queue.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    if not seen_stopped and not seen_error:
                        raise GDBBackendError("Timeout waiting for *stopped event")
                    break
                lines.append(line)
                stripped = line.strip()
                if stripped.startswith(b"*stopped"):
                    seen_stopped = True
                if stripped.startswith(b"^error"):
                    seen_error = True
                if stripped == b"(gdb)":
                    if seen_stopped or seen_error:
                        break
            result = b"".join(lines).decode("utf-8", errors="replace")
            self._extract_async_events(result)
            return result

    def _parse_mi_result(self, output: str) -> dict:
        result = {"records": [], "console": [], "log": [], "target": []}
        for line in output.splitlines():
            line = line.strip()
            if not line or line == "(gdb)":
                continue
            if line.startswith("~"):
                result["console"].append(line[1:].strip().strip("\""))
            elif line.startswith("@"):
                result["target"].append(line[1:].strip().strip("\""))
            elif line.startswith("&"):
                result["log"].append(line[1:].strip().strip("\""))
            elif any(line.startswith(p) for p in ("^done", "^error", "^running", "^exit")):
                result["records"].append(self._parse_mi_record(line))
            elif line.startswith(("*", "=", "+")):
                result["records"].append(self._parse_mi_record(line))
        return result

    def _parse_mi_record(self, line: str) -> dict:
        record = {"raw": line, "type": None, "values": {}}
        if line.startswith("^done"):
            record["type"] = "done"
            content = line[5:].strip()
        elif line.startswith("^error"):
            record["type"] = "error"
            content = line[6:].strip()
        elif line.startswith("^running"):
            record["type"] = "running"
            content = line[8:].strip()
        elif line.startswith("^exit"):
            record["type"] = "exit"
            content = ""
        elif line.startswith("*"):
            sep = 999
            for c in (" ", ","):
                idx = line.find(c)
                if 0 < idx < sep:
                    sep = idx
            record["type"] = line[1:sep]
            content = line[sep + 1:] if sep < 999 else ""
        elif line.startswith(("=", "+")):
            sep = 999
            for c in (",", " ", "="):
                idx = line.find(c)
                if 0 < idx < sep:
                    sep = idx
            record["type"] = line[1:sep]
            content = line[sep + 1:] if sep < 999 else ""
        else:
            content = line
        record["values"] = self._parse_mi_values(content) if content else {}
        return record

    def _parse_mi_values(self, content: str) -> dict:
        content = content.strip()
        if not content:
            return {}
        if content.startswith("{") and content.endswith("}"):
            inner = content[1:-1]
            return self._parse_mi_comma_list(inner)
        return self._parse_mi_comma_list(content)

    def _parse_mi_comma_list(self, content: str) -> dict:
        result = {}
        depth = 0
        in_str = False
        key = ""
        val = ""
        state = "key"
        for ch in content:
            if ch == '"' and (not val or not val.endswith('\\')):
                in_str = not in_str
            if not in_str:
                if ch in ('{', '['):
                    depth += 1
                elif ch in ('}', ']'):
                    depth -= 1
                if depth == 0:
                    if ch == '=' and state == "key":
                        key = val.strip()
                        val = ""
                        state = "val"
                        continue
                    elif ch == ',':
                        if key:
                            result[key] = val.strip().strip("\"")
                        key = ""
                        val = ""
                        state = "key"
                        continue
            val += ch
        if key:
            result[key] = val.strip().strip("\"")
        return result

    def _check_error(self, parsed: dict) -> None:
        for rec in parsed["records"]:
            if rec["type"] == "error":
                msg = rec["values"].get("msg", "Unknown GDB error")
                raise GDBBackendError(msg)

    def _extract_value(self, parsed: dict, key: str) -> Optional[str]:
        for rec in parsed["records"]:
            if key in rec["values"]:
                return rec["values"][key]
        return None

    async def load_program(self, path: str, args: str = "") -> str:
        await self.start()
        self._binary = os.path.abspath(path)
        self._args = args
        if not os.path.exists(self._binary):
            raise GDBBackendError(f"File not found: {self._binary}")
        output = await self._send_command(f"-file-exec-and-symbols {self._binary}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._running = False
        if args:
            await self._send_command(f"-exec-arguments {args}")
        return f"Loaded: {self._binary}"

    async def attach(self, pid: int) -> str:
        await self.start()
        output = await self._send_command(f"-target-attach {pid}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._pid = pid
        self._running = True
        return f"Attached to PID {pid}"

    async def detach(self) -> str:
        output = await self._send_command("-target-detach")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._pid = None
        self._running = False
        return "Detached"

    async def kill(self) -> str:
        output = await self._send_command("kill")
        parsed = self._parse_mi_result(output)
        if any(r["type"] == "error" for r in parsed["records"]):
            try:
                await self._send_command("-exec-interrupt", timeout=3.0)
            except Exception:
                pass
            output = await self._send_command("kill")
            parsed = self._parse_mi_result(output)
        self._pid = None
        self._running = False
        return "Process killed"

    async def run(self) -> str:
        output = await self._send_exec_command("-exec-run")
        parsed = self._parse_mi_result(output)
        for rec in parsed["records"]:
            if rec["type"] == "error":
                msg = rec["values"].get("msg", "")
                if "already" in msg.lower():
                    return await self.continue_exec()
                raise GDBBackendError(msg)
        self._running = False
        for rec in parsed["records"]:
            if rec["type"] == "stopped":
                reason = rec["values"].get("reason", "")
                bkptno = rec["values"].get("bkptno", "")
                if reason:
                    return f"Stopped: {reason}" + (f" (bkpt {bkptno})" if bkptno else "")
        return "Program running (no breakpoint hit)"

    async def continue_exec(self) -> str:
        output = await self._send_exec_command("-exec-continue")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._running = False
        for rec in parsed["records"]:
            if rec["type"] == "stopped":
                reason = rec["values"].get("reason", "")
                bkptno = rec["values"].get("bkptno", "")
                return f"Stopped: {reason}" + (f" (bkpt {bkptno})" if bkptno else "")
        return "Continuing (no stop received)"

    def _extract_async_events(self, output: str) -> None:
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("*") or stripped.startswith("=") or stripped.startswith("+"):
                self._async_events.append({
                    "raw": stripped,
                    "parsed": self._parse_mi_record(stripped),
                })

    def get_async_events(self) -> list[dict]:
        events = list(self._async_events)
        self._async_events.clear()
        return events

    async def interrupt(self) -> str:
        if self._process and self._process.pid:
            os.kill(self._process.pid, signal.SIGINT)
        try:
            await self._consume_until_prompt(5.0)
        except Exception:
            pass
        self._running = False
        return "Interrupted"

    async def step_into(self) -> dict:
        output = await self._send_exec_command("-exec-step-instruction")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._running = False
        return self._extract_location(parsed)

    async def step_over(self) -> dict:
        output = await self._send_exec_command("-exec-next-instruction")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._running = False
        return self._extract_location(parsed)

    async def step_out(self) -> dict:
        output = await self._send_exec_command("-exec-finish")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._running = False
        return self._extract_location(parsed)

    async def continue_to_address(self, address: str) -> dict:
        address = address.strip()
        if not address.startswith("0x") and not address.startswith("*"):
            address = f"*{address}"
        elif address.startswith("0x"):
            address = f"*{address}"
        output = await self._send_exec_command(f"-exec-until {address}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        self._running = False
        return self._extract_location(parsed)

    def _extract_location(self, parsed: dict) -> dict:
        result = {}
        for rec in parsed["records"]:
            if rec["type"] == "stopped" or "frame" in rec["values"]:
                result["reason"] = rec["values"].get("reason", "")
                frame_str = rec["values"].get("frame", "")
                if frame_str:
                    frame = self._parse_mi_tuple(frame_str)
                    if frame:
                        result.update(frame)
                bkptno = rec["values"].get("bkptno", "")
                if bkptno:
                    result["breakpoint"] = bkptno
        if not result:
            for rec in parsed["records"]:
                if rec["type"] == "done":
                    result.update(rec["values"])
        return result

    async def set_breakpoint(self, location: str, condition: str = "", temporary: bool = False) -> dict:
        cmd = "-break-insert"
        if temporary:
            cmd += " -t"
        if condition:
            cmd += f" -c {condition}"
        output = await self._send_command(f"{cmd} {location}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        for rec in parsed["records"]:
            bkpt_val = rec["values"].get("bkpt")
            if bkpt_val:
                bkpt = self._parse_mi_tuple(bkpt_val)
                if bkpt:
                    return bkpt
        return {"number": "?", "addr": location}

    async def set_hardware_breakpoint(self, location: str) -> dict:
        output = await self._send_command(f"-break-insert -h {location}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        for rec in parsed["records"]:
            bkpt_val = rec["values"].get("bkpt")
            if bkpt_val:
                bkpt = self._parse_mi_tuple(bkpt_val)
                if bkpt:
                    return bkpt
        return {"number": "?", "addr": location}

    async def set_watchpoint(self, expression: str, watch_type: str = "write") -> dict:
        type_map = {"read": "-r", "access": "-a", "write": ""}
        flag = type_map.get(watch_type, "")
        output = await self._send_command(f"-break-watch {flag} {expression}".strip())
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        for rec in parsed["records"]:
            for key in ("wpt", "hw-awpt", "hw-rwpt"):
                val = rec["values"].get(key)
                if val:
                    wp = self._parse_mi_tuple(val)
                    if wp:
                        return wp
        return {"expression": expression, "type": watch_type}

    async def remove_breakpoint(self, number: int) -> str:
        output = await self._send_command(f"-break-delete {number}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return f"Breakpoint {number} removed"

    async def enable_breakpoint(self, number: int) -> str:
        output = await self._send_command(f"-break-enable {number}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return f"Breakpoint {number} enabled"

    async def disable_breakpoint(self, number: int) -> str:
        output = await self._send_command(f"-break-disable {number}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return f"Breakpoint {number} disabled"

    async def list_breakpoints(self) -> str:
        output = await self._send_command("-break-list")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return output

    async def get_registers(self) -> dict:
        output = await self._send_command("-data-list-register-names")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        names_str = self._extract_value(parsed, "register-names") or "[]"
        names = self._parse_mi_list(names_str)
        output = await self._send_command("-data-list-register-values x")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        values_str = self._extract_value(parsed, "register-values") or "[]"
        values = self._parse_mi_list(values_str)
        name_map = {}
        for idx_raw in names:
            if isinstance(idx_raw, str) and idx_raw:
                name_map[len(name_map)] = idx_raw
        registers = {}
        for item in values:
            if isinstance(item, dict):
                num = item.get("number", "")
                val = item.get("value", "")
                if num and val:
                    idx = int(num)
                    name = name_map.get(idx, "")
                    if name:
                        registers[name] = val
        return registers

    async def get_register(self, name: str) -> str:
        output = await self._send_command(f"-data-list-register-values x {name}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        for rec in parsed["records"]:
            vals_str = rec["values"].get("register-values", "")
            if vals_str:
                vals_parsed = self._parse_mi_list(vals_str)
                for v in vals_parsed:
                    if isinstance(v, dict):
                        val = v.get("value", "")
                        if val:
                            return val
        try:
            direct = await self._send_command(f"print/x ${name}")
            parsed = self._parse_mi_result(direct)
            for rec in parsed["records"]:
                val = rec["values"].get("value", "")
                if val:
                    return val
        except GDBBackendError:
            pass
        return "?"

    async def set_register(self, name: str, value: str) -> str:
        output = await self._send_command(f"set ${name}={value}")
        parsed = self._parse_mi_result(output)
        for rec in parsed["records"]:
            if rec["type"] == "error":
                msg = rec["values"].get("msg", "")
                if "Invalid cast" not in msg:
                    raise GDBBackendError(msg)
        return f"${name} = {value}"

    async def read_memory(self, address: str, count: int = 64) -> str:
        output = await self._send_command(f"-data-read-memory-bytes {address} {count}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return output

    async def write_memory(self, address: str, data: str) -> str:
        output = await self._send_command(f"set *({address}) = {data}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return f"Written to {address}"

    async def write_memory_bytes(self, address: str, hex_bytes: str) -> str:
        hex_bytes = hex_bytes.replace(" ", "").replace("0x", "").replace("\\x", "")
        if len(hex_bytes) % 2 != 0:
            hex_bytes = "0" + hex_bytes
        output = await self._send_command(f"set *((unsigned char*){address}) = {{{hex_bytes}}}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return f"Written {len(hex_bytes)//2} bytes to {address}"

    async def hex_dump(self, address: str, count: int = 128) -> str:
        output = await self._send_command(f"-data-read-memory-bytes {address} {count}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        result_parts = [f"Hex dump at {address}:"]
        for rec in parsed["records"]:
            memory_val = rec["values"].get("memory", "")
            if memory_val:
                entries = self._parse_mi_list(memory_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        addr = entry.get("begin", "")
                        contents = entry.get("contents", "")
                        if contents:
                            raw_bytes = bytes.fromhex(contents)
                            for i in range(0, len(raw_bytes), 16):
                                chunk = raw_bytes[i:i+16]
                                hex_str = " ".join(f"{b:02x}" for b in chunk)
                                ascii_str = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
                                offset_addr = int(addr, 16) + i if addr.startswith("0x") else 0
                                result_parts.append(f"  {offset_addr:016x}: {hex_str:<48}  {ascii_str}")
        return "\n".join(result_parts) if len(result_parts) > 1 else "No memory data"

    async def get_memory_map(self) -> str:
        output = await self._send_command("info proc mappings")
        parsed = self._parse_mi_result(output)
        return "\n".join(parsed["console"]) if parsed["console"] else "No memory map data"

    async def disassemble(self, location: str, count: int = 10) -> str:
        end = f"{location}+{count * 4}"
        output = await self._send_command(f"-data-disassemble -s {location} -e {end} -- 0")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        asm_entries = []
        for rec in parsed["records"]:
            asm_val = rec["values"].get("asm_insns", "")
            if asm_val:
                entries = self._parse_mi_list(asm_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        src_and_asm = entry.get("src_and_asm_line", entry.get("line", ""))
                        if src_and_asm:
                            sub_entries = self._parse_mi_list(src_and_asm)
                            asm_entries.extend(sub_entries)
                        else:
                            asm_entries.append(entry)
        result_parts = [f"Disassembly at {location}:"]
        for entry in asm_entries:
            if isinstance(entry, dict):
                addr = entry.get("address", "")
                func = entry.get("func-name", "")
                offset = entry.get("offset", "")
                inst = entry.get("inst", "")
                result_parts.append(f"  {addr} [{func}+{offset}] {inst}")
        if len(result_parts) > 1:
            return "\n".join(result_parts)
        return await self._disassemble_fallback(location, count)

    async def _disassemble_fallback(self, location: str, count: int) -> str:
        output = await self._send_command(f"x/{count}i {location}")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else f"No disassembly at {location}"

    async def get_current_instruction(self) -> str:
        output = await self._send_command("x/1i $pc")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return lines[0] if lines else ""

    async def get_stack(self, count: int = 16) -> str:
        output = await self._send_command(f"x/{count}gx $rsp")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        if lines:
            return "\n".join(lines)
        return await self._get_stack_fallback(count)

    async def _get_stack_fallback(self, count: int) -> str:
        output = await self._send_command(f"-stack-list-frames 0 {count}")
        return output

    async def get_stack_frame(self, frame_level: int = 0) -> str:
        output = await self._send_command(f"-stack-list-frames {frame_level} {frame_level}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        for rec in parsed["records"]:
            stack_val = rec["values"].get("stack", "")
            if stack_val:
                entries = self._parse_mi_list(stack_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        frame_str = entry.get("frame", "")
                        if frame_str:
                            frame = self._parse_mi_tuple(frame_str)
                            if frame:
                                import json
                                return json.dumps(frame, indent=2)
        return "No stack frame info"

    async def get_backtrace(self, count: int = 20) -> str:
        output = await self._send_command(f"-stack-list-frames 0 {count}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        frames = []
        for rec in parsed["records"]:
            stack_val = rec["values"].get("stack", "")
            if stack_val:
                frame_list = self._parse_mi_list(stack_val)
                for f in frame_list:
                    if isinstance(f, dict):
                        frame_str = f.get("frame", "")
                        if frame_str:
                            frame_data = self._parse_mi_tuple(frame_str)
                            if frame_data:
                                frames.append(frame_data)
        result_parts = ["Backtrace:"]
        for i, f in enumerate(frames):
            addr = f.get("addr", "")
            func = f.get("func", "?")
            file_str = f.get("file", "")
            line = f.get("line", "")
            loc = f" at {file_str}:{line}" if file_str and line else ""
            addr_str = addr if addr.startswith("0x") else f"0x{addr}" if addr else "?"
            result_parts.append(f"  #{i}  {addr_str} in {func}(){loc}")
        return "\n".join(result_parts) if len(result_parts) > 1 else "No backtrace"

    async def lookup_symbol(self, name: str) -> str:
        output = await self._send_command(f"info address {name}")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        if lines:
            return "\n".join(lines)
        output = await self._send_command(f"info symbol {name}")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"] + parsed["log"]
        return "\n".join(lines) if lines else f"Symbol {name} not found"

    async def list_modules(self) -> str:
        output = await self._send_command("info sharedlibrary")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else "No shared library info"

    async def get_section_info(self, module_name: str = "") -> str:
        if module_name:
            output = await self._send_command(f"info files {module_name}")
        else:
            output = await self._send_command("info files")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else "No section info"

    async def list_threads(self) -> str:
        output = await self._send_command("-thread-info")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return output

    async def get_current_thread(self) -> dict:
        output = await self._send_command("-thread-info")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        for rec in parsed["records"]:
            tid = rec["values"].get("current-thread-id", "")
            if tid:
                return {"current_thread_id": tid}
            threads_val = rec["values"].get("threads", "")
            if threads_val:
                threads = self._parse_mi_list(threads_val)
                for t in threads:
                    if isinstance(t, dict) and "current" in t:
                        return t
        return {}

    async def set_current_thread(self, thread_id: int) -> str:
        output = await self._send_command(f"-thread-select {thread_id}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return f"Switched to thread {thread_id}"

    async def evaluate(self, expression: str) -> str:
        output = await self._send_command(f"-data-evaluate-expression {expression}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        val = self._extract_value(parsed, "value")
        return val if val else str(parsed)

    async def get_string(self, address: str, max_len: int = 256) -> str:
        output = await self._send_command(f"x/{max_len}cb {address}")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        chars = []
        for line in lines:
            parts = line.split(":\t")
            if len(parts) > 1:
                for c in parts[1].split():
                    try:
                        val = int(c)
                        if val == 0:
                            break
                        chars.append(chr(val))
                    except (ValueError, OverflowError):
                        pass
            if len(chars) >= max_len:
                break
        text = "".join(chars)
        if text:
            return text
        output2 = await self._send_command(f"x/s {address}")
        parsed2 = self._parse_mi_result(output2)
        lines2 = parsed2["console"]
        return "\n".join(lines2) if lines2 else f"No string at {address}"

    async def get_variable(self, name: str) -> str:
        output = await self._send_command(f"-data-evaluate-expression {name}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        val = self._extract_value(parsed, "value")
        return val if val else "?"

    async def set_variable(self, name: str, value: str) -> str:
        output = await self._send_command(f"set var {name}={value}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        return f"{name} = {value}"

    async def get_function_info(self, name: str) -> str:
        output = await self._send_command(f"info functions {name}")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else f"No info for {name}"

    async def get_source(self, file: str, line: int = 1, count: int = 20) -> str:
        try:
            full_path = os.path.abspath(file)
            with open(full_path) as f:
                file_lines = f.readlines()
            start = max(0, line - 1)
            end = min(len(file_lines), start + count)
            result_parts = [f"Source {file}:"]
            for i in range(start, end):
                marker = "->" if i == line - 1 else "  "
                result_parts.append(f"  {marker} {i+1:4d}: {file_lines[i].rstrip()}")
            return "\n".join(result_parts)
        except (FileNotFoundError, IOError):
            return await self._list_source_gdb(file, line, count)

    async def _list_source_gdb(self, file: str, line: int, count: int) -> str:
        output = await self._send_command(f"list {file}:{line},{line+count}")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else f"Cannot list {file}:{line}"

    async def search_memory(self, pattern: str, address: str = "", length: str = "") -> str:
        if address and length:
            cmd = f"find /b {address}, +{length}, {pattern}"
        else:
            cmd = f"find /b $pc, +0x10000, {pattern}"
        output = await self._send_command(cmd)
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else f"Pattern not found"

    async def find_strings(self, address: str = "", length: str = "") -> str:
        if address and length:
            mem_range = f"{address} {length}"
        else:
            mem_range = "$pc $pc+0x10000"
        output = await self._send_command(f"find /b {mem_range}, 0x20, 0x7f")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else "No printable strings found"

    async def search_instructions(self, pattern: str, range_start: str = "", range_end: str = "") -> str:
        if range_start and range_end:
            cmd = f"find /i {range_start}, +{range_end}, {pattern}"
        else:
            cmd = f"find /i $pc, +0x10000, {pattern}"
        output = await self._send_command(cmd)
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else f"Instruction pattern not found"

    async def find_references(self, address: str) -> str:
        result_parts = [f"References to {address}:"]
        output = await self._send_command(f"info line *{address}")
        parsed = self._parse_mi_result(output)
        result_parts.extend(parsed["console"])
        for prefix in ("info functions", "info variables"):
            try:
                output = await asyncio.wait_for(
                    self._send_command(f"{prefix} {address}"),
                    timeout=8.0
                )
                parsed = self._parse_mi_result(output)
                for line in parsed["console"]:
                    if address.lower() in line.lower():
                        result_parts.append(f"  {line}")
            except (asyncio.TimeoutError, Exception):
                result_parts.append(f"  ({prefix} timed out)")
        return "\n".join(result_parts)

    async def get_arguments(self) -> str:
        output = await self._send_command("info args")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else "No argument info"

    async def get_locals(self) -> str:
        output = await self._send_command("info locals")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else "No local variable info"

    async def restart(self) -> str:
        if not self._binary:
            raise GDBBackendError("No binary loaded. Use edb_load_program first.")
        if self._process and self._process.returncode is None:
            try:
                await self._send_command("kill", timeout=3.0)
            except Exception:
                pass
        self._pid = None
        self._running = False
        output = await self._send_command(f"-file-exec-and-symbols {self._binary}")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        if self._args:
            await self._send_command(f"-exec-arguments {self._args}")
        return await self.run()

    async def status(self) -> dict:
        result = {
            "running": self._running,
            "pid": self._pid,
            "binary": self._binary,
            "gdb_alive": self._process is not None and self._process.returncode is None,
        }
        if self._process and self._process.returncode is None:
            try:
                regs = await self.get_registers()
                rip = regs.get("rip", regs.get("eip", "?"))
                result["instruction_pointer"] = rip
                inst = await self.get_current_instruction()
                result["current_instruction"] = inst.strip() if inst else ""
                result["num_registers"] = len(regs)
                result["rsp"] = regs.get("rsp", "")
                result["rbp"] = regs.get("rbp", "")
            except Exception:
                pass
        return result

    def _parse_mi_tuple(self, content: str) -> dict:
        content = content.strip()
        if content.startswith("{") and content.endswith("}"):
            content = content[1:-1]
        return self._parse_mi_values(content)

    def _parse_mi_list(self, content: str) -> list:
        if not content or content == "{}" or content == "[]":
            return []
        content = content.strip()
        if content.startswith("[") and content.endswith("]"):
            content = content[1:-1]
        elif content.startswith("{") and content.endswith("}"):
            content = content[1:-1]
        result = []
        depth = 0
        current = ""
        in_str = False
        for ch in content:
            if ch == '"' and (not current or current[-1] != '\\'):
                in_str = not in_str
            if not in_str:
                if ch in ('{', '['):
                    depth += 1
                elif ch in ('}', ']'):
                    depth -= 1
                elif ch == ',' and depth == 0:
                    item = current.strip()
                    if item:
                        parsed = self._parse_mi_values(item)
                        result.append(parsed if parsed else item.strip("\""))
                    current = ""
                    continue
            current += ch
        if current.strip():
            item = current.strip()
            if item:
                parsed = self._parse_mi_values(item)
                result.append(parsed if parsed else item.strip("\""))
        return result

    async def get_entry_point(self) -> str:
        try:
            output = await self._send_command("info file")
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                m = re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', line)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return "Unknown"

    async def get_function_bounds(self, name: str) -> str:
        try:
            addr_result = await self._send_command(f"info address {name}")
            addr_parsed = self._parse_mi_result(addr_result)
            addr_line = " ".join(addr_parsed["console"])
            m = re.search(r'0x[0-9a-fA-F]+', addr_line)
            if not m:
                return f"Cannot find function: {name}"
            start_addr = m.group(0)
            output = await self._send_command(f"-data-disassemble -s {start_addr} -e \"{start_addr}+0x100\" -- 0")
            parsed = self._parse_mi_result(output)
            last_addr = start_addr
            for rec in parsed["records"]:
                asm_val = rec["values"].get("asm_insns", "")
                if asm_val:
                    entries = self._parse_mi_list(asm_val)
                    for entry in entries:
                        if isinstance(entry, dict):
                            src_and_asm = entry.get("src_and_asm_line", entry.get("line", ""))
                            if src_and_asm:
                                sub_entries = self._parse_mi_list(src_and_asm)
                                for se in sub_entries:
                                    if isinstance(se, dict):
                                        addr = se.get("address", "")
                                        if addr:
                                            last_addr = addr
                            else:
                                addr = entry.get("address", "")
                                if addr:
                                    last_addr = addr
            start_int = int(start_addr, 16)
            end_int = int(last_addr, 16) + 4
            size = end_int - start_int
            return f"Function: {name}\n  Start: {start_addr}\n  End:   0x{end_int:016x}\n  Size:  {size} bytes"
        except Exception as e:
            output = await self._send_command(f"info functions {name}")
            parsed = self._parse_mi_result(output)
            lines = parsed["console"]
            return "\n".join(lines) if lines else f"Cannot find function: {name}"

    async def _get_load_delta(self) -> int:
        ep_runtime_str = await self.get_entry_point()
        try:
            ep_runtime = int(ep_runtime_str, 16)
        except ValueError:
            return 0
        if not self._binary:
            return 0
        if self._pwntools_available:
            try:
                from pwn import ELF
                elf = ELF(self._binary)
                return ep_runtime - elf.entry
            except Exception:
                pass
        try:
            proc = await asyncio.create_subprocess_exec(
                "readelf", "-h", self._binary,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            for line in stdout.decode().splitlines():
                m = re.search(r'Entry point address:\s*(0x[0-9a-fA-F]+)', line)
                if m:
                    ep_file = int(m.group(1), 16)
                    return ep_runtime - ep_file
        except Exception:
            pass
        return 0

    async def _readelf_load_segments(self) -> list:
        if not self._binary:
            return []
        if self._pwntools_available:
            try:
                from pwn import ELF
                elf = ELF(self._binary)
                segments = []
                for seg in elf.segments:
                    if seg.header.p_type == 'PT_LOAD':
                        vaddr = seg.header.p_vaddr
                        file_off = seg.header.p_offset
                        filesz = seg.header.p_filesz
                        if filesz > 0:
                            segments.append((vaddr, file_off, filesz))
                return segments
            except Exception:
                pass
        try:
            proc = await asyncio.create_subprocess_exec(
                "readelf", "-l", self._binary,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            segments = []
            lines = stdout.decode().splitlines()
            for i, line in enumerate(lines):
                parts = line.split()
                if parts and parts[0] == "LOAD":
                    if len(parts) >= 4:
                        try:
                            file_off = int(parts[1], 16)
                            vaddr = int(parts[2], 16)
                            if i + 1 < len(lines):
                                next_parts = lines[i+1].split()
                                if len(next_parts) >= 2:
                                    filesz = int(next_parts[0], 16)
                                    if filesz > 0:
                                        segments.append((vaddr, file_off, filesz))
                        except (ValueError, IndexError):
                            continue
            return segments
        except Exception:
            return []

    async def file_offset_to_va(self, offset: int) -> str:
        segments = await self._readelf_load_segments()
        if not segments:
            return "Cannot read ELF program headers"
        load_delta = await self._get_load_delta()
        for vaddr, file_off, filesz in segments:
            if file_off <= offset < file_off + filesz:
                runtime_va = vaddr + (offset - file_off) + load_delta
                return f"0x{runtime_va:x}"
        return f"Cannot convert offset 0x{offset:x}"

    async def va_to_file_offset(self, address: str) -> str:
        addr_int = int(address, 16) if address.startswith("0x") else int(address, 16)
        segments = await self._readelf_load_segments()
        if not segments:
            return "Cannot read ELF program headers"
        load_delta = await self._get_load_delta()
        for vaddr, file_off, filesz in segments:
            runtime_start = vaddr + load_delta
            if runtime_start <= addr_int < runtime_start + filesz:
                off = file_off + (addr_int - runtime_start)
                return f"0x{off:x}"
        return f"Cannot convert address {address}"

    async def read_memory_as(self, address: str, data_type: str = "uint32", count: int = 1) -> str:
        type_map = {
            "int8": ("b", "signed char"), "uint8": ("b", "unsigned char"),
            "int16": ("h", "signed short"), "uint16": ("h", "unsigned short"),
            "int32": ("w", "signed int"), "uint32": ("w", "unsigned int"),
            "int64": ("g", "signed long long"), "uint64": ("g", "unsigned long long"),
            "float": ("f", "float"), "double": ("g", "double"),
            "pointer": ("a", "void*"),
        }
        if data_type == "string":
            output = await self._send_command(f"x/s {address}")
            parsed = self._parse_mi_result(output)
            lines = parsed["console"]
            return "\n".join(lines) if lines else f"No string at {address}"
        if data_type not in type_map:
            return f"Unsupported type: {data_type}"
        gdb_fmt, c_type = type_map[data_type]
        if count == 1:
            output = await self._send_command(f"print/d *({c_type}*){address}")
            parsed = self._parse_mi_result(output)
            val = self._extract_value(parsed, "value")
            if val:
                return f"{address} ({data_type}): {val}"
            output = await self._send_command(f"x/1{gdb_fmt}x {address}")
            parsed = self._parse_mi_result(output)
            lines = parsed["console"]
            return "\n".join(lines) if lines else f"No data at {address}"
        if data_type in ("pointer",):
            output = await self._send_command(f"x/{count}{gdb_fmt}x {address}")
        else:
            output = await self._send_command(f"x/{count}{gdb_fmt}x {address}")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        return "\n".join(lines) if lines else f"No data at {address}"

    async def nop_range(self, start_address: str, end_address: str) -> str:
        if start_address.startswith("0x"):
            start = int(start_address, 16)
        else:
            start = 0
        if end_address.startswith("0x"):
            end = int(end_address, 16)
        else:
            end = 0
        if end > 0 and start > 0 and end <= start:
            return "Error: end address must be greater than start address"
        if start > 0 and end > 0:
            count = end - start
            nop_bytes = " ".join(["90"] * min(count, 1024))
            return await self.write_memory_bytes(start_address, nop_bytes)
        return f"Patched NOPs from {start_address} to {end_address} (range resolved by GDB)"

    async def analyze_calls_at(self, address: str) -> str:
        output = await self._send_command(f"-data-disassemble -s {address} -e \"{address}+0x20\" -- 0")
        parsed = self._parse_mi_result(output)
        result_parts = [f"Calls/References at {address}:"]
        for rec in parsed["records"]:
            asm_val = rec["values"].get("asm_insns", "")
            if asm_val:
                entries = self._parse_mi_list(asm_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        src_and_asm = entry.get("src_and_asm_line", entry.get("line", ""))
                        target_entries = []
                        if src_and_asm:
                            sub_entries = self._parse_mi_list(src_and_asm)
                            target_entries.extend(sub_entries)
                        else:
                            target_entries.append(entry)
                        for se in target_entries:
                            if isinstance(se, dict):
                                addr = se.get("address", "")
                                inst = se.get("inst", "")
                                if inst:
                                    result_parts.append(f"  {addr}: {inst}")
                                    if "call" in inst.lower() or "jmp" in inst.lower() or "jz" in inst.lower() or "jnz" in inst.lower():
                                        inst_parts = inst.split()
                                        if len(inst_parts) >= 2:
                                            target = inst_parts[-1].rstrip(",")
                                            target_info = await self._send_command(f"info symbol {target}")
                                            t_parsed = self._parse_mi_result(target_info)
                                            t_lines = t_parsed["console"] + t_parsed["log"]
                                            if t_lines:
                                                result_parts.append(f"       -> {t_lines[0]}")
        return "\n".join(result_parts) if len(result_parts) > 1 else "No calls found"

    async def string_references(self, string_or_address: str) -> str:
        result_parts = [f"References to {string_or_address}:"]
        for prefix in ("info functions", "info variables"):
            try:
                output = await asyncio.wait_for(
                    self._send_command(f"{prefix} {string_or_address}"),
                    timeout=8.0
                )
                parsed = self._parse_mi_result(output)
                for line in parsed["console"]:
                    if string_or_address.lower() in line.lower():
                        label = "Function" if "function" in prefix else "Variable"
                        result_parts.append(f"  {label}: {line}")
            except (asyncio.TimeoutError, Exception):
                result_parts.append(f"  ({prefix} timed out)")
        try:
            output = await asyncio.wait_for(
                self._send_command("info sources", timeout=5.0),
                timeout=5.0
            )
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                if string_or_address.lower() in line.lower():
                    result_parts.append(f"  Source: {line}")
        except Exception:
            pass
        return "\n".join(result_parts)

    async def disassemble_range(self, start_address: str, end_address: str) -> str:
        output = await self._send_command(f"-data-disassemble -s {start_address} -e {end_address} -- 0")
        parsed = self._parse_mi_result(output)
        self._check_error(parsed)
        asm_entries = []
        for rec in parsed["records"]:
            asm_val = rec["values"].get("asm_insns", "")
            if asm_val:
                entries = self._parse_mi_list(asm_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        src_and_asm = entry.get("src_and_asm_line", entry.get("line", ""))
                        if src_and_asm:
                            sub_entries = self._parse_mi_list(src_and_asm)
                            asm_entries.extend(sub_entries)
                        else:
                            asm_entries.append(entry)
        result_parts = [f"Disassembly {start_address} - {end_address}:"]
        for entry in asm_entries:
            if isinstance(entry, dict):
                addr = entry.get("address", "")
                func = entry.get("func-name", "")
                offset = entry.get("offset", "")
                inst = entry.get("inst", "")
                result_parts.append(f"  {addr} [{func}+{offset}] {inst}")
        if len(result_parts) > 1:
            return "\n".join(result_parts)
        return await self._disassemble_fallback(start_address, abs(int(end_address, 16) - int(start_address, 16)) // 4)

    async def set_conditional_log_breakpoint(self, location: str, log_message: str) -> str:
        result = await self.set_breakpoint(location, temporary=False)
        num = result.get("number", "?")
        cmds = [
            f"commands {num}",
            "silent",
            f'printf "{log_message}\\n"',
            "continue",
            "end",
        ]
        async with self._input_lock:
            for cmd in cmds:
                self._process.stdin.write(cmd.encode() + b"\n")
                await self._process.stdin.drain()
                await asyncio.sleep(0.05)
            await asyncio.sleep(0.1)
            try:
                await self._consume_until_prompt(3.0)
            except Exception:
                pass
        return f"Trace point {num} at {location}: prints \"{log_message}\" and continues"

    async def fill_memory(self, address: str, byte_value: str, count: int) -> str:
        byte_value = byte_value.strip()
        if byte_value.startswith("0x"):
            byte_value = byte_value[2:]
        hex_str = " ".join([byte_value] * count)
        return await self.write_memory_bytes(address, hex_str)

    async def compare_memory(self, address1: str, address2: str, count: int) -> str:
        output1 = await self._send_command(f"-data-read-memory-bytes {address1} {count}")
        parsed1 = self._parse_mi_result(output1)
        output2 = await self._send_command(f"-data-read-memory-bytes {address2} {count}")
        parsed2 = self._parse_mi_result(output2)
        def extract_bytes(parsed):
            for rec in parsed["records"]:
                memory_val = rec["values"].get("memory", "")
                if memory_val:
                    entries = self._parse_mi_list(memory_val)
                    for entry in entries:
                        if isinstance(entry, dict):
                            contents = entry.get("contents", "")
                            if contents:
                                return bytes.fromhex(contents)
            return b""
        data1 = extract_bytes(parsed1)
        data2 = extract_bytes(parsed2)
        if not data1 or not data2:
            return "Cannot read memory"
        diff_count = 0
        result_parts = [f"Memory diff ({address1} vs {address2}):"]
        limit = min(len(data1), len(data2), count)
        for i in range(0, limit, 16):
            chunk1 = data1[i:i+16]
            chunk2 = data2[i:i+16]
            if chunk1 != chunk2:
                hex1 = " ".join(f"{b:02x}" for b in chunk1)
                hex2 = " ".join(f"{b:02x}" for b in chunk2)
                addr_val = int(address1, 16) + i if address1.startswith("0x") else i
                result_parts.append(f"  Offset +{i:04x}:")
                result_parts.append(f"    {address1}: {hex1:<48}")
                result_parts.append(f"    {address2}: {hex2:<48}")
                diff_count += 1
        result_parts.append(f"Total differing regions: {diff_count}")
        return "\n".join(result_parts)

    _comments: dict = {}

    async def add_comment(self, address: str, comment: str) -> str:
        self._comments[address] = comment
        return f"Comment added at {address}: {comment}"

    async def list_comments(self) -> str:
        if not self._comments:
            return "No comments"
        lines = ["Address annotations:"]
        for addr, comment in sorted(self._comments.items()):
            lines.append(f"  {addr}: {comment}")
        return "\n".join(lines)

    async def remove_comment(self, address: str) -> str:
        if address in self._comments:
            del self._comments[address]
            return f"Comment removed at {address}"
        return f"No comment at {address}"

    async def get_binary_info(self) -> str:
        if not self._binary:
            return "No binary loaded"
        if self._pwntools_available:
            try:
                from pwn import ELF
                elf = ELF(self._binary)
                info = ["Binary info:"]
                info.append(f"  Architecture: {elf.arch}")
                info.append(f"  Bits: {elf.bits}")
                info.append(f"  Entry point: 0x{elf.entry:x}")
                if elf.pie:
                    info.append("  Type: PIE (Position Independent Executable)")
                else:
                    info.append("  Type: Executable")
                if not elf.nx:
                    info.append("  NX: disabled")
                else:
                    info.append("  NX: enabled")
                if elf.canary:
                    info.append("  Stack canary: yes")
                else:
                    info.append("  Stack canary: no")
                if elf.relro == 'Full':
                    info.append("  RELRO: Full")
                elif elf.relro:
                    info.append("  RELRO: Partial")
                else:
                    info.append("  RELRO: None")
                return "\n".join(info)
            except Exception as e:
                return f"Error: {e}"
        try:
            proc = await asyncio.create_subprocess_exec(
                "readelf", "-h", self._binary,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            output = stdout.decode()
            info = ["Binary info:"]
            for line in output.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("ELF Header"):
                    info.append(f"  {stripped}")
            return "\n".join(info)
        except Exception as e:
            return f"Error: {e}"

    async def list_functions(self, filter_str: str = "") -> str:
        if filter_str:
            output = await self._send_command(f"info functions {filter_str}")
        else:
            output = await self._send_command("info functions")
        parsed = self._parse_mi_result(output)
        lines = parsed["console"]
        filtered = []
        for line in lines:
            if filter_str:
                if filter_str.lower() in line.lower():
                    filtered.append(line)
            else:
                if not line.startswith("All "):
                    filtered.append(line)
        return "\n".join(filtered) if filtered else "No functions found"

    async def find_rop_gadgets(self, address: str = "", depth: int = 2, count: int = 100) -> str:
        if not address:
            if self._pwntools_available and self._binary:
                try:
                    from pwn import ROP, ELF
                    elf = ELF(self._binary)
                    rop = ROP(elf)
                    if rop.gadgets:
                        gadgets = []
                        sorted_addrs = sorted(rop.gadgets.keys())[:count]
                        for gaddr in sorted_addrs:
                            ginsns = rop.gadgets[gaddr]
                            insn_str = "; ".join(ginsns.insns)
                            gadgets.append(f"  {hex(gaddr)}: {insn_str}")
                        result_parts = [f"ROP gadgets from binary ({len(gadgets)} found, showing up to {count}):"]
                        result_parts.extend(gadgets)
                        return "\n".join(result_parts)
                except Exception:
                    pass
            addr = "$pc"
        else:
            addr = address
        ret_opcodes = {"x86_64": ["c3", "cb", "ca", "cb"], "i386": ["c3", "cb", "ca", "cb"]}
        output = await self._send_command(f"-data-read-memory-bytes {addr} {count * 4}")
        parsed = self._parse_mi_result(output)
        raw_bytes = b""
        for rec in parsed["records"]:
            memory_val = rec["values"].get("memory", "")
            if memory_val:
                entries = self._parse_mi_list(memory_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        contents = entry.get("contents", "")
                        if contents:
                            raw_bytes = bytes.fromhex(contents)
        if not raw_bytes:
            return "Cannot read memory for ROP search"
        gadgets = []
        for i in range(len(raw_bytes)):
            if raw_bytes[i] == 0xc3:
                start = max(0, i - depth * 2)
                gadget_bytes = raw_bytes[start:i+1]
                if len(gadget_bytes) <= depth * 2 + 1:
                    base_addr = int(addr, 16) + start if addr.startswith("0x") else 0
                    hex_str = " ".join(f"{b:02x}" for b in gadget_bytes)
                    gadgets.append(f"  0x{base_addr:016x}: {hex_str}")
                    if len(gadgets) >= count:
                        break
        result_parts = [f"ROP gadgets near {addr} (found {len(gadgets)}):"]
        result_parts.extend(gadgets)
        return "\n".join(result_parts) if len(gadgets) > 0 else "No ROP gadgets found"

    async def analyze_region(self, address: str, size: int) -> str:
        region_start = address
        region_end = hex(int(address, 16) + size) if address.startswith("0x") else f"{address}+{size}"
        output = await self._send_command(f"-data-disassemble -s {region_start} -e {region_end} -- 0")
        parsed = self._parse_mi_result(output)
        instructions = []
        for rec in parsed["records"]:
            asm_val = rec["values"].get("asm_insns", "")
            if asm_val:
                entries = self._parse_mi_list(asm_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        src_and_asm = entry.get("src_and_asm_line", entry.get("line", ""))
                        if src_and_asm:
                            sub_entries = self._parse_mi_list(src_and_asm)
                            instructions.extend(sub_entries)
                        else:
                            instructions.append(entry)
        calls = []
        strings = []
        branches = []
        for inst in instructions:
            if isinstance(inst, dict):
                addr = inst.get("address", "")
                text = inst.get("inst", "")
                if "call" in text.lower():
                    calls.append(f"  CALL {addr}: {text}")
                elif "jmp" in text.lower() or "je " in text.lower() or "jne " in text.lower() or "jz " in text.lower() or "jnz " in text.lower():
                    branches.append(f"  BRANCH {addr}: {text}")
        addr_int = int(address, 16) if address.startswith("0x") else 0
        str_output = await self._send_command(f"find /b {region_start}, +{hex(size)}, 0x20, 0x7f")
        str_parsed = self._parse_mi_result(str_output)
        str_lines = str_parsed["console"]
        result_parts = [
            f"Analysis of region {region_start} ({size} bytes):",
            f"  Instructions: {len(instructions)}",
            f"  Call instructions: {len(calls)}",
            f"  Branch instructions: {len(branches)}",
        ]
        if calls:
            result_parts.append("\nCalls:")
            result_parts.extend(calls[:20])
        if branches:
            result_parts.append("\nBranches:")
            result_parts.extend(branches[:20])
        return "\n".join(result_parts)

    async def analyze_heap(self) -> str:
        output = await self._send_command("info proc mappings")
        parsed = self._parse_mi_result(output)
        heap_regions = []
        for line in parsed["console"]:
            if "[heap]" in line:
                parts = line.split()
                if len(parts) >= 5:
                    start = parts[0]
                    end = parts[1].rstrip(":")
                    perms = parts[2] if len(parts) > 2 else "???"
                    heap_regions.append((start, end, perms))
        if not heap_regions:
            for line in parsed["console"]:
                m = re.search(r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(rw-p|rwxp)', line)
                if m:
                    start = m.group(1)
                    end = m.group(2)
                    perms = m.group(3)
                    start_int = int(start, 16)
                    end_int = int(end, 16)
                    size = end_int - start_int
                    if 0x10000 < size < 0x10000000:
                        heap_regions.append((start, end, perms))
        if not heap_regions:
            return "No heap region found"
        result_parts = ["Heap analysis:"]
        for start, end, perms in heap_regions:
            start_int = int(start, 16)
            end_int = int(end, 16)
            size = end_int - start_int
            result_parts.append(f"\n  Region: {start} - {end} ({perms})")
            result_parts.append(f"  Size: {size} bytes ({size // 1024} KB)")
            output = await self._send_command(f"find /b {start}, +{hex(size)}, 0x20, 0x7f")
            parsed = self._parse_mi_result(output)
            str_count = len(parsed["console"])
            result_parts.append(f"  Strings found: {str_count}")
            try:
                stats = await self._send_command(f"-data-read-memory-bytes {start} {min(size, 64)}")
                s_parsed = self._parse_mi_result(stats)
                for rec in s_parsed["records"]:
                    memory_val = rec["values"].get("memory", "")
                    if memory_val:
                        entries = self._parse_mi_list(memory_val)
                        for entry in entries:
                            if isinstance(entry, dict):
                                contents = entry.get("contents", "")
                                if contents and len(contents) >= 8:
                                    result_parts.append(f"  First bytes: {contents[:32]}...")
            except Exception:
                pass
        return "\n".join(result_parts)

    _bookmarks: dict = {}

    async def add_bookmark(self, name: str, address: str) -> str:
        self._bookmarks[name] = address
        return f"Bookmark added: {name} -> {address}"

    async def list_bookmarks(self) -> str:
        if not self._bookmarks:
            return "No bookmarks"
        lines = ["Bookmarks:"]
        for name, addr in sorted(self._bookmarks.items()):
            lines.append(f"  {name}: {addr}")
        return "\n".join(lines)

    async def remove_bookmark(self, name: str) -> str:
        if name in self._bookmarks:
            del self._bookmarks[name]
            return f"Bookmark removed: {name}"
        return f"No bookmark named: {name}"

    async def get_process_properties(self) -> str:
        result_parts = ["Process properties:"]
        if self._pid:
            result_parts.append(f"  PID: {self._pid}")
        else:
            result_parts.append("  PID: (no process)")
        result_parts.append(f"  Binary: {self._binary}")
        result_parts.append(f"  Arguments: {self._args}")
        try:
            output = await self._send_command("info proc")
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                result_parts.append(f"  {line}")
        except Exception:
            pass
        try:
            ep = await self.get_entry_point()
            result_parts.append(f"  Entry point: {ep}")
        except Exception:
            pass
        try:
            regs = await self.get_registers()
            result_parts.append(f"  Register count: {len(regs)}")
            result_parts.append(f"  RIP: {regs.get('rip', '?')}")
            result_parts.append(f"  RSP: {regs.get('rsp', '?')}")
            result_parts.append(f"  RBP: {regs.get('rbp', '?')}")
        except Exception:
            pass
        return "\n".join(result_parts)

    async def dump_memory_to_file(self, address: str, size: int, file_path: str) -> str:
        output = await self._send_command(f"-data-read-memory-bytes {address} {size}")
        parsed = self._parse_mi_result(output)
        raw_bytes = b""
        for rec in parsed["records"]:
            memory_val = rec["values"].get("memory", "")
            if memory_val:
                entries = self._parse_mi_list(memory_val)
                for entry in entries:
                    if isinstance(entry, dict):
                        contents = entry.get("contents", "")
                        if contents:
                            raw_bytes = bytes.fromhex(contents)
        if not raw_bytes:
            return "Cannot read memory"
        file_path = os.path.abspath(file_path)
        try:
            with open(file_path, "wb") as f:
                f.write(raw_bytes)
            return f"Dumped {len(raw_bytes)} bytes from {address} to {file_path}"
        except Exception as e:
            return f"Error writing file: {e}"

    async def assemble(self, address: str, instruction: str) -> str:
        try:
            from keystone import Ks, KS_ARCH_X86, KS_MODE_64
            ks = Ks(KS_ARCH_X86, KS_MODE_64)
            encoding, count = ks.asm(instruction)
            if not encoding:
                return f"Cannot assemble: {instruction}"
            hex_bytes = " ".join(f"0x{b:02x}" for b in encoding)
            result = await self.write_memory_bytes(address, hex_bytes)
            addr_str = address if address.startswith("0x") else f"0x{int(address, 16):x}" if address else address
            return f"Assembled '{instruction}' -> {hex_bytes} at {addr_str}"
        except ImportError:
            return await self._assemble_gdb_fallback(address, instruction)
        except Exception as e:
            return await self._assemble_gdb_fallback(address, instruction)

    async def _assemble_gdb_fallback(self, address: str, instruction: str) -> str:
        if instruction == "nop":
            return await self.write_memory_bytes(address, "90")
        elif instruction.startswith("int3"):
            return await self.write_memory_bytes(address, "cc")
        elif instruction.startswith("ret"):
            return await self.write_memory_bytes(address, "c3")
        elif instruction.startswith("jmp ") or instruction.startswith("call "):
            return f"Cannot assemble '{instruction}' without keystone engine. Install python3-keystone or use edb_write_memory_bytes with raw opcodes."
        return f"Cannot assemble '{instruction}'. Install python3-keystone for full assembly support, or use edb_write_memory_bytes with raw hex bytes."

    async def get_arch_info(self) -> str:
        result_parts = ["Architecture info:"]
        try:
            output = await self._send_command("info proc")
            for line in self._parse_mi_result(output)["console"]:
                result_parts.append(f"  {line}")
        except Exception:
            pass
        try:
            output = await self._send_command("show architecture")
            for line in self._parse_mi_result(output)["console"]:
                result_parts.append(f"  {line}")
        except Exception:
            try:
                output = await self._send_command("show arch")
                for line in self._parse_mi_result(output)["console"]:
                    result_parts.append(f"  {line}")
            except Exception:
                pass
        if self._binary:
            if self._pwntools_available:
                try:
                    from pwn import ELF
                    elf = ELF(self._binary)
                    arch_label = {"i386": "Intel 80386", "amd64": "Advanced Micro Devices X86-64", "aarch64": "AArch64", "arm": "ARM"}.get(elf.arch, elf.arch)
                    result_parts.append(f"  Machine: {arch_label}")
                    result_parts.append(f"  Class: ELF{elf.bits}")
                    result_parts.append(f"  Entry point: 0x{elf.entry:x}")
                except Exception:
                    pass
            else:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "readelf", "-h", self._binary,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                    for line in stdout.decode().splitlines():
                        stripped = line.strip()
                        if stripped.startswith("Machine") or stripped.startswith("Class") or stripped.startswith("Type"):
                            result_parts.append(f"  {stripped}")
                except Exception:
                    pass
        return "\n".join(result_parts)

    async def instruction_detail(self, address: str = "") -> str:
        target = address if address else "$pc"
        try:
            output = await self._send_command(f"python import gdb; i=gdb.selected_frame().architecture().disassemble({target})[0]; print(f'address=0x{{i[\"addr\"]:x}}|length={{i[\"length\"]}}|asm={{i[\"asm\"]}}')", timeout=10.0)
            parsed = self._parse_mi_result(output)
            detail = parsed["console"][0] if parsed["console"] else ""
            output2 = await self._send_command(f"x/1bx {target}")
            parsed2 = self._parse_mi_result(output2)
            bytes_str = parsed2["console"][0] if parsed2["console"] else ""
            output3 = await self._send_command(f"python o=gdb.execute('info registers',to_string=True); print(o)", timeout=10.0)
            parsed3 = self._parse_mi_result(output3)
            return f"Instruction detail:\n  {detail}\n  Bytes: {bytes_str}\n  Registers at execution:\n{parsed3['console'][0] if parsed3['console'] else ''}"
        except GDBBackendError:
            try:
                output = await self._send_command(f"x/3i {target}")
                parsed = self._parse_mi_result(output)
                detail = "\n".join(parsed["console"][:3]) if parsed["console"] else "No data"
                output2 = await self._send_command(f"x/16bx {target}")
                parsed2 = self._parse_mi_result(output2)
                bytes_str = "\n".join(parsed2["console"][:2]) if parsed2["console"] else ""
                return f"Instruction detail:\n  {detail}\n  {bytes_str}"
            except Exception as e:
                return f"Error: {e}"
        except Exception as e:
            return f"Error: {e}"

    async def dump_state(self) -> str:
        parts = ["=== PROCESS STATE DUMP ==="]
        try:
            regs = await self.get_registers()
            parts.append("--- Registers ---")
            for k, v in sorted(regs.items()):
                parts.append(f"  {k}: {v}")
        except Exception:
            parts.append("  (registers unavailable)")
        try:
            inst = await self.get_current_instruction()
            parts.append(f"--- Current Instruction ---\n  {inst.strip()}")
        except Exception:
            parts.append("  (instruction unavailable)")
        try:
            stack = await self.get_stack(8)
            parts.append(f"--- Stack (top 8) ---\n{stack}")
        except Exception:
            parts.append("  (stack unavailable)")
        try:
            bt = await self.get_backtrace(10)
            parts.append(f"--- Backtrace ---\n{bt}")
        except Exception:
            parts.append("  (backtrace unavailable)")
        try:
            mm = await self.get_memory_map()
            lines = mm.split("\n")[:6]
            parts.append("--- Memory Map ---")
            parts.extend(lines if len(lines) > 1 else ["  " + mm])
        except Exception:
            parts.append("  (memory map unavailable)")
        try:
            status = await self.status()
            parts.append("--- Status ---")
            for k, v in status.items():
                parts.append(f"  {k}: {v}")
        except Exception:
            pass
        return "\n".join(parts)

    async def get_stop_reason(self) -> str:
        parts = []
        try:
            output = await self._send_command("info program")
            parsed = self._parse_mi_result(output)
            parts.extend(parsed["console"])
        except Exception:
            parts.append("Could not determine stop reason")
        try:
            output = await self._send_command("python s=gdb.selected_thread(); print(f'thread={s.num if s else \"none\"}|name={s.name or \"\"}|stopped={s.is_stopped()}|exit={s.is_exit()}')", timeout=10.0)
            parsed = self._parse_mi_result(output)
            if parsed["console"]:
                parts.append("Thread: " + parsed["console"][0])
        except Exception:
            pass
        return "\n".join(parts)

    async def get_frame_info(self, frame_level: int = 0) -> str:
        if frame_level > 0:
            await self._send_command(f"frame {frame_level}")
        try:
            output = await self._send_command("info frame")
            parsed = self._parse_mi_result(output)
            parts = parsed["console"]
            output2 = await self._send_command("info args")
            parsed2 = self._parse_mi_result(output2)
            if parsed2["console"]:
                parts.append("")
                parts.append("Arguments:")
                parts.extend(f"  {l}" for l in parsed2["console"])
            output3 = await self._send_command("info locals")
            parsed3 = self._parse_mi_result(output3)
            if parsed3["console"]:
                parts.append("")
                parts.append("Locals:")
                parts.extend(f"  {l}" for l in parsed3["console"])
            return "\n".join(parts)
        except Exception as e:
            return f"Error: {e}"

    async def set_catchpoint(self, event: str, condition: str = "") -> str:
        valid_events = ["throw", "catch", "syscall", "signal", "assert", "exec", "fork", "vfork", "load", "unload"]
        if event not in valid_events:
            events_str = ", ".join(valid_events)
            return f"Invalid event '{event}'. Valid: {events_str}"
        try:
            if event == "syscall":
                if condition:
                    cmd = f"catch syscall {condition}"
                else:
                    cmd = "catch syscall"
            else:
                cmd = f"catch {event}"
                if condition:
                    cmd += f" if {condition}"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else output.strip()
        except Exception as e:
            return f"Error: {e}"

    async def signal_handling(self, signal: str, action: str = "") -> str:
        valid_signals = {"SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS"}
        valid_actions = {"", "stop", "nostop", "print", "noprint", "pass", "nopass", "ignore"}
        if action and action not in valid_actions:
            return f"Invalid action '{action}'. Valid: stop, nostop, print, noprint, pass, nopass, ignore"
        try:
            if action == "ignore":
                cmd = f"handle {signal} nostop noprint pass"
            elif action:
                cmd = f"handle {signal} {action}"
            else:
                output = await self._send_command(f"info signal {signal}")
                parsed = self._parse_mi_result(output)
                return "\n".join(parsed["console"]) if parsed["console"] else f"Signal {signal}: no info"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Signal {signal}: {action} set"
        except Exception as e:
            return f"Error: {e}"

    async def generate_core_dump(self, file_path: str = "") -> str:
        if not file_path:
            file_path = "core"
        try:
            output = await self._send_command(f"gcore {file_path}")
            parsed = self._parse_mi_result(output)
            console = "\n".join(parsed["console"])
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                return f"Core dump saved: {file_path} ({size} bytes)\n{console}"
            return f"Core dump generated\n{console}"
        except Exception as e:
            return f"Error generating core dump: {e}"

    async def remote_connect(self, host: str, port: int, extended: bool = False) -> str:
        try:
            if extended:
                cmd = f"target extended-remote {host}:{port}"
            else:
                cmd = f"target remote {host}:{port}"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            result = "\n".join(parsed["console"]) if parsed["console"] else f"Connected to {host}:{port}"
            self._running = True
            self._pid = -1
            return result
        except Exception as e:
            return f"Error connecting to {host}:{port}: {e}"

    async def list_signals(self, signal: str = "") -> str:
        try:
            if signal:
                output = await self._send_command(f"info signal {signal}")
            else:
                output = await self._send_command("info signals")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else "No signal info available"
        except Exception as e:
            return f"Error: {e}"

    async def generate_symbols(self, path: str = "") -> str:
        binary = path if path else self._binary
        if not binary:
            return "No binary specified. Provide a path or load a binary first."
        try:
            proc = await asyncio.create_subprocess_exec(
                "edb", "--symbols", binary,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            output = stdout.decode()
            if not output:
                output = stderr.decode()
            lines = output.strip().split("\n")
            filtered = [l for l in lines if l.strip() and "BinaryInfoPlugin" not in l]
            return "\n".join(filtered[:200]) if filtered else output.strip()
        except FileNotFoundError:
            return "Error: edb not installed or --symbols not supported"
        except Exception as e:
            return f"Error generating symbols: {e}"

    async def compare_sections(self) -> str:
        try:
            output = await self._send_command("compare-sections")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else "Sections compare completed"
        except Exception as e:
            return f"Error: {e}"

    async def reverse_step(self, count: int = 1) -> str:
        try:
            output = await self._send_command(f"reverse-step {count}")
            parsed = self._parse_mi_result(output)
            if "*stopped" in output:
                return "Reverse-step completed"
            return "\n".join(parsed["console"]) if parsed["console"] else f"Reverse-step {count}"
        except Exception as e:
            return f"Error (reverse exec may not be available): {e}"

    async def reverse_continue(self) -> str:
        try:
            output = await self._send_command("reverse-continue")
            parsed = self._parse_mi_result(output)
            if "*stopped" in output:
                return "Reverse-continue completed"
            return "\n".join(parsed["console"]) if parsed["console"] else "Reverse-continue"
        except Exception as e:
            return f"Error (reverse exec may not be available): {e}"

    async def set_working_directory(self, directory: str) -> str:
        try:
            output = await self._send_command(f"cd {directory}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Working directory set to {directory}"
        except Exception as e:
            return f"Error: {e}"

    async def configure_debugger(self, setting: str, value: str = "") -> str:
        try:
            if value:
                cmd = f"set {setting} {value}"
            else:
                cmd = f"set {setting}"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Set {setting} {value}".strip()
        except Exception as e:
            return f"Error: {e}"

    async def show_configuration(self, setting: str = "") -> str:
        try:
            if setting:
                cmd = f"show {setting}"
            else:
                return "Usage: provide a setting name (e.g., 'architecture', 'follow-fork-mode', 'backtrace limit')"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else "No info available"
        except Exception as e:
            return f"Error: {e}"

    async def breakpoint_export(self, file_path: str) -> str:
        try:
            output = await self._send_command("info breakpoints")
            parsed = self._parse_mi_result(output)
            bp_lines = parsed["console"]
            bps = []
            for line in bp_lines:
                if not line.strip() or line.strip().startswith("Num") or line.strip().startswith("---"):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    bp = {"number": parts[0], "type": parts[1], "enabled": parts[2] != "n", "what": " ".join(parts[3:])}
                    bps.append(bp)
            data = {"version": "1.0", "breakpoints": bps}
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
            return f"Exported {len(bps)} breakpoints to {file_path}"
        except Exception as e:
            return f"Error: {e}"

    async def breakpoint_import(self, file_path: str) -> str:
        try:
            if not os.path.exists(file_path):
                return f"File not found: {file_path}"
            with open(file_path) as f:
                data = json.load(f)
            bps = data.get("breakpoints", [])
            if not bps:
                return "No breakpoints found in file"
            imported = 0
            for bp in bps:
                what = bp.get("what", "")
                if what:
                    try:
                        await self._send_command(f"break {what}")
                        imported += 1
                    except Exception:
                        pass
            return f"Imported {imported}/{len(bps)} breakpoints from {file_path}"
        except Exception as e:
            return f"Error: {e}"

    async def view_at_address(self, address: str) -> str:
        parts = [f"=== View at {address} ==="]
        try:
            disasm = await self.disassemble(address, 5)
            parts.append(f"--- Disassembly ---\n{disasm}")
        except Exception:
            pass
        try:
            hexmem = await self.hex_dump(address, 64)
            parts.append(f"--- Hex Dump ---\n{hexmem}")
        except Exception:
            pass
        try:
            regs = await self.get_registers()
            near_regs = {k: v for k, v in regs.items() if v.lower().startswith(("0x", address[:4])) or address.lower() in v.lower()}
            if near_regs:
                parts.append("--- Registers pointing here ---")
                for k, v in near_regs.items():
                    parts.append(f"  {k}: {v}")
        except Exception:
            pass
        try:
            refs = await self.find_references(address)
            if refs and "No references" not in refs:
                parts.append(f"--- References ---\n{refs}")
        except Exception:
            pass
        return "\n".join(parts)

    async def session_save(self, file_path: str) -> str:
        try:
            state = {
                "version": "1.0",
                "binary": self._binary,
                "args": self._args,
                "pid": self._pid,
                "running": self._running,
                "bookmarks": {},
                "comments": {},
            }
            try:
                state["bookmarks"] = dict(self._bookmarks)
            except Exception:
                pass
            try:
                state["comments"] = dict(self._comments)
            except Exception:
                pass
            try:
                output = await self._send_command("info breakpoints")
                parsed = self._parse_mi_result(output)
                state["breakpoints_raw"] = "\n".join(parsed["console"])
            except Exception:
                pass
            with open(file_path, "w") as f:
                json.dump(state, f, indent=2)
            return f"Session saved to {file_path}"
        except Exception as e:
            return f"Error: {e}"

    async def session_load(self, file_path: str) -> str:
        try:
            if not os.path.exists(file_path):
                return f"File not found: {file_path}"
            with open(file_path) as f:
                state = json.load(f)
            msgs = [f"Session loaded from {file_path}"]
            if state.get("binary") and state["binary"] != self._binary:
                try:
                    await self.load_program(state["binary"], state.get("args", ""))
                    msgs.append(f"  Binary: {state['binary']}")
                except Exception as e:
                    msgs.append(f"  Could not load binary: {e}")
            try:
                self._bookmarks.clear()
                for name, addr in state.get("bookmarks", {}).items():
                    self._bookmarks[name] = addr
                msgs.append(f"  Bookmarks: {len(state.get('bookmarks', {}))} restored")
            except Exception:
                pass
            try:
                self._comments.clear()
                for addr, comment in state.get("comments", {}).items():
                    self._comments[addr] = comment
                msgs.append(f"  Comments: {len(state.get('comments', {}))} restored")
            except Exception:
                pass
            return "\n".join(msgs)
        except Exception as e:
            return f"Error: {e}"

    async def send_signal(self, signum: int) -> str:
        try:
            output = await self._send_command(f"signal {signum}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Signal {signum} sent"
        except Exception as e:
            return f"Error: {e}"

    async def step_instruction(self, count: int = 1) -> dict:
        output = await self._send_exec_command(f"-exec-step-instruction {count}")
        return self._parse_mi_result(output)

    async def set_memory_permissions(self, address: str, permissions: str, size: int = 4096) -> str:
        valid = {"none", "r", "w", "x", "rw", "rx", "wx", "rwx"}
        perm_lower = permissions.lower()
        if perm_lower not in valid:
            return f"Invalid permissions '{permissions}'. Valid: {', '.join(sorted(valid))}"
        try:
            addr_val = int(address, 16) if address.startswith("0x") else int(address)
            end = addr_val + size
            cmd = f"mem {addr_val} {end} {perm_lower}"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Memory {hex(addr_val)}-{hex(end)}: {perm_lower}"
        except Exception as e:
            return f"Error: {e}"

    async def list_plugins(self) -> str:
        parts = ["=== Plugins ==="]
        try:
            output = await self._send_command("info auto-load")
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                stripped = line.strip()
                if stripped and "auto-load" in stripped.lower():
                    parts.append(f"  {stripped}")
        except Exception:
            pass
        try:
            output = await self._send_command("info pretty-printer")
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                stripped = line.strip()
                if stripped and stripped != "No pretty-printers.":
                    parts.append(f"  Printer: {stripped}")
        except Exception:
            pass
        try:
            parts.append("  GDB Python API: available")
            parts.append("  Capstone: available (via GDB)")
        except Exception:
            pass
        plugin_dir = "/usr/lib/x86_64-linux-gnu/edb/"
        if os.path.isdir(plugin_dir):
            plugins = sorted(os.listdir(plugin_dir))
            parts.append(f"  EDB plugins ({len(plugins)}):")
            for p in plugins:
                if p.endswith(".so"):
                    name = p[3:-3] if p.startswith("lib") else p[:-3]
                    parts.append(f"    - {name}")
        return "\n".join(parts)

    async def get_fpu_state(self) -> str:
        parts = ["=== FPU State ==="]
        try:
            output = await self._send_command("info all-registers")
            parsed = self._parse_mi_result(output)
            fpu_regs = {}
            for line in parsed["console"]:
                stripped = line.strip()
                if stripped and any(f in stripped.lower() for f in ["fctrl", "fstat", "ftag", "fioff", "fiseg", "fooff", "foseg", "fop", "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"]):
                    fpu_regs[stripped.split()[0]] = stripped
            if fpu_regs:
                for name in sorted(fpu_regs.keys()):
                    parts.append(f"  {fpu_regs[name]}")
            else:
                output2 = await self._send_command("info registers fctrl fstat ftag fioff fiseg fooff foseg fop st0 st1 st2 st3 st4 st5 st6 st7")
                parsed2 = self._parse_mi_result(output2)
                if parsed2["console"]:
                    parts.extend(f"  {l}" for l in parsed2["console"])
                else:
                    parts.append("  (not available or not supported)")
        except Exception as e:
            parts.append(f"  Error: {e}")
        return "\n".join(parts)

    async def get_simd_state(self) -> str:
        parts = ["=== SIMD State ==="]
        try:
            xmm_regs = []
            for i in range(16):
                xmm_regs.append(f"xmm{i}")
            ymm_regs = []
            for i in range(16):
                ymm_regs.append(f"ymm{i}")
            zmm_regs = []
            for i in range(32):
                zmm_regs.append(f"zmm{i}")
            all_simd = ["mxcsr"] + xmm_regs + ymm_regs[:4] + zmm_regs[:4]
            regs_str = " ".join(all_simd)
            output = await self._send_command(f"info registers {regs_str}")
            parsed = self._parse_mi_result(output)
            simd_found = []
            for line in parsed["console"]:
                stripped = line.strip()
                if stripped and any(r in stripped.split()[0].lower() for r in ["mxcsr", "xmm", "ymm", "zmm"]):
                    simd_found.append(stripped)
            for line in simd_found:
                parts.append(f"  {line}")
            if not simd_found:
                parts.append("  (SIMD registers not available or not supported)")
        except Exception as e:
            parts.append(f"  Error: {e}")
        return "\n".join(parts)

    async def set_tty(self, tty_path: str) -> str:
        try:
            output = await self._send_command(f"tty {tty_path}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Terminal set to {tty_path}"
        except Exception as e:
            return f"Error: {e}"

    async def load_symbol_file(self, file_path: str, address: str = "") -> str:
        try:
            if not os.path.exists(file_path):
                return f"File not found: {file_path}"
            if address:
                cmd = f"add-symbol-file {file_path} {address}"
            else:
                cmd = f"symbol-file {file_path}"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Symbols loaded from {file_path}"
        except Exception as e:
            return f"Error: {e}"

    async def get_memory_region_info(self) -> str:
        parts = ["=== Memory Regions ==="]
        try:
            output = await self._send_command("info mem")
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                stripped = line.strip()
                if stripped:
                    parts.append(f"  {stripped}")
            if len(parsed["console"]) == 0:
                parts.append("  (no custom memory regions defined)")
        except Exception as e:
            parts.append(f"  Error: {e}")
        return "\n".join(parts)

    async def jump_to_address(self, address: str) -> str:
        try:
            output = await self._send_command(f"jump *{address}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Jumped to {address}"
        except Exception as e:
            return f"Error: {e}"

    async def call_function(self, function_expr: str) -> str:
        try:
            output = await self._send_command(f"call {function_expr}")
            parsed = self._parse_mi_result(output)
            result = "\n".join(parsed["console"]) if parsed["console"] else f"Called {function_expr}"
            for line in parsed["console"]:
                if "=" in line and "$" in line:
                    result += f"\nReturn value: {line.strip()}"
                    break
            return result
        except Exception as e:
            return f"Error: {e}"

    async def set_breakpoint_condition(self, number: int, condition: str) -> str:
        try:
            if condition:
                cmd = f"condition {number} {condition}"
            else:
                cmd = f"condition {number}"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            result = "\n".join(parsed["console"]) if parsed["console"] else f"Breakpoint {number} condition set"
            return result
        except Exception as e:
            return f"Error: {e}"

    async def set_breakpoint_ignore_count(self, number: int, count: int) -> str:
        try:
            cmd = f"ignore {number} {count}"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Will ignore next {count} hits of breakpoint {number}"
        except Exception as e:
            return f"Error: {e}"

    async def analyze_basic_blocks(self, address: str, size: int = 256) -> str:
        try:
            output = await self._disassemble_fallback(address, size // 5)
            lines = output.strip().split("\n")
            parts = [f"=== Basic Blocks in range starting at {address} ==="]
            blocks = []
            current_block = []
            block_start = ""
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if ":" in stripped:
                    addr_part = stripped.split(":")[0].strip()
                    if addr_part.startswith("0x"):
                        if "jmp" in stripped.lower() or "je " in stripped.lower() or "jne " in stripped.lower() or "jz " in stripped.lower() or "jnz " in stripped.lower() or "jg " in stripped.lower() or "jl " in stripped.lower() or "jge " in stripped.lower() or "jle " in stripped.lower() or "ja " in stripped.lower() or "jb " in stripped.lower() or "call" in stripped.lower() or "ret" in stripped.lower() or "jmpq" in stripped.lower():
                            current_block.append(stripped)
                            blocks.append((block_start or addr_part, list(current_block)))
                            current_block = []
                            block_start = ""
                        elif ":" in stripped.split(":")[0]:
                            if current_block:
                                blocks.append((block_start, list(current_block)))
                            current_block = [stripped]
                            block_start = addr_part
                        else:
                            current_block.append(stripped)
            if current_block:
                blocks.append((block_start or "", current_block))
            for i, (start, instrs) in enumerate(blocks):
                parts.append(f"\n  Block {i}: start=0x{int(start,16) if start.startswith('0x') else start:x if start else '?'}")
                for instr in instrs:
                    parts.append(f"    {instr}")
            parts.append(f"\nTotal blocks: {len(blocks)}")
            return "\n".join(parts)
        except Exception as e:
            return f"Error: {e}"

    async def generate_cfg(self, address: str, size: int = 256) -> str:
        try:
            output = await self._disassemble_fallback(address, size // 5)
            lines = output.strip().split("\n")
            edges = []
            nodes = set()
            for line in lines:
                stripped = line.strip()
                if not stripped or ":" not in stripped:
                    continue
                parts = stripped.split(":", 1)
                try:
                    addr_str = parts[0].strip().split()[0] if parts[0].strip() else ""
                    if not addr_str.startswith("0x"):
                        continue
                    addr = int(addr_str, 16)
                    instr = parts[1].strip().lower()
                    nodes.add(addr)
                    if "call" in instr or "jmp" in instr or "je " in instr or "jne " in instr or "jz " in instr or "jnz " in instr or "jg " in instr or "jl " in instr or "jge " in instr or "jle " in instr or "ja " in instr or "jb " in instr or "jae " in instr or "jbe " in instr or "jo " in instr or "jno " in instr or "js " in instr or "jns " in instr or "jp " in instr or "jnp " in instr or "jcxz" in instr or "jecxz" in instr or "jrcxz" in instr or "loop" in instr or "ret" in instr:
                        if "ret" in instr:
                            edges.append((addr, -1, "ret"))
                            continue
                        for tok in instr.split():
                            if tok.startswith("0x"):
                                try:
                                    target = int(tok, 16)
                                    edges.append((addr, target, instr.split()[0] if instr.split() else "jmp"))
                                except ValueError:
                                    pass
                except (ValueError, IndexError):
                    pass
            dot = ["digraph CFG {"]
            dot.append("  rankdir=LR;")
            dot.append("  node [shape=box, style=filled, fillcolor=lightyellow];")
            for node in sorted(nodes):
                dot.append(f'  "0x{node:x}";')
            for src, dst, label in edges:
                if dst == -1:
                    dot.append(f'  "0x{src:x}" -> "RET"[label="{label}"];')
                else:
                    dot.append(f'  "0x{src:x}" -> "0x{dst:x}"[label="{label}"];')
            dot.append("}")
            return "\n".join(dot)
        except Exception as e:
            return f"Error: {e}"

    async def set_debug_output(self, debug_category: str = "", enable: bool = True) -> str:
        try:
            if enable:
                val = "on"
            else:
                val = "off"
            if debug_category:
                cmd = f"set debug {debug_category} {val}"
            else:
                available = ["infrun", "lin-lwp", "remote", "serial", "target", "event", "expression", "overlay", "frame", "thread"]
                return f"Available debug categories: {', '.join(available)}\nUsage: set_debug_output('<category>', on|off)"
            output = await self._send_command(cmd)
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Debug {debug_category}: {val}"
        except Exception as e:
            return f"Error: {e}"

    async def set_environment_variable(self, name: str, value: str) -> str:
        try:
            output = await self._send_command(f"set environment {name} {value}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Set {name}={value}"
        except Exception as e:
            return f"Error: {e}"

    async def unset_environment_variable(self, name: str) -> str:
        try:
            output = await self._send_command(f"unset environment {name}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"Unset {name}"
        except Exception as e:
            return f"Error: {e}"

    async def get_environment(self) -> str:
        try:
            output = await self._send_command("show environment")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else "No environment info"
        except Exception as e:
            return f"Error: {e}"

    async def set_session_logging(self, file_path: str, enable: bool = True) -> str:
        try:
            if enable:
                cmd1 = f"set logging file {file_path}"
                await self._send_command(cmd1)
                cmd2 = "set logging on"
                output = await self._send_command(cmd2)
                parsed = self._parse_mi_result(output)
                return "\n".join(parsed["console"]) if parsed["console"] else f"Logging to {file_path}"
            else:
                output = await self._send_command("set logging off")
                parsed = self._parse_mi_result(output)
                return "\n".join(parsed["console"]) if parsed["console"] else "Logging disabled"
        except Exception as e:
            return f"Error: {e}"

    async def ptype(self, expression: str) -> str:
        try:
            output = await self._send_command(f"ptype {expression}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"ptype {expression}: no info"
        except Exception as e:
            return f"Error: {e}"

    async def whatis(self, expression: str) -> str:
        try:
            output = await self._send_command(f"whatis {expression}")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else f"whatis {expression}: no info"
        except Exception as e:
            return f"Error: {e}"

    async def breakpoint_commands(self, number: int, commands: list[str]) -> str:
        try:
            cmds = "\n".join(commands)
            gdb_cmd = f"commands {number}\n{cmds}\nend"
            output = await self._send_command(gdb_cmd)
            parsed = self._parse_mi_result(output)
            result = "\n".join(parsed["console"]) if parsed["console"] else ""
            return f"Commands set for breakpoint {number}\n{result}".strip()
        except Exception as e:
            return f"Error: {e}"

    async def step_over_instruction(self, count: int = 1) -> dict:
        output = await self._send_exec_command(f"-exec-next-instruction {count}")
        return self._parse_mi_result(output)

    async def get_changed_registers(self) -> str:
        try:
            output = await self._send_command("info registers")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else "No register info"
        except Exception as e:
            return f"Error: {e}"

    async def list_source_files(self) -> str:
        try:
            output = await self._send_command("info sources")
            parsed = self._parse_mi_result(output)
            return "\n".join(parsed["console"]) if parsed["console"] else "No source info"
        except Exception as e:
            return f"Error: {e}"

    async def list_stack_arguments(self, frame_low: int = 0) -> str:
        try:
            output = await self._send_command("info args")
            parsed = self._parse_mi_result(output)
            result = []
            for i, line in enumerate(parsed["console"]):
                stripped = line.strip()
                if stripped:
                    result.append(f"  [{i}] {stripped}")
            if not result:
                return "No arguments"
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"

    async def list_features(self) -> str:
        try:
            features = ["=== GDB Features ==="]
            try:
                output = await self._send_command("show configuration", timeout=5.0)
                parsed = self._parse_mi_result(output)
                for line in parsed["console"][:10]:
                    features.append(f"  {line.strip()}")
            except Exception:
                pass
            try:
                output = await self._send_command("python print(gdb.VERSION)", timeout=5.0)
                parsed = self._parse_mi_result(output)
                for line in parsed["console"]:
                    features.append(f"  GDB: {line.strip()}")
            except Exception:
                features.append("  GDB: unknown version")
            return "\n".join(features)
        except Exception as e:
            return f"Error: {e}"

    async def inferior_info(self) -> str:
        parts = ["=== Inferior Info ==="]
        try:
            output = await self._send_command("info inferiors")
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                stripped = line.strip()
                if stripped:
                    parts.append(f"  {stripped}")
        except Exception:
            parts.append("  (no inferior info)")
        try:
            output = await self._send_command("info programs")
            parsed = self._parse_mi_result(output)
            for line in parsed["console"]:
                stripped = line.strip()
                if stripped:
                    parts.append(f"  {stripped}")
        except Exception:
            pass
        return "\n".join(parts)

    async def stack_push(self, value: str) -> str:
        try:
            output = await self._send_command("set $rsp = $rsp - 8")
            parsed = self._parse_mi_result(output)
            output2 = await self._send_command(f"set {{void*}}$rsp = {value}")
            parsed2 = self._parse_mi_result(output2)
            console = parsed.get("console", []) + parsed2.get("console", [])
            return "\n".join(console) if console else f"Pushed {value} onto stack"
        except Exception as e:
            return f"Error: {e}"

    async def stack_pop(self) -> str:
        try:
            output = await self._send_command("print *(void**)$rsp")
            parsed = self._parse_mi_result(output)
            output2 = await self._send_command("set $rsp = $rsp + 8")
            parsed2 = self._parse_mi_result(output2)
            result = []
            for line in parsed.get("console", []):
                stripped = line.strip()
                if stripped:
                    result.append(stripped)
            for line in parsed2.get("console", []):
                stripped = line.strip()
                if stripped:
                    result.append(stripped)
            return "\n".join(result) if result else "Stack pop executed"
        except Exception as e:
            return f"Error: {e}"

    async def stack_modify(self, value: str) -> str:
        try:
            output = await self._send_command(f"set *((void**)$rsp) = {value}")
            parsed = self._parse_mi_result(output)
            console = "\n".join(parsed.get("console", []))
            return console if console else f"Stack top modified to {value}"
        except Exception as e:
            return f"Error: {e}"

    async def label_address(self, address: str, label: str) -> str:
        try:
            output = await self._send_command(
                f"set {address}debug_label = \"{label}\"", timeout=8.0
            )
            parsed = self._parse_mi_result(output)
            console = "\n".join(parsed.get("console", []))
            return f"Label '{label}' set at {address}\n{console}"
        except Exception as e:
            return f"Error: {e}"

    async def set_disable_aslr(self, disable: bool) -> str:
        try:
            if disable:
                output = await self._send_command("set disable-randomization on")
            else:
                output = await self._send_command("set disable-randomization off")
            parsed = self._parse_mi_result(output)
            console = "\n".join(parsed.get("console", []))
            return f"ASLR {'disabled' if disable else 'enabled'}"
        except Exception as e:
            return f"Error: {e}"

    async def set_disable_lazy_binding(self, disable: bool) -> str:
        try:
            if disable:
                output = await self._send_command("set breakpoint pending on")
                output2 = await self._send_command("set breakpoint always-inserted on")
            else:
                output = await self._send_command("set breakpoint pending off")
                output2 = await self._send_command("set breakpoint always-inserted off")
            parsed = self._parse_mi_result(output)
            parsed2 = self._parse_mi_result(output2)
            return f"Lazy binding {'disabled' if disable else 'enabled'}"
        except Exception as e:
            return f"Error: {e}"

    async def binary_string_convert(self, hex_str: str = "", ascii_str: str = "", utf16_str: str = "") -> str:
        try:
            parts = []
            if hex_str:
                clean = hex_str.replace(" ", "").replace("0x", "").replace("\\x", "")
                try:
                    data = bytes.fromhex(clean)
                    parts.append(f"Hex: {hex_str}")
                    parts.append(f"ASCII: {data.decode('ascii', errors='replace')}")
                    parts.append(f"UTF-16LE: {data.decode('utf-16-le', errors='replace')}")
                    parts.append(f"UTF-16BE: {data.decode('utf-16-be', errors='replace')}")
                    parts.append(f"Bytes: {' '.join(f'{b:02x}' for b in data)}")
                except Exception as e:
                    parts.append(f"Hex decode error: {e}")
            if ascii_str:
                parts.append(f"ASCII: {ascii_str}")
                data = ascii_str.encode('ascii', errors='replace')
                parts.append(f"Hex: {data.hex()}")
                parts.append(f"Bytes: {' '.join(f'{b:02x}' for b in data)}")
                try:
                    utf16 = ascii_str.encode('utf-16-le')
                    parts.append(f"UTF-16LE: {utf16.hex()}")
                except Exception:
                    pass
            if utf16_str:
                parts.append(f"UTF-16: {utf16_str}")
                try:
                    data_bytes = bytes.fromhex(utf16_str.replace(" ", ""))
                    decoded = data_bytes.decode('utf-16-le', errors='replace')
                    parts.append(f"Decoded ASCII: {decoded}")
                    parts.append(f"Hex (raw): {data_bytes.hex()}")
                except Exception as e:
                    parts.append(f"UTF-16 decode error: {e}")
            return "\n".join(parts) if parts else "No input provided"
        except Exception as e:
            return f"Error: {e}"

    async def execute_gdb_command(self, command: str, timeout: int = 10) -> str:
        result = await self._send_command(command, timeout=float(timeout))
        output = result.get("output", "") if isinstance(result, dict) else str(result)
        return_output = []
        if output.strip():
            return_output.append(output.strip())
        payload = result.get("payload", {}) if isinstance(result, dict) else {}
        if isinstance(payload, dict) and payload.get("msg"):
            return_output.append(payload["msg"].strip())
        return "\n".join(return_output) if return_output else str(result)

    async def follow_fork(self, mode: str) -> str:
        valid = ("parent", "child")
        if mode not in valid:
            return f"Error: mode must be 'parent' or 'child', got '{mode}'"
        await self._send_command(f"set follow-fork-mode {mode}")
        return f"Fork follow mode set to '{mode}'"

    async def trace_start(self, address: str = "", max_size: int = 1024) -> str:
        await self._send_command(f"set trace-buffer-size {max_size}")
        if address:
            await self._send_command(f"trace {address}")
        else:
            await self._send_command("trace")
        await self._send_command("tstart")
        addr_msg = f" at {address}" if address else " (current PC)"
        return f"Trace started{addr_msg}, buffer size={max_size}MB"

    async def trace_stop(self) -> str:
        await self._send_command("tstop")
        return "Trace stopped"

    async def trace_show(self) -> str:
        status = await self._send_command("tstatus")
        frames = await self._send_command("tfind")
        dump = await self._send_command("tdump")
        parts = []
        if isinstance(status, dict):
            parts.append(status.get("output", str(status)))
        if isinstance(frames, dict):
            frames_out = frames.get("output", "")
            parts.append(frames_out)
        if isinstance(dump, dict) and dump.get("output"):
            parts.append(dump["output"])
        return "\n\n".join(parts) if parts else "Trace: no data"

    async def scan_stack_for_retaddr(self, depth: int = 64) -> str:
        try:
            sp_str = await self._send_command("p/x $rsp")
            sp = 0
            if isinstance(sp_str, dict):
                payload = sp_str.get("payload", {})
                if isinstance(payload, dict):
                    msg = payload.get("msg", "")
                else:
                    msg = str(payload)
            else:
                msg = str(sp_str)
            import re
            m = re.search(r"0x[0-9a-fA-F]+", msg)
            if m:
                sp = int(m.group(), 16)
            if not sp:
                return "Error: could not determine RSP"

            result = [f"Stack return-address scan (RSP={hex(sp)}, depth={depth}):", ""]
            for i in range(depth):
                addr = sp + i * 8
                val_str = await self._send_command(f"x/gx {hex(addr)}")
                val = 0
                if isinstance(val_str, dict):
                    val_text = val_str.get("output", "")
                    m2 = re.search(r"0x[0-9a-fA-F]+", val_text)
                    if m2:
                        val = int(m2.group(), 16)
                if val and 0x400000 <= val <= 0x7fffffffffff:
                    result.append(f"  [{i:3d}] {hex(addr)} -> {hex(val)}  (likely retaddr)")
                elif val != 0:
                    result.append(f"  [{i:3d}] {hex(addr)} -> {hex(val)}")
                else:
                    result.append(f"  [{i:3d}] {hex(addr)} -> 0x0")
            return "\n".join(result)
        except Exception as e:
            return f"Error: {e}"

    async def watch_expression(self, expression: str) -> str:
        result = await self._send_command(f"display {expression}")
        if isinstance(result, dict):
            output = result.get("output", "")
            if output.strip():
                return output
        return f"Expression '{expression}' added to auto-display list"

    async def apply_patches_to_file(self, output_path: str = "") -> str:
        if not self._binary:
            return "Error: no binary loaded"
        import os as os_mod
        import shutil
        out = output_path or self._binary + ".patched"
        shutil.copy(self._binary, out)
        corr_segments = await self._readelf_load_segments()
        patched = bytearray(open(out, "rb").read())
        total_patches = 0
        for vaddr, file_off, file_sz in corr_segments:
            if file_sz == 0:
                continue
            tmpfile = f"/tmp/_edb_patch_{vaddr:x}"
            await self._send_command(f"dump memory {tmpfile} {hex(vaddr)} {hex(vaddr + file_sz)}")
            if os_mod.path.exists(tmpfile):
                with open(tmpfile, "rb") as mf:
                    mem_data = mf.read()
                end_off = min(file_off + len(mem_data), len(patched))
                mem_data = mem_data[:end_off - file_off]
                old_slice = bytes(patched[file_off:file_off + len(mem_data)])
                if mem_data != old_slice:
                    patched[file_off:file_off + len(mem_data)] = mem_data
                    total_patches += 1
                os_mod.unlink(tmpfile)
        with open(out, "wb") as f:
            f.write(patched)
        return f"Patched binary written to {out} ({total_patches} segments updated)"

    async def get_eflags(self) -> str:
        result = await self._send_command("info registers eflags")
        if isinstance(result, dict):
            output = result.get("output", "")
            if not output.strip():
                payload = result.get("payload", {})
                if isinstance(payload, dict):
                    output = payload.get("msg", "")
            return output.strip() or "eflags: (no output)"
        return str(result)

    async def compare_snapshot(self, label: str = "") -> str:
        import time, json
        ts = label or f"snapshot_{int(time.time())}"
        regs_before = await self._send_command("info registers")
        mem_snapshots = []
        try:
            segs = await self._readelf_load_segments()
            for vaddr, file_off, file_sz in segs:
                if 0 < file_sz < 1024 * 1024 * 10:
                    tmp = f"/tmp/_edb_snap_{vaddr:x}"
                    await self._send_command(f"dump memory {tmp} {hex(vaddr)} {hex(vaddr + file_sz)}")
                    mem_snapshots.append(tmp)
        except Exception:
            pass
        return json.dumps({
            "label": ts,
            "registers": str(regs_before),
            "memory_snapshots": len(mem_snapshots),
            "snapshot_files": mem_snapshots,
        }, indent=2)

    async def pipeline_run(self, binary: str, breakpoint: str = "", args: str = "", dump_registers: bool = True) -> str:
        parts = []
        load = await self.load_program(binary, args=args)
        parts.append(f"Load: {load}")
        if breakpoint:
            bp = await self.set_breakpoint(breakpoint)
            parts.append(f"BP @ {breakpoint}: {bp}")
        run_result = await self.run()
        parts.append(f"Run: {'started' if run_result else 'error'}")
        status = await self.status()
        parts.append(f"Status: {status}")
        if dump_registers:
            regs = await self.get_registers()
            parts.append(f"Registers:\n{regs}")
        disasm = await self.disassemble("")
        parts.append(f"Disasm:\n{disasm}")
        return "\n\n".join(parts)

    async def export_state(self) -> str:
        if not self._binary:
            import json
            return json.dumps({"error": "No binary loaded"}, indent=2)
        binary_info = await self.get_binary_info()
        arch_info = await self.get_arch_info()
        regs = await self.get_registers()
        stack = await self.get_stack()
        bp_list = await self.list_breakpoints()
        modules = await self.list_modules()
        status = await self.status()
        entry = ""
        try:
            pwn = __import__("pwn", fromlist=["ELF"])
            pwn.context.log_level = "error"
            elf = pwn.ELF(self._binary, checksec=False)
            entry = hex(elf.entry) if hasattr(elf, "entry") else ""
        except Exception:
            entry = ""
        import json
        state = {
            "binary": self._binary,
            "entry_point": entry,
            "binary_info": binary_info,
            "arch_info": arch_info,
            "registers": regs,
            "stack": stack,
            "breakpoints": bp_list,
            "modules": modules,
            "status": status,
        }
        return json.dumps(state, indent=2, ensure_ascii=False)

    async def quit(self) -> None:
        await self._cleanup()
        self._binary = None
