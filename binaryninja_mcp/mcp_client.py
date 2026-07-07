"""MCP stdio transport client — talks to edb_debugger_mcp via JSON-RPC over subprocess."""

import json
import os
import select
import subprocess
from typing import Any, Optional


MCP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class MCPClient:
    """Manages a subprocess running the edb_debugger_mcp server via MCP stdio transport."""

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._capabilities: dict = {}
        self._timeout = 30.0

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self, python: str = "python3") -> str:
        if self.is_running:
            return "Already running"
        self._process = subprocess.Popen(
            [python, os.path.join(MCP_ROOT, "edb_debugger_mcp.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=MCP_ROOT,
        )
        resp = self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "binaryninja-edb-bridge", "version": "1.0.0"},
        })
        self._send_notification("notifications/initialized")
        self._capabilities = resp.get("capabilities", {})
        return f"Connected: {resp.get('serverInfo', {}).get('name', 'unknown')}"

    def stop(self):
        if self._process:
            self._send_notification("exit")
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

    def list_tools(self) -> list[dict]:
        resp = self._send_request("tools/list", {})
        return resp.get("tools", [])

    def call_tool(self, name: str, arguments: dict = None) -> Any:
        # FastMCP wraps single-param functions in a "params" field
        args = {"params": arguments or {}}
        resp = self._send_request("tools/call", {
            "name": name,
            "arguments": args,
        })
        content = resp.get("content", [])
        texts = [c["text"] for c in content if c.get("type") == "text"]
        is_error = resp.get("isError", False)
        return {"result": "\n".join(texts), "isError": is_error}

    def _send_request(self, method: str, params: dict) -> dict:
        self._request_id += 1
        msg = json.dumps({
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params,
        })
        return self._communicate(msg)

    def _send_notification(self, method: str):
        msg = json.dumps({
            "jsonrpc": "2.0",
            "method": method,
        })
        self._write(msg)

    def _communicate(self, msg: str) -> dict:
        self._write(msg)
        while True:
            line = self._read_line()
            if not line:
                raise ConnectionError("MCP server closed connection")
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in resp and resp.get("id") == self._request_id:
                if "error" in resp:
                    raise RuntimeError(resp["error"].get("message", str(resp["error"])))
                return resp.get("result", {})

    def _write(self, msg: str):
        if not self._process or not self._process.stdin:
            raise ConnectionError("MCP server not running")
        payload = (msg + "\n").encode("utf-8")
        self._process.stdin.write(payload)
        self._process.stdin.flush()

    def _read_line(self) -> Optional[str]:
        if not self._process or not self._process.stdout:
            raise ConnectionError("MCP server not running")
        r, _, _ = select.select([self._process.stdout], [], [], self._timeout)
        if not r:
            raise TimeoutError(f"MCP server did not respond within {self._timeout}s")
        line = self._process.stdout.readline()
        if not line:
            return None
        return line.decode("utf-8", errors="replace").strip()
