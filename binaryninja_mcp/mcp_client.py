"""MCP stdio transport client — talks to edb_debugger_mcp via JSON-RPC over subprocess."""

import asyncio
import json
import os
import subprocess
import sys
from typing import Any, Optional


MCP_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class MCPClient:
    """Manages a subprocess running the edb_debugger_mcp server via MCP stdio transport."""

    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._capabilities: dict = {}

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
            "protocolVersion": "2025-03-26",
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
        resp = self._send_request("tools/call", {
            "name": name,
            "arguments": arguments or {},
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
        content = (msg + "\n").encode("utf-8")
        header = f"Content-Length: {len(content)}\r\n\r\n".encode()
        self._process.stdin.write(header + content)
        self._process.stdin.flush()

    def _read_line(self) -> Optional[str]:
        if not self._process or not self._process.stdout:
            raise ConnectionError("MCP server not running")
        headers = {}
        while True:
            line = self._process.stdout.readline()
            if not line:
                return None
            line = line.decode("utf-8", errors="replace").strip()
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", 0))
        if not length:
            return None
        raw = self._process.stdout.read(length)
        return raw.decode("utf-8", errors="replace")
