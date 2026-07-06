# EDB Debugger Bridge — x64dbg Plugin

Live debugger integration that connects **x64dbg** to **edb_debugger_mcp** (GDB MI backend) via an MCP stdio transport subprocess.

## Features

- **Breakpoint Control** — Toggle / Clear All breakpoints
- **Patching** — NOP at selection, Assemble at address
- **Step Control** — Step Into / Step Over / Run / Pause
- **Register Inspection** — View live CPU register values
- **Memory View** — Dump hex at current selection

## Requirements

- [x64dbg](https://x64dbg.com/)
- [x64dbgpy](https://github.com/x64dbg/x64dbgpy) — Python plugin system for x64dbg
- Python 3.8+
- edb_debugger_mcp (included)

## Installation

1. Locate x64dbg's `py-plugins` folder (typically `C:\Program Files\x64dbg\release\x32\py-plugins\` or alongside `x64dbg.exe`)
2. Copy the entire `x64dbg_mcp` directory into `py-plugins\`
3. Restart x64dbg

Expected layout:

```
x64dbg/
├── release/
│   ├── x32/
│   │   ├── x64dbg.exe
│   │   └── py-plugins/
│   │       └── x64dbg_mcp/
│   │           ├── __init__.py
│   │           ├── mcp_client.py
│   │           ├── x64dbg_bridge.py
│   │           └── README.md
│   └── x64/
│       └── py-plugins/
│           └── x64dbg_mcp/  (same copy)
```

## Usage

1. Open x64dbg and attach / launch a target
2. **Plugins → EDB Bridge → Start Bridge** — launches `edb_debugger_mcp.py` as a subprocess
3. Use the submenu entries to control the debugger

### Menu Structure

| Menu Entry | Description |
|-----------|-------------|
| EDB Bridge → Start Bridge | Launch the MCP subprocess and connect to GDB |
| EDB Bridge → Stop Bridge | Disconnect and clean up |
| EDB Bridge → Toggle Breakpoint | Set/remove breakpoint at current selection |
| EDB Bridge → Clear All Breakpoints | Remove all breakpoints |
| EDB Bridge → NOP at Address | Replace selected byte with 0x90 |
| EDB Bridge → Assemble at Address | Write assembled instruction at selection |
| EDB Bridge → Step Into | Step one instruction into |
| EDB Bridge → Step Over | Step one instruction over |
| EDB Bridge → Run / Continue | Start or continue execution |
| EDB Bridge → Pause | Interrupt the running process |
| EDB Bridge → Show Registers | Display register values in a dialog |
| EDB Bridge → Show Memory at Selection | Hex dump 64 bytes at selection |

## Architecture

```
x64dbg (x64dbgpy plugin)
    ↓ MCP stdio (JSON-RPC over subprocess)
edb_debugger_mcp (FastMCP server)
    ↓ MI2 protocol (pipe)
GDB (GNU Debugger)
    ↓ ptrace
Target Process
```

## Notes

- **Experimental, untested.** This plugin was authored with no functional test environment. x64dbgpy plugins run in-process inside x64dbg (Windows-only). The MCP client spawns a Python subprocess to talk to the GDB backend independently of x64dbg's own debugging engine.
- x64dbg and GDB run as **separate debuggers**. Breakpoints set via the bridge affect the GDB backend, not x64dbg's native breakpoints. This is intended for cross-referencing and scripting workflows.

## Troubleshooting

- **"MCP client not initialized"** — Run Start Bridge first
- **Plugin not loading** — Check x64dbg's log window for Python import errors; verify `x64dbgpy` is installed
- **Menu not visible** — Ensure `x64dbg_mcp` is in the correct `py-plugins` directory for your architecture (x32 vs x64)
