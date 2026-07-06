# EDB Debugger Bridge — IDA Pro Plugin

Live debugger integration that connects **IDA Pro** to **edb_debugger_mcp** (GDB MI backend).

## Prerequisites

- **IDA Pro 7.x+** (with IDAPython)
- **edb_debugger_mcp** — included in the parent directory
- **GDB** (GNU Debugger) on `$PATH`
- Python 3.8+

## Installation

Copy the `ida_mcp/` directory into IDA's plugin search path:

```bash
# Linux
cp -r ida_mcp ~/.idapro/plugins/edb_debugger_bridge

# macOS
cp -r ida_mcp ~/.idapro/plugins/edb_debugger_bridge

# Windows
# Copy ida_mcp to %APPDATA%/Hex-Rays/IDA Pro/plugins/edb_debugger_bridge
```

Alternatively, set `IDAUSR` and copy there.

## Usage

1. Open a binary in IDA Pro
2. **Edit → EDB Debugger → Start Bridge** — launches `edb_debugger_mcp` as a subprocess
3. Load a target in GDB via the bridge CLI or use `edb_load_program`
4. Use **Edit → EDB Debugger** menu items to control execution, set breakpoints, patch, and inspect state

## Actions

| Menu Entry | Key Binding | Description |
|-----------|-------------|-------------|
| Start Bridge | — | Connect to GDB via MCP subprocess |
| Stop Bridge | — | Disconnect and clean up |
| Toggle Breakpoint | F2 | Set/remove software breakpoint at cursor |
| Clear All Breakpoints | — | Remove all breakpoints |
| NOP at Current Address | — | Replace 1 byte with 0x90 |
| Assemble at Current Address... | — | Write an assembled instruction |
| Step Into | F11 | Step one instruction into |
| Step Over | F10 | Step one instruction over |
| Step Out | Shift+F11 | Run until function return |
| Run / Continue | F5 | Start or continue execution |
| Pause | — | Interrupt the running process |
| Show Registers | — | Display register values in a dialog |
| Show Memory at Current Address... | — | Read and display memory at cursor |

## Architecture

```
IDA Pro (IDAPython plugin)
    ↓ MCP stdio (JSON-RPC over subprocess)
edb_debugger_mcp (FastMCP server)
    ↓ MI2 protocol (pipe)
GDB (GNU Debugger)
    ↓ ptrace
Target Process
```

## Notes

⚠ **Experimental / untested** — no IDA license available for testing.
Pull requests and bug reports welcome.

## Troubleshooting

- **"MCP server not running"** — Run **Edit → EDB Debugger → Start Bridge** first
- **"IDAPython not available"** — Ensure IDAPython is installed with your IDA copy
- **Actions greyed out** — The plugin loads automatically; if not, restart IDA or run `ida_mcp.py` via File → Script file
