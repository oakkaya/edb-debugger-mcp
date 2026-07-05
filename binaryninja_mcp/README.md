# EDB Debugger Bridge — Binary Ninja Plugin

Live debugger integration that connects **Binary Ninja** to **edb_debugger_mcp** (GDB MI backend).

## Features

- **Register Overlay** — HLIL comments with live register values
- **PC Highlight** — Auto-scroll to the current instruction
- **Breakpoints** — Right-click → Toggle / Hardware Breakpoint
- **Patching** — Right-click → NOP 1 byte / NOP Range / Assemble
- **Step Control** — Plugin menu → Step Into/Over/Out, Run, Pause
- **Sidebar Widget** — "EDB Debugger" tab with register summary

## Requirements

- [Binary Ninja](https://binary.ninja/) ≥ 3.2 (personal/commercial)
- [edb_debugger_mcp](https://github.com/yourorg/edb-debugger-mcp) (included)
- GDB (GNU Debugger) on `$PATH`

## Installation

```bash
# Symlink the plugin into Binary Ninja's plugin directory
ln -s /path/to/edb-debugger-mcp/binaryninja_mcp ~/.binaryninja/plugins/edb-debugger-bridge
```

On Windows, copy or symlink `binaryninja_mcp` to `%APPDATA%/Binary Ninja/plugins/edb-debugger-bridge`.

## Usage

1. Open a binary in Binary Ninja
2. **Plugins → EDB: Start Bridge** — launches `edb_debugger_mcp` as a subprocess
3. Load a binary in the debugger via **Plugins → EDB: Load Program** or use the GDB CLI
4. Right-click in the disassembly to set breakpoints or patch
5. Open **View → Sidebar → EDB Debugger** for live register view
6. Use **Plugins → EDB: Toggle Register Overlay** for HLIL annotations

## Actions

| Menu Entry | Key Binding | Description |
|-----------|-------------|-------------|
| EDB: Start Bridge | — | Connect to GDB via MCP subprocess |
| EDB: Stop Bridge | — | Disconnect and clean up |
| EDB: Toggle Register Overlay | — | Show/hide live register HLIL comments |
| EDB: Refresh | — | Force refresh overlay and PC highlight |
| EDB: Step Into | F11 | Step one instruction into |
| EDB: Step Over | F10 | Step one instruction over |
| EDB: Step Out | Shift+F11 | Run until function return |
| EDB: Run / Continue | F5 | Start or continue execution |
| EDB: Pause | — | Interrupt the running process |
| EDB: Show Registers | — | Display register values in a dialog |

### Right-Click (Address)

| Action | Description |
|--------|-------------|
| EDB: Toggle Breakpoint | Set/remove software breakpoint |
| EDB: Toggle Hardware Breakpoint | Set hardware breakpoint |
| EDB: NOP 1 byte | Replace instruction with 0x90 |
| EDB: NOP Range... | NOP a range of addresses |
| EDB: Assemble at Address... | Write assembled instruction |

## Architecture

```
Binary Ninja (plugin)
    ↓ MCP stdio (JSON-RPC over subprocess)
edb_debugger_mcp (FastMCP server)
    ↓ MI2 protocol (pipe)
GDB (GNU Debugger)
    ↓ ptrace
Target Process
```

## Troubleshooting

- **"MCP server not running"** — Run `Plugins → EDB: Start Bridge` first
- **"GDB not started"** — The bridge starts GDB automatically when needed
- **Register overlay is empty** — Ensure the target process is loaded and stopped at a breakpoint
- **Sidebar not visible** — `View → Sidebar → EDB Debugger` from the menu
