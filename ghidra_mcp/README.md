# EDB Debugger Bridge — Ghidra Plugin

Live debugger integration that connects **Ghidra** to **edb_debugger_mcp** (GDB MI backend) via the MCP stdio protocol.

## Features

- **Start / Stop Bridge** — Launch the MCP subprocess and connect to GDB
- **Breakpoints** — Toggle / Clear All (via `edb_set_breakpoint`, `edb_remove_breakpoint`)
- **Patching** — NOP at cursor, Assemble at address (via `edb_nop_range`, `edb_assemble`)
- **Step Control** — Step Into/Over/Out, Run/Continue, Pause (via `edb_step_*`, `edb_run`, `edb_pause`)
- **Inspection** — Show Registers, Show Memory at address (via `edb_get_registers`, `edb_read_memory`)

## Requirements

- [Ghidra](https://ghidra-sre.org/) ≥ 10.x
- [pyhidra](https://github.com/dod-cyber-crime-institute/pyhidra) — Python bridge for Ghidra
- [edb_debugger_mcp](https://github.com/oakkaya/edb-debugger-mcp) (included)
- GDB (GNU Debugger) on `$PATH`

## Installation

```bash
pip install pyhidra  # if not already installed
```

Then load the script in Ghidra:

1. Launch Ghidra and open a program
2. **File → Run Script**
3. In the script manager, select **Python** as the language
4. Navigate to `ghidra_mcp/ghidra_bridge.py` and click **Run**

The plugin will register all EDB actions under the **EDB** menu.

## Usage

1. Open a binary in Ghidra
2. **EDB → Start Bridge** — launches `edb_debugger_mcp` as a subprocess
3. Load the binary in GDB (via the MCP server or the GDB CLI)
4. Place the cursor on an address and use **EDB →** actions:
   - **Toggle Breakpoint** — set or remove a software breakpoint
   - **NOP at Address** — replace the instruction with `0x90`
   - **Assemble at Address...** — write an assembled instruction
   - **Show Memory at Address...** — read and display a memory region
5. Use **Step Into** (F11), **Step Over** (F10), **Step Out** (Shift+F11), **Run / Continue** (F5)
6. Use **Show Registers** to view CPU state in a dialog

## Actions

| Menu Entry | Key Binding | Description |
|-----------|-------------|-------------|
| EDB: Start Bridge | — | Connect to GDB via MCP subprocess |
| EDB: Stop Bridge | — | Disconnect and clean up |
| EDB: Toggle Breakpoint | — | Set/remove software breakpoint |
| EDB: Clear All Breakpoints | — | Remove all breakpoints |
| EDB: NOP at Address | — | Replace 1 byte with 0x90 |
| EDB: Assemble at Address... | — | Write assembled instruction |
| EDB: Step Into | F11 | Step one instruction into |
| EDB: Step Over | F10 | Step one instruction over |
| EDB: Step Out | Shift+F11 | Run until function return |
| EDB: Run / Continue | F5 | Start or continue execution |
| EDB: Pause | — | Interrupt the running process |
| EDB: Show Registers | — | Display CPU register values |
| EDB: Show Memory at Address... | — | Read and display memory |

## Architecture

```
Ghidra (pyhidra script)
    ↓ MCP stdio (JSON-RPC over subprocess)
edb_debugger_mcp (FastMCP server)
    ↓ MI2 protocol (pipe)
GDB (GNU Debugger)
    ↓ ptrace
Target Process
```

## Troubleshooting

- **"MCP server not running"** — Run **EDB → Start Bridge** first
- **"No address selected"** — Place the cursor on an instruction in the listing
- **pyhidra not found** — Install it with `pip install pyhidra`
- **Actions don't appear** — Ensure `ghidra_bridge.py` was run via the Script Manager

## Disclaimer

Experimental — untested. Use at your own risk.
