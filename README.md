# EDB Debugger MCP

[![CI](https://github.com/oakkaya/edb-debugger-mcp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/oakkaya/edb-debugger-mcp/actions)
[![PyPI](https://img.shields.io/pypi/v/edb-debugger-mcp)](https://pypi.org/project/edb-debugger-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/edb-debugger-mcp)](https://pypi.org/project/edb-debugger-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GDB](https://img.shields.io/badge/GDB-14+-orange)](https://www.sourceware.org/gdb/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green)](https://modelcontextprotocol.io)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/oakkaya/edb-debugger-mcp/pkgs/container/edb-debugger-mcp)
[![Changelog](https://img.shields.io/badge/changelog-v1.2.2-blue)](CHANGELOG.md)

## About

[EDB (Evan's Debugger)](https://github.com/eteran/edb-debugger) is a feature-rich, open-source GUI debugger for Linux (x86/x86-64), known for its intuitive interface, powerful plugin system (22 plugins), and extensive debugging capabilities — breakpoints, memory analysis, ROP tool, heap analyzer, and more. However, EDB has always been limited to manual GUI interaction — until now.

**EDB Debugger MCP** bridges EDB's debugging engine with modern AI via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). Every EDB feature is exposed as a tool callable by an AI assistant — Claude Desktop, Cursor, or any MCP host — effectively giving AI a debugger's intuition. The server exposes **207 debugging tools** (100 Pydantic models, 182 backend methods, ~9000 LOC).

Behind the scenes, it translates AI requests into [GDB MI commands](https://sourceware.org/gdb/current/onlinedocs/gdb/GDB_002fMI.html) via a high-performance async backend, then formats results back as structured data. Combined with [pwntools](https://github.com/Gallopsled/pwntools) integration (50 tools: ROP, shellcode, cyclic, ELF, pack, enhex, align, bitops, tubes), it becomes a complete AI-powered reverse engineering workstation.

<p align="center">
  <img alt="Workflow Demo" src="https://raw.githubusercontent.com/oakkaya/edb-debugger-mcp/main/docs/edb-workflow.gif" width="90%" loading="lazy"><br>
  <em>Complete RE workflow: load binary → disassemble → ROP search → set breakpoint → run → read registers → dump stack → backtrace → generate shellcode.</em>
</p>

<p align="center">
  <img alt="Split-Screen Demo" src="https://raw.githubusercontent.com/oakkaya/edb-debugger-mcp/main/docs/edb-splitscreen.gif" width="90%" loading="lazy"><br>
  <em>Tool call arguments and their structured results displayed side by side for clarity.</em>
</p>


| Stat | Value |
|------|-------|
| Total tools | **207** (157 edb_ + 50 pwntools_) |
| Test count | **452** (pytest, 4 Python versions) |
| EDB feature coverage | 22/22 plugins · 29/29 actions · 13/13 dialogs · 6/6 views |
| Code size | ~9000 LOC · 100 Pydantic models · 182 backend methods |

[EDB](https://github.com/eteran/edb-debugger) · [GDB](https://www.sourceware.org/gdb/) · [MCP](https://modelcontextprotocol.io) · [FastMCP](https://github.com/jlowin/fastmcp) · [pwntools](https://github.com/Gallopsled/pwntools) · [Binary Ninja](https://binary.ninja/)

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Use Cases](#use-cases)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Standalone](#standalone)
  - [Claude Desktop Integration](#claude-desktop-integration)
  - [Other MCP Hosts](#other-mcp-hosts)
- [Docker Usage](#docker-usage)
- [Architecture](#architecture)
- [pwntools Tools](#pwntools-tools)
- [EDB Plugin Mapping](#edb-plugin-mapping)
- [Binary Ninja Integration](#binary-ninja-integration)
- [Ghidra Integration](#ghidra-integration)
- [Web UI](#web-ui)
- [CTF Examples](#ctf-examples)
- [x64dbg Integration](#x64dbg-integration)
- [IDA Pro Integration](#ida-pro-integration)
- [VS Code Extension](#vs-code-extension)
- [Project Structure](#project-structure)
- [Tool Reference](#tool-reference-197-tools)
- [License](#license)

## Quick Start

```bash
pip install edb-debugger-mcp
edb-debugger-mcp &
```

Then add to Claude Desktop config and ask: *"Load /bin/ls, find ROP gadgets with pop eax, and generate execve shellcode"* — the AI handles the rest.

## Features

- **Program Control** — Load, run, pause, continue, restart, attach/detach, kill
- **Breakpoints** — Software/hardware breakpoints, watchpoints (read/write/access), conditional, ignore count, commands, catchpoints, export/import
- **Step Operations** — Step into/over/out, step instruction, step-over instruction, reverse step/continue
- **Register Management** — Read/write all CPU/FPU/SIMD registers, formatted dump, flag analysis, changed registers
- **Memory Operations** — Hex dump, write memory/bytes, fill pattern, search, compare regions, set permissions
- **Disassembly** — Full/range disassembly, current instruction, assembly patching, NOP fill
- **Stack Analysis** — Stack dump, push/pop/modify, frame info, backtrace, arguments, locals
- **Symbol Resolution** — Symbol lookup, modules, sections, entry point, symbol map, binary info
- **Thread Support** — List/switch threads, process info, thread info
- **Expression Evaluation** — C expression, variable get/set, string reading, type info (ptype/whatis)
- **Code Analysis** — Source listing, function info/bounds, references, ROP gadgets, basic blocks, CFG
- **Code Patching** — Assemble instruction, NOP range, fill zero, label address, comments/annotations
- **Session Management** — Save/load sessions, bookmark addresses, export/import breakpoints
- **Remote Debugging** — Connect to remote GDB server, generate core dumps
- **Environment** — Get/set/unset env vars, set working directory, TTY, signal handling
- **Configuration** — ASLR toggle, lazy binding toggle, debug output, session logging, signal ignore list
- **Utility** — Binary string convert (hex↔ascii↔utf-16), file↔VA offset convert, font config
- **Pwntools Integration** — Assembly/disassembly (Keystone/Capstone), ELF analysis, ROP gadget search, shellcode generation, cyclic pattern, format string payloads, pack/unpack

## Use Cases

- **CTF Exploit Development** — `pwntools_cyclic` → offset → `edb_find_rop_gadgets` → `pwntools_shellcraft` → `pwntools_asm`
- **Malware Analysis** — `edb_attach_process` → `edb_set_breakpoint` → `edb_read_memory` → `edb_generate_core_dump`
- **Bug Hunting** — `edb_disable_aslr` → `edb_run` → `edb_search_memory` → `edb_analyze_heap`
- **Vulnerability Research** — `edb_evaluate_expression` → `edb_get_stack` → `edb_instruction_detail` → `edb_call_function`
- **Reverse Engineering** — `edb_disassemble_range` → `edb_generate_cfg` → `edb_find_strings` → `edb_lookup_symbol`

## Requirements

- Python >= 3.10
- GDB (GNU Debugger) installed on the system
- Linux (x86-64 recommended)

## Installation

```bash
# Clone the repository
git clone https://github.com/oakkaya/edb-debugger-mcp.git
cd edb-debugger-mcp

# Install dependencies
pip install -r requirements.txt

# (Optional) Install with pip
pip install -e .
```

## Usage

### Standalone

```bash
python edb_debugger_mcp.py
```

This starts the MCP server on stdio, ready to accept MCP protocol messages.

### Testing

```bash
# Compile a test binary
gcc -g -o /tmp/test_bin /path/to/test.c

# Then run the server manually or use an MCP client
```

### Claude Desktop Integration

If installed via pip:

```json
{
  "mcpServers": {
    "edb-debugger-mcp": {
      "command": "edb-debugger-mcp"
    }
  }
}
```

If installed from source:

```json
{
  "mcpServers": {
    "edb-debugger-mcp": {
      "command": "python",
      "args": ["/path/to/edb_debugger_mcp/edb_debugger_mcp.py"]
    }
  }
}
```

Config file location:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Other MCP Hosts

The same server works with any MCP-compatible host. Example configurations:

**opencode** (`~/.config/opencode/config.json`):
```json
{
  "mcpServers": {
    "edb-debugger-mcp": {
      "command": "edb-debugger-mcp"
    }
  }
}
```

**Cursor** (Project Settings → MCP Servers):
```json
{
  "mcpServers": {
    "edb-debugger-mcp": {
      "command": "edb-debugger-mcp"
    }
  }
}
```

**Continue.dev** (`~/.continue/config.json`):
```json
{
  "experimental": {
    "mcpServers": {
      "edb-debugger-mcp": {
        "command": "edb-debugger-mcp"
      }
    }
  }
}
```

## Docker Usage

A pre-built Docker image is available on [GitHub Container Registry](https://github.com/oakkaya/edb-debugger-mcp/pkgs/container/edb-debugger-mcp).

```bash
# Pull the latest image
docker pull ghcr.io/oakkaya/edb-debugger-mcp:latest

# Run the MCP server (stdio mode, for MCP hosts)
docker run -i ghcr.io/oakkaya/edb-debugger-mcp

# Run with a specific version tag
docker run -i ghcr.io/oakkaya/edb-debugger-mcp:v1.2.2

# Run interactively with a shell for debugging
docker run --rm -it \
  --security-opt seccomp=unconfined \
  --cap-add=SYS_PTRACE \
  ghcr.io/oakkaya/edb-debugger-mcp /bin/bash
```

The image is built from `python:3.13-slim` with GDB pre-installed. It
is automatically rebuilt and published on every GitHub release (`v*` tag).

## Architecture

```
┌─────────────────────┐     MCP Protocol      ┌──────────────────────┐
│   MCP Client        │ ◄──────────────────►  │   FastMCP Server     │
│ (Claude, Cursor)    │     stdio JSON-RPC    │   edb_debugger_mcp.py│
└─────────────────────┘                       └──────────┬───────────┘
                                                          │
                                                      GDB MI
                                                   (--interpreter=mi2)
                                                          │
                                                 ┌────────┴───────────┐
                                                 │   GDB Backend      │
                                                 │   gdb_backend.py   │
                                                 │  (async subprocess)│
                                                 │  MI parser + 123   │
                                                 │  public methods    │
                                                 └────────────────────┘
```

The server uses GDB's MI (Machine Interface) protocol (`--interpreter=mi2`) to communicate with GDB as a subprocess. The backend:
- Sends MI/CLI commands via stdin, parses structured MI responses
- Handles `*stopped` async events for breakpoint hits
- Manages process lifecycle (start, kill, detach)
- Provides `readelf`-based file offset ↔ VA conversion

> **Note:** The EDB action/dialog/view counts listed in this README cover all of EDB's UI elements. Since this project is an MCP server, **UI-only features** (About dialog, font selector, Reset UI, window layout) cannot be mapped. All **functional debugging capabilities** (breakpoint, register, memory, stack, thread, expression, patching, analysis, ROP, session) are 100% covered.

## pwntools Tools

<details>
<summary>Click to expand the pwntools tool overview (50 tools)</summary>

The server integrates [pwntools](https://github.com/Gallopsled/pwntools) — the CTF/exploit development framework — as 50 MCP tools callable alongside the EDB debugger tools.

| Tool | Description |
|------|-------------|
| `pwntools_analyze_elf` | Full ELF binary analysis (headers, sections, symbols, security, strings) |
| `pwntools_asm` | Assemble assembly instructions to bytes (Keystone) |
| `pwntools_build_rop_chain` | Build a ROP chain with ordered gadgets |
| `pwntools_checksec` | Check ELF binary security properties (RELRO, Canary, NX, PIE) |
| `pwntools_constgrep` | Search pwntools/ELF constants by name or value |
| `pwntools_cyclic` | Generate De Bruijn cyclic pattern for offset discovery |
| `pwntools_cyclic_find` | Find offset of a value in cyclic pattern |
| `pwntools_disasm` | Disassemble raw bytes with pwntools (architecture-aware) |
| `pwntools_elf_deps` | Show shared library dependencies and interpreter |
| `pwntools_elf_patch` | Patch bytes in ELF binary at file offset (creates .bak) |
| `pwntools_elf_read` | Read bytes from ELF binary at section or address |
| `pwntools_elf_sections` | List all sections with type, flags, address, size |
| `pwntools_elf_search` | Search ELF binary for byte pattern grouped by section |
| `pwntools_elf_strings` | Extract printable strings from ELF (by section or all) |
| `pwntools_elf_symbols` | Search symbols by regex with address table |
| `pwntools_enc` | Encode shellcode (alphanumeric, null_free, xor) |
| `pwntools_entropy` | Shannon entropy analysis of file or region |
| `pwntools_erope` | Search ROP gadgets grouped by type (syscall, stack_pivot, call, jump) |
| `pwntools_find_rop` | Search for ROP gadgets by regex |
| `pwntools_flat` | Pack values/addresses into flat payload bytes |
| `pwntools_fmtstr_payload` | Generate format string write payload |
| `pwntools_hexdump` | Hex dump with ASCII side (colored, offset-labeled) |
| `pwntools_make_elf` | Compile assembly code into ELF binary |
| `pwntools_pack` | Pack integer to bytes (little/big endian, 8/16/32/64-bit) |
| `pwntools_shellcraft` | Generate shellcode for a given arch/OS (execve, bind/rev shell, etc.) |
| `pwntools_sigreturn` | Generate SROP (Sigreturn-Oriented Programming) frame |
| `pwntools_unpack` | Unpack bytes to integer |

Usage: ask the AI "Find ROP gadgets with pop rdi" or "Generate x64 execve shellcode" — no separate setup needed.
</details>

## EDB Plugin Mapping

<details>
<summary>Click to expand the EDB plugin coverage table (22 plugins)</summary>

| Plugin | MCP Coverage |
|--------|-------------|
| **DebuggerCore** | Execution, stepping, breakpoints, registers, memory, state |
| **BreakpointManager** | edb_set_breakpoint, edb_list_breakpoints, edb_export/import |
| **HardwareBreakpoints** | edb_set_hardware_breakpoint, edb_set_watchpoint |
| **InstructionInspector** | edb_instruction_detail |
| **Assembler** | edb_assemble (Keystone optional) |
| **BinaryInfo** | edb_get_binary_info |
| **BinarySearcher** | edb_search_memory |
| **Backtrace** | edb_get_backtrace |
| **FasLoader** | edb_load_symbol_file |
| **DumpState** | edb_dump_state |
| **FunctionFinder** | edb_list_functions |
| **OpcodeSearcher** | edb_search_instructions |
| **References** | edb_find_references, edb_string_references |
| **ROPTool** | edb_find_rop_gadgets |
| **HeapAnalyzer** | edb_analyze_heap |
| **Analyzer** | edb_analyze_region, edb_analyze_basic_blocks |
| **SymbolViewer** | edb_lookup_symbol |
| **ProcessProperties** | edb_get_process_properties |
| **ODbgRegisterView** | edb_get_registers, edb_get_fpu_state, edb_get_simd_state |
| **Bookmarks** | edb_add_bookmark, edb_list_bookmarks, edb_remove_bookmark |
| **CheckVersion** | Automatically handled |
| **DebuggerErrorConsole** | edb_set_debug_output |
</details>

## Binary Ninja Integration

> **⚠ Experimental / untested** — Binary Ninja is a commercial product (not available in this environment). The plugin code is structurally complete and follows the BN plugin API, but has not been verified at runtime. PRs welcome.

The `binaryninja_mcp/` directory contains a full Binary Ninja plugin that bridges the decompiler with the live debugger. Features:
- **Register overlay** — HLIL comments with live register values
- **Single-click breakpoints** — Right-click to toggle software/hardware breakpoints
- **In-place patching** — NOP, assemble, range-NOP from the disassembly context menu
- **Step control** — Step into/over/out, run, pause via Plugins menu
- **Sidebar widget** — Live register summary in the "EDB Debugger" tab

Install: `ln -s $(pwd)/binaryninja_mcp ~/.binaryninja/plugins/edb-debugger-bridge`

## Ghidra Integration

> **⚠ Experimental / untested** — Requires [pyhidra](https://github.com/Defense-Cyber-Crime-Center/pyhidra). Plugin is structurally complete but not verified at runtime. PRs welcome.

The `ghidra_mcp/` directory contains a Ghidra Python bridge that follows the same pattern as BN. Features:
- **Start/Stop Bridge** — Connect/disconnect from the MCP server
- **Toggle Breakpoint** — Set/clear breakpoints at the cursor address
- **In-place patching** — NOP, assemble instructions
- **Step/run control** — Step into/over, run, pause
- **Register & memory inspection** — Live register values, memory hex dump

Install: in Ghidra with pyhidra, run `ghidra_mcp/ghidra_bridge.py` via the Python interpreter, then use the newly registered actions from the right-click menu.

## Web UI

> **⚠ Experimental**

The `web_ui/` directory provides a browser-based debugger frontend (FastAPI + vanilla JS). No JS framework required.

```
cd web_ui
pip install -r requirements.txt
python server.py
# → http://localhost:8000
```

Features:
- **Categorized tool sidebar** — Program, Breakpoints, Run/Step, Registers/Memory, Analysis, Pwntools
- **Dynamic parameter forms** — Tools with arguments show input fields auto-generated from the tool schema
- **Dark theme** — Clean, readable interface
- **Live results** — Output streams into the result panel with auto-scroll

### REST API

<details>
<summary>Click to expand the Web UI REST API reference (18 endpoints)</summary>

The Web UI exposes a REST API used by the frontend. All endpoints return JSON unless noted.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serve the main HTML page (static) |
| `/api/quick` | GET | Quick action buttons metadata (name, tool, icon) |
| `/api/tools` | GET | All tools with category and input fields |
| `/api/tools/{name}` | GET | Single tool definition by name |
| `/api/call/{name}` | POST | Execute a tool with JSON `{"args": {...}}` |
| `/api/state` | GET | Debugger state snapshot (registers, stack, disasm, backtrace, status) |
| `/api/state/v2` | GET | Enhanced state with register diff highlighting |
| `/api/register/set` | POST | Set a register value `{"name": "eax", "value": "0x..."}` |
| `/api/memory/hex` | GET | Read memory as parsed hex dump `?address=0x400000&size=256` |
| `/api/disasm` | GET | Disassemble at address `?address=entry&count=32` |
| `/api/disasm/functions` | GET | List all functions in the binary |
| `/api/history` | GET | Tool call history (in-memory, ordered) |
| `/api/history/clear` | POST | Clear tool call history |
| `/api/sessions` | GET | List saved debugger sessions |
| `/api/sessions/save` | POST | Save session `{"name": "..."}` |
| `/api/sessions/load/{name}` | POST | Load a saved session |
| `/api/sessions/{name}` | DELETE | Delete a saved session |
| `/api/tabs/{name}` | GET | HTML fragment for a tab (history, sessions, state) |
</details>

## x64dbg Integration

> **⚠ Experimental / untested** — Windows-only. Requires [x64dbg](https://x64dbg.com/) with [x64dbgpy](https://github.com/x64dbg/x64dbgpy). No test environment available.

The `x64dbg_mcp/` directory contains an x64dbgpy plugin. Features:
- **Start/Stop Bridge** — Connect to the MCP server
- **Breakpoint control** — Toggle, clear all
- **Patching** — NOP, assemble at cursor
- **Step/run** — Step into/over, run, pause
- **Inspection** — Registers, memory at selection

Install: copy `x64dbg_mcp/` to x64dbg's `py-plugins/` directory. The "EDB Bridge" submenu appears under Plugins.

## Quick Start

```bash
# Install
pip install edb-debugger-mcp

# Start the MCP server (standalone)
edb-debugger-mcp

# Or with Web UI
pip install "edb-debugger-mcp[web]"
python3 -m web_ui.server
```

**3-step CTF solve with AI:**

```
User:  Load /challenge/bof and analyze it
AI:    → edb_load_program(path="/challenge/bof")
       → edb_disassemble("main")  → finds gets() call
       → edb_list_functions()     → finds win() at 0x4011b6

User:  Build exploit
AI:    → pwntools_cyclic(200)     → generates pattern
       → pwntools_cyclic_find("0x6161616c") → offset = 136
       → pwntools_flat([0xdeadbeef]*34 + [0x4011b6]) → payload

User:  Test it
AI:    → edb_run(args=$(python3 -c "print('A'*136 + '\xb6\x11\x40')"))
       → edb_set_breakpoint("win")
       → edb_continue() → breaks at win → flag printed!
```

## IDA Pro Integration

> **✅ Tested with IDA Pro 9.3** — IDAPython imports (ida_pro, idaapi, idc, idautils), all 13 actions register under Edit -> EDB Debugger, MCP subprocess bridge connects with 207 tools, step/run/breakpoint/patch actions work, headless mode works with `ida -c -A -S<script>` under xvfb.

The `ida_mcp/` directory contains an IDAPython plugin that connects IDA Pro to the MCP server. Features:
- **Start/Stop Bridge** — Launch and terminate the MCP subprocess
- **Toggle Breakpoint** (F2) — Set/remove software breakpoint at cursor
- **Clear All Breakpoints** — Remove all breakpoints
- **Patching** — NOP or assemble instruction at current address
- **Step/run control** — Step into (F11), step over (F10), step out (Shift+F11), run (F5), pause
- **Inspection** — Show register values, read memory at cursor

Install: copy `ida_mcp/` to IDA's plugin directory:

```bash
cp -r ida_mcp ~/.idapro/plugins/edb_debugger_bridge
```

After starting the bridge (Edit -> EDB Debugger -> Start Bridge), all actions are available from the **Edit -> EDB Debugger** menu.

## VS Code Extension

> **⚠ Experimental**

The `vscode-edb-mcp/` directory contains a VS Code extension that provides a debugger frontend inside VS Code. Features:
- **Start/Stop Bridge** — Spawn and kill the MCP subprocess
- **Debugger Panel** — WebView panel for debugging commands
- **Execution control** — Run/continue (F5), pause, step into (F11), step over (F10)
- **Breakpoint management** — Set/clear breakpoints
- **Register/Memory inspection** — View register state and memory
- **Status bar indicator** — Shows bridge connection state (connected/disconnected)

Build and install:

```bash
cd vscode-edb-mcp
npm install
npm run compile
code --install-extension edb-debugger-mcp-1.0.0.vsix
```

The extension registers commands under the `EDB:` prefix and shows a status bar item.

## Project Structure

```
edb-debugger-mcp/
├── edb_debugger_mcp/         # Package: FastMCP server (157 edb_ tools)
│   ├── __init__.py            # Entry point + main()
│   ├── _mcp.py                # FastMCP instance + GDB backend init
│   └── tools.py               # All 157 @mcp.tool function definitions
├── gdb_backend.py             # GDB MI backend (172 public methods, MI parser, session mgmt)
├── edb_models.py              # 93+ Pydantic models for tool parameters
├── pwntools_mcp.py            # Pwntools integration (50 pwntools_ tools: ROP, shellcode, ELF, asm, fmtstr, pack, tubes, enhex, elf_diff, bits, context)
├── web_ui/                    # Web debugger frontend (FastAPI + htmx, browser-based)
│   ├── server.py              # FastAPI app, tool categories, multi-page routing
│   └── templates/             # Static HTML + JavaScript frontend
├── binaryninja_mcp/           # Binary Ninja plugin (register overlay, right-click BP/patch, step)
├── ghidra_mcp/                # Ghidra bridge (pyhidra-based, same MCP client)
├── ida_mcp/                   # IDA Pro plugin (IDAPython bridge with breakpoint/patch/step)
├── x64dbg_mcp/                # x64dbgpy plugin (Windows debugger bridge)
├── vscode-edb-mcp/            # VS Code extension (debugger panel, commands, status bar)
├── scripts/                   # Utility scripts
│   └── generate_tool_table.py # Auto-generates markdown tool table
├── examples/                  # 10 CTF challenges
│   ├── ret2win/               #   Buffer overflow → call win function
│   ├── format-string/         #   Format string → GOT overwrite
│   ├── crackme/               #   Static password analysis
│   ├── rop-chain/             #   ROP chain ret2libc (NX enabled)
│   ├── shellcode-injection/   #   Shellcode on executable stack
│   ├── off-by-one/            #   Off-by-one overwrites adjacent variable
│   ├── heap-uaf/              #   Use-after-free → function pointer overwrite
│   ├── integer-overflow/      #   Signed check bypass → OOB write
│   ├── nx-bypass/             #   ROP mprotect + shellcode
│   └── canary-leak/           #   Format string leak + BOF with canary
├── tests/                     # 452 tests (pytest + pytest-asyncio)
├── CHANGELOG.md               # Version history
├── requirements.txt           # Python dependencies
├── README.md                  # This file
├── LICENSE                    # MIT License
└── .gitignore                 # Git ignore rules
```

## CTF Examples

The `examples/` directory contains 10 CTF-style challenges that showcase different exploitation techniques and the corresponding EDB MCP tools used to solve them.

| Challenge | Technique | Tools Demonstrated |
|-----------|-----------|-------------------|
| `ret2win` | Buffer overflow overwrites return address to call a hidden win function | `edb_load_program`, `edb_set_breakpoint`, `edb_get_stack`, `edb_evaluate_expression`, `edb_run` |
| `format-string` | Format string vulnerability used to overwrite GOT entries | `edb_evaluate_expression`, `edb_write_memory`, `edb_get_string`, `edb_find_strings` |
| `crackme` | Static password analysis by examining the binary | `edb_disassemble`, `edb_lookup_symbol`, `edb_get_string` |
| `rop-chain` | Return-Oriented Programming chain to bypass NX (ret2libc) | `edb_find_rop_gadgets`, `edb_get_registers`, `pwntools_build_rop_chain`, `edb_set_memory_permissions` |
| `shellcode-injection` | Shellcode injection and execution on an executable stack | `pwntools_shellcraft`, `edb_write_memory_bytes`, `edb_set_breakpoint`, `edb_run` |
| `off-by-one` | Single-byte heap overflow corrupts adjacent variable | `edb_set_breakpoint`, `edb_read_memory`, `edb_get_stack`, `edb_evaluate_expression` |
| `heap-uaf` | Use-after-free corrupts a function pointer to gain control | `edb_analyze_heap`, `edb_set_breakpoint`, `edb_read_memory`, `edb_write_memory` |
| `integer-overflow` | Integer overflow bypasses a bounds check leading to OOB write | `edb_evaluate_expression`, `edb_set_breakpoint`, `edb_read_memory`, `edb_set_register` |
| `nx-bypass` | ROP chain calls mprotect then executes shellcode | `pwntools_find_rop`, `edb_find_rop_gadgets`, `pwntools_shellcraft`, `edb_set_breakpoint` |
| `canary-leak` | Format string leaks stack canary, then BOF overwrites return address | `edb_get_stack`, `edb_find_strings`, `edb_evaluate_expression`, `edb_set_breakpoint` |

Each challenge includes source code, a compiled binary, and a solve script. Run from the challenge directory:

```bash
cd examples/ret2win
python solve.py
```

## Tool Reference (207 tools)

<details>
<summary>Click to expand the full tool reference (16 categories, 207 tools)</summary>

<!-- Auto-generated by scripts/generate_tool_table.py -->

### Program Control (12 tools)

| Tool | Description |
|------|-------------|
| `edb_load_program` | Load an executable binary for debugging. Resolves symbols and prepares for execu |
| `edb_run` | Start execution of the loaded program from the beginning. |
| `edb_continue` | Continue execution after a breakpoint or pause. |
| `edb_continue_to` | Continue execution until a specific address is reached. |
| `edb_pause` | Pause (interrupt) the running program. |
| `edb_restart` | Kill and restart the debugged program. Reloads the binary, preserves breakpoints |
| `edb_attach_process` | Attach the debugger to an already-running process by PID. |
| `edb_detach_process` | Detach from the debugged process. The process continues running independently. |
| `edb_kill_process` | Kill the debugged process immediately. |
| `edb_remote_connect` | Connect to a remote gdbserver for remote debugging. |
| `edb_send_signal` | Send a signal to the debugged process. |
| `edb_call_function` | Call a function in the context of the debugged process. |

### Step Operations (8 tools)

| Tool | Description |
|------|-------------|
| `edb_step_instruction` | Step a single instruction (assembly-level), not a source line. |
| `edb_step_into` | Execute one machine instruction, stepping into function calls. |
| `edb_step_over` | Execute one machine instruction, treating calls as atomic. |
| `edb_step_out` | Execute until the current function returns to its caller. |
| `edb_step_over_instruction` | Step over a single instruction (assembly-level), skipping calls. |
| `edb_reverse_step` | Step backward in the program execution (reverse debugging). |
| `edb_reverse_continue` | Continue execution backward to the previous breakpoint or event. |
| `edb_jump_to_address` | Jump to a specific address, setting the instruction pointer. |

### Breakpoints (18 tools)

| Tool | Description |
|------|-------------|
| `edb_set_breakpoint` | Set a breakpoint at a function, address, or source location. |
| `edb_set_hardware_breakpoint` | Set a hardware-assisted breakpoint using CPU debug registers. |
| `edb_set_watchpoint` | Set a watchpoint to monitor memory access. Three modes: |
| `edb_set_catchpoint` | Set a catchpoint for exceptions, syscalls, signals, or process events. |
| `edb_set_trace_point` | Set a trace point (logging breakpoint) that prints a message and continues |
| `edb_set_breakpoint_condition` | Set or remove a condition on an existing breakpoint. |
| `edb_set_breakpoint_ignore_count` | Set the number of times a breakpoint should be ignored before stopping. |
| `edb_breakpoint_commands` | Set commands to execute when a breakpoint is hit. |
| `edb_enable_breakpoint` | Re-activate a disabled breakpoint. |
| `edb_disable_breakpoint` | Disable a breakpoint without removing it. It can be re-enabled later. |
| `edb_remove_breakpoint` | Permanently remove a breakpoint or watchpoint by number. |
| `edb_list_breakpoints` | List all breakpoints, watchpoints, and their status (number, type, enable/disabl |
| `edb_breakpoint_export` | Export all breakpoints to a JSON file on disk. |
| `edb_breakpoint_import` | Import breakpoints from a JSON file previously exported with |
| `edb_trace_start` | Start an execution trace at an address/function. Records every instruction execu |
| `edb_trace_stop` | Stop the current execution trace session. |
| `edb_trace_show` | Show execution trace status, frames, and collected data. |
| `edb_list_breakpoint_types` | List supported breakpoint types (software, hardware, watchpoint, catchpoint). |

### Register Operations (10 tools)

| Tool | Description |
|------|-------------|
| `edb_get_registers` | Get all CPU register values as JSON. Includes general-purpose registers, |
| `edb_get_register` | Get the value of a specific CPU register. |
| `edb_set_register` | Modify a CPU register value. Useful for patching execution flow or testing condi |
| `edb_dump_registers` | Get a human-readable register dump in markdown table format. |
| `edb_get_changed_registers` | Get all register values (shows current state, EDB-style). |
| `edb_get_fpu_state` | Get the FPU (Floating Point Unit) register state. |
| `edb_get_simd_state` | Get the SIMD (SSE/AVX) register state. |
| `edb_get_arch_info` | Get architecture information about the debugged process and binary. |
| `edb_get_eflags` | Show the EFLAGS/RFLAGS CPU status register with individual flag states. |
| `edb_enum_registers` | List available CPU registers by category (GPR, SIMD, FPU, flag). |

### Memory Operations (12 tools)

| Tool | Description |
|------|-------------|
| `edb_read_memory` | Read and display memory contents at an address as a hex dump. |
| `edb_read_memory_as` | Read memory at an address interpreted as a specific data type. |
| `edb_write_memory` | Write a value to a memory address. Use for patching code or data. |
| `edb_write_memory_bytes` | Write raw hex bytes to memory starting at an address. |
| `edb_fill_memory` | Fill a memory region with a repeating byte value. |
| `edb_search_memory` | Search memory for a byte pattern. Finds all occurrences in the specified region. |
| `edb_compare_memory` | Compare two memory regions byte-by-byte and show differences. |
| `edb_compare_sections` | Compare loaded memory sections with the original binary on disk. |
| `edb_get_memory_map` | Get the process memory map (like /proc/pid/maps). |
| `edb_get_memory_region_info` | Get information about defined memory regions and their permissions. |
| `edb_set_memory_permissions` | Set memory permissions for a region (read/write/execute). |
| `edb_dump_memory_to_file` | Dump a memory region to a binary file on disk. |

### Disassembly (7 tools)

| Tool | Description |
|------|-------------|
| `edb_disassemble` | Disassemble machine code at an address or function. |
| `edb_disassemble_range` | Disassemble a range of memory from start to end address. |
| `edb_get_current_instruction` | Get the instruction at the current program counter (RIP/EIP). |
| `edb_instruction_detail` | Get detailed information about an instruction at a given address. |
| `edb_search_instructions` | Search memory for byte patterns (case-insensitive). |
| `edb_analyze_basic_blocks` | Analyze a code region and identify basic blocks. |
| `edb_analyze_calls_at` | Disassemble at an address and identify call/jump targets. |

### Stack & Frames (11 tools)

| Tool | Description |
|------|-------------|
| `edb_get_stack` | Dump the current stack (stack pointer to higher addresses). |
| `edb_get_backtrace` | Get the full call stack backtrace. Frame #0 is the current function. |
| `edb_get_frame_info` | Get detailed information about a stack frame: address, function, |
| `edb_get_locals` | Get all local variables in the current function scope. |
| `edb_get_arguments` | Get the arguments passed to the current function. |
| `edb_list_stack_arguments` | List arguments for stack frames. |
| `edb_stack_push` | Push a value onto the program stack (decrements RSP, writes value). |
| `edb_stack_pop` | Pop a value from the program stack (reads value, increments RSP). |
| `edb_stack_modify` | Modify the value at the top of the stack without changing RSP. |
| `edb_get_stack_frame` | Get detailed information about a specific stack frame level. |
| `edb_scan_stack_for_retaddr` | Scan the stack for potential return addresses (values in valid text ranges). Use |

### Symbol Analysis (11 tools)

| Tool | Description |
|------|-------------|
| `edb_lookup_symbol` | Look up a symbol's address and type. Supports functions and variables. |
| `edb_list_functions` | List all functions in the binary, optionally filtered by name. |
| `edb_get_function_info` | Get detailed info about a function: address, prototype, source location. |
| `edb_get_function_bounds` | Get the start address, end address, and size of a function. |
| `edb_list_modules` | List all shared libraries / modules loaded by the process. |
| `edb_get_section_info` | Get detailed section information for loaded modules. |
| `edb_get_entry_point` | Get the program entry point address. The entry point is the first code |
| `edb_find_references` | Find all code references to a given address or symbol. |
| `edb_find_strings` | Find printable ASCII strings in the current code region. |
| `edb_get_function_xrefs` | Show cross-references to a given address or function. |
| `edb_goto_function_start` | Find the function start address containing a given address. |

### Thread & Process (6 tools)

| Tool | Description |
|------|-------------|
| `edb_list_threads` | List all threads in the debugged process with IDs, names, and states. |
| `edb_get_current_thread` | Get info about the currently active thread. |
| `edb_set_current_thread` | Switch the debugger context to a different thread. |
| `edb_get_process_properties` | Get comprehensive properties of the debugged process. |
| `edb_inferior_info` | Get information about all inferiors (processes) being debugged. |
| `edb_follow_fork` | Set whether the debugger follows the parent or child process after a fork. |

### Expression & Data (8 tools)

| Tool | Description |
|------|-------------|
| `edb_evaluate_expression` | Evaluate a C expression in the debug context. |
| `edb_ptype` | Print the type of a variable, function, or expression. |
| `edb_whatis` | Print the type of an expression (short form). |
| `edb_get_variable` | Read the value of a local or global variable in the current scope. |
| `edb_set_variable` | Modify a variable's value in the current scope. |
| `edb_get_string` | Read a null-terminated string from a memory address. |
| `edb_string_references` | Find all code and data references to a string or address in the binary. |
| `edb_watch_expression` | Add an expression to the auto-display list. Evaluated and shown on every stop. |

### Code Analysis (8 tools)

| Tool | Description |
|------|-------------|
| `edb_analyze_region` | Analyze a code region for call instructions, branch instructions, |
| `edb_analyze_heap` | Analyze the heap memory region of the debugged process. |
| `edb_generate_cfg` | Generate a Control Flow Graph in Graphviz DOT format. |
| `edb_generate_symbols` | Generate a symbol map for a binary file using EDB's symbol generator. |
| `edb_list_source` | Display source code with line numbers. Current line is marked with '->'. |
| `edb_list_source_files` | List all source files used by the debugged program. |
| `edb_binary_string_convert` | Convert between hex, ASCII, and UTF-16 representations. |
| `edb_process_strings` | Scan process memory for readable ASCII strings. |

### Patching & Annotations (9 tools)

| Tool | Description |
|------|-------------|
| `edb_nop_range` | Replace a range of instructions with NOP (0x90) bytes. |
| `edb_assemble` | Assemble an assembly instruction and write it to memory. |
| `edb_add_bookmark` | Save a named bookmark pointing to an address for quick navigation. |
| `edb_list_bookmarks` | List all saved bookmarks with names and addresses. |
| `edb_remove_bookmark` | Remove a bookmark by name. |
| `edb_add_comment` | Add a text annotation to an address. Comments are stored in-memory |
| `edb_list_comments` | List all address annotations added via edb_add_comment. |
| `edb_remove_comment` | Remove an annotation previously added with edb_add_comment. |
| `edb_apply_patches_to_file` | Write runtime memory modifications back to the binary file on disk. |

### Session & Environment (12 tools)

| Tool | Description |
|------|-------------|
| `edb_session_save` | Save the complete debugging session to a JSON file. |
| `edb_session_load` | Load a debugging session from a JSON file. |
| `edb_set_environment_variable` | Set an environment variable for the debugged process. |
| `edb_get_environment` | Show all environment variables configured for the debugged process. |
| `edb_unset_environment_variable` | Remove an environment variable from the debugged process. |
| `edb_set_working_directory` | Set the working directory for the debugger and debugged process. |
| `edb_set_tty` | Set the terminal device for the debugged program's I/O. |
| `edb_set_debug_output` | Enable or disable GDB internal debug output. |
| `edb_set_session_logging` | Log all GDB input/output to a file for debugging or record-keeping. |
| `edb_signal_handling` | Configure how GDB handles signals (stop, print, pass to program). |
| `edb_list_signals` | List all signals and how GDB handles them. |
| `edb_get_stop_reason` | Determine why the process stopped (breakpoint, signal, step, etc.). |

### Debugger Control (23 tools)

| Tool | Description |
|------|-------------|
| `edb_configure_debugger` | Configure GDB debugger settings. Equivalent to EDB's Configure Debugger |
| `edb_show_configuration` | Display current debugger configuration settings. |
| `edb_disable_aslr` | Disable or enable ASLR for debugee. |
| `edb_disable_lazy_binding` | Disable or enable lazy binding for debugee. |
| `edb_get_status` | Get the current debugger and process status. |
| `edb_get_binary_info` | Get detailed information about the loaded binary file. |
| `edb_list_features` | List GDB debugger features and capabilities. |
| `edb_list_plugins` | List all available debugger plugins and capabilities. |
| `edb_load_symbol_file` | Load a symbol file for the debugged program. |
| `edb_view_at_address` | Navigate to and inspect an address across all views. |
| `edb_find_rop_gadgets` | Search for ROP gadgets (instructions ending with 'ret') in memory. |
| `edb_label_address` | Set a label/annotation at an address in the disassembly view. |
| `edb_dump_state` | Dump complete debugger state: all registers, current instruction, |
| `edb_generate_core_dump` | Generate a core dump of the current process for post-mortem analysis. |
| `edb_execute_gdb_command` | Execute any raw GDB command directly. Full access to GDB's CLI. Powerful for adv |
| `edb_compare_snapshot` | Save a full debugger snapshot (registers + memory) for later comparison. |
| `edb_pipeline` | Load a binary, set breakpoint, run, and dump state in one call. |
| `edb_export_state` | Export the complete debugger state as structured JSON. |
| `edb_binary_diff` | Compare the current loaded binary with its original on disk. |
| `edb_exploit_generate` | Generate a buffer-overflow exploit payload: offset + ROP chain + shellcode. |
| `edb_patch_history` | Show all memory patches made this session, or clear the history. |
| `edb_remote_arch` | Detect the architecture of a connected remote GDB target. |
| `edb_remote_info` | Show detailed information about the remote debugging target. |

### File Utils (2 tools)

| Tool | Description |
|------|-------------|
| `edb_va_to_file_offset` | Convert a virtual address in the loaded process to the corresponding |
| `edb_file_offset_to_va` | Convert a file offset from the binary on disk to the corresponding |

### pwntools (50 tools)

| Tool | Description |
|------|-------------|
| `pwntools_align` | Calculate aligned value (up/down) for a given alignment boundary. |
| `pwntools_analyze_elf` | Analyze an ELF binary using pwntools — entry point, PIE/NX/RELRO/Canary, section |
| `pwntools_asm` | Assemble assembly instructions into hex bytes using pwntools + keystone. |
| `pwntools_bits` | Get or set a specific bit in an integer. |
| `pwntools_build_rop_chain` | Build a ROP chain to call a target function with arguments using pwntools ROP. |
| `pwntools_checksec` | Check security properties of an ELF binary: RELRO, Canary, NX, PIE, RPATH/RUNPAT |
| `pwntools_constgrep` | Search pwntools/ELF constants by name or value. |
| `pwntools_context` | View or modify pwntools global context (arch, os, endian, log_level). |
| `pwntools_cyclic` | Generate a cyclic pattern for buffer overflow offset discovery. |
| `pwntools_cyclic_find` | Find the offset of a value within a cyclic pattern. |
| `pwntools_disasm` | Disassemble raw hex bytes into assembly instructions using pwntools + capstone. |
| `pwntools_elf_deps` | List shared library dependencies of an ELF binary (DT_NEEDED entries). |
| `pwntools_elf_diff` | Compare two ELF binaries: sections, segments, symbols. |
| `pwntools_elf_got` | Parse Global Offset Table (GOT) entries from an ELF binary. |
| `pwntools_elf_notes` | Show ELF notes: build ID, ABI tag, property notes. |
| `pwntools_elf_patch` | Patch bytes in an ELF binary at a given file offset. Creates a backup. |
| `pwntools_elf_plt` | Parse Procedure Linkage Table (PLT) entries from an ELF binary. |
| `pwntools_elf_read` | Read bytes from an ELF binary at a section or address, with hex dump output. |
| `pwntools_elf_relocs` | Show ELF relocation entries (GOT/PLT fixups and absolute relocations). |
| `pwntools_elf_search` | Search for a byte pattern in an ELF binary. |
| `pwntools_elf_sections` | List all ELF sections with detailed info: type, flags, address, offset, size, al |
| `pwntools_elf_segments` | List ELF program headers (segments): type, flags, offset, vaddr, filesz, memsz. |
| `pwntools_elf_strings` | Extract printable strings from an ELF binary, optionally filtered by section. |
| `pwntools_elf_symbols` | Search symbols in an ELF binary by regex pattern and type. |
| `pwntools_enc` | Encode shellcode using pwntools encoders (alphanumeric, null_free, xor). |
| `pwntools_enhex` | Encode raw bytes to hexadecimal string. Supports \x escapes. |
| `pwntools_entropy` | Calculate byte entropy (Shannon) of a file or memory region. Useful for detectin |
| `pwntools_erope` | Search ROP gadgets grouped by type: syscall, stack_pivot, call, jump. |
| `pwntools_find_rop` | Search for ROP gadgets in an ELF binary using pwntools ROP engine. |
| `pwntools_flat` | Pack a list of values/addresses into flat bytes using pwntools flat(). |
| `pwntools_fmtstr_payload` | Generate a format string exploit payload for arbitrary writes. |
| `pwntools_hexdump` | Display a formatted hex dump using pwntools hexdump styling. |
| `pwntools_log_level` | Set pwntools log verbosity. Levels: debug, info, warning, error. |
| `pwntools_make_elf` | Compile assembly code into an ELF binary using pwntools make_elf. |
| `pwntools_pack` | Pack an integer into bytes (e.g., p64, p32, p16). |
| `pwntools_process` | Start a local process for interaction (pwntools tube). |
| `pwntools_remote` | Connect to a remote TCP service (pwntools tube). |
| `pwntools_rol` | Rotate an integer value left by N bits. |
| `pwntools_ror` | Rotate an integer value right by N bits. |
| `pwntools_shellcraft` | Generate shellcode using pwntools shellcraft module. |
| `pwntools_sigreturn` | Generate a Sigreturn-Oriented Programming (SROP) frame using pwntools SigreturnF |
| `pwntools_tube_close` | Close an active tube connection. |
| `pwntools_tube_list` | List all active tube connections. |
| `pwntools_tube_recv` | Receive data from an active tube. |
| `pwntools_tube_recvline` | Receive a single line from an active tube. |
| `pwntools_tube_recvuntil` | Receive data from a tube until a pattern is found. |
| `pwntools_tube_send` | Send raw data to an active tube (process or remote). |
| `pwntools_tube_sendline` | Send a line (with newline) to an active tube. |
| `pwntools_unhex` | Decode hexadecimal string back to raw bytes. |
| `pwntools_unpack` | Unpack bytes into an integer (e.g., u64, u32, u16). |

<!-- Total tools: 207 listed: 207 -->
</details>

## License

MIT License — see [LICENSE](LICENSE) for details.
