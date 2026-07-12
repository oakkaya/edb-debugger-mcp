# EDB Debugger MCP

[![CI](https://github.com/oakkaya/edb-debugger-mcp/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/oakkaya/edb-debugger-mcp/actions)
[![PyPI](https://img.shields.io/pypi/v/edb-debugger-mcp)](https://pypi.org/project/edb-debugger-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/edb-debugger-mcp)](https://pypi.org/project/edb-debugger-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GDB](https://img.shields.io/badge/GDB-14+-orange)](https://www.sourceware.org/gdb/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green)](https://modelcontextprotocol.io)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/oakkaya/edb-debugger-mcp/pkgs/container/edb-debugger-mcp)
[![Changelog](https://img.shields.io/badge/changelog-v1.3.0-blue)](CHANGELOG.md)

## About

[EDB (Evan's Debugger)](https://github.com/eteran/edb-debugger) is a feature-rich, open-source GUI debugger for Linux (x86/x86-64), known for its intuitive interface, powerful plugin system (22 plugins), and extensive debugging capabilities — breakpoints, memory analysis, ROP tool, heap analyzer, and more. However, EDB has always been limited to manual GUI interaction — until now.

**EDB Debugger MCP** bridges EDB's debugging engine with modern AI via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io). Every EDB feature is exposed as a tool callable by an AI assistant — Claude Desktop, Cursor, or any MCP host — effectively giving AI a debugger's intuition. The server exposes **26 composite debugging tools** (19 edb_ + 7 pwntools_) that replace 157 flat primitives using parameter-driven dispatch for minimal context overhead (~4× token savings vs flat tool catalogs).

Behind the scenes, it translates AI requests into [GDB MI commands](https://sourceware.org/gdb/current/onlinedocs/gdb/GDB_002fMI.html) via a high-performance async backend, then formats results back as structured data. Combined with [pwntools](https://github.com/Gallopsled/pwntools) integration (7 composite tools covering ELF analysis, ROP, shellcode, assembly, packing, tubes, and utilities), it becomes a complete AI-powered reverse engineering workstation.

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
| Total tools | **26** (19 edb_ composite + 7 pwntools_ composite) — replaces 207 flat tools |
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
- [Tool Reference](#tool-reference-26-tools)
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

- **CTF Exploit Development** — cyclic pattern → offset discovery → ROP gadgets → shellcode → assemble
- **Malware Analysis** — attach → breakpoint → memory dump → core dump
- **Bug Hunting** — ASLR disable → run → memory search → heap analysis
- **Vulnerability Research** — expression eval → stack inspection → instruction analysis → function call
- **Reverse Engineering** — disassemble → CFG → string search → symbol lookup

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
docker run -i ghcr.io/oakkaya/edb-debugger-mcp:latest

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

> **✅ Tested with IDA Pro 9.3** — IDAPython imports (ida_pro, idaapi, idc, idautils), all 13 actions register under Edit -> EDB Debugger, MCP subprocess bridge connects with 26 composite tools, step/run/breakpoint/patch actions work, headless mode works with `ida -c -A -S<script>` under xvfb.

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
├── edb_debugger_mcp/        # Package: FastMCP server (19 composite edb_ tools)
│   ├── __init__.py           # Entry point + main()
│   ├── _mcp.py               # FastMCP instance + GDB backend init
│   ├── composite_tools.py    # 26 composite tools (19 edb_ + 7 pwntools_)
│   ├── gdb_backend.py        # GDB MI backend (172 public methods, MI parser, session mgmt)
│   └── edb_models.py         # Pydantic models for tool parameters
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
| `ret2win` | Buffer overflow overwrites return address to call a hidden win function | `edb_exec`, `edb_breakpoint`, `edb_stack`, `edb_expression` |
| `format-string` | Format string vulnerability used to overwrite GOT entries | `edb_expression`, `edb_memory` |
| `crackme` | Static password analysis by examining the binary | `edb_disassemble`, `edb_symbol`, `edb_expression` |
| `rop-chain` | Return-Oriented Programming chain to bypass NX (ret2libc) | `edb_analysis`, `edb_register`, `pwntools_rop`, `edb_memory` |
| `shellcode-injection` | Shellcode injection and execution on an executable stack | `pwntools_shellcode`, `edb_memory`, `edb_breakpoint`, `edb_exec` |
| `off-by-one` | Single-byte heap overflow corrupts adjacent variable | `edb_breakpoint`, `edb_memory`, `edb_stack`, `edb_expression` |
| `heap-uaf` | Use-after-free corrupts a function pointer to gain control | `edb_analysis`, `edb_breakpoint`, `edb_memory` |
| `integer-overflow` | Integer overflow bypasses a bounds check leading to OOB write | `edb_expression`, `edb_breakpoint`, `edb_memory`, `edb_register` |
| `nx-bypass` | ROP chain calls mprotect then executes shellcode | `pwntools_rop`, `edb_analysis`, `pwntools_shellcode`, `edb_breakpoint` |
| `canary-leak` | Format string leaks stack canary, then BOF overwrites return address | `edb_stack`, `edb_expression`, `edb_breakpoint` |

Each challenge includes source code, a compiled binary, and a solve script. Run from the challenge directory:

```bash
cd examples/ret2win
python solve.py
```

## Tool Reference (26 tools)

<details>
<summary>Click to expand the full tool reference (19 edb_ + 7 pwntools_ composite tools)</summary>

<!-- Composite tool reference -->

### Execution & Process (1 tool)

| Tool | Description |
|------|-------------|
| `edb_exec` | Load/attach/run/continue/pause/kill/restart — all execution control via `action` param |

### Stepping (1 tool)

| Tool | Description |
|------|-------------|
| `edb_step` | Step into/over/out, step N instructions, reverse step/continue |

### Tracing (1 tool)

| Tool | Description |
|------|-------------|
| `edb_trace` | Start/stop/show execution trace recording |

### Breakpoints (1 tool)

| Tool | Description |
|------|-------------|
| `edb_breakpoint` | Set/remove/enable/disable/list/condition/ignore/export/import — all breakpoint ops |

### Registers (1 tool)

| Tool | Description |
|------|-------------|
| `edb_register` | Get/set/dump all registers, FPU state, SIMD state, EFLAGS |

### Memory (1 tool)

| Tool | Description |
|------|-------------|
| `edb_memory` | Read/write/search/fill/compare/map/dump — all memory operations |

### Disassembly (1 tool)

| Tool | Description |
|------|-------------|
| `edb_disassemble` | Disassemble at address/range, current instruction, assemble, analyze calls |

### Stack (1 tool)

| Tool | Description |
|------|-------------|
| `edb_stack` | Dump/backtrace/push/pop/modify/scan for return addresses |

### Symbols (1 tool)

| Tool | Description |
|------|-------------|
| `edb_symbol` | Lookup, function info, xrefs, strings, entry point, symbol generation |

### Expressions (1 tool)

| Tool | Description |
|------|-------------|
| `edb_expression` | Evaluate C expression, get/set variables, arguments, locals, watch |

### Debug Info (1 tool)

| Tool | Description |
|------|-------------|
| `edb_debug_info` | Source listing, ptype, whatis, frame info |

### Threads (1 tool)

| Tool | Description |
|------|-------------|
| `edb_thread` | List/switch threads, inferior info |

### Modules & Plugins (1 tool)

| Tool | Description |
|------|-------------|
| `edb_module` | List modules, arch info, plugins, features |

### Analysis (1 tool)

| Tool | Description |
|------|-------------|
| `edb_analysis` | Analyze region/heap, ROP gadgets, basic blocks, CFG, exploit generation |

### Annotations (1 tool)

| Tool | Description |
|------|-------------|
| `edb_annotation` | Comments, bookmarks, labels |

### Session (1 tool)

| Tool | Description |
|------|-------------|
| `edb_session` | Status/dump/export, save/load, remote connect, signals, core dump |

### Patching (1 tool)

| Tool | Description |
|------|-------------|
| `edb_patch` | NOP range, jump to address, file↔VA offset, binary diff, snapshot |

### Configuration (1 tool)

| Tool | Description |
|------|-------------|
| `edb_config` | ASLR, lazy binding, signal handling, catchpoints, TTY, debug output |

### Environment (1 tool)

| Tool | Description |
|------|-------------|
| `edb_environment` | Environment variables, session logging, raw GDB commands |

---

### pwntools Tools (7 composite)

| Tool | Description |
|------|-------------|
| `pwntools_elf` | ELF analysis: sections, symbols, strings, deps, GOT, PLT, segments, notes, diff, patch, search, make-elf, entropy |
| `pwntools_rop` | ROP gadgets: search, extended search, chain builder, sigreturn frame, fmtstr payload |
| `pwntools_shellcode` | Shellcode generation and encoding (alphanumeric/null-free/xor) |
| `pwntools_asm` | Assembly ↔ hex: disassemble and assemble instructions |
| `pwntools_pack` | Pack/unpack, enhex/unhex, flat, hexdump — all data encoding operations |
| `pwntools_util` | Utilities: cyclic, cyclic_find, rol, ror, bits, align, constgrep, context, log_level |
| `pwntools_tube` | Process/remote I/O: send, sendline, recv, recvline, recvuntil, close, list |

<!-- Total tools: 26 listed: 26 -->
</details>

## License

MIT License — see [LICENSE](LICENSE) for details.
