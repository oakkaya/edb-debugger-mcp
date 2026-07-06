# EDB Debugger MCP — VS Code Extension

An AI-powered debugger frontend for the **edb-debugger-mcp** server. Provides 147 debugging tools via a GDB/MI backend, controllable from VS Code commands and a WebView panel.

## Prerequisites

- **Node.js** >= 18
- **Python** >= 3.10
- **edb-debugger-mcp** server: `pip install edb-debugger-mcp`

## Install

```bash
# From VSIX
code --install-extension edb-debugger-mcp-1.0.0.vsix

# Or build from source
cd vscode-edb-mcp
npm install
npm run compile
```

## Commands

| Command | Key | Action |
|---|---|---|
| `EDB: Start Bridge` | — | Spawn edb-debugger-mcp subprocess |
| `EDB: Stop Bridge` | — | Kill subprocess |
| `EDB: Show Debugger Panel` | — | Open WebView panel |
| `EDB: Load Binary` | — | Prompt for binary path → load |
| `EDB: Run / Continue` | `F5` | Run or continue execution |
| `EDB: Pause` | — | Pause execution |
| `EDB: Step Into` | `F11` | Step into instruction |
| `EDB: Step Over` | `F10` | Step over instruction |
| `EDB: Show Registers` | — | Print register state |

## Status Bar

A status bar item shows the bridge connection state (● Connected / ○ Disconnected).

## ⚠ Experimental

This extension is experimental. The MCP bridge runs a subprocess with full debugging
capabilities — use only with trusted binaries.
