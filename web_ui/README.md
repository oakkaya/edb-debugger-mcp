# EDB Debugger MCP — Web UI

A browser-based debugging interface for the `edb-debugger-mcp` server.

Provides a dark-themed, sidebar-driven UI via FastAPI + htmx — no complex JavaScript frameworks required.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Make sure edb-debugger-mcp is installed
pip install edb-debugger-mcp

# Start the web UI
python server.py
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

## Usage

- **Sidebar**: tools grouped into categories (Program, Breakpoints, Run/Step, Registers/Memory, Analysis, Pwntools)
- **Click** a tool with no parameters to call it immediately
- **Click** a tool with a gear icon to open its parameter form in the center panel
- Results appear in the right panel with `$ command` prefix
- Auto-scrolls to latest output

## Requirements

- Python 3.10+
- `edb-debugger-mcp` (installed in the parent project)
- `fastapi`, `uvicorn`, `jinja2`, `httpx` (from requirements.txt)

## Project Structure

```
web_ui/
├── requirements.txt    # Python dependencies
├── server.py           # FastAPI application (lifespan-managed MCP subprocess)
├── templates/
│   └── index.html      # Single-page dark-theme UI with htmx
└── README.md           # This file
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main HTML page |
| `/api/tools` | GET | JSON list of all tools with schemas |
| `/api/tools/{name}` | GET | Single tool definition |
| `/api/call/{name}` | POST | Execute a tool (`{"args": {...}}`) |

## Notes

- Experimental — not hardened for production use
- The MCP server runs as a subprocess managed by the Web UI's lifecycle
- Debugger state persists across tool calls within the session
