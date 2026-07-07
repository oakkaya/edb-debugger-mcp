import sys
import os
import asyncio
import json
import datetime
import html
from pathlib import Path
from contextlib import asynccontextmanager
from collections import OrderedDict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "binaryninja_mcp"))
from mcp_client import MCPClient

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import uvicorn

client = MCPClient()
history: list = []
SESSIONS_DIR = Path("/tmp/edb-sessions")
TEMPLATES_DIR = Path(__file__).parent / "templates"

CATEGORIES = OrderedDict([
    ("Program", {
        "match": lambda n: n in {
            "edb_load_program", "edb_attach_process", "edb_detach_process",
            "edb_kill_process", "edb_get_binary_info", "edb_get_arch_info",
            "edb_get_entry_point", "edb_list_modules", "edb_list_functions",
            "edb_restart", "edb_get_process_properties", "edb_generate_symbols",
            "edb_get_status", "edb_remote_connect", "edb_load_symbol_file",
            "edb_set_working_directory", "edb_set_tty",
        }
    }),
    ("Breakpoints", {
        "match": lambda n: n in {
            "edb_set_breakpoint", "edb_set_hardware_breakpoint",
            "edb_set_watchpoint", "edb_remove_breakpoint", "edb_enable_breakpoint",
            "edb_disable_breakpoint", "edb_list_breakpoints", "edb_set_trace_point",
            "edb_set_catchpoint", "edb_breakpoint_export", "edb_breakpoint_import",
            "edb_set_breakpoint_condition", "edb_set_breakpoint_ignore_count",
            "edb_breakpoint_commands",
        }
    }),
    ("Run/Step", {
        "match": lambda n: n in {
            "edb_run", "edb_continue", "edb_pause",
            "edb_step_into", "edb_step_over", "edb_step_out",
            "edb_continue_to", "edb_step_instruction",
            "edb_reverse_step", "edb_reverse_continue",
            "edb_jump_to_address",
        }
    }),
    ("Registers/Memory", {
        "match": lambda n: n in {
            "edb_get_registers", "edb_get_register",
            "edb_set_register", "edb_dump_registers", "edb_get_fpu_state",
            "edb_get_simd_state", "edb_read_memory", "edb_read_memory_as",
            "edb_write_memory", "edb_write_memory_bytes", "edb_search_memory",
            "edb_search_instructions", "edb_fill_memory", "edb_compare_memory",
            "edb_get_memory_map", "edb_get_section_info", "edb_get_stack",
            "edb_get_stack_frame", "edb_get_backtrace", "edb_get_string",
            "edb_find_strings", "edb_set_memory_permissions", "edb_dump_memory_to_file",
        }
    }),
    ("Analysis", {
        "match": lambda n: n in {
            "edb_disassemble", "edb_disassemble_range",
            "edb_get_current_instruction", "edb_instruction_detail",
            "edb_lookup_symbol", "edb_evaluate_expression", "edb_analyze_calls_at",
            "edb_analyze_region", "edb_analyze_heap", "edb_find_rop_gadgets",
            "edb_find_references", "edb_string_references", "edb_get_function_info",
            "edb_get_function_bounds", "edb_get_variable", "edb_set_variable",
            "edb_get_arguments", "edb_get_locals", "edb_list_source",
            "edb_add_comment", "edb_list_comments", "edb_remove_comment",
            "edb_add_bookmark", "edb_list_bookmarks", "edb_remove_bookmark",
            "edb_nop_range", "edb_assemble", "edb_view_at_address",
            "edb_file_offset_to_va", "edb_va_to_file_offset", "edb_dump_state",
            "edb_compare_sections", "edb_get_stop_reason", "edb_get_frame_info",
            "edb_generate_core_dump", "edb_send_signal", "edb_configure_debugger",
            "edb_show_configuration", "edb_list_signals",
            "edb_session_save", "edb_session_load", "edb_list_plugins",
        }
    }),
    ("Pwntools", {
        "match": lambda n: n.startswith("pwntools_"),
    }),
])

QUICK_ACTIONS = [
    {"name": "Registers", "tool": "edb_get_registers", "icon": "cpu"},
    {"name": "Stack", "tool": "edb_get_stack", "icon": "stack"},
    {"name": "Disasm PC", "tool": "edb_get_current_instruction", "icon": "code"},
    {"name": "Memory Map", "tool": "edb_get_memory_map", "icon": "map"},
    {"name": "Backtrace", "tool": "edb_get_backtrace", "icon": "list"},
    {"name": "Breakpoints", "tool": "edb_list_breakpoints", "icon": "stop"},
    {"name": "Status", "tool": "edb_get_status", "icon": "info"},
    {"name": "Restart", "tool": "edb_restart", "icon": "refresh"},
]


@asynccontextmanager
async def lifespan(app):
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, client.start)
        print(f"  [web_ui] {result}")
    except Exception as e:
        print(f"  [web_ui] Failed to start: {e}")
    yield
    client.stop()


app = FastAPI(title="EDB Debugger MCP — Web UI", lifespan=lifespan)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def categorize_tools(tools: list) -> OrderedDict:
    result = OrderedDict()
    for cat_name, cfg in CATEGORIES.items():
        matched = [t for t in tools if cfg["match"](t.get("name", ""))]
        if matched:
            result[cat_name] = matched
    remaining = [t for t in tools if not any(
        cfg["match"](t.get("name", "")) for cfg in CATEGORIES.values()
    )]
    if remaining:
        result["Other"] = remaining
    return result


def get_input_fields(tool_def: dict) -> list:
    schema = tool_def.get("inputSchema", {})
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    fields = []
    for name, prop in props.items():
        field = {
            "name": name,
            "type": prop.get("type", "string"),
            "description": prop.get("description", ""),
            "required": name in required,
            "default": prop.get("default", ""),
        }
        enum_vals = prop.get("enum")
        if enum_vals:
            field["enum"] = enum_vals
        pattern = prop.get("pattern")
        if pattern:
            field["pattern"] = pattern
        fields.append(field)
    return fields


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    tools = client.list_tools()
    categorized = categorize_tools(tools)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "categorized_tools": categorized,
            "quick_actions": QUICK_ACTIONS,
        },
    )


@app.get("/api/quick")
async def quick_actions():
    return {"actions": QUICK_ACTIONS}


@app.get("/api/tools")
async def list_tools():
    tools = client.list_tools()
    categorized = categorize_tools(tools)
    flat = []
    for cat, tool_list in categorized.items():
        for t in tool_list:
            entry = dict(t)
            entry["category"] = cat
            entry["input_fields"] = get_input_fields(t)
            flat.append(entry)
    return {"tools": flat, "categories": list(categorized.keys())}


@app.get("/api/tools/{tool_name}")
async def get_tool(tool_name: str):
    tools = client.list_tools()
    for t in tools:
        if t.get("name") == tool_name:
            return {**t, "input_fields": get_input_fields(t)}
    return JSONResponse({"error": f"Tool '{tool_name}' not found"}, status_code=404)


@app.post("/api/call/{tool_name}")
async def call_tool(tool_name: str, request: Request):
    body = await request.json()
    args = body.get("args", {})
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, client.call_tool, tool_name, args)
        history.append({
            "tool_name": tool_name,
            "args": dict(args),
            "result": str(result.get("result", result)),
            "is_error": result.get("isError", False),
            "timestamp": datetime.datetime.now().isoformat()
        })
        return result
    except Exception as e:
        err = {"result": f"Error: {e}", "isError": True}
        history.append({
            "tool_name": tool_name,
            "args": dict(args),
            "result": err["result"],
            "is_error": True,
            "timestamp": datetime.datetime.now().isoformat()
        })
        return err


@app.get("/api/state")
async def get_state():
    try:
        loop = asyncio.get_event_loop()
        regs = await loop.run_in_executor(None, client.call_tool, "edb_get_registers", {})
        stack = await loop.run_in_executor(None, client.call_tool, "edb_get_stack", {})
        disasm = await loop.run_in_executor(None, client.call_tool, "edb_get_current_instruction", {})
        bt = await loop.run_in_executor(None, client.call_tool, "edb_get_backtrace", {})
        status = await loop.run_in_executor(None, client.call_tool, "edb_get_status", {})
        return {
            "registers": regs,
            "stack": stack,
            "disasm": disasm,
            "backtrace": bt,
            "status": status,
            "error": False,
        }
    except Exception as e:
        return {"error": True, "message": str(e)}


@app.get("/api/history")
async def get_history():
    return history


@app.post("/api/history/clear")
async def clear_history():
    history.clear()
    return {"ok": True}


@app.get("/api/sessions")
async def list_sessions():
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(SESSIONS_DIR.glob("*.json"))
    sessions = []
    for f in files:
        mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        sessions.append({"name": f.stem, "mtime": mtime})
    return {"sessions": sessions}


@app.post("/api/sessions/save")
async def save_session(request: Request):
    body = await request.json()
    name = body.get("name", "unnamed")
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, client.call_tool, "edb_session_save", {"name": name})
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        marker = SESSIONS_DIR / f"{name}.json"
        marker.write_text(json.dumps({
            "name": name,
            "saved_at": datetime.datetime.now().isoformat(),
            "result": str(result)
        }))
        return result
    except Exception as e:
        return {"result": f"Error: {e}", "isError": True}


@app.post("/api/sessions/load/{name}")
async def load_session(name: str):
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, client.call_tool, "edb_session_load", {"name": name})
        return result
    except Exception as e:
        return {"result": f"Error: {e}", "isError": True}


@app.delete("/api/sessions/{name}")
async def delete_session(name: str):
    session_file = SESSIONS_DIR / f"{name}.json"
    if session_file.exists():
        session_file.unlink()
        return {"ok": True}
    return JSONResponse({"error": "Session not found"}, status_code=404)


@app.get("/api/tabs/{tab_name}")
async def get_tab(tab_name: str):
    if tab_name == "history":
        return HTMLResponse(_render_history_tab())
    elif tab_name == "sessions":
        return HTMLResponse(await _render_sessions_tab())
    elif tab_name == "state":
        return HTMLResponse(await _render_state_tab())
    return HTMLResponse("")


def _render_history_tab() -> str:
    parts = ['<div class="tab-padded">']
    parts.append('<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">')
    parts.append('<h2 style="font-size:16px;font-weight:600">Call History</h2>')
    if history:
        parts.append('<button onclick="clearHistory()" style="padding:4px 12px;background:none;border:1px solid var(--error);border-radius:4px;color:var(--error);font-size:11px;cursor:pointer">Clear All</button>')
    parts.append('</div>')
    if not history:
        parts.append('<p style="color:var(--text-dim)">No tool calls recorded yet.</p>')
    else:
        parts.append('<div class="history-list">')
        for entry in reversed(history):
            cls = "history-entry error" if entry.get("is_error") else "history-entry"
            result_preview = str(entry.get("result", ""))
            if len(result_preview) > 200:
                result_preview = result_preview[:200] + "..."
            parts.append(f'''<div class="{cls}">
                <div class="history-header" onclick="this.nextElementSibling.classList.toggle('collapsed')">
                    <span class="history-tool">{html.escape(entry.get("tool_name", ""))}</span>
                    <span class="history-time">{html.escape(entry.get("timestamp", ""))}</span>
                    <span class="history-arrow">&#9660;</span>
                </div>
                <div class="history-body collapsed">
                    <pre>{html.escape(str(entry.get("result", "")))}</pre>
                    <button onclick="reRunTool(\'{html.escape(entry.get("tool_name", ""))}\')" class="rerun-btn">Re-run</button>
                </div>
            </div>''')
        parts.append('</div>')
    parts.append('</div>')
    return "\n".join(parts)


async def _render_sessions_tab() -> str:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(SESSIONS_DIR.glob("*.json"))
    parts = ['<div class="tab-padded">']
    parts.append('<h2 style="font-size:16px;font-weight:600;margin-bottom:12px">Saved Sessions</h2>')
    parts.append('''<div class="session-save-row">
        <input id="session-name" type="text" placeholder="Session name..." class="session-input">
        <button onclick="saveSession()" class="btn-primary">Save Current</button>
    </div>''')
    if not files:
        parts.append('<p style="color:var(--text-dim)">No saved sessions. Use the input above to save one.</p>')
    else:
        parts.append('<div class="session-list">')
        for f in files:
            mtime = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            safe_name = html.escape(f.stem)
            parts.append(f'''<div class="session-entry">
                <div class="session-info">
                    <span class="session-name">{safe_name}</span>
                    <span class="session-time">{mtime}</span>
                </div>
                <div class="session-actions">
                    <button onclick="loadSession('{safe_name}')" class="btn-small btn-accent">Load</button>
                    <button onclick="deleteSession('{safe_name}')" class="btn-small btn-danger">Delete</button>
                </div>
            </div>''')
        parts.append('</div>')
    parts.append('</div>')
    return "\n".join(parts)


async def _render_state_tab() -> str:
    try:
        loop = asyncio.get_event_loop()
        regs = await loop.run_in_executor(None, client.call_tool, "edb_get_registers", {})
        stack = await loop.run_in_executor(None, client.call_tool, "edb_get_stack", {})
        disasm = await loop.run_in_executor(None, client.call_tool, "edb_get_current_instruction", {})
        bt = await loop.run_in_executor(None, client.call_tool, "edb_get_backtrace", {})
    except Exception as e:
        return f'<div class="tab-padded"><p class="error">Error: {html.escape(str(e))}</p></div>'

    return f'''<div class="tab-padded">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <h2 style="font-size:16px;font-weight:600">Debugger State</h2>
            <button onclick="refreshStateTab()" class="btn-small btn-accent">⟳ Refresh</button>
        </div>
        <div class="state-tab-grid">
            <div class="state-tab-card">
                <h3>Registers</h3>
                <pre>{html.escape(str(regs.get("result", "")))}</pre>
            </div>
            <div class="state-tab-card">
                <h3>Stack</h3>
                <pre>{html.escape(str(stack.get("result", "")))}</pre>
            </div>
            <div class="state-tab-card">
                <h3>Current Instruction</h3>
                <pre>{html.escape(str(disasm.get("result", "")))}</pre>
            </div>
            <div class="state-tab-card">
                <h3>Backtrace</h3>
                <pre>{html.escape(str(bt.get("result", "")))}</pre>
            </div>
        </div>
    </div>'''


def main():
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
