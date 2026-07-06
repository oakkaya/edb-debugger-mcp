import sys
import os
import asyncio
import json
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
        }
    }),
    ("Run/Step", {
        "match": lambda n: n in {
            "edb_run", "edb_continue", "edb_pause",
            "edb_step_into", "edb_step_over", "edb_step_out",
            "edb_continue_to", "edb_step_instruction",
            "edb_reverse_step", "edb_reverse_continue",
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


@asynccontextmanager
async def lifespan(app):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, client.start)
    print(f"  [web_ui] {result}")
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
        },
    )


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
            return {
                **t,
                "input_fields": get_input_fields(t),
            }
    return JSONResponse({"error": f"Tool '{tool_name}' not found"}, status_code=404)


@app.post("/api/call/{tool_name}")
async def call_tool(tool_name: str, request: Request):
    body = await request.json()
    args = body.get("args", {})
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, client.call_tool, tool_name, args)
        return result
    except Exception as e:
        return {"result": f"Error: {e}", "isError": True}


def main():
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
