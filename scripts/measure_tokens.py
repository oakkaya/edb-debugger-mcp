"""Measure MCP token overhead using cl100k_base tokenizer (same methodology as BloodHound post)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import tiktoken
except ImportError:
    print("pip install tiktoken")
    sys.exit(1)

from edb_debugger_mcp import mcp


def measure():
    enc = tiktoken.get_encoding("cl100k_base")

    tools = list(mcp._tool_manager._tools.values())

    # Serialize tool schemas as minified JSON (FastMCP-generated metadata)
    schemas = []
    for tool in tools:
        # Build minimal tool schema like FastMCP would serialize
        schema = {
            "name": tool.name,
            "description": tool.description or "",
            "inputSchema": tool.inputSchema if hasattr(tool, 'inputSchema') else {},
        }
        schemas.append(schema)

    schema_json = json.dumps(schemas, separators=(",", ":"))
    schema_tokens = len(enc.encode(schema_json))

    # Prompt text tokens
    prompt_text = ""
    if hasattr(mcp, '_prompt_manager') and hasattr(mcp._prompt_manager, '_prompts'):
        for p in mcp._prompt_manager._prompts.values():
            prompt_text += p.description + "\n\n" if hasattr(p, 'description') else ""

    # Try to read prompt function return
    try:
        import inspect
        from edb_debugger_mcp import prompts
        prompt_text = prompts.debug_assistant()
    except Exception:
        pass

    prompt_tokens = len(enc.encode(prompt_text))

    total = schema_tokens + prompt_tokens

    print(f"{'Version':<30} {'Tools':>5} {'Prompt':>8} {'Schemas':>8} {'Total':>8}")
    print("-" * 60)
    print(f"{'Current (composite)':<30} {len(tools):>5} {prompt_tokens:>8} {schema_tokens:>8} {total:>8}")

    # Estimate old flat version (inverse: 157 edb_ + 50 pwntools_)
    old_count = 207
    # Average tool schema size ≈ total / current_count
    avg_schema = schema_tokens / len(tools) if tools else 0
    old_schema = int(avg_schema * old_count)
    # Old had no prompt (or minimal)
    old_prompt = 0
    old_total = old_schema + old_prompt
    print(f"{'Estimated flat (207 tools)':<30} {old_count:>5} {old_prompt:>8} {old_schema:>8} {old_total:>8}")
    print()
    print(f"Token savings: {old_total - total:,} ({((old_total - total) / old_total * 100):.0f}%)")
    print(f"Tools: 207 -> {len(tools)} ({((207 - len(tools)) / 207 * 100):.0f}% reduction)")

    # Per-tool breakdown
    print("\n--- Per-tool schema tokens ---")
    for tool in sorted(tools, key=lambda t: t.name):
        t_schema = json.dumps({
            "name": tool.name,
            "description": (tool.description or "")[:80],
        }, separators=(",", ":"))
        t_tokens = len(enc.encode(t_schema))
        print(f"  {tool.name:<25} {t_tokens:>5}")


if __name__ == "__main__":
    measure()
