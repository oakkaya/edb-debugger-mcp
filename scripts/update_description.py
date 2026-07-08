"""Update pyproject.toml description with live tool/test counts."""
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from edb_debugger_mcp import mcp

tools = list(mcp._tool_manager._tools.keys())
edb = sum(1 for t in tools if t.startswith("edb_"))
pt = sum(1 for t in tools if t.startswith("pwntools"))

desc = (
    f"EDB Debugger MCP — {len(tools)} tools ({edb} edb_ + {pt} pwntools). "
    "AI-assisted reverse engineering with GDB MI, Web UI, IDA Pro, "
    "Binary Ninja, and Ghidra integration. Linux x86/x86-64."
)

toml = Path("pyproject.toml")
content = toml.read_text()
content = re.sub(r'^description = ".*"$', f'description = "{desc}"', content, flags=re.M)
toml.write_text(content)
print(f"Updated: {desc}")