# Changelog

## v1.2.2 (2026-07-08)

- **Fix**: Jinja2 compatibility — starlette 1.3.1 + system jinja2 3.1.6 threw `unhashable type: dict`
- **Change**: Web UI converted from server-side Jinja2 templates to static HTML + JS
- **Change**: Sidebar and toolbar built dynamically from `/api/tools` + `/api/quick`
- **Docs**: Regenerated tool reference (207/207 tools listed), REAMDE badges, test count (372)
- **Meta**: Bump to v1.2.2, git tag, CI publish (PyPI + Docker + GitHub Release)

## v1.2.1 (2026-07-08)

- **Fix**: `edb_models.py` missing from PyPI wheel — added to `pyproject.toml` wheel packages
- **Fix**: Docker `.dockerignore` excluded `web_ui/` — Docker build fixed
- **Fix**: Web UI session path traversal — `_safe_session_name()` strips `../` from names
- **CI**: Green — lint zero errors, tests pass across Python 3.10–3.13
- **CI**: `GDBBackendError` re-export fixed, IDA bridge import test restored

## v1.2.0 (2026-07-07)

- **Web UI v2**: Memory viewer (hex dump, ASCII, edit mode), live register monitor with diff highlights
- **CI/CD**: Full pipeline — lint + test (4 Python versions) + publish (PyPI + Docker + GitHub Release)
- **Performance**: MCPClient timeout fix, pwntools cache, import path fixes
- **Quality**: 43 new tests (396 total), code coverage reporting
- **CI**: Ruff lint, pytest-cov, multi-Python matrix

## v1.1.0 (2026-07-06)

- **Web UI**: History tab, multi-tab UI (console/history/sessions), session save/load
- **Pwntools**: 10 new tools — tubes (process/remote/send/recv/close/list), ELF diff, bits, context, log_level
- **EDB tools**: RE tools, remote ARM64 debug support, exploit generator
- **Coverage**: 5 missing EDB plugin tools added (function nav, xrefs, register enum, process strings, breakpoint types)
- **Docs**: Tool table auto-generation script

## v1.0.13 (2026-07-05)

- **New tools**: 12 edb_ tools — `execute_gdb_command`, `follow_fork`, `trace_start/stop/show`, `scan_stack_for_retaddr`, `watch_expression`, `apply_patches_to_file`, `get_eflags`, `compare_snapshot`, `pipeline`, `export_state`
- **Tests**: 332 tests passing

## v1.0.12 (2026-07-04)

- Web UI redesign with state panel, quick actions
- 5 new pwntools tools: `elf_sections`, `elf_symbols`, `elf_strings`, `elf_deps`, `entropy`
- 305 tests passing

## v1.0.11 (2026-07-03)

- 5 new pwntools tools: `flat`, `sigreturn`, `elf_patch`, `elf_search`, `make_elf`
- Web UI redesign
- 297 tests passing

## v1.0.10 (2026-07-02)

- IDA Pro plugin verified with IDA Pro 9.3
- Docker release automation
- /bin/ls RE analysis demo
- Core dump ignore in git

## v1.0.9 (2026-06-30)

- 10 CTF challenge examples with solve scripts
- Docker build fix
- Python 3.10/3.11 compatibility fixes
- Issue templates + CONTRIBUTING.md

## v1.0.8 (2026-06-29)

- **Refactor**: Models extracted into `edb_models.py` (93+ Pydantic models)
- **Docker**: Dockerfile + GitHub Container Registry image
- **CI**: Auto-publish to PyPI on version tags
- **IDA Pro plugin**: Full bridge with 13 menu actions
- **VS Code extension**: Debugger panel WebView
- Demo GIFs: workflow + split-screen

## v1.0.7 (2026-06-28)

- Fix pwntools import + MCPClient argument bugs
- Add workflow + split-screen GIF demos
- Ghidra plugin (experimental)
- Web UI (experimental)
- x64dbg plugin (experimental)

## v1.0.6 (2026-06-27)

- Sync tool descriptions
- Add 3 CTF examples (ret2win, format-string, crackme)
- Fix Binary Ninja `edb_interrupt` → `edb_pause`
- Scripts: `generate_tool_table.py`

## v1.0.5 (2026-06-26)

- PyPI classifiers, version badge
- Binary Ninja disclaimer
- Makefile

## v1.0.4 (2026-06-25)

- README sync to PyPI
- pwntools section, MCP hosts (opencode, cursor, continue)

## v1.0.3 (2026-06-25)

- Update PyPI description
- Collapsible tool reference section

## v1.0.2 (2026-06-24)

- **Fix**: PyPI package missing `gdb_backend.py` and `pwntools_mcp.py`

## v1.0.1 (2026-06-24)

- Fix PyPI README image paths

## v1.0.0 (2026-06-23)

- Initial release
- EDB Debugger MCP server with 147 tools (135 edb_ + 12 pwntools_)
- Binary Ninja plugin with register overlay, breakpoints, patching
- 191 tests
- GDB MI backend with 172 public methods
