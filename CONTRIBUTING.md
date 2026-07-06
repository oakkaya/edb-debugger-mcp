# Contributing to EDB Debugger MCP

Thank you for your interest in contributing. Please follow the guidelines below to keep the project consistent and maintainable.

## Table of Contents

- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Adding New Tools](#adding-new-tools)
- [Adding New Examples](#adding-new-examples)

## Development Setup

1. Clone the repository:
   ```
   git clone https://github.com/oakkaya/edb-debugger-mcp.git
   cd edb-debugger-mcp
   ```

2. Create a virtual environment:
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. (Optional) Install in editable mode:
   ```
   pip install -e .
   ```

5. Verify GDB is available on your system:
   ```
   gdb --version
   ```

## Running Tests

Run the full test suite with:

```
make test
```

This runs `pytest` against all unit tests. For additional test targets:

- `make test-cov` -- run tests with coverage report
- `make test-live` -- run live integration tests (requires GDB)
- `make lint` -- check Python syntax

## Code Style

- All code and documentation must be written in **English only**.
- **Do not add any comments** to the code -- let the code speak for itself.
- **No emojis** in code or documentation.
- Follow the existing code style in the repository (PEP 8 for Python).
- Use meaningful names for variables, functions, and classes.

## Pull Request Process

1. Ensure all tests pass before submitting.
2. Update the README.md if your change affects the public interface.
3. Keep pull requests focused on a single concern -- avoid mixed changes.
4. Reference any related issues in the PR description.
5. Maintain or improve the existing code coverage.

## Adding New Tools

New tools must follow the established three-layer pattern:

1. **Model** -- define the input/output Pydantic model in `edb_models.py`
2. **Tool** -- register the tool function in `edb_debugger_mcp.py` using the model
3. **Test** -- add a test in `tests/` following the existing test patterns

For tools that interact with GDB, add the corresponding method to `gdb_backend.py` first.

Refer to existing tools as reference -- they follow a consistent structure.

## Adding New Examples

Each CTF challenge example must follow the `examples/{name}/` pattern with exactly three files:

- `examples/{name}/{name}.c` -- the vulnerable C source file
- `examples/{name}/exploit.py` -- the exploit script using EDB Debugger MCP
- `examples/{name}/README.md` -- explanation of the vulnerability and exploitation steps

For reference, see existing examples such as `examples/ret2win/`, `examples/format-string/`, or `examples/rop-chain/`.
