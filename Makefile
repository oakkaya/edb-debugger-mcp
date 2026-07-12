.PHONY: test test-live build publish generate-tables clean

# ── Testing ──

test:
	python3 -m pytest tests/ -v --tb=short

test-cov:
	python3 -m pytest tests/ -v --tb=short --ignore=tests/live_test.py --ignore=tests/test_integration.py -k "not integration" 	--cov=edb_debugger_mcp --cov-report=term

test-live:
	python3 tests/live_test.py

test-re:
	python3 tests/re_workflow_demo.py

# ── Build ──

build:
	python3 -m build

publish:
	python3 -m twine upload --username __token__ --password $$$$PYPI_TOKEN dist/*

# ── Tool tables ──

generate-tables:
	python3 scripts/generate_tool_table.py

# ── Cleanup ──

clean:
	rm -rf dist/ *.egg-info __pycache__ .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# ── Lint ──

lint:
	python3 -m py_compile scripts/generate_tool_table.py
	python3 -m py_compile edb_debugger_mcp.py
	python3 -m py_compile edb_debugger_mcp/gdb_backend.py

# ── Default ──

default: test
