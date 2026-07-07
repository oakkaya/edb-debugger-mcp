#!/bin/bash
# IDA Pro headless plugin live test
# Usage: ./test_ida_live.sh
set -euo pipefail

IDA_ROOT="/home/kali/ida-pro-9.3"
IDA_BIN="$IDA_ROOT/ida"
PLUGIN_ROOT="/home/kali/edb_debugger_mcp"

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; ((PASS++)); }
fail() { echo "[FAIL] $1"; ((FAIL++)); }

# ── 1. Setup temp workspace ──
TESTDIR=$(mktemp -d)
trap 'rm -rf "$TESTDIR"' EXIT

# ── 2. Build test binary ──
cat > "$TESTDIR/test.c" <<'CEOF'
#include <stdio.h>
int main(void) {
    printf("Hello from EDB test\n");
    return 0;
}
CEOF

if gcc -g -O0 -o "$TESTDIR/test_binary" "$TESTDIR/test.c" 2>/dev/null; then
    pass "Test binary compiled"
else
    fail "Test binary compilation failed"
    echo "=== Final: $PASS pass, $FAIL fail ==="
    exit 1
fi

# ── 3. Write IDAPython test script ──
cat > "$TESTDIR/test_plugin.py" <<'PEOF'
import sys
sys.path.insert(0, "/home/kali/edb_debugger_mcp")

import idaapi
import idc
import idautils

# Load plugin
import ida_mcp
ida_mcp.PLUGIN_ENTRY()

# Verify all 13 actions are registered
expected = {
    "edb:start_bridge", "edb:stop_bridge",
    "edb:toggle_bp", "edb:clear_bps",
    "edb:nop_at", "edb:assemble_at",
    "edb:step_into", "edb:step_over", "edb:step_out",
    "edb:run", "edb:pause",
    "edb:show_regs", "edb:show_memory",
}

registered = set()
for a in idautils.Actions():
    if a and len(a) > 0:
        registered.add(a[0])

missing = expected - registered
if missing:
    print(f"[TEST] FAIL: Missing actions: {sorted(missing)}")
else:
    print(f"[TEST] PASS: All 13 actions registered")
    print(f"[TEST] Actions: {sorted(registered)}")

# Verify bridge starts
try:
    from ida_mcp.ida_bridge import start_bridge, stop_bridge
    result = start_bridge()
    print(f"[TEST] Bridge start: {result}")
    if "Failed" not in result and "Connected" in result:
        print("[TEST] PASS: Bridge connected")
    else:
        print(f"[TEST] FAIL: Bridge did not connect: {result}")
except Exception as e:
    print(f"[TEST] FAIL: Bridge exception: {e}")

idc.qpro(0)
PEOF

# ── 4. Run IDA headless ──
echo "--- IDA output ---"
xvfb-run -a "$IDA_BIN" -c -A -S"$TESTDIR/test_plugin.py" "$TESTDIR/test_binary" 2>&1 || true
echo "--- end IDA output ---"

echo ""
echo "=== Results: $PASS pass, $FAIL fail ==="
[ "$FAIL" -eq 0 ]
