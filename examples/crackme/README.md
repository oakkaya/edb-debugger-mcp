# Crackme — Password Recovery via Breakpoint Analysis

A simple password-check challenge. The binary compares user input against a
hardcoded password using `strcmp`. By setting a breakpoint on `strcmp` and
inspecting the argument registers, you can read the secret password directly
from memory.

## The Binary

```c
int main() {
    char input[64];
    fgets(input, 64, stdin);
    if (strcmp(input, "s3cr3t_p@ssw0rd") == 0) {
        printf("Access granted!\n");
    } else {
        printf("Access denied.\n");
    }
}
```

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -o crackme crackme.c`

## Walkthrough

### 1. Load the binary and find `strcmp`

```
edb_load_program(path="/tmp/crackme")
edb_list_functions()
edb_lookup_symbol(name="strcmp")
edb_disassemble(location="main", count=30)
```

Look for the `call strcmp@plt` instruction in `main`. Note its address so you
can set a breakpoint there.

### 2. Set breakpoint on `strcmp`

```
edb_set_breakpoint(location="strcmp@plt")
```

### 3. Run with dummy input

```
edb_run()
```

The program will ask for a password. Send some garbage like `AAAA`.

### 4. Hit breakpoint — inspect arguments

When `strcmp` is called, the System V AMD64 ABI places:
- `rdi` = pointer to our input (`"AAAA"`)
- `rsi` = pointer to the hardcoded password (`"s3cr3t_p@ssw0rd"`)

```
edb_get_registers()
edb_read_memory(address="$rdi", size=32)
edb_read_memory(address="$rsi", size=32)
```

`$rsi` should contain the secret password.

### 5. Verify by continuing

```
edb_continue()
```

Now send the correct password to the fresh run and confirm `"Access granted!"`.

## Exploit Script

```python
from pwn import *

p = process("/tmp/crackme")
p.sendline(b"AAAA")
print(p.recvall().decode())
```

The pwntools script is minimal — the real work is done interactively via the
EDB MCP breakpoint inspection in the walkthrough above.

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `edb_set_breakpoint` | Set breakpoint on `strcmp@plt` |
| `edb_run` | Start the process |
| `edb_get_registers` | Read RDI/RSI to get string pointers |
| `edb_read_memory` | Dump the password string from `[rsi]` |
| `edb_continue` | Resume program after breakpoint |
| `edb_lookup_symbol` | Find `strcmp` address |
| `edb_disassemble` | Locate the `strcmp` call site in `main` |
