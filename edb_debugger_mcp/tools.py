from edb_debugger_mcp._mcp import mcp, backend, GDBBackendError
from edb_models import *

@mcp.tool(
    name="edb_load_program",
    annotations={"title": "Load Program for Debugging", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_load_program(params: BinaryPath) -> str:
    '''Load an executable binary for debugging. Resolves symbols and prepares for execution.
    Optionally pass command-line arguments. This is the mandatory first step for debugging a new binary.

    Args:
        params (BinaryPath): Path and arguments
            - path (str): Absolute path to the executable
            - args (Optional[str]): Command-line arguments (default: "")

    Returns:
        str: Status message confirming the binary was loaded
    '''
    try:
        return await backend.load_program(params.path, params.args)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_attach_process",
    annotations={"title": "Attach to Running Process", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_attach_process(params: AttachPid) -> str:
    '''Attach the debugger to an already-running process by PID.
    The process is paused on attach.

    Args:
        params (AttachPid): Process ID
            - pid (int): Process ID to attach to

    Returns:
        str: Status message confirming attachment
    '''
    try:
        return await backend.attach(params.pid)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_detach_process",
    annotations={"title": "Detach from Process", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_detach_process() -> str:
    '''Detach from the debugged process. The process continues running independently.

    Returns:
        str: Confirmation of detachment
    '''
    try:
        return await backend.detach()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_kill_process",
    annotations={"title": "Kill Debugged Process", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_kill_process() -> str:
    '''Kill the debugged process immediately.
    Equivalent to force-terminating the debuggee.

    Returns:
        str: Confirmation the process was killed
    '''
    try:
        return await backend.kill()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_run",
    annotations={"title": "Run Program", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_run() -> str:
    '''Start execution of the loaded program from the beginning.
    Stops at the first breakpoint hit.

    Returns:
        str: Status with reason if stopped at breakpoint
    '''
    try:
        return await backend.run()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_continue",
    annotations={"title": "Continue Execution", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_continue() -> str:
    '''Continue execution after a breakpoint or pause.
    Resumes from the current instruction pointer.

    Returns:
        str: Status with stop reason if another breakpoint is hit
    '''
    try:
        return await backend.continue_exec()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_pause",
    annotations={"title": "Pause Execution", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_pause() -> str:
    '''Pause (interrupt) the running program.
    Sends a SIGINT to break execution.

    Returns:
        str: Confirmation of interruption
    '''
    try:
        return await backend.interrupt()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_restart",
    annotations={"title": "Restart Program", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_restart() -> str:
    '''Kill and restart the debugged program. Reloads the binary, preserves breakpoints.

    Returns:
        str: Status after restart
    '''
    try:
        return await backend.restart()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_step_into",
    annotations={"title": "Step Into Instruction", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_step_into() -> str:
    '''Execute one machine instruction, stepping into function calls.
    If the current instruction is a `call`, execution enters the called function.

    Returns:
        str: JSON with address, function, file, line after stepping
    '''
    try:
        loc = await backend.step_into()
        return json.dumps(loc, indent=2)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_step_over",
    annotations={"title": "Step Over Instruction", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_step_over() -> str:
    '''Execute one machine instruction, treating calls as atomic.
    If the instruction is a `call`, the entire called function runs then stops.

    Returns:
        str: JSON with address, function, file, line after stepping
    '''
    try:
        loc = await backend.step_over()
        return json.dumps(loc, indent=2)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_step_out",
    annotations={"title": "Step Out of Function", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_step_out() -> str:
    '''Execute until the current function returns to its caller.

    Returns:
        str: Location where execution stopped
    '''
    try:
        loc = await backend.step_out()
        return json.dumps(loc, indent=2)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_continue_to",
    annotations={"title": "Continue to Address", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_continue_to(params: ContinueToAddress) -> str:
    '''Continue execution until a specific address is reached.
    Sets a temporary breakpoint at the given address and runs.

    Args:
        params (ContinueToAddress): Target
            - address (str): Address in hex (e.g., '0x4000a0') or function name

    Returns:
        str: Location details when stopped
    '''
    try:
        loc = await backend.continue_to_address(params.address)
        return json.dumps(loc, indent=2)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_breakpoint",
    annotations={"title": "Set Breakpoint", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_breakpoint(params: BreakpointInput) -> str:
    '''Set a breakpoint at a function, address, or source location.
    Supports conditional breakpoints.

    Args:
        params (BreakpointInput): Breakpoint location
            - location (str): E.g., 'main', '*0x400528', 'foo.c:42'
            - condition (Optional[str]): E.g., 'x == 5' (default: none)

    Returns:
        str: Breakpoint number and details
    '''
    try:
        bkpt = await backend.set_breakpoint(params.location, params.condition)
        num = bkpt.get("number", "?")
        addr = bkpt.get("addr", params.location)
        func = f" at {bkpt['func']}" if bkpt.get("func") else ""
        return f"Breakpoint {num} at {addr}{func}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_hardware_breakpoint",
    annotations={"title": "Set Hardware Breakpoint", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_hardware_breakpoint(params: BreakpointInput) -> str:
    '''Set a hardware-assisted breakpoint using CPU debug registers.
    Useful for ROM, flash, or self-modifying code regions.

    Args:
        params (BreakpointInput): Location
            - location (str): Address or function name

    Returns:
        str: Hardware breakpoint information
    '''
    try:
        bkpt = await backend.set_hardware_breakpoint(params.location)
        num = bkpt.get("number", "?")
        addr = bkpt.get("addr", params.location)
        return f"Hardware breakpoint {num} at {addr}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_watchpoint",
    annotations={"title": "Set Watchpoint", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_watchpoint(params: WatchpointInput) -> str:
    '''Set a watchpoint to monitor memory access. Three modes:
    - 'write': stops when value changes (default)
    - 'read': stops when value is read
    - 'access': stops on both read and write

    Args:
        params (WatchpointInput): Watchpoint configuration
            - expression (str): E.g., 'x', '*0x7fff0000', 'my_global'
            - watch_type (str): 'write', 'read', or 'access' (default: 'write')

    Returns:
        str: Watchpoint details
    '''
    try:
        wp = await backend.set_watchpoint(params.expression, params.watch_type)
        return json.dumps(wp) if wp else f"Watchpoint set on {params.expression}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_remove_breakpoint",
    annotations={"title": "Remove Breakpoint", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_remove_breakpoint(params: BreakpointNumber) -> str:
    '''Permanently remove a breakpoint or watchpoint by number.
    Use edb_list_breakpoints to find breakpoint numbers.

    Args:
        params (BreakpointNumber): Breakpoint number
            - number (int): Breakpoint ID to remove

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.remove_breakpoint(params.number)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_enable_breakpoint",
    annotations={"title": "Enable Breakpoint", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_enable_breakpoint(params: BreakpointNumber) -> str:
    '''Re-activate a disabled breakpoint.

    Args:
        params (BreakpointNumber): Breakpoint number
            - number (int): Breakpoint ID to enable

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.enable_breakpoint(params.number)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_disable_breakpoint",
    annotations={"title": "Disable Breakpoint", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_disable_breakpoint(params: BreakpointNumber) -> str:
    '''Disable a breakpoint without removing it. It can be re-enabled later.

    Args:
        params (BreakpointNumber): Breakpoint number
            - number (int): Breakpoint ID to disable

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.disable_breakpoint(params.number)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_breakpoints",
    annotations={"title": "List All Breakpoints", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_breakpoints() -> str:
    '''List all breakpoints, watchpoints, and their status (number, type, enable/disable, address).

    Returns:
        str: Formatted breakpoint table
    '''
    try:
        return await backend.list_breakpoints()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_registers",
    annotations={"title": "Get All CPU Registers", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_registers() -> str:
    '''Get all CPU register values as JSON. Includes general-purpose registers,
    instruction pointer, stack pointer, base pointer, flags, and SIMD registers.

    Returns:
        str: JSON object with register names and hex values
    '''
    try:
        regs = await backend.get_registers()
        return json.dumps(regs, indent=2)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_register",
    annotations={"title": "Get Single Register", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_register(params: RegisterName) -> str:
    '''Get the value of a specific CPU register.

    Args:
        params (RegisterName): Register name
            - name (str): E.g., 'rax', 'rbx', 'rip', 'rsp', 'eflags'

    Returns:
        str: Hex value of the register
    '''
    try:
        val = await backend.get_register(params.name)
        return f"{params.name} = {val}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_register",
    annotations={"title": "Set Register Value", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_register(params: RegisterSetInput) -> str:
    '''Modify a CPU register value. Useful for patching execution flow or testing conditions.

    Args:
        params (RegisterSetInput): Register modification
            - name (str): Register name (e.g., 'rax', 'rip')
            - value (str): New value in hex (e.g., '0x7fff00001000')

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.set_register(params.name, params.value)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_dump_registers",
    annotations={"title": "Formatted Register Dump", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_dump_registers() -> str:
    '''Get a human-readable register dump in markdown table format.
    Shows all general-purpose registers, instruction pointer, flags and their meanings.

    Returns:
        str: Markdown-formatted register table
    '''
    try:
        regs = await backend.get_registers()
        lines = ["## CPU Registers", "", "| Register | Value |", "|----------|-------|"]
        for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags", "cs", "ss", "ds", "es", "fs", "gs"):
            val = regs.get(name, "")
            if val:
                lines.append(f"| {name} | {val} |")
        eflags_str = regs.get("eflags", regs.get("rflags", ""))
        if eflags_str:
            try:
                flags_val = int(eflags_str, 16) if eflags_str.startswith("0x") else int(eflags_str, 16)
                flag_names = []
                flag_map = [(0, "CF"), (2, "PF"), (4, "AF"), (6, "ZF"), (7, "SF"), (8, "TF"), (9, "IF"), (10, "DF"), (11, "OF")]
                for bit, fname in flag_map:
                    if flags_val & (1 << bit):
                        flag_names.append(fname)
                if flag_names:
                    lines.extend(["", "**Flags:** " + " ".join(flag_names)])
            except (ValueError, IndexError):
                pass
        return "\n".join(lines)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_read_memory",
    annotations={"title": "Read and Hex Dump Memory", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_read_memory(params: AddressInput) -> str:
    '''Read and display memory contents at an address as a hex dump.
    Shows hex bytes with ASCII representation.

    Args:
        params (AddressInput): Memory parameters
            - address (str): Address (e.g., '0x7fff0000' or symbol name)
            - count (int): Bytes to read, 1-4096 (default: 128)

    Returns:
        str: Formatted hex dump with address, hex bytes, and ASCII
    '''
    try:
        return await backend.hex_dump(params.address, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_write_memory",
    annotations={"title": "Write to Memory", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_write_memory(params: MemoryWriteInput) -> str:
    '''Write a value to a memory address. Use for patching code or data.

    Args:
        params (MemoryWriteInput): Memory write
            - address (str): Target address (e.g., '0x400000')
            - data (str): Data to write (e.g., '0x90' for NOP)

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.write_memory(params.address, params.data)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_write_memory_bytes",
    annotations={"title": "Write Raw Bytes to Memory", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_write_memory_bytes(params: MemoryWriteBytesInput) -> str:
    '''Write raw hex bytes to memory starting at an address.
    Useful for patching multiple bytes at once (e.g., NOP sled or shellcode).

    Args:
        params (MemoryWriteBytesInput): Raw byte write
            - address (str): Target address (e.g., '0x400000')
            - hex_bytes (str): Hex bytes (e.g., '90 90 90' or '0x90 0x90 0x90')

    Returns:
        str: Confirmation of byte count written
    '''
    try:
        return await backend.write_memory_bytes(params.address, params.hex_bytes)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_search_memory",
    annotations={"title": "Search Memory for Pattern", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_search_memory(params: SearchMemoryInput) -> str:
    '''Search memory for a byte pattern. Finds all occurrences in the specified region.

    Args:
        params (SearchMemoryInput): Search parameters
            - pattern (str): Hex bytes (e.g., '0x90 0x90')
            - address (Optional[str]): Start address (default: $pc)
            - length (Optional[str]): Region size in hex (default: 0x10000)

    Returns:
        str: Addresses where the pattern was found
    '''
    try:
        return await backend.search_memory(params.pattern, params.address, params.length)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_search_instructions",
    annotations={"title": "Search for Instruction Pattern", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_search_instructions(params: SearchInstructionsInput) -> str:
    '''Search memory for byte patterns (case-insensitive).
    Searches memory for the given hex byte pattern within the specified range.
    Useful for finding instruction opcode patterns in code sections.

    Args:
        params (SearchInstructionsInput): Pattern search
            - pattern (str): Hex byte pattern (e.g., '0x90 0x90')
            - range_start (Optional[str]): Start address of search range
            - range_end (Optional[str]): End address of search range

    Returns:
        str: Addresses where pattern was found
    '''
    try:
        return await backend.search_instructions(params.pattern, params.range_start, params.range_end)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_memory_map",
    annotations={"title": "Get Process Memory Map", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_memory_map() -> str:
    '''Get the process memory map (like /proc/pid/maps).
    Shows address ranges, permissions, offset, and paths for all mapped regions.

    Returns:
        str: Memory map listing
    '''
    try:
        return await backend.get_memory_map()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_section_info",
    annotations={"title": "Get ELF Section Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_section_info(params: SectionInfoInput) -> str:
    '''Get detailed section information for loaded modules.
    Shows section names, addresses, sizes, and file offsets.

    Args:
        params (SectionInfoInput): Module filter
            - module (Optional[str]): Module name (empty = all)

    Returns:
        str: Section information
    '''
    try:
        return await backend.get_section_info(params.module)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_disassemble",
    annotations={"title": "Disassemble Code", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_disassemble(params: DisassembleInput) -> str:
    '''Disassemble machine code at an address or function.
    Shows assembly instructions with addresses, offsets, and opcodes.

    Args:
        params (DisassembleInput): Disassembly params
            - location (str): Address (e.g., '0x400000') or function (e.g., 'main')
            - count (int): Instructions to show, 1-200 (default: 10)

    Returns:
        str: Formatted disassembly listing
    '''
    try:
        return await backend.disassemble(params.location, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_current_instruction",
    annotations={"title": "Get Current Instruction", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_current_instruction() -> str:
    '''Get the instruction at the current program counter (RIP/EIP).
    Shows what will execute next.

    Returns:
        str: Current instruction text
    '''
    try:
        inst = await backend.get_current_instruction()
        return inst if inst else "No instruction at current PC"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_stack",
    annotations={"title": "Read Stack Contents", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_stack() -> str:
    '''Dump the current stack (stack pointer to higher addresses).
    Each entry is an 8-byte (64-bit) value.

    Returns:
        str: Stack hex dump
    '''
    try:
        return await backend.get_stack(16)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_stack_frame",
    annotations={"title": "Get Stack Frame Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_stack_frame(params: StackFrameInput) -> str:
    '''Get detailed information about a specific stack frame level.
    Shows address, function, file, line for the given frame.

    Args:
        params (StackFrameInput): Frame level
            - frame_level (int): Frame number, 0 = current (default: 0)

    Returns:
        str: JSON frame information
    '''
    try:
        return await backend.get_stack_frame(params.frame_level)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_backtrace",
    annotations={"title": "Get Call Stack Backtrace", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_backtrace() -> str:
    '''Get the full call stack backtrace. Frame #0 is the current function.
    Each frame shows number, address, function name, and source location.

    Returns:
        str: Formatted backtrace
    '''
    try:
        return await backend.get_backtrace(20)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_lookup_symbol",
    annotations={"title": "Look Up Symbol", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_lookup_symbol(params: SymbolLookup) -> str:
    '''Look up a symbol's address and type. Supports functions and variables.

    Args:
        params (SymbolLookup): Symbol name
            - name (str): E.g., 'main', 'printf', 'errno'

    Returns:
        str: Symbol address and type info
    '''
    try:
        return await backend.lookup_symbol(params.name)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_modules",
    annotations={"title": "List Loaded Modules", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_modules() -> str:
    '''List all shared libraries / modules loaded by the process.
    Shows base address, text size, and path.

    Returns:
        str: Module listing
    '''
    try:
        return await backend.list_modules()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_threads",
    annotations={"title": "List Threads", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_threads() -> str:
    '''List all threads in the debugged process with IDs, names, and states.

    Returns:
        str: Thread listing
    '''
    try:
        return await backend.list_threads()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_current_thread",
    annotations={"title": "Get Current Thread", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_current_thread() -> str:
    '''Get info about the currently active thread.

    Returns:
        str: Current thread information
    '''
    try:
        info = await backend.get_current_thread()
        return json.dumps(info, indent=2) if info else "No thread info"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_current_thread",
    annotations={"title": "Switch Thread", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_current_thread(params: ThreadId) -> str:
    '''Switch the debugger context to a different thread.
    All subsequent commands apply to the selected thread.

    Args:
        params (ThreadId): Thread ID
            - thread_id (int): Thread ID to switch to

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.set_current_thread(params.thread_id)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_evaluate_expression",
    annotations={"title": "Evaluate C Expression", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_evaluate_expression(params: EvaluateExpr) -> str:
    '''Evaluate a C expression in the debug context.
    Supports variables, pointer dereferences, casts, arithmetic, and function calls.
    Examples: 'x + 5', '*(int*)0x7fff0000', 'argv[0]'

    Args:
        params (EvaluateExpr): Expression
            - expression (str): C expression to evaluate

    Returns:
        str: Expression result
    '''
    try:
        return await backend.evaluate(params.expression)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_string",
    annotations={"title": "Read String from Memory", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_string(params: ReadStringInput) -> str:
    '''Read a null-terminated string from a memory address.
    Interprets the memory as a C string (null-terminated).

    Args:
        params (ReadStringInput): String parameters
            - address (str): Address (e.g., '0x400678')
            - max_length (int): Max string length, 1-4096 (default: 256)

    Returns:
        str: String contents
    '''
    try:
        return await backend.get_string(params.address, params.max_length)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_find_strings",
    annotations={"title": "Find Strings in Memory", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_find_strings() -> str:
    '''Find printable ASCII strings in the current code region.
    Searches from current PC for printable character sequences.

    Returns:
        str: Found strings with addresses
    '''
    try:
        return await backend.find_strings()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_variable",
    annotations={"title": "Get Variable Value", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_variable(params: VariableInput) -> str:
    '''Read the value of a local or global variable in the current scope.

    Args:
        params (VariableInput): Variable name
            - name (str): Variable name (e.g., 'i', 'argc', 'buffer')

    Returns:
        str: Variable value
    '''
    try:
        val = await backend.get_variable(params.name)
        return f"{params.name} = {val}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_variable",
    annotations={"title": "Set Variable Value", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_variable(params: VariableInput) -> str:
    '''Modify a variable's value in the current scope.
    Useful for altering program behavior during debugging.

    Args:
        params (VariableInput): Variable modification
            - name (str): Variable name (e.g., 'x', 'error_flag')
            - value (str): New value (e.g., '0', '42', '"hello"')

    Returns:
        str: Confirmation
    '''
    try:
        if params.value is None:
            return "Error: value is required for set operation"
        return await backend.set_variable(params.name, params.value)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_arguments",
    annotations={"title": "Get Function Arguments", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_arguments() -> str:
    '''Get the arguments passed to the current function.
    Shows argument names and values.

    Returns:
        str: Function argument names and values
    '''
    try:
        return await backend.get_arguments()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_locals",
    annotations={"title": "Get Local Variables", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_locals() -> str:
    '''Get all local variables in the current function scope.
    Shows names and values.

    Returns:
        str: Local variable names and values
    '''
    try:
        return await backend.get_locals()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_function_info",
    annotations={"title": "Get Function Information", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_function_info(params: FunctionInfo) -> str:
    '''Get detailed info about a function: address, prototype, source location.

    Args:
        params (FunctionInfo): Function name
            - name (str): E.g., 'main', 'malloc'

    Returns:
        str: Function details
    '''
    try:
        return await backend.get_function_info(params.name)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_find_references",
    annotations={"title": "Find Code References", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_find_references(params: FindReferencesInput) -> str:
    '''Find all code references to a given address or symbol.
    Searches functions and variables referencing the address.

    Args:
        params (FindReferencesInput): Target address
            - address (str): Address to find references to

    Returns:
        str: Reference locations
    '''
    try:
        return await backend.find_references(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_source",
    annotations={"title": "List Source Code", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_source(params: SourceInput) -> str:
    '''Display source code with line numbers. Current line is marked with '->'.
    Reads directly from the source file if available.

    Args:
        params (SourceInput): Source location
            - file (str): Source file path
            - line (int): Starting line (default: 1)
            - count (int): Lines to show, 1-200 (default: 20)

    Returns:
        str: Source code listing
    '''
    try:
        return await backend.get_source(params.file, params.line, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_status",
    annotations={"title": "Get Debugger Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_status() -> str:
    '''Get the current debugger and process status.
    Shows whether a process is loaded, running or paused, PID, RIP, current instruction, register count.

    Returns:
        str: JSON status object
    '''
    try:
        status = await backend.status()
        return json.dumps(status, indent=2)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"





@mcp.tool(
    name="edb_read_memory_as",
    annotations={"title": "Read Memory as Data Type", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_read_memory_as(params: ReadMemoryAsInput) -> str:
    '''Read memory at an address interpreted as a specific data type.
    Supports integers (8-64 bit signed/unsigned), float, double, pointer, and string.
    Essential for struct inspection, pointer chasing, and data analysis.

    Args:
        params (ReadMemoryAsInput): Read parameters
            - address (str): Address or symbol name
            - data_type (str): Type: int8/16/32/64, uint8/16/32/64, float, double, pointer, string
            - count (int): Number of elements (default: 1, max: 256)

    Returns:
        str: Value(s) interpreted as the requested type
    '''
    try:
        return await backend.read_memory_as(params.address, params.data_type, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_entry_point",
    annotations={"title": "Get Program Entry Point", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_entry_point() -> str:
    '''Get the program entry point address. The entry point is the first code
    executed when the program starts (typically _start).

    Returns:
        str: Entry point address in hex
    '''
    try:
        ep = await backend.get_entry_point()
        return f"Entry point: {ep}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_function_bounds",
    annotations={"title": "Get Function Bounds", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_function_bounds(params: FunctionBoundsInput) -> str:
    '''Get the start address, end address, and size of a function.
    Useful for understanding function layout and selecting regions for patching.

    Args:
        params (FunctionBoundsInput): Function name
            - name (str): Function name (e.g., 'main')

    Returns:
        str: Start address, end address, and size
    '''
    try:
        return await backend.get_function_bounds(params.name)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_file_offset_to_va",
    annotations={"title": "Convert File Offset to Virtual Address", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_file_offset_to_va(params: FileOffsetInput) -> str:
    '''Convert a file offset from the binary on disk to the corresponding
    virtual address in the loaded process. Essential for patching binaries
    and understanding disk-to-memory mapping.

    Args:
        params (FileOffsetInput): File offset
            - offset (int): Offset in bytes from start of file

    Returns:
        str: Virtual address in hex
    '''
    try:
        va = await backend.file_offset_to_va(params.offset)
        return f"File offset 0x{params.offset:x} -> VA {va}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_va_to_file_offset",
    annotations={"title": "Convert Virtual Address to File Offset", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_va_to_file_offset(params: VirtualAddressInput) -> str:
    '''Convert a virtual address in the loaded process to the corresponding
    file offset in the binary on disk. Essential for applying patches back
    to the binary file.

    Args:
        params (VirtualAddressInput): Virtual address
            - address (str): Virtual address in hex (e.g., '0x400000')

    Returns:
        str: File offset in hex
    '''
    try:
        off = await backend.va_to_file_offset(params.address)
        return f"VA {params.address} -> File offset {off}"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_nop_range",
    annotations={"title": "NOP Out Instruction Range", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_nop_range(params: NopRangeInput) -> str:
    '''Replace a range of instructions with NOP (0x90) bytes.
    This is the primary method for patching out conditional jumps or calls.
    Use edb_get_function_bounds to find the range for a function.

    Args:
        params (NopRangeInput): Range to NOP
            - start_address (str): Start address (e.g., '0x400000')
            - end_address (str): End address, exclusive (e.g., '0x400005')

    Returns:
        str: Confirmation of bytes written
    '''
    try:
        return await backend.nop_range(params.start_address, params.end_address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_analyze_calls_at",
    annotations={"title": "Analyze Calls at Address", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_analyze_calls_at(params: AnalyzeCallsInput) -> str:
    '''Disassemble at an address and identify call/jump targets.
    Shows each instruction and resolves targets for call, jmp, jz, jnz.
    Essential for control flow analysis and understanding branch targets.

    Args:
        params (AnalyzeCallsInput): Address
            - address (str): Address to analyze

    Returns:
        str: Instructions with resolved call/jump targets
    '''
    try:
        return await backend.analyze_calls_at(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_string_references",
    annotations={"title": "Find String References", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_string_references(params: StringRefInput) -> str:
    '''Find all code and data references to a string or address in the binary.
    Searches function names, variable names, and source files for the given string.
    Useful for tracing how a particular value or string is used in the program.

    Args:
        params (StringRefInput): Search target
            - string_or_address (str): String content (e.g., 'password') or hex address

    Returns:
        str: Matching functions, variables, and sources
    '''
    try:
        return await backend.string_references(params.string_or_address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_disassemble_range",
    annotations={"title": "Disassemble Address Range", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_disassemble_range(params: DisassembleRangeInput) -> str:
    '''Disassemble a range of memory from start to end address.
    Unlike edb_disassemble which uses a count of instructions, this tool
    disassembles an exact address range. Useful for full function analysis.

    Args:
        params (DisassembleRangeInput): Range
            - start_address (str): Start address (e.g., '0x400000')
            - end_address (str): End address (e.g., '0x400100')

    Returns:
        str: Disassembly listing
    '''
    try:
        return await backend.disassemble_range(params.start_address, params.end_address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_trace_point",
    annotations={"title": "Set Conditional Logging Breakpoint", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_trace_point(params: ConditionalLogInput) -> str:
    '''Set a trace point (logging breakpoint) that prints a message and continues
    without stopping execution. Useful for tracing function calls and variable
    changes without interrupting the program flow.

    Args:
        params (ConditionalLogInput): Trace configuration
            - location (str): Breakpoint location (function, address, or file:line)
            - log_message (str): Message to print (use $reg for register values)

    Returns:
        str: Trace point number and details
    '''
    try:
        return await backend.set_conditional_log_breakpoint(params.location, params.log_message)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_fill_memory",
    annotations={"title": "Fill Memory with Byte Pattern", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_fill_memory(params: FillMemoryInput) -> str:
    '''Fill a memory region with a repeating byte value.
    Useful for zeroing buffers, filling with NOPs (0x90), or any pattern.
    Uses edb_write_memory_bytes internally.

    Args:
        params (FillMemoryInput): Fill parameters
            - address (str): Start address (e.g., '0x400000')
            - byte_value (str): Byte value (e.g., '0x90' or '90')
            - count (int): Number of bytes to fill

    Returns:
        str: Confirmation of fill operation
    '''
    try:
        return await backend.fill_memory(params.address, params.byte_value, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_compare_memory",
    annotations={"title": "Compare Memory Regions", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_compare_memory(params: CompareMemoryInput) -> str:
    '''Compare two memory regions byte-by-byte and show differences.
    Useful for detecting self-modifying code, comparing loaded vs original
    code, or analyzing binary patches.

    Args:
        params (CompareMemoryInput): Comparison parameters
            - address1 (str): First address (e.g., '0x400000')
            - address2 (str): Second address (e.g., '0x400100')
            - count (int): Number of bytes to compare (max: 4096)

    Returns:
        str: Differing regions with hex values
    '''
    try:
        return await backend.compare_memory(params.address1, params.address2, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_add_comment",
    annotations={"title": "Add Address Annotation", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_add_comment(params: CommentInput) -> str:
    '''Add a text annotation to an address. Comments are stored in-memory
    and can be listed with edb_list_comments. Useful for documenting
    analysis findings during a reverse engineering session.

    Args:
        params (CommentInput): Comment data
            - address (str): Address in hex (e.g., '0x400000')
            - comment (str): Annotation text

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.add_comment(params.address, params.comment)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_comments",
    annotations={"title": "List Address Annotations", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_comments() -> str:
    '''List all address annotations added via edb_add_comment.
    Returns a sorted list of addresses with their associated comments.

    Returns:
        str: Comment listing
    '''
    try:
        return await backend.list_comments()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_remove_comment",
    annotations={"title": "Remove Address Annotation", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_remove_comment(params: AddressOnlyInput) -> str:
    '''Remove an annotation previously added with edb_add_comment.

    Args:
        params (AddressOnlyInput): Address
            - address (str): Address to remove comment from

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.remove_comment(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"





@mcp.tool(
    name="edb_get_binary_info",
    annotations={"title": "Get Binary File Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_binary_info() -> str:
    '''Get detailed information about the loaded binary file.
    Shows ELF header, architecture, entry point, section layout, and more.
    Equivalent to EDB's BinaryInfo plugin.

    Returns:
        str: Binary file metadata
    '''
    try:
        return await backend.get_binary_info()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_functions",
    annotations={"title": "List Functions in Binary", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_functions(params: FunctionFilterInput) -> str:
    '''List all functions in the binary, optionally filtered by name.
    Equivalent to EDB's FunctionFinder plugin. Shows function names,
    addresses, and prototypes.

    Args:
        params (FunctionFilterInput): Filter
            - filter_str (str): Optional filter (e.g., 'main', 'printf')

    Returns:
        str: Function listing
    '''
    try:
        return await backend.list_functions(params.filter_str)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_find_rop_gadgets",
    annotations={"title": "Find ROP Gadgets", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_find_rop_gadgets(params: RopSearchInput) -> str:
    '''Search for ROP gadgets (instructions ending with 'ret') in memory.
    Equivalent to EDB's ROPTool plugin. Finds usable instruction sequences
    for ROP chain construction.

    Args:
        params (RopSearchInput): Search parameters
            - address (str): Start address (default: $pc)
            - depth (int): Max instructions before ret, 1-10 (default: 2)
            - count (int): Max results, 1-1000 (default: 100)

    Returns:
        str: ROP gadget addresses and bytes
    '''
    try:
        return await backend.find_rop_gadgets(params.address, params.depth, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_analyze_region",
    annotations={"title": "Analyze Code Region", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_analyze_region(params: AnalyzeRegionInput) -> str:
    '''Analyze a code region for call instructions, branch instructions,
    and strings. Equivalent to EDB's Analyzer plugin. Shows control flow
    information for the given address range.

    Args:
        params (AnalyzeRegionInput): Region parameters
            - address (str): Start address
            - size (int): Region size in bytes (default: 256)

    Returns:
        str: Analysis with call/branch/instruction counts
    '''
    try:
        return await backend.analyze_region(params.address, params.size)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_analyze_heap",
    annotations={"title": "Analyze Heap Memory", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_analyze_heap() -> str:
    '''Analyze the heap memory region of the debugged process.
    Equivalent to EDB's HeapAnalyzer plugin. Shows heap regions,
    sizes, permissions, and strings found in heap memory.

    Returns:
        str: Heap analysis including regions, sizes, and strings
    '''
    try:
        return await backend.analyze_heap()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_add_bookmark",
    annotations={"title": "Add Bookmark", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_add_bookmark(params: BookmarkInput) -> str:
    '''Save a named bookmark pointing to an address for quick navigation.
    Equivalent to EDB's Bookmarks plugin. Useful for marking key locations
    during reverse engineering.

    Args:
        params (BookmarkInput): Bookmark
            - name (str): Name (e.g., 'main_loop')
            - address (str): Address (e.g., '0x400000')

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.add_bookmark(params.name, params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_bookmarks",
    annotations={"title": "List Bookmarks", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_bookmarks() -> str:
    '''List all saved bookmarks with names and addresses.

    Returns:
        str: Bookmark listing
    '''
    try:
        return await backend.list_bookmarks()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_remove_bookmark",
    annotations={"title": "Remove Bookmark", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_remove_bookmark(params: BookmarkNameInput) -> str:
    '''Remove a bookmark by name.

    Args:
        params (BookmarkNameInput): Bookmark name
            - name (str): Bookmark name to remove

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.remove_bookmark(params.name)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_process_properties",
    annotations={"title": "Get Process Properties", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_process_properties() -> str:
    '''Get comprehensive properties of the debugged process.
    Equivalent to EDB's ProcessProperties plugin. Shows PID, binary path,
    arguments, entry point, register state, and more.

    Returns:
        str: Process properties
    '''
    try:
        return await backend.get_process_properties()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_dump_memory_to_file",
    annotations={"title": "Dump Memory to File", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_dump_memory_to_file(params: DumpMemoryToFileInput) -> str:
    '''Dump a memory region to a binary file on disk.
    Equivalent to EDB's memory dump feature. Useful for extracting
    code regions, data sections, or heap contents for offline analysis.

    Args:
        params (DumpMemoryToFileInput): Dump parameters
            - address (str): Start address
            - size (int): Number of bytes to dump (max: 1MB)
            - file_path (str): Full output file path

    Returns:
        str: Confirmation with byte count
    '''
    try:
        return await backend.dump_memory_to_file(params.address, params.size, params.file_path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_assemble",
    annotations={"title": "Assemble Instruction", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_assemble(params: AssembleInput) -> str:
    '''Assemble an assembly instruction and write it to memory.
    Equivalent to EDB's Assembler plugin. Uses keystone engine if available,
    otherwise falls back to common opcodes (nop, int3, ret).

    Args:
        params (AssembleInput): Assembly parameters
            - address (str): Target address
            - instruction (str): Assembly text (e.g., 'nop', 'mov eax, 0', 'jmp rax')

    Returns:
        str: Assembled bytes and confirmation
    '''
    try:
        return await backend.assemble(params.address, params.instruction)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_arch_info",
    annotations={"title": "Get Architecture Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_arch_info() -> str:
    '''Get architecture information about the debugged process and binary.
    Equivalent to EDB's BinaryInfo plugin. Shows CPU architecture, binary
    type (PIE/non-PIE), instruction set features, and more.

    Returns:
        str: Architecture details
    '''
    try:
        return await backend.get_arch_info()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"




@mcp.tool(
    name="edb_instruction_detail",
    annotations={"title": "Get Detailed Instruction Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_instruction_detail(params: InstructionDetailInput) -> str:
    '''Get detailed information about an instruction at a given address.
    Equivalent to EDB's InstructionInspector plugin. Shows instruction bytes,
    assembly, addressing modes, register operands, and more.

    Args:
        params (InstructionDetailInput): Address
            - address (str): Address to inspect (default: $pc)

    Returns:
        str: Detailed instruction info including bytes, opcode, operands
    '''
    try:
        return await backend.instruction_detail(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_dump_state",
    annotations={"title": "Dump Full Process State", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_dump_state() -> str:
    '''Dump complete debugger state: all registers, current instruction,
    stack, backtrace, memory map, and status. Equivalent to EDB's DumpState
    plugin. One-shot comprehensive process snapshot.

    Returns:
        str: Full process state dump
    '''
    try:
        return await backend.dump_state()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_stop_reason",
    annotations={"title": "Get Process Stop Reason", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_stop_reason() -> str:
    '''Determine why the process stopped (breakpoint, signal, step, etc.).
    Equivalent to EDB's status bar showing stop reason. Checks GDB's
    program state and thread status.

    Returns:
        str: Stop reason description
    '''
    try:
        return await backend.get_stop_reason()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_frame_info",
    annotations={"title": "Get Detailed Frame Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_frame_info(params: FrameInfoInput) -> str:
    '''Get detailed information about a stack frame: address, function,
    arguments, locals, frame type, and more. Equivalent to EDB's call
    stack panel showing frame details.

    Args:
        params (FrameInfoInput): Frame
            - frame_level (int): Frame level (0 = innermost, default: 0)

    Returns:
        str: Frame information with args and locals
    '''
    try:
        return await backend.get_frame_info(params.frame_level)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_catchpoint",
    annotations={"title": "Set Catchpoint", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_set_catchpoint(params: CatchpointInput) -> str:
    '''Set a catchpoint for exceptions, syscalls, signals, or process events.
    Equivalent to EDB's catchpoint feature. Stops execution when the
    specified event occurs.

    Args:
        params (CatchpointInput): Catchpoint
            - event (str): Event: throw, catch, syscall, signal, assert, exec, fork, vfork, load, unload
            - condition (str): Optional condition or syscall name/number

    Returns:
        str: Catchpoint confirmation
    '''
    try:
        return await backend.set_catchpoint(params.event, params.condition)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_signal_handling",
    annotations={"title": "Configure Signal Handling", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_signal_handling(params: SignalHandlingInput) -> str:
    '''Configure how GDB handles signals (stop, print, pass to program).
    Equivalent to EDB's signal handling in DebuggerCore. When action is
    empty, queries current handling for the signal.

    Args:
        params (SignalHandlingInput): Signal settings
            - signal (str): Signal name (e.g., SIGSEGV, SIGINT, SIGTRAP)
            - action (str): Action: stop, nostop, print, noprint, pass, nopass, ignore

    Returns:
        str: Signal handling configuration
    '''
    try:
        return await backend.signal_handling(params.signal, params.action)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_generate_core_dump",
    annotations={"title": "Generate Core Dump", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_generate_core_dump(params: CoreDumpInput) -> str:
    '''Generate a core dump of the current process for post-mortem analysis.
    Equivalent to EDB's save state feature. Saves full process memory
    and register state to a core file.

    Args:
        params (CoreDumpInput): Output
            - file_path (str): Output file path (default: core)

    Returns:
        str: Core dump confirmation with file size
    '''
    try:
        return await backend.generate_core_dump(params.file_path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_remote_connect",
    annotations={"title": "Connect to Remote GDB Server", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_remote_connect(params: RemoteConnectInput) -> str:
    '''Connect to a remote gdbserver for remote debugging.
    Equivalent to starting a new debugging session with remote target.
    Use extended mode for continuous connection.

    Args:
        params (RemoteConnectInput): Connection
            - host (str): Remote hostname or IP
            - port (int): Remote port (1-65535)
            - extended (bool): Use extended-remote mode

    Returns:
        str: Connection status
    '''
    try:
        return await backend.remote_connect(params.host, params.port, params.extended)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_signals",
    annotations={"title": "List Signal Configurations", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_signals(params: ListSignalsInput) -> str:
    '''List all signals and how GDB handles them.
    Equivalent to EDB's signal configuration view. Shows which signals
    cause stop, print notification, and are passed to the program.

    Args:
        params (ListSignalsInput): Filter
            - signal (str): Specific signal to query (default: all)

    Returns:
        str: Signal list with handling info
    '''
    try:
        return await backend.list_signals(params.signal)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_compare_sections",
    annotations={"title": "Compare Binary Sections with Memory", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_compare_sections() -> str:
    '''Compare loaded memory sections with the original binary on disk.
    Detects modifications to code sections (self-modifying code, patches).
    Equivalent to EDB's memory comparison features.

    Returns:
        str: Section comparison results
    '''
    try:
        return await backend.compare_sections()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_generate_symbols",
    annotations={"title": "Generate Binary Symbol Map", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_generate_symbols(params: GenerateSymbolsInput) -> str:
    '''Generate a symbol map for a binary file using EDB's symbol generator.
    Equivalent to running `edb --symbols <file>`. Useful for creating
    symbol map files for stripped binaries.

    Args:
        params (GenerateSymbolsInput): Input
            - path (str): Binary file path (default: loaded binary)

    Returns:
        str: Symbol map
    '''
    try:
        return await backend.generate_symbols(params.path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_reverse_step",
    annotations={"title": "Reverse Step (Step Backward)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_reverse_step(params: ReverseStepInput) -> str:
    '''Step backward in the program execution (reverse debugging).
    Requires GDB recording to be active (`target record-full`). Steps
    the program backward one or more instructions.

    Args:
        params (ReverseStepInput): Step count
            - count (int): Number of reverse steps (default: 1)

    Returns:
        str: Reverse step result
    '''
    try:
        return await backend.reverse_step(params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_reverse_continue",
    annotations={"title": "Reverse Continue (Run Backward)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_reverse_continue() -> str:
    '''Continue execution backward to the previous breakpoint or event.
    Requires GDB recording to be active (`target record-full`). Useful
    for rewinding to find where state changed.

    Returns:
        str: Reverse continue result
    '''
    try:
        return await backend.reverse_continue()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"




@mcp.tool(
    name="edb_set_working_directory",
    annotations={"title": "Set Working Directory", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_working_directory(params: WorkingDirectoryInput) -> str:
    '''Set the working directory for the debugger and debugged process.
    Equivalent to EDB's actionApplication_Working_Directory. Useful for
    programs that need to load files from a specific directory.

    Args:
        params (WorkingDirectoryInput): Directory
            - directory (str): Working directory path

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.set_working_directory(params.directory)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_configure_debugger",
    annotations={"title": "Configure Debugger Settings", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_configure_debugger(params: DebuggerConfigInput) -> str:
    '''Configure GDB debugger settings. Equivalent to EDB's Configure Debugger
    dialog. Controls follow-fork-mode, ASLR, scheduler-locking, backtrace limits,
    and many other debugger behaviors.

    Args:
        params (DebuggerConfigInput): Setting
            - setting (str): Setting name (e.g., 'follow-fork-mode', 'disable-randomization',
              'scheduler-locking', 'backtrace limit', 'print elements')
            - value (str): Value to set (empty to query, use 'on'/'off' for booleans)

    Returns:
        str: Configuration result
    '''
    try:
        return await backend.configure_debugger(params.setting, params.value)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_show_configuration",
    annotations={"title": "Show Debugger Configuration", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_show_configuration(params: ShowConfigInput) -> str:
    '''Display current debugger configuration settings.
    Uses GDB's `show` command to query various settings.

    Args:
        params (ShowConfigInput): Query
            - setting (str): Setting name (e.g., 'architecture', 'follow-fork-mode')

    Returns:
        str: Current configuration value
    '''
    try:
        return await backend.show_configuration(params.setting)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_breakpoint_export",
    annotations={"title": "Export Breakpoints to File", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_breakpoint_export(params: BreakpointFileInput) -> str:
    '''Export all breakpoints to a JSON file on disk.
    Equivalent to EDB's BreakpointManager export feature.
    Breakpoints can be reloaded later with edb_breakpoint_import.

    Args:
        params (BreakpointFileInput): Output
            - file_path (str): Full path to JSON file

    Returns:
        str: Export confirmation with count
    '''
    try:
        return await backend.breakpoint_export(params.file_path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_breakpoint_import",
    annotations={"title": "Import Breakpoints from File", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_breakpoint_import(params: BreakpointFileInput) -> str:
    '''Import breakpoints from a JSON file previously exported with
    edb_breakpoint_export. Equivalent to EDB's BreakpointManager import feature.

    Args:
        params (BreakpointFileInput): Input
            - file_path (str): Full path to JSON file

    Returns:
        str: Import confirmation with count
    '''
    try:
        return await backend.breakpoint_import(params.file_path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_view_at_address",
    annotations={"title": "View Address in CPU/Hex/Stack", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_view_at_address(params: ViewAddressInput) -> str:
    '''Navigate to and inspect an address across all views.
    Equivalent to EDB's viewInCpu() / viewInDump() / viewInStack() context
    menu actions. Shows disassembly, hex dump, register references, and
    code references for the given address.

    Args:
        params (ViewAddressInput): Address
            - address (str): Address to view (e.g., '0x400000', 'main', '$rsp')

    Returns:
        str: Combined view across all panels
    '''
    try:
        return await backend.view_at_address(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_session_save",
    annotations={"title": "Save Debugging Session", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_session_save(params: SessionFileInput) -> str:
    '''Save the complete debugging session to a JSON file.
    Equivalent to EDB's SessionManager. Saves breakpoints, bookmarks,
    comments, binary path, and arguments for later restoration.

    Args:
        params (SessionFileInput): Output
            - file_path (str): Full path to session file

    Returns:
        str: Save confirmation
    '''
    try:
        return await backend.session_save(params.file_path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_session_load",
    annotations={"title": "Load Debugging Session", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_session_load(params: SessionFileInput) -> str:
    '''Load a debugging session from a JSON file.
    Equivalent to EDB's SessionManager. Restores breakpoints, bookmarks,
    comments, binary path, and arguments from a saved session.

    Args:
        params (SessionFileInput): Input
            - file_path (str): Full path to session file

    Returns:
        str: Load confirmation with details
    '''
    try:
        return await backend.session_load(params.file_path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_send_signal",
    annotations={"title": "Send Signal to Process", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_send_signal(params: SignalSendInput) -> str:
    '''Send a signal to the debugged process.
    Equivalent to EDB's signal delivery mechanism. Can be used to send
    SIGINT (2) to interrupt, SIGTERM (15) for graceful shutdown, etc.

    Args:
        params (SignalSendInput): Signal
            - signum (int): Signal number (1-64), e.g., 2=SIGINT, 9=SIGKILL, 15=SIGTERM

    Returns:
        str: Signal delivery result
    '''
    try:
        return await backend.send_signal(params.signum)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_step_instruction",
    annotations={"title": "Step One Instruction (Assembly Level)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_step_instruction(params: StepInstructionInput) -> str:
    '''Step a single instruction (assembly-level), not a source line.
    Equivalent to EDB's action_Single_Step. Unlike edb_step_into which
    steps by source line, this steps by individual CPU instruction.

    Args:
        params (StepInstructionInput): Count
            - count (int): Number of instructions to step (default: 1)

    Returns:
        str: Step result with current instruction
    '''
    try:
        result = await backend.step_instruction(params.count)
        console = result.get("console", [])
        return "\n".join(console) if console else f"Stepped {params.count} instruction(s)"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"




@mcp.tool(
    name="edb_set_memory_permissions",
    annotations={"title": "Set Memory Region Permissions", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_memory_permissions(params: MemoryPermissionsInput) -> str:
    '''Set memory permissions for a region (read/write/execute).
    Equivalent to EDB's DialogMemoryRegions permission checkboxes.
    Uses GDB's `mem` command to define memory region attributes.

    Args:
        params (MemoryPermissionsInput): Permissions
            - address (str): Start address
            - permissions (str): Permissions: none, r, w, x, rw, rx, wx, rwx
            - size (int): Region size (default: 4096)

    Returns:
        str: Permission change confirmation
    '''
    try:
        return await backend.set_memory_permissions(params.address, params.permissions, params.size)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_plugins",
    annotations={"title": "List Debugger Plugins", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_plugins() -> str:
    '''List all available debugger plugins and capabilities.
    Equivalent to EDB's DialogPlugins. Shows EDB plugins, GDB auto-load
    scripts, and pretty-printers.

    Returns:
        str: Plugin listing with descriptions
    '''
    try:
        return await backend.list_plugins()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_fpu_state",
    annotations={"title": "Get FPU Register State", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_fpu_state() -> str:
    '''Get the FPU (Floating Point Unit) register state.
    Equivalent to EDB's RegisterViewModel FPU category. Shows ST0-ST7
    stack registers, FPU control word, status word, and tag word.

    Returns:
        str: FPU register values
    '''
    try:
        return await backend.get_fpu_state()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_simd_state",
    annotations={"title": "Get SIMD Register State", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_simd_state() -> str:
    '''Get the SIMD (SSE/AVX) register state.
    Equivalent to EDB's RegisterViewModel SIMD category. Shows XMM0-15,
    YMM0-15, ZMM0-31 registers and MXCSR control/status register.

    Returns:
        str: SIMD register values
    '''
    try:
        return await backend.get_simd_state()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_tty",
    annotations={"title": "Set Terminal for Program I/O", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_tty(params: TTYInput) -> str:
    '''Set the terminal device for the debugged program's I/O.
    Equivalent to EDB's TTY configuration in DialogOptions.
    The program's stdin/stdout/stderr will be redirected to this TTY.

    Args:
        params (TTYInput): Terminal
            - tty_path (str): TTY device path (e.g., '/dev/pts/0')

    Returns:
        str: TTY configuration result
    '''
    try:
        return await backend.set_tty(params.tty_path)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_load_symbol_file",
    annotations={"title": "Load Symbol File", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_load_symbol_file(params: SymbolFileInput) -> str:
    '''Load a symbol file for the debugged program.
    Equivalent to EDB's FasLoader plugin and GDB's symbol-file command.
    Supports ELF debug info files, FAS format, and separated debug symbols.

    Args:
        params (SymbolFileInput): Symbol file
            - file_path (str): Path to symbol file
            - address (str): Base address (for add-symbol-file with .o/.so)

    Returns:
        str: Symbol loading result
    '''
    try:
        return await backend.load_symbol_file(params.file_path, params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_memory_region_info",
    annotations={"title": "Get Memory Region Configuration", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_memory_region_info() -> str:
    '''Get information about defined memory regions and their permissions.
    Equivalent to EDB's DialogMemoryRegions detail view. Shows regions
    defined with edb_set_memory_permissions and their access attributes.

    Returns:
        str: Memory region permissions
    '''
    try:
        return await backend.get_memory_region_info()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"




@mcp.tool(
    name="edb_jump_to_address",
    annotations={"title": "Jump to Address (Set Instruction Pointer)", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_jump_to_address(params: JumpAddressInput) -> str:
    '''Jump to a specific address, setting the instruction pointer.
    Equivalent to EDB's jump_to_address (double-click address in
    BreakpointManager). Use this to skip code or continue from a
    specific location.

    Args:
        params (JumpAddressInput): Target
            - address (str): Address to jump to (e.g., '0x400000', 'main+5')

    Returns:
        str: Jump confirmation
    '''
    try:
        return await backend.jump_to_address(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_call_function",
    annotations={"title": "Call Function in Debugged Process", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_call_function(params: CallFunctionInput) -> str:
    '''Call a function in the context of the debugged process.
    Equivalent to GDB's `call` command. Useful for testing functions
    with specific arguments or calling library functions.

    Args:
        params (CallFunctionInput): Function call
            - function_expr (str): Expression (e.g., 'printf(\"hello\")', 'malloc(100)')

    Returns:
        str: Function result (return value in EAX/RAX)
    '''
    try:
        return await backend.call_function(params.function_expr)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_breakpoint_condition",
    annotations={"title": "Set Breakpoint Condition", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_breakpoint_condition(params: BreakpointConditionInput) -> str:
    '''Set or remove a condition on an existing breakpoint.
    Equivalent to EDB's DialogBreakpoints condition button.
    The breakpoint will only trigger when the condition evaluates to true.

    Args:
        params (BreakpointConditionInput): Condition
            - number (int): Breakpoint number
            - condition (str): Condition (empty to remove, e.g., 'eax == 0')

    Returns:
        str: Condition update result
    '''
    try:
        return await backend.set_breakpoint_condition(params.number, params.condition)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_breakpoint_ignore_count",
    annotations={"title": "Set Breakpoint Ignore Count", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_breakpoint_ignore_count(params: BreakpointIgnoreInput) -> str:
    '''Set the number of times a breakpoint should be ignored before stopping.
    Equivalent to GDB's `ignore` command. Useful for skipping a breakpoint
    N times (e.g., in a loop) before breaking.

    Args:
        params (BreakpointIgnoreInput): Ignore
            - number (int): Breakpoint number
            - count (int): Skip count (0 = don't skip)

    Returns:
        str: Ignore count result
    '''
    try:
        return await backend.set_breakpoint_ignore_count(params.number, params.count)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_analyze_basic_blocks",
    annotations={"title": "Analyze Basic Blocks in Region", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_analyze_basic_blocks(params: AnalyzeBasicBlocksInput) -> str:
    '''Analyze a code region and identify basic blocks.
    Equivalent to EDB's Analyzer plugin basic block detection.
    Shows each basic block with its instructions, where blocks end
    at branch/jump/call/ret instructions.

    Args:
        params (AnalyzeBasicBlocksInput): Region
            - address (str): Start address
            - size (int): Region size (default: 256)

    Returns:
        str: Basic block listing with instruction count per block
    '''
    try:
        return await backend.analyze_basic_blocks(params.address, params.size)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_generate_cfg",
    annotations={"title": "Generate Control Flow Graph (DOT Format)", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_generate_cfg(params: AnalyzeBasicBlocksInput) -> str:
    '''Generate a Control Flow Graph in Graphviz DOT format.
    Equivalent to EDB's GraphWidget (which uses Graphviz). The output
    DOT can be rendered with `dot -Tpng -o output.png` or viewed in
    any Graphviz viewer. Shows edges between basic blocks.

    Args:
        params (AnalyzeBasicBlocksInput): Region
            - address (str): Start address
            - size (int): Region size (default: 256)

    Returns:
        str: DOT format CFG
    '''
    try:
        return await backend.generate_cfg(params.address, params.size)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"




@mcp.tool(
    name="edb_set_debug_output",
    annotations={"title": "Set GDB Debug Output", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_debug_output(params: DebugOutputInput) -> str:
    '''Enable or disable GDB internal debug output.
    Equivalent to EDB's Debug Logger panel. Shows detailed GDB internals
    for troubleshooting: target events, breakpoint insertion, stepping, etc.
    Available categories: infrun, lin-lwp, remote, serial, target, event,
    expression, overlay, frame, thread.

    Args:
        params (DebugOutputInput): Debug settings
            - category (str): Debug category (empty to list available)
            - enable (bool): True=on, False=off (default: True)

    Returns:
        str: Debug output status
    '''
    try:
        return await backend.set_debug_output(params.category, params.enable)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_environment_variable",
    annotations={"title": "Set Environment Variable", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_environment_variable(params: EnvironmentInput) -> str:
    '''Set an environment variable for the debugged process.
    Equivalent to EDB's process environment configuration. Variables
    set here are passed to the program when it runs.

    Args:
        params (EnvironmentInput): Variable
            - name (str): Variable name (e.g., 'LD_PRELOAD', 'PATH')
            - value (str): Variable value

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.set_environment_variable(params.name, params.value)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_unset_environment_variable",
    annotations={"title": "Unset Environment Variable", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_unset_environment_variable(params: EnvironmentUnsetInput) -> str:
    '''Remove an environment variable from the debugged process.
    Useful for clearing variables that may affect program behavior.

    Args:
        params (EnvironmentUnsetInput): Variable name
            - name (str): Variable name to unset

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.unset_environment_variable(params.name)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_environment",
    annotations={"title": "Show Environment Variables", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_environment() -> str:
    '''Show all environment variables configured for the debugged process.
    Equivalent to EDB's process properties environment view.

    Returns:
        str: Environment variables
    '''
    try:
        return await backend.get_environment()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_set_session_logging",
    annotations={"title": "Set GDB Session Logging", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_set_session_logging(params: SessionLoggingInput) -> str:
    '''Log all GDB input/output to a file for debugging or record-keeping.
    Useful for creating session transcripts and debugging GDB interactions.

    Args:
        params (SessionLoggingInput): Logging
            - file_path (str): Log file path (default: gdb.log)
            - enable (bool): Enable (True) or disable (False) logging

    Returns:
        str: Logging status
    '''
    try:
        return await backend.set_session_logging(params.file_path, params.enable)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"





@mcp.tool(
    name="edb_ptype",
    annotations={"title": "Print Type of Expression", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_ptype(params: PtypeInput) -> str:
    '''Print the type of a variable, function, or expression.
    Equivalent to GDB's `ptype` command. Shows complete type definition
    including struct/class members, function signatures, and typedefs.

    Args:
        params (PtypeInput): Expression
            - expression (str): Expression (e.g., 'main', 'argc', 'struct stat')

    Returns:
        str: Type definition
    '''
    try:
        return await backend.ptype(params.expression)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_whatis",
    annotations={"title": "What Is Expression", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_whatis(params: PtypeInput) -> str:
    '''Print the type of an expression (short form).
    Equivalent to GDB's `whatis` command. Shows the type name without
    full definition (unlike edb_ptype).

    Args:
        params (PtypeInput): Expression
            - expression (str): Expression (e.g., 'main', 'argc')

    Returns:
        str: Type name
    '''
    try:
        return await backend.whatis(params.expression)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_breakpoint_commands",
    annotations={"title": "Set Breakpoint Commands", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_breakpoint_commands(params: BreakpointCommandsInput) -> str:
    '''Set commands to execute when a breakpoint is hit.
    Equivalent to GDB's `commands` keyword. Can run any GDB command
    including print, continue, set, etc. Useful for logging data
    without stopping.

    Args:
        params (BreakpointCommandsInput): Commands
            - number (int): Breakpoint number
            - commands (list[str]): Commands (e.g., ['print rax', 'continue'])

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.breakpoint_commands(params.number, params.commands)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_step_over_instruction",
    annotations={"title": "Step Over Instruction (Assembly Level)", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_step_over_instruction(params: StepOverInstructionInput) -> str:
    '''Step over a single instruction (assembly-level), skipping calls.
    Equivalent to GDB's `nexti` command. Unlike edb_step_over (source line)
    and edb_step_instruction (step INTO calls), this steps over calls
    at the instruction level.

    Args:
        params (StepOverInstructionInput): Count
            - count (int): Number of instructions (default: 1)

    Returns:
        str: Step result
    '''
    try:
        result = await backend.step_over_instruction(params.count)
        console = result.get("console", [])
        return "\n".join(console) if console else f"Stepped over {params.count} instruction(s)"
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_changed_registers",
    annotations={"title": "Get Changed Registers", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_changed_registers() -> str:
    '''Get all register values (shows current state, EDB-style).
    Equivalent to EDB's register view with highlighted changed values.
    Shows all CPU registers with current values.

    Returns:
        str: Register dump
    '''
    try:
        return await backend.get_changed_registers()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_source_files",
    annotations={"title": "List Source Files", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_source_files() -> str:
    '''List all source files used by the debugged program.
    Equivalent to GDB's `info sources` command. Shows compiled source
    files and their paths.

    Returns:
        str: Source file list
    '''
    try:
        return await backend.list_source_files()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_stack_arguments",
    annotations={"title": "List Stack Frame Arguments", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_stack_arguments(params: FrameRangeInput) -> str:
    '''List arguments for stack frames.
    Equivalent to EDB's stack frame panel. Shows function arguments
    for the current frame.

    Args:
        params (FrameRangeInput): Frame range
            - frame_low (int): Lowest frame (default: 0)

    Returns:
        str: Arguments per frame
    '''
    try:
        return await backend.list_stack_arguments(params.frame_low)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_features",
    annotations={"title": "List GDB Features", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_features() -> str:
    '''List GDB debugger features and capabilities.
    Shows GDB version, build configuration, and available Python modules.

    Returns:
        str: Feature list
    '''
    try:
        return await backend.list_features()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_inferior_info",
    annotations={"title": "Get Inferior/Process Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_inferior_info() -> str:
    '''Get information about all inferiors (processes) being debugged.
    Equivalent to GDB's `info inferiors` command. Shows process list,
    their PIDs, and the program they're running.

    Returns:
        str: Inferior list with details
    '''
    try:
        return await backend.inferior_info()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"




@mcp.tool(
    name="edb_stack_push",
    annotations={"title": "Push Value onto Stack", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_stack_push(params: StackPushInput) -> str:
    '''Push a value onto the program stack (decrements RSP, writes value).
    Equivalent to EDB's Stack context menu → Push. Modifies the target
    process stack and register state.

    Args:
        params (StackPushInput): Push value
            - value (str): Value to push (e.g., '0x1234', '&main')

    Returns:
        str: Result
    '''
    try:
        return await backend.stack_push(params.value)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_stack_pop",
    annotations={"title": "Pop Value from Stack", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_stack_pop() -> str:
    '''Pop a value from the program stack (reads value, increments RSP).
    Equivalent to EDB's Stack context menu → Pop. Returns the popped
    value and modifies the target process RSP register.

    Returns:
        str: Popped value and result
    '''
    try:
        return await backend.stack_pop()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_stack_modify",
    annotations={"title": "Modify Stack Top Value", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_stack_modify(params: StackModifyInput) -> str:
    '''Modify the value at the top of the stack without changing RSP.
    Equivalent to EDB's Stack context menu → Modify. Writes a new
    value to the current stack pointer location.

    Args:
        params (StackModifyInput): New value
            - value (str): New value (e.g., '0xdeadbeef')

    Returns:
        str: Result
    '''
    try:
        return await backend.stack_modify(params.value)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_label_address",
    annotations={"title": "Label an Address in Disassembly", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_label_address(params: LabelAddressInput) -> str:
    '''Set a label/annotation at an address in the disassembly view.
    Equivalent to EDB's CPU context menu → Label Address. Labels
    help identify important locations in the code.

    Args:
        params (LabelAddressInput): Address + label
            - address (str): Address (e.g., '0x401000')
            - label (str): Label text (e.g., 'my_func')

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.label_address(params.address, params.label)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_disable_aslr",
    annotations={"title": "Disable/Enable ASLR", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_disable_aslr(params: DisableASLRInput) -> str:
    '''Disable or enable ASLR for debugee.
    Equivalent to EDB's DialogOptions → Disable ASLR checkbox.
    Affects future runs of the debugged program.

    Args:
        params (DisableASLRInput): ASLR setting
            - disable (bool): True = disable ASLR, False = enable

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.set_disable_aslr(params.disable)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_disable_lazy_binding",
    annotations={"title": "Disable/Enable Lazy Binding", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": True}
)
async def edb_disable_lazy_binding(params: DisableLazyBindingInput) -> str:
    '''Disable or enable lazy binding for debugee.
    Equivalent to EDB's DialogOptions → Disable Lazy Binding checkbox.
    When disabled, all shared library symbols are resolved at startup,
    making breakpoints on library functions more reliable.

    Args:
        params (DisableLazyBindingInput): Lazy binding setting
            - disable (bool): True = disable lazy binding, False = enable

    Returns:
        str: Confirmation
    '''
    try:
        return await backend.set_disable_lazy_binding(params.disable)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_binary_string_convert",
    annotations={"title": "Convert Hex/ASCII/UTF-16 Strings", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_binary_string_convert(params: BinaryStringConvertInput) -> str:
    '''Convert between hex, ASCII, and UTF-16 representations.
    Equivalent to EDB's BinaryString widget (DialogInputBinaryString).
    Useful for preparing data for memory patches or analyzing strings.

    Provide at least one of: hex_str, ascii_str, or utf16_str.

    Args:
        params (BinaryStringConvertInput): Input string
            - hex_str (str): Hex input (e.g., '48656c6c6f')
            - ascii_str (str): ASCII input (e.g., 'Hello')
            - utf16_str (str): UTF-16 hex (e.g., '48006500')

    Returns:
        str: All representations
    '''
    try:
        return await backend.binary_string_convert(
            hex_str=params.hex_str or "",
            ascii_str=params.ascii_str or "",
            utf16_str=params.utf16_str or ""
        )
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_execute_gdb_command",
    annotations={"title": "Execute Raw GDB Command", "readOnlyHint": True, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_execute_gdb_command(params: ExecuteGdbInput) -> str:
    '''Execute any raw GDB command directly. Full access to GDB's CLI. Powerful for advanced debugging.'''
    try:
        return await backend.execute_gdb_command(params.command, params.timeout)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_follow_fork",
    annotations={"title": "Set Fork Follow Mode", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_follow_fork(params: FollowForkInput) -> str:
    '''Set whether the debugger follows the parent or child process after a fork.'''
    try:
        return await backend.follow_fork(params.mode)
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_trace_start",
    annotations={"title": "Start Execution Trace", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_trace_start(params: TraceStartInput) -> str:
    '''Start an execution trace at an address/function. Records every instruction execution.'''
    try:
        return await backend.trace_start(params.address or "", params.max_size)
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_trace_stop",
    annotations={"title": "Stop Execution Trace", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_trace_stop() -> str:
    '''Stop the current execution trace session.'''
    try:
        return await backend.trace_stop()
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_trace_show",
    annotations={"title": "Show Trace Data", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_trace_show() -> str:
    '''Show execution trace status, frames, and collected data.'''
    try:
        return await backend.trace_show()
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_scan_stack_for_retaddr",
    annotations={"title": "Scan Stack for Return Addresses", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_scan_stack_for_retaddr(params: ScanStackForRetaddrInput) -> str:
    '''Scan the stack for potential return addresses (values in valid text ranges). Useful for ROP/exploit analysis.'''
    try:
        return await backend.scan_stack_for_retaddr(params.depth)
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_watch_expression",
    annotations={"title": "Watch Expression", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_watch_expression(params: WatchExpressionInput) -> str:
    '''Add an expression to the auto-display list. Evaluated and shown on every stop.'''
    try:
        return await backend.watch_expression(params.expression)
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_apply_patches_to_file",
    annotations={"title": "Apply Memory Patches to Binary", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_apply_patches_to_file(params: ApplyPatchesInput) -> str:
    '''Write runtime memory modifications back to the binary file on disk.'''
    try:
        return await backend.apply_patches_to_file(params.output_path or "")
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_get_eflags",
    annotations={"title": "Get EFLAGS Register", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_eflags() -> str:
    '''Show the EFLAGS/RFLAGS CPU status register with individual flag states.'''
    try:
        return await backend.get_eflags()
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_compare_snapshot",
    annotations={"title": "Compare Debugger Snapshot", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}
)
async def edb_compare_snapshot(params: CompareSnapshotInput) -> str:
    '''Save a full debugger snapshot (registers + memory) for later comparison.'''
    try:
        return await backend.compare_snapshot(params.label or "")
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_pipeline",
    annotations={"title": "Pipeline: Load -> BP -> Run -> Dump", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_pipeline(params: PipelineInput) -> str:
    '''Load a binary, set breakpoint, run, and dump state in one call.'''
    try:
        return await backend.pipeline_run(
            params.binary,
            breakpoint=params.breakpoint or "",
            args=params.args or "",
            dump_registers=params.dump_registers
        )
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_export_state",
    annotations={"title": "Export Debugger State", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_export_state() -> str:
    '''Export the complete debugger state as structured JSON.'''
    try:
        return await backend.export_state()
    except GDBBackendError as e:
        return f"Error: {e}"


@mcp.tool(
    name="edb_patch_history",
    annotations={"title": "Show/Clear Patch History", "readOnlyHint": True, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}
)
async def edb_patch_history(params: PatchHistoryInput) -> str:
    '''Show all memory patches made this session, or clear the history.'''
    try:
        if params.clear:
            return await backend.clear_patch_history()
        return await backend.get_patch_history()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_binary_diff",
    annotations={"title": "Compare Binary vs Original", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_binary_diff() -> str:
    '''Compare the current loaded binary with its original on disk.'''
    try:
        return await backend.binary_diff()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_remote_arch",
    annotations={"title": "Detect Remote Target Architecture", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_remote_arch() -> str:
    '''Detect the architecture of a connected remote GDB target.'''
    try:
        return await backend.remote_arch()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_remote_info",
    annotations={"title": "Show Remote Target Info", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_remote_info() -> str:
    '''Show detailed information about the remote debugging target.'''
    try:
        return await backend.remote_info()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_exploit_generate",
    annotations={"title": "Generate BOF Exploit", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_exploit_generate(params: ExploitGenerateInput) -> str:
    '''Generate a buffer-overflow exploit payload: offset + ROP chain + shellcode.
    Supports amd64 (ret2libc ROP), i386 (ret2libc), and aarch64 (shellcode).'''
    try:
        return await backend.exploit_generate(
            params.binary, params.offset, params.cmd, params.save_path, params.arch
        )
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_get_function_xrefs",
    annotations={"title": "Get Function Cross-References", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_get_function_xrefs(params: AddressRefInput) -> str:
    '''Show cross-references to a given address or function.'''
    try:
        return await backend.get_function_xrefs(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_goto_function_start",
    annotations={"title": "Go to Function Start", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_goto_function_start(params: AddressRefInput) -> str:
    '''Find the function start address containing a given address.'''
    try:
        return await backend.goto_function_start(params.address)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_enum_registers",
    annotations={"title": "Enumerate CPU Registers", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_enum_registers() -> str:
    '''List available CPU registers by category (GPR, SIMD, FPU, flag).'''
    try:
        return await backend.enum_registers()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_process_strings",
    annotations={"title": "Scan Process for Strings", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_process_strings(params: ProcessStringsInput) -> str:
    '''Scan process memory for readable ASCII strings.'''
    try:
        return await backend.process_strings(params.min_length)
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"


@mcp.tool(
    name="edb_list_breakpoint_types",
    annotations={"title": "List Breakpoint Types", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
)
async def edb_list_breakpoint_types() -> str:
    '''List supported breakpoint types (software, hardware, watchpoint, catchpoint).'''
    try:
        return await backend.list_breakpoint_types()
    except GDBBackendError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: Unexpected error: {e}"

