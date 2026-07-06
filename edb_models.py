"""Pydantic models for EDB Debugger MCP tool parameters."""

from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class BinaryPath(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: str = Field(..., description="Absolute path to the executable binary file", min_length=1)
    args: Optional[str] = Field(default="", description="Command-line arguments to pass to the program")


class AttachPid(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    pid: int = Field(..., description="Process ID to attach to", ge=1)


class AddressInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Memory address in hex (e.g., '0x7ffff7a3d000') or symbol name")
    count: Optional[int] = Field(default=128, description="Number of bytes to read (default: 128, max: 4096)", ge=1, le=4096)


class MemoryWriteInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Memory address in hex (e.g., '0x7ffff7a3d000')")
    data: str = Field(..., description="Value to write (e.g., '0x90' for a byte, '{0x90,0x91}' for bytes)")


class MemoryWriteBytesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Memory address to write to (e.g., '0x7ffff7a3d000')")
    hex_bytes: str = Field(..., description="Hex bytes to write (e.g., '90 90 90' or '0x90 0x90')")


class BreakpointInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    location: str = Field(..., description="Breakpoint location: function name (e.g., 'main'), address (e.g., '*0x400000'), or file:line")
    condition: Optional[str] = Field(default="", description="Conditional breakpoint expression (e.g., 'x == 5')")


class BreakpointNumber(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    number: int = Field(..., description="Breakpoint ID number", ge=1)


class WatchpointInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    expression: str = Field(..., description="Expression to watch (e.g., 'x', '*0x7fff0000')")
    watch_type: str = Field(default="write", pattern="^(write|read|access)$", description="Watch type: 'write' (data written), 'read' (data read), 'access' (both)")


class RegisterName(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Register name (e.g., 'rax', 'rbx', 'rip', 'rsp', 'eflags')")


class RegisterSetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Register name (e.g., 'rax', 'rbx')")
    value: str = Field(..., description="Value to set in hex (e.g., '0x7fff00001000')")


class SearchMemoryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    pattern: str = Field(..., description="Byte pattern to search for in hex (e.g., '0x90 0x90' for NOP sled)")
    address: Optional[str] = Field(default="", description="Start address to search from (default: current $pc)")
    length: Optional[str] = Field(default="", description="Length of region to search (e.g., '0x10000')")


class SearchInstructionsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    pattern: str = Field(..., description="Instruction byte pattern to search for (e.g., '0x90 0x90')")
    range_start: Optional[str] = Field(default="", description="Start address of search range")
    range_end: Optional[str] = Field(default="", description="End address of search range")


class DisassembleInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    location: str = Field(..., description="Address or symbol to disassemble from (e.g., '0x400000', 'main')")
    count: Optional[int] = Field(default=10, description="Number of instructions to disassemble", ge=1, le=200)


class ContinueToAddress(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Target address in hex (e.g., '0x4000a0') or function name")


class SymbolLookup(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Symbol name to look up (e.g., 'main', 'printf')")


class ThreadId(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    thread_id: int = Field(..., description="Thread ID to switch to", ge=1)


class EvaluateExpr(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    expression: str = Field(..., description="Expression to evaluate (e.g., 'x + 5', '*(int*)0x7fff0000')")


class ReadStringInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address to read string from (e.g., '0x7fff0000')")
    max_length: Optional[int] = Field(default=256, description="Maximum string length", ge=1, le=4096)


class VariableInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Variable name (e.g., 'my_var', 'x', 'argv')")
    value: Optional[str] = Field(default=None, description="Value to set the variable to (for set operation)")


class SourceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    file: str = Field(..., description="Source file path")
    line: Optional[int] = Field(default=1, description="Starting line number", ge=1)
    count: Optional[int] = Field(default=20, description="Number of lines to display", ge=1, le=200)


class FunctionInfo(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Function name to get info about")


class FindReferencesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address to find references to (e.g., '0x400000')")


class StackFrameInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    frame_level: Optional[int] = Field(default=0, description="Stack frame level (0 = current)", ge=0, le=1000)


class SectionInfoInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    module: Optional[str] = Field(default="", description="Module name to get section info for (empty = all sections)")
class ReadMemoryAsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Memory address (e.g., '0x7fff0000' or symbol name)")
    data_type: str = Field(default="uint32", pattern="^(int8|uint8|int16|uint16|int32|uint32|int64|uint64|float|double|pointer|string)$", description="Data type to interpret as: int8/16/32/64, uint8/16/32/64, float, double, pointer, string")
    count: Optional[int] = Field(default=1, description="Number of elements to read", ge=1, le=256)


class NopRangeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    start_address: str = Field(..., description="Start address in hex (e.g., '0x400000')")
    end_address: str = Field(..., description="End address in hex (exclusive, e.g., '0x400010')")


class AnalyzeCallsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address to analyze for calls/jumps (e.g., '0x400000')")


class FunctionBoundsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Function name (e.g., 'main', 'helper_function')")


class FileOffsetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    offset: int = Field(..., description="File offset in bytes", ge=0)


class VirtualAddressInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Virtual address in hex (e.g., '0x400000')")


class StringRefInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    string_or_address: str = Field(..., description="String content or address to find references to")


class DisassembleRangeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    start_address: str = Field(..., description="Start address in hex (e.g., '0x400000')")
    end_address: str = Field(..., description="End address in hex (e.g., '0x400100')")


class ConditionalLogInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    location: str = Field(..., description="Breakpoint location (function, address, or file:line)")
    log_message: str = Field(..., description="Message to log when breakpoint is hit")


class FillMemoryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Start address in hex (e.g., '0x400000')")
    byte_value: str = Field(..., description="Byte value to fill with (e.g., '0x90' or '90')")
    count: int = Field(..., description="Number of bytes to fill", ge=1, le=65536)


class CompareMemoryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address1: str = Field(..., description="First address in hex (e.g., '0x400000')")
    address2: str = Field(..., description="Second address in hex (e.g., '0x400100')")
    count: int = Field(..., description="Number of bytes to compare", ge=1, le=4096)


class CommentInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address in hex (e.g., '0x400000')")
    comment: str = Field(..., description="Annotation text (e.g., 'NOP sled start')")


class AddressOnlyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address in hex (e.g., '0x400000')")
class FunctionFilterInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    filter_str: Optional[str] = Field(default="", description="Optional filter string (e.g., 'main', 'printf') to narrow results")


class RopSearchInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: Optional[str] = Field(default="", description="Start address to search (default: $pc)")
    depth: Optional[int] = Field(default=2, description="Max instructions before ret (default: 2)", ge=1, le=10)
    count: Optional[int] = Field(default=100, description="Max gadgets to return (default: 100)", ge=1, le=1000)


class AnalyzeRegionInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Start address (e.g., '0x400000' or function name)")
    size: int = Field(default=256, description="Size of region in bytes (default: 256)", ge=16, le=65536)


class DumpMemoryToFileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Start address (e.g., '0x7fff0000')")
    size: int = Field(..., description="Number of bytes to dump", ge=1, le=1048576)
    file_path: str = Field(..., description="Full path for output file (e.g., '/tmp/dump.bin')")


class AssembleInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address to write assembled bytes to (e.g., '0x400000')")
    instruction: str = Field(..., description="Assembly instruction (e.g., 'mov rax, 0', 'nop', 'jmp rax')")


class BookmarkInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Bookmark name (e.g., 'main_loop', 'vuln_func')")
    address: Optional[str] = Field(default="", description="Address to bookmark (e.g., '0x400000')")


class BookmarkNameInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Bookmark name to remove")
class InstructionDetailInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: Optional[str] = Field(default="", description="Address to inspect (default: $pc)")


class FrameInfoInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    frame_level: Optional[int] = Field(default=0, description="Frame level (0 = innermost)", ge=0, le=1000000)


class CatchpointInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    event: str = Field(..., description="Event to catch: throw, catch, syscall, signal, assert, exec, fork, vfork, load, unload")
    condition: Optional[str] = Field(default="", description="Optional condition or syscall name/number")


class SignalHandlingInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    signal: str = Field(..., description="Signal name (e.g., SIGSEGV, SIGINT, SIGTRAP)")
    action: Optional[str] = Field(default="", description="Action: stop, nostop, print, noprint, pass, nopass, ignore")


class CoreDumpInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    file_path: Optional[str] = Field(default="core", description="Output file path")


class RemoteConnectInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    host: str = Field(..., description="Remote gdbserver hostname or IP")
    port: int = Field(..., description="Remote gdbserver port", ge=1, le=65535)
    extended: Optional[bool] = Field(default=False, description="Use extended-remote mode")


class ListSignalsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    signal: Optional[str] = Field(default="", description="Specific signal to query (default: all)")


class ReverseStepInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    count: Optional[int] = Field(default=1, description="Number of reverse steps", ge=1, le=1000)


class GenerateSymbolsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    path: Optional[str] = Field(default="", description="Binary file path (default: loaded binary)")
class WorkingDirectoryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    directory: str = Field(..., description="Working directory path")


class DebuggerConfigInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    setting: str = Field(..., description="Setting name (e.g., 'follow-fork-mode', 'disable-randomization', 'scheduler-locking', 'backtrace limit', 'print elements')")
    value: Optional[str] = Field(default="", description="Value to set (empty to query current, or for boolean settings use 'on'/'off')")


class ShowConfigInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    setting: Optional[str] = Field(default="", description="Setting name to show (e.g., 'architecture', 'follow-fork-mode')")


class BreakpointFileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    file_path: str = Field(..., description="Full path to breakpoint file (JSON)")


class ViewAddressInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address to navigate to (e.g., '0x400000', 'main', '$rsp')")


class SessionFileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    file_path: str = Field(..., description="Full path to session file (JSON)")


class SignalSendInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    signum: int = Field(..., description="Signal number to send (e.g., 2 for SIGINT, 9 for SIGKILL, 15 for SIGTERM)", ge=1, le=64)


class StepInstructionInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    count: Optional[int] = Field(default=1, description="Number of instructions to step", ge=1, le=1000)
class MemoryPermissionsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Start address (e.g., '0x7ffff7a00000')")
    permissions: str = Field(..., description="Permissions: none, r, w, x, rw, rx, wx, rwx")
    size: Optional[int] = Field(default=4096, description="Region size in bytes (default: 4096)", ge=1, le=1073741824)


class SymbolFileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    file_path: str = Field(..., description="Path to symbol file (FAS, ELF, or debug link)")
    address: Optional[str] = Field(default="", description="Base address (required for add-symbol-file with .o/.so)")


class TTYInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    tty_path: str = Field(..., description="TTY device path (e.g., '/dev/pts/0')")
class JumpAddressInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address to jump to (e.g., '0x400000', 'main+5', '$rip-0x10')")


class CallFunctionInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    function_expr: str = Field(..., description="Function expression (e.g., 'printf(\"hello\")', 'malloc(100)', 'my_func(arg1, arg2)')")


class BreakpointConditionInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    number: int = Field(..., description="Breakpoint number", ge=1, le=1000000)
    condition: Optional[str] = Field(default="", description="Condition expression (empty to remove condition, e.g., 'eax == 0', 'rdi != 0')")


class BreakpointIgnoreInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    number: int = Field(..., description="Breakpoint number", ge=1, le=1000000)
    count: int = Field(..., description="Number of times to skip hitting this breakpoint", ge=0, le=1000000)


class AnalyzeBasicBlocksInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Start address (e.g., '0x400000' or function name)")
    size: Optional[int] = Field(default=256, description="Region size in bytes (default: 256)", ge=16, le=65536)
class DebugOutputInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    category: Optional[str] = Field(default="", description="Debug category: infrun, lin-lwp, remote, serial, target, event, expression, overlay, frame, thread")
    enable: Optional[bool] = Field(default=True, description="Enable (True) or disable (False)")


class EnvironmentInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Environment variable name (e.g., 'LD_PRELOAD', 'PATH', 'DISPLAY')")
    value: Optional[str] = Field(default="", description="Variable value")


class EnvironmentUnsetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(..., description="Environment variable name to unset")


class SessionLoggingInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    file_path: Optional[str] = Field(default="gdb.log", description="Log file path")
    enable: Optional[bool] = Field(default=True, description="Enable (True) or disable (False) logging")
class PtypeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    expression: str = Field(..., description="Expression or variable name (e.g., 'main', 'argc', 'struct stat', 'int*')")


class BreakpointCommandsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    number: int = Field(..., description="Breakpoint number", ge=1, le=1000000)
    commands: list[str] = Field(..., description="List of GDB commands to execute on hit (e.g., ['print rax', 'print rbx', 'continue'])")


class StepOverInstructionInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    count: Optional[int] = Field(default=1, description="Number of instructions to step over", ge=1, le=1000)


class FrameRangeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    frame_low: Optional[int] = Field(default=0, description="Lowest frame (default: 0)")
class StackPushInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    value: str = Field(..., description="Value to push onto the stack (e.g., '0x1234', '1234', '&main')")

class StackModifyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    value: str = Field(..., description="New value for stack top (e.g., '0xdeadbeef', '&function')")

class LabelAddressInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    address: str = Field(..., description="Address to label (e.g., '0x401000', 'main+5')")
    label: str = Field(..., description="Label text (e.g., 'my_function', 'loop_start')")

class DisableASLRInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    disable: bool = Field(..., description="True = disable ASLR, False = enable ASLR")

class DisableLazyBindingInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    disable: bool = Field(..., description="True = disable lazy binding, False = enable lazy binding")

class BinaryStringConvertInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    hex_str: Optional[str] = Field(default=None, description="Hex string (e.g., '48656c6c6f' or '48 65 6c 6c 6f' or '\\x48\\x65\\x6c\\x6c\\x6f')")
    ascii_str: Optional[str] = Field(default=None, description="ASCII string (e.g., 'Hello')")
    utf16_str: Optional[str] = Field(default=None, description="UTF-16 hex string (e.g., '480065006c006c006f00')")
