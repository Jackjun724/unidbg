package com.github.unidbg.mcp;

import capstone.api.Instruction;
import capstone.api.RegsAccess;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.Family;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.TraceHook;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.Cpsr;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.Task;
import com.github.unidbg.unwind.Frame;
import com.github.unidbg.unwind.Unwinder;
import com.github.unidbg.utils.Inspector;
import com.github.zhkl0228.demumble.DemanglerFactory;
import com.github.zhkl0228.demumble.GccDemangler;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.List;
import java.util.Map;

public class McpTools {

    private final Emulator<?> emulator;
    private final McpServer server;
    private final List<CustomTool> customTools = new ArrayList<>();
    private final Map<Long, Allocation> allocatedBlocks = new LinkedHashMap<>();
    private TraceHook activeTraceCode;
    private TraceHook activeTraceRead;
    private TraceHook activeTraceWrite;

    private static class Allocation {
        final MemoryBlock block;
        final boolean runtime;
        final int size;
        Allocation(MemoryBlock block, boolean runtime, int size) {
            this.block = block;
            this.runtime = runtime;
            this.size = size;
        }
    }

    public McpTools(Emulator<?> emulator, McpServer server) {
        this.emulator = emulator;
        this.server = server;
    }

    public void addCustomTool(String name, String description, String... paramNames) {
        customTools.add(new CustomTool(name, description, paramNames));
    }

    public JSONArray getToolSchemas() {
        JSONArray tools = new JSONArray();
        tools.add(toolSchema("check_connection", "Check emulator status. Returns: architecture, backend type and capabilities, process name, debug idle (true=paused/ready, false=running), " +
                "isRunning (true=emulation in progress, cannot call call_function), breakpoint count, pending events, and modules. " +
                "Call this first to understand current state and backend limitations. " +
                "Backend capabilities vary: " +
                "Unicorn/Unicorn2: full support (unlimited breakpoints, code/read/write hooks, single-step, write hook reports size+value). " +
                "Hypervisor (macOS): hardware breakpoints (limited count), 1 code hook at a time, write hook cannot report size/value, single-step supported. " +
                "Dynarmic/KVM: breakpoints only, no code/read/write hooks, no single-step — trace_code/trace_read/trace_write/step_into/step_over will NOT work."));
        tools.add(toolSchema("read_memory", "Read memory at address and return hex dump",
                param("address", "string", "Hex address, e.g. 0x40001000"),
                param("size", "integer", "Number of bytes to read, default 0x70")));
        tools.add(toolSchema("write_memory", "Write bytes to memory at the given address. Data is provided as a hex-encoded string.",
                param("address", "string", "Hex address, e.g. \"0x12c5f000\""),
                param("hex_bytes", "string", "Hex-encoded bytes to write, e.g. \"48656c6c6f\" writes 5 bytes [0x48,0x65,0x6c,0x6c,0x6f]. Also accepts parameter names: data, hex_data, bytes.")));
        tools.add(toolSchema("list_memory_map", "List all memory mapped regions with base, size and permissions"));
        tools.add(toolSchema("search_memory", "Search for byte pattern or text string in memory. " +
                        "Supports: (1) hex byte pattern with optional ?? wildcards (e.g. '48656c6c6f', 'ff??00??ab'), " +
                        "(2) text string search (set type='string'). " +
                        "Search scope: specify module_name to search within a module, or start+end for a specific range, " +
                        "or scope='stack' to search the stack (from SP to stack base), " +
                        "or scope='heap' with permission to search heap memory by permission, " +
                        "or omit all to search all readable mapped memory.",
                param("pattern", "string", "The pattern to search. For hex: hex bytes, ?? for wildcard. For string: the text to find."),
                param("type", "string", "Optional. 'hex' (default) or 'string'. If 'string', pattern is treated as UTF-8 text."),
                param("module_name", "string", "Optional. Search only within this module."),
                param("start", "string", "Optional. Hex start address."),
                param("end", "string", "Optional. Hex end address."),
                param("scope", "string", "Optional. 'stack' to search stack only, 'heap' to search heap by permission. Omit for default behavior."),
                param("permission", "string", "Optional. Used with scope='heap'. 'read', 'write', or 'execute'. Default 'write'."),
                param("max_results", "integer", "Optional. Max matches to return. Default 50.")));

        tools.add(toolSchema("get_registers", "Read all general purpose registers"));
        tools.add(toolSchema("get_register", "Read a specific register by name",
                param("name", "string", "Register name, e.g. X0, R0, SP, PC, LR")));
        tools.add(toolSchema("set_register", "Write a value to a specific register",
                param("name", "string", "Register name"),
                param("value", "string", "Hex value to write")));

        tools.add(toolSchema("disassemble", "Disassemble instructions at address. To disassemble at current PC, first use get_register to read PC value. " +
                        "Branch targets (bl, b, cbz, etc.) are automatically annotated with the nearest symbol name when available, " +
                        "e.g. 'bl #0x12a38770  ; memset'.",
                param("address", "string", "Hex address to disassemble at"),
                param("count", "integer", "Number of instructions to disassemble, default 10")));
        tools.add(toolSchema("assemble", "Assemble instruction text to machine code hex (does not write to memory)",
                param("assembly", "string", "Assembly instruction text, e.g. 'mov x0, #1'"),
                param("address", "string", "Hex address for PC-relative encoding, default 0")));
        tools.add(toolSchema("patch", "Assemble instruction and write to memory at address",
                param("address", "string", "Hex address to patch"),
                param("assembly", "string", "Assembly instruction text")));
        tools.add(toolSchema("add_breakpoint", "Add a breakpoint at address. Optionally set as temporary (auto-removed after first hit).",
                param("address", "string", "Hex address"),
                param("temporary", "boolean", "If true, breakpoint is removed automatically after first hit. Default false.")));
        tools.add(toolSchema("remove_breakpoint", "Remove breakpoint at address",
                param("address", "string", "Hex address")));
        tools.add(toolSchema("list_breakpoints", "List all currently set breakpoints with address, module info, temporary status and disassembly of the instruction at each breakpoint address"));
        tools.add(toolSchema("add_breakpoint_by_symbol", "Add a breakpoint at a symbol in a module. Saves the two-step process of find_symbol + add_breakpoint.",
                param("module_name", "string", "Module name, e.g. libnative.so"),
                param("symbol_name", "string", "Symbol name, e.g. JNI_OnLoad, _Z3foov"),
                param("temporary", "boolean", "If true, breakpoint is removed automatically after first hit. Default false.")));
        tools.add(toolSchema("add_breakpoint_by_offset", "Add a breakpoint at a module base + offset. Convenient when working with IDA/Ghidra offsets.",
                param("module_name", "string", "Module name, e.g. libnative.so"),
                param("offset", "string", "Hex offset from module base, e.g. 0x1234"),
                param("temporary", "boolean", "If true, breakpoint is removed automatically after first hit. Default false.")));
        tools.add(toolSchema("continue_execution", "Resume emulator execution. " +
                "If paused at a breakpoint, continues from current PC. " +
                "If emulation has completed, re-runs the emulation from the beginning. " +
                "Returns immediately; use poll_events to receive execution_started, breakpoint_hit, or execution_completed events."));
        tools.add(toolSchema("step_over", "Step over current instruction (does not enter function calls). " +
                "Sets a temporary breakpoint at the next instruction and resumes. Use poll_events to wait for completion."));
        tools.add(toolSchema("step_into", "Step into: execute specified number of instructions then stop. Use poll_events to wait for completion.",
                param("count", "integer", "Number of instructions to execute. Default 1.")));
        tools.add(toolSchema("step_out", "Step out of current function. Reads the LR (link register), sets a temporary breakpoint at that address, " +
                "and continues execution. Equivalent to 'run until function returns'. Use poll_events to wait for the breakpoint_hit event."));
        tools.add(toolSchema("stop_emulation", "Force stop the emulator immediately. Use when emulation is stuck in an infinite loop or " +
                "running too long. This is a safety mechanism — the emulator will stop and return to debug idle state."));
        tools.add(toolSchema("next_block", "Resume execution and break at the start of the next basic block. " +
                "A basic block is a straight-line sequence of instructions with no branches except at the end. " +
                "This is useful for quickly skipping the rest of the current block. " +
                "Only supported on Unicorn/Unicorn2 backends — will fail on Hypervisor/Dynarmic/KVM. " +
                "Use poll_events to wait for the breakpoint_hit event."));
        tools.add(toolSchema("step_until_mnemonic", "Resume execution and break when an instruction with the specified mnemonic is about to execute. " +
                        "For example, use mnemonic='bl' to stop at the next BL (branch with link / function call) instruction, " +
                        "or 'ret' to stop at the next RET instruction. " +
                        "This works by enabling per-instruction code hooks internally, so it may be slower than normal execution. " +
                        "Only supported on Unicorn/Unicorn2 backends (requires setFastDebug) — will fail on Hypervisor/Dynarmic/KVM. " +
                        "Use poll_events to wait for the breakpoint_hit event.",
                param("mnemonic", "string", "The instruction mnemonic to break on, e.g. 'bl', 'blx', 'ret', 'svc', 'brk'. Case-sensitive, use lowercase.")));
        tools.add(toolSchema("poll_events", "Poll for runtime events. Event types: " +
                "execution_started (emulation began), execution_completed (emulation finished), breakpoint_hit (breakpoint triggered with pc/module/offset), " +
                "trace_code (instruction executed), trace_read (memory read), trace_write (memory write). " +
                "Call this after continue_execution/step_over/step_into to wait for results. " +
                "Returns all pending events, or waits up to timeout_ms for at least one event.",
                param("timeout_ms", "integer", "Max milliseconds to wait for events. Default 10000 (10s). Set 0 for no wait.")));

        tools.add(toolSchema("trace_read", "Start tracing memory reads in address range. Each memory read triggers a trace_read event (with pc, address, size, hex, module, offset) collected via poll_events. Trace is automatically removed when a breakpoint hits, single-step completes, or execution finishes.",
                param("begin", "string", "Hex start address"),
                param("end", "string", "Hex end address"),
                param("break_on", "string", "Optional. Hex address condition: when a read hits this exact address, the emulator pauses into debug state (like a conditional breakpoint). Omit to collect events only without pausing.")));
        tools.add(toolSchema("trace_write", "Start tracing memory writes in address range. Each memory write triggers a trace_write event (with pc, address, size, value, module, offset) collected via poll_events. Note: on Hypervisor backend, size and value may be 0 due to backend limitation; use disassemble on the pc to determine write size from the instruction (e.g. STR=4/8 bytes, STRB=1, STRH=2, STP=16), then set a breakpoint or step_into to pause after the write and use read_memory to inspect. Trace is automatically removed when a breakpoint hits, single-step completes, or execution finishes.",
                param("begin", "string", "Hex start address"),
                param("end", "string", "Hex end address"),
                param("break_on", "string", "Optional. Hex address condition: when a write hits this exact address, the emulator pauses into debug state (like a conditional breakpoint). Omit to collect events only without pausing.")));
        tools.add(toolSchema("trace_code", "Start tracing instruction execution in address range. Each executed instruction triggers a trace_code event collected via poll_events. " +
                        "Event fields: address, mnemonic, operands, size, module, offset, " +
                        "regs_read (register values read by this instruction BEFORE execution), " +
                        "prev_write (register values written by the PREVIOUS instruction AFTER execution). " +
                        "This makes the trace self-contained — you can follow data flow without separate register reads. " +
                        "Useful for understanding execution flow, data dependencies and control transfer. " +
                        "Trace is automatically removed when a breakpoint hits, single-step completes, or execution finishes.",
                param("begin", "string", "Hex start address"),
                param("end", "string", "Hex end address"),
                param("break_on", "string", "Optional. Hex PC address condition: when execution reaches this exact address, the emulator pauses into debug state (like a conditional breakpoint). Omit to collect events only without pausing.")));
        tools.add(toolSchema("get_callstack", "Get the current call stack (backtrace). Returns each frame with PC address, module name, offset, and nearest symbol name if available. Only meaningful when the emulator is paused (breakpoint or single-step)."));
        tools.add(toolSchema("find_symbol", "Find symbol by name in a module, or find the nearest symbol to an address. " +
                "Provide module_name + symbol_name to look up a symbol's address. " +
                "Provide address to find the nearest symbol at that address. " +
                "Note: unidbg only has dynamic/exported symbols from ELF .dynsym; many symbols visible in IDA (from .symtab or DWARF) may not be found here. " +
                "If a symbol is not found, use module base + offset from IDA/disassembler to calculate the address directly.",
                param("module_name", "string", "Optional. Module name to search in, e.g. libnative.so"),
                param("symbol_name", "string", "Optional. Symbol name to find, e.g. JNI_OnLoad, _Z3foov"),
                param("address", "string", "Optional. Hex address to find nearest symbol for")));
        tools.add(toolSchema("read_string", "Read a null-terminated C string (UTF-8) from memory at address. Useful for reading strings pointed to by registers or memory.",
                param("address", "string", "Hex address to read string from"),
                param("max_length", "integer", "Max bytes to read before giving up. Default 256.")));
        tools.add(toolSchema("read_std_string", "Read a C++ std::string (libc++ layout) from memory. " +
                        "Parses the SSO (Small String Optimization) or heap-allocated layout automatically. " +
                        "The address should point to the std::string object itself (not the data pointer). " +
                        "Returns the string value, data size, storage type (SSO/heap), and hex dump of the data.",
                param("address", "string", "Hex address of the std::string object")));
        tools.add(toolSchema("read_pointer", "Read pointer value(s) at address, optionally following a pointer chain. " +
                        "Useful for traversing data structures like ObjC isa chains, vtables, linked lists, etc. " +
                        "Each level dereferences the pointer and reads the next value. " +
                        "Returns each level's address, pointer value, module info, and nearest symbol.",
                param("address", "string", "Hex address to read pointer from"),
                param("depth", "integer", "Optional. Number of levels to follow the pointer chain. Default 1 (just read one pointer)."),
                param("offset", "integer", "Optional. Byte offset to add at each dereference level. Default 0. E.g. offset=8 reads *(ptr+8) at each level.")));
        tools.add(toolSchema("read_typed", "Read memory as typed values. Interprets raw bytes as the specified data type. " +
                        "Supports: int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, pointer. " +
                        "For pointer type, also shows module+offset and nearest symbol for each value.",
                param("address", "string", "Hex address to read from"),
                param("type", "string", "Data type: int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, pointer"),
                param("count", "integer", "Optional. Number of elements to read. Default 1.")));
        tools.add(toolSchema("call_function", "Call a native function at the given address with arguments and return the result. " +
                        "IMPORTANT: Cannot be called while emulator is running (isRunning=true). " +
                        "The function executes synchronously and may fail with any exception (crash, invalid memory, etc). " +
                        "You can set up trace_code/trace_read/trace_write BEFORE calling this tool — " +
                        "traces will be active during the function execution, and trace events can be retrieved via poll_events after call_function returns. " +
                        "Arguments are passed via args array. Each element MUST be a string (not a number). Types:\n" +
                        "  - Hex integer: \"0x1234\" or \"1234\" (BOTH are parsed as hexadecimal. \"128\" = 0x128 = 296 decimal, NOT 128 decimal. For decimal 128, use \"0x80\")\n" +
                        "  - C string: \"s:hello world\" (auto-allocated in memory, pointer passed as arg)\n" +
                        "  - Byte array: \"b:48656c6c6f\" (hex-encoded bytes, auto-allocated, pointer passed)\n" +
                        "  - Null pointer: \"null\"\n" +
                        "Examples: calloc(1, 256) = args: [\"0x1\", \"0x100\"], memset(ptr, 0, 64) = args: [\"0x12c5f000\", \"0x0\", \"0x40\"], puts(msg) = args: [\"s:hello\"]. " +
                        "Return value is the function's return (X0 on ARM64, R0 on ARM32). " +
                        "If the return value looks like a pointer, the tool automatically shows module+symbol info, " +
                        "attempts to read it as a C string, and shows a hex dump preview.",
                param("address", "string", "Hex address of the function to call"),
                argsParam("Optional. Array of argument strings. MUST be strings, not numbers. E.g. [\"0x1\", \"0x100\", \"s:hello\", \"null\"]"),
                param("preview_size", "integer", "Optional. Number of bytes to hex-dump at the return address when it looks like a pointer. Default 64. Set 0 to disable preview.")));

        tools.add(toolSchema("call_symbol", "Call a named exported function by module and symbol name. " +
                        "Resolves the symbol address automatically, saving a separate find_symbol + call_function workflow. " +
                        "IMPORTANT: Cannot be called while emulator is running (isRunning=true). " +
                        "Arguments follow the same format as call_function.",
                param("module_name", "string", "Module name containing the symbol, e.g. 'libc.so'"),
                param("symbol_name", "string", "Exported symbol name, e.g. 'malloc', 'memset'. For ELF: prefix with '_' is optional."),
                argsParam("Optional. Array of argument strings, same format as call_function. E.g. [\"0x100\"] for malloc(256)."),
                param("preview_size", "integer", "Optional. Number of bytes to hex-dump at the return address. Default 64. Set 0 to disable.")));

        tools.add(toolSchema("list_modules", "List all loaded modules with name, base address and size. Optionally filter by name.",
                param("filter", "string", "Optional. Filter modules by name (case-insensitive substring match). E.g. 'libc' matches 'libc.so', 'libcrypto.so', etc.")));
        tools.add(toolSchema("get_module_info", "Get detailed information about a loaded module including exported symbol count",
                param("module_name", "string", "Module name, e.g. libnative.so")));
        tools.add(toolSchema("list_exports", "List exported/dynamic symbols of a module. Useful for discovering available functions. " +
                        "Returns symbol name, address, and demangled name (for C++ symbols). " +
                        "Note: only dynamic symbols (.dynsym for ELF, export trie for Mach-O) are available.",
                param("module_name", "string", "Module name, e.g. libnative.so"),
                param("filter", "string", "Optional. Filter symbols by name (case-insensitive substring match). E.g. 'jni' to find JNI-related symbols.")));
        tools.add(toolSchema("get_threads", "List all threads/tasks in the emulator with their IDs and status."));
        tools.add(toolSchema("allocate_memory", "Allocate a block of readable+writable memory in the emulator. " +
                        "Returns the base address of the allocated region. Useful for preparing complex data structures " +
                        "or buffers before calling call_function. Use free_memory to release when done.\n" +
                        "Optionally, pass 'data' (hex-encoded bytes) to fill the allocated memory immediately, " +
                        "saving a separate write_memory call. If 'data' is provided without 'size', " +
                        "the size is inferred from the data length.\n" +
                        "Allocation strategy depends on emulator state:\n" +
                        "- When isRunning=true: MUST use runtime=true (mmap). Cannot call libc malloc while emulator is executing.\n" +
                        "- When isRunning=false (default): uses runtime=false (libc malloc), which allocates from the heap " +
                        "like a normal program would. You can also pass runtime=true to force mmap.\n" +
                        "mmap allocates page-aligned memory (wastes space for small allocations); malloc is more efficient for small buffers.",
                param("size", "integer", "Number of bytes to allocate. If omitted and 'data' is provided, inferred from data length."),
                param("data", "string", "Optional. Hex-encoded bytes to write into the allocated memory, e.g. \"48656c6c6f\" for \"Hello\". " +
                        "If provided, the data is written starting at the base address immediately after allocation."),
                param("runtime", "boolean", "Optional. true=use mmap (page-aligned, always safe), false=use libc malloc (heap, more efficient, requires isRunning=false). " +
                        "Default: true when isRunning, false when stopped.")));
        tools.add(toolSchema("free_memory", "Free a previously allocated memory block. Only blocks allocated via allocate_memory can be freed. " +
                        "Blocks allocated with malloc (runtime=false) will call libc free() — requires isRunning=false. " +
                        "Blocks allocated with mmap (runtime=true) will call munmap — safe in any state.",
                param("address", "string", "Hex address of the allocated block to free (as returned by allocate_memory)")));
        tools.add(toolSchema("list_allocations", "List all memory blocks allocated via allocate_memory that have not been freed yet."));

        if (emulator.getFamily() == Family.iOS) {
            tools.add(toolSchema("dump_objc_class", "Dump an Objective-C class definition including properties, instance methods, class methods, protocols, and ivars. " +
                            "IMPORTANT: Cannot be called while emulator is running (isRunning=true). " +
                            "LIMITATIONS:\n" +
                            "1) iOS ONLY — this tool is not available on Android emulators.\n" +
                            "2) Requires the ObjC runtime to be loaded. A 'libclassdump' helper dylib is auto-loaded on first use.\n" +
                            "3) The class must exist in the ObjC runtime (already registered). Use search_objc_classes to discover class names.\n" +
                            "4) Internally calls ObjC runtime methods, which WILL modify emulator state (registers, stack). " +
                            "Save/restore registers manually if needed.\n" +
                            "5) The class name must be the exact Objective-C class name (e.g. 'NSString', 'UIViewController').",
                    param("class_name", "string", "Exact Objective-C class name, e.g. 'NSString', 'UIViewController', 'MyCustomClass'")));
        }

        if (emulator.getFamily() == Family.iOS && emulator.is64Bit()) {
            tools.add(toolSchema("dump_gpb_protobuf", "Dump a GPB (Google Protobuf for Objective-C) message class definition as .proto format. " +
                            "IMPORTANT: Cannot be called while emulator is running (isRunning=true). " +
                            "IMPORTANT LIMITATIONS:\n" +
                            "1) iOS 64-bit ONLY — this tool is not available on Android emulators.\n" +
                            "2) Requires the Google Protobuf Objective-C runtime (GPB) library to be loaded in the process.\n" +
                            "3) The class must be a GPBMessage subclass that responds to the 'descriptor' ObjC selector.\n" +
                            "4) Only dumps the message DEFINITION (field names, types, numbers) — NOT the actual data/contents of any message instance.\n" +
                            "5) Internally calls ObjC runtime methods, which WILL modify emulator state (registers, stack). " +
                            "Save/restore registers manually if needed.\n" +
                            "6) The class name must be the exact Objective-C class name (e.g. 'MyApp_SearchRequest', not the proto message name).\n" +
                            "Use list_exports or search_memory to discover GPB class names (they typically have a 'GPB' prefix or contain 'Root' suffix for root classes).",
                    param("class_name", "string", "Exact Objective-C GPBMessage subclass name, e.g. 'GPBStruct', 'MyApp_SearchRequest'")));
        }

        for (CustomTool ct : customTools) {
            JSONObject schema = new JSONObject(true);
            schema.put("name", ct.name);
            schema.put("description", "[Custom] " + ct.description + ". Triggers target function execution (library already loaded). Set breakpoints/traces BEFORE calling, then poll_events for results.");
            schema.put("inputSchema", buildInputSchema(ct.paramNames));
            tools.add(schema);
        }
        return tools;
    }

    public JSONObject callTool(String name, JSONObject args) {
        if (isExecutionTool(name)) {
            return dispatchTool(name, args);
        }
        if (!server.isDebugIdle()) {
            return errorResult("Emulator is not in debug idle state. Tools can only be called when emulator is stopped at a breakpoint.");
        }
        return server.runOnDebuggerThread(() -> dispatchTool(name, args));
    }

    private boolean isExecutionTool(String name) {
        if ("continue_execution".equals(name)) return true;
        if ("step_over".equals(name)) return true;
        if ("step_into".equals(name)) return true;
        if ("step_out".equals(name)) return true;
        if ("stop_emulation".equals(name)) return true;
        if ("next_block".equals(name)) return true;
        if ("step_until_mnemonic".equals(name)) return true;
        if ("poll_events".equals(name)) return true;
        if ("check_connection".equals(name)) return true;
        for (CustomTool ct : customTools) {
            if (ct.name.equals(name)) return true;
        }
        return false;
    }

    private JSONObject dispatchTool(String name, JSONObject args) {
        switch (name) {
            case "check_connection": return checkConnection();
            case "read_memory": return readMemory(args);
            case "write_memory": return writeMemory(args);
            case "list_memory_map": return listMemoryMap();
            case "search_memory": return searchMemory(args);
            case "get_registers": return getRegisters();
            case "get_register": return getRegister(args);
            case "set_register": return setRegister(args);
            case "disassemble": return disassemble(args);
            case "assemble": return assemble(args);
            case "patch": return patch(args);
            case "add_breakpoint": return addBreakpoint(args);
            case "add_breakpoint_by_symbol": return addBreakpointBySymbol(args);
            case "add_breakpoint_by_offset": return addBreakpointByOffset(args);
            case "remove_breakpoint": return removeBreakpoint(args);
            case "list_breakpoints": return listBreakpoints();
            case "continue_execution": return continueExecution();
            case "step_over": return stepOver();
            case "step_into": return stepInto(args);
            case "step_out": return stepOut();
            case "stop_emulation": return stopEmulation();
            case "next_block": return nextBlock();
            case "step_until_mnemonic": return stepUntilMnemonic(args);
            case "poll_events": return pollEvents(args);
            case "trace_read": return traceRead(args);
            case "trace_write": return traceWrite(args);
            case "trace_code": return traceCode(args);
            case "get_callstack": return getCallstack();
            case "find_symbol": return findSymbol(args);
            case "read_string": return readString(args);
            case "read_std_string": return readStdString(args);
            case "read_pointer": return readPointer(args);
            case "read_typed": return readTyped(args);
            case "call_function": return callFunction(args);
            case "call_symbol": return callSymbol(args);
            case "list_modules": return listModules(args);
            case "get_module_info": return getModuleInfo(args);
            case "list_exports": return listExports(args);
            case "get_threads": return getThreads();
            case "allocate_memory": return allocateMemory(args);
            case "free_memory": return freeMemory(args);
            case "list_allocations": return listAllocations();
            case "dump_objc_class": return dumpObjcClass(args);
            case "dump_gpb_protobuf": return dumpGpbProtobuf(args);
            default:
                for (CustomTool ct : customTools) {
                    if (ct.name.equals(name)) {
                        return executeCustomTool(ct, args);
                    }
                }
                return errorResult("Unknown tool: " + name);
        }
    }

    private JSONObject checkConnection() {
        StringBuilder sb = new StringBuilder();
        sb.append("Connected to unidbg emulator\n");
        Family family = emulator.getFamily();
        sb.append("Family: ").append(family.name()).append('\n');
        sb.append("Architecture: ").append(emulator.is64Bit() ? "ARM64" : "ARM32").append('\n');
        String backendClass = emulator.getBackend().getClass().getSimpleName();
        sb.append("Backend: ").append(backendClass).append('\n');
        sb.append("Backend capabilities: ").append(getBackendCapabilities(backendClass)).append('\n');
        sb.append("Process: ").append(emulator.getProcessName()).append('\n');
        sb.append("PID: ").append(emulator.getPid()).append('\n');
        sb.append("Page size: 0x").append(Long.toHexString(emulator.getPageAlign())).append('\n');
        sb.append("Debug idle: ").append(server.isDebugIdle()).append('\n');
        sb.append("Is running: ").append(emulator.isRunning()).append('\n');
        sb.append("Breakpoints: ").append(emulator.attach().getBreakPoints().size()).append('\n');
        sb.append("Pending events: ").append(server.getPendingEventCount()).append('\n');
        Collection<Module> modules = emulator.getMemory().getLoadedModules();
        sb.append("Loaded modules: ").append(modules.size()).append('\n');
        for (Module m : modules) {
            sb.append("  ").append(m.name).append(" @ 0x").append(Long.toHexString(m.base)).append('\n');
        }
        return textResult(sb.toString());
    }

    private static String getBackendCapabilities(String backendClass) {
        if (backendClass.contains("Unicorn")) {
            return "FULL — unlimited breakpoints, code/read/write trace, single-step, block hook (next_block), " +
                    "per-instruction hook (step_until_mnemonic), write trace reports size+value";
        } else if (backendClass.contains("Hypervisor")) {
            return "PARTIAL — hardware breakpoints (limited count), 1 code trace at a time, read/write trace via watchpoints (limited count), " +
                    "write trace cannot report size/value, single-step supported, " +
                    "NO block hook (next_block unavailable), NO per-instruction hook (step_until_mnemonic unavailable)";
        } else if (backendClass.contains("Dynarmic") || backendClass.contains("Kvm")) {
            return "MINIMAL — breakpoints only, NO code/read/write trace, NO single-step, NO block hook, NO per-instruction hook " +
                    "(trace_code/trace_read/trace_write/step_into/step_over/next_block/step_until_mnemonic unavailable)";
        }
        return "unknown";
    }

    private JSONObject readMemory(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        int size = args.containsKey("size") ? args.getIntValue("size") : 0x70;
        try {
            byte[] data = emulator.getBackend().mem_read(address, size);
            String dump = Inspector.inspectString(data, "0x" + Long.toHexString(address));
            return textResult(dump);
        } catch (Exception e) {
            return errorResult("Failed to read memory at 0x" + Long.toHexString(address) + ": " + exMsg(e));
        }
    }

    private JSONObject writeMemory(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        String hexBytes = args.getString("hex_bytes");
        if (hexBytes == null) hexBytes = args.getString("data");
        if (hexBytes == null) hexBytes = args.getString("hex_data");
        if (hexBytes == null) hexBytes = args.getString("bytes");
        if (hexBytes == null) {
            return errorResult("Missing required parameter. Use 'hex_bytes' (hex encoded string, e.g. \"48656c6c6f\"). " +
                    "Also accepts aliases: 'data', 'hex_data', 'bytes'.");
        }
        try {
            byte[] data = Hex.decodeHex(hexBytes.toCharArray());
            emulator.getBackend().mem_write(address, data);
            return textResult("Written " + data.length + " bytes to 0x" + Long.toHexString(address));
        } catch (DecoderException e) {
            return errorResult("Invalid hex string: \"" + hexBytes + "\". Expected hex-encoded bytes, e.g. \"48656c6c6f\" for \"Hello\".");
        } catch (Exception e) {
            return errorResult("Failed to write memory at 0x" + Long.toHexString(address) + ": " + exMsg(e));
        }
    }

    private JSONObject listMemoryMap() {
        Collection<MemoryMap> maps = emulator.getMemory().getMemoryMap();
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-18s %-18s %-10s %s%n", "Base", "End", "Size", "Perm"));
        for (MemoryMap map : maps) {
            String perm = permString(map.prot);
            sb.append(String.format("0x%016x 0x%016x 0x%-8x %s%n",
                    map.base, map.base + map.size, map.size, perm));
        }
        return textResult(sb.toString());
    }

    private JSONObject searchMemory(JSONObject args) {
        String patternStr = args.getString("pattern");
        String type = args.containsKey("type") ? args.getString("type") : "hex";
        String moduleName = args.getString("module_name");
        String startStr = args.getString("start");
        String endStr = args.getString("end");
        String scope = args.getString("scope");
        String permission = args.getString("permission");
        int maxResults = args.containsKey("max_results") ? args.getIntValue("max_results") : 50;

        byte[] patternBytes;
        byte[] maskBytes;
        try {
            if ("string".equalsIgnoreCase(type)) {
                patternBytes = patternStr.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                maskBytes = null;
            } else {
                String hex = patternStr.replace(" ", "");
                if (hex.length() % 2 != 0) {
                    return errorResult("Hex pattern must have even number of characters: " + patternStr);
                }
                int byteLen = hex.length() / 2;
                patternBytes = new byte[byteLen];
                maskBytes = new byte[byteLen];
                boolean hasMask = false;
                for (int i = 0; i < byteLen; i++) {
                    String byteStr = hex.substring(i * 2, i * 2 + 2);
                    if ("??".equals(byteStr)) {
                        patternBytes[i] = 0;
                        maskBytes[i] = 0;
                        hasMask = true;
                    } else {
                        patternBytes[i] = (byte) Integer.parseInt(byteStr, 16);
                        maskBytes[i] = (byte) 0xFF;
                    }
                }
                if (!hasMask) {
                    maskBytes = null;
                }
            }
        } catch (NumberFormatException e) {
            return errorResult("Invalid hex pattern: " + patternStr);
        }

        List<long[]> ranges = new ArrayList<>();
        if ("stack".equalsIgnoreCase(scope)) {
            UnidbgPointer sp = emulator.getContext().getStackPointer();
            long stackBase = emulator.getMemory().getStackBase();
            ranges.add(new long[]{sp.peer, stackBase});
        } else if ("heap".equalsIgnoreCase(scope)) {
            int prot = resolvePermission(permission);
            for (MemoryMap map : emulator.getMemory().getMemoryMap()) {
                if ((map.prot & prot) != 0) {
                    ranges.add(new long[]{map.base, map.base + map.size});
                }
            }
        } else if (moduleName != null && !moduleName.isEmpty()) {
            Module module = emulator.getMemory().findModule(moduleName);
            if (module == null) {
                return errorResult("Module not found: " + moduleName);
            }
            ranges.add(new long[]{module.base, module.base + module.size});
        } else if (startStr != null && endStr != null) {
            ranges.add(new long[]{parseAddress(startStr), parseAddress(endStr)});
        } else {
            for (MemoryMap map : emulator.getMemory().getMemoryMap()) {
                if ((map.prot & 1) != 0) {
                    ranges.add(new long[]{map.base, map.base + map.size});
                }
            }
        }

        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();
        List<String> results = new ArrayList<>();
        int chunkSize = 0x10000;

        for (long[] range : ranges) {
            long rangeStart = range[0];
            long rangeEnd = range[1];
            long overlap = patternBytes.length - 1;
            long step = Math.max(1, chunkSize - overlap);

            for (long addr = rangeStart; addr < rangeEnd && results.size() < maxResults; addr += step) {
                int readSize = (int) Math.min(chunkSize, rangeEnd - addr);
                byte[] chunk;
                try {
                    chunk = backend.mem_read(addr, readSize);
                } catch (Exception e) {
                    continue;
                }
                for (int i = 0; i <= chunk.length - patternBytes.length && results.size() < maxResults; i++) {
                    if (matchPattern(chunk, i, patternBytes, maskBytes)) {
                        long matchAddr = addr + i;
                        StringBuilder sb = new StringBuilder();
                        sb.append("0x").append(Long.toHexString(matchAddr));
                        Module module = memory.findModuleByAddress(matchAddr);
                        if (module != null) {
                            sb.append("  (").append(module.name).append("+0x").append(Long.toHexString(matchAddr - module.base)).append(')');
                        }
                        results.add(sb.toString());
                    }
                }
            }
            if (results.size() >= maxResults) break;
        }

        if (results.isEmpty()) {
            return textResult("Pattern not found.");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Found ").append(results.size()).append(" match(es)");
        if (results.size() >= maxResults) {
            sb.append(" (limit reached)");
        }
        sb.append(":\n");
        for (String r : results) {
            sb.append(r).append('\n');
        }
        return textResult(sb.toString());
    }

    private static boolean matchPattern(byte[] data, int offset, byte[] pattern, byte[] mask) {
        for (int j = 0; j < pattern.length; j++) {
            if (mask != null) {
                if ((data[offset + j] & mask[j]) != (pattern[j] & mask[j])) {
                    return false;
                }
            } else {
                if (data[offset + j] != pattern[j]) {
                    return false;
                }
            }
        }
        return true;
    }

    private JSONObject getRegisters() {
        Backend backend = emulator.getBackend();
        StringBuilder sb = new StringBuilder();
        if (emulator.is64Bit()) {
            for (int i = 0; i <= 28; i++) {
                long val = backend.reg_read(Arm64Const.UC_ARM64_REG_X0 + i).longValue();
                sb.append(String.format("X%-3d = 0x%016x%n", i, val));
            }
            sb.append(String.format("FP   = 0x%016x%n", backend.reg_read(Arm64Const.UC_ARM64_REG_FP).longValue()));
            sb.append(String.format("LR   = 0x%016x%n", backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue()));
            sb.append(String.format("SP   = 0x%016x%n", backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue()));
            sb.append(String.format("PC   = 0x%016x%n", backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue()));
        } else {
            for (int i = 0; i <= 12; i++) {
                long val = backend.reg_read(ArmConst.UC_ARM_REG_R0 + i).intValue() & 0xffffffffL;
                sb.append(String.format("R%-3d = 0x%08x%n", i, val));
            }
            sb.append(String.format("SP   = 0x%08x%n", backend.reg_read(ArmConst.UC_ARM_REG_SP).intValue() & 0xffffffffL));
            sb.append(String.format("LR   = 0x%08x%n", backend.reg_read(ArmConst.UC_ARM_REG_LR).intValue() & 0xffffffffL));
            sb.append(String.format("PC   = 0x%08x%n", backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue() & 0xffffffffL));
        }
        return textResult(sb.toString());
    }

    private JSONObject getRegister(JSONObject args) {
        String raw = args.getString("name");
        if (raw == null || raw.isEmpty()) {
            return errorResult("Missing required parameter 'name'. Specify a register name, e.g. X0, SP, PC.");
        }
        String name = raw.toUpperCase();
        try {
            int regId = resolveRegister(name);
            Backend backend = emulator.getBackend();
            if (emulator.is64Bit()) {
                long val = backend.reg_read(regId).longValue();
                if (name.startsWith("W")) {
                    val &= 0xFFFFFFFFL;
                }
                return textResult(name + " = 0x" + Long.toHexString(val));
            } else {
                long val = backend.reg_read(regId).intValue() & 0xffffffffL;
                return textResult(name + " = 0x" + Long.toHexString(val));
            }
        } catch (Exception e) {
            return errorResult("Failed to read register " + name + ": " + exMsg(e));
        }
    }

    private JSONObject setRegister(JSONObject args) {
        String raw = args.getString("name");
        if (raw == null || raw.isEmpty()) {
            return errorResult("Missing required parameter 'name'. Specify a register name, e.g. X0, SP, PC.");
        }
        String name = raw.toUpperCase();
        long value = parseAddress(args.getString("value"));
        try {
            int regId = resolveRegister(name);
            emulator.getBackend().reg_write(regId, value);
            return textResult(name + " set to 0x" + Long.toHexString(value));
        } catch (Exception e) {
            return errorResult("Failed to set register " + name + ": " + exMsg(e));
        }
    }

    private JSONObject disassemble(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        int count = args.containsKey("count") ? args.getIntValue("count") : 10;
        try {
            int size = count * 4;
            byte[] code = emulator.getBackend().mem_read(address, size);
            boolean thumb = emulator.is32Bit() && ARM.isThumb(emulator.getBackend());
            Instruction[] insns = emulator.disassemble(address, code, thumb, count);
            Memory memory = emulator.getMemory();
            GccDemangler demangler = DemanglerFactory.createDemangler();
            StringBuilder sb = new StringBuilder();
            for (Instruction insn : insns) {
                sb.append(String.format("0x%x: %s %s", insn.getAddress(), insn.getMnemonic(), insn.getOpStr()));
                String annotation = resolveInsnTargetSymbol(insn, memory, demangler);
                if (annotation != null) {
                    sb.append("  ; ").append(annotation);
                }
                sb.append('\n');
            }
            if (insns.length == 0) {
                sb.append("No instructions at 0x").append(Long.toHexString(address));
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Disassemble failed: " + exMsg(e));
        }
    }

    private static final java.util.regex.Pattern IMM_ADDR_PATTERN = java.util.regex.Pattern.compile("#0x([0-9a-fA-F]+)");

    private String resolveInsnTargetSymbol(Instruction insn, Memory memory, GccDemangler demangler) {
        String mnemonic = insn.getMnemonic().toLowerCase();
        if (!isBranchMnemonic(mnemonic)) {
            return null;
        }
        java.util.regex.Matcher m = IMM_ADDR_PATTERN.matcher(insn.getOpStr());
        long target = -1;
        while (m.find()) {
            try {
                target = Long.parseUnsignedLong(m.group(1), 16);
            } catch (NumberFormatException ignored) {
            }
        }
        if (target <= 0) {
            return null;
        }
        Module module = memory.findModuleByAddress(target);
        if (module == null) {
            return null;
        }
        Symbol symbol = module.findClosestSymbolByAddress(target, false);
        if (symbol != null && target - symbol.getAddress() <= Unwinder.SYMBOL_SIZE) {
            String name = demangler.demangle(symbol.getName());
            long offset = target - symbol.getAddress();
            if (offset == 0) {
                return name;
            }
            return name + "+0x" + Long.toHexString(offset);
        }
        return module.name + "+0x" + Long.toHexString(target - module.base);
    }

    private static boolean isBranchMnemonic(String mnemonic) {
        switch (mnemonic) {
            case "b": case "bl": case "br": case "blr":
            case "cbz": case "cbnz": case "tbz": case "tbnz":
            case "bx": case "blx":
                return true;
            default:
                if (mnemonic.startsWith("b.")) return true;
                if (mnemonic.startsWith("bl") && mnemonic.length() <= 5) return true;
                return mnemonic.startsWith("b") && mnemonic.length() <= 4
                        && !mnemonic.startsWith("bic") && !mnemonic.startsWith("bfi") && !mnemonic.startsWith("bfc");
        }
    }

    private JSONObject assemble(JSONObject args) {
        String assembly = args.getString("assembly");
        try (Keystone keystone = createKeystone()) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            byte[] code = encoded.getMachineCode();
            return textResult("Machine code: " + Hex.encodeHexString(code) + " (" + code.length + " bytes)");
        } catch (Exception e) {
            return errorResult("Assemble failed: " + exMsg(e));
        }
    }

    private JSONObject patch(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        String assembly = args.getString("assembly");
        try (Keystone keystone = createKeystone()) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            byte[] code = encoded.getMachineCode();
            emulator.getBackend().mem_write(address, code);
            return textResult("Patched " + code.length + " bytes at 0x" + Long.toHexString(address) +
                    ": " + Hex.encodeHexString(code));
        } catch (Exception e) {
            return errorResult("Patch failed: " + exMsg(e));
        }
    }

    private JSONObject addBreakpoint(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        boolean temporary = args.containsKey("temporary") && args.getBooleanValue("temporary");
        try {
            BreakPoint bp = emulator.attach().addBreakPoint(address);
            if (temporary) {
                bp.setTemporary(true);
            }
            String type = temporary ? "Temporary breakpoint" : "Breakpoint";
            return textResult(type + " added at 0x" + Long.toHexString(address));
        } catch (Exception e) {
            return errorResult("Failed to add breakpoint: " + exMsg(e));
        }
    }

    private JSONObject addBreakpointBySymbol(JSONObject args) {
        String moduleName = args.getString("module_name");
        String symbolName = args.getString("symbol_name");
        boolean temporary = args.containsKey("temporary") && args.getBooleanValue("temporary");
        try {
            Module module = emulator.getMemory().findModule(moduleName);
            if (module == null) {
                return errorResult("Module not found: " + moduleName);
            }
            Debugger debugger = emulator.attach();
            BreakPoint bp = debugger.addBreakPoint(module, symbolName);
            if (bp == null) {
                return errorResult("Symbol '" + symbolName + "' not found in " + moduleName);
            }
            if (temporary) {
                bp.setTemporary(true);
            }
            long addr = 0;
            for (Map.Entry<Long, BreakPoint> entry : debugger.getBreakPoints().entrySet()) {
                if (entry.getValue() == bp) {
                    addr = entry.getKey();
                    break;
                }
            }
            String typeStr = temporary ? "Temporary breakpoint" : "Breakpoint";
            return textResult(typeStr + " added at " + symbolName + " (0x" + Long.toHexString(addr) +
                    ", " + moduleName + "+0x" + Long.toHexString(addr - module.base) + ")");
        } catch (Exception e) {
            return errorResult("Failed to add breakpoint by symbol: " + exMsg(e));
        }
    }

    private JSONObject addBreakpointByOffset(JSONObject args) {
        String moduleName = args.getString("module_name");
        long offset = parseAddress(args.getString("offset"));
        boolean temporary = args.containsKey("temporary") && args.getBooleanValue("temporary");
        try {
            Module module = emulator.getMemory().findModule(moduleName);
            if (module == null) {
                return errorResult("Module not found: " + moduleName);
            }
            BreakPoint bp = emulator.attach().addBreakPoint(module, offset);
            if (temporary) {
                bp.setTemporary(true);
            }
            long addr = module.base + offset;
            String typeStr = temporary ? "Temporary breakpoint" : "Breakpoint";
            return textResult(typeStr + " added at " + moduleName + "+0x" + Long.toHexString(offset) +
                    " (0x" + Long.toHexString(addr) + ")");
        } catch (Exception e) {
            return errorResult("Failed to add breakpoint by offset: " + exMsg(e));
        }
    }

    private JSONObject listBreakpoints() {
        try {
            Map<Long, BreakPoint> breakPoints = emulator.attach().getBreakPoints();
            if (breakPoints.isEmpty()) {
                return textResult("No breakpoints set.");
            }
            Memory memory = emulator.getMemory();
            Backend backend = emulator.getBackend();
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Total: %d breakpoint(s)%n", breakPoints.size()));
            for (Map.Entry<Long, BreakPoint> entry : breakPoints.entrySet()) {
                long addr = entry.getKey();
                BreakPoint bp = entry.getValue();
                Module module = memory.findModuleByAddress(addr);
                String location;
                if (module != null) {
                    long offset = addr - module.base;
                    location = String.format("%s+0x%x", module.name, offset);
                } else {
                    location = "unknown";
                }
                String temp = bp.isTemporary() ? " [temporary]" : "";
                sb.append(String.format("0x%x  %s%s", addr, location, temp));
                try {
                    byte[] code = backend.mem_read(addr, 4);
                    boolean thumb = emulator.is32Bit() && (addr & 1) != 0;
                    long disAddr = thumb ? (addr & ~1L) : addr;
                    Instruction[] insns = emulator.disassemble(disAddr, code, thumb, 1);
                    if (insns.length > 0) {
                        sb.append(String.format("  ; %s %s", insns[0].getMnemonic(), insns[0].getOpStr()));
                    }
                } catch (Exception ignored) {
                }
                sb.append('\n');
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to list breakpoints: " + exMsg(e));
        }
    }

    private JSONObject removeBreakpoint(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        try {
            boolean removed = emulator.attach().removeBreakPoint(address);
            if (removed) {
                return textResult("Breakpoint removed at 0x" + Long.toHexString(address));
            } else {
                return errorResult("No breakpoint found at 0x" + Long.toHexString(address));
            }
        } catch (Exception e) {
            return errorResult("Failed to remove breakpoint: " + exMsg(e));
        }
    }

    private JSONObject continueExecution() {
        server.injectCommand("c");
        return textResult("Execution resumed. Use poll_events to wait for breakpoint_hit or execution_completed.");
    }


    private JSONObject stepOver() {
        server.injectCommand("n");
        return textResult("Step over. Use poll_events to wait for completion.");
    }

    private JSONObject stepInto(JSONObject args) {
        int count = args.containsKey("count") ? args.getIntValue("count") : 1;
        if (count <= 1) {
            server.injectCommand("s");
        } else {
            server.injectCommand("s" + count);
        }
        return textResult("Step into (" + count + " instruction" + (count > 1 ? "s" : "") + "). Use poll_events to wait for completion.");
    }

    private JSONObject stepOut() {
        if (!server.isDebugIdle()) {
            return errorResult("Emulator is not in debug idle state.");
        }
        try {
            JSONObject result = server.runOnDebuggerThread(() -> {
                Backend backend = emulator.getBackend();
                int lrReg = emulator.is64Bit() ? Arm64Const.UC_ARM64_REG_LR : ArmConst.UC_ARM_REG_LR;
                long lr = backend.reg_read(lrReg).longValue();
                if (emulator.is32Bit()) {
                    lr &= 0xffffffffL;
                }
                BreakPoint bp = emulator.attach().addBreakPoint(lr);
                bp.setTemporary(true);
                return textResult("Temporary breakpoint set at LR=0x" + Long.toHexString(lr));
            });
            if (result.containsKey("isError")) {
                return result;
            }
            server.injectCommand("c");
            String text = result.getJSONArray("content").getJSONObject(0).getString("text");
            return textResult(text + "\nExecution resumed. Use poll_events to wait for breakpoint_hit when function returns.");
        } catch (Exception e) {
            return errorResult("Step out failed: " + exMsg(e));
        }
    }

    private JSONObject stopEmulation() {
        try {
            emulator.getBackend().emu_stop();
            return textResult("Emulation stop requested. The emulator will halt at the next opportunity.");
        } catch (Exception e) {
            return errorResult("Failed to stop emulation: " + exMsg(e));
        }
    }

    private JSONObject nextBlock() {
        if (!server.isDebugIdle()) {
            return errorResult("Emulator is not in debug idle state.");
        }
        String backendClass = emulator.getBackend().getClass().getSimpleName();
        if (backendClass.contains("Hypervisor") || backendClass.contains("Dynarmic") || backendClass.contains("Kvm")) {
            return errorResult("next_block is not supported on " + backendClass + " backend. Only Unicorn/Unicorn2 backends support BlockHook.");
        }
        server.injectCommand("nb");
        return textResult("Resuming execution, will break at the start of the next basic block. Use poll_events to wait for breakpoint_hit.");
    }

    private JSONObject stepUntilMnemonic(JSONObject args) {
        String mnemonic = args.getString("mnemonic");
        if (mnemonic == null || mnemonic.isEmpty()) {
            return errorResult("mnemonic parameter is required.");
        }
        if (!server.isDebugIdle()) {
            return errorResult("Emulator is not in debug idle state.");
        }
        String backendClass = emulator.getBackend().getClass().getSimpleName();
        if (backendClass.contains("Hypervisor") || backendClass.contains("Dynarmic") || backendClass.contains("Kvm")) {
            return errorResult("step_until_mnemonic is not supported on " + backendClass +
                    " backend. Only Unicorn/Unicorn2 backends support per-instruction hook (setFastDebug).");
        }
        server.injectCommand("s" + mnemonic);
        return textResult("Resuming execution, will break when a '" + mnemonic +
                "' instruction is reached. Use poll_events to wait for breakpoint_hit.");
    }

    private JSONObject pollEvents(JSONObject args) {
        long timeoutMs = args.containsKey("timeout_ms") ? args.getLongValue("timeout_ms") : 10000;
        java.util.List<JSONObject> events = server.pollEvents(timeoutMs);
        if (events.isEmpty()) {
            return textResult("No events received within timeout.");
        }
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%d event(s):%n", events.size()));
        for (JSONObject event : events) {
            sb.append(event.toJSONString()).append('\n');
        }
        return textResult(sb.toString());
    }

    private JSONObject traceRead(JSONObject args) {
        long begin = parseAddress(args.getString("begin"));
        long end = parseAddress(args.getString("end"));
        String breakOnStr = args.getString("break_on");
        final long breakOn = breakOnStr != null ? parseAddress(breakOnStr) : -1;
        try {
            if (activeTraceRead != null) {
                activeTraceRead.stopTrace();
                activeTraceRead = null;
            }
            activeTraceRead = emulator.traceRead(begin, end, (emu, address, data, hex) -> {
                JSONObject event = new JSONObject(true);
                event.put("event", "trace_read");
                event.put("pc", "0x" + Long.toHexString(emu.getBackend().reg_read(
                        emu.is64Bit() ? Arm64Const.UC_ARM64_REG_PC : ArmConst.UC_ARM_REG_PC).longValue()));
                event.put("address", "0x" + Long.toHexString(address));
                event.put("size", data.length);
                event.put("hex", hex);
                putModuleInfo(event, emu, address);
                server.queueEvent(event);
                if (breakOn != -1 && address == breakOn) {
                    emu.getBackend().setSingleStep(1);
                }
                return false;
            });
            StringBuilder msg = new StringBuilder("Trace read started: 0x" + Long.toHexString(begin) + " - 0x" + Long.toHexString(end));
            if (breakOn != -1) {
                msg.append(", will break on address 0x").append(Long.toHexString(breakOn));
            }
            msg.append(". Trace data will be collected as trace_read events, use poll_events to retrieve.");
            return textResult(msg.toString());
        } catch (Exception e) {
            return errorResult("Failed to start trace read: " + e.getClass().getName() + ": " + exMsg(e));
        }
    }

    private JSONObject traceWrite(JSONObject args) {
        long begin = parseAddress(args.getString("begin"));
        long end = parseAddress(args.getString("end"));
        String breakOnStr = args.getString("break_on");
        final long breakOn = breakOnStr != null ? parseAddress(breakOnStr) : -1;
        try {
            if (activeTraceWrite != null) {
                activeTraceWrite.stopTrace();
                activeTraceWrite = null;
            }
            activeTraceWrite = emulator.traceWrite(begin, end, (emu, address, size, value) -> {
                JSONObject event = new JSONObject(true);
                event.put("event", "trace_write");
                event.put("pc", "0x" + Long.toHexString(emu.getBackend().reg_read(
                        emu.is64Bit() ? Arm64Const.UC_ARM64_REG_PC : ArmConst.UC_ARM_REG_PC).longValue()));
                event.put("address", "0x" + Long.toHexString(address));
                event.put("size", size);
                event.put("value", "0x" + Long.toHexString(value));
                putModuleInfo(event, emu, address);
                server.queueEvent(event);
                if (breakOn != -1 && address == breakOn) {
                    emu.getBackend().setSingleStep(1);
                }
                return false;
            });
            StringBuilder msg = new StringBuilder("Trace write started: 0x" + Long.toHexString(begin) + " - 0x" + Long.toHexString(end));
            if (breakOn != -1) {
                msg.append(", will break on address 0x").append(Long.toHexString(breakOn));
            }
            msg.append(". Trace data will be collected as trace_write events, use poll_events to retrieve.");
            return textResult(msg.toString());
        } catch (Exception e) {
            return errorResult("Failed to start trace write: " + e.getClass().getName() + ": " + exMsg(e));
        }
    }

    private short[] lastTraceWriteRegs;
    private Instruction lastTraceInsn;

    private String formatRegValues(Instruction insn, short[] regs) {
        if (regs == null || regs.length == 0) return null;
        Backend backend = emulator.getBackend();
        StringBuilder sb = new StringBuilder();
        for (short reg : regs) {
            int regId = insn.mapToUnicornReg(reg);
            if (emulator.is32Bit()) {
                if ((regId >= ArmConst.UC_ARM_REG_R0 && regId <= ArmConst.UC_ARM_REG_R12) ||
                        regId == ArmConst.UC_ARM_REG_LR || regId == ArmConst.UC_ARM_REG_SP ||
                        regId == ArmConst.UC_ARM_REG_CPSR) {
                    if (sb.length() > 0) sb.append(", ");
                    if (regId == ArmConst.UC_ARM_REG_CPSR) {
                        Cpsr cpsr = Cpsr.getArm(backend);
                        sb.append(String.format(Locale.US, "cpsr: N=%d, Z=%d, C=%d, V=%d",
                                cpsr.isNegative() ? 1 : 0, cpsr.isZero() ? 1 : 0,
                                cpsr.hasCarry() ? 1 : 0, cpsr.isOverflow() ? 1 : 0));
                    } else {
                        int value = backend.reg_read(regId).intValue();
                        sb.append(insn.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                    }
                }
            } else {
                if ((regId >= Arm64Const.UC_ARM64_REG_X0 && regId <= Arm64Const.UC_ARM64_REG_X28) ||
                        (regId >= Arm64Const.UC_ARM64_REG_X29 && regId <= Arm64Const.UC_ARM64_REG_SP)) {
                    if (sb.length() > 0) sb.append(", ");
                    if (regId == Arm64Const.UC_ARM64_REG_NZCV) {
                        Cpsr cpsr = Cpsr.getArm64(backend);
                        if (cpsr.isA32()) {
                            sb.append(String.format(Locale.US, "cpsr: N=%d, Z=%d, C=%d, V=%d",
                                    cpsr.isNegative() ? 1 : 0, cpsr.isZero() ? 1 : 0,
                                    cpsr.hasCarry() ? 1 : 0, cpsr.isOverflow() ? 1 : 0));
                        } else {
                            sb.append(String.format(Locale.US, "nzcv: N=%d, Z=%d, C=%d, V=%d",
                                    cpsr.isNegative() ? 1 : 0, cpsr.isZero() ? 1 : 0,
                                    cpsr.hasCarry() ? 1 : 0, cpsr.isOverflow() ? 1 : 0));
                        }
                    } else {
                        long value = backend.reg_read(regId).longValue();
                        sb.append(insn.regName(reg)).append("=0x").append(Long.toHexString(value));
                    }
                } else if (regId >= Arm64Const.UC_ARM64_REG_W0 && regId <= Arm64Const.UC_ARM64_REG_W30) {
                    if (sb.length() > 0) sb.append(", ");
                    int value = backend.reg_read(regId).intValue();
                    sb.append(insn.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                }
            }
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    private JSONObject traceCode(JSONObject args) {
        long begin = parseAddress(args.getString("begin"));
        long end = parseAddress(args.getString("end"));
        String breakOnStr = args.getString("break_on");
        final long breakOn = breakOnStr != null ? parseAddress(breakOnStr) : -1;
        try {
            if (activeTraceCode != null) {
                activeTraceCode.stopTrace();
                activeTraceCode = null;
            }
            lastTraceWriteRegs = null;
            lastTraceInsn = null;
            activeTraceCode = emulator.traceCode(begin, end, (emu, address, insn) -> {
                JSONObject event = new JSONObject(true);
                event.put("event", "trace_code");
                event.put("address", "0x" + Long.toHexString(address));
                if (insn != null) {
                    event.put("mnemonic", insn.getMnemonic());
                    event.put("operands", insn.getOpStr());
                    event.put("size", insn.getSize());
                }
                Module module = emu.getMemory().findModuleByAddress(address);
                if (module != null) {
                    event.put("module", module.name);
                    event.put("offset", "0x" + Long.toHexString(address - module.base));
                }
                if (lastTraceWriteRegs != null && lastTraceInsn != null) {
                    String writeValues = formatRegValues(lastTraceInsn, lastTraceWriteRegs);
                    if (writeValues != null) {
                        event.put("prev_write", writeValues);
                    }
                }
                if (insn != null) {
                    RegsAccess regsAccess = insn.regsAccess();
                    if (regsAccess != null) {
                        String readValues = formatRegValues(insn, regsAccess.getRegsRead());
                        if (readValues != null) {
                            event.put("regs_read", readValues);
                        }
                        short[] regsWrite = regsAccess.getRegsWrite();
                        if (regsWrite != null && regsWrite.length > 0) {
                            lastTraceWriteRegs = regsWrite;
                            lastTraceInsn = insn;
                        } else {
                            lastTraceWriteRegs = null;
                            lastTraceInsn = null;
                        }
                    } else {
                        lastTraceWriteRegs = null;
                        lastTraceInsn = null;
                    }
                }
                server.queueEvent(event);
                if (breakOn != -1 && address == breakOn) {
                    emu.attach().debug("trace_code break_on address hit: 0x" + Long.toHexString(address));
                }
            });
            StringBuilder msg = new StringBuilder("Trace code started: 0x" + Long.toHexString(begin) + " - 0x" + Long.toHexString(end));
            if (breakOn != -1) {
                msg.append(", will break on PC 0x").append(Long.toHexString(breakOn));
            }
            msg.append(". Trace data will be collected as trace_code events, use poll_events to retrieve.");
            return textResult(msg.toString());
        } catch (Exception e) {
            return errorResult("Failed to start trace code: " + e.getClass().getName() + ": " + exMsg(e));
        }
    }


    private JSONObject getCallstack() {
        try {
            Unwinder unwinder = emulator.getUnwinder();
            Memory memory = emulator.getMemory();
            java.util.List<Frame> frames = unwinder.getFrames(50);
            if (frames.isEmpty()) {
                return textResult("No call stack frames available.");
            }
            StringBuilder sb = new StringBuilder();
            GccDemangler demangler = DemanglerFactory.createDemangler();
            for (int i = 0; i < frames.size(); i++) {
                long pc = frames.get(i).ip.peer;
                Module module = memory.findModuleByAddress(pc);
                sb.append(String.format("#%-3d 0x%x", i, pc));
                if (module != null) {
                    sb.append(String.format("  %s+0x%x", module.name, pc - module.base));
                    Symbol symbol = module.findClosestSymbolByAddress(pc, false);
                    if (symbol != null && pc - symbol.getAddress() <= Unwinder.SYMBOL_SIZE) {
                        sb.append(String.format("  (%s+0x%x)", demangler.demangle(symbol.getName()), pc - symbol.getAddress()));
                    }
                }
                sb.append('\n');
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to get callstack: " + e.getClass().getName() + ": " + exMsg(e));
        }
    }

    private JSONObject findSymbol(JSONObject args) {
        String moduleName = args.getString("module_name");
        String symbolName = args.getString("symbol_name");
        String addressStr = args.getString("address");
        try {
            if (addressStr != null && !addressStr.isEmpty()) {
                long address = parseAddress(addressStr);
                Module module = emulator.getMemory().findModuleByAddress(address);
                if (module == null) {
                    return errorResult("No module found at address 0x" + Long.toHexString(address));
                }
                Symbol symbol = module.findClosestSymbolByAddress(address, false);
                if (symbol == null || address - symbol.getAddress() > Unwinder.SYMBOL_SIZE) {
                    return textResult("No symbol found near 0x" + Long.toHexString(address) +
                            " (in " + module.name + "+0x" + Long.toHexString(address - module.base) + ")");
                }
                GccDemangler demangler = DemanglerFactory.createDemangler();
                String sb = "Address: 0x" + Long.toHexString(address) + '\n' +
                        "Module: " + module.name + '\n' +
                        "Nearest symbol: " + symbol.getName() + '\n' +
                        "Demangled: " + demangler.demangle(symbol.getName()) + '\n' +
                        "Symbol address: 0x" + Long.toHexString(symbol.getAddress()) + '\n' +
                        "Offset from symbol: +0x" + Long.toHexString(address - symbol.getAddress()) + '\n';
                return textResult(sb);
            }
            if (moduleName != null && symbolName != null) {
                Module module = emulator.getMemory().findModule(moduleName);
                if (module == null) {
                    return errorResult("Module not found: " + moduleName);
                }
                Symbol symbol = module.findSymbolByName(symbolName, false);
                if (symbol == null) {
                    return errorResult("Symbol '" + symbolName + "' not found in " + moduleName);
                }
                GccDemangler demangler = DemanglerFactory.createDemangler();
                String sb = "Symbol: " + symbol.getName() + '\n' +
                        "Demangled: " + demangler.demangle(symbol.getName()) + '\n' +
                        "Address: 0x" + Long.toHexString(symbol.getAddress()) + '\n' +
                        "Module: " + moduleName + '\n' +
                        "Offset: 0x" + Long.toHexString(symbol.getAddress() - module.base) + '\n';
                return textResult(sb);
            }
            return errorResult("Provide either (module_name + symbol_name) or (address).");
        } catch (Exception e) {
            return errorResult("Find symbol failed: " + e.getClass().getName() + ": " + exMsg(e));
        }
    }

    private JSONObject readString(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        int maxLength = args.containsKey("max_length") ? args.getIntValue("max_length") : 256;
        try {
            byte[] data = emulator.getBackend().mem_read(address, maxLength);
            int len = 0;
            while (len < data.length && data[len] != 0) {
                len++;
            }
            String str = new String(data, 0, len, java.nio.charset.StandardCharsets.UTF_8);
            StringBuilder sb = new StringBuilder();
            sb.append("Address: 0x").append(Long.toHexString(address)).append('\n');
            sb.append("Length: ").append(len).append(" bytes").append('\n');
            sb.append("String: ").append(str).append('\n');
            if (len == maxLength) {
                sb.append("(truncated, no null terminator found within max_length)");
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to read string at 0x" + Long.toHexString(address) + ": " + exMsg(e));
        }
    }

    private JSONObject readStdString(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        try {
            UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
            if (pointer == null) {
                return errorResult("Null pointer for address 0x" + Long.toHexString(address));
            }
            com.github.unidbg.unix.struct.StdString stdStr =
                    com.github.unidbg.unix.struct.StdString.createStdString(emulator, pointer);
            long dataSize = stdStr.getDataSize();
            boolean isTiny = (emulator.getBackend().mem_read(address, 1)[0] & 1) == 0;
            byte[] data = stdStr.getData(emulator);
            String str = new String(data, java.nio.charset.StandardCharsets.UTF_8);

            StringBuilder sb = new StringBuilder();
            sb.append("Address: 0x").append(Long.toHexString(address)).append('\n');
            sb.append("Storage: ").append(isTiny ? "SSO (inline)" : "heap").append('\n');
            sb.append("Size: ").append(dataSize).append(" bytes").append('\n');
            sb.append("String: ").append(str).append('\n');
            if (dataSize > 0) {
                sb.append("Hex: ").append(Hex.encodeHexString(data)).append('\n');
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to read std::string at 0x" + Long.toHexString(address) + ": " + exMsg(e));
        }
    }

    private void appendModuleAndSymbol(StringBuilder sb, Memory memory, GccDemangler demangler, long address) {
        Module module = memory.findModuleByAddress(address);
        if (module != null) {
            sb.append(String.format("  (%s+0x%x)", module.name, address - module.base));
            Symbol symbol = module.findClosestSymbolByAddress(address, false);
            if (symbol != null && address - symbol.getAddress() <= Unwinder.SYMBOL_SIZE) {
                sb.append(String.format("  <%s>", demangler.demangle(symbol.getName())));
            }
        }
    }

    private JSONObject readPointer(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        int depth = args.containsKey("depth") ? args.getIntValue("depth") : 1;
        int offset = args.containsKey("offset") ? args.getIntValue("offset") : 0;
        boolean is64 = emulator.is64Bit();
        int ptrSize = is64 ? 8 : 4;
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();
        GccDemangler demangler = DemanglerFactory.createDemangler();

        StringBuilder sb = new StringBuilder();
        long currentAddr = address;
        try {
            for (int level = 0; level <= depth; level++) {
                sb.append(String.format("[%d] 0x%x", level, currentAddr));
                appendModuleAndSymbol(sb, memory, demangler, currentAddr);
                sb.append('\n');

                if (level < depth) {
                    long readAddr = currentAddr + offset;
                    byte[] data = backend.mem_read(readAddr, ptrSize);
                    long ptrValue;
                    ptrValue = 0;
                    if (is64) {
                        for (int i = 7; i >= 0; i--) {
                            ptrValue = (ptrValue << 8) | (data[i] & 0xFFL);
                        }
                    } else {
                        for (int i = 3; i >= 0; i--) {
                            ptrValue = (ptrValue << 8) | (data[i] & 0xFFL);
                        }
                    }
                    if (offset != 0) {
                        sb.append(String.format("    -> read at 0x%x+0x%x = 0x%x%n", currentAddr, offset, ptrValue));
                    } else {
                        sb.append(String.format("    -> 0x%x%n", ptrValue));
                    }
                    if (ptrValue == 0) {
                        sb.append("    (null pointer, chain ends)\n");
                        break;
                    }
                    currentAddr = ptrValue;
                }
            }
        } catch (Exception e) {
            sb.append(String.format("    (read failed at 0x%x: %s)%n", currentAddr, exMsg(e)));
        }
        return textResult(sb.toString());
    }

    private JSONObject readTyped(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        String rawType = args.getString("type");
        if (rawType == null || rawType.isEmpty()) {
            return errorResult("Missing required parameter 'type'. Supported: int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, pointer");
        }
        String type = rawType.toLowerCase();
        int count = args.containsKey("count") ? args.getIntValue("count") : 1;

        int elemSize;
        switch (type) {
            case "int8": case "uint8": elemSize = 1; break;
            case "int16": case "uint16": elemSize = 2; break;
            case "int32": case "uint32": case "float": elemSize = 4; break;
            case "int64": case "uint64": case "double": elemSize = 8; break;
            case "pointer": elemSize = emulator.is64Bit() ? 8 : 4; break;
            default: return errorResult("Unsupported type: " + type + ". Supported: int8, uint8, int16, uint16, int32, uint32, int64, uint64, float, double, pointer");
        }

        try {
            byte[] data = emulator.getBackend().mem_read(address, (long) elemSize * count);
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            Memory memory = emulator.getMemory();
            GccDemangler demangler = DemanglerFactory.createDemangler();
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < count; i++) {
                long elemAddr = address + (long) i * elemSize;
                sb.append(String.format("[%d] 0x%x: ", i, elemAddr));
                switch (type) {
                    case "int8": sb.append(data[i]); break;
                    case "uint8": sb.append(data[i] & 0xFF); break;
                    case "int16": sb.append(buf.getShort(i * 2)); break;
                    case "uint16": sb.append(buf.getShort(i * 2) & 0xFFFF); break;
                    case "int32": sb.append(buf.getInt(i * 4)); break;
                    case "uint32": sb.append(Integer.toUnsignedString(buf.getInt(i * 4))); break;
                    case "float": sb.append(buf.getFloat(i * 4)); break;
                    case "int64": sb.append(buf.getLong(i * 8)); break;
                    case "uint64": sb.append(Long.toUnsignedString(buf.getLong(i * 8))); break;
                    case "double": sb.append(buf.getDouble(i * 8)); break;
                    case "pointer": {
                        long ptrVal = emulator.is64Bit() ? buf.getLong(i * 8) : (buf.getInt(i * 4) & 0xFFFFFFFFL);
                        sb.append("0x").append(Long.toHexString(ptrVal));
                        if (ptrVal != 0) {
                            appendModuleAndSymbol(sb, memory, demangler, ptrVal);
                        }
                        break;
                    }
                }
                sb.append('\n');
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to read typed data at 0x" + Long.toHexString(address) + ": " + exMsg(e));
        }
    }

    private JSONObject callFunction(JSONObject args) {
        if (emulator.isRunning()) {
            return errorResult("Cannot call function while emulator is running.");
        }
        long address = parseAddress(args.getString("address"));
        return doCallFunction(address, null, args);
    }

    private JSONObject callSymbol(JSONObject args) {
        if (emulator.isRunning()) {
            return errorResult("Cannot call function while emulator is running.");
        }
        String moduleName = args.getString("module_name");
        String symbolName = args.getString("symbol_name");
        if (moduleName == null || moduleName.isEmpty()) {
            return errorResult("Missing required parameter 'module_name'.");
        }
        if (symbolName == null || symbolName.isEmpty()) {
            return errorResult("Missing required parameter 'symbol_name'.");
        }
        Module module = emulator.getMemory().findModule(moduleName);
        if (module == null) {
            return errorResult("Module not found: " + moduleName);
        }
        Symbol symbol = module.findSymbolByName(symbolName, false);
        if (symbol == null) {
            symbol = module.findSymbolByName("_" + symbolName, false);
        }
        if (symbol == null) {
            return errorResult("Symbol '" + symbolName + "' not found in " + moduleName +
                    ". Use list_exports to see available symbols.");
        }
        String label = moduleName + "!" + symbolName;
        return doCallFunction(symbol.getAddress(), label, args);
    }

    private JSONObject doCallFunction(long address, String label, JSONObject args) {
        JSONArray argsArray = args.getJSONArray("args");
        Object[] funcArgs;
        if (argsArray == null || argsArray.isEmpty()) {
            funcArgs = new Object[0];
        } else {
            funcArgs = new Object[argsArray.size()];
            for (int i = 0; i < argsArray.size(); i++) {
                String argStr = argsArray.getString(i);
                try {
                    funcArgs[i] = parseCallArg(argStr);
                } catch (Exception e) {
                    return errorResult("Invalid argument[" + i + "] '" + argStr + "': " + exMsg(e));
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Calling ");
        if (label != null) {
            sb.append(label).append(" (0x").append(Long.toHexString(address)).append(')');
        } else {
            sb.append("0x").append(Long.toHexString(address));
            Module module = emulator.getMemory().findModuleByAddress(address);
            if (module != null) {
                sb.append(" (").append(module.name).append("+0x").append(Long.toHexString(address - module.base)).append(')');
            }
        }
        sb.append(" with ").append(funcArgs.length).append(" arg(s)\n");
        for (int i = 0; i < funcArgs.length; i++) {
            Object arg = funcArgs[i];
            if (arg instanceof Long) {
                sb.append(String.format("  arg[%d]: 0x%x%n", i, (Long) arg));
            } else if (arg instanceof String) {
                sb.append(String.format("  arg[%d]: string \"%s\"%n", i, arg));
            } else if (arg instanceof byte[]) {
                sb.append(String.format("  arg[%d]: byte[%d] %s%n", i, ((byte[]) arg).length, Hex.encodeHexString((byte[]) arg)));
            } else {
                sb.append(String.format("  arg[%d]: null%n", i));
            }
        }

        int previewSize = args.containsKey("preview_size") ? args.getIntValue("preview_size") : 64;

        try {
            Number result = Module.emulateFunction(emulator, address, funcArgs);
            long retVal = result.longValue();
            sb.append("\nResult: 0x").append(Long.toHexString(retVal));
            sb.append(" (").append(retVal).append(")\n");

            Memory memory = emulator.getMemory();
            GccDemangler demangler = DemanglerFactory.createDemangler();
            Module retModule = memory.findModuleByAddress(retVal);
            if (retModule != null) {
                sb.append("  Module: ").append(retModule.name).append("+0x").append(Long.toHexString(retVal - retModule.base));
                Symbol sym = retModule.findClosestSymbolByAddress(retVal, false);
                if (sym != null && retVal - sym.getAddress() <= Unwinder.SYMBOL_SIZE) {
                    sb.append("  <").append(demangler.demangle(sym.getName())).append('>');
                }
                sb.append('\n');
            }

            if (retVal > 0x1000 && previewSize > 0) {
                try {
                    byte[] previewData = emulator.getBackend().mem_read(retVal, previewSize);
                    int strLen = 0;
                    boolean printable = true;
                    while (strLen < previewData.length && previewData[strLen] != 0) {
                        if (previewData[strLen] < 0x20 || previewData[strLen] > 0x7e) {
                            printable = false;
                            break;
                        }
                        strLen++;
                    }
                    if (printable && strLen > 0) {
                        sb.append("  String: \"").append(new String(previewData, 0, strLen, java.nio.charset.StandardCharsets.UTF_8)).append("\"\n");
                    }
                    sb.append("  Hex preview (").append(previewSize).append(" bytes): ").append(Hex.encodeHexString(previewData)).append('\n');
                } catch (Exception ignored) {
                }
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            sb.append("\nCall FAILED: ").append(e.getClass().getName()).append(": ").append(exMsg(e)).append('\n');
            Throwable cause = e.getCause();
            if (cause != null) {
                sb.append("Caused by: ").append(cause.getClass().getName()).append(": ").append(cause.getMessage() != null ? cause.getMessage() : cause.getClass().getName()).append('\n');
            }
            return errorResult(sb.toString());
        }
    }

    private Object parseCallArg(String argStr) throws DecoderException {
        if (argStr == null || "null".equalsIgnoreCase(argStr)) {
            return null;
        }
        if (argStr.startsWith("s:")) {
            return argStr.substring(2);
        }
        if (argStr.startsWith("b:")) {
            return Hex.decodeHex(argStr.substring(2).toCharArray());
        }
        return parseAddress(argStr);
    }

    private JSONObject listModules(JSONObject args) {
        String filter = args != null ? args.getString("filter") : null;
        Collection<Module> modules = emulator.getMemory().getLoadedModules();
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-40s %-18s %-10s%n", "Name", "Base", "Size"));
        int count = 0;
        for (Module m : modules) {
            if (filter != null && !filter.isEmpty() && !m.name.toLowerCase().contains(filter.toLowerCase())) {
                continue;
            }
            sb.append(String.format("%-40s 0x%016x 0x%x%n", m.name, m.base, m.size));
            count++;
        }
        if (filter != null && !filter.isEmpty()) {
            sb.insert(0, String.format("Showing %d of %d modules (filter: '%s')%n", count, modules.size(), filter));
        }
        return textResult(sb.toString());
    }

    private JSONObject getModuleInfo(JSONObject args) {
        String moduleName = args.getString("module_name");
        Module module = emulator.getMemory().findModule(moduleName);
        if (module == null) {
            return errorResult("Module not found: " + moduleName);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(module.name).append('\n');
        sb.append("Base: 0x").append(Long.toHexString(module.base)).append('\n');
        sb.append("Size: 0x").append(Long.toHexString(module.size)).append('\n');
        sb.append("Path: ").append(module.getPath()).append('\n');
        Collection<Symbol> exports = module.getExportedSymbols();
        sb.append("Exported symbols: ").append(exports.size()).append('\n');
        sb.append("Dependencies: ").append(module.getNeededLibraries().size()).append('\n');
        for (Module dep : module.getNeededLibraries()) {
            sb.append("  ").append(dep.name).append('\n');
        }
        return textResult(sb.toString());
    }

    private JSONObject executeCustomTool(CustomTool tool, JSONObject args) {
        StringBuilder cmd = new StringBuilder("run ");
        cmd.append(tool.name);
        for (String pn : tool.paramNames) {
            String val = args.getString(pn);
            if (val != null) {
                cmd.append(' ').append(val);
            }
        }
        server.injectCommand(cmd.toString());
        return textResult("Emulation started: " + tool.name);
    }

    private JSONObject listExports(JSONObject args) {
        String moduleName = args.getString("module_name");
        String filter = args.getString("filter");
        try {
            Module module = emulator.getMemory().findModule(moduleName);
            if (module == null) {
                return errorResult("Module not found: " + moduleName);
            }
            Collection<Symbol> symbols = module.getExportedSymbols();
            if (symbols.isEmpty()) {
                return textResult("No exported symbols found in " + moduleName +
                        ". Note: only dynamic/exported symbols are available.");
            }
            GccDemangler demangler = DemanglerFactory.createDemangler();
            List<String> lines = new ArrayList<>();
            for (Symbol symbol : symbols) {
                if (filter != null && !filter.isEmpty()) {
                    String name = symbol.getName();
                    String demangled = demangler.demangle(name);
                    if (!name.toLowerCase().contains(filter.toLowerCase()) &&
                            !demangled.toLowerCase().contains(filter.toLowerCase())) {
                        continue;
                    }
                }
                long addr = symbol.getAddress();
                String demangled = demangler.demangle(symbol.getName());
                String line = String.format("0x%x  %s+0x%x  %s", addr, moduleName,
                        addr - module.base, symbol.getName());
                if (!demangled.equals(symbol.getName())) {
                    line += "  (" + demangled + ")";
                }
                lines.add(line);
            }
            StringBuilder sb = new StringBuilder();
            if (filter != null && !filter.isEmpty()) {
                sb.append(String.format("Showing %d of %d symbols (filter: '%s')%n", lines.size(), symbols.size(), filter));
            } else {
                sb.append(String.format("%d exported symbol(s):%n", lines.size()));
            }
            for (String line : lines) {
                sb.append(line).append('\n');
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to list exports: " + e.getClass().getName() + ": " + exMsg(e));
        }
    }

    private JSONObject getThreads() {
        try {
            List<Task> tasks = emulator.getThreadDispatcher().getTaskList();
            if (tasks.isEmpty()) {
                return textResult("No threads/tasks.");
            }
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("%d thread(s):%n", tasks.size()));
            for (Task task : tasks) {
                sb.append(String.format("  tid=%d: %s%n", task.getId(), task));
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to get threads: " + exMsg(e));
        }
    }

    private JSONObject allocateMemory(JSONObject args) {
        String hexData = args.getString("data");
        byte[] initData = null;
        if (hexData != null && !hexData.isEmpty()) {
            try {
                initData = Hex.decodeHex(hexData.toCharArray());
            } catch (DecoderException e) {
                return errorResult("Invalid 'data' hex string: \"" + hexData + "\". Expected hex-encoded bytes, e.g. \"48656c6c6f\" for \"Hello\".");
            }
        }
        int size = args.containsKey("size") ? args.getIntValue("size") : 0;
        if (size <= 0 && initData != null) {
            size = initData.length;
        }
        if (size <= 0) {
            return errorResult("Size must be positive. Provide 'size' or 'data' (hex-encoded bytes to infer size from).");
        }
        if (initData != null && initData.length > size) {
            return errorResult("Data length (" + initData.length + " bytes) exceeds allocation size (" + size + " bytes).");
        }
        boolean isRunning = emulator.isRunning();
        Boolean runtimeParam = args.containsKey("runtime") ? args.getBoolean("runtime") : null;
        boolean runtime;
        if (isRunning) {
            if (runtimeParam != null && !runtimeParam) {
                return errorResult("Cannot use runtime=false (libc malloc) while emulator is running. " +
                        "Use runtime=true (mmap) or omit the parameter.");
            }
            runtime = true;
        } else {
            runtime = runtimeParam != null ? runtimeParam : false;
        }
        try {
            MemoryBlock block = emulator.getMemory().malloc(size, runtime);
            UnidbgPointer pointer = block.getPointer();
            allocatedBlocks.put(pointer.peer, new Allocation(block, runtime, size));
            if (initData != null) {
                pointer.write(0, initData, 0, initData.length);
            }
            String method = runtime ? "mmap (page-aligned, free anytime)" : "malloc (heap, free requires isRunning=false)";
            StringBuilder sb = new StringBuilder();
            sb.append("Allocated ").append(size).append(" bytes (0x").append(Integer.toHexString(size))
                    .append(") at 0x").append(Long.toHexString(pointer.peer))
                    .append(" via ").append(method);
            if (initData != null) {
                sb.append("\nWritten ").append(initData.length).append(" bytes of initial data.");
            }
            sb.append("\nUse free_memory to release when done.");
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to allocate memory: " + exMsg(e));
        }
    }

    private JSONObject freeMemory(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        Allocation alloc = allocatedBlocks.get(address);
        if (alloc == null) {
            return errorResult("No tracked allocation at 0x" + Long.toHexString(address) +
                    ". Only blocks allocated via allocate_memory can be freed.");
        }
        if (!alloc.runtime && emulator.isRunning()) {
            return errorResult("Cannot free malloc-allocated memory at 0x" + Long.toHexString(address) +
                    " while emulator is running. malloc blocks require isRunning=false to call libc free()." +
                    " Wait until emulator stops or use stop_emulation first.");
        }
        try {
            alloc.block.free();
            allocatedBlocks.remove(address);
            String method = alloc.runtime ? "munmap" : "libc free";
            return textResult("Freed memory at 0x" + Long.toHexString(address) + " via " + method + ".");
        } catch (Exception e) {
            return errorResult("Failed to free memory at 0x" + Long.toHexString(address) + ": " + exMsg(e));
        }
    }

    private JSONObject listAllocations() {
        if (allocatedBlocks.isEmpty()) {
            return textResult("No active allocations.");
        }
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%d active allocation(s):%n", allocatedBlocks.size()));
        for (Map.Entry<Long, Allocation> entry : allocatedBlocks.entrySet()) {
            long addr = entry.getKey();
            Allocation alloc = entry.getValue();
            String type = alloc.runtime ? "mmap (free anytime)" : "malloc (free requires isRunning=false)";
            sb.append(String.format("  0x%x  size=%d (0x%x)  type=%s%n", addr, alloc.size, alloc.size, type));
        }
        return textResult(sb.toString());
    }

    private JSONObject dumpObjcClass(JSONObject args) {
        if (emulator.isRunning()) {
            return errorResult("Cannot call dump_objc_class while emulator is running. " +
                    "This tool calls ObjC runtime methods internally and requires the emulator to be stopped.");
        }
        if (emulator.getFamily() != Family.iOS) {
            return errorResult("dump_objc_class is only available on iOS emulators. Current family: " + emulator.getFamily());
        }
        String className = args.getString("class_name");
        if (className == null || className.isEmpty()) {
            return errorResult("class_name parameter is required.");
        }
        try {
            String classDef = emulator.dumpObjcClass(className);
            if (classDef == null || classDef.isEmpty()) {
                return errorResult("Class '" + className + "' not found or returned empty definition. " +
                        "Make sure the class exists in the ObjC runtime.");
            }
            return textResult("ObjC class dump for " + className + ":\n\n" + classDef +
                    "\n\nNote: Registers and stack may have been modified by the ObjC runtime calls used to extract this definition.");
        } catch (UnsupportedOperationException e) {
            return errorResult("ObjC class dump not supported: " + exMsg(e));
        } catch (Exception e) {
            return errorResult("Failed to dump ObjC class '" + className + "': " +
                    e.getClass().getSimpleName() + ": " + exMsg(e));
        }
    }

    private JSONObject dumpGpbProtobuf(JSONObject args) {
        if (emulator.isRunning()) {
            return errorResult("Cannot call dump_gpb_protobuf while emulator is running. " +
                    "This tool calls ObjC runtime methods internally and requires the emulator to be stopped.");
        }
        if (emulator.getFamily() != Family.iOS) {
            return errorResult("dump_gpb_protobuf is only available on iOS emulators. Current family: " + emulator.getFamily());
        }
        if (!emulator.is64Bit()) {
            return errorResult("dump_gpb_protobuf is only available on 64-bit iOS emulators.");
        }
        String className = args.getString("class_name");
        if (className == null || className.isEmpty()) {
            return errorResult("class_name parameter is required.");
        }
        try {
            String protoDef = emulator.dumpGPBProtobufDef(className);
            return textResult("GPB Protobuf definition for " + className + ":\n\n" + protoDef +
                    "\n\nNote: This is the message SCHEMA (field definitions), not actual data. " +
                    "Registers and stack may have been modified by the ObjC runtime calls used to extract this definition.");
        } catch (UnsupportedOperationException e) {
            return errorResult("GPB protobuf dump not supported: " + exMsg(e) +
                    ". Ensure the Google Protobuf Objective-C runtime (GPB) library is loaded and the class '" +
                    className + "' is a GPBMessage subclass that responds to 'descriptor'.");
        } catch (Exception e) {
            return errorResult("Failed to dump GPB protobuf for '" + className + "': " +
                    e.getClass().getSimpleName() + ": " + exMsg(e));
        }
    }

    private static int resolvePermission(String permission) {
        if (permission == null || permission.isEmpty() || "write".equalsIgnoreCase(permission)) {
            return UnicornConst.UC_PROT_WRITE;
        }
        if ("read".equalsIgnoreCase(permission)) {
            return UnicornConst.UC_PROT_READ;
        }
        if ("execute".equalsIgnoreCase(permission)) {
            return UnicornConst.UC_PROT_EXEC;
        }
        return UnicornConst.UC_PROT_WRITE;
    }

    private Keystone createKeystone() {
        if (emulator.is64Bit()) {
            return new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian);
        } else {
            boolean thumb = ARM.isThumb(emulator.getBackend());
            return new Keystone(KeystoneArchitecture.Arm, thumb ? KeystoneMode.ArmThumb : KeystoneMode.Arm);
        }
    }

    private int resolveRegister(String name) {
        if (emulator.is64Bit()) {
            if (name.startsWith("X")) {
                int num = Integer.parseInt(name.substring(1));
                if (num >= 0 && num <= 28) {
                    return Arm64Const.UC_ARM64_REG_X0 + num;
                } else if (num == 29) {
                    return Arm64Const.UC_ARM64_REG_FP;
                } else if (num == 30) {
                    return Arm64Const.UC_ARM64_REG_LR;
                }
                throw new IllegalArgumentException("Invalid X register number: " + num);
            }
            if (name.startsWith("W")) {
                int num = Integer.parseInt(name.substring(1));
                if (num >= 0 && num <= 30) {
                    return Arm64Const.UC_ARM64_REG_W0 + num;
                }
                throw new IllegalArgumentException("Invalid W register number: " + num);
            }
            switch (name) {
                case "SP": return Arm64Const.UC_ARM64_REG_SP;
                case "PC": return Arm64Const.UC_ARM64_REG_PC;
                case "LR": return Arm64Const.UC_ARM64_REG_LR;
                case "FP": return Arm64Const.UC_ARM64_REG_FP;
                default: throw new IllegalArgumentException("Unknown ARM64 register: " + name);
            }
        } else {
            if (name.startsWith("R")) {
                int num = Integer.parseInt(name.substring(1));
                if (num >= 0 && num <= 12) {
                    return ArmConst.UC_ARM_REG_R0 + num;
                } else if (num == 13) {
                    return ArmConst.UC_ARM_REG_SP;
                } else if (num == 14) {
                    return ArmConst.UC_ARM_REG_LR;
                } else if (num == 15) {
                    return ArmConst.UC_ARM_REG_PC;
                }
                throw new IllegalArgumentException("Invalid R register number: " + num);
            }
            switch (name) {
                case "SP": return ArmConst.UC_ARM_REG_SP;
                case "PC": return ArmConst.UC_ARM_REG_PC;
                case "LR": return ArmConst.UC_ARM_REG_LR;
                case "FP": return ArmConst.UC_ARM_REG_FP;
                case "IP": return ArmConst.UC_ARM_REG_IP;
                default: throw new IllegalArgumentException("Unknown ARM register: " + name);
            }
        }
    }

    private static long parseAddress(String address) {
        if (address == null) return 0;
        address = address.trim();
        if (address.startsWith("0x") || address.startsWith("0X")) {
            return Long.parseUnsignedLong(address.substring(2), 16);
        }
        return Long.parseUnsignedLong(address, 16);
    }

    private static String permString(int prot) {
        return ((prot & 1) != 0 ? "r" : "-") +
                ((prot & 2) != 0 ? "w" : "-") +
                ((prot & 4) != 0 ? "x" : "-");
    }

    private static JSONObject textResult(String text) {
        JSONObject result = new JSONObject(true);
        JSONArray content = new JSONArray();
        JSONObject item = new JSONObject(true);
        item.put("type", "text");
        item.put("text", text);
        content.add(item);
        result.put("content", content);
        return result;
    }

    static JSONObject errorResult(String message) {
        JSONObject result = textResult(message);
        result.put("isError", true);
        return result;
    }

    private static String exMsg(Exception e) {
        String msg = e.getMessage();
        if (msg == null || msg.isEmpty()) {
            return e.getClass().getName();
        }
        return msg;
    }

    private static JSONObject toolSchema(String name, String description, JSONObject... params) {
        JSONObject schema = new JSONObject(true);
        schema.put("name", name);
        schema.put("description", description);
        JSONObject inputSchema = new JSONObject(true);
        inputSchema.put("type", "object");
        if (params.length > 0) {
            JSONObject properties = new JSONObject(true);
            for (JSONObject p : params) {
                properties.put(p.getString("_name"), p);
                p.remove("_name");
            }
            inputSchema.put("properties", properties);
        }
        schema.put("inputSchema", inputSchema);
        return schema;
    }

    private static void putModuleInfo(JSONObject event, Emulator<?> emu, long address) {
        Module module = emu.getMemory().findModuleByAddress(address);
        if (module != null) {
            event.put("module", module.name);
            event.put("offset", "0x" + Long.toHexString(address - module.base));
        }
    }

    private static JSONObject buildInputSchema(String... paramNames) {
        JSONObject inputSchema = new JSONObject(true);
        inputSchema.put("type", "object");
        if (paramNames.length > 0) {
            JSONObject properties = new JSONObject(true);
            JSONArray required = new JSONArray();
            for (String pn : paramNames) {
                JSONObject p = new JSONObject(true);
                p.put("type", "string");
                properties.put(pn, p);
                required.add(pn);
            }
            inputSchema.put("properties", properties);
            inputSchema.put("required", required);
        }
        return inputSchema;
    }

    private static JSONObject param(String name, String type, String description) {
        JSONObject p = new JSONObject(true);
        p.put("_name", name);
        p.put("type", type);
        p.put("description", description);
        return p;
    }

    private static JSONObject argsParam(String description) {
        JSONObject p = new JSONObject(true);
        p.put("_name", "args");
        p.put("type", "array");
        JSONObject items = new JSONObject(true);
        items.put("type", "string");
        p.put("items", items);
        p.put("description", description);
        return p;
    }

    private static class CustomTool {
        final String name;
        final String description;
        final String[] paramNames;

        CustomTool(String name, String description, String[] paramNames) {
            this.name = name;
            this.description = description;
            this.paramNames = paramNames != null ? paramNames : new String[0];
        }
    }
}
