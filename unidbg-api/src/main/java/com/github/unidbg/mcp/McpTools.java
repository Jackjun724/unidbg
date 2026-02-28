package com.github.unidbg.mcp;

import capstone.api.Instruction;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.TraceHook;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

public class McpTools {

    private final Emulator<?> emulator;
    private final McpServer server;
    private final List<CustomTool> customTools = new ArrayList<>();
    private TraceHook activeTraceCode;
    private TraceHook activeTraceRead;
    private TraceHook activeTraceWrite;

    public McpTools(Emulator<?> emulator, McpServer server) {
        this.emulator = emulator;
        this.server = server;
    }

    public void addCustomTool(String name, String description, String... paramNames) {
        customTools.add(new CustomTool(name, description, paramNames));
    }

    public JSONArray getToolSchemas() {
        JSONArray tools = new JSONArray();
        tools.add(toolSchema("check_connection", "Check emulator status. Returns: architecture, backend type and capabilities, process name, debug idle (true=paused/ready, false=running), breakpoint count, pending events, and modules. " +
                "Call this first to understand current state and backend limitations. " +
                "Backend capabilities vary: " +
                "Unicorn/Unicorn2: full support (unlimited breakpoints, code/read/write hooks, single-step, write hook reports size+value). " +
                "Hypervisor (macOS): hardware breakpoints (limited count), 1 code hook at a time, write hook cannot report size/value, single-step supported. " +
                "Dynarmic/KVM: breakpoints only, no code/read/write hooks, no single-step — trace_code/trace_read/trace_write/step_into/step_over will NOT work."));
        tools.add(toolSchema("read_memory", "Read memory at address and return hex dump",
                param("address", "string", "Hex address, e.g. 0x40001000"),
                param("size", "integer", "Number of bytes to read, default 0x70")));
        tools.add(toolSchema("write_memory", "Write hex bytes to memory at address",
                param("address", "string", "Hex address"),
                param("hex_bytes", "string", "Hex encoded bytes to write")));
        tools.add(toolSchema("list_memory_map", "List all memory mapped regions with base, size and permissions"));
        tools.add(toolSchema("search_memory", "Search for byte pattern or text string in memory. " +
                        "Supports: (1) hex byte pattern with optional ?? wildcards (e.g. '48656c6c6f', 'ff??00??ab'), " +
                        "(2) text string search (set type='string'). " +
                        "Search scope: specify module_name to search within a module, or start+end for a specific range, " +
                        "or omit all to search all readable mapped memory.",
                param("pattern", "string", "The pattern to search. For hex: hex bytes, ?? for wildcard. For string: the text to find."),
                param("type", "string", "Optional. 'hex' (default) or 'string'. If 'string', pattern is treated as UTF-8 text."),
                param("module_name", "string", "Optional. Search only within this module."),
                param("start", "string", "Optional. Hex start address."),
                param("end", "string", "Optional. Hex end address."),
                param("max_results", "integer", "Optional. Max matches to return. Default 50.")));

        tools.add(toolSchema("get_registers", "Read all general purpose registers"));
        tools.add(toolSchema("get_register", "Read a specific register by name",
                param("name", "string", "Register name, e.g. X0, R0, SP, PC, LR")));
        tools.add(toolSchema("set_register", "Write a value to a specific register",
                param("name", "string", "Register name"),
                param("value", "string", "Hex value to write")));

        tools.add(toolSchema("disassemble", "Disassemble instructions at address. To disassemble at current PC, first use get_register to read PC value.",
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
        tools.add(toolSchema("list_breakpoints", "List all currently set breakpoints with address, module info and temporary status"));
        tools.add(toolSchema("run_until", "Run emulator until it reaches a specific address, then stop. " +
                        "Internally sets a temporary breakpoint, continues execution, and waits for the breakpoint to be hit. " +
                        "Returns when the target address is reached, execution completes, or timeout expires. " +
                        "Much more efficient than repeated continue_execution + poll_events cycles.",
                param("address", "string", "Hex target address to run to"),
                param("timeout_ms", "integer", "Optional. Max milliseconds to wait. Default 30000 (30s). Set 0 for no timeout (wait indefinitely).")));
        tools.add(toolSchema("continue_execution", "Resume emulator execution. " +
                "If paused at a breakpoint, continues from current PC. " +
                "If emulation has completed, re-runs the emulation from the beginning. " +
                "Returns immediately; use poll_events to receive execution_started, breakpoint_hit, or execution_completed events."));
        tools.add(toolSchema("step_over", "Step over current instruction (does not enter function calls). " +
                "Sets a temporary breakpoint at the next instruction and resumes. Use poll_events to wait for completion."));
        tools.add(toolSchema("step_into", "Step into: execute specified number of instructions then stop. Use poll_events to wait for completion.",
                param("count", "integer", "Number of instructions to execute. Default 1.")));
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
        tools.add(toolSchema("trace_code", "Start tracing instruction execution in address range. Each executed instruction triggers a trace_code event (with address, mnemonic, operands, size, module, offset) collected via poll_events. Useful for understanding execution flow and control transfer. Trace is automatically removed when a breakpoint hits, single-step completes, or execution finishes.",
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
                        "Arguments are passed via args array. Each element is a string with a type prefix: " +
                        "'0x1234' or '1234' for integer/hex values, " +
                        "'s:hello world' for C string (auto-allocated in memory, pointer passed), " +
                        "'b:48656c6c6f' for byte array (auto-allocated, pointer passed), " +
                        "'null' for null pointer. " +
                        "Return value is the function's return (X0 on ARM64, R0 on ARM32).",
                param("address", "string", "Hex address of the function to call"),
                param("args", "array", "Optional. Array of argument strings with type prefix. E.g. [\"0x1\", \"s:hello\", \"null\"]")));

        tools.add(toolSchema("list_modules", "List all loaded modules with name, base address and size"));
        tools.add(toolSchema("get_module_info", "Get detailed information about a loaded module",
                param("module_name", "string", "Module name, e.g. libnative.so")));

        for (CustomTool ct : customTools) {
            JSONObject schema = new JSONObject(true);
            schema.put("name", ct.name);
            schema.put("description", "Re-run emulation: " + ct.description);
            if (ct.paramNames.length > 0) {
                schema.put("inputSchema", buildInputSchema(ct.paramNames));
            }
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
        if ("run_until".equals(name)) return true;
        if ("step_over".equals(name)) return true;
        if ("step_into".equals(name)) return true;
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
            case "remove_breakpoint": return removeBreakpoint(args);
            case "list_breakpoints": return listBreakpoints();
            case "continue_execution": return continueExecution();
            case "run_until": return runUntil(args);
            case "step_over": return stepOver();
            case "step_into": return stepInto(args);
            case "poll_events": return pollEvents(args);
            case "trace_read": return traceRead(args);
            case "trace_write": return traceWrite(args);
            case "trace_code": return traceCode(args);
            case "get_callstack": return getCallstack();
            case "find_symbol": return findSymbol(args);
            case "read_string": return readString(args);
            case "read_pointer": return readPointer(args);
            case "read_typed": return readTyped(args);
            case "call_function": return callFunction(args);
            case "list_modules": return listModules();
            case "get_module_info": return getModuleInfo(args);
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
        sb.append("Architecture: ").append(emulator.is64Bit() ? "ARM64" : "ARM32").append('\n');
        String backendClass = emulator.getBackend().getClass().getSimpleName();
        sb.append("Backend: ").append(backendClass).append('\n');
        sb.append("Backend capabilities: ").append(getBackendCapabilities(backendClass)).append('\n');
        sb.append("Process: ").append(emulator.getProcessName()).append('\n');
        sb.append("Debug idle: ").append(server.isDebugIdle()).append('\n');
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
            return "FULL — unlimited breakpoints, code/read/write trace, single-step, write trace reports size+value";
        } else if (backendClass.contains("Hypervisor")) {
            return "PARTIAL — hardware breakpoints (limited count), 1 code trace at a time, read/write trace via watchpoints (limited count), " +
                    "write trace cannot report size/value, single-step supported";
        } else if (backendClass.contains("Dynarmic") || backendClass.contains("Kvm")) {
            return "MINIMAL — breakpoints only, NO code/read/write trace, NO single-step (trace_code/trace_read/trace_write/step_into/step_over unavailable)";
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
            return errorResult("Failed to read memory at 0x" + Long.toHexString(address) + ": " + e.getMessage());
        }
    }

    private JSONObject writeMemory(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        String hexBytes = args.getString("hex_bytes");
        try {
            byte[] data = Hex.decodeHex(hexBytes.toCharArray());
            emulator.getBackend().mem_write(address, data);
            return textResult("Written " + data.length + " bytes to 0x" + Long.toHexString(address));
        } catch (DecoderException e) {
            return errorResult("Invalid hex: " + hexBytes);
        } catch (Exception e) {
            return errorResult("Failed to write memory: " + e.getMessage());
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
        if (moduleName != null && !moduleName.isEmpty()) {
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
        String name = args.getString("name").toUpperCase();
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
            return errorResult("Failed to read register " + name + ": " + e.getMessage());
        }
    }

    private JSONObject setRegister(JSONObject args) {
        String name = args.getString("name").toUpperCase();
        long value = parseAddress(args.getString("value"));
        try {
            int regId = resolveRegister(name);
            emulator.getBackend().reg_write(regId, value);
            return textResult(name + " set to 0x" + Long.toHexString(value));
        } catch (Exception e) {
            return errorResult("Failed to set register " + name + ": " + e.getMessage());
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
            StringBuilder sb = new StringBuilder();
            for (Instruction insn : insns) {
                sb.append(String.format("0x%x: %s %s%n", insn.getAddress(), insn.getMnemonic(), insn.getOpStr()));
            }
            if (insns.length == 0) {
                sb.append("No instructions at 0x").append(Long.toHexString(address));
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Disassemble failed: " + e.getMessage());
        }
    }

    private JSONObject assemble(JSONObject args) {
        String assembly = args.getString("assembly");
        try (Keystone keystone = createKeystone()) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            byte[] code = encoded.getMachineCode();
            return textResult("Machine code: " + Hex.encodeHexString(code) + " (" + code.length + " bytes)");
        } catch (Exception e) {
            return errorResult("Assemble failed: " + e.getMessage());
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
            return errorResult("Patch failed: " + e.getMessage());
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
            return errorResult("Failed to add breakpoint: " + e.getMessage());
        }
    }

    private JSONObject listBreakpoints() {
        try {
            Map<Long, BreakPoint> breakPoints = emulator.attach().getBreakPoints();
            if (breakPoints.isEmpty()) {
                return textResult("No breakpoints set.");
            }
            Memory memory = emulator.getMemory();
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
                sb.append(String.format("0x%x  %s%s%n", addr, location, temp));
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            return errorResult("Failed to list breakpoints: " + e.getMessage());
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
            return errorResult("Failed to remove breakpoint: " + e.getMessage());
        }
    }

    private JSONObject continueExecution() {
        server.injectCommand("c");
        return textResult("Execution resumed. Use poll_events to wait for breakpoint_hit or execution_completed.");
    }

    private JSONObject runUntil(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        long timeoutMs = args.containsKey("timeout_ms") ? args.getLongValue("timeout_ms") : 30000;

        if (!server.isDebugIdle()) {
            return errorResult("Emulator is not in debug idle state.");
        }

        try {
            server.runOnDebuggerThread(() -> {
                BreakPoint bp = emulator.attach().addBreakPoint(address);
                bp.setTemporary(true);
                return null;
            });
        } catch (Exception e) {
            return errorResult("Failed to set temporary breakpoint: " + e.getMessage());
        }

        server.pollEvents(0);
        server.injectCommand("c");

        long deadline = timeoutMs > 0 ? System.currentTimeMillis() + timeoutMs : Long.MAX_VALUE;
        List<JSONObject> allEvents = new ArrayList<>();
        boolean reached = false;
        boolean completed = false;

        while (System.currentTimeMillis() < deadline) {
            long remaining = timeoutMs > 0 ? Math.max(1, deadline - System.currentTimeMillis()) : 5000;
            long pollTime = Math.min(remaining, 5000);
            List<JSONObject> events = server.pollEvents(pollTime);
            allEvents.addAll(events);

            for (JSONObject event : events) {
                String eventType = event.getString("event");
                if ("breakpoint_hit".equals(eventType)) {
                    String pc = event.getString("pc");
                    if (pc != null && parseAddress(pc) == address) {
                        reached = true;
                    }
                } else if ("execution_completed".equals(eventType)) {
                    completed = true;
                }
            }
            if (reached || completed) break;
        }

        StringBuilder sb = new StringBuilder();
        if (reached) {
            sb.append("Reached target address 0x").append(Long.toHexString(address)).append('\n');
            try {
                JSONObject regs = server.runOnDebuggerThread(this::getRegisters);
                String regsText = regs.getJSONArray("content").getJSONObject(0).getString("text");
                sb.append(regsText);
            } catch (Exception ignored) {
            }
        } else if (completed) {
            sb.append("Execution completed before reaching 0x").append(Long.toHexString(address)).append('\n');
        } else {
            try {
                server.runOnDebuggerThread(() -> {
                    emulator.attach().removeBreakPoint(address);
                    return null;
                });
            } catch (Exception ignored) {
            }
            sb.append("Timeout after ").append(timeoutMs).append("ms. Target 0x").append(Long.toHexString(address)).append(" not reached.\n");
        }
        if (!allEvents.isEmpty()) {
            sb.append("\nEvents during execution: ").append(allEvents.size()).append('\n');
            int show = Math.min(allEvents.size(), 20);
            for (int i = 0; i < show; i++) {
                sb.append(allEvents.get(i).toJSONString()).append('\n');
            }
            if (allEvents.size() > show) {
                sb.append("... and ").append(allEvents.size() - show).append(" more events\n");
            }
        }
        return textResult(sb.toString());
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
            return errorResult("Failed to start trace read: " + e.getClass().getName() + ": " + e.getMessage());
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
            return errorResult("Failed to start trace write: " + e.getClass().getName() + ": " + e.getMessage());
        }
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
                server.queueEvent(event);
                if (breakOn != -1 && address == breakOn) {
                    emu.attach().debug();
                }
            });
            StringBuilder msg = new StringBuilder("Trace code started: 0x" + Long.toHexString(begin) + " - 0x" + Long.toHexString(end));
            if (breakOn != -1) {
                msg.append(", will break on PC 0x").append(Long.toHexString(breakOn));
            }
            msg.append(". Trace data will be collected as trace_code events, use poll_events to retrieve.");
            return textResult(msg.toString());
        } catch (Exception e) {
            return errorResult("Failed to start trace code: " + e.getClass().getName() + ": " + e.getMessage());
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
            return errorResult("Failed to get callstack: " + e.getClass().getName() + ": " + e.getMessage());
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
            return errorResult("Find symbol failed: " + e.getClass().getName() + ": " + e.getMessage());
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
            return errorResult("Failed to read string at 0x" + Long.toHexString(address) + ": " + e.getMessage());
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
            sb.append(String.format("    (read failed at 0x%x: %s)%n", currentAddr, e.getMessage()));
        }
        return textResult(sb.toString());
    }

    private JSONObject readTyped(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        String type = args.getString("type").toLowerCase();
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
            return errorResult("Failed to read typed data at 0x" + Long.toHexString(address) + ": " + e.getMessage());
        }
    }

    private JSONObject callFunction(JSONObject args) {
        if (emulator.isRunning()) {
            return errorResult("Cannot call function while emulator is running.");
        }

        long address = parseAddress(args.getString("address"));
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
                    return errorResult("Invalid argument[" + i + "] '" + argStr + "': " + e.getMessage());
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Calling 0x").append(Long.toHexString(address));
        Module module = emulator.getMemory().findModuleByAddress(address);
        if (module != null) {
            sb.append(" (").append(module.name).append("+0x").append(Long.toHexString(address - module.base)).append(')');
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

        try {
            Number result = Module.emulateFunction(emulator, address, funcArgs);
            long retVal = result.longValue();
            sb.append("\nResult: 0x").append(Long.toHexString(retVal));
            sb.append(" (").append(retVal).append(")\n");
            Module retModule = emulator.getMemory().findModuleByAddress(retVal);
            if (retModule != null) {
                sb.append("  -> ").append(retModule.name).append("+0x").append(Long.toHexString(retVal - retModule.base)).append('\n');
            }
            if (retVal > 0x1000 && retVal < 0xFFFFFFFFL) {
                try {
                    byte[] strData = emulator.getBackend().mem_read(retVal, 64);
                    int len = 0;
                    boolean printable = true;
                    while (len < strData.length && strData[len] != 0) {
                        if (strData[len] < 0x20 || strData[len] > 0x7e) {
                            printable = false;
                            break;
                        }
                        len++;
                    }
                    if (printable && len > 0) {
                        sb.append("  -> string: \"").append(new String(strData, 0, len, java.nio.charset.StandardCharsets.UTF_8)).append("\"\n");
                    }
                } catch (Exception ignored) {
                }
            }
            return textResult(sb.toString());
        } catch (Exception e) {
            sb.append("\nCall FAILED: ").append(e.getClass().getName()).append(": ").append(e.getMessage()).append('\n');
            Throwable cause = e.getCause();
            if (cause != null) {
                sb.append("Caused by: ").append(cause.getClass().getName()).append(": ").append(cause.getMessage()).append('\n');
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

    private JSONObject listModules() {
        Collection<Module> modules = emulator.getMemory().getLoadedModules();
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%-40s %-18s %-10s%n", "Name", "Base", "Size"));
        for (Module m : modules) {
            sb.append(String.format("%-40s 0x%016x 0x%x%n", m.name, m.base, m.size));
        }
        return textResult(sb.toString());
    }

    private JSONObject getModuleInfo(JSONObject args) {
        String moduleName = args.getString("module_name");
        Module module = emulator.getMemory().findModule(moduleName);
        if (module == null) {
            return errorResult("Module not found: " + moduleName);
        }
        String sb = "Name: " + module.name + '\n' +
                "Base: 0x" + Long.toHexString(module.base) + '\n' +
                "Size: 0x" + Long.toHexString(module.size) + '\n' +
                "Path: " + module.getPath() + '\n';
        return textResult(sb);
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
        return inputSchema;
    }

    private static JSONObject param(String name, String type, String description) {
        JSONObject p = new JSONObject(true);
        p.put("_name", name);
        p.put("type", type);
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
