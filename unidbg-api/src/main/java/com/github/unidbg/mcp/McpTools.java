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
        tools.add(toolSchema("search_memory", "Search for byte pattern in memory range",
                param("pattern", "string", "Hex encoded byte pattern to search for"),
                param("start", "string", "Hex start address"),
                param("end", "string", "Hex end address")));

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
            case "step_over": return stepOver();
            case "step_into": return stepInto(args);
            case "poll_events": return pollEvents(args);
            case "trace_read": return traceRead(args);
            case "trace_write": return traceWrite(args);
            case "trace_code": return traceCode(args);
            case "get_callstack": return getCallstack();
            case "find_symbol": return findSymbol(args);
            case "read_string": return readString(args);
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
        long start = parseAddress(args.getString("start"));
        long end = parseAddress(args.getString("end"));
        String patternHex = args.getString("pattern");
        try {
            byte[] pattern = Hex.decodeHex(patternHex.toCharArray());
            Backend backend = emulator.getBackend();
            List<String> results = new ArrayList<>();
            long chunkSize = 0x10000;
            for (long addr = start; addr < end; addr += chunkSize) {
                long readSize = Math.min(chunkSize, end - addr);
                byte[] chunk = backend.mem_read(addr, (int) readSize);
                for (int i = 0; i <= chunk.length - pattern.length; i++) {
                    boolean match = true;
                    for (int j = 0; j < pattern.length; j++) {
                        if (chunk[i + j] != pattern[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        results.add("0x" + Long.toHexString(addr + i));
                        if (results.size() >= 100) break;
                    }
                }
                if (results.size() == 100) break;
            }
            if (results.isEmpty()) {
                return textResult("Pattern not found");
            }
            return textResult("Found " + results.size() + " match(es):\n" + String.join("\n", results));
        } catch (DecoderException e) {
            return errorResult("Invalid hex pattern: " + patternHex);
        } catch (Exception e) {
            return errorResult("Search failed: " + e.getMessage());
        }
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
            if (name.startsWith("X") || name.startsWith("W")) {
                int num = Integer.parseInt(name.substring(1));
                return Arm64Const.UC_ARM64_REG_X0 + num;
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
                return ArmConst.UC_ARM_REG_R0 + num;
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
