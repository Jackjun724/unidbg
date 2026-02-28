package com.github.unidbg.mcp;

import capstone.api.Instruction;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.BreakPoint;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.utils.Inspector;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class McpTools {

    private final Emulator<?> emulator;
    private final McpServer server;
    private DebugRunnable<?> runnable;
    private final List<CustomTool> customTools = new ArrayList<>();

    public McpTools(Emulator<?> emulator, McpServer server) {
        this.emulator = emulator;
        this.server = server;
    }

    public void setRunnable(DebugRunnable<?> runnable) {
        this.runnable = runnable;
    }

    public void addCustomTool(String name, String description, String... paramNames) {
        customTools.add(new CustomTool(name, description, paramNames));
    }

    public JSONArray getToolSchemas() {
        JSONArray tools = new JSONArray();
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

        tools.add(toolSchema("disassemble", "Disassemble instructions at address",
                param("address", "string", "Hex address"),
                param("count", "integer", "Number of instructions to disassemble, default 10")));
        tools.add(toolSchema("assemble", "Assemble instruction text to machine code hex (does not write to memory)",
                param("assembly", "string", "Assembly instruction text, e.g. 'mov x0, #1'"),
                param("address", "string", "Hex address for PC-relative encoding, default 0")));
        tools.add(toolSchema("patch", "Assemble instruction and write to memory at address",
                param("address", "string", "Hex address to patch"),
                param("assembly", "string", "Assembly instruction text")));
        tools.add(toolSchema("add_breakpoint", "Add a breakpoint at address",
                param("address", "string", "Hex address")));
        tools.add(toolSchema("remove_breakpoint", "Remove breakpoint at address",
                param("address", "string", "Hex address")));
        tools.add(toolSchema("continue_execution", "Resume emulator execution. Returns immediately; breakpoint hits and completion are reported via async notifications."));

        tools.add(toolSchema("trace_read", "Start tracing memory reads in address range. Events are reported via async notifications.",
                param("begin", "string", "Hex start address"),
                param("end", "string", "Hex end address")));
        tools.add(toolSchema("trace_write", "Start tracing memory writes in address range. Events are reported via async notifications.",
                param("begin", "string", "Hex start address"),
                param("end", "string", "Hex end address")));
        tools.add(toolSchema("stop_trace", "Stop all memory read/write tracing"));

        tools.add(toolSchema("list_modules", "List all loaded modules with name, base address and size"));
        tools.add(toolSchema("get_module_info", "Get detailed information about a loaded module",
                param("module_name", "string", "Module name, e.g. libnative.so")));

        for (CustomTool ct : customTools) {
            JSONObject schema = new JSONObject(true);
            schema.put("name", ct.name);
            schema.put("description", "Re-run emulation: " + ct.description);
            if (ct.paramNames.length > 0) {
                JSONObject inputSchema = new JSONObject(true);
                inputSchema.put("type", "object");
                JSONObject properties = new JSONObject(true);
                JSONArray required = new JSONArray();
                for (String pn : ct.paramNames) {
                    JSONObject p = new JSONObject(true);
                    p.put("type", "string");
                    properties.put(pn, p);
                    required.add(pn);
                }
                inputSchema.put("properties", properties);
                inputSchema.put("required", required);
                schema.put("inputSchema", inputSchema);
            }
            tools.add(schema);
        }
        return tools;
    }

    public JSONObject callTool(String name, JSONObject args) {
        if (!emulator.getSyscallHandler().isRunning() || isExecutionTool(name)) {
            return dispatchTool(name, args);
        }
        return errorResult("Emulator is running. Tools can only be called when emulator is in debug idle state.");
    }

    private boolean isExecutionTool(String name) {
        if ("continue_execution".equals(name)) return true;
        for (CustomTool ct : customTools) {
            if (ct.name.equals(name)) return true;
        }
        return false;
    }

    private JSONObject dispatchTool(String name, JSONObject args) {
        switch (name) {
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
            case "continue_execution": return continueExecution();
            case "trace_read": return traceRead(args);
            case "trace_write": return traceWrite(args);
            case "stop_trace": return stopTrace();
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
                if (results.size() >= 100) break;
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
        try {
            BreakPoint bp = emulator.attach().addBreakPoint(address);
            return textResult("Breakpoint added at 0x" + Long.toHexString(address));
        } catch (Exception e) {
            return errorResult("Failed to add breakpoint: " + e.getMessage());
        }
    }

    private JSONObject removeBreakpoint(JSONObject args) {
        long address = parseAddress(args.getString("address"));
        try {
            emulator.getBackend().removeBreakPoint(address);
            return textResult("Breakpoint removed at 0x" + Long.toHexString(address));
        } catch (Exception e) {
            return errorResult("Failed to remove breakpoint: " + e.getMessage());
        }
    }

    private JSONObject continueExecution() {
        server.injectCommand("c");
        return textResult("Execution resumed");
    }

    private JSONObject traceRead(JSONObject args) {
        long begin = parseAddress(args.getString("begin"));
        long end = parseAddress(args.getString("end"));
        try {
            emulator.traceRead(begin, end);
            return textResult("Trace read started: 0x" + Long.toHexString(begin) + " - 0x" + Long.toHexString(end));
        } catch (Exception e) {
            return errorResult("Failed to start trace read: " + e.getMessage());
        }
    }

    private JSONObject traceWrite(JSONObject args) {
        long begin = parseAddress(args.getString("begin"));
        long end = parseAddress(args.getString("end"));
        try {
            emulator.traceWrite(begin, end);
            return textResult("Trace write started: 0x" + Long.toHexString(begin) + " - 0x" + Long.toHexString(end));
        } catch (Exception e) {
            return errorResult("Failed to start trace write: " + e.getMessage());
        }
    }

    private JSONObject stopTrace() {
        return textResult("Trace stopped");
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
        StringBuilder sb = new StringBuilder();
        sb.append("Name: ").append(module.name).append('\n');
        sb.append("Base: 0x").append(Long.toHexString(module.base)).append('\n');
        sb.append("Size: 0x").append(Long.toHexString(module.size)).append('\n');
        sb.append("Path: ").append(module.getPath()).append('\n');
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

    private static JSONObject errorResult(String message) {
        JSONObject result = new JSONObject(true);
        JSONArray content = new JSONArray();
        JSONObject item = new JSONObject(true);
        item.put("type", "text");
        item.put("text", message);
        content.add(item);
        result.put("content", content);
        result.put("isError", true);
        return result;
    }

    private static JSONObject toolSchema(String name, String description, JSONObject... params) {
        JSONObject schema = new JSONObject(true);
        schema.put("name", name);
        schema.put("description", description);
        if (params.length > 0) {
            JSONObject inputSchema = new JSONObject(true);
            inputSchema.put("type", "object");
            JSONObject properties = new JSONObject(true);
            for (JSONObject p : params) {
                properties.put(p.getString("_name"), p);
                p.remove("_name");
            }
            inputSchema.put("properties", properties);
            schema.put("inputSchema", inputSchema);
        }
        return schema;
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
