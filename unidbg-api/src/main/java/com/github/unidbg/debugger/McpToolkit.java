package com.github.unidbg.debugger;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class McpToolkit implements DebugRunnable<Void> {

    private final Map<String, McpTool> tools = new LinkedHashMap<>();

    public McpToolkit addTool(McpTool tool) {
        tools.put(tool.name(), tool);
        return this;
    }

    public void run(Debugger debugger) throws Exception {
        for (McpTool tool : tools.values()) {
            debugger.addMcpTool(tool.name(), tool.description(), tool.paramNames());
        }
        debugger.run(this);
    }

    @Override
    public Void runWithArgs(String[] args) throws Exception {
        String toolName = args != null ? args[0] : null;
        McpTool tool = toolName != null ? tools.get(toolName) : null;
        if (tool != null) {
            String[] params = args.length > 1 ? Arrays.copyOfRange(args, 1, args.length) : new String[0];
            tool.execute(params);
        }
        return null;
    }

}
