package com.github.unidbg.mcp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.debugger.DebugRunnable;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class McpServer {

    private static final Logger log = LoggerFactory.getLogger(McpServer.class);

    private final Emulator<?> emulator;
    private final int port;
    private final McpTools mcpTools;
    private final Map<String, McpSession> sessions = new ConcurrentHashMap<>();
    private HttpServer httpServer;
    private PipedOutputStream commandPipe;

    public McpServer(Emulator<?> emulator, int port) {
        this.emulator = emulator;
        this.port = port;
        this.mcpTools = new McpTools(emulator, this);
    }

    public int getPort() {
        return port;
    }

    public void setRunnable(DebugRunnable<?> runnable) {
        mcpTools.setRunnable(runnable);
    }

    public void addCustomTool(String name, String description, String... paramNames) {
        mcpTools.addCustomTool(name, description, paramNames);
    }

    public void start() throws IOException {
        commandPipe = new PipedOutputStream();
        PipedInputStream pipedIn = new PipedInputStream(commandPipe, 4096);

        OutputStream originalOut = System.out;
        java.io.InputStream originalIn = System.in;
        System.setIn(new MergedInputStream(originalIn, pipedIn));

        httpServer = HttpServer.create(new InetSocketAddress(port), 0);
        httpServer.setExecutor(Executors.newFixedThreadPool(4));
        httpServer.createContext("/sse", this::handleSse);
        httpServer.createContext("/message", this::handleMessage);
        httpServer.start();
    }

    public void stop() {
        if (httpServer != null) {
            httpServer.stop(0);
        }
        for (McpSession session : sessions.values()) {
            session.close();
        }
        sessions.clear();
    }

    public void injectCommand(String command) {
        if (commandPipe != null) {
            try {
                commandPipe.write((command + "\n").getBytes(StandardCharsets.UTF_8));
                commandPipe.flush();
            } catch (IOException e) {
                log.warn("Failed to inject command: {}", command, e);
            }
        }
    }

    public void broadcastNotification(String event, JSONObject data) {
        JSONObject notification = new JSONObject();
        notification.put("jsonrpc", "2.0");
        notification.put("method", "notifications/message");

        JSONObject params = new JSONObject();
        params.put("level", "info");
        params.put("logger", "unidbg");
        data.put("event", event);
        params.put("data", data.toJSONString());
        notification.put("params", params);

        for (McpSession session : sessions.values()) {
            if (!session.isClosed()) {
                session.sendNotification(notification);
            }
        }
    }

    private void handleSse(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method Not Allowed");
            return;
        }

        McpSession session = new McpSession();
        sessions.put(session.getSessionId(), session);

        session.attachSseStream(exchange);
        session.sendEndpointEvent("/message");

        while (!session.isClosed()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                break;
            }
        }
        sessions.remove(session.getSessionId());
    }

    private void handleMessage(HttpExchange exchange) throws IOException {
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
            exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, OPTIONS");
            exchange.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(exchange.getRequestMethod())) {
            sendErrorResponse(exchange, 405, "Method Not Allowed");
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String sessionId = null;
        if (query != null) {
            for (String param : query.split("&")) {
                if (param.startsWith("sessionId=")) {
                    sessionId = param.substring("sessionId=".length());
                    break;
                }
            }
        }

        McpSession session = sessionId != null ? sessions.get(sessionId) : null;
        if (session == null) {
            sendErrorResponse(exchange, 400, "Invalid session");
            return;
        }

        String body = IOUtils.toString(exchange.getRequestBody(), StandardCharsets.UTF_8);
        JSONObject request = JSON.parseObject(body);

        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(202, -1);
        exchange.close();

        String method = request.getString("method");
        Object id = request.get("id");

        if ("notifications/initialized".equals(method) || (method != null && method.startsWith("notifications/"))) {
            return;
        }

        JSONObject response = new JSONObject();
        response.put("jsonrpc", "2.0");
        response.put("id", id);

        try {
            JSONObject result = dispatch(method, request.getJSONObject("params"));
            response.put("result", result);
        } catch (Exception e) {
            JSONObject error = new JSONObject();
            error.put("code", -32603);
            error.put("message", e.getMessage());
            response.put("error", error);
        }

        session.sendJsonRpcResponse(response);
    }

    private JSONObject dispatch(String method, JSONObject params) {
        if ("initialize".equals(method)) {
            return handleInitialize();
        }
        if ("tools/list".equals(method)) {
            return handleToolsList();
        }
        if ("tools/call".equals(method)) {
            return handleToolsCall(params);
        }
        if ("ping".equals(method)) {
            return new JSONObject();
        }
        throw new RuntimeException("Unknown method: " + method);
    }

    private JSONObject handleInitialize() {
        JSONObject result = new JSONObject();

        JSONObject serverInfo = new JSONObject();
        serverInfo.put("name", "unidbg-mcp");
        serverInfo.put("version", "1.0.0");
        result.put("serverInfo", serverInfo);

        JSONObject capabilities = new JSONObject();
        JSONObject tools = new JSONObject();
        tools.put("listChanged", false);
        capabilities.put("tools", tools);
        JSONObject logging = new JSONObject();
        capabilities.put("logging", logging);
        result.put("capabilities", capabilities);

        result.put("protocolVersion", "2024-11-05");
        return result;
    }

    private JSONObject handleToolsList() {
        JSONObject result = new JSONObject();
        JSONArray toolsArray = mcpTools.getToolSchemas();
        result.put("tools", toolsArray);
        return result;
    }

    private JSONObject handleToolsCall(JSONObject params) {
        String name = params.getString("name");
        JSONObject arguments = params.getJSONObject("arguments");
        if (arguments == null) {
            arguments = new JSONObject();
        }
        return mcpTools.callTool(name, arguments);
    }

    private void sendErrorResponse(HttpExchange exchange, int code, String message) throws IOException {
        byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    public boolean isDebugging() {
        return emulator.is32Bit() || emulator.is64Bit();
    }
}
