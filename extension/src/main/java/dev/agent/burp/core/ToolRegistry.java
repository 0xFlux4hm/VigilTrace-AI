package dev.agent.burp.core;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.agent.burp.gateway.BurpGateway;
import dev.agent.burp.gateway.GatewayException;
import dev.agent.burp.gateway.KeyValueStore;
import dev.agent.burp.json.Json;

/**
 * Name → tool dispatch plus the manifest served at {@code GET /tools}. The manifest is the {@code burp-tools.json}
 * resource that the build writes from the package's {@code aobh/tools/tools.json}, so the bridge, the docs and the MCP
 * server show the same definitions. Every call goes through {@link #dispatch}, which produces the response envelope,
 * validates required arguments and keeps the {@code tool_calls} / {@code tool_errors} counters.
 */
public final class ToolRegistry {
    static final String MANIFEST_RESOURCE = "/burp-tools.json";
    public static final String EXTENSION_NAME = "AI Agent Bridge";
    /** Wire protocol version of the bridge endpoints. */
    public static final int PROTOCOL_VERSION = 1;
    /** Hard cap on a request body (tool arguments). */
    public static final long MAX_BODY_BYTES = 16L * 1024 * 1024;

    private final BurpGateway gateway;
    private final TrafficCounters counters;
    private final RateLimiter rate;
    private final ToolContext ctx;
    private final Map<String, Tool> tools = new LinkedHashMap<>();
    private final Map<String, Map<String, Object>> definitions = new LinkedHashMap<>();
    private final Map<String, List<String>> required = new LinkedHashMap<>();
    private final ScopeGuard scope;
    private Map<String, Object> manifestMeta = new LinkedHashMap<>();

    private ToolRegistry(BurpGateway gateway, TrafficCounters counters, RateLimiter rate, ToolContext ctx, ScopeGuard scope) {
        this.gateway = gateway;
        this.counters = counters;
        this.rate = rate;
        this.ctx = ctx;
        this.scope = scope;
    }

    /** Wires the persisted components and registers the given tools; fails loudly if a tool lacks a manifest entry. */
    public static ToolRegistry create(BurpGateway gateway, TrafficCounters counters, RateLimiter rate,
                                      KeyValueStore store, List<Tool> toolInstances) {
        ScopeBackend backend = new ScopeBackend() {
            @Override
            public boolean isInScope(String url) {
                return gateway.isInScope(url);
            }

            @Override
            public void include(String prefix) {
                gateway.includeInScope(prefix);
            }

            @Override
            public void exclude(String prefix) {
                gateway.excludeFromScope(prefix);
            }
        };
        ScopeGuard scope = ScopeGuard.load(store, backend);
        ToolContext ctx = new ToolContext(gateway, counters, rate, scope, RequestLog.load(store), CollabSession.load(gateway, store));
        ToolRegistry registry = new ToolRegistry(gateway, counters, rate, ctx, scope);
        registry.loadManifest();
        for (Tool tool : toolInstances) {
            registry.tools.put(tool.name(), tool);
            if (!registry.definitions.containsKey(tool.name())) {
                throw new IllegalStateException("Tool " + tool.name() + " has no entry in " + MANIFEST_RESOURCE);
            }
        }
        for (String name : registry.definitions.keySet()) {
            if (!registry.tools.containsKey(name)) {
                throw new IllegalStateException("Manifest tool " + name + " has no implementation");
            }
        }
        return registry;
    }

    @SuppressWarnings("unchecked")
    private void loadManifest() {
        try (InputStream in = ToolRegistry.class.getResourceAsStream(MANIFEST_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException(MANIFEST_RESOURCE + " is missing from the jar — build with extension/build.py");
            }
            Map<String, Object> doc = Json.parseObject(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            Object meta = doc.get("meta");
            if (meta instanceof Map<?, ?>) {
                manifestMeta = new LinkedHashMap<>((Map<String, Object>) meta);
            }
            Object list = doc.get("tools");
            if (!(list instanceof List<?> items)) {
                throw new IllegalStateException(MANIFEST_RESOURCE + " has no tools array");
            }
            for (Object o : items) {
                Map<String, Object> def = (Map<String, Object>) o;
                String name = String.valueOf(def.get("name"));
                definitions.put(name, def);
                Object schema = def.get("inputSchema");
                Object req = schema instanceof Map<?, ?> m ? m.get("required") : null;
                List<String> names = new ArrayList<>();
                if (req instanceof List<?> l) {
                    for (Object r : l) {
                        names.add(String.valueOf(r));
                    }
                }
                required.put(name, names);
            }
        } catch (IOException | ClassCastException | Json.JsonException e) {
            throw new IllegalStateException("Could not read " + MANIFEST_RESOURCE + ": " + e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------------- introspection

    public int toolCount() {
        return tools.size();
    }

    public List<String> toolNames() {
        return new ArrayList<>(tools.keySet());
    }

    public String version() {
        return String.valueOf(manifestMeta.get("version"));
    }

    /** The {@code GET /health} document. */
    public Map<String, Object> health() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("extension", EXTENSION_NAME);
        m.put("version", version());
        m.put("protocol_version", PROTOCOL_VERSION);
        m.put("counters_version", TrafficCounters.COUNTERS_VERSION);
        m.put("instance", counters.instance());
        m.put("started_at", counters.startedAt());
        m.put("uptime_seconds", counters.uptimeSeconds());
        m.put("mode", gateway.mode());
        m.put("burp_version", gateway.productVersion());
        m.put("tools", tools.size());
        m.put("rate_limit_per_second", rate.permitsPerSecond());
        m.put("scope_prefixes", scope.registry().size());
        m.put("counters", counters.snapshot());
        m.put("counters_note", "Monotonic for this instance only. Key on 'instance' and sum across instances; "
                + "fuzz_requests is a subset of requests_sent; scope-refused requests are not in requests_sent.");
        return m;
    }

    /** The {@code GET /tools} document. */
    public Map<String, Object> manifest() {
        Map<String, Object> meta = new LinkedHashMap<>();
        for (String key : new String[] {"name", "version", "protocol", "response_envelope", "source_schema", "safety_model", "authorization", "bridge"}) {
            if (manifestMeta.containsKey(key)) {
                meta.put(key, manifestMeta.get(key));
            }
        }
        return Json.obj(
                "tools", new ArrayList<>(definitions.values()),
                "count", definitions.size(),
                "meta", meta);
    }

    /** Manifest definition of one tool (self-test parity checks). */
    public Map<String, Object> definition(String toolName) {
        return definitions.get(toolName);
    }

    /** The counters behind {@code GET /health} (self-test). */
    public TrafficCounters counters() {
        return counters;
    }

    /** The authorization registry (the self-test seeds it the way a bootstrap would). */
    public ScopeGuard scope() {
        return scope;
    }

    // ---------------------------------------------------------------- dispatch

    /** Runs one tool call: JSON arguments in, the response envelope as JSON out. Never throws. */
    public String dispatch(String toolName, String body) {
        counters.recordToolCall();
        Map<String, Object> out;
        try {
            Tool tool = tools.get(toolName);
            if (tool == null) {
                throw new ToolException("unknown_tool", "Unknown tool '" + toolName + "'. GET /tools lists the " + tools.size() + " available tools.");
            }
            Map<String, Object> raw;
            try {
                raw = Json.parseObject(body);
            } catch (Json.JsonException e) {
                throw new ToolException("invalid_json", "The request body is not valid JSON: " + e.getMessage());
            }
            Args args = new Args(raw);
            for (String r : required.getOrDefault(toolName, List.of())) {
                if (!args.has(r)) {
                    throw new ToolException("missing_argument", "Missing required argument '" + r + "' for " + toolName + ".");
                }
            }
            Map<String, Object> data = tool.handle(ctx, args);
            out = Json.obj("ok", true, "data", data == null ? new LinkedHashMap<String, Object>() : data);
        } catch (ToolException e) {
            if (!ToolException.OUT_OF_SCOPE.equals(e.getMessage())) {
                counters.recordRejectedOther();
            }
            out = Json.obj("ok", false, "error", e.getMessage(), "hint", e.hint());
        } catch (GatewayException e) {
            counters.recordToolError();
            out = Json.obj("ok", false, "error", "burp_error", "hint", "Burp returned an error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            counters.recordToolError();
            out = Json.obj("ok", false, "error", "interrupted", "hint", "The bridge was stopped while the tool was running.");
        } catch (IllegalArgumentException e) {   // JsonException extends IllegalArgumentException
            counters.recordRejectedOther();
            out = Json.obj("ok", false, "error", "invalid_argument", "hint", e.getMessage());
        } catch (RuntimeException e) {
            counters.recordToolError();
            gateway.logError("Internal error in " + toolName, e);
            out = Json.obj("ok", false, "error", "internal_error",
                    "hint", "Unexpected failure in " + toolName + ": " + e + ". The exchange was not sent unless a send was already counted; check /health.");
        }
        return Json.write(out);
    }
}
