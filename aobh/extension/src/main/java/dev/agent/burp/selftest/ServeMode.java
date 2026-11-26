package dev.agent.burp.selftest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import dev.agent.burp.bridge.BridgeServer;
import dev.agent.burp.core.Args;
import dev.agent.burp.core.RateLimiter;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.ToolRegistry;
import dev.agent.burp.core.TrafficCounters;
import dev.agent.burp.gateway.KeyValueStore;
import dev.agent.burp.gateway.SendSpec;
import dev.agent.burp.standalone.FakeBurpGateway;
import dev.agent.burp.tools.Tools;

/**
 * Serves the bridge on a plain JVM for the Python integration test (tests/test_integration.py): the same
 * {@link FakeBurpGateway} + {@link BridgeServer} wiring the {@link SelfTest} exercises, kept up until the
 * process is killed. The authorization registry starts empty (the client drives it via {@code add_to_scope}),
 * every send is answered by one fixed scripted response and {@code raise_issue} always fails with
 * {@link #SCRIPTED_ERROR}, so the Python side can assert both success envelopes and a tool-level failure
 * envelope through the real wire protocol.
 *
 * <p>Started with {@code SelfTest --serve --port N --token T} (StandaloneDemo hands {@code --serve} here too,
 * so {@code java -jar burp-agent-bridge.jar --serve …} works as well). Stdout stays quiet except for the single
 * {@code BRIDGE SERVE MODE READY} line the Python test waits for; the access log is dropped and the fake
 * gateway's chatter goes to stdout only through tool logs, never before the READY line.
 */
public final class ServeMode {
    /** The marker the scripted responder writes into every response body; the Python test asserts on it. */
    public static final String MARKER = "AOBH-SCRIPTED-MARKER";
    /** The stable error code the scripted tool fails with; the Python test asserts the failure envelope. */
    public static final String SCRIPTED_ERROR = "scripted_tool_error";
    private static final String SCRIPTED_TOOL = "raise_issue";

    private ServeMode() {
    }

    /** Argument entry point: {@code [--port N] --token T}; the token is mandatory, exactly as for the real bridge. */
    public static void main(String[] args) {
        int port = 8787;
        String token = null;
        for (int k = 0; k < args.length; k++) {
            if ("--port".equals(args[k]) && k + 1 < args.length) {
                port = Integer.parseInt(args[++k]);
            } else if ("--token".equals(args[k]) && k + 1 < args.length) {
                token = args[++k];
            }
        }
        if (token == null || token.isBlank()) {
            System.out.println("BRIDGE SERVE MODE FAILED --token is required (at least 16 chars)");
            System.out.flush();
            System.exit(2);
        }
        System.exit(run(port, token.trim()));
    }

    /**
     * Builds the bridge exactly as the self-test does and serves until the process is killed.
     *
     * @return 2 when the port cannot be opened; otherwise it never returns (the main thread joins itself)
     */
    public static int run(int port, String token) {
        FakeBurpGateway gw = new FakeBurpGateway();
        gw.responder = ServeMode::scriptedResponse;
        ToolRegistry registry = ToolRegistry.create(gw, new TrafficCounters(), new RateLimiter(1000.0),
                new KeyValueStore.Memory(), withScriptedFailure(Tools.all()));
        BridgeServer server;
        try {
            server = BridgeServer.start(registry, "127.0.0.1", port, token, line -> { });
        } catch (IOException e) {
            System.out.println("BRIDGE SERVE MODE FAILED port=" + port + " " + e);
            System.out.flush();
            return 2;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "serve-mode-shutdown"));
        System.out.println("BRIDGE SERVE MODE READY port=" + server.port());
        System.out.flush();
        try {
            Thread.currentThread().join();               // serve until the process is killed
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        server.stop();
        return 0;
    }

    /** The fixed answer to every send: a 200 text/html page carrying the marker — nothing leaves the process. */
    static String scriptedResponse(SendSpec spec, String url) {
        String body = "<html><head><title>" + MARKER + "</title></head><body><p>" + MARKER
                + " fake-gateway scripted 200</p></body></html>";
        return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                + body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n" + body;
    }

    /** The tool list with {@code raise_issue} replaced by a wrapper that fails with the scripted code. */
    private static List<Tool> withScriptedFailure(List<Tool> tools) {
        List<Tool> out = new ArrayList<>();
        for (Tool tool : tools) {
            if (SCRIPTED_TOOL.equals(tool.name())) {
                out.add(new Tool() {
                    @Override
                    public String name() {
                        return SCRIPTED_TOOL;
                    }

                    @Override
                    public Map<String, Object> handle(ToolContext ctx, Args args) {
                        throw new ToolException(SCRIPTED_ERROR,
                                "Serve-mode script: raise_issue always fails with this code so the client can "
                                        + "assert a tool-level failure envelope.");
                    }
                });
            } else {
                out.add(tool);
            }
        }
        return out;
    }
}
