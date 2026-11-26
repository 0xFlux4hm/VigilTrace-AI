package dev.agent.burp.standalone;

import java.io.IOException;
import java.util.Arrays;

import dev.agent.burp.BridgeConfig;
import dev.agent.burp.bridge.BridgeServer;
import dev.agent.burp.core.RateLimiter;
import dev.agent.burp.core.TrafficCounters;
import dev.agent.burp.core.ToolRegistry;
import dev.agent.burp.gateway.KeyValueStore;
import dev.agent.burp.selftest.SelfTest;
import dev.agent.burp.selftest.ServeMode;
import dev.agent.burp.tools.Tools;

/**
 * Runs the whole bridge on a plain JVM with {@link FakeBurpGateway} in place of Burp: {@code --demo} lets a person
 * point the MCP server or curl at a working bridge without Burp, {@code --self-test} is what
 * {@code extension/build.py --test} runs, and {@code --serve} hands the process to {@link ServeMode} for the
 * Python integration test. Nothing here is loaded when the jar runs inside Burp.
 */
public final class StandaloneDemo {
    /** A running standalone bridge. */
    public static final class Demo {
        public final BridgeServer server;
        public final FakeBurpGateway gateway;
        public final TrafficCounters counters;
        public final ToolRegistry registry;

        Demo(BridgeServer server, FakeBurpGateway gateway, TrafficCounters counters, ToolRegistry registry) {
            this.server = server;
            this.gateway = gateway;
            this.counters = counters;
            this.registry = registry;
        }
    }

    /** Starts a bridge on loopback. {@code port} 0 picks a free port. The scope registry starts empty. */
    public static Demo start(int port, String token, KeyValueStore store, RateLimiter rate) throws IOException {
        FakeBurpGateway gateway = new FakeBurpGateway();
        TrafficCounters counters = new TrafficCounters();
        ToolRegistry registry = ToolRegistry.create(gateway, counters, rate, store, Tools.all());
        BridgeServer server = BridgeServer.start(registry, "127.0.0.1", port, token, gateway::log);
        return new Demo(server, gateway, counters, registry);
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--self-test".equals(args[0])) {
            System.exit(SelfTest.run(args.length > 1 ? args[1] : null));
        }
        if (args.length > 0 && "--serve".equals(args[0])) {
            ServeMode.main(Arrays.copyOfRange(args, 1, args.length));
            return;                                  // ServeMode.main exits the process itself
        }
        int port = 0;
        String token = null;
        for (int k = 0; k < args.length; k++) {
            if ("--port".equals(args[k]) && k + 1 < args.length) {
                port = Integer.parseInt(args[++k]);
            } else if ("--token".equals(args[k]) && k + 1 < args.length) {
                token = args[++k];
            }
        }
        boolean generated = token == null;
        token = generated ? BridgeConfig.generateToken() : token.trim();
        Demo demo = start(port, token, new KeyValueStore.Memory(), new RateLimiter(RateLimiter.DEFAULT_PERMITS_PER_SECOND));
        String uri = demo.server.uri();
        System.out.println("AI Agent Bridge " + demo.registry.version() + " — STANDALONE DEMO (no Burp, nothing leaves this process)");
        System.out.println("  listening : " + uri);
        System.out.println("  tools     : " + demo.registry.toolCount() + "   instance: " + demo.counters.instance());
        System.out.println("  token     : " + token + (generated ? "   (generated for this run)" : ""));
        System.out.println("  MCP server: BURP_BRIDGE_URL=" + uri + " BURP_BRIDGE_TOKEN=" + token);
        System.out.println("  health    : curl -s -H 'Authorization: Bearer <token>' " + uri + "/health");
        System.out.println("  scope     : the authorization registry is empty; add a prefix before any send, e.g.");
        System.out.println("             curl -s -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \\");
        System.out.println("               -d '{\"url_prefix\":\"http://127.0.0.1:8080\",\"added_from\":\"demo\",\"bootstrap_override\":true}' \\");
        System.out.println("               " + uri + "/tools/add_to_scope");
        Thread.currentThread().join();
    }

    private StandaloneDemo() {
    }
}
