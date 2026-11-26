package dev.agent.burp;

import java.io.IOException;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.persistence.Preferences;
import dev.agent.burp.bridge.BridgeServer;
import dev.agent.burp.core.RateLimiter;
import dev.agent.burp.core.TrafficCounters;
import dev.agent.burp.core.ToolRegistry;
import dev.agent.burp.gateway.MontoyaGateway;
import dev.agent.burp.tools.Tools;
import dev.agent.burp.ui.SettingsPanel;

/**
 * The Burp extension proper: one class implementing {@link BurpExtension}. It wires the real gateway, the counters,
 * the rate limiter and the tool registry to a {@link BridgeServer}, and registers the settings tab. Without a token
 * nothing is started — the extension loads, shows why in its tab and raises a critical event.
 */
public final class AgentExtension implements BurpExtension {
    private MontoyaApi api;
    private SettingsPanel panel;
    private BridgeServer server;
    private Registration unloadingRegistration;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(ToolRegistry.EXTENSION_NAME);
        panel = new SettingsPanel(new SettingsPanel.Listener() {
            @Override
            public String apply(String token, String bind, String port, String rate) {
                return applySettings(token, bind, port, rate);
            }

            @Override
            public String newToken() {
                return BridgeConfig.generateToken();
            }
        });
        try {
            api.userInterface().registerSuiteTab(ToolRegistry.EXTENSION_NAME, panel.component());
            api.userInterface().applyThemeToComponent(panel.component());
        } catch (RuntimeException e) {
            api.logging().logToError("[agent-bridge] could not register the settings tab", e);
        }
        unloadingRegistration = api.extension().registerUnloadingHandler(this::shutdown);
        start();
    }

    private BridgeConfig.Preferences preferences() {
        Preferences preferences = api.persistence().preferences();
        return new BridgeConfig.Preferences() {
            @Override
            public String get(String key) {
                return preferences.getString(key);
            }

            @Override
            public void set(String key, String value) {
                preferences.setString(key, value);
            }

            @Override
            public void delete(String key) {
                preferences.deleteString(key);
            }
        };
    }

    /** Starts the bridge from the current configuration, or reports exactly why it is not running. */
    private void start() {
        server = null;
        BridgeConfig config = BridgeConfig.resolve(preferences(), System::getenv, System::getProperty);
        panel.load(config);
        String problem = config.problem();
        if (problem != null) {
            api.logging().raiseCriticalEvent(ToolRegistry.EXTENSION_NAME + " is NOT running: " + problem);
            panel.stopped(problem);
            return;
        }
        try {
            MontoyaGateway gateway = new MontoyaGateway(api, new MontoyaGateway.PersistedStore(api.persistence().extensionData()));
            TrafficCounters counters = new TrafficCounters();
            RateLimiter rate = new RateLimiter(config.permitsPerSecond);
            ToolRegistry registry = ToolRegistry.create(gateway, counters, rate,
                    new MontoyaGateway.PersistedStore(api.persistence().extensionData()), Tools.all());
            BridgeServer started = BridgeServer.start(registry, config.bindAddress, config.port, config.token,
                    line -> api.logging().logToOutput("[agent-bridge] " + line));
            server = started;
            api.logging().logToOutput("[agent-bridge] v" + registry.version() + " listening on " + started.uri() + " — "
                    + registry.toolCount() + " tools, instance " + counters.instance() + ", " + config.describe());
            api.logging().raiseInfoEvent(ToolRegistry.EXTENSION_NAME + " is listening on " + started.uri()
                    + " (" + registry.toolCount() + " tools).");
            if (!started.isLoopbackOnly()) {
                api.logging().raiseErrorEvent(ToolRegistry.EXTENSION_NAME + " is reachable from other machines on "
                        + started.uri() + ". Anyone holding the token can send requests through Burp; prefer bind address 127.0.0.1.");
            }
            panel.running(started.uri(), registry.toolCount(), counters.instance(), started.isLoopbackOnly());
        } catch (IOException | RuntimeException e) {
            server = null;
            String message = "The bridge could not start (" + config.describe() + "): " + e.getMessage()
                    + ". Check that the port is free and the bind address is valid, then press Apply.";
            api.logging().raiseErrorEvent(ToolRegistry.EXTENSION_NAME + ": " + message);
            panel.failed(message);
        }
    }

    private String applySettings(String token, String bind, String port, String rate) {
        BridgeConfig config;
        try {
            config = BridgeConfig.fromFields(token, bind, port, rate);
        } catch (IllegalArgumentException e) {
            return e.getMessage();
        }
        String problem = config.problem(config.token != null);
        if (problem != null) {
            return problem;
        }
        BridgeConfig.Preferences prefs = preferences();
        if (config.token == null) {
            prefs.delete(BridgeConfig.PREF_TOKEN);
        } else {
            prefs.set(BridgeConfig.PREF_TOKEN, config.token);
        }
        prefs.set(BridgeConfig.PREF_BIND, config.bindAddress);
        prefs.set(BridgeConfig.PREF_PORT, String.valueOf(config.port));
        prefs.set(BridgeConfig.PREF_RATE, String.valueOf(config.permitsPerSecond));
        shutdown();
        start();
        return server == null ? "The bridge is not running; see the status text and Burp's events." : null;
    }

    private void shutdown() {
        if (server != null) {
            BridgeServer running = server;
            server = null;
            try {
                running.stop();
            } catch (RuntimeException e) {
                api.logging().logToError("[agent-bridge] error while stopping the bridge", e);
            }
        }
    }
}
