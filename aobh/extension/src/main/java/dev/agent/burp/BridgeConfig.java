package dev.agent.burp;

import java.util.function.Function;

/**
 * Where the bridge's settings come from, in the order that wins: the value saved from the settings tab, then the
 * environment variable, then the JVM system property, then the default. The token has no default: without one the
 * bridge does not start, which is the only fail-closed choice for a socket that can send traffic through Burp.
 *
 * <p>This class has no dependency on Burp, so the resolution order is unit-testable on a plain JVM; the extension
 * passes Montoya-backed accessors in.
 */
public final class BridgeConfig {
    public static final String PREF_TOKEN = "agent.bridge.token.v1";
    public static final String PREF_BIND = "agent.bridge.bind.v1";
    public static final String PREF_PORT = "agent.bridge.port.v1";
    public static final String PREF_RATE = "agent.bridge.rate.v1";
    public static final String ENV_TOKEN = "BURP_BRIDGE_TOKEN";
    public static final String ENV_BIND = "BURP_BRIDGE_BIND";
    public static final String ENV_PORT = "BURP_BRIDGE_PORT";
    public static final String ENV_RATE = "BURP_BRIDGE_RATE";
    public static final String SYS_TOKEN = "burp.bridge.token";
    public static final String SYS_BIND = "burp.bridge.bind";
    public static final String SYS_PORT = "burp.bridge.port";
    public static final String SYS_RATE = "burp.bridge.rate";
    public static final int MIN_TOKEN_CHARS = 16;
    public static final double DEFAULT_RATE = dev.agent.burp.core.RateLimiter.DEFAULT_PERMITS_PER_SECOND;
    /** Only these characters: safe in an HTTP header, an environment variable and a shell assignment alike. */
    private static final String TOKEN_CHARS = "A-Za-z0-9._~+/=-";

    /** The final token; {@code null} when none is configured anywhere. Never log or render it. */
    public final String token;
    /** Where the token came from ({@code "settings"}, {@code "BURP_BRIDGE_TOKEN"}, {@code "burp.bridge.token"} or {@code null}). */
    public final String tokenSource;
    public final String bindAddress;
    public final int port;
    public final double permitsPerSecond;

    private BridgeConfig(String token, String tokenSource, String bindAddress, int port, double permitsPerSecond) {
        this.token = token;
        this.tokenSource = tokenSource;
        this.bindAddress = bindAddress;
        this.port = port;
        this.permitsPerSecond = permitsPerSecond;
    }

    /** The stored settings as the tab reads and writes them. */
    public interface Preferences {
        String get(String key);

        void set(String key, String value);

        void delete(String key);
    }

    public static BridgeConfig resolve(Preferences prefs, Function<String, String> env, Function<String, String> systemProperty) {
        String token = trimToNull(prefs.get(PREF_TOKEN));
        String tokenSource = token == null ? null : "settings";
        if (token == null) {
            token = trimToNull(env.apply(ENV_TOKEN));
            tokenSource = token == null ? null : ENV_TOKEN;
        }
        if (token == null) {
            token = trimToNull(systemProperty.apply(SYS_TOKEN));
            tokenSource = token == null ? null : SYS_TOKEN;
        }

        Named bind = firstNonBlank(
                named("settings", prefs.get(PREF_BIND)),
                named(ENV_BIND, env.apply(ENV_BIND)),
                named(SYS_BIND, systemProperty.apply(SYS_BIND)));
        Named portValue = firstNonBlank(
                named("settings", prefs.get(PREF_PORT)),
                named(ENV_PORT, env.apply(ENV_PORT)),
                named(SYS_PORT, systemProperty.apply(SYS_PORT)));
        Named rateValue = firstNonBlank(
                named("settings", prefs.get(PREF_RATE)),
                named(ENV_RATE, env.apply(ENV_RATE)),
                named(SYS_RATE, systemProperty.apply(SYS_RATE)));
        int portNumber;
        double permits;
        try {
            portNumber = portValue == null ? dev.agent.burp.bridge.BridgeServer.DEFAULT_PORT
                    : Integer.parseInt(portValue.value.trim());
            permits = rateValue == null ? DEFAULT_RATE : Double.parseDouble(rateValue.value.trim());
        } catch (RuntimeException e) {   // a stored or exported value that is not a number: reported, never fatal
            portNumber = -1;
            permits = Double.NaN;
        }
        return new BridgeConfig(token, tokenSource,
                bind == null ? dev.agent.burp.bridge.BridgeServer.DEFAULT_BIND : bind.value.trim(), portNumber, permits);
    }

    /** Validates the values that a running bridge depends on. Returns the problem, or {@code null} when usable. */
    public String problem() {
        return problem(true);
    }

    /** Same, with {@code requireToken} false for a settings form that may legitimately clear the token. */
    public String problem(boolean requireToken) {
        if (token == null) {
            return requireToken ? "No token is configured: the bridge is not running. Set one in this tab or in the "
                    + ENV_TOKEN + " environment variable." : null;
        }
        if (token.length() < MIN_TOKEN_CHARS || !token.matches("[" + TOKEN_CHARS + "]+")) {
            return "The token must be at least " + MIN_TOKEN_CHARS + " characters of letters, digits or ._~+/=- (got "
                    + token.length() + "). Use 'Generate token'.";
        }
        if (bindAddress == null || bindAddress.isBlank()) {
            return "Bind address is empty. Use 127.0.0.1.";
        }
        if (port < 1 || port > 65535) {
            return "Port must be 1..65535, got " + port + ".";
        }
        if (!(permitsPerSecond > 0.0) || permitsPerSecond > 10_000.0 || Double.isInfinite(permitsPerSecond)
                || Double.isNaN(permitsPerSecond)) {
            return "Rate must be greater than 0 and at most 10000 requests per second, got " + permitsPerSecond + ".";
        }
        return null;
    }

    /** A settings description that is safe to print: it never contains the token. */
    public String describe() {
        return "token " + (token == null ? "absent" : "from " + tokenSource + " (" + token.length() + " chars, not shown)")
                + ", bind " + bindAddress + ", port " + port + ", rate " + permitsPerSecond + " req/s";
    }

    /** Parses the four text fields of the settings tab the same way {@link #resolve} reads stored values. */
    public static BridgeConfig fromFields(String token, String bind, String port, String rate) {
        double permits;
        int portNumber;
        try {
            portNumber = Integer.parseInt(port.trim());
            permits = Double.parseDouble(rate.trim());
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Port must be a whole number and rate a number.");
        }
        return new BridgeConfig(trimToNull(token), trimToNull(token) == null ? null : "settings",
                bind == null || bind.isBlank() ? dev.agent.burp.bridge.BridgeServer.DEFAULT_BIND : bind.trim(), portNumber, permits);
    }

    /** A fresh 32-character token from a secure RNG. */
    public static String generateToken() {
        byte[] bytes = new byte[24];
        new java.security.SecureRandom().nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String trimToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }

    private static final class Named {
        final String source;
        final String value;

        Named(String source, String value) {
            this.source = source;
            this.value = value;
        }
    }

    private static Named named(String source, String value) {
        return value == null || value.isBlank() ? null : new Named(source, value);
    }

    private static Named firstNonBlank(Named... candidates) {
        for (Named c : candidates) {
            if (c != null) {
                return c;
            }
        }
        return null;
    }
}
