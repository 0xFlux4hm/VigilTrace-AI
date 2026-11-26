package dev.agent.burp.core;

import java.util.Map;

/** One bridge tool. Implementations never touch Burp directly: everything goes through the {@link ToolContext}. */
public interface Tool {
    /** Manifest name, e.g. {@code send_http_request}. */
    String name();

    /**
     * The {@code data} object of the response envelope. Throw {@link ToolException} for expected failures
     * (bad arguments, out of scope, not found) and {@link GatewayException} when Burp itself fails.
     * {@link InterruptedException} is the only checked exception, so the registry can account for every
     * outcome in {@code /health}.
     */
    Map<String, Object> handle(ToolContext ctx, Args args) throws InterruptedException;
}
