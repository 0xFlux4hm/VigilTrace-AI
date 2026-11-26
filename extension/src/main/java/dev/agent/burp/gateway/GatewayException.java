package dev.agent.burp.gateway;

/** Raised when a call into Burp (or the fake gateway) fails; mapped to a clean error envelope by the registry. */
public final class GatewayException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public GatewayException(String message) {
        super(message);
    }

    public GatewayException(String message, Throwable cause) {
        super(message, cause);
    }
}
