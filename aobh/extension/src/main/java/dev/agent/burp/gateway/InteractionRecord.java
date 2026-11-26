package dev.agent.burp.gateway;

/** A Collaborator interaction. The gateway formats {@link #summary}; no Montoya types cross the seam. */
public final class InteractionRecord {
    /** Interaction id — equals the payload id it answers. */
    public String payloadId;
    /** {@code DNS | HTTP | SMTP} */
    public String type;
    /** ISO-8601 timestamp. */
    public String time;
    public long timeEpochMillis;
    public String clientIp;
    public int clientPort;
    /** Human-readable: DNS query type + query, HTTP request line + header excerpt, or SMTP conversation excerpt. */
    public String summary;
    public boolean detailsAvailable;
}
