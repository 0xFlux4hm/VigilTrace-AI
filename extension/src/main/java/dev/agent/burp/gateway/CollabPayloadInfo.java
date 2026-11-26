package dev.agent.burp.gateway;

/** A freshly generated Collaborator payload. */
public final class CollabPayloadInfo {
    /** Interaction id; pass to {@code poll_collaborator(payload_id=...)}. */
    public String payloadId;
    /** The hostname to plant in the target. */
    public String payload;
}
