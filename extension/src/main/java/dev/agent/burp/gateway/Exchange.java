package dev.agent.burp.gateway;

import java.util.ArrayList;
import java.util.List;

/**
 * One HTTP request/response exchange as plain Java data — the only form of an exchange the tools ever see.
 * Montoya objects stay inside {@code MontoyaGateway}; anything sent to Repeater/Organizer or attached as
 * evidence is rebuilt from the raw text held here.
 */
public final class Exchange {
    /** {@code "a-17"} once recorded in the agent request log; else {@code null}. */
    public String agentId;
    /** Proxy history id when the exchange was loaded from the proxy; else {@code null}. */
    public Integer proxyId;
    /** Resolved URL of the request ({@code scheme://host[:port]/path?query}). */
    public String url;
    public String method;
    /** Full raw request text (headers + body). */
    public String requestRaw;
    /** Decoded request body; {@code null} when there is no body. */
    public String requestBody;
    /** Full raw response text; {@code null} when no response was received. */
    public String responseRaw;
    /** Decoded (decompressed) response body; {@code null} when no response was received. */
    public String responseBody;
    /** Response headers in wire order: {@code [name, value]}. */
    public List<String[]> responseHeaders = new ArrayList<>();
    /** Status code; {@code 0} when there is no response. */
    public int status;
    public String reason;
    /** Burp {@code MimeType} name, e.g. {@code "JSON"}; may be {@code null}. */
    public String mimeType;
    /** Response body length in bytes. */
    public long responseLength;
    public Long latencyMs;
    /** ISO-8601 timestamp of the exchange. */
    public String time;
    /** Annotation note. */
    public String note;
    /** Annotation highlight color name (Burp {@code HighlightColor}); may be {@code null}. */
    public String highlight;
    /** {@code true} when the stored raw response text was cut to fit the in-memory log bound. */
    public boolean responseTruncated;

    public boolean hasResponse() {
        return responseRaw != null || responseBody != null;
    }

    public String header(String name) {
        for (String[] h : responseHeaders) {
            if (h[0] != null && h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return null;
    }
}
