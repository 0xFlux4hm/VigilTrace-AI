package dev.agent.burp.gateway;

import java.util.ArrayList;
import java.util.List;

/** What to send. Tools build it; only {@code ToolContext.send} hands it to the gateway, after the scope and rate gates. */
public final class SendSpec {
    public static final String REDIRECT_NEVER = "never";
    public static final String REDIRECT_SAME_HOST = "same_host";
    public static final String REDIRECT_IN_SCOPE = "in_scope";
    public static final String REDIRECT_ALWAYS = "always";

    public String method = "GET";
    /** Target URL. Required unless {@link #rawRequest} is given; when both are given it only supplies scheme/host/port. */
    public String url;
    /** Ordered headers to add: {@code [name, value]}. */
    public List<String[]> headers = new ArrayList<>();
    /** Request body; {@code null} for no body. */
    public String body;
    /** Byte-exact mode: the full raw request text. */
    public String rawRequest;
    /** One of the {@code REDIRECT_*} constants. */
    public String redirectMode = REDIRECT_NEVER;
    public long timeoutMs = 20_000L;
    public boolean http2;
    public boolean verifyUpstreamTls = true;
    /** Annotation note. */
    public String note;
    /** Annotation highlight (Burp {@code HighlightColor} name). */
    public String highlight = "BLUE";
    /** Register the exchange in Burp's site map. */
    public boolean addToSiteMap = true;

    public boolean followsRedirects() {
        return !REDIRECT_NEVER.equals(redirectMode);
    }

    /** {@code true} when the request is given as raw text and no URL supplies the service. */
    public boolean serviceFromHostHeader() {
        return rawRequest != null && url == null;
    }
}
