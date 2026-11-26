package dev.agent.burp.gateway;

/** Proxy history row: metadata only, cheap to build for a whole history. Text is loaded on demand with {@code loadProxyItem}. */
public final class HistoryItem {
    public int id;
    /** ISO-8601 timestamp. */
    public String time;
    public long timeEpochMillis;
    public String method;
    public String url;
    public String host;
    public String path;
    /** Status code; {@code 0} when there is no response. */
    public int status;
    public boolean hasResponse;
    public String mimeType;
    public long responseLength;
    public boolean inScope;
}
