package dev.agent.burp.gateway;

import java.util.ArrayList;
import java.util.List;

/** Site map row: metadata only. */
public final class SiteItem {
    /** Position in the full site map listing at the time of the call — informational, not a stable id. */
    public int index;
    public String method;
    public String url;
    /** Status code; {@code 0} when there is no response. */
    public int status;
    public boolean hasResponse;
    public String mimeType;
    public long responseLength;
    public boolean inScope;
    public List<String> paramNames = new ArrayList<>();
}
