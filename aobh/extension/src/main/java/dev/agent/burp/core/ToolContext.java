package dev.agent.burp.core;

import java.util.List;
import java.util.Map;

import dev.agent.burp.gateway.BurpGateway;
import dev.agent.burp.gateway.CollabPayloadInfo;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.GatewayException;
import dev.agent.burp.gateway.HistoryItem;
import dev.agent.burp.gateway.InteractionRecord;
import dev.agent.burp.gateway.IssueRecord;
import dev.agent.burp.gateway.SendSpec;
import dev.agent.burp.gateway.SiteItem;

/**
 * Everything a tool may do. It is deliberately the only way to reach Burp: tools never hold the
 * {@link BurpGateway}, so a request can only leave the bridge through {@link #send}, which gates it on scope,
 * paces it through the rate limiter and counts it in {@link TrafficCounters} before it is handed over.
 */
public final class ToolContext {
    private final BurpGateway gateway;
    private final TrafficCounters counters;
    private final RateLimiter rate;
    private final ScopeGuard scope;
    private final RequestLog log;
    private final CollabSession collab;
    private final TabNames tabNames = new TabNames();

    public ToolContext(BurpGateway gateway, TrafficCounters counters, RateLimiter rate,
                       ScopeGuard scope, RequestLog log, CollabSession collab) {
        this.gateway = gateway;
        this.counters = counters;
        this.rate = rate;
        this.scope = scope;
        this.log = log;
        this.collab = collab;
    }

    public TrafficCounters counters() {
        return counters;
    }

    public RateLimiter rate() {
        return rate;
    }

    public ScopeGuard scope() {
        return scope;
    }

    public RequestLog log() {
        return log;
    }

    public CollabSession collab() {
        return collab;
    }

    public String mode() {
        return gateway.mode();
    }

    public void log(String message) {
        gateway.log(message);
    }

    // ---------------------------------------------------------------- the counted send path

    /**
     * Resolves the URL the way Burp will (raw requests: from the explicit service URL, else from the Host header)
     * without sending anything. Also refuses a {@code Host} header that names a different host than the service —
     * a Host swap can reach a different virtual host on a shared address, so it must be an explicit scope decision.
     */
    public String previewUrl(SendSpec spec) {
        String url;
        try {
            if (spec.rawRequest != null) {
                Exchange parsed = gateway.parse(spec.rawRequest, spec.url);
                url = parsed.url;
            } else {
                url = spec.url;
                Urls.parse(url);
            }
        } catch (GatewayException e) {
            throw new ToolException("invalid_request", "Burp could not parse the request: " + e.getMessage()
                    + ". A raw request needs a request line ('GET /path HTTP/1.1') and a Host header; pair raw_request with url to set the scheme.");
        }
        String hostHeader = null;
        if (spec.rawRequest != null) {
            hostHeader = RawRequest.parse(spec.rawRequest).hostHeader();
        } else {
            for (String[] h : spec.headers) {
                if (h[0] != null && h[0].equalsIgnoreCase("Host")) {
                    hostHeader = h[1];
                }
            }
        }
        if (hostHeader != null) {
            String serviceHost = Urls.parse(url).host;
            String headerHost;
            try {
                headerHost = Urls.parse(url.substring(0, url.indexOf("://") + 3) + hostHeader.trim()).host;
            } catch (ToolException e) {
                throw new ToolException("invalid_request", "The Host header '" + hostHeader.trim() + "' is not a valid host name.");
            }
            if (!serviceHost.equals(headerHost)) {
                counters.recordRejectedOutOfScope();
                throw new ToolException("host_header_mismatch",
                        "The request's Host header names '" + headerHost + "' but it would be sent to '" + serviceHost
                                + "'. A Host swap can reach a different (possibly unauthorized) virtual host, so it is refused. "
                                + "Test the other host directly once it is in scope, or drop the Host header.");
            }
        }
        return url;
    }

    /** Resolves a raw request the way Burp does (URL from the service URL or the Host header) without sending it. */
    public Exchange parseRaw(String raw) {
        try {
            return gateway.parse(raw, null);
        } catch (GatewayException e) {
            throw new ToolException("invalid_request", "Burp could not parse the request: " + e.getMessage()
                    + ". A raw request needs a request line ('GET /path HTTP/1.1') and a Host header.");
        }
    }

    /** {@code null} when the URL passes the scope gate, otherwise the refusal text (dry runs and reports). */
    public String scopeVerdict(String url) {
        try {
            scope.assertInScope(url, "scope_check");
            return null;
        } catch (ToolException e) {
            return e.getMessage() + " " + e.hint();
        }
    }

    /** A fresh, recognisable Repeater tab name derived from {@code base}. */
    public String repeaterTabName(String base) {
        return tabNames.unique(base);
    }

    /**
     * Sends one request. Order matters and is the safety argument: scope gate → rate limit → count → send.
     * A request refused by the scope gate is never counted in {@code requests_sent}; a send that is attempted is
     * counted even when Burp fails, because packets may already have left.
     *
     * @param fuzz {@code true} for requests issued by {@code run_simple_fuzz} (counted in {@code fuzz_requests} too)
     */
    public Exchange send(SendSpec spec, boolean fuzz, String toolName) {
        String url = previewUrl(spec);
        try {
            scope.assertInScope(url, toolName);
        } catch (ToolException e) {
            counters.recordRejectedOutOfScope();
            throw e;
        }
        rate.acquire();
        counters.recordSend(fuzz, spec.followsRedirects());
        try {
            Exchange ex = gateway.send(spec);
            if (ex != null && ex.url == null) {
                ex.url = url;
            }
            return ex;
        } catch (RuntimeException e) {
            counters.recordSendError();
            if (e instanceof ToolException t) {
                throw t;
            }
            throw new ToolException("send_failed", "Burp could not complete the request to " + url + ": " + e.getMessage()
                    + ". The attempt is still counted against the request budget. Check reachability and TLS, or raise timeout_seconds (max 120).");
        }
    }

    /** Sends and records in the agent log: what every sending tool ends with. */
    public Exchange sendAndLog(SendSpec spec, boolean fuzz, String toolName, String note) {
        return log.record(send(spec, fuzz, toolName), note);
    }

    // ---------------------------------------------------------------- sources

    /** Resolves {@code {"source": {"type": "proxy"|"agent"|"sitemap"|"raw", "id" / "url" / "request": ...}}}. */
    public Exchange resolveSource(Args args) {
        if (!args.has("source")) {
            throw new ToolException("missing_argument",
                    "Argument 'source' is required: {\"type\": \"proxy\", \"id\": 48211} | {\"type\": \"agent\", \"id\": \"a-17\"} "
                            + "| {\"type\": \"sitemap\", \"url\": \"https://...\"} | {\"type\": \"raw\", \"request\": \"GET / HTTP/1.1\\r\\nHost: ...\"}.");
        }
        Args src = args.sub("source");
        String type = src.choice("type", null, "proxy", "agent", "sitemap", "raw");
        if (type == null) {
                throw new ToolException("missing_argument", "source.type must be one of proxy, agent, sitemap, raw.");
        }
        switch (type) {
            case "proxy": {
                if (!src.has("id")) {
                    throw new ToolException("missing_argument", "source.id (the proxy history item id) is required for type proxy.");
                }
                int id = src.integer("id", null, 1, Integer.MAX_VALUE);
                Exchange ex = gateway.loadProxyItem(id);
                if (ex == null) {
                    throw new ToolException("source_not_found", "Proxy history item " + id + " is not in the current history "
                            + "(it was cleared, filtered out, or belongs to another project). Re-read get_proxy_history for a current id.");
                }
                return ex;
            }
            case "agent": {
                String id = src.required("id");
                Exchange ex = log.get(id);
                if (ex == null) {
                    throw new ToolException("source_not_found", "No agent request with id '" + id + "' is in the request log "
                            + (log.size() > 0 ? "(it was evicted from the bounded log or sent in an earlier session)" : "(the log is empty)")
                            + ". Use an id returned by send_http_request / modify_and_resend_request / run_simple_fuzz.");
                }
                return ex;
            }
            case "sitemap": {
                String url = src.required("url");
                String method = src.has("method") ? src.str("method", "GET").trim().toUpperCase(java.util.Locale.ROOT) : "GET";
                Exchange ex = gateway.loadSiteMapItem(url, method);
                if (ex == null) {
                    throw new ToolException("source_not_found", "The site map has no " + method + " entry for '" + url
                            + "'. Use get_site_map to list current entries (sitemap ids are positional and change as the site map grows).");
                }
                return ex;
            }
            default: {
                String raw = src.required("request");
                try {
                    return gateway.parse(raw, null);
                } catch (GatewayException e) {
                    throw new ToolException("invalid_request", "Burp could not parse source.request: " + e.getMessage());
                }
            }
        }
    }

    // ---------------------------------------------------------------- stored traffic

    public List<HistoryItem> proxyHistory() {
        return gateway.proxyHistory();
    }

    public Exchange loadProxyItem(int id) {
        Exchange ex = gateway.loadProxyItem(id);
        if (ex == null) {
            throw new ToolException("source_not_found", "Proxy history item " + id + " is no longer in the history.");
        }
        return ex;
    }

    public List<SiteItem> siteMap(String urlPrefix) {
        return gateway.siteMap(urlPrefix);
    }

    public Exchange loadSiteMapItem(String url, String method) {
        return gateway.loadSiteMapItem(url, method);
    }

    public List<IssueRecord> auditIssues(String urlPrefix) {
        return gateway.auditIssues(urlPrefix);
    }

    // ---------------------------------------------------------------- visibility channels (no target traffic)

    public void sendToRepeater(Exchange request, String tabName) {
        try {
            gateway.sendToRepeater(request, tabName);
        } catch (RuntimeException e) {
            throw new ToolException("repeater_failed", "Could not open the Repeater tab: " + e.getMessage());
        }
    }

    public void sendToOrganizer(Exchange exchange, String note) {
        try {
            gateway.sendToOrganizer(exchange, note);
        } catch (RuntimeException e) {
            throw new ToolException("organizer_failed", "Could not send the exchange to Organizer: " + e.getMessage());
        }
    }

    public void sendToIntruder(Exchange template, String name) {
        try {
            gateway.sendToIntruder(template, name);
        } catch (RuntimeException e) {
            throw new ToolException("intruder_failed", "Could not send the template to Intruder: " + e.getMessage());
        }
    }

    public String raiseIssue(IssueRecord.Input issue) {
        try {
            return gateway.raiseIssue(issue);
        } catch (RuntimeException e) {
            throw new ToolException("issue_failed", "Burp did not accept the issue: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------- collaborator

    public CollabPayloadInfo newCollaboratorPayload() {
        try {
            return gateway.newCollaboratorPayload();
        } catch (RuntimeException e) {
            throw new ToolException("collaborator_unavailable", "Burp Collaborator did not generate a payload: " + e.getMessage()
                    + ". Check that Collaborator is enabled (Project > Collaborator settings).");
        }
    }

    public List<InteractionRecord> collaboratorInteractions(String payloadIdOrNull) {
        return gateway.collaboratorInteractions(payloadIdOrNull);
    }
}
