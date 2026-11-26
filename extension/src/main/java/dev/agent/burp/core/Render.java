package dev.agent.burp.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.HistoryItem;
import dev.agent.burp.gateway.InteractionRecord;
import dev.agent.burp.gateway.IssueRecord;
import dev.agent.burp.gateway.SiteItem;
import dev.agent.burp.json.Json;

/** Compact JSON views of exchanges and rows — what the language model actually reads. Bodies are capped in bytes. */
public final class Render {
    public static final int DEFAULT_MAX_BYTES = 20_000;
    public static final int MAX_BYTES_CAP = 200_000;
    static final int MAX_HEADER_VALUE_CHARS = 300;
    static final int MAX_HEADERS = 60;

    private Render() {
    }

    // ---------------------------------------------------------------- text helpers

    /** UTF-8 length of a string in bytes. */
    public static long utf8Length(String s) {
        return s == null ? 0L : s.getBytes(StandardCharsets.UTF_8).length;
    }

    /** Cuts a string to at most {@code maxBytes} UTF-8 bytes without splitting a character. */
    public static String truncate(String s, int maxBytes) {
        if (s == null || maxBytes <= 0) {
            return "";
        }
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= maxBytes) {
            return s;
        }
        String cut = new String(bytes, 0, maxBytes, StandardCharsets.UTF_8);
        while (!cut.isEmpty() && cut.charAt(cut.length() - 1) == '\uFFFD') {
            cut = cut.substring(0, cut.length() - 1);
        }
        return cut;
    }

    /** Response headers as an object; a repeated name becomes {@code Set-Cookie (2)}, {@code Set-Cookie (3)}, … */
    public static Map<String, Object> headers(List<String[]> headers) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Integer> seen = new LinkedHashMap<>();
        int n = 0;
        for (String[] h : headers) {
            if (n++ >= MAX_HEADERS) {
                break;
            }
            String name = h[0];
            String value = Params.preview(h[1], MAX_HEADER_VALUE_CHARS);
            Integer count = seen.get(name.toLowerCase());
            if (count == null) {
                seen.put(name.toLowerCase(), 1);
                out.put(name, value);
            } else {
                seen.put(name.toLowerCase(), count + 1);
                out.put(name + " (" + (count + 1) + ")", value);
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- exchanges

    /** The {@code send_http_request} / {@code modify_and_resend_request} result shape. */
    public static Map<String, Object> exchange(Exchange ex, int maxBytes) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("agent_id", ex.agentId);
        m.put("method", ex.method);
        m.put("url", ex.url);
        m.put("host", ex.url == null ? null : hostOrNull(ex.url));
        m.put("path", ex.url == null ? null : pathOrNull(ex.url));
        m.put("status_code", ex.status == 0 ? null : ex.status);
        m.put("reason", ex.reason);
        m.put("latency_ms", ex.latencyMs);
        m.put("request_length", Render.utf8Length(ex.requestRaw));
        m.put("response_headers", headers(ex.responseHeaders));
        long full = ex.responseLength > 0 ? ex.responseLength : utf8Length(ex.responseBody);
        m.put("response_length", full);
        String body = ex.responseBody == null ? null : truncate(ex.responseBody, maxBytes);
        m.put("response_body", body);
        m.put("response_truncated", ex.responseBody != null && (long) maxBytes < Math.max(full, utf8Length(ex.responseBody)));
        m.put("response_mimetype", ex.mimeType);
        String location = ex.header("Location");
        m.put("redirect_location", ex.status >= 300 && ex.status < 400 ? location : null);
        m.put("annotation", ex.note);
        m.put("time", ex.time);
        return m;
    }

    private static String hostOrNull(String url) {
        try {
            return Urls.parse(url).host;
        } catch (ToolException e) {
            return null;
        }
    }

    private static String pathOrNull(String url) {
        try {
            String rest = Urls.parse(url).rest;
            return rest.isEmpty() ? "/" : rest;
        } catch (ToolException e) {
            return null;
        }
    }

    // ---------------------------------------------------------------- rows

    public static Map<String, Object> historyItem(HistoryItem h) {
        return Json.obj(
                "proxy_id", h.id,
                "time", h.time,
                "method", h.method,
                "url", h.url,
                "status_code", h.status == 0 ? null : h.status,
                "response_length", h.responseLength,
                "mimetype", h.mimeType,
                "has_response", h.hasResponse,
                "host", h.host,
                "path", h.path,
                "in_scope", h.inScope);
    }

    public static Map<String, Object> siteItem(SiteItem s) {
        return Json.obj(
                "sitemap_id", "s-" + s.index,
                "method", s.method,
                "url", s.url,
                "status_code", s.status == 0 ? null : s.status,
                "mimetype", s.mimeType,
                "response_length", s.responseLength,
                "has_response", s.hasResponse,
                "has_params", !s.paramNames.isEmpty(),
                "param_names", new ArrayList<>(s.paramNames),
                "in_scope", s.inScope);
    }

    public static Map<String, Object> interaction(InteractionRecord r, String note) {
        return Json.obj(
                "payload_id", r.payloadId,
                "note", note,
                "type", r.type,
                "time", r.time,
                "client_ip", r.clientIp,
                "client_port", r.clientPort,
                "summary", r.summary,
                "details_available", r.detailsAvailable);
    }

    public static Map<String, Object> issue(IssueRecord i, String issueId, int excerptChars) {
        return Json.obj(
                "issue_id", issueId,
                "name", i.name,
                "severity", i.severity,
                "confidence", i.confidence,
                "baseUrl", i.baseUrl,
                "host", i.host,
                "detail_excerpt", Params.preview(i.detail == null ? "" : i.detail, excerptChars),
                "remediation_excerpt", Params.preview(i.remediation == null ? "" : i.remediation, excerptChars),
                "evidence_count", i.evidenceCount,
                "raised_by_agent", i.raisedByAgent);
    }
}
