package dev.agent.burp.tools;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.HistoryItem;
import dev.agent.burp.json.Json;

/** {@code get_proxy_history}: metadata listing of the Proxy history with cheap filters first, body loads last. */
public final class GetProxyHistoryTool implements Tool {
    private static final int DEFAULT_MAX_SCAN = 20_000;

    @Override
    public String name() {
        return "get_proxy_history";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        Pattern urlContains = ToolSupport.regex("url_contains", args.str("url_contains", null), true);
        List<String> methods = ToolSupport.upperList(args, "method");
        String statusClass = args.choice("status_class", null, "1xx", "2xx", "3xx", "4xx", "5xx");
        boolean wantStatus = args.has("status_code");
        int statusCode = args.integer("status_code", null, 100, 599);
        Boolean hasResponse = args.has("has_response") ? args.bool("has_response", true) : null;
        Pattern requestContains = ToolSupport.regex("request_contains", args.str("request_contains", null), true);
        Pattern responseContains = ToolSupport.regex("response_contains", args.str("response_contains", null), true);
        String mimetype = args.has("mimetype") ? args.str("mimetype", null).trim().toUpperCase(Locale.ROOT) : null;
        boolean inScopeOnly = args.bool("in_scope_only", false);
        Instant after = ToolSupport.timeBound(args, "after");
        Instant before = ToolSupport.timeBound(args, "before");
        int limit = args.integer("limit", 50, 1, 500);
        int offset = args.integer("offset", 0, 0, null);
        boolean newestFirst = args.bool("newest_first", true);
        int maxScan = args.integer("max_scan", DEFAULT_MAX_SCAN, 1, 1_000_000);
        boolean textFilter = requestContains != null || responseContains != null;

        List<HistoryItem> all = ctx.proxyHistory();
        int n = all.size();
        List<HistoryItem> matched = new ArrayList<>();
        int scanned = 0;
        int loaded = 0;
        int gone = 0;
        boolean truncated = false;
        for (int k = 0; k < n; k++) {
            if (scanned >= maxScan) {
                truncated = true;
                break;
            }
            HistoryItem h = all.get(newestFirst ? n - 1 - k : k);
            scanned++;
            if (urlContains != null && (h.url == null || !urlContains.matcher(h.url).find())) {
                continue;
            }
            if (methods != null && (h.method == null || !methods.contains(h.method.toUpperCase(Locale.ROOT)))) {
                continue;
            }
            if (!ToolSupport.inStatusClass(h.status, statusClass) || wantStatus && h.status != statusCode) {
                continue;
            }
            if (hasResponse != null && h.hasResponse != hasResponse) {
                continue;
            }
            if (mimetype != null && (h.mimeType == null || !mimetype.equals(h.mimeType.toUpperCase(Locale.ROOT)))) {
                continue;
            }
            if (inScopeOnly && !h.inScope) {
                continue;
            }
            if (!ToolSupport.passesTime(ToolSupport.instantOf(h.time), after, before)) {
                continue;
            }
            if (textFilter) {
                if (loaded >= maxScan) {
                    truncated = true;
                    break;
                }
                loaded++;
                Exchange ex;
                try {
                    ex = ctx.loadProxyItem(h.id);
                } catch (ToolException e) {
                    gone++;
                    continue;
                }
                if (requestContains != null && (ex.requestRaw == null || !requestContains.matcher(ex.requestRaw).find())) {
                    continue;
                }
                if (responseContains != null && (ex.responseBody == null || !responseContains.matcher(ex.responseBody).find())) {
                    continue;
                }
            }
            matched.add(h);
        }

        List<Map<String, Object>> items = new ArrayList<>();
        int end = matched.size() <= offset ? 0 : Math.min(matched.size(), offset + limit);
        for (int k = Math.min(offset, matched.size()); k < end; k++) {
            items.add(Render.historyItem(matched.get(k)));
        }
        return Json.obj(
                "items", items,
                "returned", items.size(),
                "matched", matched.size(),
                "total_history", n,
                "scanned", scanned,
                "loaded_for_text_filters", loaded,
                "skipped_unavailable", gone,
                "truncated", truncated,
                "offset", offset,
                "limit", limit,
                "newest_first", newestFirst,
                "truncation_hint", truncated
                        ? "The scan stopped after max_scan=" + maxScan + " items, so older items were not examined. "
                        + "Raise max_scan, or narrow the filters (url_contains, method, status_class, after/before)."
                        : null);
    }
}
