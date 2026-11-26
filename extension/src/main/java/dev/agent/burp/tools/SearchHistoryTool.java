package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.HistoryItem;
import dev.agent.burp.json.Json;

/**
 * {@code search_history}: one regex over Proxy history and the agent's own request log, newest first, with context
 * snippets instead of full bodies.
 */
public final class SearchHistoryTool implements Tool {
    private static final int DEFAULT_MAX_SCAN = 20_000;
    private static final int MAX_SEARCH_CHARS = 4_000_000;
    private static final int MAX_MATCHES_COUNTED = 10_000;

    @Override
    public String name() {
        return "search_history";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        String rawPattern = args.str("pattern", null);
        if (rawPattern == null || rawPattern.isEmpty()) {
            throw new ToolException("missing_argument", "Argument 'pattern' is required: the regex to search for.");
        }
        Pattern pattern = ToolSupport.regex("pattern", rawPattern, true);
        String search = args.choice("search", "all", "all", "request", "response", "url");
        boolean inScopeOnly = args.bool("in_scope_only", true);
        List<String> methods = ToolSupport.upperList(args, "method");
        String statusClass = args.choice("status_class", null, "1xx", "2xx", "3xx", "4xx", "5xx");
        int contextChars = args.integer("context_chars", 120, 0, 2000);
        int maxPerItem = args.integer("max_matches_per_item", 3, 1, 50);
        int limit = args.integer("limit", 50, 1, 300);
        int maxScan = args.integer("max_scan", DEFAULT_MAX_SCAN, 1, 1_000_000);

        List<Map<String, Object>> matches = new ArrayList<>();
        int[] scanned = {0};
        int[] skipped = {0};
        boolean[] truncated = {false};
        boolean[] textCut = {false};

        // Newest first: the agent's own traffic first (it is small and most relevant), then the Proxy history.
        for (Exchange ex : ctx.log().recent()) {
            if (matches.size() >= limit || scanned[0] >= maxScan) {
                break;
            }
            scanned[0]++;
            if (inScopeOnly && !ctx.scope().registryCovers(ex.url)) {
                continue;
            }
            searchExchange(ex, "agent", ex.agentId, pattern, search, methods, statusClass, contextChars, maxPerItem, matches, textCut);
        }
        List<HistoryItem> history = ctx.proxyHistory();
        for (int k = history.size() - 1; k >= 0; k--) {
            if (matches.size() >= limit || scanned[0] >= maxScan) {
                break;
            }
            HistoryItem h = history.get(k);
            scanned[0]++;
            if (inScopeOnly && !h.inScope) {
                continue;
            }
            if (methods != null && (h.method == null || !methods.contains(h.method.toUpperCase(Locale.ROOT)))) {
                continue;
            }
            if (!ToolSupport.inStatusClass(h.status, statusClass)) {
                continue;
            }
            if ("url".equals(search)) {
                searchExchange(urlOnly(h), "proxy", h.id, pattern, search, null, null, contextChars, maxPerItem, matches, textCut);
                continue;
            }
            Exchange ex;
            try {
                ex = ctx.loadProxyItem(h.id);
            } catch (ToolException e) {
                skipped[0]++;
                continue;
            }
            searchExchange(ex, "proxy", h.id, pattern, search, null, null, contextChars, maxPerItem, matches, textCut);
        }
        truncated[0] = scanned[0] >= maxScan || matches.size() >= limit;

        return Json.obj(
                "matches", matches,
                "count", matches.size(),
                "scanned", scanned[0],
                "skipped_unavailable", skipped[0],
                "truncated", truncated[0],
                "limit", limit,
                "search", search,
                "in_scope_only", inScopeOnly,
                "bodies_cut", textCut[0],
                "truncation_hint", truncated[0]
                        ? "The scan stopped at max_scan=" + maxScan + " items or at limit=" + limit
                        + " matching items; older traffic was not searched. Narrow with method/status_class or in_scope_only=false."
                        : null);
    }

    /** A stand-in exchange for URL-only searches, so no history item has to be loaded. */
    private static Exchange urlOnly(HistoryItem h) {
        Exchange ex = new Exchange();
        ex.proxyId = h.id;
        ex.url = h.url;
        ex.method = h.method;
        return ex;
    }

    private static void searchExchange(Exchange ex, String sourceType, Object sourceId, Pattern pattern, String search,
                                        List<String> methods, String statusClass, int contextChars, int maxPerItem,
                                        List<Map<String, Object>> out, boolean[] textCut) {
        if (methods != null && (ex.method == null || !methods.contains(ex.method.toUpperCase(Locale.ROOT)))) {
            return;
        }
        if (statusClass != null && !ToolSupport.inStatusClass(ex.status, statusClass)) {
            return;
        }
        List<Map<String, Object>> parts = new ArrayList<>();
        int total = 0;
        if (!"request".equals(search) && !"response".equals(search)) {
            total += find(ex.url, "url", pattern, contextChars, maxPerItem, parts, textCut);
        }
        if (!"url".equals(search) && !"response".equals(search)) {
            total += find(ex.requestRaw, "request", pattern, contextChars, maxPerItem, parts, textCut);
        }
        if (!"url".equals(search) && !"request".equals(search)) {
            total += find(ex.responseBody, "response", pattern, contextChars, maxPerItem, parts, textCut);
        }
        if (parts.isEmpty()) {
            return;
        }
        out.add(Json.obj(
                "source_type", sourceType,
                "source_id", sourceId,
                "url", ex.url,
                "method", ex.method,
                "status_code", ex.status == 0 ? null : ex.status,
                "match_count", total,
                "matches", parts));
    }

    /** Adds up to {@code maxPerItem} snippets of {@code text} to {@code out}; returns the total number of matches. */
    private static int find(String text, String where, Pattern pattern, int contextChars, int maxPerItem,
                            List<Map<String, Object>> out, boolean[] textCut) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        if (text.length() > MAX_SEARCH_CHARS) {
            text = text.substring(0, MAX_SEARCH_CHARS);
            textCut[0] = true;
        }
        Matcher m = pattern.matcher(text);
        int total = 0;
        while (m.find()) {
            total++;
            if (total > MAX_MATCHES_COUNTED) {
                break;
            }
            if (total <= maxPerItem) {
                int from = Math.max(0, m.start() - contextChars);
                int to = Math.min(text.length(), m.end() + contextChars);
                StringBuilder snippet = new StringBuilder();
                if (from > 0) {
                    snippet.append("…");
                }
                snippet.append(text, from, to);
                if (to < text.length()) {
                    snippet.append("…");
                }
                out.add(Json.obj(
                        "where", where,
                        "match", m.group(),
                        "start", m.start(),
                        "snippet", snippet.toString()));
            }
        }
        return total > MAX_MATCHES_COUNTED ? MAX_MATCHES_COUNTED : total;
    }
}
