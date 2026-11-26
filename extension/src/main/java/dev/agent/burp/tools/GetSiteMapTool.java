package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.Urls;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.SiteItem;
import dev.agent.burp.json.Json;

/** {@code get_site_map}: endpoint inventory from Burp's site map; body loads happen only for {@code response_contains}. */
public final class GetSiteMapTool implements Tool {
    private static final int DEFAULT_MAX_SCAN = 50_000;

    @Override
    public String name() {
        return "get_site_map";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        String urlPrefix = args.str("url_prefix", null);
        if (urlPrefix != null && !urlPrefix.isBlank()) {
            urlPrefix = urlPrefix.trim();
            Urls.parse(urlPrefix);
        } else {
            urlPrefix = null;
        }
        boolean inScopeOnly = args.bool("in_scope_only", true);
        List<String> methods = ToolSupport.upperList(args, "method");
        String statusClass = args.choice("status_class", null, "1xx", "2xx", "3xx", "4xx", "5xx");
        Boolean hasResponse = args.has("has_response") ? args.bool("has_response", true) : null;
        Pattern responseContains = ToolSupport.regex("response_contains", args.str("response_contains", null), true);
        boolean withParamsOnly = args.bool("with_params_only", false);
        int limit = args.integer("limit", 100, 1, 1000);
        int offset = args.integer("offset", 0, 0, null);
        int maxScan = args.integer("max_scan", DEFAULT_MAX_SCAN, 1, 2_000_000);

        List<SiteItem> all = ctx.siteMap(urlPrefix);
        List<SiteItem> matched = new ArrayList<>();
        int scanned = 0;
        int loaded = 0;
        boolean truncated = false;
        for (SiteItem s : all) {
            if (scanned >= maxScan) {
                truncated = true;
                break;
            }
            scanned++;
            if (inScopeOnly && !s.inScope) {
                continue;
            }
            if (methods != null && (s.method == null || !methods.contains(s.method.toUpperCase(Locale.ROOT)))) {
                continue;
            }
            if (!ToolSupport.inStatusClass(s.status, statusClass)) {
                continue;
            }
            if (hasResponse != null && s.hasResponse != hasResponse) {
                continue;
            }
            if (withParamsOnly && s.paramNames.isEmpty()) {
                continue;
            }
            if (responseContains != null) {
                if (loaded >= maxScan) {
                    truncated = true;
                    break;
                }
                loaded++;
                Exchange ex = ctx.loadSiteMapItem(s.url, s.method);
                if (ex == null || ex.responseBody == null || !responseContains.matcher(ex.responseBody).find()) {
                    continue;
                }
            }
            matched.add(s);
        }

        List<Map<String, Object>> items = new ArrayList<>();
        int end = matched.size() <= offset ? 0 : Math.min(matched.size(), offset + limit);
        for (int k = Math.min(offset, matched.size()); k < end; k++) {
            items.add(Render.siteItem(matched.get(k)));
        }
        return Json.obj(
                "items", items,
                "returned", items.size(),
                "matched", matched.size(),
                "entries_under_prefix", all.size(),
                "scanned", scanned,
                "loaded_for_response_filter", loaded,
                "truncated", truncated,
                "offset", offset,
                "limit", limit,
                "url_prefix", urlPrefix,
                "in_scope_only", inScopeOnly,
                "truncation_hint", truncated
                        ? "The scan stopped after max_scan=" + maxScan + " entries. Narrow url_prefix or raise max_scan."
                        : null);
    }
}
