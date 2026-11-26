package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Params;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.json.Json;

/**
 * {@code get_response}: reads a stored exchange. Sending nothing also means counting nothing: the tool only touches
 * the agent log and Burp's history.
 */
public final class GetResponseTool implements Tool {
    private static final int MAX_REGEX_MATCHES = 200;
    private static final int REGEX_CONTEXT_CHARS = 80;
    private static final Pattern BASE64 = Pattern.compile("^[A-Za-z0-9+/]+={0,2}$");

    @Override
    public String name() {
        return "get_response";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        String type = args.sub("source").choice("type", null, "proxy", "agent", "sitemap", "raw");
        if ("raw".equals(type)) {
            throw new ToolException("invalid_argument",
                    "source.type 'raw' has no stored response. Use an agent id (a-17), a proxy id, or {\"type\": \"sitemap\", \"url\": ...}.");
        }
        Exchange ex = ctx.resolveSource(args);
        String part = args.choice("part", "response", "all", "request", "response");
        int maxBytes = ToolSupport.maxBytes(args, "max_bytes", Render.DEFAULT_MAX_BYTES);
        boolean includeHeaders = args.bool("include_headers", false);
        String decode = args.choice("decode", "auto", "auto", "none", "base64");
        String jsonPath = args.str("json_path", null);
        if (jsonPath != null && jsonPath.isBlank()) {
            jsonPath = null;
        }
        Pattern regex = ToolSupport.regex("regex_extract", args.str("regex_extract", null), true);
        boolean extractOnly = jsonPath != null || regex != null;

        String response = select(ex.responseRaw, ex.responseBody, includeHeaders);
        String request = select(ex.requestRaw, ex.requestBody, includeHeaders);
        boolean decoded = false;
        if ("base64".equals(decode) && response != null) {
            String plain = tryBase64(response);
            if (plain != null) {
                response = plain;
                decoded = true;
            }
        }

        Object jsonValue = null;
        if (jsonPath != null) {
            if (!"response".equals(part) && !"all".equals(part)) {
                throw new ToolException("invalid_argument", "json_path applies to the response body; use part 'response' or 'all'.");
            }
            Object root = Params.parseJsonOrNull(response);
            if (root == null) {
                throw new ToolException("invalid_argument",
                        "The response body is not JSON, so json_path cannot be used. Fetch the body (without json_path) and inspect it.");
            }
            Object value = Params.jsonGet(root, jsonPath);
            if (value == null) {
                throw new ToolException("not_found", "JSON path '" + jsonPath + "' does not resolve in the response of "
                        + describe(ex) + ". " + topLevel(root));
            }
            jsonValue = value instanceof String s ? s : Json.write(value);
        }

        List<Map<String, Object>> matches = new ArrayList<>();
        if (regex != null) {
            if (!"request".equals(part)) {
                collect(regex, response, "response", matches);
            }
            if ("all".equals(part) || "request".equals(part)) {
                collect(regex, request, "request", matches);
            }
        }

        Map<String, Object> out = Json.obj(
                "source", ToolSupport.sourceRef(args),
                "agent_id", ex.agentId,
                "url", ex.url,
                "method", ex.method,
                "status_code", ex.status == 0 ? null : ex.status,
                "response_headers", Render.headers(ex.responseHeaders),
                "part", part,
                "include_headers", includeHeaders,
                "decode", decode,
                "decoded", decoded);
        boolean wantRequest = "all".equals(part) || "request".equals(part);
        boolean wantResponse = "all".equals(part) || "response".equals(part);
        if (!extractOnly) {
            out.put("request", wantRequest ? Render.truncate(request, maxBytes) : null);
            out.put("response", wantResponse ? Render.truncate(response, maxBytes) : null);
            out.put("request_truncated", wantRequest && Render.utf8Length(request) > maxBytes);
            out.put("response_truncated", wantResponse && Render.utf8Length(response) > maxBytes);
            out.put("response_length", ex.responseLength > 0 ? ex.responseLength : Render.utf8Length(ex.responseBody));
        }
        out.put("json_path", jsonPath);
        out.put("json_value", jsonValue);
        out.put("match_count", matches.size());
        out.put("matches", matches);
        out.put("annotation", ex.note);
        if (ex.responseTruncated) {
            out.put("storage_note", "The stored response was cut to fit the agent log bound; re-request it if the tail matters.");
        }
        return out;
    }

    private static String select(String raw, String body, boolean includeHeaders) {
        if (includeHeaders) {
            return raw != null ? raw : body;
        }
        return body;
    }

    /** Decodes a whole-body base64 text, or returns {@code null} when the body is not base64 of valid UTF-8 text. */
    static String tryBase64(String text) {
        String compact = text.replaceAll("\\s+", "");
        if (compact.length() < 8 || compact.length() % 4 != 0 || !BASE64.matcher(compact).matches()) {
            return null;
        }
        try {
            byte[] bytes = Base64.getDecoder().decode(compact);
            String plain = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            return plain.indexOf('\uFFFD') >= 0 ? null : plain;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static void collect(Pattern regex, String text, String where, List<Map<String, Object>> out) {
        if (text == null) {
            return;
        }
        Matcher m = regex.matcher(text);
        int shown = 0;
        while (m.find()) {
            if (shown >= MAX_REGEX_MATCHES) {
                Map<String, Object> more = Json.obj("where", where, "match", null,
                        "snippet", "… more matches exist; narrow regex_extract or use max_bytes");
                out.add(more);
                return;
            }
            int from = Math.max(0, m.start() - REGEX_CONTEXT_CHARS);
            int to = Math.min(text.length(), m.end() + REGEX_CONTEXT_CHARS);
            StringBuilder snippet = new StringBuilder();
            if (from > 0) {
                snippet.append("…");
            }
            snippet.append(text, from, to);
            if (to < text.length()) {
                snippet.append("…");
            }
            out.add(Json.obj("where", where, "match", m.group(), "start", m.start(), "snippet", snippet.toString()));
            shown++;
        }
    }

    private static String describe(Exchange ex) {
        if (ex.agentId != null) {
            return ex.agentId;
        }
        return ex.proxyId != null ? "proxy item " + ex.proxyId : "this exchange";
    }

    private static String topLevel(Object root) {
        if (root instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                if (keys.size() >= 30) {
                    keys.add("…");
                    break;
                }
                keys.add(String.valueOf(k));
            }
            return "Top-level keys: " + String.join(", ", keys) + ".";
        }
        if (root instanceof List<?> list) {
            return "The body is a JSON array with " + list.size() + " elements; index it with [0], [1], …";
        }
        return "The body is a single JSON value with no members.";
    }
}
