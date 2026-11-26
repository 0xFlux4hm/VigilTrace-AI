package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.RawRequest;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.Urls;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.SendSpec;

/** {@code send_http_request}: one fully controlled request, built from parts or from raw bytes. */
public final class SendHttpRequestTool implements Tool {
    private static final Pattern TOKEN = Pattern.compile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$");
    private static final String[] REDIRECT_MODES = {SendSpec.REDIRECT_NEVER, SendSpec.REDIRECT_SAME_HOST,
            SendSpec.REDIRECT_IN_SCOPE, SendSpec.REDIRECT_ALWAYS};

    @Override
    public String name() {
        return "send_http_request";
    }

    /** Reads the shared send arguments (note, url, headers, cookie, body, raw_request, redirect/timeout options). */
    static SendSpec readSpec(Args args) {
        SendSpec spec = new SendSpec();
        spec.note = args.str("note", null);
        String raw = args.str("raw_request", null);
        String url = args.str("url", null);
        spec.url = url == null || url.isBlank() ? null : url.trim();
        if (raw != null && !raw.isBlank()) {
            spec.rawRequest = raw;
            RawRequest parsed = RawRequest.parse(raw);
            if (spec.url == null) {
                if (parsed.hostHeader() == null || parsed.hostHeader().isBlank()) {
                    throw new ToolException("invalid_argument",
                            "raw_request has no Host header, so the destination is unknown. Add one ('Host: api.example.com') "
                                    + "or pass url to set the scheme, host and port.");
                }
            } else {
                Urls.parse(spec.url);
            }
        } else {
            if (spec.url == null) {
                throw new ToolException("missing_argument",
                        "Argument 'url' is required unless raw_request is given (e.g. 'https://api.example.com/v2/orders').");
            }
            Urls.parse(spec.url);
            String method = args.str("method", "GET").trim().toUpperCase(Locale.ROOT);
            if (!TOKEN.matcher(method).matches()) {
                throw new ToolException("invalid_argument",
                        "Argument 'method' must be an HTTP token (GET, POST, PATCH, PROPFIND, …); got '" + method + "'.");
            }
            spec.method = method;
            spec.headers = new ArrayList<>();
            boolean hasCookieHeader = false;
            for (String[] h : args.nameValues("headers")) {
                String headerName = h[0].trim();
                if (!TOKEN.matcher(headerName).matches()) {
                    throw new ToolException("invalid_argument", "Header name '" + headerName + "' is not a valid HTTP token.");
                }
                if (h[1].indexOf('\r') >= 0 || h[1].indexOf('\n') >= 0) {
                    throw new ToolException("invalid_argument",
                            "Header value of '" + headerName + "' contains a line break. For byte-exact control use raw_request.");
                }
                if (headerName.equalsIgnoreCase("cookie")) {
                    hasCookieHeader = true;
                }
                spec.headers.add(new String[] {headerName, h[1]});
            }
            String cookie = args.str("cookie", null);
            if (cookie != null && !cookie.isBlank()) {
                if (cookie.indexOf('\r') >= 0 || cookie.indexOf('\n') >= 0) {
                    throw new ToolException("invalid_argument", "Argument 'cookie' contains a line break.");
                }
                if (!hasCookieHeader) {
                    spec.headers.add(new String[] {"Cookie", cookie.trim()});
                }
            }
            spec.body = args.str("body", null);
        }
        spec.redirectMode = args.choice("follow_redirects", SendSpec.REDIRECT_NEVER, REDIRECT_MODES);
        spec.timeoutMs = args.integer("timeout_seconds", 20, 1, 120) * 1000L;
        spec.http2 = args.bool("http2", false);
        spec.verifyUpstreamTls = args.bool("verify_upstream_tls", true);
        spec.addToSiteMap = args.bool("add_to_sitemap", true);
        return spec;
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        String note = args.required("note");
        int maxBytes = ToolSupport.maxBytes(args, "max_bytes", Render.DEFAULT_MAX_BYTES);
        SendSpec spec = readSpec(args);
        spec.note = note;
        Exchange ex = ctx.sendAndLog(spec, false, name(), note);
        Map<String, Object> out = Render.exchange(ex, maxBytes);
        out.put("note", note);
        out.put("follow_redirects", spec.redirectMode);
        out.put("counted_as", "requests_sent");
        if (ex.status >= 300 && ex.status < 400 && ex.header("Location") != null) {
            out.put("redirect_hint", "Redirects are not followed by default. Inspect redirect_location, check that its host is in scope, "
                    + "then request it explicitly or pass follow_redirects.");
        }
        return out;
    }
}
