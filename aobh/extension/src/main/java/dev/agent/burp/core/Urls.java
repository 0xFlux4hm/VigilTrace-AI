package dev.agent.burp.core;

import java.util.Locale;
import java.util.regex.Pattern;

/** URL parsing and literal prefix matching for the scope gate. Pure Java, no Burp types. */
public final class Urls {
    /** Scheme/host/port (effective port filled in) plus the untouched {@code path?query#fragment} remainder. */
    public static final class Parsed {
        public final String scheme;
        public final String host;
        public final int port;
        public final String rest;

        Parsed(String scheme, String host, int port, String rest) {
            this.scheme = scheme;
            this.host = host;
            this.port = port;
            this.rest = rest;
        }

        public String origin() {
            boolean defaultPort = ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
            return scheme + "://" + host + (defaultPort ? "" : ":" + port);
        }
    }

    private static final Pattern DNS_NAME = Pattern.compile("^[a-z0-9._-]+$");
    private static final Pattern IPV6 = Pattern.compile("^\\[[0-9a-f:.]+$");
    private static final String PATTERN_CHARS = "*^|()$\\{}";
    private static final String BOUNDARY_TAIL = "/?&=.;";

    private Urls() {
    }

    public static int defaultPort(String scheme) {
        return "https".equals(scheme) ? 443 : 80;
    }

    /** Parses an http(s) URL. Throws {@code invalid_argument} (via {@link ToolException}) for anything else. */
    public static Parsed parse(String url) {
        if (url == null || url.isBlank()) {
            throw invalid("URL is missing.", url);
        }
        String s = url.trim();
        int schemeEnd = s.indexOf("://");
        if (schemeEnd <= 0) {
            throw invalid("URL must include a scheme (http:// or https://).", url);
        }
        String scheme = s.substring(0, schemeEnd).toLowerCase(Locale.ROOT);
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw invalid("Only http and https URLs are allowed.", url);
        }
        String after = s.substring(schemeEnd + 3);
        int cut = after.length();
        for (int k = 0; k < after.length(); k++) {
            char c = after.charAt(k);
            if (c == '/' || c == '?' || c == '#') {
                cut = k;
                break;
            }
        }
        String authority = after.substring(0, cut);
        String rest = after.substring(cut);
        int at = authority.lastIndexOf('@');
        if (at >= 0) {
            authority = authority.substring(at + 1);
        }
        String host;
        int port = -1;
        if (authority.startsWith("[")) {
            int end = authority.indexOf(']');
            if (end < 0) {
                throw invalid("Malformed IPv6 host.", url);
            }
            host = authority.substring(0, end + 1);
            String tail = authority.substring(end + 1);
            if (tail.startsWith(":")) {
                port = parsePort(tail.substring(1), url);
            } else if (!tail.isEmpty()) {
                throw invalid("Malformed host.", url);
            }
        } else {
            int colon = authority.lastIndexOf(':');
            if (colon >= 0) {
                host = authority.substring(0, colon).toLowerCase(Locale.ROOT);
                port = parsePort(authority.substring(colon + 1), url);
            } else {
                host = authority.toLowerCase(Locale.ROOT);
            }
        }
        if (host.endsWith(".") && !host.startsWith("[")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty()) {
            throw invalid("URL has no host.", url);
        }
        if (!DNS_NAME.matcher(host).matches() && !IPV6.matcher(host).matches()) {
            throw invalid("URL host contains unexpected characters.", url);
        }
        return new Parsed(scheme, host, port < 0 ? defaultPort(scheme) : port, rest);
    }

    private static int parsePort(String digits, String url) {
        if (!digits.matches("\\d{1,5}")) {
            throw invalid("Malformed port.", url);
        }
        int port = Integer.parseInt(digits);
        if (port < 1 || port > 65535) {
            throw invalid("Port out of range.", url);
        }
        return port;
    }

    private static ToolException invalid(String what, String url) {
        return new ToolException("invalid_argument", what + (url == null ? "" : " Got: '" + url + "'"));
    }

    /** {@code true} when the string parses as an http(s) URL. */
    public static boolean isHttpUrl(String url) {
        try {
            parse(url);
            return true;
        } catch (ToolException e) {
            return false;
        }
    }

    public static String hostOf(String url) {
        return parse(url).host;
    }

    /**
     * Validates a scope prefix and returns its normalized form (lower-case scheme and host, default port removed,
     * path/query kept verbatim). Only literal prefixes are accepted: patterns are refused so the registry is always
     * checkable by this class alone.
     */
    public static String normalizePrefix(String prefix) {
        if (prefix == null || prefix.isBlank()) {
            throw new ToolException("invalid_argument", "url_prefix is required.");
        }
        String p = prefix.trim();
        for (int k = 0; k < PATTERN_CHARS.length(); k++) {
            char c = PATTERN_CHARS.charAt(k);
            if (p.indexOf(c) >= 0) {
                throw new ToolException("invalid_argument",
                        "url_prefix must be a literal URL prefix, not a pattern (found '" + c + "'). Got: '" + prefix + "'");
            }
        }
        Parsed u = parse(p);
        if (u.rest.indexOf('#') >= 0) {
            throw new ToolException("invalid_argument", "url_prefix must not contain a '#' fragment. Got: '" + prefix + "'");
        }
        if (u.rest.indexOf('[') >= 0 || u.rest.indexOf(']') >= 0) {
            throw new ToolException("invalid_argument",
                    "url_prefix must not contain '[' or ']' outside an IPv6 host. Got: '" + prefix + "'");
        }
        return u.origin() + u.rest;
    }

    /**
     * A URL in the form where two spellings of the same resource compare equal: lower-case scheme and host, no default
     * port, no fragment and at least a {@code /} for the path. {@code https://Example.com} and
     * {@code http://EXAMPLE.com:80/#x} become {@code https://example.com/} and {@code http://example.com/}.
     */
    public static String normalizeUrl(String url) {
        Parsed u = parse(url);
        int fragment = u.rest.indexOf('#');
        String rest = fragment >= 0 ? u.rest.substring(0, fragment) : u.rest;
        return u.origin() + (rest.isEmpty() ? "/" : rest);
    }

    /**
     * Literal prefix match on a normalized prefix: same scheme, host and effective port, then the remainder must
     * start with the prefix remainder and end at a boundary — {@code https://h/app} covers {@code /app/x} and
     * {@code /app?y} but not {@code /apples}.
     */
    public static boolean covers(String normalizedPrefix, String url) {
        final Parsed p;
        final Parsed u;
        try {
            p = parse(normalizedPrefix);
            u = parse(url);
        } catch (ToolException e) {
            return false;
        }
        if (!p.scheme.equals(u.scheme) || !p.host.equals(u.host) || p.port != u.port) {
            return false;
        }
        if (p.rest.isEmpty()) {
            return true;
        }
        if (!u.rest.startsWith(p.rest)) {
            return false;
        }
        if (u.rest.length() == p.rest.length()) {
            return true;
        }
        char last = p.rest.charAt(p.rest.length() - 1);
        if (BOUNDARY_TAIL.indexOf(last) >= 0) {
            return true;
        }
        char next = u.rest.charAt(p.rest.length());
        return next == '/' || next == '?' || next == '#';
    }
}
