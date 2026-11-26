package dev.agent.burp.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A raw HTTP request split into request line, ordered headers and body, editable and serializable back with CRLF.
 * Edits preserve header order, header-name case and the body verbatim, which is what makes differential tests
 * single-variable. Only text bodies are supported (the tool interface is JSON strings anyway).
 */
public final class RawRequest {
    public String method;
    /** Origin-form ({@code /path?query}), absolute-form, or {@code *} for OPTIONS. */
    public String target;
    public String version;
    /** {@code [name, value]} in wire order. */
    public final List<String[]> headers = new ArrayList<>();
    public String body = "";

    public static RawRequest parse(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new ToolException("invalid_argument", "The request is empty.");
        }
        int crlf = raw.indexOf("\r\n\r\n");
        int lf = raw.indexOf("\n\n");
        int boundary;
        int bodyStart;
        if (crlf >= 0 && (lf < 0 || crlf + 1 <= lf)) {
            boundary = crlf;
            bodyStart = crlf + 4;
        } else if (lf >= 0) {
            boundary = lf;
            bodyStart = lf + 2;
        } else {
            boundary = -1;
            bodyStart = raw.length();
        }
        String head = boundary < 0 ? raw : raw.substring(0, boundary);
        String body = boundary < 0 ? "" : raw.substring(bodyStart);

        RawRequest r = new RawRequest();
        String[] lines = head.split("\r\n|\n", -1);
        String[] first = lines[0].trim().split("\\s+");
        if (first.length < 2) {
            throw new ToolException("invalid_argument", "Malformed request line: '" + lines[0] + "'. "
                    + "Expected 'METHOD /path HTTP/1.1' followed by CRLF-separated headers and a blank line.");
        }
        r.method = first[0];
        r.target = first[1];
        r.version = first.length >= 3 ? first[2] : "HTTP/1.1";
        for (int k = 1; k < lines.length; k++) {
            String line = lines[k];
            if (line.isEmpty()) {
                continue;
            }
            if ((line.startsWith(" ") || line.startsWith("\t")) && !r.headers.isEmpty()) {
                String[] prev = r.headers.get(r.headers.size() - 1);
                prev[1] = prev[1] + " " + line.trim();
                continue;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                throw new ToolException("invalid_argument", "Malformed header line (no colon): '" + line + "'.");
            }
            r.headers.add(new String[] {line.substring(0, colon).trim(), line.substring(colon + 1).trim()});
        }
        r.body = body;
        return r;
    }

    public String serialize() {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(target).append(' ').append(version == null ? "HTTP/1.1" : version).append("\r\n");
        for (String[] h : headers) {
            sb.append(h[0]).append(": ").append(h[1]).append("\r\n");
        }
        sb.append("\r\n");
        sb.append(body == null ? "" : body);
        return sb.toString();
    }

    // ---------------------------------------------------------------- headers

    public boolean hasHeader(String name) {
        return header(name) != null;
    }

    /** First value of the header, or {@code null}. */
    public String header(String name) {
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                return h[1];
            }
        }
        return null;
    }

    public List<String> values(String name) {
        List<String> out = new ArrayList<>();
        for (String[] h : headers) {
            if (h[0].equalsIgnoreCase(name)) {
                out.add(h[1]);
            }
        }
        return out;
    }

    /** Updates the first occurrence in place, drops later duplicates, adds at the end when missing. */
    public void setHeader(String name, String value) {
        if (value == null) {
            removeHeader(name);
            return;
        }
        boolean seen = false;
        for (int k = headers.size() - 1; k >= 0; k--) {
            String[] h = headers.get(k);
            if (h[0].equalsIgnoreCase(name)) {
                if (seen) {
                    headers.remove(k);
                } else {
                    h[1] = value;
                    seen = true;
                }
            }
        }
        if (!seen) {
            headers.add(new String[] {name, value});
        }
    }

    public boolean removeHeader(String name) {
        boolean removed = false;
        for (int k = headers.size() - 1; k >= 0; k--) {
            if (headers.get(k)[0].equalsIgnoreCase(name)) {
                headers.remove(k);
                removed = true;
            }
        }
        return removed;
    }

    public String hostHeader() {
        return header("Host");
    }

    public String contentType() {
        String ct = header("Content-Type");
        if (ct == null) {
            return "";
        }
        int semi = ct.indexOf(';');
        return (semi < 0 ? ct : ct.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
    }

    // ---------------------------------------------------------------- target

    /** The path with query as it appears in the request line ({@code /a/b?c=d}); absolute-form targets are reduced to it. */
    public String pathAndQuery() {
        if (target == null || target.startsWith("/") || "*".equals(target)) {
            return target == null ? "/" : target;
        }
        int schemeEnd = target.indexOf("://");
        if (schemeEnd > 0) {
            String rest = target.substring(schemeEnd + 3);
            int slash = rest.indexOf('/');
            int q = rest.indexOf('?');
            if (slash < 0 && q < 0) {
                return "/";
            }
            if (slash >= 0 && (q < 0 || slash < q)) {
                return rest.substring(slash);
            }
            return "/?" + rest.substring(q + 1);
        }
        return target;
    }

    /** Replaces the path/query, keeping the target form the request already used. */
    public void setPathAndQuery(String pathAndQuery) {
        if (target != null && (target.startsWith("/") || "*".equals(target))) {
            target = pathAndQuery;
            return;
        }
        if (target != null) {
            int schemeEnd = target.indexOf("://");
            if (schemeEnd > 0) {
                String rest = target.substring(schemeEnd + 3);
                int cut = rest.length();
                for (int k = 0; k < rest.length(); k++) {
                    char c = rest.charAt(k);
                    if (c == '/' || c == '?') {
                        cut = k;
                        break;
                    }
                }
                target = target.substring(0, schemeEnd + 3) + rest.substring(0, cut) + pathAndQuery;
            }
        }
    }
}
