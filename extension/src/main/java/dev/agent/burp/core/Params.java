package dev.agent.burp.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.agent.burp.json.Json;

/**
 * Query-string, form-body, cookie, multipart, JSON and XML helpers: pure string work on raw request text.
 */
public final class Params {
    private static final Pattern BOUNDARY = Pattern.compile("boundary=\"?([^\";]+)\"?", Pattern.CASE_INSENSITIVE);
    private static final Pattern DISPOSITION_NAME = Pattern.compile("name=\"([^\"]*)\"");
    private static final Pattern DISPOSITION_FILENAME = Pattern.compile("filename=\"([^\"]*)\"");
    private static final Pattern XML_LEAF = Pattern.compile("<([\\w.:\\-]+)(?:\\s[^<>]*)?>([^<>]*)</\\1>", Pattern.DOTALL);
    private static final Pattern XML_TAG = Pattern.compile("<[A-Za-z_][\\w.:\\-]*((?:\\s+[\\w.:\\-]+\\s*=\\s*\"[^\"]*\")*)\\s*/?>");
    private static final Pattern XML_ATTR = Pattern.compile("([\\w.:\\-]+)\\s*=\\s*\"([^\"]*)\"");
    private static final Pattern NAME_INDEX = Pattern.compile("^(.*?)((?:\\[\\d+\\])+)$");

    /** Headers reported as pseudo-parameters when {@code include_headers} is set. */
    private static final String[] NOTABLE_HEADERS = {
            "Authorization", "X-Api-Key", "X-Auth-Token", "Referer", "Origin", "Forwarded",
            "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Original-URL", "X-Rewrite-URL"};

    /** One parameter of a request: where it lives, its value and (for nested JSON) the path it was found at. */
    public static final class Param {
        public String name;
        public String value;
        /** query | body | cookie | json | multipart | xml | header */
        public String location;
        /** Dot/bracket path for JSON leaves ({@code data.user.role}); {@code null} elsewhere. */
        public String jsonPath;
        /** {@code filename} of a multipart part; {@code null} for plain fields. */
        public String filename;

        public Param(String name, String value, String location, String jsonPath) {
            this.name = name;
            this.value = value;
            this.location = location;
            this.jsonPath = jsonPath;
        }
    }

    /** Multipart part: field name, optional filename, decoded text body. */
    public static final class Part {
        public String name;
        public String filename;
        public String value;
    }

    private Params() {
    }

    // ---------------------------------------------------------------- encoding

    /** Percent-decoding (UTF-8) with {@code +} read as space. Undecodable sequences are kept verbatim. */
    public static String urlDecode(String s) {
        if (s == null || (s.indexOf('%') < 0 && s.indexOf('+') < 0)) {
            return s;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            if (c == '+') {
                out.write(' ');
            } else if (c == '%' && k + 2 < s.length()) {
                int hi = Character.digit(s.charAt(k + 1), 16);
                int lo = Character.digit(s.charAt(k + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) | lo);
                    k += 2;
                } else {
                    out.write(c);
                }
            } else {
                int cp = s.codePointAt(k);
                byte[] bytes = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
                out.write(bytes, 0, bytes.length);
                k += Character.charCount(cp) - 1;
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    /** Percent-encoding of everything outside the unreserved characters (RFC 3986); space becomes {@code %20}. */
    public static String urlEncode(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (byte b : s.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            boolean unreserved = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~';
            if (unreserved) {
                sb.append((char) c);
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- pair lists (query / form)

    /** Undecoded {@code [name, value]} pairs of {@code a=1&b=2}; a segment without {@code =} has value "". */
    public static List<String[]> rawPairs(String s, char sep) {
        List<String[]> out = new ArrayList<>();
        if (s == null || s.isEmpty()) {
            return out;
        }
        for (String segment : s.split(String.valueOf(sep))) {
            if (segment.isEmpty()) {
                continue;
            }
            int eq = segment.indexOf('=');
            out.add(eq < 0 ? new String[] {segment, ""} : new String[] {segment.substring(0, eq), segment.substring(eq + 1)});
        }
        return out;
    }

    public static String joinPairs(List<String[]> pairs, char sep) {
        StringBuilder sb = new StringBuilder();
        for (String[] p : pairs) {
            if (sb.length() > 0) {
                sb.append(sep);
            }
            sb.append(p[0]).append('=').append(p[1]);
        }
        return sb.toString();
    }

    /**
     * Sets one parameter in a raw pair string: the first occurrence is replaced, later duplicates dropped, and the
     * pair is appended when the name is absent. Returns the new raw string.
     */
    public static String setInPairs(String s, char sep, String name, String value) {
        List<String[]> out = new ArrayList<>();
        boolean seen = false;
        for (String[] p : rawPairs(s, sep)) {
            if (name.equals(urlDecode(p[0]))) {
                if (!seen) {
                    out.add(new String[] {urlEncode(name), urlEncode(value)});
                    seen = true;
                }
            } else {
                out.add(p);
            }
        }
        if (!seen) {
            out.add(new String[] {urlEncode(name), urlEncode(value)});
        }
        return joinPairs(out, sep);
    }

    public static String removeFromPairs(String s, char sep, String name) {
        List<String[]> out = new ArrayList<>();
        for (String[] p : rawPairs(s, sep)) {
            if (!name.equals(urlDecode(p[0]))) {
                out.add(p);
            }
        }
        return joinPairs(out, sep);
    }

    public static boolean pairExists(String s, char sep, String name) {
        for (String[] p : rawPairs(s, sep)) {
            if (name.equals(urlDecode(p[0]))) {
                return true;
            }
        }
        return false;
    }

    // ---------------------------------------------------------------- query part of a target

    public static String queryOf(String pathAndQuery) {
        if (pathAndQuery == null) {
            return "";
        }
        int q = pathAndQuery.indexOf('?');
        return q < 0 ? "" : pathAndQuery.substring(q + 1);
    }

    public static String pathOf(String pathAndQuery) {
        if (pathAndQuery == null) {
            return "/";
        }
        int q = pathAndQuery.indexOf('?');
        return q < 0 ? pathAndQuery : pathAndQuery.substring(0, q);
    }

    public static String withQuery(String path, String query) {
        return query == null || query.isEmpty() ? path : path + "?" + query;
    }

    // ---------------------------------------------------------------- cookies

    /** {@code [name, value]} pairs of a Cookie header value. */
    public static List<String[]> parseCookies(String headerValue) {
        List<String[]> out = new ArrayList<>();
        if (headerValue == null) {
            return out;
        }
        for (String part : headerValue.split(";")) {
            String p = part.trim();
            if (p.isEmpty()) {
                continue;
            }
            int eq = p.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            out.add(new String[] {p.substring(0, eq).trim(), p.substring(eq + 1).trim()});
        }
        return out;
    }

    private static String cookieHeader(List<String[]> cookies) {
        StringBuilder sb = new StringBuilder();
        for (String[] c : cookies) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(c[0]).append('=').append(c[1]);
        }
        return sb.toString();
    }

    /** New Cookie header value with the cookie set (first occurrence replaced, later duplicates dropped, appended when missing). */
    public static String setCookie(String headerValue, String name, String value) {
        List<String[]> out = new ArrayList<>();
        boolean seen = false;
        for (String[] c : parseCookies(headerValue)) {
            if (c[0].equals(name)) {
                if (!seen) {
                    out.add(new String[] {name, value});
                    seen = true;
                }
            } else {
                out.add(c);
            }
        }
        if (!seen) {
            out.add(new String[] {name, value});
        }
        return cookieHeader(out);
    }

    public static String removeCookie(String headerValue, String name) {
        List<String[]> out = new ArrayList<>();
        for (String[] c : parseCookies(headerValue)) {
            if (!c[0].equals(name)) {
                out.add(c);
            }
        }
        return cookieHeader(out);
    }

    // ---------------------------------------------------------------- content types

    public static boolean isFormContentType(String contentType) {
        return "application/x-www-form-urlencoded".equals(contentType);
    }

    public static boolean isJsonContentType(String contentType) {
        return contentType != null && (contentType.equals("application/json") || contentType.endsWith("+json"));
    }

    public static boolean isMultipartContentType(String contentType) {
        return contentType != null && contentType.startsWith("multipart/");
    }

    public static boolean isXmlContentType(String contentType) {
        return contentType != null && (contentType.endsWith("xml") || contentType.startsWith("text/xml"));
    }

    // ---------------------------------------------------------------- multipart

    public static List<Part> parseMultipart(String contentType, String body) {
        List<Part> out = new ArrayList<>();
        if (contentType == null || body == null) {
            return out;
        }
        Matcher m = BOUNDARY.matcher(contentType);
        if (!m.find()) {
            return out;
        }
        String delimiter = "--" + m.group(1).trim();
        String[] chunks = body.split(Pattern.quote(delimiter));
        for (int k = 1; k < chunks.length; k++) {
            String chunk = chunks[k];
            if (chunk.startsWith("--")) {
                break;
            }
            String normalized = chunk.startsWith("\r\n") ? chunk.substring(2) : chunk.startsWith("\n") ? chunk.substring(1) : chunk;
            int end = normalized.indexOf("\r\n\r\n");
            int headLen = 4;
            int endLf = normalized.indexOf("\n\n");
            if (end < 0 || (endLf >= 0 && endLf < end)) {
                end = endLf;
                headLen = 2;
            }
            if (end < 0) {
                continue;
            }
            String head = normalized.substring(0, end);
            String content = normalized.substring(end + headLen);
            if (content.endsWith("\r\n")) {
                content = content.substring(0, content.length() - 2);
            } else if (content.endsWith("\n")) {
                content = content.substring(0, content.length() - 1);
            }
            Part part = new Part();
            Matcher n = DISPOSITION_NAME.matcher(head);
            if (n.find()) {
                part.name = n.group(1);
            }
            Matcher f = DISPOSITION_FILENAME.matcher(head);
            if (f.find()) {
                part.filename = f.group(1);
            }
            part.value = content;
            if (part.name != null) {
                out.add(part);
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- JSON

    /** Parses JSON text; returns {@code null} when it is not JSON. */
    public static Object parseJsonOrNull(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return Json.parse(text);
        } catch (Json.JsonException e) {
            return null;
        }
    }

    /** Path tokens: {@code a.b[0].c} → {@code [a, b, [0], c]}. */
    public static List<String> jsonPathTokens(String path) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int k = 0; k < path.length(); k++) {
            char c = path.charAt(k);
            if (c == '.' || c == '[') {
                if (cur.length() > 0) {
                    out.add(cur.toString());
                    cur.setLength(0);
                }
                if (c == '[') {
                    int close = path.indexOf(']', k);
                    if (close < 0) {
                        throw new ToolException("invalid_argument", "Malformed JSON path (missing ']'): '" + path + "'.");
                    }
                    out.add(path.substring(k, close + 1));
                    k = close;
                }
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) {
            out.add(cur.toString());
        }
        return out;
    }

    /** {@code true} when the string uses dot/bracket path syntax rather than a plain parameter name. */
    public static boolean isJsonPathSyntax(String s) {
        return s.indexOf('.') >= 0 || s.indexOf('[') >= 0;
    }

    /** Value at a dot/bracket path, or {@code null} when the path does not resolve. */
    public static Object jsonGet(Object root, String path) {
        Object cur = root;
        for (String token : jsonPathTokens(path)) {
            if (token.startsWith("[")) {
                int idx;
                try {
                    idx = Integer.parseInt(token.substring(1, token.length() - 1));
                } catch (NumberFormatException e) {
                    return null;
                }
                if (!(cur instanceof List<?> list) || idx < 0 || idx >= list.size()) {
                    return null;
                }
                cur = list.get(idx);
            } else {
                if (!(cur instanceof Map<?, ?> map)) {
                    return null;
                }
                cur = map.get(token);
            }
            if (cur == null) {
                return null;
            }
        }
        return cur;
    }

    /**
     * Sets a string value at a dot/bracket path in a JSON document and returns the re-serialized (compact) text.
     * Missing objects along the path are created; array indexes must already exist.
     */
    @SuppressWarnings("unchecked")
    public static String jsonSet(String jsonText, String path, String value) {
        Object root = parseJsonOrNull(jsonText);
        if (root == null) {
            throw new ToolException("invalid_argument", "The request body is not valid JSON, so the 'json' parameter location cannot be used.");
        }
        List<String> tokens = jsonPathTokens(path);
        if (tokens.isEmpty()) {
            throw new ToolException("invalid_argument", "Empty JSON path.");
        }
        if (!(root instanceof Map || root instanceof List)) {
            throw new ToolException("invalid_argument", "The JSON path '" + path + "' cannot be applied: the body is a single JSON value.");
        }
        Object cur = root;
        for (int k = 0; k < tokens.size() - 1; k++) {
            String token = tokens.get(k);
            Object next = jsonGet(cur, token);
            if (next == null) {
                if (token.startsWith("[")) {
                    throw new ToolException("invalid_argument", "JSON path '" + path + "' points into an array element that does not exist.");
                }
                if (!(cur instanceof Map)) {
                    throw new ToolException("invalid_argument", "JSON path '" + path + "' crosses a non-object value.");
                }
                next = new LinkedHashMap<String, Object>();
                ((Map<String, Object>) cur).put(token, next);
            }
            cur = next;
        }
        String last = tokens.get(tokens.size() - 1);
        if (last.startsWith("[")) {
            int idx;
            try {
                idx = Integer.parseInt(last.substring(1, last.length() - 1));
            } catch (NumberFormatException e) {
                throw new ToolException("invalid_argument", "Malformed JSON path index in '" + path + "'.");
            }
            if (!(cur instanceof List<?> list) || idx < 0 || idx >= list.size()) {
                throw new ToolException("invalid_argument", "JSON path '" + path + "' points into an array element that does not exist.");
            }
            ((List<Object>) list).set(idx, value);
        } else {
            if (!(cur instanceof Map)) {
                throw new ToolException("invalid_argument", "JSON path '" + path + "' crosses a non-object value.");
            }
            ((Map<String, Object>) cur).put(last, value);
        }
        return Json.write(root);
    }

    private static String stringOf(Object v) {
        return v instanceof String s ? s : Json.write(v);
    }

    /**
     * Removes the value at a dot/bracket path and returns the re-serialized (compact) JSON, or {@code null} when the
     * body is not JSON or the path does not resolve.
     */
    @SuppressWarnings("unchecked")
    public static String jsonDelete(String jsonText, String path) {
        Object root = parseJsonOrNull(jsonText);
        if (root == null) {
            return null;
        }
        List<String> tokens = jsonPathTokens(path);
        if (tokens.isEmpty()) {
            return null;
        }
        Object cur = root;
        for (int k = 0; k < tokens.size() - 1; k++) {
            cur = jsonGet(cur, tokens.get(k));
            if (cur == null) {
                return null;
            }
        }
        String last = tokens.get(tokens.size() - 1);
        if (last.startsWith("[")) {
            int idx;
            try {
                idx = Integer.parseInt(last.substring(1, last.length() - 1));
            } catch (NumberFormatException e) {
                return null;
            }
            if (!(cur instanceof List<?> list) || idx < 0 || idx >= list.size()) {
                return null;
            }
            ((List<Object>) list).remove(idx);
        } else if (cur instanceof Map<?, ?> map && map.containsKey(last)) {
            ((Map<String, Object>) map).remove(last);
        } else {
            return null;
        }
        return Json.write(root);
    }

    // ---------------------------------------------------------------- multipart editing

    /** The multipart delimiter of a Content-Type value ({@code --boundary}), or {@code null}. */
    public static String multipartBoundary(String contentType) {
        if (contentType == null) {
            return null;
        }
        Matcher m = BOUNDARY.matcher(contentType);
        return m.find() ? "--" + m.group(1).trim() : null;
    }

    private static String[] multipartChunks(String body, String delimiter) {
        return body.split(Pattern.quote(delimiter), -1);
    }

    private static boolean chunkIsPart(String chunk) {
        return !chunk.startsWith("--");
    }

    private static String partName(String chunk) {
        Matcher n = DISPOSITION_NAME.matcher(partHead(chunk));
        return n.find() ? n.group(1) : null;
    }

    private static String partHead(String chunk) {
        String normalized = chunk.startsWith("\r\n") ? chunk.substring(2) : chunk.startsWith("\n") ? chunk.substring(1) : chunk;
        int end = normalized.indexOf("\r\n\r\n");
        int endLf = normalized.indexOf("\n\n");
        if (end < 0 || endLf >= 0 && endLf < end) {
            end = endLf;
        }
        return end < 0 ? normalized : normalized.substring(0, end);
    }

    /**
     * Rebuilds the multipart body with the value of the first part named {@code name} replaced. Returns {@code null}
     * when there is no such part.
     */
    public static String setMultipartPart(String body, String delimiter, String name, String value) {
        String[] chunks = multipartChunks(body, delimiter);
        for (int k = 1; k < chunks.length; k++) {
            String chunk = chunks[k];
            if (!chunkIsPart(chunk) || !name.equals(partName(chunk))) {
                continue;
            }
            String head = partHead(chunk);
            int headEnd = chunk.indexOf(head) + head.length();
            String tail = chunk.substring(headEnd);
            String lineBreak = tail.startsWith("\r\n\r\n") ? "\r\n\r\n" : "\n\n";
            int contentStart = headEnd + lineBreak.length();
            String content = chunk.substring(contentStart);
            String ending = content.endsWith("\r\n") ? "\r\n" : content.endsWith("\n") ? "\n" : "";
            chunks[k] = chunk.substring(0, contentStart) + value + ending;
            return String.join(delimiter, chunks);
        }
        return null;
    }

    /** Rebuilds the multipart body without the parts named {@code name}; {@code null} when there is no such part. */
    public static String removeMultipartPart(String body, String delimiter, String name) {
        String[] chunks = multipartChunks(body, delimiter);
        List<String> kept = new ArrayList<>();
        boolean removed = false;
        for (int k = 0; k < chunks.length; k++) {
            if (k >= 1 && chunkIsPart(chunks[k]) && name.equals(partName(chunks[k]))) {
                removed = true;
                continue;
            }
            kept.add(chunks[k]);
        }
        return removed ? String.join(delimiter, kept) : null;
    }

    /** Leaf value of a JSON node, or its compact JSON text for containers. */
    public static String leafName(String path) {
        if (path == null) {
            return "$";
        }
        Matcher m = NAME_INDEX.matcher(path);
        if (m.matches()) {
            path = m.group(1);
        }
        int dot = path.lastIndexOf('.');
        return dot < 0 ? path : path.substring(dot + 1);
    }

    /** Appends every leaf under {@code node} to {@code out}, or only the top-level members when {@code deep} is false. */
    public static void flattenJson(Object node, String path, boolean deep, List<Param> out) {
        if (node instanceof Map<?, ?> map) {
            if (map.isEmpty()) {
                out.add(new Param(leafName(path), "{}", "json", path));
                return;
            }
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String key = String.valueOf(e.getKey());
                String child = path == null ? key : path + "." + key;
                addJson(e.getValue(), key, child, deep, out);
            }
        } else if (node instanceof List<?> list) {
            if (list.isEmpty()) {
                out.add(new Param(leafName(path), "[]", "json", path));
                return;
            }
            for (int k = 0; k < list.size(); k++) {
                String child = path == null ? "[" + k + "]" : path + "[" + k + "]";
                addJson(list.get(k), leafName(path) + "[" + k + "]", child, deep, out);
            }
        } else if (path == null) {
            // A bare scalar document (e.g. `42`) has no member name; report it under a root marker.
            out.add(new Param("$", stringOf(node), "json", "$"));
        } else {
            out.add(new Param(leafName(path), stringOf(node), "json", path));
        }
    }

    private static void addJson(Object value, String name, String path, boolean deep, List<Param> out) {
        boolean container = value instanceof Map<?, ?> m && !m.isEmpty() || value instanceof List<?> l && !l.isEmpty();
        if (deep || !container) {
            flattenJson(value, path, deep, out);
        } else {
            out.add(new Param(name, stringOf(value), "json", path));
        }
    }

    // ---------------------------------------------------------------- XML

    /** Leaf element text values and attribute values of an XML/SOAP body. */
    public static List<Param> extractXml(String body) {
        List<Param> out = new ArrayList<>();
        Matcher leaf = XML_LEAF.matcher(body);
        while (leaf.find()) {
            String text = leaf.group(2).trim();
            if (!text.isEmpty() && !text.startsWith("<")) {
                out.add(new Param(leaf.group(1), text, "xml", null));
            }
        }
        Matcher tag = XML_TAG.matcher(body);
        while (tag.find()) {
            Matcher attr = XML_ATTR.matcher(tag.group(1));
            while (attr.find()) {
                out.add(new Param(attr.group(1), attr.group(2), "xml", null));
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- whole-request extraction

    /** Every parameter of a raw request: query, cookies, body (form / JSON / multipart / XML) and notable headers. */
    public static List<Param> extract(String requestRaw, boolean includeCookies, boolean includeHeaders, boolean deepJson) {
        RawRequest r = RawRequest.parse(requestRaw);
        List<Param> out = new ArrayList<>();
        for (String[] p : rawPairs(queryOf(r.pathAndQuery()), '&')) {
            out.add(new Param(urlDecode(p[0]), urlDecode(p[1]), "query", null));
        }
        if (includeCookies) {
            for (String[] c : parseCookies(r.header("Cookie"))) {
                out.add(new Param(c[0], c[1], "cookie", null));
            }
        }
        String ct = r.contentType();
        String body = r.body == null ? "" : r.body;
        if (!body.isBlank()) {
            String trimmed = body.trim();
            if (isFormContentType(ct)) {
                appendForm(body, out);
            } else if (isMultipartContentType(ct)) {
                for (Part part : parseMultipart(r.header("Content-Type"), body)) {
                    Param p = new Param(part.name, part.value, "multipart", null);
                    p.filename = part.filename;
                    out.add(p);
                }
            } else if (isJsonContentType(ct) || ct.isEmpty() && (trimmed.startsWith("{") || trimmed.startsWith("["))) {
                Object json = parseJsonOrNull(body);
                if (json != null) {
                    flattenJson(json, null, deepJson, out);
                }
            } else if (isXmlContentType(ct) || ct.isEmpty() && trimmed.startsWith("<")) {
                out.addAll(extractXml(body));
            } else if (ct.isEmpty() && body.indexOf('=') > 0 && body.indexOf('\n') < 0 && body.indexOf('<') < 0) {
                appendForm(body, out);
            }
        }
        if (includeHeaders) {
            for (String h : NOTABLE_HEADERS) {
                String value = r.header(h);
                if (value != null) {
                    out.add(new Param(h, value, "header", null));
                }
            }
        }
        return out;
    }

    private static void appendForm(String body, List<Param> out) {
        for (String[] p : rawPairs(body, '&')) {
            out.add(new Param(urlDecode(p[0]), urlDecode(p[1]), "body", null));
        }
    }

    /** Truncates to {@code max} characters with an ellipsis marker. */
    public static String preview(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    /** Lower-cased locale-stable string, or {@code null}. */
    public static String lower(String s) {
        return s == null ? null : s.toLowerCase(Locale.ROOT);
    }
}
