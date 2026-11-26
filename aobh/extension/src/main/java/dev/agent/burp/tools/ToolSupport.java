package dev.agent.burp.tools;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Times;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.json.Json;

/** Small helpers shared by the tool handlers. */
final class ToolSupport {
    private static final java.util.Set<String> SECRET_HEADERS =
            java.util.Set.of("authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization");

    private ToolSupport() {
    }

    /** Compiles a user regex; a broken pattern is an {@code invalid_argument}, never an internal error. */
    static Pattern regex(String arg, String value, boolean caseInsensitive) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Pattern.compile(value, caseInsensitive ? Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE : 0);
        } catch (PatternSyntaxException e) {
            throw new ToolException("invalid_argument",
                    "Argument '" + arg + "' is not a valid Java regex: " + e.getDescription() + " (near index " + e.getIndex() + "). Got: '" + value + "'");
        }
    }

    /** Upper-cased method list, e.g. {@code ["post","PUT"] → [POST, PUT]}; {@code null} when the filter is absent. */
    static List<String> upperList(Args args, String key) {
        if (!args.has(key) || args.list(key).isEmpty()) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (String m : args.stringList(key)) {
            out.add(m.trim().toUpperCase(Locale.ROOT));
        }
        return out;
    }

    /** {@code true} when {@code status} belongs to the {@code 2xx}-style class, or the filter is absent. */
    static boolean inStatusClass(int status, String statusClass) {
        if (statusClass == null) {
            return true;
        }
        if (status < 100 || status > 599) {
            return false;
        }
        return statusClass.charAt(0) == String.valueOf(status).charAt(0);
    }

    /** Parses an ISO-8601 {@code after}/{@code before} bound, or returns {@code null}. */
    static Instant timeBound(Args args, String key) {
        String v = args.str(key, null);
        if (v == null || v.isBlank()) {
            return null;
        }
        return Times.parse(v.trim(), key);
    }

    /** Best-effort parse of a stored timestamp: {@code null} when absent or unparsable. */
    static Instant instantOf(String iso) {
        if (iso == null || iso.isBlank()) {
            return null;
        }
        try {
            return Times.parse(iso, "time");
        } catch (ToolException e) {
            return null;
        }
    }

    static boolean passesTime(Instant t, Instant after, Instant before) {
        return (after == null || t == null || !t.isBefore(after)) && (before == null || t == null || t.isBefore(before));
    }

    /** A validated {@code max_bytes}-style argument (1 .. {@link Render#MAX_BYTES_CAP}). */
    static int maxBytes(Args args, String key, int def) {
        return args.integer(key, def, 1, Render.MAX_BYTES_CAP);
    }

    /** {@code {"type": ..., "id"/"url": ...}} of the source argument, for echoing it back. */
    static Map<String, Object> sourceRef(Args args) {
        if (!args.has("source")) {
            return null;
        }
        Args src = args.sub("source");
        Map<String, Object> out = Json.obj("type", src.str("type", null));
        for (String key : new String[] {"id", "url", "method"}) {
            if (src.has(key)) {
                out.put(key, src.get(key));
            }
        }
        if (src.has("request")) {
            String raw = src.str("request", "");
            int line = raw.indexOf('\n');
            out.put("request_line", line < 0 ? raw : raw.substring(0, line).trim());
        }
        return out;
    }

    /** Request line plus the header lines — enough to recognise a request in a list. The body is never included. */
    static String requestPreview(Exchange ex, int maxChars) {
        if (ex == null || ex.requestRaw == null) {
            return "";
        }
        String raw = ex.requestRaw;
        int headEnd = raw.indexOf("\r\n\r\n");
        int headEndLf = raw.indexOf("\n\n");
        if (headEnd < 0 || headEndLf >= 0 && headEndLf < headEnd) {
            headEnd = headEndLf;
        }
        String head = headEnd < 0 ? raw : raw.substring(0, headEnd);
        StringBuilder sb = new StringBuilder();
        for (String line : head.split("\r\n|\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            int colon = trimmed.indexOf(':');
            boolean sensitive = colon > 0 && SECRET_HEADERS.contains(trimmed.substring(0, colon).trim().toLowerCase(Locale.ROOT));
            sb.append(sensitive ? trimmed.substring(0, colon + 1) + " <redacted>" : trimmed);
        }
        return dev.agent.burp.core.Params.preview(sb.toString(), maxChars);
    }

    /** First 8 hex characters of SHA-1 — a deterministic id for a string pair. */
    static String shortHash(String a, String b) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-1").digest((a + "\n" + b).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < 4; k++) {
                sb.append(String.format("%02x", d[k] & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 unavailable", e);
        }
    }

    /** The UTF-8 byte length of a body, for Content-Length. */
    static long utf8Length(String s) {
        return s == null ? 0L : s.getBytes(StandardCharsets.UTF_8).length;
    }
}
