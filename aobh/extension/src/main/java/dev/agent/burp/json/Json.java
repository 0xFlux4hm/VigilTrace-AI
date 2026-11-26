package dev.agent.burp.json;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, strict JSON reader and writer. No third-party dependency.
 *
 * <p>Parsed values are {@link Map} ({@link LinkedHashMap}, insertion-ordered), {@link List},
 * {@link String}, {@link Long}, {@link Double}, {@link Boolean} and {@code null}.
 */
public final class Json {
    /** Thrown on malformed input. Extends IllegalArgumentException so callers can catch either. */
    public static final class JsonException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        JsonException(String message) {
            super(message);
        }
    }

    private static final int MAX_DEPTH = 64;

    private Json() {
    }

    // ------------------------------------------------------------------ builders

    /** Ordered object from key/value pairs: {@code obj("a", 1, "b", "x")}. */
    public static Map<String, Object> obj(Object... pairs) {
        if (pairs.length % 2 != 0) {
            throw new IllegalArgumentException("obj() needs key/value pairs");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            m.put(String.valueOf(pairs[i]), pairs[i + 1]);
        }
        return m;
    }

    public static List<Object> arr(Object... items) {
        List<Object> l = new ArrayList<>();
        for (Object o : items) {
            l.add(o);
        }
        return l;
    }

    public static List<Object> arr(Collection<?> items) {
        return new ArrayList<>(items);
    }

    // ------------------------------------------------------------------ parse

    /** Parses any JSON value; rejects trailing characters and nesting deeper than 64. */
    public static Object parse(String text) {
        if (text == null) {
            throw new JsonException("empty JSON");
        }
        return new Parser(text).parseTop();
    }

    /** Parses a JSON object. An empty or blank document is treated as {@code {}} (empty tool argument set). */
    public static Map<String, Object> parseObject(String text) {
        if (text == null || text.isBlank()) {
            return new LinkedHashMap<>();
        }
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new JsonException("expected a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) v;
        return m;
    }

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s;
        }

        Object parseTop() {
            skipWs();
            Object v = value(0);
            skipWs();
            if (i != s.length()) {
                throw err("unexpected trailing characters");
            }
            return v;
        }

        private JsonException err(String what) {
            return new JsonException(what + " at offset " + i);
        }

        private void skipWs() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    i++;
                } else {
                    break;
                }
            }
        }

        private char peek() {
            if (i >= s.length()) {
                throw err("unexpected end of input");
            }
            return s.charAt(i);
        }

        private void expect(char c) {
            if (peek() != c) {
                throw err("expected '" + c + "'");
            }
            i++;
        }

        private void expectWord(String word) {
            if (!s.startsWith(word, i)) {
                throw err("invalid literal");
            }
            i += word.length();
        }

        private Object value(int depth) {
            if (depth > MAX_DEPTH) {
                throw err("nesting too deep");
            }
            char c = peek();
            switch (c) {
                case '{':
                    return object(depth);
                case '[':
                    return array(depth);
                case '"':
                    return string();
                case 't':
                    expectWord("true");
                    return Boolean.TRUE;
                case 'f':
                    expectWord("false");
                    return Boolean.FALSE;
                case 'n':
                    expectWord("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw err("unexpected character '" + c + "'");
            }
        }

        private Map<String, Object> object(int depth) {
            expect('{');
            Map<String, Object> m = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') {
                i++;
                return m;
            }
            while (true) {
                skipWs();
                String key = string();
                skipWs();
                expect(':');
                skipWs();
                m.put(key, value(depth + 1));
                skipWs();
                char c = peek();
                if (c == ',') {
                    i++;
                } else if (c == '}') {
                    i++;
                    return m;
                } else {
                    throw err("expected ',' or '}'");
                }
            }
        }

        private List<Object> array(int depth) {
            expect('[');
            List<Object> l = new ArrayList<>();
            skipWs();
            if (peek() == ']') {
                i++;
                return l;
            }
            while (true) {
                skipWs();
                l.add(value(depth + 1));
                skipWs();
                char c = peek();
                if (c == ',') {
                    i++;
                } else if (c == ']') {
                    i++;
                    return l;
                } else {
                    throw err("expected ',' or ']'");
                }
            }
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (i >= s.length()) {
                    throw err("unterminated string");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (i >= s.length()) {
                        throw err("unterminated escape");
                    }
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (i + 4 > s.length()) {
                                throw err("bad unicode escape");
                            }
                            int code = 0;
                            for (int k = 0; k < 4; k++) {
                                int d = Character.digit(s.charAt(i + k), 16);
                                if (d < 0) {
                                    throw err("bad unicode escape");
                                }
                                code = (code << 4) | d;
                            }
                            i += 4;
                            sb.append((char) code);
                            break;
                        default:
                            throw err("invalid escape '\\" + e + "'");
                    }
                } else if (c < 0x20) {
                    throw err("unescaped control character in string");
                } else {
                    sb.append(c);
                }
            }
        }

        private Object number() {
            int start = i;
            if (peek() == '-') {
                i++;
            }
            int digits = scanDigits();
            boolean integral = true;
            if (peek() == '.') {
                integral = false;
                i++;
                scanDigits();
            }
            if (peek() == 'e' || peek() == 'E') {
                integral = false;
                i++;
                if (peek() == '+' || peek() == '-') {
                    i++;
                }
                scanDigits();
            }
            String tok = s.substring(start, i);
            if (digits == 0) {
                throw err("invalid number");
            }
            if (integral) {
                try {
                    return Long.parseLong(tok);
                } catch (NumberFormatException tooBig) {
                    return Double.parseDouble(tok);
                }
            }
            return Double.parseDouble(tok);
        }

        private int scanDigits() {
            int n = 0;
            while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') {
                i++;
                n++;
            }
            return n;
        }
    }

    // ------------------------------------------------------------------ write

    /** Compact serialization. */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, null, 0);
        return sb.toString();
    }

    /** Two-space indented serialization (health/tools endpoints, logs). */
    public static String writePretty(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value, "  ", 0);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object v, String indent, int level) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String || v instanceof CharSequence || v instanceof Character || v instanceof Enum<?>) {
            writeString(sb, v.toString());
        } else if (v instanceof Boolean) {
            sb.append(v);
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                sb.append("null");
            } else if (d == Math.rint(d) && Math.abs(d) < 9.0e15) {
                sb.append((long) d);
            } else {
                sb.append(d);
            }
        } else if (v instanceof Number) {
            sb.append(v);
        } else if (v instanceof Map<?, ?>) {
            writeObject(sb, (Map<?, ?>) v, indent, level);
        } else if (v instanceof Iterable<?>) {
            writeArray(sb, (Iterable<?>) v, indent, level);
        } else if (v instanceof Object[]) {
            writeArray(sb, List.of((Object[]) v), indent, level);
        } else if (v instanceof int[]) {
            writeArray(sb, List.of(box((int[]) v)), indent, level);
        } else if (v instanceof long[]) {
            writeArray(sb, List.of(box((long[]) v)), indent, level);
        } else {
            writeString(sb, v.toString());
        }
    }

    private static Object[] box(int[] a) {
        Object[] out = new Object[a.length];
        for (int k = 0; k < a.length; k++) {
            out[k] = a[k];
        }
        return out;
    }

    private static Object[] box(long[] a) {
        Object[] out = new Object[a.length];
        for (int k = 0; k < a.length; k++) {
            out[k] = a[k];
        }
        return out;
    }

    private static void newline(StringBuilder sb, String indent, int level) {
        if (indent != null) {
            sb.append('\n');
            sb.append(indent.repeat(level));
        }
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> m, String indent, int level) {
        if (m.isEmpty()) {
            sb.append("{}");
            return;
        }
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : m.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            newline(sb, indent, level + 1);
            writeString(sb, String.valueOf(e.getKey()));
            sb.append(':');
            if (indent != null) {
                sb.append(' ');
            }
            writeValue(sb, e.getValue(), indent, level + 1);
        }
        newline(sb, indent, level);
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, Iterable<?> items, String indent, int level) {
        sb.append('[');
        boolean first = true;
        boolean empty = true;
        for (Object o : items) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            empty = false;
            newline(sb, indent, level + 1);
            writeValue(sb, o, indent, level + 1);
        }
        if (!empty) {
            newline(sb, indent, level);
        }
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20 || c == '\u2028' || c == '\u2029') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
