package dev.agent.burp.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Typed access to a tool's argument object. Strict about structure, forgiving about scalars: a number or boolean
 * passed where a string is expected is rendered as text, a numeric string is accepted for an integer — every
 * violation still fails with a precise {@code invalid_argument} / {@code missing_argument} error.
 */
public final class Args {
    private final Map<String, Object> raw;

    public Args(Map<String, Object> raw) {
        this.raw = raw == null ? new java.util.LinkedHashMap<>() : raw;
    }

    public Map<String, Object> raw() {
        return raw;
    }

    /** {@code true} when present and not JSON {@code null}. */
    public boolean has(String key) {
        return raw.containsKey(key) && raw.get(key) != null;
    }

    public Object get(String key) {
        return raw.get(key);
    }

    private static ToolException invalid(String key, Object value, String expected) {
        return new ToolException("invalid_argument",
                "Argument '" + key + "' must be " + expected + "; got " + describe(value) + ".");
    }

    private static String describe(Object v) {
        if (v == null) {
            return "null";
        }
        if (v instanceof String || v instanceof Map || v instanceof List) {
            String s = v instanceof String ? "\"" + v + "\"" : String.valueOf(v);
            return (v instanceof String ? "a string " : v instanceof Map ? "an object " : "an array ") + Params.preview(s, 120);
        }
        return "the number/boolean " + v;
    }

    // ---------------------------------------------------------------- scalars

    public String str(String key, String def) {
        Object v = raw.get(key);
        if (v == null) {
            return def;
        }
        if (v instanceof String || v instanceof Number || v instanceof Boolean) {
            return String.valueOf(v);
        }
        throw invalid(key, v, "a string");
    }

    public String required(String key) {
        String v = str(key, null);
        if (v == null || v.isBlank()) {
            throw new ToolException("missing_argument", "Argument '" + key + "' is required and must not be empty.");
        }
        return v;
    }

    /** Lower-cased enum value checked against the allowed set. */
    public String choice(String key, String def, String... allowed) {
        Object v = raw.get(key);
        if (v == null) {
            return def;
        }
        String s = String.valueOf(v).trim().toLowerCase(Locale.ROOT);
        for (String a : allowed) {
            if (a.equals(s)) {
                return s;
            }
        }
        throw new ToolException("invalid_argument",
                "Argument '" + key + "' must be one of " + String.join(", ", allowed) + "; got " + describe(v) + ".");
    }

    public int integer(String key, Integer def, Integer min, Integer max) {
        Object v = raw.get(key);
        if (v == null) {
            return def == null ? 0 : def;
        }
        long n;
        if (v instanceof Number num) {
            double d = num.doubleValue();
            if (d != Math.rint(d)) {
                throw invalid(key, v, "an integer");
            }
            n = num.longValue();
        } else if (v instanceof String s && s.trim().matches("-?\\d{1,18}")) {
            n = Long.parseLong(s.trim());
        } else {
            throw invalid(key, v, "an integer");
        }
        if (min != null && n < min || max != null && n > max) {
            throw new ToolException("invalid_argument",
                    "Argument '" + key + "' must be between " + min + " and " + max + "; got " + n + ".");
        }
        return (int) n;
    }

    public boolean bool(String key, boolean def) {
        Object v = raw.get(key);
        if (v == null) {
            return def;
        }
        if (v instanceof Boolean b) {
            return b;
        }
        if (v instanceof String s) {
            String t = s.trim().toLowerCase(Locale.ROOT);
            if (t.equals("true") || t.equals("false")) {
                return t.equals("true");
            }
        }
        throw invalid(key, v, "true or false");
    }

    // ---------------------------------------------------------------- composites

    /** The raw list at {@code key}, or an empty list. */
    public List<Object> list(String key) {
        Object v = raw.get(key);
        if (v == null) {
            return new ArrayList<>();
        }
        if (v instanceof List<?> l) {
            return new ArrayList<>(l);
        }
        throw invalid(key, v, "an array");
    }

    public List<String> stringList(String key) {
        List<String> out = new ArrayList<>();
        int k = 0;
        for (Object o : list(key)) {
            if (!(o instanceof String) && !(o instanceof Number)) {
                throw new ToolException("invalid_argument", "Item " + k + " of '" + key + "' must be a string; got " + describe(o) + ".");
            }
            out.add(String.valueOf(o));
            k++;
        }
        return out;
    }

    /** Every element as an object; throws when an element is not an object. */
    public List<Map<String, Object>> objectList(String key) {
        List<Map<String, Object>> out = new ArrayList<>();
        int k = 0;
        for (Object o : list(key)) {
            if (!(o instanceof Map<?, ?> m)) {
                throw new ToolException("invalid_argument", "Item " + k + " of '" + key + "' must be an object; got " + describe(o) + ".");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) m;
            out.add(map);
        }
        return out;
    }

    /** {@code [name, value]} pairs from {@code [{"name": ..., "value": ...}]}. */
    public List<String[]> nameValues(String key) {
        List<String[]> out = new ArrayList<>();
        int k = 0;
        for (Map<String, Object> o : objectList(key)) {
            Object name = o.get("name");
            Object value = o.get("value");
            if (name == null || !(name instanceof String) || ((String) name).isBlank()) {
                throw new ToolException("invalid_argument", "Item " + k + " of '" + key + "' needs a non-empty 'name'.");
            }
            out.add(new String[] {(String) name, value == null ? "" : String.valueOf(value)});
            k++;
        }
        return out;
    }

    public Map<String, Object> object(String key) {
        Object v = raw.get(key);
        if (v == null) {
            return new java.util.LinkedHashMap<>();
        }
        if (v instanceof Map<?, ?> m) {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) m;
            return map;
        }
        throw invalid(key, v, "an object");
    }

    public Args sub(String key) {
        return new Args(object(key));
    }
}
