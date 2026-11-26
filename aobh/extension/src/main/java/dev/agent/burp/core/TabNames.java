package dev.agent.burp.core;

import java.util.HashSet;
import java.util.Set;

/**
 * Names of the Repeater tabs the agent opens: always prefixed so agent tabs are recognisable in the UI, and
 * deduplicated because Burp appends a counter of its own when a name repeats.
 */
public final class TabNames {
    public static final String PREFIX = "AGENT — ";
    private static final int MAX_BASE_CHARS = 60;

    private final Set<String> used = new HashSet<>();

    /** Collapses whitespace, drops control characters and caps the length; {@code untitled} when nothing is left. */
    public static String sanitize(String raw) {
        String s = raw == null ? "" : raw.replaceAll("[\\p{Cntrl}]+", " ").trim().replaceAll("\\s+", " ");
        if (s.startsWith(PREFIX)) {
            s = s.substring(PREFIX.length()).trim();
        }
        if (s.length() > MAX_BASE_CHARS) {
            s = s.substring(0, MAX_BASE_CHARS).trim();
        }
        return s.isEmpty() ? "untitled" : s;
    }

    /** {@code AGENT — <base>}, or {@code AGENT — <base> (2)}, {@code (3)} … when the base was used before. */
    public synchronized String unique(String rawBase) {
        String base = PREFIX + sanitize(rawBase);
        String name = base;
        for (int n = 2; !used.add(name); n++) {
            name = base + " (" + n + ")";
        }
        return name;
    }
}
