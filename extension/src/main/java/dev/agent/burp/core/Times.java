package dev.agent.burp.core;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;

/** ISO-8601 helpers (all output is UTC, millisecond precision). */
public final class Times {
    private static final DateTimeFormatter ISO_MILLIS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);

    private Times() {
    }

    public static String now() {
        return iso(Instant.now());
    }

    public static String iso(Instant instant) {
        return ISO_MILLIS.format(instant);
    }

    public static String iso(ZonedDateTime time) {
        return time == null ? null : ISO_MILLIS.format(time.toInstant());
    }

    public static String isoEpochMillis(long epochMillis) {
        return ISO_MILLIS.format(Instant.ofEpochMilli(epochMillis));
    }

    /**
     * Parses an ISO-8601 timestamp (a missing zone means UTC) or an epoch-seconds / epoch-milliseconds number.
     * Returns {@code null} for blank input; throws {@link ToolException} for anything unparsable.
     */
    public static Instant parse(String value, String what) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String s = value.trim();
        if (s.matches("-?\\d{9,}")) {
            long n = Long.parseLong(s);
            return Instant.ofEpochMilli(n < 100_000_000_000L ? n * 1000L : n);
        }
        try {
            return Instant.parse(s.endsWith("Z") || s.matches(".*[+-]\\d\\d:?\\d\\d$") ? s : s + "Z");
        } catch (DateTimeParseException first) {
            try {
                return ZonedDateTime.parse(s).toInstant();
            } catch (DateTimeParseException second) {
                throw new ToolException("invalid_argument",
                        what + " must be an ISO-8601 timestamp (e.g. 2026-11-26T14:05:00Z) or epoch seconds; got '" + value + "'.");
            }
        }
    }
}
