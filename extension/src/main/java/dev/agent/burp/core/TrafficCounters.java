package dev.agent.burp.core;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Traffic counters for one bridge process — the numbers the Mission Control budget governor reads from
 * {@code GET /health}.
 *
 * <p>Contract:
 * <ul>
 *   <li>{@code requests_sent} counts every request the bridge hands to Burp's HTTP stack, incremented <em>before</em>
 *       the send so a failed or timed-out attempt is still counted (a budget must over-count, never under-count).</li>
 *   <li>Requests refused by the scope gate never reach the send path and are counted in
 *       {@code rejected_out_of_scope} instead.</li>
 *   <li>{@code fuzz_requests} is the subset of {@code requests_sent} issued by {@code run_simple_fuzz}.</li>
 *   <li>Counters are monotonic and live as long as the process; {@code instance} is unique per start, so a consumer
 *       that keys on {@code instance} sees a Burp restart as a new instance starting from zero, never as a reset.</li>
 *   <li>One send with redirects followed can produce several HTTP requests; Burp does not expose the hop count, so
 *       such sends are flagged in {@code redirect_following_requests} rather than guessed.</li>
 * </ul>
 */
public final class TrafficCounters {
    /** Layout version of the counters object; bumped on incompatible changes. */
    public static final int COUNTERS_VERSION = 1;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss").withZone(ZoneOffset.UTC);

    private final String instance;
    private final long startedMillis;
    private final Clock clock;

    private final AtomicLong requestsSent = new AtomicLong();
    private final AtomicLong fuzzRequests = new AtomicLong();
    private final AtomicLong redirectFollowingRequests = new AtomicLong();
    private final AtomicLong sendErrors = new AtomicLong();
    private final AtomicLong toolCalls = new AtomicLong();
    private final AtomicLong toolErrors = new AtomicLong();
    private final AtomicLong rejectedOutOfScope = new AtomicLong();
    private final AtomicLong rejectedOther = new AtomicLong();

    public TrafficCounters() {
        this(newInstanceId(), System.currentTimeMillis(), Clock.systemUTC());
    }

    /** Deterministic constructor for tests. */
    public TrafficCounters(String instance, long startedMillis, Clock clock) {
        this.instance = instance;
        this.startedMillis = startedMillis;
        this.clock = clock;
    }

    /** {@code br-<UTC start stamp>-<8 random hex>}, e.g. {@code br-20261126T083000-a1b2c3d4}. */
    public static String newInstanceId() {
        byte[] rnd = new byte[4];
        RANDOM.nextBytes(rnd);
        StringBuilder hex = new StringBuilder(8);
        for (byte b : rnd) {
            hex.append(String.format("%02x", b & 0xff));
        }
        return "br-" + STAMP.format(Instant.now()) + "-" + hex;
    }

    public String instance() {
        return instance;
    }

    /** ISO-8601 UTC start time. */
    public String startedAt() {
        return Times.iso(Instant.ofEpochMilli(startedMillis));
    }

    public long startedAtEpochMillis() {
        return startedMillis;
    }

    public long uptimeSeconds() {
        return Math.max(0L, (clock.millis() - startedMillis) / 1000L);
    }

    // ---------------------------------------------------------------- recording

    /** Called by {@code ToolContext.send} right before the request is handed to Burp. */
    public void recordSend(boolean fuzz, boolean followsRedirects) {
        requestsSent.incrementAndGet();
        if (fuzz) {
            fuzzRequests.incrementAndGet();
        }
        if (followsRedirects) {
            redirectFollowingRequests.incrementAndGet();
        }
    }

    public void recordSendError() {
        sendErrors.incrementAndGet();
    }

    public void recordToolCall() {
        toolCalls.incrementAndGet();
    }

    public void recordToolError() {
        toolErrors.incrementAndGet();
    }

    public void recordRejectedOutOfScope() {
        rejectedOutOfScope.incrementAndGet();
    }

    public void recordRejectedOther() {
        rejectedOther.incrementAndGet();
    }

    // ---------------------------------------------------------------- readings

    public long requestsSent() {
        return requestsSent.get();
    }

    public long fuzzRequests() {
        return fuzzRequests.get();
    }

    /** The {@code counters} object of {@code /health}: plain integers in a stable order. */
    public Map<String, Object> snapshot() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("requests_sent", requestsSent.get());
        m.put("fuzz_requests", fuzzRequests.get());
        m.put("redirect_following_requests", redirectFollowingRequests.get());
        m.put("send_errors", sendErrors.get());
        m.put("tool_calls", toolCalls.get());
        m.put("tool_errors", toolErrors.get());
        m.put("rejected_out_of_scope", rejectedOutOfScope.get());
        m.put("rejected_other", rejectedOther.get());
        return m;
    }
}
