package dev.agent.burp.core;

import java.util.function.LongSupplier;

/**
 * Strict pacing gate shared by every send path: one permit per {@code 1 / permitsPerSecond} seconds, no burst
 * (a token bucket of capacity one). The default is 2 req/s.
 *
 * <p>Permits are reserved under a lock and waited for outside it, so concurrent tool calls queue in arrival order
 * without holding the lock while sleeping. Clock and sleeper are injectable so the arithmetic is unit-testable.
 */
public final class RateLimiter {
    /** {@link Thread#sleep} by default. */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    public static final double DEFAULT_PERMITS_PER_SECOND = 2.0;

    private final double permitsPerSecond;
    private final long intervalNanos;
    private final LongSupplier clock;
    private final Sleeper sleeper;
    private long nextFreeNanos;

    public RateLimiter(double permitsPerSecond) {
        this(permitsPerSecond, System::nanoTime, Thread::sleep);
    }

    public RateLimiter(double permitsPerSecond, LongSupplier clock, Sleeper sleeper) {
        if (!(permitsPerSecond > 0.0) || permitsPerSecond > 10_000.0 || Double.isInfinite(permitsPerSecond)) {
            throw new ToolException("invalid_argument",
                    "rate limit must be greater than 0 and at most 10000 requests per second; got " + permitsPerSecond);
        }
        this.permitsPerSecond = permitsPerSecond;
        this.intervalNanos = (long) Math.ceil(1_000_000_000.0 / permitsPerSecond);
        this.clock = clock;
        this.sleeper = sleeper;
    }

    public double permitsPerSecond() {
        return permitsPerSecond;
    }

    /** Blocks until this caller's slot arrives. Restores the interrupt flag and raises {@code interrupted} if woken. */
    public void acquire() {
        long waitNanos;
        synchronized (this) {
            long now = clock.getAsLong();
            long slot = Math.max(nextFreeNanos, now);
            nextFreeNanos = slot + intervalNanos;
            waitNanos = slot - now;
        }
        if (waitNanos > 0L) {
            try {
                sleeper.sleep(Math.max(1L, waitNanos / 1_000_000L));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ToolException("interrupted", "The bridge was stopped (or Burp is shutting down) while waiting for the rate limit.");
            }
        }
    }

    /** Nanoseconds until the next free slot from "now", for tests and diagnostics. */
    public synchronized long nanosUntilNextPermit() {
        return Math.max(0L, nextFreeNanos - clock.getAsLong());
    }
}
