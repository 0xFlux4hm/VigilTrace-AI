package dev.agent.burp.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.KeyValueStore;
import dev.agent.burp.json.Json;

/**
 * The agent's own request log: every exchange the bridge sent gets an id ({@code a-1}, {@code a-2}, …) that the
 * other tools accept as a source. Exchanges live in memory for the session; an index (id, method, url, note, time)
 * is persisted so ids survive a reload and never repeat.
 *
 * <p>Stored raw text is bounded so a few huge responses cannot exhaust Burp's heap: the response body is cut at
 * {@value #MAX_RESPONSE_CHARS} characters and the request at {@value #MAX_REQUEST_CHARS}; older entries beyond
 * {@value #MAX_IN_MEMORY} keep only their index entry.
 */
public final class RequestLog {
    static final String STORE_KEY = "requestlog.index.v1";
    static final int MAX_RESPONSE_CHARS = 262_144;
    static final int MAX_REQUEST_CHARS = 65_536;
    static final int MAX_IN_MEMORY = 2000;
    private static final int MAX_INDEX_ENTRIES = 500;

    private final KeyValueStore store;
    private final LinkedHashMap<String, Exchange> exchanges = new LinkedHashMap<>();
    private int next = 1;

    private RequestLog(KeyValueStore store) {
        this.store = store;
    }

    public static RequestLog load(KeyValueStore store) {
        RequestLog log = new RequestLog(store);
        String json = store.get(STORE_KEY);
        if (json != null && !json.isBlank()) {
            try {
                Object n = Json.parseObject(json).get("next");
                if (n instanceof Number num) {
                    log.next = Math.max(1, num.intValue());
                }
            } catch (Json.JsonException | ClassCastException e) {
                log.next = 1;
            }
        }
        return log;
    }

    /** Assigns the next id, attaches the note and stores a bounded copy of the exchange. */
    public synchronized Exchange record(Exchange ex, String note) {
        ex.agentId = "a-" + next++;
        ex.note = note;
        if (ex.time == null) {
            ex.time = Times.now();
        }
        if (ex.responseRaw != null && ex.responseRaw.length() > MAX_RESPONSE_CHARS) {
            ex.responseRaw = ex.responseRaw.substring(0, MAX_RESPONSE_CHARS);
            ex.responseTruncated = true;
        }
        if (ex.responseBody != null && ex.responseBody.length() > MAX_RESPONSE_CHARS) {
            ex.responseBody = ex.responseBody.substring(0, MAX_RESPONSE_CHARS);
            ex.responseTruncated = true;
        }
        if (ex.requestRaw != null && ex.requestRaw.length() > MAX_REQUEST_CHARS) {
            ex.requestRaw = ex.requestRaw.substring(0, MAX_REQUEST_CHARS);
        }
        exchanges.put(ex.agentId, ex);
        while (exchanges.size() > MAX_IN_MEMORY) {
            exchanges.remove(exchanges.keySet().iterator().next());
        }
        persist();
        return ex;
    }

    public synchronized Exchange get(String id) {
        return id == null ? null : exchanges.get(id.trim());
    }

    /** Newest first. */
    public synchronized List<Exchange> recent() {
        List<Exchange> out = new ArrayList<>();
        List<Exchange> all = new ArrayList<>(exchanges.values());
        for (int k = all.size() - 1; k >= 0; k--) {
            out.add(all.get(k));
        }
        return out;
    }

    public synchronized int size() {
        return exchanges.size();
    }

    /** Next id that will be assigned — lets tests and docs state the numbering. */
    public synchronized int nextNumber() {
        return next;
    }

    private void persist() {
        List<Map<String, Object>> entries = new ArrayList<>();
        int from = Math.max(0, exchanges.size() - MAX_INDEX_ENTRIES);
        List<Exchange> all = new ArrayList<>(exchanges.values());
        for (int k = from; k < all.size(); k++) {
            Exchange ex = all.get(k);
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("id", ex.agentId);
            e.put("method", ex.method);
            e.put("url", ex.url);
            e.put("note", ex.note);
            e.put("at", ex.time);
            entries.add(e);
        }
        store.set(STORE_KEY, Json.write(Json.obj("version", 1, "next", next, "entries", entries)));
    }
}
