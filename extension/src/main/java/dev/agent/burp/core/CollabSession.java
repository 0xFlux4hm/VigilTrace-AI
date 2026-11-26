package dev.agent.burp.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import dev.agent.burp.gateway.BurpGateway;
import dev.agent.burp.gateway.CollabPayloadInfo;
import dev.agent.burp.gateway.InteractionRecord;
import dev.agent.burp.gateway.KeyValueStore;
import dev.agent.burp.json.Json;

/**
 * Collaborator payloads the agent generated, with the label given at generation time, so a later interaction can be
 * attributed back to a hypothesis ("H4 ssrf preview.url"). The client's secret key is persisted by the gateway.
 */
public final class CollabSession {
    static final String STORE_KEY = "collab.payloads.v1";
    private static final int MAX_TRACKED = 2000;
    private static final long POLL_INTERVAL_MS = 2000L;
    private static final int MAX_WAIT_SECONDS = 120;

    private final BurpGateway gateway;
    private final KeyValueStore store;
    private final List<Map<String, Object>> payloads = new ArrayList<>();

    private CollabSession(BurpGateway gateway, KeyValueStore store) {
        this.gateway = gateway;
        this.store = store;
    }

    public static CollabSession load(BurpGateway gateway, KeyValueStore store) {
        CollabSession session = new CollabSession(gateway, store);
        String json = store.get(STORE_KEY);
        if (json != null && !json.isBlank()) {
            try {
                Object list = Json.parseObject(json).get("payloads");
                if (list instanceof List<?> items) {
                    for (Object o : items) {
                        if (o instanceof Map<?, ?> m) {
                            @SuppressWarnings("unchecked")
                            Map<String, Object> entry = (Map<String, Object>) m;
                            session.payloads.add(new LinkedHashMap<>(entry));
                        }
                    }
                }
            } catch (Json.JsonException | ClassCastException e) {
                session.payloads.clear();
            }
        }
        return session;
    }

    public synchronized int count() {
        return payloads.size();
    }

    public List<Map<String, Object>> generate(int count, String note) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int k = 0; k < count; k++) {
            Map<String, Object> entry;
            try {
                var info = gateway.newCollaboratorPayload();
                entry = Json.obj(
                        "payload_id", info.payloadId,
                        "payload", info.payload,
                        "note", note,
                        "generated_at", Times.now());
            } catch (RuntimeException e) {
                if (out.isEmpty()) {
                    throw new ToolException("collaborator_unavailable",
                            "Burp Collaborator did not generate a payload: " + e.getMessage()
                                    + ". Check that Collaborator is enabled (Project > Collaborator settings) or use a private server.");
                }
                break;
            }
            synchronized (this) {
                payloads.add(entry);
                while (payloads.size() > MAX_TRACKED) {
                    payloads.remove(0);
                }
                persist();
            }
            out.add(entry);
        }
        return out;
    }

    /** Records a payload that was generated elsewhere (the fuzz tool) under a label, so interactions are attributable. */
    public synchronized Map<String, Object> register(CollabPayloadInfo info, String note) {
        Map<String, Object> entry = Json.obj(
                "payload_id", info.payloadId,
                "payload", info.payload,
                "note", note,
                "generated_at", Times.now());
        payloads.add(entry);
        while (payloads.size() > MAX_TRACKED) {
            payloads.remove(0);
        }
        persist();
        return entry;
    }

    /**
     * Polls for interactions. With {@code waitSeconds > 0} it keeps polling (every {@value #POLL_INTERVAL_MS} ms,
     * capped at {@value #MAX_WAIT_SECONDS} s) until at least one interaction shows up or the wait is over.
     */
    public Map<String, Object> poll(String payloadId, String type, String since, int waitSeconds) throws InterruptedException {
        int wait = Math.max(0, Math.min(MAX_WAIT_SECONDS, waitSeconds));
        long deadline = System.currentTimeMillis() + wait * 1000L;
        while (true) {
            List<InteractionRecord> hits = filter(payloadId, type, since);
            if (!hits.isEmpty() || System.currentTimeMillis() >= deadline) {
                List<Map<String, Object>> interactions = new ArrayList<>();
                for (InteractionRecord r : hits) {
                    interactions.add(Render.interaction(r, noteFor(r.payloadId)));
                }
                return Json.obj(
                        "interactions", interactions,
                        "count", interactions.size(),
                        "payload_id", payloadId == null || payloadId.isBlank() ? null : payloadId.trim(),
                        "waited_seconds", wait > 0 && hits.isEmpty() ? wait : 0,
                        "hint", hits.isEmpty()
                                ? "No interaction yet. DNS-only hits prove reachability; HTTP interactions are the strong signal. Poll again after a delay and once more before closing the engagement."
                                : "Poll once more before closing the engagement; later interactions can still arrive.");
            }
            Thread.sleep(POLL_INTERVAL_MS);
        }
    }

    private List<InteractionRecord> filter(String payloadId, String type, String since) {
        String id = payloadId == null || payloadId.isBlank() ? null : payloadId.trim();
        String want = type == null || type.isBlank() ? null : type.trim().toUpperCase(Locale.ROOT);
        java.time.Instant after = Times.parse(since, "since");
        List<InteractionRecord> all;
        try {
            all = gateway.collaboratorInteractions(id);
        } catch (RuntimeException e) {
            throw new ToolException("collaborator_unavailable",
                    "Could not read Collaborator interactions: " + e.getMessage()
                            + ". Check that Burp Collaborator is enabled; the payload registry is kept, so polling works again once it is.");
        }
        List<InteractionRecord> out = new ArrayList<>();
        for (InteractionRecord r : all) {
            if (id != null && !id.equals(r.payloadId)) {
                continue;
            }
            if (want != null && !want.equals(r.type)) {
                continue;
            }
            if (after != null && r.timeEpochMillis > 0 && r.timeEpochMillis < after.toEpochMilli()) {
                continue;
            }
            out.add(r);
        }
        return out;
    }

    public synchronized String noteFor(String payloadId) {
        if (payloadId == null) {
            return null;
        }
        for (int k = payloads.size() - 1; k >= 0; k--) {
            Map<String, Object> p = payloads.get(k);
            if (payloadId.equals(p.get("payload_id"))) {
                return String.valueOf(p.get("note"));
            }
        }
        return null;
    }

    /** Ids of payloads labeled with the given note (used by the fuzz tool to scope a collaborator check). */
    public synchronized List<String> payloadIdsForNote(String note) {
        List<String> ids = new ArrayList<>();
        for (Map<String, Object> p : payloads) {
            if (note != null && note.equals(p.get("note"))) {
                ids.add(String.valueOf(p.get("payload_id")));
            }
        }
        return ids;
    }

    private void persist() {
        store.set(STORE_KEY, Json.write(Json.obj("version", 1, "payloads", payloads)));
    }
}
