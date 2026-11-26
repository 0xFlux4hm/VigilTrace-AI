package dev.agent.burp.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.agent.burp.gateway.KeyValueStore;
import dev.agent.burp.json.Json;

/**
 * The authorization registry behind the scope gate. A request may leave the bridge only when two independent
 * conditions both hold: its URL is covered by a prefix in this registry (seeded from scope.md at bootstrap, every
 * later addition carries provenance) <em>and</em> Burp itself considers it in scope. Burp's scope cannot be
 * enumerated through the API, so the registry is what makes "what was authorized, when, by whom" answerable.
 *
 * <p>State is one JSON document in the {@link KeyValueStore}, rewritten atomically on every change. A corrupt or
 * missing document loads as an empty registry — the gate then rejects everything until prefixes are re-added.
 */
public final class ScopeGuard {
    static final String STORE_KEY = "scope.registry.v1";
    private static final int MAX_EVENTS = 200;

    private final KeyValueStore store;
    private final ScopeBackend backend;
    private final List<Map<String, Object>> registry = new ArrayList<>();
    private final List<Map<String, Object>> excluded = new ArrayList<>();
    private final List<Map<String, Object>> events = new ArrayList<>();

    private ScopeGuard(KeyValueStore store, ScopeBackend backend) {
        this.store = store;
        this.backend = backend;
    }

    public static ScopeGuard load(KeyValueStore store, ScopeBackend backend) {
        ScopeGuard guard = new ScopeGuard(store, backend);
        String json = store.get(STORE_KEY);
        if (json != null && !json.isBlank()) {
            try {
                Map<String, Object> doc = Json.parseObject(json);
                loadInto(doc.get("registry"), guard.registry);
                loadInto(doc.get("excluded"), guard.excluded);
                loadInto(doc.get("events"), guard.events);
            } catch (Json.JsonException | ClassCastException e) {
                guard.registry.clear();
                guard.excluded.clear();
                guard.events.clear();
            }
        }
        return guard;
    }

    @SuppressWarnings("unchecked")
    private static void loadInto(Object list, List<Map<String, Object>> target) {
        if (!(list instanceof List<?> items)) {
            return;
        }
        for (Object o : items) {
            if (o instanceof Map<?, ?> m) {
                target.add(new LinkedHashMap<>((Map<String, Object>) m));
            }
        }
    }

    // ---------------------------------------------------------------- mutations

    /**
     * Adds a prefix to Burp's scope and to the registry.
     *
     * @throws ToolException {@code prefix_not_authorized} when the prefix widens the registry and
     *                       {@code bootstrapOverride} is false
     */
    public synchronized String add(String rawPrefix, String addedFrom, boolean bootstrapOverride) {
        String prefix = Urls.normalizePrefix(rawPrefix);
        if (addedFrom == null || addedFrom.isBlank()) {
            throw new ToolException("missing_argument",
                    "added_from is required: name the authorization (e.g. 'scope.md line 12', 'program policy <url>', 'user statement 2026-11-26').");
        }
        boolean narrowing = registry.stream().anyMatch(e -> Urls.covers(String.valueOf(e.get("prefix")), prefix));
        if (!narrowing && !bootstrapOverride) {
            throw new ToolException("prefix_not_authorized",
                    "Prefix '" + prefix + "' widens the authorized set, and the extension only accepts widening at bootstrap. "
                            + "Re-declare it with bootstrap_override=true ONLY during Phase 0 when scope.md authorizes it; otherwise stay inside: "
                            + registryPrefixes());
        }
        backend.include(prefix);
        excluded.removeIf(e -> prefix.equals(e.get("prefix")));
        Map<String, Object> entry = Json.obj(
                "prefix", prefix,
                "added_at", Times.now(),
                "added_by", bootstrapOverride ? "bootstrap_override" : "sub-prefix",
                "added_from", addedFrom.trim());
        registry.removeIf(e -> prefix.equals(e.get("prefix")));
        registry.add(entry);
        addEvent("add", Json.obj("prefix", prefix, "added_from", addedFrom.trim(),
                "bootstrap_override", bootstrapOverride));
        persist();
        return prefix;
    }

    /** Excludes a prefix from Burp's scope; the exclusion is recorded so it stays visible in {@link #status}. */
    public synchronized String remove(String rawPrefix, boolean dropFromRegistry) {
        String prefix = Urls.normalizePrefix(rawPrefix);
        backend.exclude(prefix);
        if (excluded.stream().noneMatch(e -> prefix.equals(e.get("prefix")))) {
            excluded.add(Json.obj("prefix", prefix, "at", Times.now()));
        }
        if (dropFromRegistry) {
            registry.removeIf(e -> Urls.covers(prefix, String.valueOf(e.get("prefix"))));
        }
        addEvent("remove", Json.obj("prefix", prefix, "drop_from_registry", dropFromRegistry));
        persist();
        return prefix;
    }

    // ---------------------------------------------------------------- gate

    /** Throws {@code out_of_scope} unless the URL is authorized by the registry and in Burp's scope. */
    public void assertInScope(String url, String tool) {
        Urls.parse(url);
        String excludedBy = excludedBy(url);
        if (excludedBy != null) {
            throw outOfScope(url, tool, "explicitly excluded from scope (exclusion '" + excludedBy + "')");
        }
        if (!registryCovers(url)) {
            throw outOfScope(url, tool, "not covered by any prefix in the agent authorization registry");
        }
        if (!backend.isInScope(url)) {
            throw outOfScope(url, tool, "not in Burp's scope (Target > Scope)");
        }
    }

    private ToolException outOfScope(String url, String tool, String why) {
        return new ToolException(ToolException.OUT_OF_SCOPE,
                "[" + tool + "] " + url + " is " + why + ". " + registryPrefixes()
                        + " Call get_scope to compare Burp scope with the agent registry; add_to_scope(url_prefix, added_from) "
                        + "registers a prefix your authorization covers. Never widen scope beyond scope.md.");
    }

    public synchronized boolean registryCovers(String url) {
        return registry.stream().anyMatch(e -> Urls.covers(String.valueOf(e.get("prefix")), url));
    }

    /** The excluded prefix covering the URL, or {@code null}. */
    public synchronized String excludedBy(String url) {
        for (Map<String, Object> e : excluded) {
            String prefix = String.valueOf(e.get("prefix"));
            if (Urls.covers(prefix, url)) {
                return prefix;
            }
        }
        return null;
    }

    public synchronized boolean isEmpty() {
        return registry.isEmpty();
    }

    // ---------------------------------------------------------------- reporting

    /** Registry + exclusions + per-URL verdicts + mismatch warnings: the {@code get_scope} payload. */
    public Map<String, Object> status(List<String> checkUrls) {
        List<Map<String, Object>> reg;
        List<Map<String, Object>> exc;
        List<Map<String, Object>> ev;
        synchronized (this) {
            reg = deepCopy(registry);
            exc = deepCopy(excluded);
            ev = deepCopy(events);
        }
        List<Map<String, Object>> burpScope = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        for (Map<String, Object> e : reg) {
            String prefix = String.valueOf(e.get("prefix"));
            boolean inBurp = backend.isInScope(prefix);
            burpScope.add(Json.obj("prefix", prefix, "enabled", inBurp, "in_burp_scope", inBurp, "source", "registry"));
            if (!inBurp) {
                warnings.add("Registry prefix " + prefix + " is NOT in Burp's scope (Burp > Target > Scope was changed by hand). "
                        + "Requests under it are rejected until the two are reconciled.");
            }
        }
        for (Map<String, Object> e : exc) {
            String prefix = String.valueOf(e.get("prefix"));
            burpScope.add(Json.obj("prefix", prefix, "enabled", backend.isInScope(prefix), "in_burp_scope", backend.isInScope(prefix), "source", "excluded"));
        }
        List<Map<String, Object>> checks = new ArrayList<>();
        if (checkUrls != null) {
            for (String url : checkUrls) {
                Urls.parse(url);
                boolean inRegistry = registryCovers(url);
                String ex = excludedBy(url);
                boolean inBurp = backend.isInScope(url);
                boolean inScope = inRegistry && inBurp && ex == null;
                checks.add(Json.obj("url", url, "in_scope", inScope, "in_burp_scope", inBurp, "in_registry", inRegistry,
                        "excluded_by", ex));
                if (ex != null) {
                    warnings.add("URL " + url + " is explicitly excluded (" + ex + ") — never test it.");
                } else if (inBurp && !inRegistry) {
                    warnings.add("URL " + url + " is in Burp's scope but not in the agent authorization registry. "
                            + "If scope.md authorizes it, call add_to_scope with added_from provenance before testing it.");
                } else if (inRegistry && !inBurp) {
                    warnings.add("URL " + url + " is in the agent registry but not in Burp's scope — Burp scope was changed by hand; "
                            + "requests will be rejected until it is reconciled.");
                }
            }
        }
        int shown = Math.min(ev.size(), 20);
        return Json.obj(
                "agent_registry", reg,
                "burp_scope", burpScope,
                "excluded", exc,
                "checks", checks,
                "mismatch_warnings", warnings,
                "events", new ArrayList<>(ev.subList(ev.size() - shown, ev.size())),
                "gate", "a request is sent only when its URL is covered by the agent registry AND Burp scope, and not excluded");
    }

    public synchronized List<Map<String, Object>> registry() {
        return deepCopy(registry);
    }

    private synchronized String registryPrefixes() {
        if (registry.isEmpty()) {
            return "The agent registry is empty (no bootstrap has been declared).";
        }
        StringBuilder sb = new StringBuilder("Authorized prefixes: ");
        int n = Math.min(registry.size(), 10);
        for (int k = 0; k < n; k++) {
            if (k > 0) {
                sb.append(", ");
            }
            sb.append(registry.get(k).get("prefix"));
        }
        if (registry.size() > n) {
            sb.append(", … (").append(registry.size()).append(" total)");
        }
        sb.append('.');
        return sb.toString();
    }

    private static List<Map<String, Object>> deepCopy(List<Map<String, Object>> src) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> m : src) {
            out.add(new LinkedHashMap<>(m));
        }
        return out;
    }

    private void addEvent(String action, Map<String, Object> detail) {
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("at", Times.now());
        ev.put("action", action);
        ev.putAll(detail);
        events.add(ev);
        while (events.size() > MAX_EVENTS) {
            events.remove(0);
        }
    }

    private void persist() {
        store.set(STORE_KEY, Json.write(Json.obj(
                "version", 1,
                "registry", registry,
                "excluded", excluded,
                "events", events)));
    }
}
