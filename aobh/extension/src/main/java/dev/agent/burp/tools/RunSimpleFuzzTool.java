package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Params;
import dev.agent.burp.core.RawRequest;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.Urls;
import dev.agent.burp.gateway.CollabPayloadInfo;
import dev.agent.burp.gateway.SendSpec;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.InteractionRecord;
import dev.agent.burp.json.Json;

/**
 * {@code run_simple_fuzz}: bounded, sequential, single-insertion-point fuzzing. Every request goes through the same
 * counted send path as a hand-written one — so the scope gate re-runs per payload (a payload that rewrites the path
 * or the Host header is refused like any other request), the rate limiter paces it, and every send lands in
 * {@code requests_sent} and {@code fuzz_requests}.
 */
public final class RunSimpleFuzzTool implements Tool {
    static final String FUZZ = "{{FUZZ}}";
    static final String ORIG = "{{ORIG}}";
    /** Placeholder inside {@code ssrf_oob} payloads that becomes a fresh Collaborator hostname per request. */
    static final String COLLAB_PLACEHOLDER = "{P}";
    static final int MAX_PAYLOADS = 200;
    static final int MAX_REQUESTS = 200;
    static final long MIN_DELAY_MS = 100L;
    private static final int MAX_PAYLOAD_CHARS = 4096;
    private static final int MAX_CONSECUTIVE_FAILURES = 3;

    /** Benign payload sets: probes that can only produce an observable difference, never an effect. */
    static final Map<String, List<String>> PRESETS = new LinkedHashMap<>();

    static {
        PRESETS.put("sqli_error_based", List.of(
                "'", "\"", "'\")", "')\"))", "' OR '1'='1", "1 OR 1=1", "1' ORDER BY 1-- -", "1 UNION SELECT NULL-- -",
                "1;SELECT 1", "(SELECT 1)", "1' AND '1'='1", "1' AND '1'='0"));
        PRESETS.put("xss_reflected_basic", List.of(
                "<agentmark97>", "agentmark97", "\"agentmark97", "'agentmark97", "<agentmark97 id=agentmark97>",
                "<svg/agentmark97>", "<img agentmark97>", "<a agentmark97>", "</agentmark97>", "<agentmark97 x=\">"));
        PRESETS.put("path_traversal_basic", List.of(
                "../agentmark97", "..\\agentmark97", "....//agentmark97", "/etc/agentmark97", "..%2fagentmark97",
                "%2e%2e/agentmark97", "..;/agentmark97", ".././../agentmark97"));
        PRESETS.put("command_injection_benign", List.of(
                "; agentmark97", "| agentmark97", "`agentmark97`", "$(agentmark97)", "&& agentmark97", "|| agentmark97", "%0aagentmark97"));
        PRESETS.put("open_redirect", List.of(
                "https://agentmark97.example/", "//agentmark97.example", "https:agentmark97.example",
                "\\/\\/agentmark97.example", "/%09/agentmark97.example", "//agentmark97.example%2f.."));
        PRESETS.put("ssrf_oob", List.of(
                "{P}", "http://{P}", "http://{P}/agentmark97", "http://{P}:8080/agentmark97", "//{P}/agentmark97"));
        PRESETS.put("param_boolean_diff", List.of(
                "1 AND 1=1", "1 AND 1=0", "1' AND '1'='1", "1' AND '1'='0", "1 OR 1=1", "1 OR 1=0",
                "1 AND 1=1-- -", "1 AND 1=0-- -", "1') AND ('1'='1", "1') AND ('1'='0"));
        PRESETS.put("idor_id_swaps", List.of(
                "0", "1", "2", "3", "10", "100", "1000", "9999", "100000", "-1", "me", "self", "null", "undefined", "*", "%00"));
        PRESETS.put("template_injection_basic", List.of(
                "${7*7}", "{{7*7}}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}", "${agentmark97}", "{{agentmark97}}", "#{agentmark97}",
                "<%= agentmark97 %>"));
    }

    @Override
    public String name() {
        return "run_simple_fuzz";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) throws InterruptedException {
        String template = args.required("request_template");
        String notePrefix = args.required("note_prefix");
        if (!template.contains(FUZZ)) {
            throw new ToolException("invalid_argument",
                    "request_template must contain the literal marker {{FUZZ}} at the insertion point, e.g. 'GET /orders?id={{FUZZ}} HTTP/1.1'.");
        }
        if (template.indexOf(FUZZ) != template.lastIndexOf(FUZZ)) {
            throw new ToolException("invalid_argument",
                    "request_template contains more than one {{FUZZ}} marker. Use one insertion point per run so each result has a single cause.");
        }
        String origValue = args.str("orig_value", null);
        if (template.contains(ORIG) && (origValue == null || origValue.isEmpty())) {
            throw new ToolException("invalid_argument",
                    "request_template uses {{ORIG}} but orig_value is missing. Pass the original value of the parameter (from get_response / extract_parameters).");
        }

        boolean hasPayloads = args.has("payloads");
        boolean hasPreset = args.has("payload_preset");
        if (hasPayloads == hasPreset) {
            throw new ToolException("invalid_argument", "Pass exactly one of payloads (explicit list) or payload_preset (built-in set).");
        }
        String preset = null;
        List<String> payloads;
        if (hasPreset) {
            preset = args.choice("payload_preset", null, PRESETS.keySet().toArray(new String[0]));
            payloads = PRESETS.get(preset);
        } else {
            payloads = new ArrayList<>();
            for (String p : args.stringList("payloads")) {
                if (p.length() > MAX_PAYLOAD_CHARS) {
                    throw new ToolException("invalid_argument",
                            "payloads[" + payloads.size() + "] is longer than " + MAX_PAYLOAD_CHARS + " characters.");
                }
                payloads.add(p);
            }
            if (payloads.size() > MAX_PAYLOADS) {
                throw new ToolException("invalid_argument",
                        "payloads has " + payloads.size() + " entries; the cap is " + MAX_PAYLOADS + ". Split the run or narrow the list.");
            }
        }
        if (payloads.isEmpty()) {
            throw new ToolException("invalid_argument", "payloads is empty.");
        }

        Args stopOn = args.sub("stop_on");
        Integer stopStatus = stopOn.integer("status_code", null, 100, 599);
        Pattern stopRegex = ToolSupport.regex("stop_on.response_regex", stopOn.str("response_regex", null), true);
        boolean stopOnCollab = stopOn.bool("collaborator_hit", false);
        long delayMs = Math.max(MIN_DELAY_MS, args.integer("delay_ms", 250, 0, 60_000));
        int maxRequests = args.integer("max_requests", 100, 1, MAX_REQUESTS);
        boolean intruder = args.bool("also_send_to_intruder", false);
        String serviceUrl = args.str("url", null);
        serviceUrl = serviceUrl == null || serviceUrl.isBlank() ? null : serviceUrl.trim();

        // Everything that can be refused is refused before the first request leaves.
        RawRequest base = RawRequest.parse(template);
        if (serviceUrl == null && (base.hostHeader() == null || base.hostHeader().isBlank())) {
            throw new ToolException("invalid_argument",
                    "request_template has no Host header, so the destination is unknown. Add one or pass url (scheme, host, port).");
        }
        if (serviceUrl != null) {
            Urls.parse(serviceUrl);
        }
        int total = Math.min(payloads.size(), maxRequests);
        String runId = "f-" + ctx.log().nextNumber();

        if (intruder) {
            String position = "§" + (origValue == null ? "" : origValue) + "§";
            String intruderTemplate = template.replace(ORIG, origValue == null ? "" : origValue).replace(FUZZ, position);
            Exchange marker = new Exchange();
            marker.requestRaw = intruderTemplate;
            marker.url = serviceUrl;
            marker.method = base.method;
            ctx.sendToIntruder(marker, notePrefix);
        }

        List<Map<String, Object>> results = new ArrayList<>();
        List<Map<String, Object>> collabPayloads = new ArrayList<>();
        List<String> collabIds = new ArrayList<>();
        boolean stoppedEarly = false;
        String stopReason = null;
        int failures = 0;
        long startedAt = System.currentTimeMillis();
        for (int i = 0; i < total; i++) {
            String payload = payloads.get(i);
            String payloadId = null;
            if (payload.contains(COLLAB_PLACEHOLDER)) {
                CollabPayloadInfo info = ctx.newCollaboratorPayload();
                payload = payload.replace(COLLAB_PLACEHOLDER, info.payload);
                payloadId = info.payloadId;
                collabIds.add(payloadId);
                collabPayloads.add(ctx.collab().register(info, notePrefix + " [" + (i + 1) + "]"));
            }
            String raw = template;
            if (origValue != null) {
                raw = raw.replace(ORIG, origValue);
            }
            raw = raw.replace(FUZZ, payload);
            SendSpec spec = new SendSpec();
            spec.rawRequest = raw;
            spec.url = serviceUrl;
            String note = notePrefix + " [" + (i + 1) + "/" + total + "] " + Params.preview(payload, 60);
            spec.note = note;
            if (i > 0) {
                Thread.sleep(delayMs);
            }
            Exchange ex;
            try {
                ex = ctx.sendAndLog(spec, true, name(), note);
            } catch (ToolException e) {
                if (!"send_failed".equals(e.getMessage())) {
                    // Refused by the gate or unparsable: stop immediately, and say exactly what was already sent.
                    throw new ToolException(e.getMessage(),
                            "Fuzz run " + runId + " stopped at payload " + (i + 1) + " of " + total + " ("
                                    + Params.preview(payload, 60) + "). " + sentSummary(results) + " " + e.hint());
                }
                failures++;
                results.add(Json.obj(
                        "index", i,
                        "payload_preview", Params.preview(payload, 120),
                        "error", "send_failed",
                        "detail", e.hint(),
                        "match", false));
                if (failures >= MAX_CONSECUTIVE_FAILURES) {
                    stoppedEarly = true;
                    stopReason = MAX_CONSECUTIVE_FAILURES + " consecutive send failures — the target looks unreachable; stopped. "
                            + "The failed attempts are still counted in requests_sent.";
                    break;
                }
                continue;
            }
            failures = 0;
            boolean matched = stopStatus != null && ex.status == stopStatus
                    || stopRegex != null && ex.responseBody != null && stopRegex.matcher(ex.responseBody).find();
            String reason = null;
            if (matched) {
                reason = stopStatus != null && ex.status == stopStatus
                        ? "status_code " + stopStatus + " at payload " + (i + 1)
                        : "response_regex matched at payload " + (i + 1);
            }
            if (!matched && stopOnCollab && !collabIds.isEmpty() && !interactionsFor(ctx, collabIds).isEmpty()) {
                matched = true;
                reason = "collaborator interaction observed after payload " + (i + 1);
            }
            results.add(Json.obj(
                    "index", i,
                    "payload_preview", Params.preview(payload, 120),
                    "status_code", ex.status == 0 ? null : ex.status,
                    "response_length", ex.responseLength > 0 ? ex.responseLength : Render.utf8Length(ex.responseBody),
                    "match", matched,
                    "latency_ms", ex.latencyMs,
                    "agent_id", ex.agentId,
                    "collaborator_payload_id", payloadId));
            if (matched) {
                stoppedEarly = true;
                stopReason = reason;
                break;
            }
        }

        List<Map<String, Object>> hits = new ArrayList<>();
        if (!collabIds.isEmpty()) {
            for (InteractionRecord r : interactionsFor(ctx, collabIds)) {
                hits.add(Render.interaction(r, notePrefix));
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("run_id", runId);
        out.put("preset", preset);
        out.put("total_sent", results.size());
        out.put("send_failures", failures);
        out.put("planned", total);
        out.put("payloads_available", payloads.size());
        out.put("payloads_truncated", payloads.size() > maxRequests);
        out.put("stopped_early", stoppedEarly);
        out.put("stop_reason", stopReason);
        out.put("results", results);
        out.put("collaborator_payloads", collabPayloads);
        out.put("collaborator_hits", hits);
        out.put("collaborator_check", stopOnCollab
                ? (collabIds.isEmpty() ? "no payload of this run used a Collaborator hostname ({P} / preset ssrf_oob), so there was nothing to poll"
                        : "polled between requests and once more at the end")
                : "disabled (stop_on.collaborator_hit not set)");
        out.put("delay_ms", delayMs);
        out.put("elapsed_ms", System.currentTimeMillis() - startedAt);
        out.put("counted_as", "requests_sent and fuzz_requests (see GET /health)");
        out.put("budget", Json.obj("requests_sent", ctx.counters().requestsSent(), "fuzz_requests", ctx.counters().fuzzRequests()));
        out.put("next_step", "Review status/length outliers and matches, then reproduce any interesting payload one at a time with "
                + "modify_and_resend_request (single-variable change) before recording a candidate.");
        return out;
    }

    private static List<InteractionRecord> interactionsFor(ToolContext ctx, List<String> payloadIds) {
        List<InteractionRecord> out = new ArrayList<>();
        try {
            for (InteractionRecord r : ctx.collaboratorInteractions(null)) {
                if (payloadIds.contains(r.payloadId)) {
                    out.add(r);
                }
            }
        } catch (RuntimeException e) {
            return out;
        }
        return out;
    }

    private static String sentSummary(List<Map<String, Object>> results) {
        if (results.isEmpty()) {
            return "No request of this run had been sent yet.";
        }
        Object first = results.get(0).get("agent_id");
        Object last = results.get(results.size() - 1).get("agent_id");
        return "The " + results.size() + " request(s) before it were sent and logged (agent ids " + first + " … " + last
                + ") and are counted in requests_sent / fuzz_requests; read them with get_response.";
    }
}
