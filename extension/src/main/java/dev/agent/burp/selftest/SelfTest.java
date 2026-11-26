package dev.agent.burp.selftest;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import dev.agent.burp.BridgeConfig;
import dev.agent.burp.bridge.BridgeServer;
import dev.agent.burp.core.RateLimiter;
import dev.agent.burp.core.ScopeBackend;
import dev.agent.burp.core.ScopeGuard;
import dev.agent.burp.core.Times;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.ToolRegistry;
import dev.agent.burp.core.TrafficCounters;
import dev.agent.burp.core.Urls;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.KeyValueStore;
import dev.agent.burp.json.Json;
import dev.agent.burp.standalone.FakeBurpGateway;
import dev.agent.burp.tools.Tools;
import dev.agent.burp.ui.SettingsPanel;

/**
 * Proves the bridge's wire behaviour on a plain JVM, with {@link FakeBurpGateway} standing in for Burp. It speaks
 * raw HTTP/1.1 over a socket, so it controls the Host and Origin headers, bodies and connection reuse exactly.
 * Exit code 0 means every check passed; the output lists each failed check.
 */
public final class SelfTest {
    private static final String TOKEN = "selftest-token-0123456789-abcdefghijklmnop";
    private static final List<String> COUNTER_KEYS = List.of("requests_sent", "fuzz_requests",
            "redirect_following_requests", "send_errors", "tool_calls", "tool_errors", "rejected_out_of_scope",
            "rejected_other");
    private static final Pattern PAYLOAD = Pattern.compile("([0-9a-f]{13}\\.oast\\.example)");

    private static int passed;
    private static int failed;
    private static final List<String> FAILURES = new ArrayList<>();

    private SelfTest() {
    }

    public static int run(String manifestPath) {
        System.out.println("AI Agent Bridge self-test" + (manifestPath == null ? "" : " (manifest: " + manifestPath + ")"));
        try {
            exercise(manifestPath);
        } catch (Throwable t) {
            failed++;
            System.out.println("  FAIL self-test aborted: " + t);
            t.printStackTrace(System.out);
        }
        if (failed == 0) {
            System.out.println("SELF-TEST PASSED: " + passed + " checks");
            return 0;
        }
        System.out.println("SELF-TEST FAILED: " + failed + " of " + (passed + failed) + " checks");
        for (String f : FAILURES) {
            System.out.println("  - " + f);
        }
        return 1;
    }

    public static void main(String[] args) {
        if (args.length > 0 && "--serve".equals(args[0])) {
            ServeMode.main(Arrays.copyOfRange(args, 1, args.length));
            return;                                  // ServeMode.main exits the process itself
        }
        System.exit(run(args.length > 0 ? args[0] : null));
    }

    private static void check(String label, boolean ok, String detail) {
        if (ok) {
            passed++;
        } else {
            failed++;
            FAILURES.add(label + " — " + detail);
            System.out.println("  FAIL " + label + " — " + detail);
        }
    }

    // ------------------------------------------------------------------ the scenario

    private static void exercise(String manifestPath) throws Exception {
        FakeBurpGateway gw = new FakeBurpGateway();
        TrafficCounters counters = new TrafficCounters();
        ToolRegistry registry = ToolRegistry.create(gw, counters, new RateLimiter(1000.0), new KeyValueStore.Memory(),
                Tools.all());
        registry.scope().add("http://127.0.0.1:8080", "self-test: scope line 1", true);
        seedProxy(gw);

        // ---- authentication and client policy
        List<String> accessLog = java.util.Collections.synchronizedList(new ArrayList<>());
        BridgeServer server = BridgeServer.start(registry, "127.0.0.1", 0, TOKEN, accessLog::add);
        try {
            String host = "127.0.0.1:" + server.port();
            Reply r;
            try (Client c = new Client(host)) {
                r = c.send("GET", "/health", host, null, null, null, false);
                check("GET /health without a token is 401", r.status == 401, r.status + " " + r.body);
                check("401 offers the Bearer challenge and the error envelope",
                        r.headers.containsKey("www-authenticate") && "unauthorized".equals(json(r.body).get("error")), r.body);
            }
            try (Client c = new Client(host)) {
                r = c.send("GET", "/health", host, "wrong-token-wrong-token-wrong", null, null, false);
                check("a wrong token is 401", r.status == 401, r.status + " " + r.body);
            }
            try (Client c = new Client(host)) {
                r = c.send("GET", "/health", host, null, new String[] {"Origin: http://evil.example"}, null, false);
                check("a browser origin is refused before anything else (403, no token needed)",
                        r.status == 403 && "forbidden".equals(json(r.body).get("error")), r.status + " " + r.body);
            }
            try (Client c = new Client(host)) {
                r = c.send("GET", "/health", "evil.example", TOKEN, null, null, false);
                check("a foreign Host header is refused even with the right token", r.status == 403, r.status + " " + r.body);
            }
            try (Client c = new Client(host)) {
                r = c.send("GET", "/health", "localhost:" + server.port(), TOKEN, null, null, false);
                check("Host localhost:<port> is accepted", r.status == 200, r.status + " " + r.body);
            }
            try (Client c = new Client(host)) {
                r = c.send("POST", "/health", host, TOKEN, null, "{}", false);
            }
            Reply notATool;
            try (Client c = new Client(host)) {
                notATool = c.send("GET", "/tools/no-such-tool", host, TOKEN, null, null, false);
            }
            Reply noPath;
            try (Client c = new Client(host)) {
                noPath = c.send("GET", "/nope", host, TOKEN, null, null, false);
            }
            Reply head;
            try (Client c = new Client(host)) {
                head = c.send("HEAD", "/health", host, TOKEN, null, null, false);
            }
            check("wrong method is 405 with Allow, unknown tool 404, unknown path 404, HEAD is 200 without a body; "
                    + "error responses close the connection",
                    r.status == 405 && r.headers.containsKey("allow") && "close".equals(r.headers.get("connection"))
                            && notATool.status == 404 && noPath.status == 404 && head.status == 200 && head.body.isEmpty(),
                    r.status + "/" + notATool.status + "/" + noPath.status + "/" + head.status);

            // ---- /health document
            Map<String, Object> health;
            Map<String, Object> cn;
            try (Client c = new Client(host)) {
                health = get(c, "/health");
                cn = map(health.get("counters"));
                Reply a = c.send("GET", "/health", host, TOKEN, null, null, false);
                Reply b = c.send("POST", "/tools/get_scope", host, TOKEN, null, "{}", false);
                Reply k = c.send("POST", "/tools/get_scope", host, TOKEN, null, "{\"check_urls\":[]}", true);
                check("keep-alive: a second request on the same connection is answered", a.status == 200 && b.status == 200,
                        a.status + "/" + b.status);
                check("a chunked request body is read", k.status == 200 && Boolean.TRUE.equals(json(k.body).get("ok")),
                        k.status + " " + k.body);
            }
            check("/health: ok, counters_version 1, 15 tools, standalone mode",
                    Boolean.TRUE.equals(health.get("ok")) && num(health, "counters_version") == 1 && num(health, "tools") == 15
                            && "standalone".equals(health.get("mode")), Json.write(health));
            check("/health: instance id has the documented shape",
                    String.valueOf(health.get("instance")).matches("br-\\d{8}T\\d{6}-[0-9a-f]{8}"), String.valueOf(health.get("instance")));
            check("/health: instance equals the counters object's id", counters.instance().equals(health.get("instance")), "");
            check("/health: counters has the eight keys in the documented order", new ArrayList<>(cn.keySet()).equals(COUNTER_KEYS),
                    String.valueOf(cn.keySet()));
            check("/health: every counter starts at zero", allZero(cn), Json.write(cn));

            // ---- /tools parity with the manifest file
            List<Map<String, Object>> served;
            try (Client c = new Client(host)) {
                served = list(get(c, "/tools").get("tools"));
            }
            check("/tools serves 15 definitions", served.size() == 15, String.valueOf(served.size()));
            if (manifestPath != null) {
                Map<String, Object> manifest = json(Files.readString(Path.of(manifestPath)));
                List<String> expected = list(map(map(manifest.get("meta")).get("bridge")).get("tool_names"));
                List<String> names = new ArrayList<>();
                served.forEach(t -> names.add(String.valueOf(t.get("name"))));
                check("/tools names and order equal meta.bridge.tool_names of tools.json", names.equals(expected),
                        names + " vs " + expected);
                int mismatched = 0;
                for (Map<String, Object> tool : served) {
                    Map<String, Object> file = null;
                    List<Map<String, Object>> manifestTools = list(manifest.get("tools"));
                for (Map<String, Object> t : manifestTools) {
                        if (String.valueOf(t.get("name")).equals(String.valueOf(tool.get("name")))) {
                            file = t;
                        }
                    }
                    if (file == null || !Json.write(file.get("description")).equals(Json.write(tool.get("description")))
                            || !Json.write(file.get("inputSchema")).equals(Json.write(tool.get("inputSchema")))) {
                        mismatched++;
                    }
                }
                check("/tools descriptions and input schemas are identical to tools.json", mismatched == 0,
                        mismatched + " tools differ");
            } else {
                System.out.println("  (no manifest path given: file parity not checked)");
            }

            // ---- counting on the send path
            Map<String, Object> first = call(host, "send_http_request",
                    obj("url", "http://127.0.0.1:8080/app?x=1", "note", "H1n counting"));
            check("send_http_request succeeds", Boolean.TRUE.equals(first.get("ok")), Json.write(first));
            Map<String, Object> d1 = map(first.get("data"));
            String agentId = String.valueOf(d1.get("agent_id"));
            check("the first agent request is a-1 and the response is rendered",
                    "a-1".equals(agentId) && "200".equals(String.valueOf(d1.get("status_code"))), Json.write(d1));
            cn = counters(host);
            check("a sent request counts in requests_sent (not fuzz); tool_calls holds the two earlier get_scope calls too",
                    num(cn, "requests_sent") == 1 && num(cn, "fuzz_requests") == 0 && num(cn, "tool_calls") == 3
                            && num(cn, "rejected_out_of_scope") == 0 && num(cn, "tool_errors") == 0,
                    Json.write(cn));

            Map<String, Object> refused = call(host, "send_http_request", obj("url", "http://evil.example/", "note", "H1n out of scope"));
            check("a URL outside the registry is refused with out_of_scope",
                    !Boolean.TRUE.equals(refused.get("ok")) && "out_of_scope".equals(refused.get("error")), Json.write(refused));
            cn = counters(host);
            check("a refused URL is not sent and not in requests_sent",
                    num(cn, "requests_sent") == 1 && num(cn, "rejected_out_of_scope") == 1 && gw.sent.size() == 1, Json.write(cn));

            Map<String, Object> mismatch = call(host, "send_http_request", obj("url", "http://127.0.0.1:8080/",
                    "raw_request", "GET / HTTP/1.1\r\nHost: other.example\r\n\r\n", "note", "H1n host mismatch"));
            check("a raw request whose Host differs from the authorized URL is refused with host_header_mismatch",
                    "host_header_mismatch".equals(mismatch.get("error")), Json.write(mismatch));
            cn = counters(host);
            check("the Host-mismatch refusal is counted as out of scope and nothing reached Burp",
                    num(cn, "requests_sent") == 1 && num(cn, "rejected_out_of_scope") == 2 && gw.sent.size() == 1, Json.write(cn));

            List<Map<String, Object>> setParams = List.of(obj("name", "x", "value", "2"));
            Map<String, Object> dry = call(host, "modify_and_resend_request", obj("source", obj("type", "agent", "id", agentId),
                    "set_params", setParams, "send_now", false, "note", "H1n dry run"));
            check("a dry run reports dry_run and sends nothing",
                    Boolean.TRUE.equals(dry.get("ok")) && Boolean.TRUE.equals(map(dry.get("data")).get("dry_run")), Json.write(dry));
            cn = counters(host);
            check("a dry run is not counted", num(cn, "requests_sent") == 1 && gw.sent.size() == 1, Json.write(cn));

            Map<String, Object> modified = call(host, "modify_and_resend_request", obj("source", obj("type", "agent", "id", agentId),
                    "set_params", setParams, "note", "H1n modify and resend"));
            cn = counters(host);
            check("the real resend is sent with the new parameter and counted once",
                    Boolean.TRUE.equals(modified.get("ok")) && gw.sent.size() == 2 && num(cn, "requests_sent") == 2
                            && (String.valueOf(gw.sent.get(1).url) + String.valueOf(gw.sent.get(1).rawRequest)).contains("x=2"),
                    Json.write(cn));

            String template = "GET /app?x={{FUZZ}} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n";
            Map<String, Object> fuzz = call(host, "run_simple_fuzz", obj("request_template", template,
                    "payloads", List.of("p1", "p2", "p3"), "note_prefix", "H3n fuzz", "delay_ms", 100));
            cn = counters(host);
            check("a 3-payload fuzz adds 3 to both requests_sent and fuzz_requests",
                    Boolean.TRUE.equals(fuzz.get("ok")) && num(map(fuzz.get("data")), "total_sent") == 3
                            && num(cn, "requests_sent") == 5 && num(cn, "fuzz_requests") == 3, Json.write(cn));

            Map<String, Object> stopped = call(host, "run_simple_fuzz", obj("request_template", template,
                    "payloads", List.of("p1", "p2", "p3", "p4", "p5"), "note_prefix", "H3n stop_on",
                    "stop_on", obj("response_regex", "p3"), "delay_ms", 100));
            check("stop_on.response_regex stops the run after the matching request",
                    num(map(stopped.get("data")), "total_sent") == 3, Json.write(stopped));
            Map<String, Object> capped = call(host, "run_simple_fuzz", obj("request_template", template,
                    "payloads", List.of("p1", "p2", "p3", "p4", "p5"), "note_prefix", "H3n cap", "max_requests", 2, "delay_ms", 100));
            cn = counters(host);
            check("max_requests caps the run at 2 (10 sent, 8 fuzz in total)",
                    num(map(capped.get("data")), "total_sent") == 2 && num(cn, "requests_sent") == 10 && num(cn, "fuzz_requests") == 8,
                    Json.write(cn));

            Map<String, Object> hostFuzz = call(host, "run_simple_fuzz", obj("request_template",
                    "GET / HTTP/1.1\r\nHost: {{FUZZ}}.127.0.0.1:8080\r\n\r\n", "url", "http://127.0.0.1:8080/",
                    "payloads", List.of("evil1", "evil2"), "note_prefix", "H3n host fuzz"));
            cn = counters(host);
            check("a payload that lands in the Host header is refused before anything is sent",
                    "host_header_mismatch".equals(hostFuzz.get("error")) && gw.sent.size() == 10
                            && num(cn, "requests_sent") == 10 && num(cn, "rejected_out_of_scope") == 3,
                    Json.write(hostFuzz) + " / " + Json.write(cn));

            String[][] badTemplates = {
                    {"no marker", "GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"},
                    {"two markers", "GET /?a={{FUZZ}}&b={{FUZZ}} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"},
                    {"ORIG without orig_value", "GET /?a={{FUZZ}}&b={{ORIG}} HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"}};
            int rejectedTemplates = 0;
            for (String[] bad : badTemplates) {
                Map<String, Object> out = call(host, "run_simple_fuzz", obj("request_template", bad[1],
                        "payloads", List.of("p"), "note_prefix", "H3n invalid"));
                if (!Boolean.TRUE.equals(out.get("ok")) && "invalid_argument".equals(out.get("error"))) {
                    rejectedTemplates++;
                }
            }
            check("malformed fuzz templates are refused with invalid_argument", rejectedTemplates == badTemplates.length,
                    rejectedTemplates + " of " + badTemplates.length);

            // ---- envelope and error accounting
            try (Client c = new Client(host)) {
                Reply broken = c.send("POST", "/tools/get_scope", host, TOKEN, null, "{not json", false);
                Reply unknown = c.send("POST", "/tools/no_such_tool", host, TOKEN, null, "{}", false);
                Reply missing = c.send("POST", "/tools/send_http_request", host, TOKEN, null, "{\"url\":\"http://127.0.0.1:8080/\"}", false);
                check("broken JSON -> invalid_json, unknown tool -> unknown_tool, missing note -> missing_argument",
                        "invalid_json".equals(json(broken.body).get("error")) && "unknown_tool".equals(json(unknown.body).get("error"))
                                && "missing_argument".equals(json(missing.body).get("error")),
                        broken.body + " | " + unknown.body + " | " + missing.body);
            }
            try (Client c = new Client(host)) {
                c.raw("POST /tools/get_scope HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Bearer " + TOKEN
                        + "\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n");
                String interim = c.line();
                c.raw("{}");
                Reply after = c.read();
                check("Expect: 100-continue gets the interim response, then the body is read",
                        interim != null && interim.contains("100 Continue") && after.status == 200, interim + " / " + after.status);
            }
            try (Client c = new Client(host)) {
                c.raw("POST /tools/get_scope HTTP/1.1\r\nHost: " + host + "\r\nAuthorization: Bearer " + TOKEN + "\r\nContent-Length: "
                        + (BridgeServer.MAX_BODY_BYTES + 1) + "\r\n\r\n");
                Reply tooBig = c.read(true);
                check("a declared body over 16 MiB is refused with 413 before it is read",
                        tooBig.status == 413 && "payload_too_large".equals(json(tooBig.body).get("error")), tooBig.status + " " + tooBig.body);
            }
            cn = counters(host);
            check("invalid calls count in tool_calls and rejected_other; out-of-scope refusals do not",
                    num(cn, "tool_calls") == 18 && num(cn, "rejected_other") == 8 && num(cn, "requests_sent") == 10, Json.write(cn));

            Thread slow = new Thread(() -> {
                try (Client c = new Client(host)) {
                    c.send("POST", "/tools/poll_collaborator", host, TOKEN, null, "{\"wait_seconds\":3}", false);
                } catch (IOException e) {
                    System.out.println("  (long poll ended with " + e + ")");
                }
            });
            slow.start();
            Thread.sleep(300);
            long t0 = System.nanoTime();
            try (Client c = new Client(host)) {
                Reply quick = c.send("GET", "/health", host, TOKEN, null, null, false);
                long ms = (System.nanoTime() - t0) / 1_000_000;
                check("/health is answered while a tool call is waiting", quick.status == 200 && ms < 1500, ms + " ms");
            }
            slow.join();

            // ---- the rest of the tool surface through the same bridge
            Map<String, Object> tab1 = call(host, "create_repeater_tab", obj("source", obj("type", "agent", "id", agentId)));
            Map<String, Object> tab2 = call(host, "create_repeater_tab", obj("source", obj("type", "agent", "id", agentId)));
            check("two repeater tabs get distinct agent names",
                    Boolean.TRUE.equals(tab1.get("ok")) && gw.repeaterTabs.size() == 2
                            && !gw.repeaterTabs.get(0).equals(gw.repeaterTabs.get(1)), gw.repeaterTabs.toString());
            Map<String, Object> resp = call(host, "get_response", obj("source", obj("type", "agent", "id", agentId)));
            check("get_response returns the stored response with its headers",
                    Boolean.TRUE.equals(resp.get("ok")) && Json.write(resp).contains("X-Demo") && Json.write(resp).contains("standalone"),
                    Json.write(resp));
            Map<String, Object> hist = call(host, "get_proxy_history", obj("url_contains", "/login"));
            check("proxy history is filtered by URL substring",
                    Boolean.TRUE.equals(hist.get("ok")) && Json.write(hist).contains("/login?next=/home"), Json.write(hist));
            Map<String, Object> site = call(host, "get_site_map", obj("url_prefix", "http://127.0.0.1:8080/app"));
            check("sent requests are registered in the site map",
                    Boolean.TRUE.equals(site.get("ok")) && Json.write(site).contains("127.0.0.1:8080/app?x="), Json.write(site));
            Map<String, Object> scopeOut = call(host, "get_scope", obj("check_urls", List.of("http://127.0.0.1:8080/x", "http://evil.example/")));
            check("get_scope reports enabled flags and in_scope checks",
                    Json.write(scopeOut).contains("\"enabled\":true") && Json.write(scopeOut).contains("\"in_scope\":true")
                            && Json.write(scopeOut).contains("\"in_scope\":false"), Json.write(scopeOut));
            Map<String, Object> truncated = call(host, "send_http_request", obj("url", "http://127.0.0.1:8080/cap", "note", "H1n cap", "max_bytes", 5));
            check("max_bytes truncates the returned body and says so",
                    Boolean.TRUE.equals(truncated.get("ok")) && Json.write(truncated).contains("\"response_truncated\":true"), Json.write(truncated));
            Map<String, Object> noEvidence = call(host, "raise_issue", obj("title", "T", "severity", "high", "confidence", "firm",
                    "url", "http://127.0.0.1:8080/app", "description", "d"));
            Map<String, Object> raised = call(host, "raise_issue", obj("title", "T", "severity", "high", "confidence", "firm",
                    "url", "http://127.0.0.1:8080/app", "description", "d",
                    "evidence", List.of(obj("source", obj("type", "agent", "id", agentId), "step", "sent x=2"))));
            check("a high-severity issue needs evidence; a raised one gets the id agent-issue-1",
                    "invalid_argument".equals(noEvidence.get("error")) && Json.write(raised).contains("agent-issue-1"),
                    Json.write(noEvidence) + " | " + Json.write(raised));
            Map<String, Object> payloadOut = call(host, "get_collaborator_payload", obj("note", "H4n oob"));
            Matcher m = PAYLOAD.matcher(Json.write(payloadOut));
            String payloadId = m.find() ? m.group(1) : null;
            check("a Collaborator payload is issued", payloadId != null, Json.write(payloadOut));
            if (payloadId != null) {
                gw.addInteraction(payloadId, "dns", "A? " + payloadId);
            }
            Map<String, Object> poll = call(host, "poll_collaborator", obj("payload_id", payloadId == null ? "none" : payloadId));
            check("poll_collaborator returns the recorded interaction for that payload",
                    Boolean.TRUE.equals(poll.get("ok")) && Json.write(poll).contains("oast.example"), Json.write(poll));
            gw.collaboratorEnabled = false;
            Map<String, Object> noCollab = call(host, "get_collaborator_payload", obj("note", "H4n disabled"));
            gw.collaboratorEnabled = true;
            check("a disabled Collaborator surfaces as collaborator_unavailable, not as a crash",
                    !Boolean.TRUE.equals(noCollab.get("ok")) && "collaborator_unavailable".equals(noCollab.get("error")), Json.write(noCollab));
            cn = counters(host);
            check("counters only ever moved through the send path",
                    num(cn, "requests_sent") == 11 && num(cn, "fuzz_requests") == 8 && num(cn, "send_errors") == 0
                            && num(cn, "tool_errors") == 0 && num(cn, "rejected_out_of_scope") == 3, Json.write(cn));
            check("the access log never contains the token", accessLog.stream().noneMatch(line -> line.contains(TOKEN)),
                    accessLog.size() + " lines");
            String firstInstance = String.valueOf(health.get("instance"));
            server.stop();

            // ---- restart: a new instance id with zeroed counters
            ToolRegistry registry2 = ToolRegistry.create(gw, new TrafficCounters(), new RateLimiter(1000.0),
                    new KeyValueStore.Memory(), Tools.all());
            BridgeServer server2 = BridgeServer.start(registry2, "127.0.0.1", 0, TOKEN, line -> { });
            try (Client c = new Client("127.0.0.1:" + server2.port())) {
                Map<String, Object> again = get(c, "/health");
                check("a restarted bridge has a new instance id and zeroed counters",
                        !firstInstance.equals(again.get("instance")) && allZero(map(again.get("counters"))), Json.write(again));
            } finally {
                server2.stop();
            }
        } finally {
            server.stop();
        }

        scopeRules();
        ratePacing();
        configRules();
        settingsPanel();
    }

    private static void seedProxy(FakeBurpGateway gw) {
        Exchange ex = new Exchange();
        ex.url = "http://127.0.0.1:8080/login?next=/home";
        ex.method = "GET";
        ex.status = 200;
        ex.mimeType = "HTML";
        ex.requestRaw = "GET /login?next=/home HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nCookie: sid=abc\r\n\r\n";
        ex.responseRaw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><form action=/login method=post>"
                + "<input name=user value=><input name=pass></form></html>";
        ex.responseBody = "<html><form action=/login method=post><input name=user value=><input name=pass></form></html>";
        ex.responseLength = ex.responseBody.length();
        ex.time = Times.now();
        gw.addProxyItem(ex);
    }

    /** The authorization registry's prefix rules, on a fresh guard with a recording backend. */
    private static void scopeRules() {
        List<String> included = new ArrayList<>();
        List<String> excluded = new ArrayList<>();
        ScopeBackend backend = new ScopeBackend() {
            @Override
            public boolean isInScope(String url) {
                for (String p : excluded) {
                    if (Urls.covers(p, url)) {
                        return false;
                    }
                }
                for (String p : included) {
                    if (Urls.covers(p, url)) {
                        return true;
                    }
                }
                return false;
            }

            @Override
            public void include(String prefix) {
                included.add(prefix);
            }

            @Override
            public void exclude(String prefix) {
                excluded.add(prefix);
            }
        };
        ScopeGuard guard = ScopeGuard.load(new KeyValueStore.Memory(), backend);
        guard.add("https://shop.example/app", "scope.md line 3", true);
        check("scope: /app covers /app/admin/x and /app?y=1",
                guard.registryCovers("https://shop.example/app/admin/x") && guard.registryCovers("https://shop.example/app?y=1"), "");
        check("scope: /app does not cover /apples, a look-alike host, or another scheme",
                !guard.registryCovers("https://shop.example/apples") && !guard.registryCovers("https://shop.example.evil.com/app")
                        && !guard.registryCovers("http://shop.example/app"), "");
        check("scope: the default port is normalized (:443 = https)", guard.registryCovers("https://shop.example:443/app/x"), "");
        boolean narrowed = true;
        try {
            guard.add("https://shop.example/app/admin", "scope.md line 4", false);
        } catch (ToolException e) {
            narrowed = false;
        }
        boolean widened = false;
        try {
            guard.add("https://shop.example/", "too wide", false);
        } catch (ToolException e) {
            widened = "prefix_not_authorized".equals(e.getMessage());
        }
        check("scope: narrowing is allowed, widening needs bootstrap_override", narrowed && widened, narrowed + "/" + widened);
        int before = guard.registry().size();
        guard.remove("https://shop.example/app/admin", false);
        String refusal = null;
        try {
            guard.assertInScope("https://shop.example/app/admin/x", "scope_check");
        } catch (ToolException e) {
            refusal = e.getMessage() + " " + e.hint();
        }
        check("scope: remove_from_scope without drop_from_registry keeps the registry entry as provenance; the exclusion already blocks its URLs",
                guard.registry().size() == before && guard.registryCovers("https://shop.example/app/admin/x")
                        && "https://shop.example/app/admin".equals(guard.excludedBy("https://shop.example/app/admin/x"))
                        && refusal != null && refusal.contains("explicitly excluded"),
                before + " -> " + guard.registry().size() + "; refusal: " + refusal);
        guard.remove("https://shop.example/app/admin", true);
        boolean entryDropped = true;
        for (Map<String, Object> e : guard.registry()) {
            if ("https://shop.example/app/admin".equals(e.get("prefix"))) {
                entryDropped = false;
            }
        }
        check("scope: remove_from_scope with drop_from_registry=true drops the registry entry it covers",
                guard.registry().size() == before - 1 && entryDropped
                        && guard.registryCovers("https://shop.example/app/admin/x"),
                before + " -> " + guard.registry().size());
    }

    private static void ratePacing() {
        RateLimiter limiter = new RateLimiter(25.0);
        long t0 = System.nanoTime();
        for (int k = 0; k < 6; k++) {
            limiter.acquire();
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;
        check("the rate limiter spaces 6 permits at 25 req/s over at least 160 ms", ms >= 160 && ms < 10_000, ms + " ms");
    }

    private static void configRules() {
        Map<String, String> saved = new HashMap<>();
        BridgeConfig.Preferences prefs = new BridgeConfig.Preferences() {
            @Override
            public String get(String key) {
                return saved.get(key);
            }

            @Override
            public void set(String key, String value) {
                saved.put(key, value);
            }

            @Override
            public void delete(String key) {
                saved.remove(key);
            }
        };
        Function<String, String> noEnv = k -> null;
        BridgeConfig fromEnv = BridgeConfig.resolve(prefs, k -> "BURP_BRIDGE_TOKEN".equals(k) ? "env-token-0123456789abcdef" : null, noEnv);
        saved.put(BridgeConfig.PREF_TOKEN, "settings-token-0123456789");
        BridgeConfig fromSettings = BridgeConfig.resolve(prefs, k -> "BURP_BRIDGE_TOKEN".equals(k) ? "env-token-0123456789abcdef" : null, noEnv);
        saved.clear();
        BridgeConfig none = BridgeConfig.resolve(prefs, noEnv, noEnv);
        BridgeConfig badPort = BridgeConfig.resolve(prefs, k -> "BURP_BRIDGE_PORT".equals(k) ? "abc"
                : k.equals(BridgeConfig.ENV_TOKEN) ? "valid-token-0123456789abcdef" : null, noEnv);
        BridgeConfig shortToken = BridgeConfig.resolve(prefs, k -> "BURP_BRIDGE_TOKEN".equals(k) ? "short" : null, noEnv);
        BridgeConfig defaults = BridgeConfig.resolve(prefs,
                k -> "BURP_BRIDGE_TOKEN".equals(k) ? "sysprop-token-0123456789ab" : null, k -> "burp.bridge.port".equals(k) ? "9000" : null);
        check("settings: the token comes from the environment when nothing is saved, and from the settings when both exist",
                "env-token-0123456789abcdef".equals(fromEnv.token) && "BURP_BRIDGE_TOKEN".equals(fromEnv.tokenSource)
                        && "settings-token-0123456789".equals(fromSettings.token) && "settings".equals(fromSettings.tokenSource), "");
        check("settings: without a token the config is unusable and says so",
                none.token == null && none.problem() != null && !String.valueOf(none.problem()).contains(TOKEN), String.valueOf(none.problem()));
        check("settings: a bad port and a short token are reported, not thrown",
                badPort.problem() != null && badPort.problem().contains("Port") && shortToken.problem() != null
                        && shortToken.problem().contains("at least 16"),
                String.valueOf(badPort.problem()) + " | " + String.valueOf(shortToken.problem()));
        check("settings: defaults are 127.0.0.1:8787 at 2 req/s, a system property supplies the port",
                "127.0.0.1".equals(defaults.bindAddress) && defaults.port == 9000 && defaults.permitsPerSecond == 2.0
                        && defaults.problem() == null, defaults.describe());
        check("settings: describe() never shows the token", !fromEnv.describe().contains(fromEnv.token), fromEnv.describe());
        String t1 = BridgeConfig.generateToken();
        String t2 = BridgeConfig.generateToken();
        check("settings: generated tokens are 32 URL-safe chars and never repeat",
                t1.length() == 32 && t1.matches("[A-Za-z0-9_-]+") && !t1.equals(t2), t1);
        BridgeConfig blank = BridgeConfig.fromFields("  ", "127.0.0.1", "8787", "2");
        check("settings: an empty token field means no token (the tab can switch the bridge off)",
                blank.token == null && blank.problem(false) == null && blank.problem() != null, "");
    }

    private static void settingsPanel() {
        String[] applied = new String[1];
        String[] problem = new String[1];
        SettingsPanel panel = new SettingsPanel(new SettingsPanel.Listener() {
            @Override
            public String apply(String token, String bind, String port, String rate) {
                applied[0] = token + "|" + bind + "|" + port + "|" + rate;
                return problem[0];
            }

            @Override
            public String newToken() {
                return "generated-token-0123456789abcd";
            }
        });
        check("settings tab: builds without a display", panel.component() != null, "");
        panel.setFields("tok", "127.0.0.1", "8787", "2");
        panel.clickApply();
        check("settings tab: Apply hands the four fields to the extension", "tok|127.0.0.1|8787|2".equals(applied[0]), String.valueOf(applied[0]));
        panel.clickGenerate();
        check("settings tab: Generate fills the token field", "generated-token-0123456789abcd".equals(panel.tokenText()), panel.tokenText());
        problem[0] = "Port must be 1..65535, got 0.";
        panel.setFields("tok", "127.0.0.1", "0", "2");
        panel.clickApply();
        check("settings tab: a refused apply shows the problem", panel.statusText().contains("65535"), panel.statusText());
        panel.running("http://127.0.0.1:8787", 17, "br-20260101T000000-00000000", true);
        check("settings tab: the running status names the URI and the MCP variables",
                panel.statusText().contains("http://127.0.0.1:8787") && panel.statusText().contains("BURP_BRIDGE_TOKEN"), panel.statusText());
        panel.running("http://10.0.0.5:8787", 17, "br-x", false);
        panel.stopped("No token is configured.");
        check("settings tab: a stopped bridge shows the reason", panel.statusText().startsWith("No token is configured."), panel.statusText());
    }

    // ------------------------------------------------------------------ helpers

    private static Map<String, Object> get(Client c, String path) throws IOException {
        Reply r = c.send("GET", path, c.authority, TOKEN, null, null, false);
        if (r.status != 200) {
            throw new IOException(path + " -> " + r.status + " " + r.body);
        }
        return json(r.body);
    }

    private static Map<String, Object> call(String authority, String tool, Map<String, Object> arguments) throws IOException {
        try (Client c = new Client(authority)) {
            Reply r = c.send("POST", "/tools/" + tool, authority, TOKEN, null, Json.write(arguments), false);
            if (r.status != 200) {
                throw new IOException(tool + " -> HTTP " + r.status + " " + r.body);
            }
            return json(r.body);
        }
    }

    private static Map<String, Object> counters(String authority) throws IOException {
        try (Client c = new Client(authority)) {
            return map(get(c, "/health").get("counters"));
        }
    }

    private static boolean allZero(Map<String, Object> counters) {
        for (Object v : counters.values()) {
            if (!(v instanceof Number n) || n.longValue() != 0) {
                return false;
            }
        }
        return !counters.isEmpty();
    }

    private static Map<String, Object> json(String text) {
        return Json.parseObject(text);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) {
        return o == null ? new LinkedHashMap<>() : (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static <T> List<T> list(Object o) {
        return o == null ? List.of() : (List<T>) o;
    }

    private static long num(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v instanceof Number n ? n.longValue() : -1;
    }

    private static Map<String, Object> obj(Object... keyValues) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k < keyValues.length; k += 2) {
            m.put(String.valueOf(keyValues[k]), keyValues[k + 1]);
        }
        return m;
    }

    private static final class Reply {
        int status;
        String body = "";
        final Map<String, String> headers = new LinkedHashMap<>();
    }

    /** One TCP connection to the bridge; the caller decides which headers go on the wire. */
    private static final class Client implements Closeable {
        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;
        final String authority;

        Client(String authority) throws IOException {
            this.authority = authority;
            socket = new Socket("127.0.0.1", Integer.parseInt(authority.substring(authority.indexOf(':') + 1)));
            socket.setSoTimeout(20_000);
            in = socket.getInputStream();
            out = socket.getOutputStream();
        }

        Reply send(String method, String target, String hostHeader, String bearer, String[] extraHeaders, String body,
                   boolean chunked) throws IOException {
            StringBuilder head = new StringBuilder(method).append(' ').append(target).append(" HTTP/1.1\r\nHost: ")
                    .append(hostHeader).append("\r\n");
            if (bearer != null) {
                head.append("Authorization: Bearer ").append(bearer).append("\r\n");
            }
            if (extraHeaders != null) {
                for (String h : extraHeaders) {
                    head.append(h).append("\r\n");
                }
            }
            byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
            if (body != null && chunked) {
                head.append("Transfer-Encoding: chunked\r\n\r\n");
                out.write(head.toString().getBytes(StandardCharsets.UTF_8));
                out.write((Integer.toHexString(bytes.length) + "\r\n").getBytes(StandardCharsets.UTF_8));
                out.write(bytes);
                out.write("\r\n0\r\n\r\n".getBytes(StandardCharsets.UTF_8));
            } else {
                if (body != null) {
                    head.append("Content-Type: application/json\r\n");
                }
                head.append("Content-Length: ").append(bytes.length).append("\r\n\r\n");
                out.write(head.toString().getBytes(StandardCharsets.UTF_8));
                out.write(bytes);
            }
            out.flush();
            return read(!"HEAD".equals(method));
        }

        /** Writes the request head exactly as given; it must end with the blank line. */
        void raw(String head) throws IOException {
            out.write(head.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }

        Reply read() throws IOException {
            return read(true);
        }

        Reply read(boolean expectBody) throws IOException {
            String statusLine = line();
            while (statusLine != null && statusLine.isEmpty()) {
                statusLine = line();                 // a blank line left behind by an interim response
            }
            if (statusLine == null) {
                throw new EOFException("connection closed before a status line");
            }
            String[] parts = statusLine.split(" ", 3);
            Reply r = new Reply();
            r.status = Integer.parseInt(parts[1]);
            for (String h = line(); h != null && !h.isEmpty(); h = line()) {
                int colon = h.indexOf(':');
                if (colon > 0) {
                    r.headers.put(h.substring(0, colon).trim().toLowerCase(Locale.ROOT), h.substring(colon + 1).trim());
                }
            }
            int length = Integer.parseInt(r.headers.getOrDefault("content-length", "0"));
            r.body = expectBody && length > 0 ? new String(in.readNBytes(length), StandardCharsets.UTF_8) : "";
            return r;
        }

        String line() throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            int b = in.read();
            while (b != -1) {
                if (b == '\n') {
                    break;
                }
                if (b != '\r') {
                    buf.write(b);
                }
                b = in.read();
            }
            return b == -1 && buf.size() == 0 ? null : buf.toString(StandardCharsets.UTF_8);
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }
}
