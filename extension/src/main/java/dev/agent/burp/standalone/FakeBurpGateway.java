package dev.agent.burp.standalone;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import dev.agent.burp.core.Times;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.Urls;
import dev.agent.burp.gateway.BurpGateway;
import dev.agent.burp.gateway.CollabPayloadInfo;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.GatewayException;
import dev.agent.burp.gateway.HistoryItem;
import dev.agent.burp.gateway.InteractionRecord;
import dev.agent.burp.gateway.IssueRecord;
import dev.agent.burp.gateway.SendSpec;
import dev.agent.burp.gateway.SiteItem;

/**
 * An in-memory stand-in for Burp: no network, no Montoya. It drives the self-test and the {@code --demo} mode on a
 * plain JVM. Every request handed to {@link #send} is recorded and answered by a configurable {@link Responder},
 * so tests can assert on exactly what would have left the bridge.
 *
 * <p>URL resolution mirrors what the bridge relies on Burp for: an explicit service URL wins; otherwise the Host
 * header names the host and port (https when the port is 443, else http); an absolute-form request target is
 * resolved from itself. This is the documented behaviour of the fake, not a claim about Burp's internals.
 */
public final class FakeBurpGateway implements BurpGateway {
    /** Produces the raw response text for a request, or {@code null} for "no response". */
    @FunctionalInterface
    public interface Responder {
        String respond(SendSpec spec, String url);
    }

    public final List<SendSpec> sent = new CopyOnWriteArrayList<>();
    public final List<String> repeaterTabs = new CopyOnWriteArrayList<>();
    public final List<String> organizer = new CopyOnWriteArrayList<>();
    public final List<String> intruder = new CopyOnWriteArrayList<>();
    public final List<IssueRecord> issues = new CopyOnWriteArrayList<>();
    public final List<String> logLines = new CopyOnWriteArrayList<>();
    public volatile Responder responder = FakeBurpGateway::echoResponse;
    public volatile boolean failSends;
    public volatile long sendDelayMs;
    public volatile boolean collaboratorEnabled = true;
    public volatile String productVersion = "standalone-fake 1.5";

    private final Map<Integer, Exchange> proxy = new LinkedHashMap<>();
    private final List<Exchange> site = new ArrayList<>();
    private final List<String> scopePrefixes = new ArrayList<>();
    private final List<String> excludedPrefixes = new ArrayList<>();
    private final Map<String, List<InteractionRecord>> interactions = new ConcurrentHashMap<>();
    private final List<String> payloads = new ArrayList<>();
    private int proxySeq = 100;
    private int issueSeq;
    private long payloadSeq = System.nanoTime() & 0xffff;

    // ---------------------------------------------------------------- seeding

    /** Registers an exchange as a proxy history entry. */
    public synchronized FakeBurpGateway addProxyItem(Exchange ex) {
        if (ex.proxyId == null) {
            ex.proxyId = ++proxySeq;
        }
        if (ex.time == null) {
            ex.time = Times.now();
        }
        proxy.put(ex.proxyId, ex);
        return this;
    }

    public synchronized FakeBurpGateway addSiteMapItem(Exchange ex) {
        site.add(ex);
        return this;
    }

    /** Records an interaction for a payload, as a Collaborator poll would later return it. */
    public FakeBurpGateway addInteraction(String payloadId, String type, String summary) {
        InteractionRecord r = new InteractionRecord();
        r.payloadId = payloadId;
        r.type = type;
        r.time = Times.now();
        r.timeEpochMillis = Instant.now().toEpochMilli();
        r.clientIp = "203.0.113.7";
        r.clientPort = 51000 + (int) (System.nanoTime() % 1000);
        r.summary = summary;
        r.detailsAvailable = true;
        interactions.computeIfAbsent(payloadId, k -> new CopyOnWriteArrayList<>()).add(r);
        return this;
    }

    // ---------------------------------------------------------------- identity

    @Override
    public String mode() {
        return "standalone";
    }

    @Override
    public String productVersion() {
        return productVersion;
    }

    // ---------------------------------------------------------------- scope

    @Override
    public boolean isInScope(String url) {
        for (String prefix : excludedPrefixes) {
            if (Urls.covers(prefix, url)) {
                return false;
            }
        }
        for (String prefix : scopePrefixes) {
            if (Urls.covers(prefix, url)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void includeInScope(String prefix) {
        scopePrefixes.add(normalize(prefix));
    }

    @Override
    public void excludeFromScope(String prefix) {
        excludedPrefixes.add(normalize(prefix));
    }

    private static String normalize(String prefix) {
        try {
            return Urls.normalizePrefix(prefix);
        } catch (ToolException e) {
            throw new GatewayException(e.getMessage());
        }
    }

    // ---------------------------------------------------------------- stored traffic

    @Override
    public synchronized List<HistoryItem> proxyHistory() {
        List<HistoryItem> out = new ArrayList<>();
        for (Exchange ex : proxy.values()) {
            HistoryItem h = new HistoryItem();
            h.id = ex.proxyId;
            h.time = ex.time;
            try {
                h.timeEpochMillis = Times.parse(ex.time, "time").toEpochMilli();
            } catch (RuntimeException e) {
                h.timeEpochMillis = 0L;
            }
            h.method = ex.method;
            h.url = ex.url;
            h.host = ex.url == null ? null : Urls.hostOf(ex.url);
            h.path = ex.url == null ? null : Urls.parse(ex.url).rest;
            h.status = ex.status;
            h.hasResponse = ex.hasResponse();
            h.mimeType = ex.mimeType;
            h.responseLength = ex.responseLength;
            h.inScope = ex.url != null && isInScope(ex.url);
            out.add(h);
        }
        return out;
    }

    @Override
    public synchronized Exchange loadProxyItem(int id) {
        return proxy.get(id);
    }

    @Override
    public synchronized List<SiteItem> siteMap(String urlPrefix) {
        List<SiteItem> out = new ArrayList<>();
        for (Exchange ex : site) {
            if (urlPrefix != null && (ex.url == null || !Urls.covers(normalize(urlPrefix), ex.url))) {
                continue;
            }
            SiteItem s = new SiteItem();
            s.index = out.size();
            s.method = ex.method;
            s.url = ex.url;
            s.status = ex.status;
            s.hasResponse = ex.hasResponse();
            s.mimeType = ex.mimeType;
            s.responseLength = ex.responseLength;
            s.inScope = ex.url != null && isInScope(ex.url);
            out.add(s);
        }
        return out;
    }

    @Override
    public synchronized Exchange loadSiteMapItem(String url, String method) {
        String wanted = Urls.normalizeUrl(url);
        for (Exchange ex : site) {
            if (ex.method != null && ex.method.equalsIgnoreCase(method) && ex.url != null
                    && wanted.equals(Urls.normalizeUrl(ex.url))) {
                return ex;
            }
        }
        return null;
    }

    @Override
    public synchronized List<IssueRecord> auditIssues(String urlPrefix) {
        List<IssueRecord> out = new ArrayList<>();
        for (IssueRecord issue : issues) {
            if (urlPrefix == null || urlPrefix.isBlank() || issue.baseUrl != null
                    && Urls.covers(normalize(urlPrefix), issue.baseUrl)) {
                out.add(issue);
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- requests

    @Override
    public Exchange parse(String rawRequest, String serviceUrlOrNull) {
        return resolve(parseRequestLine(rawRequest), rawRequest, serviceUrlOrNull);
    }

    @Override
    public Exchange send(SendSpec spec) {
        sent.add(spec);
        if (sendDelayMs > 0) {
            try {
                Thread.sleep(sendDelayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new GatewayException("interrupted");
            }
        }
        if (failSends) {
            throw new GatewayException("simulated send failure");
        }
        String raw = spec.rawRequest != null ? spec.rawRequest : serialize(spec);
        Exchange ex = resolve(parseRequestLine(raw), raw, spec.url);
        if (spec.addToSiteMap) {
            synchronized (this) {
                site.add(ex);
            }
        }
        String rawResponse = responder.respond(spec, ex.url);
        if (rawResponse != null) {
            fillResponse(ex, rawResponse);
        }
        return ex;
    }

    /** The same wire format {@code MontoyaGateway} produces for a request given as parts. */
    public static String serialize(SendSpec spec) {
        Urls.Parsed p = Urls.parse(spec.url);
        String rest = p.rest;
        int fragment = rest.indexOf('#');
        if (fragment >= 0) {
            rest = rest.substring(0, fragment);
        }
        StringBuilder raw = new StringBuilder(256);
        raw.append(spec.method).append(' ').append(rest.isEmpty() ? "/" : rest).append(" HTTP/1.1\r\n");
        raw.append("Host: ").append(p.port == Urls.defaultPort(p.scheme) ? p.host : p.host + ":" + p.port).append("\r\n");
        boolean lengthDeclared = false;
        for (String[] h : spec.headers) {
            if (h[0] == null || h[0].isBlank()) {
                continue;
            }
            lengthDeclared |= h[0].trim().equalsIgnoreCase("content-length");
            raw.append(h[0].trim().replaceAll("[\r\n]", " ")).append(": ")
                    .append(h[1] == null ? "" : h[1].replaceAll("[\r\n]", " ")).append("\r\n");
        }
        String body = spec.body == null ? "" : spec.body;
        if (!body.isEmpty() && !lengthDeclared) {
            raw.append("Content-Length: ").append(body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length).append("\r\n");
        }
        return raw.append("\r\n").append(body).toString();
    }

    /** {@code [method, target]} of the request line. */
    public static String[] parseRequestLine(String raw) {
        if (raw == null) {
            throw new GatewayException("empty request");
        }
        int eol = raw.indexOf('\n');
        String line = (eol < 0 ? raw : raw.substring(0, eol)).trim();
        String[] parts = line.split(" ");
        if (parts.length != 3 || parts[0].isEmpty() || !parts[1].startsWith("/") && !parts[1].contains("://")) {
            throw new GatewayException("malformed request line: '" + line + "'");
        }
        return new String[] {parts[0], parts[1]};
    }

    private static Exchange resolve(String[] requestLine, String raw, String serviceUrl) {
        Exchange ex = new Exchange();
        ex.requestRaw = raw;
        ex.method = requestLine[0];
        ex.requestBody = bodyOf(raw);
        String target = requestLine[1];
        String scheme = null;
        String host = null;
        int port = -1;
        if (serviceUrl != null) {
            Urls.Parsed s = Urls.parse(serviceUrl);
            scheme = s.scheme;
            host = s.host;
            port = s.port;
        } else if (target.contains("://")) {
            Urls.Parsed a = Urls.parse(target);
            scheme = a.scheme;
            host = a.host;
            port = a.port;
            target = a.rest.isEmpty() ? "/" : a.rest;
        } else {
            String header = header(raw, "Host");
            if (header == null || header.isBlank()) {
                throw new GatewayException("the request has no Host header, so there is no destination");
            }
            header = header.trim();
            int explicitPort = -1;
            if (header.startsWith("[")) {
                int end = header.indexOf(']');
                if (end < 0) {
                    throw new GatewayException("malformed Host header");
                }
                host = header.substring(0, end + 1);
                if (header.length() > end + 1 && header.charAt(end + 1) == ':') {
                    explicitPort = Integer.parseInt(header.substring(end + 2));
                }
            } else {
                int colon = header.lastIndexOf(':');
                if (colon >= 0) {
                    host = header.substring(0, colon).toLowerCase(Locale.ROOT);
                    explicitPort = Integer.parseInt(header.substring(colon + 1));
                } else {
                    host = header.toLowerCase(Locale.ROOT);
                }
            }
            scheme = explicitPort == 443 ? "https" : "http";
            port = explicitPort;
        }
        if (port < 0) {
            port = Urls.defaultPort(scheme);
        }
        boolean defaultPort = port == Urls.defaultPort(scheme);
        ex.url = scheme + "://" + host + (defaultPort ? "" : ":" + port) + (target.isEmpty() ? "/" : target);
        return ex;
    }

    private static String header(String raw, String name) {
        int end = raw.indexOf("\r\n\r\n");
        String head = end < 0 ? raw : raw.substring(0, end);
        for (String line : head.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private static String bodyOf(String raw) {
        int cut = raw.indexOf("\r\n\r\n");
        if (cut < 0) {
            return null;
        }
        String body = raw.substring(cut + 4);
        return body.isEmpty() ? null : body;
    }

    private static void fillResponse(Exchange ex, String raw) {
        int cut = raw.indexOf("\r\n\r\n");
        String head = cut < 0 ? raw : raw.substring(0, cut);
        String[] lines = head.split("\r\n");
        String[] statusLine = lines[0].split(" ", 3);
        ex.status = Integer.parseInt(statusLine[1]);
        ex.reason = statusLine.length > 2 ? statusLine[2] : "";
        for (int k = 1; k < lines.length; k++) {
            int colon = lines[k].indexOf(':');
            ex.responseHeaders.add(new String[] {lines[k].substring(0, colon).trim(), lines[k].substring(colon + 1).trim()});
        }
        ex.responseBody = cut < 0 ? "" : raw.substring(cut + 4);
        ex.responseRaw = raw;
        ex.responseLength = ex.responseBody.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        ex.latencyMs = 1L;
        ex.time = Times.now();
        for (String[] h : ex.responseHeaders) {
            if ("Content-Type".equalsIgnoreCase(h[0]) && h[1].toLowerCase(Locale.ROOT).contains("json")) {
                ex.mimeType = "JSON";
            }
        }
    }

    /** The default responder: JSON echoing the request target and body, so payloads are visible in the response. */
    public static String echoResponse(SendSpec spec, String url) {
        String[] line = parseRequestLine(spec.rawRequest != null ? spec.rawRequest : serialize(spec));
        String body = "{\"ok\": true, \"target\": \"" + line[1].replace("\\", "\\\\").replace("\"", "\\\"")
                + "\", \"host\": \"" + url + "\"}";
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Demo: standalone\r\nContent-Length: "
                + body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length + "\r\n\r\n" + body;
    }

    // ---------------------------------------------------------------- visibility channels

    @Override
    public void sendToRepeater(Exchange request, String tabName) {
        repeaterTabs.add(tabName);
    }

    @Override
    public void sendToOrganizer(Exchange exchange, String note) {
        organizer.add(note == null ? "" : note);
    }

    @Override
    public void sendToIntruder(Exchange template, String name) {
        intruder.add(name);
    }

    @Override
    public synchronized String raiseIssue(IssueRecord.Input issue) {
        String id = "agent-issue-" + (++issueSeq);
        IssueRecord r = new IssueRecord();
        r.id = id;
        r.name = issue.name;
        r.severity = issue.severity;
        r.confidence = issue.confidence;
        r.baseUrl = issue.baseUrl;
        r.host = Urls.hostOf(issue.baseUrl);
        r.detail = issue.detail;
        r.remediation = issue.remediation;
        r.evidenceCount = issue.evidence == null ? 0 : issue.evidence.size();
        r.raisedByAgent = true;
        issues.add(r);
        return id;
    }

    // ---------------------------------------------------------------- collaborator

    @Override
    public synchronized CollabPayloadInfo newCollaboratorPayload() {
        if (!collaboratorEnabled) {
            throw new GatewayException("Collaborator is disabled in the fake gateway");
        }
        String label = String.format("%013x", payloadSeq++ & 0xfffffffffffffL);
        CollabPayloadInfo info = new CollabPayloadInfo();
        info.payload = label + ".oast.example";
        info.payloadId = info.payload;
        payloads.add(info.payloadId);
        return info;
    }

    @Override
    public List<InteractionRecord> collaboratorInteractions(String payloadIdOrNull) {
        List<InteractionRecord> out = new ArrayList<>();
        for (Map.Entry<String, List<InteractionRecord>> e : interactions.entrySet()) {
            if (payloadIdOrNull == null || payloadIdOrNull.equals(e.getKey())) {
                out.addAll(e.getValue());
            }
        }
        out.sort((a, b) -> Long.compare(a.timeEpochMillis, b.timeEpochMillis));
        return out;
    }

    // ---------------------------------------------------------------- logging

    @Override
    public void log(String message) {
        logLines.add(message);
        System.out.println("[fake-burp] " + message);
    }

    @Override
    public void logError(String message, Throwable cause) {
        logLines.add("ERROR " + message);
        System.err.println("[fake-burp] ERROR " + message);
    }
}
