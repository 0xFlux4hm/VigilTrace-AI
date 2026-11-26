package dev.agent.burp.gateway;

import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.collaborator.DnsDetails;
import burp.api.montoya.collaborator.HttpDetails;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.SecretKey;
import burp.api.montoya.collaborator.SmtpDetails;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.core.Version;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.utilities.CompressionType;
import dev.agent.burp.core.Times;
import dev.agent.burp.core.Urls;

/**
 * The only class in the extension that touches {@code burp.api.montoya.*}. It converts between Montoya objects and
 * the plain {@link Exchange} data the tools work on, and it is the one place where behaviour that the Montoya
 * documentation leaves unsaid is handled defensively instead of assumed:
 * <ul>
 *   <li>{@code sendRequest} gives no contract for an unreachable target, so a missing response, a zero status and a
 *       thrown exception are all treated as "no HTTP response" and Burp's own text is passed through;</li>
 *   <li>the API does not say whether {@code bodyToString()} is content-decoded, so a body that still looks compressed
 *       is decompressed on a best-effort basis and otherwise returned as stored;</li>
 *   <li>{@code HttpRequest.httpRequest(String)} does not document how it derives the service from a raw request, so
 *       raw requests are always paired with an explicit service when the bridge knows the URL, and the URL used for
 *       the scope check is whatever Burp resolved.</li>
 * </ul>
 */
public final class MontoyaGateway implements BurpGateway {
    static final String COLLAB_SECRET_KEY = "collab.secret.v1";
    static final String ISSUE_COUNTER_KEY = "issues.counter";
    /** Written into every issue the bridge raises, so a later listing can recognise its own issues. */
    static final String ISSUE_ID_LINE = "Issue id: ";
    private static final Pattern AGENT_ISSUE_ID = Pattern.compile("Issue id: (agent-issue-\\d+)");
    private static final int INTERACTION_EXCERPT = 400;

    private final MontoyaApi api;
    private final KeyValueStore store;
    private volatile CollaboratorClient collaborator;

    public MontoyaGateway(MontoyaApi api, KeyValueStore store) {
        this.api = api;
        this.store = store;
    }

    @Override
    public String mode() {
        return "burp";
    }

    @Override
    public String productVersion() {
        try {
            Version v = api.burpSuite().version();
            // Version.build()/major()/minor() are deprecated for removal; toString() and the build number are the stable surface.
            return v + " (build " + v.buildNumber() + ")";
        } catch (RuntimeException e) {
            return "Burp Suite (version unavailable)";
        }
    }

    // ---------------------------------------------------------------- scope

    @Override
    public boolean isInScope(String url) {
        return api.scope().isInScope(url);
    }

    @Override
    public void includeInScope(String prefix) {
        api.scope().includeInScope(prefix);
    }

    @Override
    public void excludeFromScope(String prefix) {
        api.scope().excludeFromScope(prefix);
    }

    // ---------------------------------------------------------------- stored traffic

    @Override
    public List<HistoryItem> proxyHistory() {
        List<ProxyHttpRequestResponse> history;
        try {
            history = api.proxy().history();
        } catch (RuntimeException e) {
            throw new GatewayException("could not read the proxy history: " + e.getMessage(), e);
        }
        List<HistoryItem> out = new ArrayList<>(history.size());
        for (ProxyHttpRequestResponse item : history) {
            try {
                out.add(toHistoryItem(item));
            } catch (RuntimeException e) {
                // An entry Burp cannot describe is left out; the agent works with the readable history.
            }
        }
        return out;
    }

    private static HistoryItem toHistoryItem(ProxyHttpRequestResponse item) {
        HistoryItem h = new HistoryItem();
        h.id = item.id();
        ZonedDateTime time = item.time();
        h.time = Times.iso(time);
        h.timeEpochMillis = time == null ? 0L : time.toInstant().toEpochMilli();
        HttpRequest request = item.finalRequest();
        h.method = safeString(request::method);
        h.url = urlOf(request);
        h.host = hostOf(request);
        h.path = safeString(request::path);
        if (item.hasResponse()) {
            HttpResponse response = item.response();
            if (response != null) {
                h.status = response.statusCode();
                h.mimeType = mimeType(response);
                h.responseLength = bodyLength(response);
            }
        }
        h.hasResponse = h.status != 0;
        h.inScope = request.isInScope();
        return h;
    }

    private static String hostOf(HttpRequest request) {
        try {
            HttpService service = request.httpService();
            return service == null ? null : service.host();
        } catch (RuntimeException e) {
            return null;
        }
    }

    @Override
    public Exchange loadProxyItem(int id) {
        List<ProxyHttpRequestResponse> history;
        try {
            history = api.proxy().history();
        } catch (RuntimeException e) {
            throw new GatewayException("could not read the proxy history: " + e.getMessage(), e);
        }
        for (ProxyHttpRequestResponse item : history) {
            if (item.id() == id) {
                return toExchange(item.finalRequest(), item.hasResponse() ? item.response() : null, item.annotations(),
                        item.timingData(), Times.iso(item.time()), item.id());
            }
        }
        return null;
    }

    @Override
    public List<SiteItem> siteMap(String urlPrefix) {
        List<SiteItem> out = new ArrayList<>();
        int index = 0;
        for (HttpRequestResponse rr : siteMapEntries(urlPrefix)) {
            HttpRequest request = rr.request();
            SiteItem s = new SiteItem();
            s.index = index++;
            s.method = safeString(request::method);
            s.url = urlOf(request);
            if (rr.hasResponse()) {
                HttpResponse response = rr.response();
                if (response != null) {
                    s.status = response.statusCode();
                    s.mimeType = mimeType(response);
                    s.responseLength = bodyLength(response);
                }
            }
            s.hasResponse = s.status != 0;
            s.inScope = request.isInScope();
            Set<String> names = new HashSet<>();
            for (ParsedHttpParameter p : request.parameters()) {
                if (p.name() != null && names.add(p.name())) {
                    s.paramNames.add(p.name());
                }
            }
            out.add(s);
        }
        return out;
    }

    @Override
    public Exchange loadSiteMapItem(String url, String method) {
        String wanted = Urls.normalizeUrl(url);
        for (HttpRequestResponse rr : siteMapEntries(null)) {
            HttpRequest request = rr.request();
            String method0 = safeString(request::method);
            if (method0 != null && method0.equalsIgnoreCase(method) && wanted.equals(Urls.normalizeUrl(urlOf(request)))) {
                return toExchange(request, rr.hasResponse() ? rr.response() : null, rr.annotations(),
                        rr.timingData().orElse(null), null, null);
            }
        }
        return null;
    }

    private List<HttpRequestResponse> siteMapEntries(String urlPrefix) {
        try {
            return urlPrefix == null
                    ? api.siteMap().requestResponses()
                    : api.siteMap().requestResponses(SiteMapFilter.prefixFilter(urlPrefix));
        } catch (RuntimeException e) {
            throw new GatewayException("could not read the site map: " + e.getMessage(), e);
        }
    }

    @Override
    public List<IssueRecord> auditIssues(String urlPrefix) {
        List<AuditIssue> issues;
        try {
            issues = urlPrefix == null
                    ? api.siteMap().issues()
                    : api.siteMap().issues(SiteMapFilter.prefixFilter(urlPrefix));
        } catch (RuntimeException e) {
            throw new GatewayException("could not read Burp's issues: " + e.getMessage(), e);
        }
        List<IssueRecord> out = new ArrayList<>(issues.size());
        for (AuditIssue issue : issues) {
            IssueRecord r = new IssueRecord();
            r.name = issue.name();
            r.severity = issue.severity() == null ? null : issue.severity().name();
            r.confidence = issue.confidence() == null ? null : issue.confidence().name();
            r.baseUrl = issue.baseUrl();
            r.host = safeString(() -> issue.httpService() == null ? null : issue.httpService().host());
            r.detail = issue.detail();
            r.remediation = issue.remediation();
            r.evidenceCount = issue.requestResponses() == null ? 0 : issue.requestResponses().size();
            Matcher m = r.detail == null ? null : AGENT_ISSUE_ID.matcher(r.detail);
            if (m != null && m.find()) {
                r.id = m.group(1);
                r.raisedByAgent = true;
            }
            out.add(r);
        }
        return out;
    }

    // ---------------------------------------------------------------- requests

    @Override
    public Exchange parse(String rawRequest, String serviceUrlOrNull) {
        try {
            Exchange ex = new Exchange();
            fillRequest(ex, serviceUrlOrNull == null ? HttpRequest.httpRequest(rawRequest)
                    : HttpRequest.httpRequest(serviceOf(serviceUrlOrNull), rawRequest));
            return ex;
        } catch (MalformedRequestException | IllegalArgumentException | NullPointerException e) {
            throw new GatewayException(describe(e));
        }
    }

    @Override
    public Exchange send(SendSpec spec) {
        HttpRequest request = build(spec);
        RequestOptions options = RequestOptions.requestOptions()
                .withRedirectionMode(redirection(spec.redirectMode))
                .withResponseTimeout(spec.timeoutMs);
        if (spec.http2) {
            options = options.withHttpMode(HttpMode.HTTP_2);
        }
        if (spec.verifyUpstreamTls) {
            options = options.withUpstreamTLSVerification();
        }
        HttpRequestResponse rr;
        try {
            rr = api.http().sendRequest(request, options);
        } catch (RuntimeException e) {
            throw new GatewayException("Burp could not send the request: " + describe(e), e);
        }
        Annotations annotations = Annotations.annotations(spec.note == null ? "" : spec.note, highlight(spec.highlight));
        try {
            rr = rr.withAnnotations(annotations);
            if (spec.addToSiteMap) {
                api.siteMap().add(rr);
            }
        } catch (RuntimeException e) {
            logError("could not annotate or add the exchange to the site map", e);
        }
        TimingData timing = rr.timingData().orElse(null);
        return toExchange(rr.request(), rr.hasResponse() ? rr.response() : null, annotations, timing, null, null);
    }

    /**
     * The request as Burp will see it. A raw request is sent byte-exact; a request given as parts is serialised here,
     * on the wire exactly as the fields say, rather than through Montoya's builder, so no implicit default header
     * ever appears in a request the agent did not ask for.
     */
    private static HttpRequest build(SendSpec spec) {
        try {
            if (spec.rawRequest != null) {
                return spec.url == null
                        ? HttpRequest.httpRequest(spec.rawRequest)
                        : HttpRequest.httpRequest(serviceOf(spec.url), spec.rawRequest);
            }
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
                if (h[0].trim().equalsIgnoreCase("content-length")) {
                    lengthDeclared = true;
                }
                raw.append(h[0].trim().replaceAll("[\r\n]", " ")).append(": ")
                        .append(h[1] == null ? "" : h[1].replaceAll("[\r\n]", " ")).append("\r\n");
            }
            String body = spec.body == null ? "" : spec.body;
            if (!body.isEmpty() && !lengthDeclared) {
                raw.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
            }
            raw.append("\r\n").append(body);
            return HttpRequest.httpRequest(serviceOf(spec.url), raw.toString());
        } catch (MalformedRequestException | IllegalArgumentException e) {
            throw new GatewayException("Burp rejected the request: " + describe(e), e);
        }
    }

    private static HttpService serviceOf(String url) {
        Urls.Parsed p = Urls.parse(url);
        String host = p.host.startsWith("[") ? p.host.substring(1, p.host.length() - 1) : p.host;
        return HttpService.httpService(host, p.port, "https".equals(p.scheme));
    }

    private static RedirectionMode redirection(String mode) {
        switch (mode == null ? SendSpec.REDIRECT_NEVER : mode) {
            case SendSpec.REDIRECT_ALWAYS:
                return RedirectionMode.ALWAYS;
            case SendSpec.REDIRECT_SAME_HOST:
                return RedirectionMode.SAME_HOST;
            case SendSpec.REDIRECT_IN_SCOPE:
                return RedirectionMode.IN_SCOPE;
            default:
                return RedirectionMode.NEVER;
        }
    }

    // ---------------------------------------------------------------- conversion to Exchange

    private static void fillRequest(Exchange ex, HttpRequest request) {
        ex.url = requiredUrl(request);
        ex.method = safeString(request::method);
        ex.requestRaw = request.toString();
        ex.requestBody = bodyLength(request) == 0 ? null : request.bodyToString();
    }

    private Exchange toExchange(HttpRequest request, HttpResponse response, Annotations annotations,
                                TimingData timing, String time, Integer proxyId) {
        Exchange ex = new Exchange();
        fillRequest(ex, request);
        ex.proxyId = proxyId;
        if (response != null) {
            ex.status = response.statusCode();
            ex.reason = safeString(response::reasonPhrase);
            ex.mimeType = mimeType(response);
            for (HttpHeader h : response.headers()) {
                ex.responseHeaders.add(new String[] {h.name(), h.value()});
            }
            ex.responseRaw = response.toString();
            ex.responseBody = responseText(response);
            ex.responseLength = bodyLength(response);
        }
        if (timing != null && timing.timeBetweenRequestSentAndStartOfResponse() != null) {
            ex.latencyMs = timing.timeBetweenRequestSentAndStartOfResponse().toMillis();
        }
        if (timing != null && timing.timeRequestSent() != null && time == null) {
            time = Times.iso(timing.timeRequestSent());
        }
        ex.time = time == null ? Times.now() : time;
        if (annotations != null) {
            if (annotations.hasNotes()) {
                ex.note = annotations.notes();
            }
            ex.highlight = annotations.highlightColor() == null ? null : annotations.highlightColor().name();
        }
        return ex;
    }

    /** The URL Burp resolved for the request; throws {@link MalformedRequestException} when there is none. */
    private static String requiredUrl(HttpRequest request) {
        return request.url();
    }

    /** {@link HttpRequest#url()}, else the service plus path for a request Burp considers malformed. */
    private static String urlOf(HttpRequest request) {
        try {
            return request.url();
        } catch (RuntimeException e) {
            try {
                HttpService service = request.httpService();
                String path = safeString(request::path);
                if (service == null || service.host() == null || path == null) {
                    return null;
                }
                return (service.secure() ? "https://" : "http://") + service.host()
                        + ((service.secure() ? 443 : 80) == service.port() ? "" : ":" + service.port()) + path;
            } catch (RuntimeException inner) {
                return null;
            }
        }
    }

    private static String mimeType(HttpResponse response) {
        try {
            MimeType type = response.mimeType();
            return type == null ? null : type.name();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static int bodyLength(HttpResponse response) {
        try {
            ByteArray body = response.body();
            return body == null ? 0 : body.length();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    private static int bodyLength(HttpRequest request) {
        try {
            ByteArray body = request.body();
            return body == null ? 0 : body.length();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    /**
     * The body as text. When {@code Content-Encoding} says the stored bytes are compressed and the text still looks
     * like binary, the bytes are decompressed through Burp's utilities; anything unexpected keeps the stored text.
     */
    private String responseText(HttpResponse response) {
        String text;
        try {
            text = response.bodyToString();
        } catch (RuntimeException e) {
            return null;
        }
        String encoding;
        try {
            encoding = response.headerValue("Content-Encoding");
        } catch (RuntimeException e) {
            encoding = null;
        }
        CompressionType type = compressionType(encoding);
        if (type == null || !looksBinary(text)) {
            return text;
        }
        try {
            return api.utilities().compressionUtils().decompress(response.body(), type).toString();
        } catch (RuntimeException e) {
            return text;
        }
    }

    private static CompressionType compressionType(String encoding) {
        if (encoding == null) {
            return null;
        }
        switch (encoding.trim().toLowerCase(Locale.ROOT)) {
            case "gzip":
            case "x-gzip":
                return CompressionType.GZIP;
            case "deflate":
                return CompressionType.DEFLATE;
            case "br":
                return CompressionType.BROTLI;
            default:
                return null;
        }
    }

    /** {@code true} when more than an eighth of the characters are C0 controls or undecodable bytes. */
    private static boolean looksBinary(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }
        int odd = 0;
        int end = Math.min(text.length(), 8192);
        for (int k = 0; k < end; k++) {
            char c = text.charAt(k);
            if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == '\uFFFD') {
                odd++;
            }
        }
        return odd * 8 > end;
    }

    // ---------------------------------------------------------------- visibility channels

    private static HttpRequest toHttpRequest(Exchange ex) {
        if (ex.requestRaw == null) {
            throw new GatewayException("the exchange has no raw request text");
        }
        try {
            return ex.url == null || !Urls.isHttpUrl(ex.url)
                    ? HttpRequest.httpRequest(ex.requestRaw)
                    : HttpRequest.httpRequest(serviceOf(ex.url), ex.requestRaw);
        } catch (MalformedRequestException | IllegalArgumentException e) {
            throw new GatewayException("Burp rejected the stored request: " + describe(e), e);
        }
    }

    private static HttpRequestResponse toHttpRequestResponse(Exchange ex) {
        HttpRequest request = toHttpRequest(ex);
        HttpResponse response = null;
        if (ex.responseRaw != null) {
            try {
                response = HttpResponse.httpResponse(ex.responseRaw);
            } catch (RuntimeException e) {
                response = null;
            }
        }
        return HttpRequestResponse.httpRequestResponse(request, response,
                Annotations.annotations(ex.note == null ? "" : ex.note, highlight(ex.highlight)));
    }

    @Override
    public void sendToRepeater(Exchange request, String tabName) {
        api.repeater().sendToRepeater(toHttpRequest(request), tabName);
    }

    @Override
    public void sendToOrganizer(Exchange exchange, String note) {
        if (note != null && !note.isBlank()) {
            exchange.note = exchange.note == null || exchange.note.isBlank() ? note : exchange.note + "\n" + note;
        }
        api.organizer().sendToOrganizer(toHttpRequestResponse(exchange));
    }

    @Override
    public void sendToIntruder(Exchange template, String name) {
        api.intruder().sendToIntruder(toHttpRequest(template), name);
    }

    @Override
    public String raiseIssue(IssueRecord.Input issue) {
        int number = nextIssueNumber();
        String id = "agent-issue-" + number;
        List<HttpRequestResponse> evidence = new ArrayList<>();
        for (Exchange ex : issue.evidence == null ? List.<Exchange>of() : issue.evidence) {
            evidence.add(toHttpRequestResponse(ex));
        }
        AuditIssueSeverity severity = AuditIssueSeverity.valueOf(issue.severity);
        AuditIssue auditIssue = AuditIssue.auditIssue(issue.name, issue.detail + "\n" + ISSUE_ID_LINE + id,
                issue.remediation, issue.baseUrl, severity, AuditIssueConfidence.valueOf(issue.confidence),
                issue.background, issue.remediationBackground, severity, evidence);
        try {
            api.siteMap().add(auditIssue);
        } catch (RuntimeException e) {
            throw new GatewayException("Burp did not register the issue: " + describe(e)
                    + ". Attaching at least one evidence request/response pair usually resolves this.", e);
        }
        api.logging().raiseInfoEvent("AI Agent Bridge registered " + id + " (" + issue.severity + "): " + issue.name);
        return id;
    }

    private synchronized int nextIssueNumber() {
        int next = 1;
        String stored = store.get(ISSUE_COUNTER_KEY);
        if (stored != null && stored.trim().matches("\\d{1,9}")) {
            next = Integer.parseInt(stored.trim()) + 1;
        }
        store.set(ISSUE_COUNTER_KEY, String.valueOf(next));
        return next;
    }

    // ---------------------------------------------------------------- collaborator

    /** One client per project, its secret key persisted so payloads from an earlier session keep polling. */
    private CollaboratorClient collaborator() {
        CollaboratorClient client = collaborator;
        if (client != null) {
            return client;
        }
        synchronized (this) {
            if (collaborator == null) {
                String key = store.get(COLLAB_SECRET_KEY);
                if (key != null && !key.isBlank()) {
                    try {
                        collaborator = api.collaborator().restoreClient(SecretKey.secretKey(key));
                        return collaborator;
                    } catch (RuntimeException e) {
                        logError("stored Collaborator key is not usable; creating a new client", e);
                        store.delete(COLLAB_SECRET_KEY);
                    }
                }
                try {
                    collaborator = api.collaborator().createClient();
                } catch (RuntimeException e) {
                    throw new GatewayException("Burp Collaborator is disabled or unreachable: " + describe(e), e);
                }
                store.set(COLLAB_SECRET_KEY, collaborator.getSecretKey().toString());
            }
            return collaborator;
        }
    }

    @Override
    public CollabPayloadInfo newCollaboratorPayload() {
        CollaboratorPayload payload;
        try {
            payload = collaborator().generatePayload();
        } catch (IllegalStateException e) {
            throw new GatewayException("Burp Collaborator is disabled: " + describe(e), e);
        } catch (RuntimeException e) {
            throw new GatewayException("Collaborator did not generate a payload: " + describe(e), e);
        }
        CollabPayloadInfo info = new CollabPayloadInfo();
        info.payloadId = String.valueOf(payload.id());
        info.payload = payload.toString();
        return info;
    }

    @Override
    public List<InteractionRecord> collaboratorInteractions(String payloadIdOrNull) {
        List<Interaction> interactions;
        try {
            interactions = collaborator().getAllInteractions();
        } catch (RuntimeException e) {
            throw new GatewayException("could not read Collaborator interactions: " + describe(e), e);
        }
        List<InteractionRecord> out = new ArrayList<>();
        for (Interaction interaction : interactions) {
            String id = String.valueOf(interaction.id());
            if (payloadIdOrNull != null && !payloadIdOrNull.equals(id)) {
                continue;
            }
            InteractionRecord r = new InteractionRecord();
            r.payloadId = id;
            r.type = interaction.type() == null ? null : interaction.type().name();
            ZonedDateTime at = interaction.timeStamp();
            r.time = Times.iso(at);
            r.timeEpochMillis = at == null ? 0L : at.toInstant().toEpochMilli();
            r.clientIp = interaction.clientIp() == null ? null : interaction.clientIp().getHostAddress();
            r.clientPort = interaction.clientPort();
            Optional<DnsDetails> dns = interaction.dnsDetails();
            Optional<HttpDetails> http = interaction.httpDetails();
            Optional<SmtpDetails> smtp = interaction.smtpDetails();
            r.detailsAvailable = dns.isPresent() || http.isPresent() || smtp.isPresent();
            if (dns.isPresent()) {
                r.summary = "DNS " + dns.get().queryType() + " " + dns.get().query();
            } else if (http.isPresent()) {
                r.summary = excerpt(http.get().requestResponse().request().toString());
            } else if (smtp.isPresent()) {
                r.summary = excerpt(smtp.get().conversation());
            } else {
                r.summary = r.type + " interaction";
            }
            out.add(r);
        }
        return out;
    }

    private static String excerpt(String text) {
        if (text == null) {
            return null;
        }
        String flat = text.replaceAll("[\\r\\n]+", " | ");
        return flat.length() <= INTERACTION_EXCERPT ? flat : flat.substring(0, INTERACTION_EXCERPT) + "…";
    }

    // ---------------------------------------------------------------- logging

    @Override
    public void log(String message) {
        api.logging().logToOutput("[agent-bridge] " + message);
    }

    @Override
    public void logError(String message, Throwable cause) {
        api.logging().logToError("[agent-bridge] " + message, cause);
    }

    // ---------------------------------------------------------------- helpers

    private static HighlightColor highlight(String name) {
        if (name == null) {
            return HighlightColor.NONE;
        }
        try {
            return HighlightColor.valueOf(name.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return HighlightColor.NONE;
        }
    }

    /** Runs a Montoya accessor; {@code null} when Burp cannot answer it for this message. */
    private static String safeString(Supplier<String> accessor) {
        try {
            return accessor.get();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static String describe(Throwable e) {
        return e.getMessage() == null || e.getMessage().isBlank() ? e.getClass().getSimpleName() : e.getMessage();
    }

    /** {@link KeyValueStore} over the extension's project-persistent storage. */
    public static final class PersistedStore implements KeyValueStore {
        private final PersistedObject data;

        public PersistedStore(PersistedObject data) {
            this.data = data;
        }

        @Override
        public String get(String key) {
            return data.getString(key);
        }

        @Override
        public void set(String key, String value) {
            data.setString(key, value);
        }

        @Override
        public void delete(String key) {
            data.deleteString(key);
        }
    }
}
