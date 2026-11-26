package dev.agent.burp.bridge;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import dev.agent.burp.core.ToolRegistry;
import dev.agent.burp.json.Json;

/**
 * The local HTTP endpoint of the AI Agent Bridge: {@code GET /health}, {@code GET /tools} and
 * {@code POST /tools/<name>}, all behind the same bearer token.
 *
 * <p>It is written on {@code java.base} sockets alone rather than {@code jdk.httpserver}, so the set of
 * modules Burp's bundled runtime resolves is not something this extension has to care about. Every
 * connection gets its own thread, so {@code /health} stays answerable while a tool call blocks for minutes
 * (a slow fuzz run, a Collaborator poll with {@code wait_seconds}).
 *
 * <p>Hardening, in the order it is applied to every request:
 * <ol>
 *   <li>size limits on the request line, the headers and the body;</li>
 *   <li>a request carrying an {@code Origin} header is refused: a browser made it, and no legitimate
 *       client (the MCP server, curl) ever sends one;</li>
 *   <li>a {@code Host} header that is not a loopback or local address is refused, which closes the
 *       DNS-rebinding route where a public name resolves to 127.0.0.1;</li>
 *   <li>the token is compared through its SHA-256 in constant time, before any route exists for the caller;</li>
 *   <li>no CORS header is ever emitted, responses are {@code no-store} and {@code nosniff}.</li>
 * </ol>
 * Nothing about a request other than method, path, status and duration is ever logged.
 */
public final class BridgeServer {
    public static final int DEFAULT_PORT = 8787;
    public static final String DEFAULT_BIND = "127.0.0.1";
    /** Request bodies larger than this are refused before being read. */
    public static final long MAX_BODY_BYTES = ToolRegistry.MAX_BODY_BYTES;

    private static final int MAX_LINE_BYTES = 16 * 1024;
    private static final int MAX_HEADER_BYTES = 64 * 1024;
    private static final int MAX_HEADERS = 200;
    private static final int IDLE_TIMEOUT_MS = 30_000;
    private static final int BACKLOG = 64;
    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    private static final Pattern IPV6 = Pattern.compile("[0-9a-fA-F:.%]+");

    private final ToolRegistry registry;
    private final String bindAddress;
    private final int requestedPort;
    private final byte[] expectedTokenDigest;
    private final Consumer<String> accessLog;
    private final Set<InetAddress> acceptedHosts = ConcurrentHashMap.newKeySet();
    private final Set<Socket> openSockets = ConcurrentHashMap.newKeySet();
    private final ExecutorService workers;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private volatile boolean running;

    private BridgeServer(ToolRegistry registry, String bindAddress, int port, String token, Consumer<String> accessLog) {
        this.registry = registry;
        this.bindAddress = bindAddress;
        this.requestedPort = port;
        this.expectedTokenDigest = sha256(token);
        this.accessLog = accessLog == null ? line -> {
        } : accessLog;
        AtomicInteger seq = new AtomicInteger();
        this.workers = Executors.newCachedThreadPool(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "agent-bridge-conn-" + seq.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        });
    }

    /**
     * Creates and starts the server.
     *
     * @param registry     the tools and counters this endpoint exposes
     * @param bindAddress  loopback by default; any other address is the operator's explicit decision
     * @param port         0 picks a free port (standalone demo, self-test)
     * @param token        the shared secret every request must present; must not be empty
     * @param accessLog    receives one line per request; may be {@code null}
     */
    public static BridgeServer start(ToolRegistry registry, String bindAddress, int port, String token,
                                     Consumer<String> accessLog) throws IOException {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException(
                    "A bridge without a token would let any local process send requests through Burp; refusing to start.");
        }
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("port must be 0..65535, got " + port);
        }
        BridgeServer server = new BridgeServer(registry, bindAddress == null ? DEFAULT_BIND : bindAddress.trim(), port,
                token, accessLog);
        server.open();
        return server;
    }

    private void open() throws IOException {
        InetAddress bind = InetAddress.getByName(bindAddress);
        collectAcceptedHosts(bind);
        ServerSocket socket = new ServerSocket();
        socket.setReuseAddress(true);
        try {
            socket.bind(new InetSocketAddress(bind, requestedPort), BACKLOG);
        } catch (IOException e) {
            socket.close();
            workers.shutdownNow();
            throw e;
        }
        serverSocket = socket;
        running = true;
        acceptThread = new Thread(this::acceptLoop, "agent-bridge-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
    }

    /** Loopback, the address bound to, and — for a wildcard bind — every address of a local interface. */
    private void collectAcceptedHosts(InetAddress bind) throws IOException {
        acceptedHosts.add(InetAddress.getByName("127.0.0.1"));
        acceptedHosts.add(InetAddress.getByName("::1"));
        acceptedHosts.add(bind);
        if (bind.isAnyLocalAddress()) {
            try {
                for (NetworkInterface nic : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                    acceptedHosts.addAll(Collections.list(nic.getInetAddresses()));
                }
            } catch (SocketException e) {
                // Without the interface list only loopback and the wildcard itself are accepted.
            }
        }
    }

    private void acceptLoop() {
        while (running) {
            Socket client;
            try {
                client = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    accessLog.accept("bridge: accept failed: " + e.getMessage());
                }
                return;
            }
            openSockets.add(client);
            workers.execute(() -> serve(client));
        }
    }

    // ---------------------------------------------------------------- lifecycle

    /** The port actually bound ({@code requestedPort} may have been 0). */
    public int port() {
        return serverSocket.getLocalPort();
    }

    /** {@code http://<bind>:<port>} for logs and the settings tab. */
    public String uri() {
        String host = bindAddress.replace("/", "");
        if (host.contains(":")) {
            host = "[" + host + "]";
        }
        return "http://" + host + ":" + port();
    }

    /** {@code false} when the server can be reached from other machines. */
    public boolean isLoopbackOnly() {
        for (InetAddress a : acceptedHosts) {
            if (!a.isLoopbackAddress()) {
                return false;
            }
        }
        return true;
    }

    /** Stops accepting, closes open connections and interrupts tool calls still running. */
    public void stop() {
        running = false;
        try {
            serverSocket.close();
        } catch (IOException e) {
            // Closing is best effort.
        }
        for (Socket s : openSockets) {
            closeQuietly(s);
        }
        openSockets.clear();
        workers.shutdownNow();
    }

    // ---------------------------------------------------------------- one connection

    private void serve(Socket client) {
        try (client) {
            client.setSoTimeout(IDLE_TIMEOUT_MS);
            client.setTcpNoDelay(true);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            while (running) {
                if (!handleOne(in, out)) {
                    return;
                }
            }
        } catch (SocketTimeoutException idle) {
            // No further request within the idle window: the normal end of a kept-alive connection.
        } catch (IOException e) {
            // The peer went away mid-request; there is nobody to answer to.
        } finally {
            openSockets.remove(client);
        }
    }

    /** Serves one request; returns whether the connection may carry another. Never throws for bad input. */
    private boolean handleOne(InputStream in, OutputStream out) throws IOException {
        long started = System.nanoTime();
        String method = "-";
        String target = "-";
        boolean keepAlive = false;
        Response response;
        try {
            String requestLine = readLine(in, MAX_LINE_BYTES);
            if (requestLine == null) {
                return false;                       // closed by the peer between requests
            }
            if (requestLine.isEmpty()) {
                return true;                        // tolerate a stray CRLF ahead of the request line
            }
            String[] parts = splitRequestLine(requestLine);
            if (parts == null) {
                response = Response.error(400, "bad_request", "Expected 'METHOD /path HTTP/1.1'.");
            } else {
                method = parts[0];
                target = parts[1];
                Map<String, String> headers = readHeaders(in);
                if (headers == null) {
                    response = Response.error(400, "bad_request", "Malformed or oversized request headers.");
                } else {
                    String connection = lower(headers.getOrDefault("connection", ""));
                    keepAlive = "HTTP/1.0".equals(parts[2]) ? connection.contains("keep-alive") : !connection.contains("close");
                    Response refused = enforceClientPolicy(headers);
                    if (refused != null) {
                        response = refused;
                    } else {
                        Response unauthorized = authorize(headers);
                        response = unauthorized != null ? unauthorized : route(method, target, headers, in, out);
                    }
                }
            }
        } catch (BadRequest e) {
            response = Response.error(400, "bad_request", e.getMessage());
        } catch (RequestTooLarge e) {
            response = Response.error(413, "payload_too_large", e.getMessage());
        } catch (IOException e) {
            throw e;
        } catch (RuntimeException e) {
            response = Response.error(500, "internal_error",
                    "The bridge could not process the request: " + e.getClass().getSimpleName());
        }
        keepAlive &= !response.close;
        respond(out, method, response, keepAlive);
        accessLog.accept("bridge: " + method + " " + target + " -> " + response.status() + " ("
                + (System.nanoTime() - started) / 1_000_000 + " ms)");
        return keepAlive;
    }

    /** Refuses what a browser would send. Returns {@code null} when the request may continue. */
    private Response enforceClientPolicy(Map<String, String> headers) {
        if (headers.containsKey("origin")) {
            return Response.error(403, "forbidden",
                    "Requests from a web page are refused: this bridge sends traffic through Burp and is not a browser API.");
        }
        if (!acceptedHost(headers.getOrDefault("host", ""))) {
            return Response.error(403, "forbidden",
                    "The Host header does not name this machine. Use http://127.0.0.1:<port> (this also blocks DNS rebinding).");
        }
        return null;
    }

    private boolean acceptedHost(String hostHeader) {
        if (hostHeader == null || hostHeader.isBlank()) {
            return false;                           // HTTP/1.1 requires a Host header
        }
        String host = hostHeader.trim().toLowerCase(Locale.ROOT);
        if (host.startsWith("[")) {
            int end = host.indexOf(']');
            if (end < 0) {
                return false;
            }
            host = host.substring(0, end + 1);
        } else {
            int colon = host.lastIndexOf(':');
            if (colon >= 0 && host.substring(colon + 1).matches("\\d{1,5}")) {
                host = host.substring(0, colon);
            }
        }
        if (host.isEmpty()) {
            return false;
        }
        if ("localhost".equals(host)) {
            return true;
        }
        // Literal addresses only: no name resolution, so a hostile Host header cannot make the bridge look it up.
        String literal = host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
        boolean ipv4 = IPV4.matcher(literal).matches();
        boolean ipv6 = literal.contains(":") && IPV6.matcher(literal).matches();
        if (!ipv4 && !ipv6) {
            return false;
        }
        try {
            return acceptedHosts.contains(InetAddress.getByName(literal));
        } catch (IOException e) {
            return false;
        }
    }

    /** {@code null} when the request is authorized. The comparison runs over fixed-size digests, so neither the
     *  token's value nor its length is observable through timing. */
    private Response authorize(Map<String, String> headers) {
        String header = headers.getOrDefault("authorization", "");
        String presented = header.regionMatches(true, 0, "bearer ", 0, 7) ? header.substring(7).trim() : "";
        if (presented.isEmpty() || !MessageDigest.isEqual(sha256(presented), expectedTokenDigest)) {
            return Response.error(401, "unauthorized",
                    "Send 'Authorization: Bearer <token>' (the token is shown in the AI Agent Bridge settings tab).", true);
        }
        return null;
    }

    private Response route(String method, String target, Map<String, String> headers, InputStream in, OutputStream out)
            throws IOException {
        String path = target;
        int query = target.indexOf('?');
        if (query >= 0) {
            path = target.substring(0, query);
        }
        boolean read = "GET".equals(method) || "HEAD".equals(method);
        if (!read && !"POST".equals(method)) {
            return Response.error(405, "method_not_allowed", "Use GET /health, GET /tools or POST /tools/<name>.",
                    "Allow", "GET, HEAD, POST");
        }
        if ("/health".equals(path) || "/tools".equals(path)) {
            if (!read) {
                return Response.error(405, "method_not_allowed", path + " is read-only.", "Allow", "GET, HEAD");
            }
            return Response.json(200, "/health".equals(path)
                    ? Json.writePretty(registry.health())
                    : Json.write(registry.manifest()));
        }
        if (!path.startsWith("/tools/")) {
            return Response.error(404, "not_found",
                    "Unknown path '" + path + "'. Endpoints: GET /health, GET /tools, POST /tools/<name>.");
        }
        String name = path.substring("/tools/".length());
        if (read) {
            Map<String, Object> definition = registry.definition(name);
            return definition == null
                    ? Response.error(404, "not_found", "Unknown tool '" + name + "'. GET /tools lists the available tools.")
                    : Response.json(200, Json.write(definition));
        }
        if (name.isEmpty()) {
            return Response.error(404, "not_found", "POST /tools/<name> needs a tool name. GET /tools lists them.");
        }
        String body = readBody(in, out, headers);
        return Response.json(200, registry.dispatch(name, body));
    }

    // ---------------------------------------------------------------- request reading

    /** The request is syntactically broken; answering 400 and closing is the only safe move. */
    private static final class BadRequest extends IOException {
        private static final long serialVersionUID = 1L;

        BadRequest(String message) {
            super(message);
        }
    }

    private static final class RequestTooLarge extends IOException {
        private static final long serialVersionUID = 1L;

        RequestTooLarge(String message) {
            super(message);
        }
    }

    /** One LF- or CRLF-terminated line without its terminator; {@code null} at a clean end of stream. */
    private static String readLine(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                byte[] bytes = buf.toByteArray();
                int len = bytes.length - (bytes.length > 0 && bytes[bytes.length - 1] == '\r' ? 1 : 0);
                return new String(bytes, 0, len, StandardCharsets.UTF_8);
            }
            if (buf.size() >= maxBytes) {
                throw new RequestTooLarge("A request line exceeds " + maxBytes + " bytes.");
            }
            buf.write(b);
        }
        return buf.size() == 0 ? null : new String(buf.toByteArray(), StandardCharsets.UTF_8);
    }

    private static String[] splitRequestLine(String line) {
        String[] parts = line.split(" ");
        if (parts.length != 3 || parts[0].isEmpty() || !parts[1].startsWith("/")) {
            return null;
        }
        return "HTTP/1.1".equals(parts[2]) || "HTTP/1.0".equals(parts[2]) ? parts : null;
    }

    /** Lower-cased header names; {@code null} when the header block is malformed or too large. */
    private static Map<String, String> readHeaders(InputStream in) throws IOException {
        Map<String, String> headers = new HashMap<>();
        int total = 0;
        while (true) {
            String line = readLine(in, MAX_LINE_BYTES);
            if (line == null || headers.size() >= MAX_HEADERS || total > MAX_HEADER_BYTES) {
                return null;
            }
            if (line.isEmpty()) {
                return headers;
            }
            total += line.length() + 2;
            int colon = line.indexOf(':');
            if (colon <= 0) {
                return null;
            }
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            if (name.isEmpty() || name.chars().anyMatch(Character::isWhitespace)) {
                return null;                        // no folded continuations: no room for header smuggling
            }
            String value = line.substring(colon + 1).trim();
            String existing = headers.get(name);
            headers.put(name, existing == null ? value : existing + ", " + value);
        }
    }

    /** Reads a Content-Length or chunked body as UTF-8; {@code ""} when there is none. */
    private static String readBody(InputStream in, OutputStream out, Map<String, String> headers) throws IOException {
        String encoding = lower(headers.getOrDefault("transfer-encoding", ""));
        if (!encoding.isEmpty()) {
            if (!"chunked".equals(encoding)) {
                throw new BadRequest("Only Transfer-Encoding: chunked is supported.");
            }
            return new String(readChunked(in), StandardCharsets.UTF_8);
        }
        String declared = headers.get("content-length");
        if (declared == null) {
            return "";
        }
        if (!declared.trim().matches("\\d{1,19}")) {
            throw new BadRequest("Malformed Content-Length.");
        }
        long length = Long.parseLong(declared.trim());
        if (length > MAX_BODY_BYTES) {
            throw new RequestTooLarge("The request body is larger than the " + (MAX_BODY_BYTES >> 20) + " MiB limit.");
        }
        if (length == 0) {
            return "";
        }
        if ("100-continue".equalsIgnoreCase(headers.getOrDefault("expect", ""))) {
            out.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
        }
        byte[] body = new byte[(int) length];
        int off = 0;
        while (off < body.length) {
            int n = in.read(body, off, body.length - off);
            if (n < 0) {
                throw new BadRequest("The request body ended before Content-Length bytes arrived.");
            }
            off += n;
        }
        return new String(body, StandardCharsets.UTF_8);
    }

    private static byte[] readChunked(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        while (true) {
            String line = readLine(in, 1024);
            if (line == null) {
                throw new BadRequest("The chunked body ended without a terminating chunk.");
            }
            String hex = (line.indexOf(';') >= 0 ? line.substring(0, line.indexOf(';')) : line).trim();
            if (!hex.matches("[0-9a-fA-F]{1,7}")) {
                throw new BadRequest("Malformed chunk size.");
            }
            int size = Integer.parseInt(hex, 16);
            if (size == 0) {
                break;
            }
            if (buf.size() + (long) size > MAX_BODY_BYTES) {
                throw new RequestTooLarge("The request body is larger than the " + (MAX_BODY_BYTES >> 20) + " MiB limit.");
            }
            byte[] chunk = new byte[size];
            int off = 0;
            while (off < size) {
                int n = in.read(chunk, off, size - off);
                if (n < 0) {
                    throw new BadRequest("The chunked body ended inside a chunk.");
                }
                buf.write(chunk, off, n);
                off += n;
            }
            if (!"".equals(readLine(in, 16))) {
                throw new BadRequest("A chunk is not followed by CRLF.");
            }
        }
        while (true) {                               // optional trailers end at an empty line
            String line = readLine(in, MAX_LINE_BYTES);
            if (line == null || line.isEmpty()) {
                break;
            }
        }
        return buf.toByteArray();
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    // ---------------------------------------------------------------- response writing

    /** {@code close} is set on every error response: a request that was not fully read cannot be followed by another. */
    private record Response(int status, byte[] body, Map<String, String> extraHeaders, boolean close) {

        static Response json(int status, String text) {
            return new Response(status, text.getBytes(StandardCharsets.UTF_8), Map.of(), false);
        }

        static Response error(int status, String code, String hint, boolean wwwAuthenticate, String... headerPairs) {
            Map<String, String> extra = new HashMap<>();
            for (int k = 0; k + 1 < headerPairs.length; k += 2) {
                extra.put(headerPairs[k], headerPairs[k + 1]);
            }
            if (wwwAuthenticate) {
                extra.put("WWW-Authenticate", "Bearer realm=\"ai-agent-bridge\"");
            }
            return new Response(status,
                    Json.write(Json.obj("ok", false, "error", code, "hint", hint)).getBytes(StandardCharsets.UTF_8), extra, true);
        }

        static Response error(int status, String code, String hint, String... headerPairs) {
            return error(status, code, hint, false, headerPairs);
        }

        String reason() {
            switch (status) {
                case 200: return "OK";
                case 400: return "Bad Request";
                case 401: return "Unauthorized";
                case 403: return "Forbidden";
                case 404: return "Not Found";
                case 405: return "Method Not Allowed";
                case 413: return "Payload Too Large";
                default: return "Internal Server Error";
            }
        }
    }

    private static void respond(OutputStream out, String method, Response response, boolean keepAlive) throws IOException {
        StringBuilder head = new StringBuilder(320);
        head.append("HTTP/1.1 ").append(response.status()).append(' ').append(response.reason()).append("\r\n");
        head.append("Content-Type: application/json; charset=utf-8\r\n");
        head.append("Content-Length: ").append(response.body().length).append("\r\n");
        head.append("Cache-Control: no-store\r\n");
        head.append("X-Content-Type-Options: nosniff\r\n");
        for (Map.Entry<String, String> h : response.extraHeaders().entrySet()) {
            head.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
        }
        head.append("Connection: ").append(keepAlive ? "keep-alive" : "close").append("\r\n\r\n");
        out.write(head.toString().getBytes(StandardCharsets.UTF_8));
        if (!"HEAD".equals(method)) {
            out.write(response.body());
        }
        out.flush();
    }

    private static byte[] sha256(String text) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException e) {
            // Already gone.
        }
    }
}
