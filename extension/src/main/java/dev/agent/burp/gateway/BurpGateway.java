package dev.agent.burp.gateway;

import java.util.List;

/**
 * The seam between the bridge and Burp. Everything in {@code core}, {@code tools} and {@code bridge} is plain Java
 * that only sees this interface and the data classes next to it; {@code MontoyaGateway} is the single implementation
 * that touches {@code burp.api.montoya.*}. A fake implementation ({@code standalone.FakeBurpGateway}) drives the
 * self-test and the standalone demo on a plain JVM.
 */
public interface BurpGateway {
    /** {@code "burp"} or {@code "standalone"}. */
    String mode();

    /** Burp version string in Burp mode; a label in standalone mode. */
    String productVersion();

    // ---------------------------------------------------------------- scope

    boolean isInScope(String url);

    void includeInScope(String prefix);

    void excludeFromScope(String prefix);

    // ---------------------------------------------------------------- stored traffic (no network)

    /** Proxy history, oldest first. Metadata only. */
    List<HistoryItem> proxyHistory();

    /** Full exchange for a proxy history id, or {@code null}. */
    Exchange loadProxyItem(int id);

    /** Site map entries. Metadata only. {@code urlPrefix} may be null for everything. */
    List<SiteItem> siteMap(String urlPrefix);

    /** A site map exchange for {@code url} + {@code method}, or {@code null}. */
    Exchange loadSiteMapItem(String url, String method);

    /** Issues recorded in Burp; {@code urlPrefix} may be null. */
    List<IssueRecord> auditIssues(String urlPrefix);

    // ---------------------------------------------------------------- requests

    /** Resolves the request's URL and service the way Burp would, without sending anything. */
    Exchange parse(String rawRequest, String serviceUrlOrNull);

    /** Sends the request. Callers must go through {@code ToolContext.send} so the send is counted. */
    Exchange send(SendSpec spec);

    // ---------------------------------------------------------------- visibility channels (no target traffic)

    void sendToRepeater(Exchange request, String tabName);

    void sendToOrganizer(Exchange exchange, String note);

    void sendToIntruder(Exchange template, String name);

    /** Registers the issue in Burp's site map and returns an id. */
    String raiseIssue(IssueRecord.Input issue);

    // ---------------------------------------------------------------- collaborator

    CollabPayloadInfo newCollaboratorPayload();

    /** Interactions for one payload id, or for all payloads of this extension's client when {@code null}. */
    List<InteractionRecord> collaboratorInteractions(String payloadIdOrNull);

    // ---------------------------------------------------------------- logging

    void log(String message);

    void logError(String message, Throwable cause);
}
