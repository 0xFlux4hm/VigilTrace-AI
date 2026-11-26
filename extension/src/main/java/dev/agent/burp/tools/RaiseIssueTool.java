package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.core.Urls;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.IssueRecord;
import dev.agent.burp.json.Json;

/**
 * {@code raise_issue}: turns a validated finding into a real Burp issue with the evidence pairs attached. The
 * HIGH/critical evidence rule is enforced here, not left to the skill text.
 */
public final class RaiseIssueTool implements Tool {
    private static final int MAX_TEXT = 60_000;

    @Override
    public String name() {
        return "raise_issue";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        String title = args.required("title");
        String severity = args.choice("severity", null, "critical", "high", "medium", "low", "info");
        String confidence = args.choice("confidence", null, "certain", "firm", "tentative");
        String url = args.required("url");
        Urls.parse(url.trim());
        String description = args.required("description");
        String remediation = args.str("remediation", null);
        String provenance = args.choice("provenance", "agent-validated", "agent-validated", "burp-scanner", "needs-human-review");

        List<Map<String, Object>> evidenceSpec = args.objectList("evidence");
        boolean severe = "critical".equals(severity) || "high".equals(severity);
        if (severe && evidenceSpec.isEmpty()) {
            throw new ToolException("invalid_argument",
                    "severity " + severity + " needs at least one evidence item: evidence=[{\"source\": {\"type\": \"agent\", \"id\": \"a-21\"}, "
                            + "\"step\": \"what this exchange demonstrates\"}]. The pairs are attached to the Burp issue so it stays replayable.");
        }
        List<Exchange> evidence = new ArrayList<>();
        List<String> evidenceLines = new ArrayList<>();
        for (int k = 0; k < evidenceSpec.size(); k++) {
            Args item = new Args(evidenceSpec.get(k));
            Exchange ex = ctx.resolveSource(item);
            String step = item.str("step", "");
            if (step.isBlank()) {
                step = "evidence exchange";
            }
            evidence.add(ex);
            evidenceLines.add("  " + (k + 1) + ". " + step.trim() + "  [" + refOf(ex) + " " + ex.method + " " + ex.url
                    + " -> " + (ex.status == 0 ? "no response" : ex.status) + "]");
        }

        List<String> reproduction = args.stringList("reproduction");
        List<String> references = args.stringList("references");
        String storedSeverity = storedSeverity(severity);
        String storedConfidence = confidence.toUpperCase(java.util.Locale.ROOT);

        StringBuilder detail = new StringBuilder();
        if ("critical".equals(severity)) {
            detail.append("[CRITICAL] Reported severity: CRITICAL. Burp's issue model has no critical level, so it is stored as HIGH.\n\n");
        }
        detail.append(title.trim()).append("\n\n").append(cap(description.trim()));
        if (!evidenceLines.isEmpty()) {
            detail.append("\n\nEvidence:\n").append(String.join("\n", evidenceLines));
        }
        if (!reproduction.isEmpty()) {
            detail.append("\n\nReproduction:\n");
            for (int k = 0; k < reproduction.size(); k++) {
                detail.append("  ").append(k + 1).append(". ").append(cap(reproduction.get(k).trim())).append('\n');
            }
        }
        detail.append("\nProvenance: ").append(provenance);
        if (!references.isEmpty()) {
            detail.append("\nReferences: ").append(cap(String.join("; ", references)));
        }
        detail.append("\nRaised through: AI Agent Bridge");

        IssueRecord.Input issue = new IssueRecord.Input();
        issue.name = title.trim();
        issue.severity = storedSeverity;
        issue.confidence = storedConfidence;
        issue.baseUrl = url.trim();
        issue.detail = cap(detail.toString());
        issue.remediation = remediation == null || remediation.isBlank()
                ? "No remediation text was supplied; confirm the fix with the program's security contact."
                : cap(remediation.trim());
        issue.background = "";
        issue.remediationBackground = "";
        issue.evidence = evidence;
        String issueId = ctx.raiseIssue(issue);

        return Json.obj(
                "issue_id", issueId,
                "url", url.trim(),
                "severity", severity,
                "severity_stored", storedSeverity,
                "confidence_stored", storedConfidence,
                "evidence_attached", evidence.size(),
                "provenance", provenance,
                "report_pointer", "Burp > Target > Issues (issue '" + issueId + "' carries the evidence request/response pairs); "
                        + "report.md finding and validate_finding score should reference " + issueId + ".");
    }

    /** The report's five levels on Burp's four: CRITICAL is stored as HIGH and marked in the detail. */
    static String storedSeverity(String severity) {
        switch (severity) {
            case "critical":
            case "high":
                return "HIGH";
            case "medium":
                return "MEDIUM";
            case "low":
                return "LOW";
            default:
                return "INFORMATION";
        }
    }

    private static String refOf(Exchange ex) {
        if (ex.agentId != null) {
            return ex.agentId;
        }
        return ex.proxyId != null ? "proxy " + ex.proxyId : "raw request";
    }

    private static String cap(String s) {
        return s.length() <= MAX_TEXT ? s : s.substring(0, MAX_TEXT) + " …[cut at " + MAX_TEXT + " characters]";
    }
}
