package dev.agent.burp.gateway;

import java.util.List;

/** An issue already recorded in Burp (scanner or another extension). */
public final class IssueRecord {
    /** Stable id: {@code agent-issue-N} for issues raised through the bridge, {@code bi-<hash>} for scanner issues. */
    public String id;
    public String name;
    /** {@code HIGH | MEDIUM | LOW | INFORMATION | FALSE_POSITIVE} */
    public String severity;
    /** {@code CERTAIN | FIRM | TENTATIVE} */
    public String confidence;
    public String baseUrl;
    public String host;
    public String detail;
    public String remediation;
    public int evidenceCount;
    public boolean raisedByAgent;

    /** An issue to register in Burp. */
    public static final class Input {
        public String name;
        public String detail;
        public String remediation;
        public String baseUrl;
        /** {@code HIGH | MEDIUM | LOW | INFORMATION} */
        public String severity;
        /** {@code CERTAIN | FIRM | TENTATIVE} */
        public String confidence;
        public String background;
        public String remediationBackground;
        public List<Exchange> evidence;
    }

    /** Severity rank for sorting/filtering; lower is more severe. */
    public static int severityRank(String severity) {
        if (severity == null) {
            return 9;
        }
        switch (severity) {
            case "HIGH": return 0;
            case "MEDIUM": return 1;
            case "LOW": return 2;
            case "INFORMATION": return 3;
            default: return 4;
        }
    }

    public static int confidenceRank(String confidence) {
        if (confidence == null) {
            return 9;
        }
        switch (confidence) {
            case "CERTAIN": return 0;
            case "FIRM": return 1;
            case "TENTATIVE": return 2;
            default: return 3;
        }
    }
}
