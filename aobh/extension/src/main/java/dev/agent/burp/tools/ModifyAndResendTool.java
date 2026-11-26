package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.RawRequest;
import dev.agent.burp.core.Render;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.gateway.SendSpec;
import dev.agent.burp.json.Json;

/**
 * {@code modify_and_resend_request}: baseline-vs-variant testing. The modification list is returned with the
 * response so the variant can be replayed exactly; {@code send_now=false} returns the edited request and a scope
 * verdict without sending or counting anything.
 */
public final class ModifyAndResendTool implements Tool {
    private static final int MAX_RAW_PREVIEW_BYTES = 65_536;

    @Override
    public String name() {
        return "modify_and_resend_request";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        Exchange src = ctx.resolveSource(args);
        String note = args.required("note");
        int maxBytes = ToolSupport.maxBytes(args, "max_bytes", Render.DEFAULT_MAX_BYTES);
        boolean sendNow = args.bool("send_now", true);
        boolean repeater = args.bool("create_repeater_tab", false);

        RawRequest request = RawRequest.parse(src.requestRaw);
        RequestEditor edit = new RequestEditor(request);
        List<String> applied = new ArrayList<>();
        for (String header : args.stringList("remove_headers")) {
            applied.add(edit.removeHeader(header));
        }
        for (String[] header : args.nameValues("set_headers")) {
            applied.add(edit.setHeader(header[0], header[1]));
        }
        for (Map<String, Object> p : args.objectList("set_params")) {
            Args pa = new Args(p);
            applied.add(edit.setParam(pa.required("name"), pa.required("value"),
                    pa.choice("location", "auto", "query", "body", "cookie", "json", "auto")));
        }
        for (String p : args.stringList("remove_params")) {
            applied.add(edit.removeParam(p));
        }
        for (Map<String, Object> replacement : args.objectList("replace_in_body")) {
            Args ra = new Args(replacement);
            applied.add(edit.replaceInBody(ra.required("find"), ra.str("replace_with", ""),
                    ra.integer("max_occurrences", 1, 0, 100_000)));
        }
        for (Map<String, Object> replacement : args.objectList("replace_in_url")) {
            Args ra = new Args(replacement);
            applied.add(edit.replaceInUrl(ra.required("find"), ra.str("replace_with", "")));
        }
        String method = args.str("method", null);
        if (method != null && !method.isBlank()) {
            applied.add(edit.setMethod(method));
        }
        String urlOverride = args.str("url_override", null);
        if (urlOverride != null && !urlOverride.isBlank()) {
            applied.add(edit.setUrl(urlOverride.trim()));
        }

        SendSpec spec = new SendSpec();
        spec.rawRequest = edit.serialize();
        spec.url = urlOverride != null && !urlOverride.isBlank() ? urlOverride.trim() : src.url;
        spec.note = note;

        Map<String, Object> source = ToolSupport.sourceRef(args);
        if (!sendNow) {
            return dryRun(ctx, spec, applied, source, note);
        }

        Exchange ex = ctx.sendAndLog(spec, false, name(), note);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("modifications_applied", applied);
        out.putAll(Render.exchange(ex, maxBytes));
        out.put("source", source);
        Map<String, Object> baseline = new LinkedHashMap<>();
        baseline.put("source", describeSource(src));
        baseline.put("agent_id", src.agentId);
        baseline.put("proxy_id", src.proxyId);
        baseline.put("url", src.url);
        baseline.put("method", src.method);
        baseline.put("status_code", src.status == 0 ? null : src.status);
        baseline.put("response_length", src.responseLength > 0 ? src.responseLength : Render.utf8Length(src.responseBody));
        baseline.put("advice", "This is one variant. A differential finding needs this baseline and the variant under identical "
                + "conditions, repeated cold; compare status, length and the specific body fields with get_response.");
        out.put("baseline_hint", baseline);
        if (repeater) {
            try {
                String tab = ctx.repeaterTabName(note);
                ctx.sendToRepeater(ex, tab);
                out.put("repeater_tab", tab);
            } catch (ToolException e) {
                out.put("repeater_tab_error", e.getMessage());
            }
        }
        return out;
    }

    private static Map<String, Object> dryRun(ToolContext ctx, SendSpec spec, List<String> applied,
                                              Map<String, Object> source, String note) {
        String url = null;
        String verdict;
        try {
            url = ctx.previewUrl(spec);
            verdict = ctx.scopeVerdict(url);
        } catch (ToolException e) {
            verdict = e.getMessage() + " " + e.hint();
        }
        return Json.obj(
                "dry_run", true,
                "sent", false,
                "counted", false,
                "source", source,
                "modifications_applied", applied,
                "modified_request", Render.truncate(spec.rawRequest, MAX_RAW_PREVIEW_BYTES),
                "request_truncated", Render.utf8Length(spec.rawRequest) > MAX_RAW_PREVIEW_BYTES,
                "scope_check", Json.obj("url", url, "in_scope", verdict == null, "reason", verdict),
                "note", note,
                "next_step", "Send the same arguments with send_now=true (remove nothing: the edit is re-applied from the source).");
    }

    private static String describeSource(Exchange src) {
        if (src.agentId != null) {
            return "agent request " + src.agentId;
        }
        if (src.proxyId != null) {
            return "proxy item " + src.proxyId;
        }
        return "the raw source request";
    }
}
