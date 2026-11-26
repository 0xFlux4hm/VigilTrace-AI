package dev.agent.burp.tools;

import java.util.Map;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.core.ToolException;
import dev.agent.burp.gateway.Exchange;
import dev.agent.burp.json.Json;

/** {@code create_repeater_tab}: parks a request in a named Repeater tab for the human. Nothing is sent. */
public final class CreateRepeaterTabTool implements Tool {
    @Override
    public String name() {
        return "create_repeater_tab";
    }

    @Override
    public Map<String, Object> handle(ToolContext ctx, Args args) {
        String raw = args.str("raw_request", null);
        Exchange ex;
        Map<String, Object> source;
        if (raw != null && !raw.isBlank()) {
            ex = ctx.parseRaw(raw);
            source = Json.obj("type", "raw", "request_line", ToolSupport.requestPreview(ex, 160));
        } else {
            if (!args.has("source")) {
                throw new ToolException("missing_argument",
                        "Pass either source (proxy id / agent id) or raw_request.");
            }
            ex = ctx.resolveSource(args);
            source = ToolSupport.sourceRef(args);
        }
        String tab = ctx.repeaterTabName(args.str("tab_name", "untitled"));
        String note = args.str("note", null);
        ctx.sendToRepeater(ex, tab);
        return Json.obj(
                "tab_name", tab,
                "note", note,
                "source", source,
                "url", ex.url,
                "request_preview", ToolSupport.requestPreview(ex, 300),
                "sent", false,
                "counted", false);
    }
}
