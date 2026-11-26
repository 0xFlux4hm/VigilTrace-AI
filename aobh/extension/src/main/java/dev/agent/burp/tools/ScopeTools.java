package dev.agent.burp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import dev.agent.burp.core.Args;
import dev.agent.burp.core.Tool;
import dev.agent.burp.core.ToolContext;
import dev.agent.burp.json.Json;

/** {@code get_scope}, {@code add_to_scope}, {@code remove_from_scope}: the tools that keep the agent legal. */
public final class ScopeTools {

    /** {@code get_scope}: registry + Burp scope + verdicts for the URLs passed. */
    public static final class Get implements Tool {
        @Override
        public String name() {
            return "get_scope";
        }

        @Override
        public Map<String, Object> handle(ToolContext ctx, Args args) {
            List<String> urls = new ArrayList<>();
            for (String u : args.stringList("check_urls")) {
                urls.add(u.trim());
            }
            return ctx.scope().status(urls);
        }
    }

    /** {@code add_to_scope}: widens Burp scope and the registry, with provenance. */
    public static final class Add implements Tool {
        @Override
        public String name() {
            return "add_to_scope";
        }

        @Override
        public Map<String, Object> handle(ToolContext ctx, Args args) {
            String prefix = args.required("url_prefix");
            String addedFrom = args.required("added_from");
            boolean bootstrapOverride = args.bool("bootstrap_override", false);
            String added = ctx.scope().add(prefix, addedFrom, bootstrapOverride);
            ctx.log("add_to_scope: " + added + " (from: " + addedFrom.trim() + (bootstrapOverride ? ", bootstrap override" : "") + ")");
            return Json.obj(
                    "added", added,
                    "added_from", addedFrom.trim(),
                    "bootstrap_override", bootstrapOverride,
                    "agent_registry", ctx.scope().registry(),
                    "burp_scope_after", ctx.scope().status(List.of(added)).get("burp_scope"),
                    "mismatch_warnings", ctx.scope().status(List.of()).get("mismatch_warnings"),
                    "reminder", "Only test what this prefix and your authorization cover; sub-paths need no separate entry.");
        }
    }

    /** {@code remove_from_scope}: excludes a prefix immediately. */
    public static final class Remove implements Tool {
        @Override
        public String name() {
            return "remove_from_scope";
        }

        @Override
        public Map<String, Object> handle(ToolContext ctx, Args args) {
            String prefix = args.required("url_prefix");
            boolean drop = args.bool("drop_from_registry", false);
            String removed = ctx.scope().remove(prefix, drop);
            ctx.log("remove_from_scope: " + removed + (drop ? " (dropped from the agent registry)" : ""));
            return Json.obj(
                    "removed", removed,
                    "drop_from_registry", drop,
                    "agent_registry", ctx.scope().registry(),
                    "burp_scope_after", ctx.scope().status(List.of(removed)).get("burp_scope"),
                    "gate", "requests under the removed prefix are now refused by the bridge");
        }
    }

    private ScopeTools() {
    }
}
