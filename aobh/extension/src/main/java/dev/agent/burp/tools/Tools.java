package dev.agent.burp.tools;

import java.util.List;

import dev.agent.burp.core.Tool;

/** The bridge's tools, in manifest order. {@code ToolRegistry.create} refuses any mismatch with the embedded manifest. */
public final class Tools {
    private Tools() {
    }

    public static List<Tool> all() {
        return List.of(
                new GetProxyHistoryTool(),
                new GetSiteMapTool(),
                new SearchHistoryTool(),
                new ExtractParametersTool(),
                new SendHttpRequestTool(),
                new ModifyAndResendTool(),
                new GetResponseTool(),
                new CreateRepeaterTabTool(),
                new ScopeTools.Get(),
                new ScopeTools.Add(),
                new ScopeTools.Remove(),
                new RunSimpleFuzzTool(),
                new CollaboratorTools.GetPayload(),
                new CollaboratorTools.Poll(),
                new RaiseIssueTool());
    }
}
