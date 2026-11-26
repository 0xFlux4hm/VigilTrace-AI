package dev.agent.burp.core;

/** A tool-level failure: {@code error} is a stable machine-readable code, {@code hint} tells the agent what to do next. */
public final class ToolException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public static final String OUT_OF_SCOPE = "out_of_scope";

    private final String hint;

    public ToolException(String error, String hint) {
        super(error);
        this.hint = hint == null ? "" : hint;
    }

    public String hint() {
        return hint;
    }
}
