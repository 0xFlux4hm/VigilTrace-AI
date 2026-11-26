package dev.agent.burp.core;

/** The three scope operations the guard needs; implemented by the Montoya gateway and by test doubles. */
public interface ScopeBackend {
    boolean isInScope(String url);

    void include(String prefix);

    void exclude(String prefix);
}
