---
description: Scope readout, authorization checks, and the add-prefix flow
agent: orchestrator
---
Handle scope for: $ARGUMENTS

1. Empty args → `get_scope`: print all authorized prefixes + exclusions, explain each in one line.
2. `check <url>` → state the scope verdict and which prefix covers it (or why it is refused).
3. `add <url_prefix> <source>` → `add_to_scope(url_prefix, added_from=source)` — the source must cite the authorization file line or the operator directive. The Python gate and the Java ScopeGuard both enforce it; exclusions always win.
4. If the requested prefix widens scope beyond the program brief, say so explicitly and ask for the authorization reference before adding.
