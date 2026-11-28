"""aobh.tamper — Layer 12: parameter tampering with change observation.

Doctrine: skills/param_tampering.md. The loop is BASELINE → TAMPER (one
variable per probe) → OBSERVE (normalized field-level diff) → ATTRIBUTE →
VERDICT. This package owns the four tamper tools (tamper_matrix_build,
param_tamper_run, res_diff, param_discover); all target-facing HTTP goes
through the Burp bridge like every other group.
"""
