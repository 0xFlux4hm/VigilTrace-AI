"""aobh.waf — WAF/CDN fingerprinting, inert probe battery, ranked normalization
transforms and budgeted bypass testing (ported from the proven waf/waf_core.py).

All target-facing HTTP goes through aobh.core.bridge.BridgeClient; budgets are
per host per engagement (waf_state.json in the engagement dir). Tool handlers
live in tools.py (`register()`), the schemas come from aobh/tools/tools.json.
"""
