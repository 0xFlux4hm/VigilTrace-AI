# scope.example.md — the operator's authorization contract for one engagement.
# The agent may only widen the registry with prefixes this file covers
# (add_to_scope(url_prefix, added_from="scope.md line N")).
# Anything not listed here is out of scope, full stop. Parsed by
# aobh.core.authz.parse_scope_md: the "in scope" section authorizes; comments
# and the "out of scope" section never do.

## in scope
https://shop.example          # main site + subpaths, all methods
https://api.shop.example/v2   # public API v2

## out of scope
# https://shop.example/admin   # internal, third-party operated
# *.shop.example               # wildcard subdomains NOT authorized
