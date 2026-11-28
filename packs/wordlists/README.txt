Wordlists are intentionally NOT bundled here.

For L3 content discovery:  raft-small-files-letters (~8k)      -> your local SecLists copy
For L4 exhaustive runs:    raft-large + extension filtering (~80k)
Permutation word source:   built into recon_permutate (DEFAULT_PERM_WORDS)

Point tools at your local copies, e.g.:
  hunter_fuzz_run(url, mode=path, ...)         # built-in param/path list (60 words)
  python3 - <<'PY' ...                         # custom scripts read wordlists from your SecLists path

Recommended canonical source: https://github.com/danielmiessler/SecLists (download once, store outside this repo).
The recon_policy.wordlists field in mission.json documents which list belongs to which depth.
