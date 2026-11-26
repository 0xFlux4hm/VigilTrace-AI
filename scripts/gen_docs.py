#!/usr/bin/env python3
"""Generate docs/02-tools.md from aobh/tools/tools.json (single source of
truth). Run via `make docs` or scripts/gen_docs.py."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "aobh" / "tools" / "tools.json"
OUT = ROOT / "docs" / "02-tools.md"


def first_sentence(text: str, limit: int = 150) -> str:
    m = re.match(r"(.+?\.)", text or "", re.S)
    s = (m.group(1) if m else text or "").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def main() -> int:
    doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    meta = doc["meta"]
    lines = [
        "# AOBH tool surface (48 tools)",
        "",
        f"Generated from `aobh/tools/tools.json` v{meta.get('version', '1.0.0')} — the source of truth.",
        "Six groups; every tool keeps the JSON Schema of the proven implementation it wraps.",
        "Folded tools are listed at the bottom.",
        "",
    ]
    for group, count in meta["groups"].items():
        lines += [f"## {group} ({count})", "", "| Tool | Summary | Required args |", "|---|---|---|"]
        for t in doc["tools"]:
            if t["group"] != group:
                continue
            req = ", ".join(t.get("inputSchema", {}).get("required", [])) or "—"
            lines.append(f"| `{t['name']}` | {first_sentence(t.get('description', ''))} | {req} |")
        lines.append("")
    folding = meta.get("folding", {})
    if folding:
        lines += ["## Folded tools (capability preserved, not exposed separately)", ""]
        for old_name, where in folding.items():
            lines.append(f"- `{old_name}` → {where}")
        lines.append("")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"docs/02-tools.md: {len(doc['tools'])} tools, {len(lines)} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
