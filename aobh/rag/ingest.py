"""ingest.py — normalize the reddelexc/hackerone-reports CSV into the RAG cache.

Ported 1:1 from autonomous-bug-hunter/rag/ingest_reports.py (names and
behavior unchanged).

Usage:
    python -m aobh.rag.ingest <path-to-data.csv> [output.jsonl]

Reads columns: program,title,link,upvotes,bounty,vuln_type
  * strips junk, normalizes empty vuln_type -> "Unspecified"
  * parses upvotes (int) and bounty (float), tolerant of blanks
  * dedupes by report link, keeps first occurrence
  * writes one JSON object per line (the cache store.py loads at startup;
    default output is the sibling index/ directory of the CSV)
  * prints corpus statistics so you can sanity-check the ingest

Run it after every dataset refresh (the upstream repo updates periodically):
    python -m aobh.rag.ingest aobh/rag/data/hackerone_reports.csv
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

VALID_TYPES = Counter()


def normalize_row(row: dict) -> dict | None:
    program = (row.get("program") or "").strip()
    title = (row.get("title") or "").strip()
    link = (row.get("link") or "").strip()
    if not title or not link:
        return None
    upvotes_raw = str(row.get("upvotes") or "").strip()
    bounty_raw = str(row.get("bounty") or "").strip()
    try:
        upvotes = int(float(upvotes_raw)) if upvotes_raw else 0
    except ValueError:
        upvotes = 0
    try:
        bounty = float(bounty_raw) if bounty_raw else 0.0
    except ValueError:
        bounty = 0.0
    vuln_type = (row.get("vuln_type") or "").strip() or "Unspecified"
    VALID_TYPES[vuln_type] += 1
    return {
        "program": program,
        "title": title,
        "link": link,
        "upvotes": max(upvotes, 0),
        "bounty": max(bounty, 0.0),
        "vuln_type": vuln_type,
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else src.parent.parent / "index" / "reports.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)

    seen, records, skipped = set(), [], 0
    with src.open(encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            rec = normalize_row(row)
            if rec is None:
                skipped += 1
                continue
            if rec["link"] in seen:
                continue
            seen.add(rec["link"])
            records.append(rec)

    with out.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    paid = [r for r in records if r["bounty"] > 0]
    types = Counter(r["vuln_type"] for r in records)
    print(f"ingested {len(records)} unique reports -> {out}  (skipped {skipped} malformed/duplicate rows)")
    print(f"programs: {len(set(r['program'] for r in records))} | vuln types: {len(types)}")
    print(f"paid reports: {len(paid)} | max bounty: ${max((r['bounty'] for r in records), default=0):,.0f}")
    print("top 10 vuln types:")
    for vt, n in types.most_common(10):
        print(f"  {n:6,}  {vt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
