#!/usr/bin/env python3
"""memory.py — TargetMemory: durable quirks/intel/failures across sessions.

Split out of the proven mission_core.py unchanged. The point of target memory:
a fresh session inherits everything the hunt learned, so re-work never happens.

  * save()    — one specific fact (kind: quirk | intel | failure | decision |
                preference); the engine validates the kind and raises MissionError
  * search()  — recall by free-text query, kind or tag; tags matching the whole
                query score +3 each, tokens score per occurrence in
                text+tags; ties break on created_at and the list is returned
                newest-first (an empty query returns the most recent items)

All persistence is the store's (memory.json).
"""
from __future__ import annotations

MEMORY_KINDS = ("quirk", "intel", "failure", "decision", "preference")


class TargetMemory:
    """Save + scored recall over the store's memory list."""

    def __init__(self, store):
        self.store = store

    def save(self, kind: str, text: str, tags: list[str] | None = None,
             refs: list[str] | None = None, endpoint: str = "") -> dict:
        return self.store.add_memory({"kind": kind, "text": text, "tags": tags or [],
                                      "refs": refs or [], "endpoint": endpoint})

    def search(self, query: str = "", kind: str = "", tag: str = "",
               limit: int = 10) -> tuple[list[dict], int]:
        """Returns (matches, total_memories). matches is newest-first, scored."""
        items = self.store.memory()
        scored = []
        tokens = [t for t in query.lower().split() if t]
        for m in items:
            if kind and m["kind"] != kind:
                continue
            if tag and tag not in m["tags"]:
                continue
            hay = (m["text"] + " " + " ".join(m["tags"])).lower()
            score = sum(3 for tg in m["tags"] if tg.lower() in query.lower()) if query else 0
            score += sum(hay.count(tok) for tok in tokens)
            scored.append((score, m))
        scored.sort(key=lambda s: (-s[0], s[1]["created_at"]))
        matches = [m for _, m in scored][:max(1, min(limit, 50))]
        return list(reversed(matches)), len(items)
