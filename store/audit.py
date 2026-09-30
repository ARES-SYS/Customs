"""
CUSTOMS Audit Trail — JSONL-based immutable audit log.
Every inbound inspection and outbound verification is recorded.
"""

import json
import collections
from pathlib import Path
from datetime import datetime, timezone


class AuditTrail:
    """Append-only JSONL audit log."""

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, entry: dict):
        entry["_timestamp"] = datetime.now(timezone.utc).isoformat()
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def log_inbound(self, session: str, filepath: str, verdict: str,
                    score: int, signals: list[str] = None):
        self._append({
            "direction": "INBOUND",
            "session": session,
            "filepath": filepath,
            "verdict": verdict,
            "score": score,
            "signals": signals or [],
        })

    def log_outbound(self, session: str, source: str, verdict: str,
                     score: int, violations: list[str] = None):
        self._append({
            "direction": "OUTBOUND",
            "session": session,
            "source": source,
            "verdict": verdict,
            "score": score,
            "violations": violations or [],
        })

    def count(self) -> int:
        if not self.log_path.exists():
            return 0
        with open(self.log_path) as f:
            return sum(1 for _ in f)

    def recent(self, limit: int = 50) -> list[dict]:
        """Fetch recent entries without loading the entire file into memory.
        
        Uses deque(maxlen=limit) as a sliding window — consumes the iterator
        but only keeps the last N items in RAM. Safe for multi-GB audit logs.
        """
        if not self.log_path.exists():
            return []
        with open(self.log_path) as f:
            last_lines = collections.deque(f, maxlen=limit)
        return [json.loads(line) for line in last_lines]

    def search(self, direction: str = None, verdict: str = None,
               limit: int = 50) -> list[dict]:
        """Filter audit entries, returning the MOST RECENT matches first.
        
        Uses fast string pre-filter to avoid JSON parsing overhead on
        non-matching lines, then deque to cap memory usage.
        """
        if not self.log_path.exists():
            return []
        matches = collections.deque(maxlen=limit)
        with open(self.log_path) as f:
            for line in f:
                # Fast string pre-filter — skip JSON parse on misses
                if direction and f'"direction": "{direction}"' not in line:
                    continue
                if verdict and f'"verdict": "{verdict}"' not in line:
                    continue
                entry = json.loads(line)
                if (direction and entry.get("direction") != direction) or \
                   (verdict and entry.get("verdict") != verdict):
                    continue
                matches.append(entry)
        return list(reversed(matches))
