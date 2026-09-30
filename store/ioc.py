"""
CUSTOMS IOC Store — Indicator of Compromise extraction and storage.
SQLite-backed with FTS5 search.
"""

import sqlite3
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


class IOCStore:
    """Persistent IOC database with full-text search."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ioc_type TEXT NOT NULL,
                    ioc_value TEXT NOT NULL,
                    source_file TEXT,
                    source_hash TEXT,
                    risk_score INTEGER,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    times_seen INTEGER DEFAULT 1,
                    notes TEXT,
                    UNIQUE(ioc_type, ioc_value)
                )
            """)
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS iocs_fts USING fts5(
                    ioc_value, source_file, notes, content='iocs', content_rowid='id'
                )
            """)
            # Triggers keep external-content FTS5 in sync with base table.
            # Without these, INSERT/UPDATE/DELETE on iocs leaves the FTS
            # index stale — searches return outdated or missing results.
            conn.executescript("""
                CREATE TRIGGER IF NOT EXISTS iocs_ai AFTER INSERT ON iocs BEGIN
                    INSERT INTO iocs_fts(rowid, ioc_value, source_file, notes)
                    VALUES (new.id, new.ioc_value, new.source_file, new.notes);
                END;
                CREATE TRIGGER IF NOT EXISTS iocs_ad AFTER DELETE ON iocs BEGIN
                    INSERT INTO iocs_fts(iocs_fts, rowid, ioc_value, source_file, notes)
                    VALUES ('delete', old.id, old.ioc_value, old.source_file, old.notes);
                END;
                CREATE TRIGGER IF NOT EXISTS iocs_au AFTER UPDATE ON iocs BEGIN
                    INSERT INTO iocs_fts(iocs_fts, rowid, ioc_value, source_file, notes)
                    VALUES ('delete', old.id, old.ioc_value, old.source_file, old.notes);
                    INSERT INTO iocs_fts(rowid, ioc_value, source_file, notes)
                    VALUES (new.id, new.ioc_value, new.source_file, new.notes);
                END;
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    filepath TEXT NOT NULL,
                    file_hash TEXT,
                    verdict TEXT NOT NULL,
                    score INTEGER,
                    report_json TEXT
                )
            """)
            conn.commit()

    def extract_and_store(self, report: dict) -> list[dict]:
        """Extract IOCs from pipeline report and store them."""
        stored = []
        filepath = report.get("file", "unknown")
        file_hash = ""
        score = report.get("score", 0)

        for stage in report.get("stages", []):
            if stage.get("stage") == "N2_hash":
                file_hash = stage.get("sha256", "")

            if stage.get("stage") == "N16_ioc_extraction":
                iocs = stage.get("iocs", {})

                # Store URLs
                for url in iocs.get("urls", []):
                    stored.append(self._store_ioc("url", url, filepath, file_hash, score))

                # Store IPs
                for ip in iocs.get("ips", []):
                    stored.append(self._store_ioc("ip", ip, filepath, file_hash, score))

            if stage.get("stage") == "N9_strings":
                # Store suspicious string matches as IOCs
                for match in stage.get("suspicious_matches", []):
                    pattern = match.get("pattern", "unknown")
                    value = match.get("match", "")[:200]
                    if value:
                        stored.append(self._store_ioc(
                            f"string:{pattern}", value, filepath, file_hash, score
                        ))

        # Store the pipeline run record
        self._store_run(filepath, file_hash, report)

        return stored

    def _store_ioc(self, ioc_type: str, value: str, source: str,
                   source_hash: str, score: int) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                INSERT INTO iocs (ioc_type, ioc_value, source_file, source_hash,
                                  risk_score, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_type, ioc_value) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    times_seen = times_seen + 1,
                    risk_score = MAX(risk_score, excluded.risk_score)
            """, [ioc_type, value, source, source_hash, score, now, now])
            conn.commit()

            row = conn.execute("SELECT id, times_seen FROM iocs WHERE ioc_type=? AND ioc_value=?",
                               [ioc_type, value]).fetchone()
        return {
            "ioc_type": ioc_type,
            "ioc_value": value[:100],
            "id": row[0] if row else None,
            "times_seen": row[1] if row else 1,
        }

    def _store_run(self, filepath: str, file_hash: str, report: dict):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                INSERT INTO pipeline_runs (timestamp, filepath, file_hash, verdict, score, report_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, [now, filepath, file_hash, report.get("verdict", "UNKNOWN"),
                  report.get("score", 0), json.dumps(report, default=str)])
            conn.commit()

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """FTS5 search across IOCs."""
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute("""
                SELECT i.id, i.ioc_type, i.ioc_value, i.source_file, i.risk_score,
                       i.first_seen, i.last_seen, i.times_seen
                FROM iocs i
                JOIN iocs_fts fts ON i.id = fts.rowid
                WHERE iocs_fts MATCH ?
                ORDER BY i.risk_score DESC
                LIMIT ?
            """, [query, limit]).fetchall()

        return [{
            "id": r[0], "ioc_type": r[1], "ioc_value": r[2],
            "source_file": r[3], "risk_score": r[4],
            "first_seen": r[5], "last_seen": r[6], "times_seen": r[7],
        } for r in rows]

    def count(self) -> int:
        with sqlite3.connect(str(self.db_path)) as conn:
            return conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

    def recent(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute("""
                SELECT ioc_type, ioc_value, risk_score, last_seen, times_seen
                FROM iocs ORDER BY last_seen DESC LIMIT ?
            """, [limit]).fetchall()
        return [{"ioc_type": r[0], "ioc_value": r[1], "risk_score": r[2],
                 "last_seen": r[3], "times_seen": r[4]} for r in rows]

    def top_threats(self, limit: int = 10) -> list[dict]:
        with sqlite3.connect(str(self.db_path)) as conn:
            rows = conn.execute("""
                SELECT ioc_type, ioc_value, risk_score, times_seen, last_seen
                FROM iocs WHERE risk_score >= 50
                ORDER BY risk_score DESC LIMIT ?
            """, [limit]).fetchall()
        return [{"ioc_type": r[0], "ioc_value": r[1], "risk_score": r[2],
                 "times_seen": r[3], "last_seen": r[4]} for r in rows]
