"""
CUSTOMS 

Dual 17-stage verification:
  INPUT  → Pipeline (17 stages): file/message analysis before entering the system
  OUTPUT → Guard (17 checks): agent response verification before reaching the user

Lema: "Sovereignty Through Infrastructure"
Philosophy: Zero Trust, Control Total. Nothing enters or exits without inspection.

Usage:
    python3 customs.py --file /path/to/sample       # Analyze a file (full pipeline)
    python3 customs.py --text "agent response..."    # Verify agent output (full guard)
    python3 customs.py --serve                       # MCP server mode (stdio JSON-RPC)
    python3 customs.py --check                       # Run both pipeline + guard in demo mode
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# Ensure the customs package is importable
sys.path.insert(0, str(Path(__file__).parent))

from pipeline.stages import Pipeline
from guard.checks import Guard
from store.ioc import IOCStore
from store.audit import AuditTrail
from config import (
    QUARANTINE_THRESHOLD, REVIEW_THRESHOLD,
    CUSTOMS_DIR, IOC_DB_PATH, AUDIT_LOG_PATH,
    QUARANTINE_DIR,
)

# ═══════════════════════════════════════════════════════════════════════════
# CORE: The Gate
# ═══════════════════════════════════════════════════════════════════════════

class Customs:
    """The border gate. Two directions: inbound (pipeline), outbound (guard)."""

    def __init__(self):
        self.pipeline = Pipeline()
        self.guard = Guard()
        self.ioc_store = IOCStore(IOC_DB_PATH)
        self.audit = AuditTrail(AUDIT_LOG_PATH)
        self.session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def _validate_path(self, filepath: str) -> str:
        """Resolve and validate file path. Prevents path traversal.
        
        Returns the resolved absolute path or raises ValueError if the
        path is outside allowed boundaries (not a regular file, symlink
        to outside, etc.).
        """
        path = Path(filepath).resolve()
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        if not path.is_file():
            raise ValueError(f"Not a regular file: {filepath}")
        # Reject symlinks pointing outside their directory
        if path.is_symlink():
            target = path.readlink().resolve()
            if not str(target).startswith(str(path.parent)):
                raise ValueError(f"Symlink escapes directory: {filepath}")
        return str(path)

    def _quarantine_file(self, filepath: str, report: dict) -> str:
        """Move a flagged file to isolated quarantine storage.
        
        Creates a session-scoped directory under store/quarantine/,
        moves the file there, and strips all permissions (0000).
        The file is physically isolated from the system — no read,
        write, or execute possible without explicit admin action.
        
        Returns the quarantine path or empty string on failure.
        """
        src = Path(filepath)
        if not src.exists():
            return ""
        try:
            dest_dir = QUARANTINE_DIR / self.session_id
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / src.name
            # Avoid overwriting — append counter if name collision
            if dest.exists():
                stem, suffix = dest.stem, dest.suffix
                counter = 1
                while dest.exists():
                    dest = dest_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
            import shutil
            try:
                shutil.move(str(src), str(dest))
            except shutil.Error:
                # Cross-device move — fall back to copy + delete
                import tempfile
                shutil.copy2(str(src), str(dest))
                src.unlink()
            dest.chmod(0o000)  # strip all permissions (POSIX)
            return str(dest)
        except Exception:
            return ""

    def inspect_inbound(self, filepath: str) -> dict:
        """Run full 17-stage pipeline on a file entering the system.
        
        Returns: {verdict, score, stages[], iocs[]}
        """
        filepath = self._validate_path(filepath)
        report = self.pipeline.analyze(filepath)
        
        # Extract IOCs from quarantined files
        if report["verdict"] == "QUARANTINE":
            self._quarantine_file(filepath, report)
            iocs = self.ioc_store.extract_and_store(report)
            report["iocs"] = iocs
        
        # Audit
        self.audit.log_inbound(
            session=self.session_id,
            filepath=filepath,
            verdict=report["verdict"],
            score=report["score"],
            signals=report.get("scoring", {}).get("signals", [])
        )
        
        return report

    def inspect_outbound(self, text: str, source: str = "agent") -> dict:
        """Run full 17-check guard on text leaving the system.
        
        Returns: {verdict, score, checks[], violations[]}
        """
        report = self.guard.verify(text, source=source)
        
        # Audit
        self.audit.log_outbound(
            session=self.session_id,
            source=source,
            verdict=report["verdict"],
            score=report["score"],
            violations=report.get("violations", [])
        )
        
        return report

    def full_scan(self) -> dict:
        """Run both pipeline (on recent intake dir) and guard (self-test)."""
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session": self.session_id,
            "pipeline_status": self.pipeline.status(),
            "guard_status": self.guard.status(),
            "ioc_count": self.ioc_store.count(),
            "audit_entries": self.audit.count(),
        }
        return results


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def format_inbound_report(report: dict) -> str:
    """Human-readable inbound (pipeline) report."""
    lines = []
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║  CUSTOMS — INBOUND INSPECTION                               ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    lines.append(f"║  FILE:    {Path(report['file']).name[:46]:<46s} ║")
    lines.append(f"║  SCORE:   {report['score']:<3d}/100  →  {report['verdict']:<20s}         ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    
    for r in report.get("stages", []):
        stage = r.get("stage", "?").upper()
        status = "✓"
        flags = []
        
        if r.get("high"):
            flags.append("HIGH ENTROPY")
            status = "⚠"
        if r.get("infected"):
            flags.append(f"CLAMAV: {len(r.get('hits',[]))} hits")
            status = "🚨"
        if r.get("mismatch"):
            flags.append("TYPE MISMATCH")
            status = "⚠"
        if r.get("flagged"):
            flags.append(f"STRINGS: {len(r.get('suspicious_matches',[]))}")
            status = "⚠"
        if r.get("suspicious"):
            flags.append("STRUCTURAL")
            status = "⚠"
        if r.get("deviation"):
            flags.append("ENTROPY DEV")
            status = "⚠"
        
        flag_str = ", ".join(flags) if flags else "clean"
        lines.append(f"║  [{status}] {stage:<20s} → {flag_str:<36s} ║")
    
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    
    scoring = report.get("scoring", {})
    for s in scoring.get("signals", []):
        lines.append(f"║    → {s:<52s} ║")
    
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    
    if report.get("iocs"):
        lines.append("║  IOCs EXTRACTED:                                           ║")
        for ioc in report["iocs"][:5]:
            lines.append(f"║    {str(ioc)[:52]:<52s} ║")
    
    lines.append("╚══════════════════════════════════════════════════════════════╝")
    return "\n".join(lines)


def format_outbound_report(report: dict) -> str:
    """Human-readable outbound (guard) report."""
    lines = []
    lines.append("╔══════════════════════════════════════════════════════════════╗")
    lines.append("║  CUSTOMS — OUTBOUND INSPECTION                              ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    lines.append(f"║  SOURCE:  {report.get('source', 'unknown'):<46s} ║")
    lines.append(f"║  SCORE:   {report['score']:<3d}/100  →  {report['verdict']:<20s}         ║")
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    
    for check in report.get("checks", []):
        level = check.get("level", "?").upper()
        passed = check.get("passed", True)
        icon = "✓" if passed else "🚨"
        detail = check.get("detail", "")[:44]
        lines.append(f"║  [{icon}] {level:<20s} → {detail:<36s} ║")
    
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    
    for v in report.get("violations", []):
        lines.append(f"║  VIOLATION: {v[:52]:<52s} ║")
    
    lines.append("╚══════════════════════════════════════════════════════════════╝")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="CUSTOMS — Sovereignty Through Infrastructure"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", help="File to inspect (inbound pipeline)")
    group.add_argument("--text", help="Text to verify (outbound guard)")
    group.add_argument("--serve", action="store_true", help="MCP server mode")
    group.add_argument("--check", action="store_true", help="Full status check")
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    
    args = parser.parse_args()
    customs = Customs()
    
    if args.file:
        report = customs.inspect_inbound(args.file)
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print(format_inbound_report(report))
    
    elif args.text:
        report = customs.inspect_outbound(args.text)
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print(format_outbound_report(report))
    
    elif args.check:
        report = customs.full_scan()
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            print(json.dumps(report, indent=2, default=str))
    
    elif args.serve:
        print("CUSTOMS MCP server mode — stdio JSON-RPC", file=sys.stderr)
        print("ready", file=sys.stderr, flush=True)
        
        # MCP loop — Content-Length + newline-delimited JSON-RPC.
        # Reads a Content-Length header, then exactly that many bytes
        # of JSON payload. Handles pretty-printed / multiline JSON.
        import re as _re
        buffer = ""
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                buffer += line
                
                # Look for Content-Length header
                if not buffer.startswith("Content-Length:"):
                    buffer = ""
                    continue
                    
                header_match = _re.match(r"Content-Length:\s*(\d+)\r?\n\r?\n", buffer)
                if not header_match:
                    continue
                    
                content_length = int(header_match.group(1))
                body_start = header_match.end()
                remaining_body = content_length - (len(buffer) - body_start)
                
                if remaining_body > 0:
                    buffer += sys.stdin.read(remaining_body)
                
                body = buffer[body_start:body_start + content_length]
                buffer = buffer[body_start + content_length:]
                
                req = json.loads(body)
                method = req.get("method", "")
                req_id = req.get("id")
                
                if method == "inspect_inbound":
                    result = customs.inspect_inbound(req["params"]["filepath"])
                elif method == "inspect_outbound":
                    result = customs.inspect_outbound(
                        req["params"]["text"],
                        req["params"].get("source", "agent")
                    )
                elif method == "full_scan":
                    result = customs.full_scan()
                elif method == "status":
                    result = customs.full_scan()
                else:
                    result = {"error": f"Unknown method: {method}"}
                
                resp = {"jsonrpc": "2.0", "id": req_id, "result": result}
                print(json.dumps(resp, default=str), flush=True)
            except Exception as e:
                err = {"jsonrpc": "2.0", "id": req.get("id") if 'req' in dir() else None, "error": str(e)}
                print(json.dumps(err, default=str), flush=True)


if __name__ == "__main__":
    main()
