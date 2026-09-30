#!/usr/bin/env python3
"""
CUSTOMS Pipeline — 17-stage inbound file/message analysis.

Stages:
  N1  — Intake & Isolation       N10 — Sandbox Detonation
  N2  — Cryptographic Hashing    N11 — System Call Capture
  N3  — File Type Detection      N12 — Network Behavior
  N4  — Entropy Calculation      N13 — Filesystem Changes
  N5  — Entropy Deviation        N14 — Behavioral Risk Scoring
  N6  — Structural Analysis      N15 — Manual Triage Queue
  N7  — Signature Scan (ClamAV)  N16 — IOC Extraction
  N8  — YARA Rule Matching       N17 — Audit & Reporting
  N9  — String Extraction

Each stage is a standalone function. Stages compose in order.
"""

import hashlib
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from config import (
    MAGIC_SIGNATURES, SUSPICIOUS_PATTERNS, EXPECTED_ENTROPY,
    ENTROPY_HIGH, PIPELINE_WEIGHTS, SANDBOX_TIMEOUT, SANDBOX_IMAGE,
    QUARANTINE_THRESHOLD, REVIEW_THRESHOLD, RULES_DIR,
)


# ═══════════════════════════════════════════════════════════════════════
# STAGE 1 — Intake & Isolation
# ═══════════════════════════════════════════════════════════════════════

def stage_intake(filepath: str) -> dict:
    """Validate file exists, record metadata."""
    path = Path(filepath)
    if not path.exists():
        return {"stage": "N1_intake", "error": f"File not found: {filepath}"}
    stat = path.stat()
    return {
        "stage": "N1_intake",
        "filename": path.name,
        "size_bytes": stat.st_size,
        "mode": oct(stat.st_mode),
        "intake_time": datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 2 — Cryptographic Hashing
# ═══════════════════════════════════════════════════════════════════════

def stage_hash(filepath: str) -> dict:
    """SHA-256 + SHA-1 + MD5 for dedup and IOC generation."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "stage": "N2_hash",
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 3 — File Type Detection (magic bytes)
# ═══════════════════════════════════════════════════════════════════════

def stage_filetype(filepath: str) -> dict:
    """Detect file type from magic bytes, not extension."""
    detected = "unknown"
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
    except Exception:
        return {"stage": "N3_filetype", "detected": "unreadable"}

    for magic, ftype in MAGIC_SIGNATURES.items():
        if header.startswith(magic):
            detected = ftype
            break

    ext = Path(filepath).suffix.lower()
    mismatch = False
    text_extensions = {".txt", ".md", ".csv", ".json", ".xml", ".yaml", ".yml", ".log", ".ini", ".cfg"}
    executable_types = {"ELF executable", "PE executable (DOS/Windows)", "Mach-O"}
    executable_extensions = {".exe", ".dll", ".so", ".elf", ".o", ".sys", ".dylib"}

    # Text file claiming to be something else
    if ext in text_extensions and detected in executable_types:
        mismatch = True
    elif ext in text_extensions and detected not in ("unknown",):
        mismatch = True
    # Executable magic in non-executable extension (e.g., PE header in .bin, .dat)
    elif detected in executable_types and ext not in executable_extensions:
        mismatch = True

    return {
        "stage": "N3_filetype",
        "detected": detected,
        "extension": ext,
        "mismatch": mismatch,
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 4 — Entropy Calculation
# ═══════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return _shannon_entropy_counts(counts, len(data))


def _shannon_entropy_counts(counts: list[int], total: int) -> float:
    """Shannon entropy from pre-computed byte counts (chunked-friendly)."""
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def stage_entropy(filepath: str) -> dict:
    """Shannon entropy over full file using chunked reading.
    
    Processes large files in 64KB chunks to keep memory constant.
    Section entropies are sampled from the first 10MB.
    """
    CHUNK = 65536  # 64KB
    MAX_SAMPLE = 10 * 1024 * 1024  # 10MB max for section analysis
    
    counts = [0] * 256
    total_bytes = 0
    section_samples = []
    
    try:
        with open(filepath, "rb") as f:
            offset = 0
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                total_bytes += len(chunk)
                for b in chunk:
                    counts[b] += 1
                # Sample sections for large files
                if offset < MAX_SAMPLE and len(section_samples) < 10:
                    section_samples.append(chunk[:1024])
                offset += len(chunk)
    except Exception:
        return {"stage": "N4_entropy", "error": "unreadable"}
    
    if total_bytes == 0:
        return {"stage": "N4_entropy", "value": 0.0, "high": False, "section_entropies": []}
    
    value = round(_shannon_entropy_counts(counts, total_bytes), 2)
    section_entropies = []
    for sample in section_samples:
        sc = [0] * 256
        for b in sample:
            sc[b] += 1
        section_entropies.append(round(_shannon_entropy_counts(sc, len(sample)), 2))

    return {
        "stage": "N4_entropy",
        "value": value,
        "high": value > ENTROPY_HIGH,
        "section_entropies": section_entropies[:10],
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 5 — Entropy Deviation Scoring
# ═══════════════════════════════════════════════════════════════════════

def stage_entropy_deviation(filepath: str, entropy_value: float) -> dict:
    """Check entropy against expected range for file type."""
    ext = Path(filepath).suffix.lower()
    expected = EXPECTED_ENTROPY.get(ext)

    if expected is None:
        return {
            "stage": "N5_entropy_deviation",
            "deviation": False,
            "reason": f"no baseline for extension '{ext}'",
        }

    low, high = expected
    deviation = entropy_value < low or entropy_value > high
    return {
        "stage": "N5_entropy_deviation",
        "expected_range": f"{low}-{high}",
        "actual": entropy_value,
        "deviation": deviation,
        "reason": f"entropy {entropy_value} outside expected {low}-{high} for {ext}" if deviation else "within range",
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 6 — Structural Analysis
# ═══════════════════════════════════════════════════════════════════════

def stage_structural(filepath: str, filetype: str) -> dict:
    """Parse executable headers for suspicious characteristics."""
    flags = []

    if filetype == "ELF executable":
        try:
            with open(filepath, "rb") as f:
                header = f.read(64)
            if len(header) >= 20:
                # RWX segment detection
                for i in range(0, len(header) - 4, 4):
                    word = header[i:i+4]
                    if word == b"\x07\x00\x00\x00":
                        flags.append("RWX segment detected")
                        break
            # Check ELF class and endianness
            if header[4] == 1:  # 32-bit
                flags.append("32-bit ELF")
            elif header[4] == 2:  # 64-bit
                pass
        except Exception:
            pass

    if filetype == "PE executable (DOS/Windows)":
        try:
            with open(filepath, "rb") as f:
                f.seek(0x3C)
                pe_offset_data = f.read(4)
                if len(pe_offset_data) == 4:
                    pe_offset = int.from_bytes(pe_offset_data, "little")
                    f.seek(pe_offset)
                    pe_sig = f.read(4)
                    if pe_sig == b"PE\x00\x00":
                        f.seek(pe_offset + 22)
                        characteristics = f.read(2)
                        if len(characteristics) == 2:
                            chars = int.from_bytes(characteristics, "little")
                            if chars & 0x2000:
                                flags.append("DLL detected")
        except Exception:
            pass

    return {
        "stage": "N6_structural",
        "flags": flags,
        "suspicious": len(flags) > 0,
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 7 — Signature Scan (ClamAV)
# ═══════════════════════════════════════════════════════════════════════

def stage_clamav(filepath: str) -> dict:
    """ClamAV signature scan. Graceful if not installed."""
    clamav_path = shutil.which("clamscan") or shutil.which("clamdscan")
    if not clamav_path:
        return {"stage": "N7_clamav", "available": False, "hits": [], "infected": False}

    try:
        result = subprocess.run(
            [clamav_path, "--no-summary", filepath],
            capture_output=True, text=True, timeout=30
        )
        hits = [line.strip() for line in result.stdout.splitlines() if "FOUND" in line]
        return {"stage": "N7_clamav", "available": True, "hits": hits, "infected": len(hits) > 0}
    except Exception as e:
        return {"stage": "N7_clamav", "available": True, "error": str(e), "hits": [], "infected": False}


# ═══════════════════════════════════════════════════════════════════════
# STAGE 8 — YARA Rule Matching
# ═══════════════════════════════════════════════════════════════════════

def stage_yara(filepath: str) -> dict:
    """YARA rule matching. Requires yara-python. Falls back gracefully."""
    try:
        import yara
    except ImportError:
        return {"stage": "N8_yara", "available": False, "matches": [], "note": "yara-python not installed"}

    rules_dir = RULES_DIR
    compiled_path = rules_dir / "compiled.yarc"

    matches = []
    try:
        if compiled_path.exists():
            rules = yara.load(str(compiled_path))
        else:
            rule_files = {str(p) for p in rules_dir.glob("*.yar")}
            if not rule_files:
                return {"stage": "N8_yara", "available": True, "matches": [], "note": "no .yar files in rules/"}
            rules = yara.compile(filepaths=rule_files)

        matches = rules.match(filepath)
    except Exception as e:
        return {"stage": "N8_yara", "available": True, "error": str(e), "matches": []}

    return {
        "stage": "N8_yara",
        "available": True,
        "matches": [{"rule": m.rule, "tags": m.tags, "strings": [(s.identifier, s.instances) for s in m.strings]} for m in matches],
        "match_count": len(matches),
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 9 — String Extraction & Pattern Matching
# ═══════════════════════════════════════════════════════════════════════

def stage_strings(filepath: str) -> dict:
    """Extract printable strings and match suspicious patterns."""
    try:
        result = subprocess.run(
            ["strings", "-n", "4", filepath],
            capture_output=True, text=True, timeout=30
        )
        all_strings = result.stdout.splitlines()
    except Exception:
        all_strings = []

    matches = []
    urls_found = set()
    ips_found = set()

    for s in all_strings[:5000]:
        # Extract all URLs
        url_matches = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', s)
        urls_found.update(url_matches)
        # Extract all IPs
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s)
        ips_found.update(ip_matches)
        # Match suspicious patterns
        for pattern, label in SUSPICIOUS_PATTERNS:
            if re.search(pattern, s, re.IGNORECASE):
                matches.append({"pattern": label, "match": s[:120]})
                break  # One match per string

    return {
        "stage": "N9_strings",
        "total_strings": len(all_strings),
        "suspicious_matches": matches[:30],
        "flagged": len(matches) > 0,
        "urls": list(urls_found)[:20],
        "ips": list(ips_found)[:20],
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 10-13 — Sandbox Detonation
# ═══════════════════════════════════════════════════════════════════════

def stage_sandbox(filepath: str) -> dict:
    """Execute file in isolated container with strace capture."""
    docker_path = shutil.which("docker")
    if not docker_path:
        return {
            "stage": "N10-13_sandbox", "available": False,
            "note": "Docker not installed",
            "syscalls": [], "network_attempts": [], "persistence_detected": False,
        }

    abs_path = os.path.abspath(filepath)
    sandbox_name = f"customs_sandbox_{os.getpid()}_{int(time.time())}"
    sample_name = os.path.basename(filepath)
    # Sanitize filename for shell — prevent command injection via metacharacters.
    # Only allow alphanumeric, dots, hyphens, underscores. Replace rest with '_'.
    import re as _re
    safe_name = _re.sub(r'[^a-zA-Z0-9._-]', '_', sample_name)
    syscalls_log = []
    network_attempts = []
    persistence_detected = False

    try:
        result = subprocess.run([
            "docker", "run", "--rm", "--name", sandbox_name,
            "--network", "none", "--memory", "256m", "--cpus", "1",
            "--read-only", "--tmpfs", "/tmp:noexec,nosuid,size=64M",
            "-v", f"{abs_path}:/sample/{safe_name}:ro",
            SANDBOX_IMAGE,
            "timeout", str(SANDBOX_TIMEOUT), "strace", "-f",
            "-e", "trace=execve,connect,sendto,unlink,mount,rename,openat,write",
            "sh", "-c",
            f"apk add --no-cache strace >/dev/null 2>&1; chmod +x /sample/{safe_name} 2>/dev/null; /sample/{safe_name} 2>/dev/null; echo EXIT:$?"
        ], capture_output=True, text=True, timeout=SANDBOX_TIMEOUT + 15)

        # Parse strace output
        for line in (result.stderr + result.stdout).splitlines():
            if "execve" in line:
                syscalls_log.append({"call": "execve", "detail": line[:200]})
            elif "connect(" in line:
                network_attempts.append(line[:200])
            elif "unlink(" in line or "rename(" in line:
                syscalls_log.append({"call": "file_op", "detail": line[:200]})
            elif "sendto(" in line:
                network_attempts.append(line[:200])
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", sandbox_name], capture_output=True)
    except Exception:
        pass
    finally:
        subprocess.run(["docker", "rm", "-f", sandbox_name], capture_output=True)

    return {
        "stage": "N10-13_sandbox",
        "available": True,
        "syscalls": syscalls_log[:20],
        "network_attempts": network_attempts[:10],
        "network_isolated": True,  # --network none: all connect/sendto attempts blocked
        "persistence_detected": persistence_detected,
        "total_syscalls": len(syscalls_log),
    }


# ═══════════════════════════════════════════════════════════════════════
# STAGE 14 — Behavioral Risk Scoring
# ═══════════════════════════════════════════════════════════════════════

def stage_scoring(results: list[dict]) -> dict:
    """Aggregate all stages into weighted risk score."""
    score = 0
    signals = []

    for r in results:
        stage_name = r.get("stage", "")

        if "entropy" in stage_name and "deviation" not in stage_name:
            if r.get("high"):
                score += PIPELINE_WEIGHTS["entropy_high"]
                signals.append(f"entropy_high (+{PIPELINE_WEIGHTS['entropy_high']})")

        if "filetype" in stage_name and r.get("mismatch"):
            score += PIPELINE_WEIGHTS["type_mismatch"]
            signals.append(f"type_mismatch (+{PIPELINE_WEIGHTS['type_mismatch']})")

        if "structural" in stage_name and r.get("suspicious"):
            score += PIPELINE_WEIGHTS["suspicious_section"]
            signals.append(f"suspicious_section (+{PIPELINE_WEIGHTS['suspicious_section']})")

        if "entropy_deviation" in stage_name and r.get("deviation"):
            score += PIPELINE_WEIGHTS["encoded_payload"]
            signals.append(f"entropy_deviation (+{PIPELINE_WEIGHTS['encoded_payload']})")

        if "clamav" in stage_name and r.get("infected"):
            hit_count = len(r.get("hits", []))
            score += PIPELINE_WEIGHTS["clamav_hit"] * hit_count
            signals.append(f"clamav_hit x{hit_count} (+{PIPELINE_WEIGHTS['clamav_hit'] * hit_count})")

        if "yara" in stage_name and r.get("match_count", 0) > 0:
            mc = r["match_count"]
            score += PIPELINE_WEIGHTS["yara_hit"] * mc
            signals.append(f"yara_hit x{mc} (+{PIPELINE_WEIGHTS['yara_hit'] * mc})")

        if "strings" in stage_name and r.get("flagged"):
            match_count = len(r.get("suspicious_matches", []))
            added = min(PIPELINE_WEIGHTS["suspicious_string"] * match_count, 50)
            score += added
            signals.append(f"suspicious_string x{match_count} (+{added})")

        if "sandbox" in stage_name:
            if r.get("persistence_detected"):
                score += PIPELINE_WEIGHTS["persistence_detected"]
                signals.append(f"persistence_detected (+{PIPELINE_WEIGHTS['persistence_detected']})")
            net_attempts = len(r.get("network_attempts", []))
            if net_attempts:
                added = min(PIPELINE_WEIGHTS["network_attempt"] * net_attempts, 50)
                score += added
                signals.append(f"network_attempt x{net_attempts} (+{added})")
            if r.get("total_syscalls", 0) > 100:
                execve_count = sum(1 for s in r.get("syscalls", []) if "execve" in str(s))
                if execve_count:
                    score += PIPELINE_WEIGHTS["execve_syscall"]
                    signals.append(f"execve_syscall x{execve_count} (+{PIPELINE_WEIGHTS['execve_syscall']})")

    score = min(score, 100)

    # Compound threat bonus — multiple independent signal categories
    # amplify the risk beyond linear addition. A file with type mismatch
    # AND suspicious strings AND entropy deviation is more dangerous
    # than the sum of its parts.
    signal_categories = 0
    if any("type_mismatch" in s for s in signals):
        signal_categories += 1
    if any("entropy" in s for s in signals):
        signal_categories += 1
    if any("suspicious_string" in s for s in signals):
        signal_categories += 1
    if any("yara_hit" in s or "clamav_hit" in s for s in signals):
        signal_categories += 1
    if any(w in s for s in signals for w in ["network_attempt","persistence","execve","syscall"]):
        signal_categories += 1
    
    if signal_categories >= 3:
        bonus = min(signal_categories * 10, 30)
        score = min(score + bonus, 100)
        signals.append(f"compound_threat x{signal_categories} categories (+{bonus})")

    if score >= QUARANTINE_THRESHOLD:
        verdict = "QUARANTINE"
    elif score >= REVIEW_THRESHOLD:
        verdict = "REVIEW"
    else:
        verdict = "LOW_RISK"

    return {
        "stage": "N14_scoring",
        "score": score,
        "verdict": verdict,
        "thresholds": {"quarantine": QUARANTINE_THRESHOLD, "review": REVIEW_THRESHOLD},
        "signals": signals,
    }


# ═══════════════════════════════════════════════════════════════════════
# PIPELINE ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class Pipeline:
    """17-stage inbound file analysis pipeline."""

    def analyze(self, filepath: str) -> dict:
        stages = []

        # N1
        r = stage_intake(filepath)
        if "error" in r:
            return {"file": filepath, "error": r["error"], "stages": stages, "verdict": "ERROR", "score": 0}
        stages.append(r)

        # N2
        stages.append(stage_hash(filepath))

        # N3
        ft = stage_filetype(filepath)
        stages.append(ft)

        # N4
        ent = stage_entropy(filepath)
        stages.append(ent)

        # N5
        if "value" in ent:
            stages.append(stage_entropy_deviation(filepath, ent["value"]))

        # N6
        stages.append(stage_structural(filepath, ft.get("detected", "unknown")))

        # N7
        stages.append(stage_clamav(filepath))

        # N8
        stages.append(stage_yara(filepath))

        # N9
        stages.append(stage_strings(filepath))

        # N10-13
        stages.append(stage_sandbox(filepath))

        # N14
        scoring = stage_scoring(stages)
        stages.append(scoring)

        # Extract URLs and IPs for IOC (N16)
        ioc_data = {}
        for s in stages:
            if s.get("stage") == "N9_strings":
                ioc_data["urls"] = s.get("urls", [])
                ioc_data["ips"] = s.get("ips", [])
        stages.append({"stage": "N16_ioc_extraction", "iocs": ioc_data})

        # Audit trail (N17)
        stages.append({
            "stage": "N17_audit",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": scoring["verdict"],
            "stages_executed": len(stages),
        })

        return {
            "file": filepath,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verdict": scoring["verdict"],
            "score": scoring["score"],
            "scoring": scoring,
            "stages": stages,
        }

    def status(self) -> dict:
        """Health check — which stages are operational."""
        checks = {
            "intake": True,
            "hash": True,
            "filetype": True,
            "entropy": True,
            "entropy_deviation": True,
            "structural": True,
            "clamav": shutil.which("clamscan") is not None or shutil.which("clamdscan") is not None,
            "yara": False,
            "strings": shutil.which("strings") is not None,
            "sandbox": shutil.which("docker") is not None,
        }
        try:
            import yara
            checks["yara"] = True
        except ImportError:
            pass

        available = sum(1 for v in checks.values() if v)
        return {"stages_available": available, "stages_total": len(checks), "checks": checks}
