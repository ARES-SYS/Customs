"""
CUSTOMS Configuration — all thresholds, weights, rules, and paths.
Single source of truth for the entire gatekeeper system.
"""

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────
CUSTOMS_DIR = Path(os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd())
IOC_DB_PATH = CUSTOMS_DIR / "store" / "ioc.db"
AUDIT_LOG_PATH = CUSTOMS_DIR / "store" / "audit.jsonl"
QUARANTINE_DIR = CUSTOMS_DIR / "store" / "quarantine"
RULES_DIR = CUSTOMS_DIR / "rules"

# ── Scoring Thresholds ─────────────────────────────────────────────────
QUARANTINE_THRESHOLD = 50    # Score >= 50 → auto-quarantine
REVIEW_THRESHOLD = 20        # Score >= 20 → manual review required

# ── Pipeline Weights (Inbound) ─────────────────────────────────────────
PIPELINE_WEIGHTS = {
    "entropy_high": 15,
    "type_mismatch": 20,
    "suspicious_section": 30,
    "clamav_hit": 40,
    "yara_hit": 35,
    "execve_syscall": 50,
    "network_attempt": 25,
    "persistence_detected": 40,
    "encoded_payload": 20,
    "suspicious_string": 10,
}

# ── Guard Weights (Outbound) ───────────────────────────────────────────
GUARD_WEIGHTS = {
    "fabrication": 50,       # Invented data, hallucination
    "unverified_claim": 25,  # Statement without tool backing
    "ai_slop": 15,           # Generic AI excuse patterns
    "fake_url": 40,          # Unverified or invented URL
    "contradiction": 35,     # Self-contradictory statements
    "hidden_error": 30,      # Concealed failure
    "destructive_intent": 60, # Command that could damage
    "pii_leak": 55,           # SSN, credit card, API keys, tokens, passwords
    "type_mismatch": 20,     # Claims JSON but outputs text
    "overconfidence": 10,    # "Definitely" without verification
    "vague_claim": 10,       # "Probably", "should work"
}

# ── Entropy Thresholds ─────────────────────────────────────────────────
ENTROPY_HIGH = 7.2  # Must match YARA rules in suspicious.yar (math.entropy >= 7.2)

# ── Expected entropy ranges per file extension ─────────────────────────
EXPECTED_ENTROPY = {
    ".txt": (4.0, 5.5), ".md": (4.0, 5.5), ".csv": (3.5, 5.0),
    ".json": (4.5, 5.5), ".xml": (4.5, 5.5), ".py": (4.5, 5.5),
    ".c": (4.5, 5.5), ".html": (4.5, 5.5), ".png": (6.5, 8.0),
    ".jpg": (7.0, 8.0), ".gif": (6.0, 8.0), ".pdf": (6.0, 8.0),
    ".zip": (7.0, 8.0), ".gz": (7.5, 8.0), ".exe": (6.0, 7.0),
    ".dll": (6.0, 7.0), ".so": (6.0, 7.0), ".elf": (5.5, 7.0),
}

# ── Magic byte signatures ──────────────────────────────────────────────
MAGIC_SIGNATURES = {
    b"\x7fELF": "ELF executable",
    b"MZ": "PE executable (DOS/Windows)",
    b"\x89PNG": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF8": "GIF image",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP archive",
    b"\x1f\x8b": "GZIP archive",
    b"BZh": "BZIP2 archive",
    b"\xfd7zXZ": "XZ archive",
    b"\xcf\xfa\xed\xfe": "Mach-O (x86_64)",
    b"\xce\xfa\xed\xfe": "Mach-O (i386)",
    b"\xca\xfe\xba\xbe": "Mach-O (universal)",
    b"RIFF": "RIFF container",
    b"\xd0\xcf\x11\xe0": "OLE2 (Office doc)",
}

# ── Suspicious string patterns (Pipeline Stage 9) ──────────────────────
SUSPICIOUS_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP URL"),
    (r"(curl|wget)\s+.*\|\s*(bash|sh|zsh)", "curl-to-shell"),
    (r"base64\s+-d|base64\s+--decode|Base64\.decode", "base64 decode"),
    (r"rm\s+-rf\s+/", "recursive delete root"),
    (r"/dev/tcp/", "bash reverse shell"),
    (r"nc\s+.*-e\s+/bin/(bash|sh)", "netcat reverse shell"),
    (r"eval\s*\(.*base64_decode", "eval base64"),
    (r"cmd\.exe\s+/c", "Windows cmd execution"),
    (r"powershell.*-enc\s|powershell.*-EncodedCommand", "encoded PowerShell"),
    (r"Invoke-\w+.*-Uri\s+http", "PowerShell web request"),
    (r"Start-Process\s+.*-WindowStyle\s+Hidden", "hidden PowerShell process"),
    (r"HKEY_(LOCAL_MACHINE|CURRENT_USER)", "registry access"),
    (r"schtasks\s+/create", "scheduled task creation"),
    (r"sc\s+create\s+\w+\s+binPath", "Windows service creation"),
    (r"reg\s+(add|delete)\s+HKEY", "registry modification"),
    (r"wget\s+.*-O\s+/", "wget download to filesystem"),
]

# ── Known C2 indicators (EXAMPLE VALUES — replace with your own threat intel) ──
C2_DOMAINS = ["example-c2.com", "example-backup.net"]
C2_SUBNET = "192.0.2.0/24"
C2_PORTS = [4444, 5555, 6666]

# ── AI Slop / Fabrication keywords (Guard N10) ─────────────────────────
AI_SLOP_KEYWORDS = [
    "I apologize", "I cannot", "As an AI", "I would suggest",
    "Let me explain", "Probably", "Should work", "I think",
    "I believe", "It seems", "It appears", "It's worth noting",
    "Keep in mind", "Please note that", "I hope this helps",
    "Let me know if", "Feel free to",
]

# ── Fabrication indicators (Guard N15) ─────────────────────────────────
FABRICATION_INDICATORS = [
    "I have created", "I have written", "I have built",
    "The file contains", "The output shows",
]

# ── Sandbox config ─────────────────────────────────────────────────────
SANDBOX_TIMEOUT = 120
SANDBOX_IMAGE = "alpine:3.20"  # Pinned — avoid mutable :latest tag

# ── Auto-init storage directories ──────────────────────────────────────
# Ensure critical paths exist before any module tries to write to them.
for path in [IOC_DB_PATH.parent, QUARANTINE_DIR, RULES_DIR]:
    path.mkdir(parents=True, exist_ok=True)
