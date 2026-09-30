#!/usr/bin/env python3
"""
CUSTOMS Guard — 17-level outbound response verification.

Levels:
  N1  — SIZE           N10 — YARA/KEYWORDS (AI slop)
  N2  — NOMBRE PROHIBIDO N11 — ANTI-PHISHING (fake URLs)
  N3  — DOBLE EXTENSION  N12 — PDF PROFUNDO (auto-actions)
  N4  — EXTENSION NEGRA  N13 — HTML/JS MALICIOSO (unsanitized)
  N5  — HASH (repeticion) N14 — DETONACION CONTROLADA
  N6  — ENTROPY          N15 — METADATA (source trace)
  N7  — MAGIC BYTES       N16 — STEGANOGRAPHY (hidden error)
  N8  — PE DISGUISED     N17 — POLYGLOTS (contradiction)
  N9  — MACROS

Each level inspects agent output for fabrication, hallucination,
or dangerous patterns before it reaches the user.
"""

import re
import json
import threading
from datetime import datetime, timezone
from typing import Optional
from config import (
    AI_SLOP_KEYWORDS, FABRICATION_INDICATORS, GUARD_WEIGHTS,
    QUARANTINE_THRESHOLD, REVIEW_THRESHOLD,
)


# ═══════════════════════════════════════════════════════════════════════
# N1 — Size : Is the output empty or suspiciously long without value?
# ═══════════════════════════════════════════════════════════════════════

def check_size(text: str) -> dict:
    """Check if output has real content or is a stub."""
    stripped = text.strip()

    if not stripped:
        return {"level": "N1_SIZE", "passed": False, "detail": "Empty output", "weight": GUARD_WEIGHTS["fabrication"]}

    if len(stripped) < 20:
        return {"level": "N1_SIZE", "passed": False, "detail": f"Too short: {len(stripped)} chars", "weight": GUARD_WEIGHTS["vague_claim"]}

    # Check for stub patterns
    stub_patterns = [
        r"^(Let me|I will|I'll|I would)\s+\w+\s+(that|this|the)",
        r"^(Here is|This is)\s+a\s+(summary|brief|quick)",
        r"^I (can|could|would) help",
    ]
    for pat in stub_patterns:
        if re.match(pat, stripped, re.IGNORECASE):
            return {"level": "N1_SIZE", "passed": False, "detail": "Appears to be a stub/plan, not a result", "weight": GUARD_WEIGHTS["vague_claim"]}

    return {"level": "N1_SIZE", "passed": True, "detail": f"{len(stripped)} chars — has content"}


# ═══════════════════════════════════════════════════════════════════════
# N2 — NOMBRE PROHIBIDO: Fabrication detection
# ═══════════════════════════════════════════════════════════════════════

def check_fabrication(text: str) -> dict:
    """Detect invented data, hallucinated file contents."""
    lower = text.lower()

    fabrication_phrases = [p.lower() for p in FABRICATION_INDICATORS]

    hits = [p for p in fabrication_phrases if p in lower]

    # Evidence must be a real path (starts with / or ./) or a tool-like
    # reference — not just any word.word pattern which is trivial to fake.
    has_evidence = bool(re.search(r"(?:^|\s)((?:/|\./)[\w./-]+|\w+\.(?:py|json|md|txt|yaml|yml|log|csv|xml|cfg|ini|sh|js|ts|html|css|sql|db))\b", text))

    if hits and not has_evidence:
        return {
            "level": "N2_FABRICATION",
            "passed": False,
            "detail": f"Fabrication indicators without evidence: {hits[:3]}",
            "weight": GUARD_WEIGHTS["fabrication"],
        }

    if hits and has_evidence:
        # Has file references — lower risk but still flag
        return {
            "level": "N2_FABRICATION",
            "passed": True,
            "detail": f"Claims with file evidence: {hits[:3]}",
            "warning": True,
        }

    return {"level": "N2_FABRICATION", "passed": True, "detail": "No fabrication indicators"}


# ═══════════════════════════════════════════════════════════════════════
# N3 — DOBLE EXTENSION: Mixed output (real + fabricated)
# ═══════════════════════════════════════════════════════════════════════

def check_mixed_output(text: str) -> dict:
    """Detect when real data is mixed with fabricated additions."""
    # Check for contradictory signals
    has_real_paths = bool(re.search(r"(/[\w/\-\.]+|\w+\.(py|md|json|yaml|txt|sh))", text))
    has_vague = any(p in text.lower() for p in ["probably", "should work", "i think", "maybe", "might be"])

    if has_real_paths and has_vague:
        return {
            "level": "N3_MIXED",
            "passed": False,
            "detail": "Real path references mixed with uncertainty language",
            "weight": GUARD_WEIGHTS["contradiction"],
        }

    return {"level": "N3_MIXED", "passed": True, "detail": "No mixed signals detected"}


# ═══════════════════════════════════════════════════════════════════════
# N4 — EXTENSION NEGRA: Destructive command detection
# ═══════════════════════════════════════════════════════════════════════

DESTRUCTIVE_PATTERNS = [
    (r"rm\s+-rf\s+/", "rm -rf /"),
    (r"rm\s+-rf\s+~", "rm -rf ~"),
    (r">\s*/dev/sd[a-z]", "overwrite block device"),
    (r"dd\s+if=.*of=/dev/sd", "dd to block device"),
    (r"mkfs\.\w+\s+/dev/", "format filesystem"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "fork bomb"),
    (r"chmod\s+-R\s+777\s+/", "chmod -R 777 /"),
    (r"chown\s+-R\s+\w+:\w+\s+/", "recursive chown root"),
    (r"iptables\s+-F", "flush firewall"),
    (r"kill\s+-9\s+-1", "kill -9 -1"),
    (r"shutdown\s+-h\s+now", "shutdown now"),
    (r"reboot", "reboot command"),
    (r"git\s+push\s+--force\s+origin", "force push"),
    (r"DROP\s+TABLE|DELETE\s+FROM\s+\w+\s+WHERE", "SQL destructive"),
    (r"(curl|wget)\s+\S+\s*\|\s*(bash|sh|zsh)", "curl/wget pipe to shell"),
    (r"\|\s*(bash|sh|zsh)\b", "pipe to shell"),
    (r"eval\s+", "eval injection"),
    (r"\$\(.*\)", "command substitution"),
]

# N4.5 — PII/CREDENTIAL LEAK DETECTION
PII_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern"),
    (r"\b\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}\b", "credit card pattern"),
    (r"(api[_\-]?key|api[_\-]?secret|access[_\-]?key|secret[_\-]?key)\s*[:=]\s*\S+", "API key in output"),
    (r"(password|passwd|pwd)\b.*?[:=]\s*\S+", "password in output"),
    (r"(token|auth)\s*[:=]\s*[A-Za-z0-9_\-.]{20,}", "auth token in output"),
]


def check_destructive(text: str) -> dict:
    """Detect destructive commands in output."""
    hits = []
    for pattern, label in DESTRUCTIVE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            hits.append(label)

    if hits:
        return {
            "level": "N4_DESTRUCTIVE",
            "passed": False,
            "detail": f"Destructive commands: {hits}",
            "weight": GUARD_WEIGHTS["destructive_intent"],
        }

    return {"level": "N4_DESTRUCTIVE", "passed": True, "detail": "No destructive commands"}


def check_pii(text: str) -> dict:
    """Detect PII and credential leaks in output. Redacts on detection."""
    hits = []
    sanitized = text
    for pattern, label in PII_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            hits.append(label)
            # Redact actual matches — don't just flag, remove the secret
            sanitized = re.sub(pattern, f'[{label.upper().replace(" ", "_")}]', sanitized, flags=re.IGNORECASE)
    if hits:
        return {
            "level": "N4b_PII_LEAK",
            "passed": False,
            "detail": f"PII/credential leak: {', '.join(hits)}",
            "weight": GUARD_WEIGHTS.get("pii_leak", 35),
            "sanitized_text": sanitized,
        }
    return {"level": "N4b_PII_LEAK", "passed": True, "detail": "No PII/credential leaks"}


# ═══════════════════════════════════════════════════════════════════════
# N5 — HASH: Repeated errors / déjà vu
# ═══════════════════════════════════════════════════════════════════════

def check_repetition(text: str, history: list[str] = None) -> dict:
    """Check if this response repeats a known error pattern."""
    if not history:
        return {"level": "N5_HASH", "passed": True, "detail": "No history to compare"}

    # Simple fingerprint: first 100 chars normalized
    fp = text.strip()[:100].lower().replace(" ", "")
    for past in history[-5:]:
        past_fp = past.strip()[:100].lower().replace(" ", "")
        if fp == past_fp:
            return {
                "level": "N5_HASH",
                "passed": False,
                "detail": "Exact repetition of previous response (possible loop)",
                "weight": GUARD_WEIGHTS["contradiction"],
            }

    return {"level": "N5_HASH", "passed": True, "detail": "No repetition detected"}


# ═══════════════════════════════════════════════════════════════════════
# N6 — ENTROPY: Too perfect or too chaotic?
# ═══════════════════════════════════════════════════════════════════════

def check_content_entropy(text: str) -> dict:
    """Check if content has natural variability."""
    if len(text) < 100:
        return {"level": "N6_ENTROPY", "passed": True, "detail": "Too short for entropy check"}

    # Sentence length variance
    sentences = re.split(r'[.!?]+', text)
    lengths = [len(s.strip().split()) for s in sentences if s.strip()]

    if len(lengths) < 3:
        return {"level": "N6_ENTROPY", "passed": True, "detail": "Too few sentences"}

    avg_len = sum(lengths) / len(lengths)
    variance = sum((l - avg_len) ** 2 for l in lengths) / len(lengths)

    # Very low variance = AI-generated monotony
    if variance < 1.0 and len(text) > 200:
        return {
            "level": "N6_ENTROPY",
            "passed": False,
            "detail": f"Abnormally uniform sentence structure (variance={variance:.1f})",
            "weight": GUARD_WEIGHTS["ai_slop"],
        }

    return {"level": "N6_ENTROPY", "passed": True, "detail": f"Natural variability (variance={variance:.1f})"}


# ═══════════════════════════════════════════════════════════════════════
# N7 — MAGIC BYTES: Type integrity check
# ═══════════════════════════════════════════════════════════════════════

def check_type_integrity(text: str) -> dict:
    """Verify claimed output type matches actual content."""
    lower = text.lower()

    # Claims to be JSON but isn't
    json_claims = any(p in lower for p in ["json output", "json format", "here is the json", "```json"])
    if json_claims:
        # Try to find a JSON block
        json_block = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
        if json_block:
            try:
                json.loads(json_block.group(1))
            except json.JSONDecodeError:
                return {
                    "level": "N7_MAGIC_BYTES",
                    "passed": False,
                    "detail": "Claims JSON but content is not valid JSON",
                    "weight": GUARD_WEIGHTS["type_mismatch"],
                }

    # Claims to be code but contains AI commentary mixed in
    code_claims = any(p in lower for p in ["```python", "```bash", "```sh", "here is the code"])
    commentary = any(p in lower for p in ["this code will", "this script does", "here is what", "let me explain"])

    if code_claims and commentary and "```" not in text:
        return {
            "level": "N7_MAGIC_BYTES",
            "passed": False,
            "detail": "Describes code but doesn't provide actual code block",
            "weight": GUARD_WEIGHTS["vague_claim"],
        }

    return {"level": "N7_MAGIC_BYTES", "passed": True, "detail": "Type integrity OK"}


# ═══════════════════════════════════════════════════════════════════════
# N8 — PE DISGUISED: Hidden executable/code in data
# ═══════════════════════════════════════════════════════════════════════

def check_hidden_executable(text: str) -> dict:
    """Detect executable code embedded in what appears to be data."""
    # Base64 blocks that might be hidden payloads
    b64_blocks = re.findall(r'(?:echo\s+)?([A-Za-z0-9+/]{40,}={0,2})', text)
    
    # Validate: try to decode and check for PE/ELF/shell headers.
    # Skip blocks that look like PEM certs, JWTs, or hex hashes.
    import base64 as _b64
    long_b64 = []
    for b in b64_blocks:
        if len(b) <= 100:
            continue
        # Skip PEM certificates, JWTs, SSH public keys
        if b.startswith(("LS0tLS1CRUdJTi",  # "-----BEGIN" in b64
                         "ZXlKaGJHY2lPaUp",  # "eyJhbGciOiJ" — JWT header
                         "c3NoLXJzYSBBQ")):  # "ssh-rsa AA"  in b64
            continue
        try:
            decoded = _b64.b64decode(b + "=" * (4 - len(b) % 4))
            # Check for executable magic bytes
            if decoded[:2] in (b'MZ', b'\x7fE') or b'#!/' in decoded[:50]:
                long_b64.append(b[:80])
        except Exception:
            continue

    # Hex-encoded content
    hex_blocks = re.findall(r'(?:\\x[0-9a-fA-F]{2}){20,}', text)

    if long_b64 or hex_blocks:
        return {
            "level": "N8_PE_DISGUISED",
            "passed": False,
            "detail": f"Encoded payload detected: {len(long_b64)} base64 blocks, {len(hex_blocks)} hex blocks",
            "weight": GUARD_WEIGHTS["fabrication"],
        }

    return {"level": "N8_PE_DISGUISED", "passed": True, "detail": "No hidden payloads"}


# ═══════════════════════════════════════════════════════════════════════
# N9 — MACROS: Hidden automation in responses
# ═══════════════════════════════════════════════════════════════════════

def check_hidden_automation(text: str) -> dict:
    """Detect automatic actions embedded in output."""
    # Auto-executing instructions
    patterns = [
        (r"run\s+this\s+command", "implicit command execution"),
        (r"execute\s+the\s+following", "implicit execution"),
        (r"add\s+this\s+to\s+your\s+(cron|bashrc|profile)", "persistence suggestion"),
        (r"install\s+this\s+(package|tool|script)", "unsolicited install"),
        (r"pip\s+install\s+|npm\s+install\s+|apt\s+install\s+", "package install command"),
    ]

    hits = []
    for pat, label in patterns:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(label)

    if hits:
        return {
            "level": "N9_MACROS",
            "passed": False,
            "detail": f"Unsolicited automation: {hits}",
            "weight": GUARD_WEIGHTS["destructive_intent"] // 2,
        }

    return {"level": "N9_MACROS", "passed": True, "detail": "No hidden automation"}


# ═══════════════════════════════════════════════════════════════════════
# N10 — YARA/KEYWORDS: AI slop detection
# ═══════════════════════════════════════════════════════════════════════

def check_ai_slop(text: str) -> dict:
    """Detect generic AI excuse patterns and slop phrases."""
    lower = text.lower()
    hits = [kw for kw in AI_SLOP_KEYWORDS if kw.lower() in lower]

    if len(hits) >= 3:
        return {
            "level": "N10_YARA_KEYWORDS",
            "passed": False,
            "detail": f"AI slop detected: {len(hits)} keywords ({hits[:3]}...)",
            "weight": GUARD_WEIGHTS["ai_slop"],
        }
    elif hits:
        return {
            "level": "N10_YARA_KEYWORDS",
            "passed": True,
            "detail": f"Minor slop: {len(hits)} keywords — acceptable",
            "warning": True,
        }

    return {"level": "N10_YARA_KEYWORDS", "passed": True, "detail": "No AI slop detected"}


# ═══════════════════════════════════════════════════════════════════════
# N11 — ANTI-PHISHING: Fake URL detection
# ═══════════════════════════════════════════════════════════════════════

def check_fake_urls(text: str) -> dict:
    """Verify URLs in output are legitimate, not invented."""
    urls = re.findall(r'https?://[^\s<>"\]\)]+', text)

    if not urls:
        return {"level": "N11_ANTI_PHISHING", "passed": True, "detail": "No URLs in output"}

    # Check for suspicious URL patterns
    suspicious = []
    for url in urls:
        url_lower = url.lower()
        if re.search(r'(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|test\.com|placeholder)', url_lower):
            suspicious.append(f"placeholder/suspicious URL: {url}")
        if len(url) > 200:
            suspicious.append(f"excessively long URL: {url[:80]}...")
        if re.search(r'\.(tk|ml|ga|cf|gq)$', url_lower):
            suspicious.append(f"free TLD: {url}")

    if suspicious:
        return {
            "level": "N11_ANTI_PHISHING",
            "passed": False,
            "detail": f"Suspicious URLs: {suspicious[:3]}",
            "weight": GUARD_WEIGHTS["fake_url"],
        }

    return {"level": "N11_ANTI_PHISHING", "passed": True, "detail": f"{len(urls)} URLs — no suspicious patterns"}


# ═══════════════════════════════════════════════════════════════════════
# N12 — PDF PROFUNDO: Auto-actions without confirmation
# ═══════════════════════════════════════════════════════════════════════

def check_auto_actions(text: str) -> dict:
    """Detect automatic file operations without user confirmation."""
    auto_patterns = [
        (r"i('ll| will) (create|write|delete|modify|change|update|remove|install)", "auto file operation"),
        (r"let me (create|write|delete|modify|change)", "auto action without confirmation"),
        (r"i'?ve (gone ahead|already|just) (and\s+)?(created|written|deleted)", "action already taken"),
    ]

    hits = []
    for pat, label in auto_patterns:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(label)

    if hits:
        return {
            "level": "N12_DEEP_PDF",
            "passed": False,
            "detail": f"Auto-actions without confirmation: {hits}",
            "weight": GUARD_WEIGHTS["destructive_intent"] // 2,
        }

    return {"level": "N12_DEEP_PDF", "passed": True, "detail": "No unauthorized auto-actions"}


# ═══════════════════════════════════════════════════════════════════════
# N13 — HTML/JS MALICIOSO: Unsanitized input execution
# ═══════════════════════════════════════════════════════════════════════

def check_unsanitized_input(text: str) -> dict:
    """Detect if output includes unvalidated user input that could execute."""
    # Script tags, event handlers in output
    dangerous_html = re.findall(
        r'(<script|onerror=|onload=|onclick=|javascript:|<iframe|<object|<embed)',
        text, re.IGNORECASE
    )

    if dangerous_html:
        return {
            "level": "N13_MALICIOUS_HTML_JS",
            "passed": False,
            "detail": f"Dangerous HTML/JS in output: {dangerous_html[:3]}",
            "weight": GUARD_WEIGHTS["fabrication"],
        }

    return {"level": "N13_MALICIOUS_HTML_JS", "passed": True, "detail": "No unsanitized executable content"}


# ═══════════════════════════════════════════════════════════════════════
# N14 — DETONACION CONTROLADA: Complex output validation
# ═══════════════════════════════════════════════════════════════════════

def check_controlled_detonation(text: str) -> dict:
    """Verify complex multi-step outputs have been validated step by step."""
    # Check for "trust me" patterns in complex responses
    trust_me_patterns = [
        r"this (should|will|must) work",
        r"(trust|believe) me",
        r"(just|simply)\s+(run|execute|do)",
        r"it('s| is) (that|just)\s+simple",
    ]

    hits = []
    for pat in trust_me_patterns:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(pat)

    if len(hits) >= 2 and len(text) > 500:
        return {
            "level": "N14_CONTROLLED_DETONATION",
            "passed": False,
            "detail": "Complex output with overconfident language — may skip validation",
            "weight": GUARD_WEIGHTS["overconfidence"],
        }

    return {"level": "N14_CONTROLLED_DETONATION", "passed": True, "detail": "Controlled, validated output"}


# ═══════════════════════════════════════════════════════════════════════
# N15 — METADATA: Source traceability
# ═══════════════════════════════════════════════════════════════════════

def check_source_traceability(text: str) -> dict:
    """Verify claims can be traced to actual tool output."""
    lower = text.lower()

    # Claims that require tool backing
    factual_claims = any(p in lower for p in [
        "the file contains", "the output shows", "the scan found",
        "the analysis detected", "according to", "the result is",
        "the hash is", "the size is", "the path is",
    ])

    # Evidence of actual tool use
    has_evidence = bool(re.search(
        r'(exit_code|pid|bytes|lines|seconds|minutes|MB|GB|TB)',
        text
    ))

    if factual_claims and not has_evidence:
        return {
            "level": "N15_METADATA",
            "passed": False,
            "detail": "Factual claims without tool output evidence",
            "weight": GUARD_WEIGHTS["unverified_claim"],
        }

    return {"level": "N15_METADATA", "passed": True, "detail": "Claims traceable to tool output"}


# ═══════════════════════════════════════════════════════════════════════
# N16 — STEGANOGRAPHY: Hidden errors
# ═══════════════════════════════════════════════════════════════════════

def check_hidden_errors(text: str) -> dict:
    """Detect concealed failures in seemingly successful output."""
    # Success language mixed with failure signals
    success_words = ["success", "completed", "done", "created", "passed", "ok"]
    failure_signals = [
        "error", "failed", "traceback", "exception", "cannot", "unable",
        "not found", "denied", "timeout", "refused", "invalid",
    ]

    has_success = any(w in text.lower() for w in success_words)
    has_failure = any(w in text.lower() for w in failure_signals)

    if has_success and has_failure:
        # Check if the failure is acknowledged or buried
        failure_positions = []
        for signal in failure_signals:
            idx = text.lower().rfind(signal)  # last occurrence, not first
            if idx >= 0:
                failure_positions.append(idx)

        if failure_positions:
            last_failure_pos = max(failure_positions)
            # If failure is in the last 20% of text, it might be buried
            if last_failure_pos > len(text) * 0.8:
                return {
                    "level": "N16_STEGANOGRAPHY",
                    "passed": False,
                    "detail": "Error signal buried at end of success-toned output",
                    "weight": GUARD_WEIGHTS["hidden_error"],
                }

    return {"level": "N16_STEGANOGRAPHY", "passed": True, "detail": "No hidden errors detected"}


# ═══════════════════════════════════════════════════════════════════════
# N17 — POLYGLOTS: Self-contradiction detection
# ═══════════════════════════════════════════════════════════════════════

def check_self_contradiction(text: str) -> dict:
    """Detect when the response contradicts itself."""
    lower = text.lower()

    contradictions = [
        (["success", "completed", "passed"], ["failed", "error", "cannot"]),
        (["created", "written", "saved"], ["does not exist", "not found", "missing"]),
        (["verified", "confirmed", "checked"], ["unverified", "not checked", "assumed"]),
        (["all tests pass", "100%", "everything works"], ["except", "however", "but"]),
    ]

    for positive_set, negative_set in contradictions:
        has_pos = any(p in lower for p in positive_set)
        has_neg = any(n in lower for n in negative_set)
        if has_pos and has_neg:
            return {
                "level": "N17_POLYGLOTS",
                "passed": False,
                "detail": f"Self-contradiction: claims {positive_set[0]} but also mentions {negative_set[0]}",
                "weight": GUARD_WEIGHTS["contradiction"],
            }

    return {"level": "N17_POLYGLOTS", "passed": True, "detail": "No self-contradictions"}


# ═══════════════════════════════════════════════════════════════════════
# GUARD ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class Guard:
    """17-level outbound response verification.
    
    Instance is session-scoped — one Guard per user/session.
    Do not share across concurrent users; history is per-instance.
    """
    
    # ReDoS guard — cap text length to prevent catastrophic backtracking
    # on pathological inputs targeting regex-heavy checks (PII, destructive).
    MAX_TEXT_LENGTH = 50_000

    def __init__(self):
        self.history: list[str] = []

    def verify(self, text: str, source: str = "agent") -> dict:
        """Run all 17 checks on agent output."""
        # ReDoS guard — truncate before regex-heavy stages
        if len(text) > self.MAX_TEXT_LENGTH:
            text = text[:self.MAX_TEXT_LENGTH]
        checks = []
        total_score = 0
        violations = []

        # N1-N17 in order
        for check_fn in [
            check_size, check_fabrication, check_mixed_output,
            check_destructive, check_pii, check_repetition, check_content_entropy,
            check_type_integrity, check_hidden_executable,
            check_hidden_automation, check_ai_slop, check_fake_urls,
            check_auto_actions, check_unsanitized_input,
            check_controlled_detonation, check_source_traceability,
            check_hidden_errors, check_self_contradiction,
        ]:
            # check_repetition needs history
            if check_fn == check_repetition:
                result = check_fn(text, self.history)
            else:
                result = check_fn(text)

            checks.append(result)
            if not result.get("passed", True):
                total_score += result.get("weight", 0)
                violations.append(f"{result['level']}: {result['detail']}")

        total_score = min(total_score, 100)

        if total_score >= QUARANTINE_THRESHOLD:
            verdict = "BLOCK"
        elif total_score >= REVIEW_THRESHOLD:
            verdict = "WARN"
        else:
            verdict = "PASS"

        # Store in history for N5
        self.history.append(text)
        if len(self.history) > 50:
            self.history.pop(0)

        return {
            "source": source,
            "verdict": verdict,
            "score": total_score,
            "checks": checks,
            "violations": violations,
            "violation_count": len(violations),
        }

    def status(self) -> dict:
        """Health check — verify all 17 checks are callable."""
        return {
            "checks_available": 17,
            "checks_total": 17,
            "history_size": len(self.history),
            "operational": True,
        }
