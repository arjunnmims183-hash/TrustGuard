"""
secret_scanner.py
-----------------
Detects hardcoded secrets in Python source code using two methods:

  1. Regex patterns  - matches known secret formats (API keys, tokens,
                       AWS credentials, private keys, passwords, etc.)

  2. Shannon entropy - any string literal with very high randomness
                       (>= 4.5 bits/char) and length >= 20 chars is
                       flagged as a potential encoded secret or key,
                       even if it doesn't match a known pattern.

Each finding includes:
    method      - "regex" or "entropy"
    pattern     - which pattern matched (regex only)
    value       - the matched/suspicious string (truncated for display)
    lineno      - line number in source
    severity    - LOW / MEDIUM / HIGH
    reason      - plain-English explanation
"""

import re
import math
from typing import List, Dict, Any, Set, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.secret_patterns import (
    SECRET_PATTERNS,
    SECRET_CHARSET,
    ENTROPY_THRESHOLD,
    MIN_SECRET_LENGTH,
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _truncate(value: str, max_len: int) -> str:
    """Truncate a string for display, appending '...' if cut."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."


def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy (bits per character) of a string.
    A perfectly random string of 64 printable chars has ~6 bits/char.
    Normal English text is around 3.5-4.0 bits/char.
    """
    if not s:
        return 0.0
    
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _is_mostly_secret_chars(s: str) -> bool:
    """
    Return True if >80% of the string's characters are in the secret charset.
    This avoids flagging long natural-language strings (error messages, etc.)
    """
    if not s:
        return False
    
    secret_count = sum(1 for ch in s if ch in SECRET_CHARSET)
    return (secret_count / len(s)) >= 0.80


def _format_finding(
    method: str,
    pattern: str,
    value: str,
    lineno: int,
    severity: str,
    reason: str
) -> Dict[str, Any]:
    """
    Create a standardized finding dictionary.
    """
    return {
        "method": method,
        "pattern": pattern,
        "value": _truncate(value, 60),
        "lineno": lineno,
        "severity": severity,
        "reason": reason,
    }


# ==========================================
# SCANNING FUNCTIONS
# ==========================================

def _regex_scan(source: str) -> List[Dict[str, Any]]:
    """
    Scan source line-by-line with each pattern and collect matches.
    """
    findings = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, start=1):
        for name, pattern, severity, reason in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(0)
                findings.append(_format_finding(
                    "regex", name, value, lineno, severity, reason
                ))

    return findings


def _entropy_scan(source: str) -> List[Dict[str, Any]]:
    """
    Find all string literals, compute Shannon entropy, and flag
    anything that is long enough and random enough to be a secret.

    We use a simple regex rather than the AST so we catch strings
    inside comments or triple-quoted blocks too.
    """
    findings = []
    lines = source.splitlines()

    # Match both single and double quoted strings (non-greedy, single line)
    string_pattern = re.compile(
        r"(['\"])((?:(?!\1).){" + str(MIN_SECRET_LENGTH) + r",})\1"
    )

    for lineno, line in enumerate(lines, start=1):
        for match in string_pattern.finditer(line):
            value = match.group(2)
            
            if _is_mostly_secret_chars(value):
                entropy = _shannon_entropy(value)
                
                if entropy >= ENTROPY_THRESHOLD:
                    findings.append(_format_finding(
                        "entropy",
                        "High-entropy string",
                        value,
                        lineno,
                        "MEDIUM",
                        (
                            f"String with Shannon entropy {entropy:.2f} bits/char "
                            f"(threshold: {ENTROPY_THRESHOLD}) — likely an encoded "
                            "secret, key, or obfuscated payload."
                        ),
                    ))

    return findings


# ==========================================
# MAIN DETECTION FUNCTION
# ==========================================

def detect_secrets(source: str) -> List[Dict[str, Any]]:
    """
    Run both regex and entropy scanning on raw source code.
    Returns a deduplicated, line-sorted list of findings.
    """
    findings = []

    regex_hits = _regex_scan(source)
    entropy_hits = _entropy_scan(source)

    findings.extend(regex_hits)
    findings.extend(entropy_hits)

    # Deduplicate by (lineno, value) to avoid double-reporting the same string
    seen = set()
    unique = []
    for f in findings:
        key = (f["lineno"], f["value"][:40])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: f["lineno"])
    return unique


# ==========================================
# LEGACY SUPPORT
# ==========================================

def detect_secrets_legacy(source: str) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return detect_secrets(source)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "detect_secrets",
    "detect_secrets_legacy",
    "SECRET_PATTERNS",
]