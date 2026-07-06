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
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Regex-based secret patterns
# Each entry: (pattern_name, compiled_regex, severity, reason)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    (
        "AWS Access Key ID",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "HIGH",
        "Matches the format of an AWS Access Key ID.",
    ),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)(aws.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
        "HIGH",
        "Matches a potential AWS Secret Access Key (40-char base64-like string).",
    ),
    (
        "Generic API Key",
        re.compile(r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9\-_\.]{16,}['\"]"),
        "HIGH",
        "Hardcoded API key assignment detected.",
    ),
    (
        "Generic Secret/Token",
        re.compile(r"(?i)(secret|token|auth|passwd|password|pwd|pass)\s*[=:]\s*['\"][A-Za-z0-9\-_\.!@#$%^&*]{8,}['\"]"),
        "HIGH",
        "Hardcoded secret, token, or password assignment detected.",
    ),
    (
        "GitHub Token",
        re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
        "HIGH",
        "Matches a GitHub personal access, OAuth, or fine-grained token.",
    ),
    (
        "Slack Token",
        re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        "HIGH",
        "Matches a Slack API token.",
    ),
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "HIGH",
        "Matches a Google API key format.",
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "HIGH",
        "Private key material found in source code.",
    ),
    (
        "Basic Auth in URL",
        re.compile(r"https?://[A-Za-z0-9\-_.]+:[A-Za-z0-9\-_.@!#$%^&*]+@"),
        "HIGH",
        "Username and password embedded directly in a URL.",
    ),
    (
        "Database Connection String",
        re.compile(r"(?i)(mysql|postgresql|postgres|mongodb|sqlite|mssql|oracle)://[^\s'\"]+:[^\s'\"]+@"),
        "HIGH",
        "Database connection string with embedded credentials.",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "MEDIUM",
        "JSON Web Token (JWT) hardcoded in source — should not be stored in code.",
    ),
    (
        "IP Address (Hardcoded)",
        re.compile(r"(?<![.\d])(\d{1,3}\.){3}\d{1,3}(?![.\d])"),
        "LOW",
        "Hardcoded IP address — could indicate C2 server or hardcoded infrastructure.",
    ),
    (
        "Email Address",
        re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
        "LOW",
        "Email address embedded in source — could be an account credential or contact.",
    ),
]

# ---------------------------------------------------------------------------
# Entropy configuration
# ---------------------------------------------------------------------------

# Characters commonly found in secrets (base64, hex, alphanumeric+symbols)
SECRET_CHARSET = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-")

ENTROPY_THRESHOLD = 4.5   # bits per character; >4.5 is very high randomness
MIN_SECRET_LENGTH = 20    # only flag strings this long or longer


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
                findings.append({
                    "method": "regex",
                    "pattern": name,
                    "value": _truncate(value, 60),
                    "lineno": lineno,
                    "severity": severity,
                    "reason": reason,
                })

    return findings


def _entropy_scan(source: str) -> List[Dict[str, Any]]:
    """
    Find all string literals, compute Shannon entropy, and flag
    anything that is long enough and random enough to be a secret.

    We re-parse here with a simple regex rather than the AST so we
    catch strings inside comments or triple-quoted blocks too.
    """
    findings = []
    lines = source.splitlines()

    # Match both single and double quoted strings (non-greedy, single line)
    string_pattern = re.compile(r"(['\"])((?:(?!\1).){" + str(MIN_SECRET_LENGTH) + r",})\1")

    for lineno, line in enumerate(lines, start=1):
        for match in string_pattern.finditer(line):
            value = match.group(2)
            if _is_mostly_secret_chars(value):
                entropy = _shannon_entropy(value)
                if entropy >= ENTROPY_THRESHOLD:
                    findings.append({
                        "method": "entropy",
                        "pattern": "High-entropy string",
                        "value": _truncate(value, 60),
                        "lineno": lineno,
                        "severity": "MEDIUM",
                        "reason": (
                            f"String with Shannon entropy {entropy:.2f} bits/char "
                            f"(threshold: {ENTROPY_THRESHOLD}) — likely an encoded "
                            "secret, key, or obfuscated payload."
                        ),
                    })

    return findings


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


def _truncate(value: str, max_len: int) -> str:
    """Truncate a string for display, appending '...' if cut."""
    if len(value) <= max_len:
        return value
    return value[:max_len] + "..."
