"""
secret_patterns.py
------------------
Secret detection patterns for secret_scanner.py.
Each entry: (pattern_name, compiled_regex, severity, reason)
"""

import re
from typing import List, Tuple, Pattern

SECRET_PATTERNS: List[Tuple[str, Pattern, str, str]] = [
    # (pattern_name, compiled_regex, severity, reason)
    
    # =====================================
    # Cloud Credentials
    # =====================================
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
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "HIGH",
        "Matches a Google API key format.",
    ),
    
    # =====================================
    # API Tokens / Keys
    # =====================================
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
    
    # =====================================
    # Platform Tokens
    # =====================================
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
    
    # =====================================
    # Private Keys
    # =====================================
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "HIGH",
        "Private key material found in source code.",
    ),
    
    # =====================================
    # Credentials in URLs / Connection Strings
    # =====================================
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
    
    # =====================================
    # Tokens / JWTs
    # =====================================
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "MEDIUM",
        "JSON Web Token (JWT) hardcoded in source — should not be stored in code.",
    ),
    
    # =====================================
    # Infrastructure Indicators
    # =====================================
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
    
    # =====================================
    # Additional Cloud Credentials
    # =====================================
    (
        "Azure Storage Account Key",
        re.compile(r"(?i)(azure|storage).{0,20}['\"][A-Za-z0-9+/=]{88}['\"]"),
        "HIGH",
        "Matches an Azure Storage Account Key format.",
    ),
    (
        "GCP Service Account Key",
        re.compile(r"-----BEGIN PRIVATE KEY-----(?:.|\n)*?-----END PRIVATE KEY-----"),
        "HIGH",
        "GCP service account private key found in source.",
    ),
]

# ==========================================
# ENTROPY CONFIGURATION
# ==========================================

# Characters commonly found in secrets (base64, hex, alphanumeric+symbols)
SECRET_CHARSET = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-")

ENTROPY_THRESHOLD = 4.5   # bits per character; >4.5 is very high randomness
MIN_SECRET_LENGTH = 20    # only flag strings this long or longer


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "SECRET_PATTERNS",
    "SECRET_CHARSET",
    "ENTROPY_THRESHOLD",
    "MIN_SECRET_LENGTH",
]