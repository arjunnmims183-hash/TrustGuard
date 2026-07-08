"""
dependency_scanner.py
---------------------
Scans a requirements.txt file for:

  1. Known malicious packages  - packages documented in supply-chain attacks
  2. Typosquatting candidates  - names very close to popular packages
  3. Risky-by-nature packages  - packages that are legitimate but have
                                  historically been vectors for supply-chain risk

Each finding includes:
    package     - package name from requirements.txt
    version     - version specifier (if any)
    lineno      - line number in requirements.txt
    severity    - LOW / MEDIUM / HIGH
    flag_type   - "known_malicious" / "typosquatting" / "risky_package"
    reason      - plain-English explanation
"""

import re
from typing import List, Dict, Any, Optional, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.dependency_risks import (
    KNOWN_MALICIOUS,
    POPULAR_PACKAGES,
    RISKY_PACKAGES,
    SEVERITY_ORDER,
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _edit_distance(a: str, b: str) -> int:
    """
    Standard dynamic-programming Levenshtein distance.
    Fast enough for short package names.
    """
    if abs(len(a) - len(b)) > 2:
        return 99  # early exit — too different to be a typosquat
    
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[j] = prev[j - 1]
            else:
                dp[j] = 1 + min(prev[j], dp[j - 1], prev[j - 1])
    
    return dp[n]


def _parse_requirement_line(line: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse a line like 'requests==2.28.0' or 'numpy>=1.21' or 'flask'
    Returns (package_name, version_specifier_or_empty_string).
    """
    # Strip inline comments
    line = line.split("#")[0].strip()
    
    # Match package name (allowing hyphens and underscores) + optional version
    match = re.match(r"^([A-Za-z0-9]([A-Za-z0-9\-_.]*[A-Za-z0-9])?)(.*)?$", line)
    if match:
        return match.group(1), match.group(3).strip()
    
    return None, None


def _check_typosquatting(package: str) -> str:
    """
    Check if a package name is suspiciously close to a known popular package
    using Levenshtein edit distance. Returns the target name if distance == 1,
    empty string otherwise.
    """
    for popular in POPULAR_PACKAGES:
        if package == popular:
            return ""  # exact match — not a typosquat
        if _edit_distance(package, popular) == 1:
            return popular
    return ""


def _format_finding(
    package: str,
    version: str,
    lineno: int,
    severity: str,
    flag_type: str,
    reason: str,
) -> Dict[str, Any]:
    """
    Create a standardized finding dictionary.
    """
    return {
        "package": package,
        "version": version,
        "lineno": lineno,
        "severity": severity,
        "flag_type": flag_type,
        "reason": reason,
    }


# ==========================================
# MAIN SCANNING FUNCTION
# ==========================================

def scan_dependencies(filepath: str) -> List[Dict[str, Any]]:
    """
    Parse a requirements.txt file and flag suspicious packages.

    Returns a list of findings sorted by severity and line number.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return [{"error": f"File not found: {filepath}"}]

    findings = []
    
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        package, version = _parse_requirement_line(line)
        if not package:
            continue

        package_lower = package.lower()

        # =====================================
        # Check 1: Known Malicious
        # =====================================
        if package_lower in KNOWN_MALICIOUS:
            findings.append(_format_finding(
                package=package,
                version=version,
                lineno=lineno,
                severity="HIGH",
                flag_type="known_malicious",
                reason=KNOWN_MALICIOUS[package_lower],
            ))
            continue  # no need to check further for this package

        # =====================================
        # Check 2: Typosquatting
        # =====================================
        typo_target = _check_typosquatting(package_lower)
        if typo_target:
            findings.append(_format_finding(
                package=package,
                version=version,
                lineno=lineno,
                severity="HIGH",
                flag_type="typosquatting",
                reason=(
                    f"'{package}' is suspiciously close to the popular package "
                    f"'{typo_target}' — possible typosquatting attack."
                ),
            ))
            continue

        # =====================================
        # Check 3: Risky by Nature
        # =====================================
        if package_lower in RISKY_PACKAGES:
            severity, reason = RISKY_PACKAGES[package_lower]
            findings.append(_format_finding(
                package=package,
                version=version,
                lineno=lineno,
                severity=severity,
                flag_type="risky_package",
                reason=reason,
            ))

    # Sort by severity (HIGH → MEDIUM → LOW) then by line number
    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f.get("severity", "LOW"), 2),
            f["lineno"]
        )
    )
    
    return findings


# ==========================================
# LEGACY SUPPORT
# ==========================================

def scan_dependencies_legacy(filepath: str) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return scan_dependencies(filepath)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "scan_dependencies",
    "scan_dependencies_legacy",
]