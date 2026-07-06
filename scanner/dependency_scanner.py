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
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Known malicious packages
# (documented in PyPI security advisories and supply-chain research)
# ---------------------------------------------------------------------------

KNOWN_MALICIOUS = {
    "colourama":        "Typosquat of 'colorama' — known to exfiltrate data on install.",
    "python-mongo":     "Malicious package impersonating MongoDB drivers.",
    "jeIlyfish":        "Typosquat of 'jellyfish' — contained credential-stealing code.",
    "bs4-requests":     "Unofficial combo package — contained a backdoor.",
    "request":          "Typosquat of 'requests' — popular supply-chain attack target.",
    "urlib":            "Typosquat of 'urllib' — impersonates a standard library.",
    "urllib2":          "Impersonates Python 2's urllib2, not a valid Python 3 package.",
    "urllib3-patch":    "Unofficial patch package — documented to contain malicious code.",
    "cryptocheck":      "Cryptomining package distributed under a misleading name.",
    "setup-tools":      "Typosquat of 'setuptools' with hyphen — known malicious.",
    "python-dateutils": "Typosquat of 'python-dateutil' — known exfiltration payload.",
    "loguru-config":    "Unofficial extension of loguru — contained a backdoor.",
    "discordapp":       "Unofficial Discord package — credential harvester.",
    "importantpackage": "Known test/attack package used in supply-chain demonstrations.",
    "noblesse":         "Known malware package targeting Discord tokens.",
    "pyquest":          "Known credential-stealer masquerading as a utility.",
    "py-bcrypt":        "Impersonates 'bcrypt' — documented malicious payload.",
}


# ---------------------------------------------------------------------------
# Typosquatting detection
# Popular packages that are commonly impersonated
# ---------------------------------------------------------------------------

POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "sqlalchemy", "celery", "boto3", "paramiko", "cryptography",
    "pillow", "setuptools", "colorama", "tqdm", "click", "pydantic",
    "pytest", "scipy", "matplotlib", "tensorflow", "torch", "scikit-learn",
    "urllib3", "certifi", "charset-normalizer", "idna", "six", "attrs",
    "pytz", "dateutil", "loguru", "httpx", "aiohttp", "uvicorn", "gunicorn",
]


# ---------------------------------------------------------------------------
# Risky-by-nature packages
# Legitimate but historically used as supply-chain vectors or pose risk
# ---------------------------------------------------------------------------

RISKY_PACKAGES = {
    "pyinstaller": ("MEDIUM", "Packages Python apps into standalone executables — can be used to distribute malware."),
    "py2exe":      ("MEDIUM", "Same as pyinstaller — executable packing for Windows."),
    "nuitka":      ("MEDIUM", "Python compiler that can obscure source code."),
    "obfuscator":  ("HIGH",   "Explicit obfuscation tool — no legitimate forensic justification."),
    "pynput":      ("HIGH",   "Captures keyboard and mouse input — primary keylogging library."),
    "keyboard":    ("HIGH",   "Hooks into keyboard events globally — keylogger vector."),
    "mouse":       ("MEDIUM", "Hooks into mouse events globally — surveillance vector."),
    "pyperclip":   ("MEDIUM", "Reads and writes clipboard content — can harvest copied passwords."),
    "pygetwindow": ("MEDIUM", "Captures window titles — can reveal what the user is doing."),
    "mss":         ("MEDIUM", "Screen capture library — surveillance vector."),
    "pillow":      ("LOW",    "Image library — legitimate, but sometimes used to encode data in images (steganography)."),
    "scapy":       ("HIGH",   "Low-level network packet crafting — reconnaissance and attack tool."),
    "impacket":    ("HIGH",   "Network protocols library used in many penetration testing tools."),
    "pywin32":     ("MEDIUM", "Deep Windows API access — can manipulate processes, registry, services."),
    "winshell":    ("MEDIUM", "Windows shell integration — can create startup shortcuts (persistence)."),
    "schedule":    ("LOW",    "Task scheduling — can be used to create time-based triggers (logic bombs)."),
    "apscheduler": ("LOW",    "Advanced scheduler — same concern as 'schedule'."),
    "pyautogui":   ("MEDIUM", "GUI automation — can simulate user input to bypass interactive prompts."),
    "selenium":    ("LOW",    "Browser automation — can be used to scrape credentials from web sessions."),
    "mechanize":   ("MEDIUM", "Headless HTTP browser — credential harvesting and automated access."),
}


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
        if not line or line.startswith("#"):
            continue

        package, version = _parse_requirement_line(line)
        if not package:
            continue

        package_lower = package.lower()

        # Check 1: Known malicious
        if package_lower in KNOWN_MALICIOUS:
            findings.append({
                "package": package,
                "version": version,
                "lineno": lineno,
                "severity": "HIGH",
                "flag_type": "known_malicious",
                "reason": KNOWN_MALICIOUS[package_lower],
            })
            continue  # no need to check further for this package

        # Check 2: Typosquatting
        typo_target = _check_typosquatting(package_lower)
        if typo_target:
            findings.append({
                "package": package,
                "version": version,
                "lineno": lineno,
                "severity": "HIGH",
                "flag_type": "typosquatting",
                "reason": (
                    f"'{package}' is suspiciously close to the popular package "
                    f"'{typo_target}' — possible typosquatting attack."
                ),
            })
            continue

        # Check 3: Risky by nature
        if package_lower in RISKY_PACKAGES:
            severity, reason = RISKY_PACKAGES[package_lower]
            findings.append({
                "package": package,
                "version": version,
                "lineno": lineno,
                "severity": severity,
                "flag_type": "risky_package",
                "reason": reason,
            })

    findings.sort(key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.get("severity", "LOW"), 3), f["lineno"]))
    return findings


def _parse_requirement_line(line: str):
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
