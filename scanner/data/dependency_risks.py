"""
dependency_risks.py
-------------------
Dependency risk data for dependency_scanner.py.
Contains:
    1. Known malicious packages
    2. Popular packages (for typosquatting detection)
    3. Risky-by-nature packages
"""

from typing import Dict, Tuple, List

# ==========================================
# Known Malicious Packages
# ==========================================

KNOWN_MALICIOUS: Dict[str, str] = {
    # (package_name: reason)
    "colourama": "Typosquat of 'colorama' — known to exfiltrate data on install.",
    "python-mongo": "Malicious package impersonating MongoDB drivers.",
    "jeIlyfish": "Typosquat of 'jellyfish' — contained credential-stealing code.",
    "bs4-requests": "Unofficial combo package — contained a backdoor.",
    "request": "Typosquat of 'requests' — popular supply-chain attack target.",
    "urlib": "Typosquat of 'urllib' — impersonates a standard library.",
    "urllib2": "Impersonates Python 2's urllib2, not a valid Python 3 package.",
    "urllib3-patch": "Unofficial patch package — documented to contain malicious code.",
    "cryptocheck": "Cryptomining package distributed under a misleading name.",
    "setup-tools": "Typosquat of 'setuptools' with hyphen — known malicious.",
    "python-dateutils": "Typosquat of 'python-dateutil' — known exfiltration payload.",
    "loguru-config": "Unofficial extension of loguru — contained a backdoor.",
    "discordapp": "Unofficial Discord package — credential harvester.",
    "importantpackage": "Known test/attack package used in supply-chain demonstrations.",
    "noblesse": "Known malware package targeting Discord tokens.",
    "pyquest": "Known credential-stealer masquerading as a utility.",
    "py-bcrypt": "Impersonates 'bcrypt' — documented malicious payload.",
}


# ==========================================
# Popular Packages (for Typosquatting Detection)
# ==========================================

POPULAR_PACKAGES: List[str] = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "sqlalchemy", "celery", "boto3", "paramiko", "cryptography",
    "pillow", "setuptools", "colorama", "tqdm", "click", "pydantic",
    "pytest", "scipy", "matplotlib", "tensorflow", "torch", "scikit-learn",
    "urllib3", "certifi", "charset-normalizer", "idna", "six", "attrs",
    "pytz", "dateutil", "loguru", "httpx", "aiohttp", "uvicorn", "gunicorn",
]


# ==========================================
# Risky-by-Nature Packages
# ==========================================

RISKY_PACKAGES: Dict[str, Tuple[str, str]] = {
    # (package_name: (severity, reason))
    
    # Packing / Obfuscation
    "pyinstaller": ("MEDIUM", "Packages Python apps into standalone executables — can be used to distribute malware."),
    "py2exe": ("MEDIUM", "Same as pyinstaller — executable packing for Windows."),
    "nuitka": ("MEDIUM", "Python compiler that can obscure source code."),
    "obfuscator": ("HIGH", "Explicit obfuscation tool — no legitimate forensic justification."),
    
    # Input Capture / Keylogging
    "pynput": ("HIGH", "Captures keyboard and mouse input — primary keylogging library."),
    "keyboard": ("HIGH", "Hooks into keyboard events globally — keylogger vector."),
    "mouse": ("MEDIUM", "Hooks into mouse events globally — surveillance vector."),
    "pyperclip": ("MEDIUM", "Reads and writes clipboard content — can harvest copied passwords."),
    
    # Surveillance
    "pygetwindow": ("MEDIUM", "Captures window titles — can reveal what the user is doing."),
    "mss": ("MEDIUM", "Screen capture library — surveillance vector."),
    "pillow": ("LOW", "Image library — legitimate, but sometimes used to encode data in images (steganography)."),
    
    # Network / Pentesting
    "scapy": ("HIGH", "Low-level network packet crafting — reconnaissance and attack tool."),
    "impacket": ("HIGH", "Network protocols library used in many penetration testing tools."),
    
    # Windows / System Access
    "pywin32": ("MEDIUM", "Deep Windows API access — can manipulate processes, registry, services."),
    "winshell": ("MEDIUM", "Windows shell integration — can create startup shortcuts (persistence)."),
    
    # Scheduling / Persistence
    "schedule": ("LOW", "Task scheduling — can be used to create time-based triggers (logic bombs)."),
    "apscheduler": ("LOW", "Advanced scheduler — same concern as 'schedule'."),
    
    # Automation
    "pyautogui": ("MEDIUM", "GUI automation — can simulate user input to bypass interactive prompts."),
    "selenium": ("LOW", "Browser automation — can be used to scrape credentials from web sessions."),
    "mechanize": ("MEDIUM", "Headless HTTP browser — credential harvesting and automated access."),
}

# ==========================================
# SEVERITY ORDER (for sorting)
# ==========================================

SEVERITY_ORDER = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}

# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "KNOWN_MALICIOUS",
    "POPULAR_PACKAGES",
    "RISKY_PACKAGES",
    "SEVERITY_ORDER",
]