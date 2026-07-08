"""
scoring_weights.py
------------------
Weight configurations for scoring.py.
All scoring parameters are defined here for easy tuning.
"""

from typing import Dict, Any

# ==========================================
# WEIGHT CONFIGURATIONS
# ==========================================

# Dangerous API weights — by category
CATEGORY_WEIGHTS: Dict[str, int] = {
    "Code Execution": 25,
    "Network": 20,
    "Obfuscation": 15,
    "Unsafe Deserial.": 20,
    "Credential Theft": 20,
    "Persistence": 20,
    "Reconnaissance": 5,
    "File Access": 10,
    "System Access": 5,
    "Crypto": 5,
    "Execution": 5,
    "Destructive": 15,
}

# Severity multipliers
SEVERITY_MULTIPLIER: Dict[str, float] = {
    "HIGH": 1.0,
    "MEDIUM": 0.6,
    "LOW": 0.3,
}

# Per-finding-type weights
SECRET_WEIGHT: int = 15
VULNERABLE_DEP_WEIGHT: int = 15
KNOWN_MALICIOUS_DEP: int = 30
BACKDOOR_WEIGHT: int = 30

# Vulnerability weights by category
VULNERABILITY_WEIGHTS: Dict[str, int] = {
    "SQL Injection": 25,
    "Command Injection": 25,
    "Weak Cryptography": 10,
    "Insecure Deserialization": 20,
    "Path Traversal": 15,
    "Insecure Configuration": 10,
    "Anti-Forensics": 20,
    "Persistence": 20,
    "Cryptomining": 25,
    "Code Execution": 25,
}

# Obfuscation weights by severity
OBFUSCATION_WEIGHTS: Dict[str, int] = {
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}

# Behavioral chain weights by confidence level
CHAIN_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 50,
    "HIGH": 40,
    "MEDIUM": 25,
    "LOW": 10,
}

# Logic bomb weights
LOGIC_BOMB_WEIGHT: int = 35

# Correlation bonus weights
CORRELATION_BONUSES: Dict[str, Dict[str, Any]] = {
    "data_exfiltration_chain": {
        "points": 40,
        "description": "File access + obfuscation/encoding + network transmission",
    },
    "credential_exfiltration": {
        "points": 35,
        "description": "Hardcoded credentials present + network activity",
    },
    "remote_code_execution_backdoor": {
        "points": 40,
        "description": "Backdoor pattern + code execution capability",
    },
    "persistent_c2_callback": {
        "points": 35,
        "description": "Persistence mechanism + network access",
    },
    "system_fingerprinting": {
        "points": 20,
        "description": "System reconnaissance + network access",
    },
    "persistent_self_destructing": {
        "points": 30,
        "description": "Destructive file operations + persistence",
    },
    "full_kill_chain": {
        "points": 50,
        "description": "Reconnaissance + code execution + persistence + network",
    },
}

# ==========================================
# MAXIMUM CAPS
# ==========================================

CAPS: Dict[str, int] = {
    "dangerous_apis": 40,
    "secrets": 25,
    "vulnerabilities": 35,
    "backdoors": 40,
    "obfuscation": 25,
    "dependencies": 30,
    "behavioral_chains": 60,
    "logic_bombs": 40,
    "correlation_bonuses": 60,
}

# ==========================================
# RISK THRESHOLDS
# ==========================================

RISK_THRESHOLDS: Dict[str, int] = {
    "Safe": 20,
    "Low Risk": 45,
    "Suspicious": 70,
    "High Risk": 89,
}

# ==========================================
# OTHER CONFIGURATIONS
# ==========================================

DIMINISHING_FACTOR: float = 0.3

# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "CATEGORY_WEIGHTS",
    "SEVERITY_MULTIPLIER",
    "SECRET_WEIGHT",
    "VULNERABLE_DEP_WEIGHT",
    "KNOWN_MALICIOUS_DEP",
    "BACKDOOR_WEIGHT",
    "VULNERABILITY_WEIGHTS",
    "OBFUSCATION_WEIGHTS",
    "CHAIN_WEIGHTS",
    "LOGIC_BOMB_WEIGHT",
    "CORRELATION_BONUSES",
    "CAPS",
    "RISK_THRESHOLDS",
    "DIMINISHING_FACTOR",
]