"""
backdoor_patterns.py
--------------------
Backdoor detection patterns for backdoor_detector.py.
Each entry: (pattern_name, regex, severity, category, reason)
"""

import re
from typing import List, Tuple, Pattern

# ==========================================
# LINE-BASED BACKDOOR PATTERNS
# ==========================================

LINE_RULES: List[Tuple[str, Pattern, str, str, str]] = [
    # (pattern_name, compiled_regex, severity, category, reason)
    
    # =====================================
    # Hardcoded Credential Bypass
    # =====================================
    (
        "Hardcoded password comparison",
        re.compile(r'(password|passwd|pwd|pass)\s*(==|!=|is)\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
        "HIGH",
        "Hardcoded Credential Bypass",
        "Password compared against a hardcoded string — classic backdoor pattern.",
    ),
    (
        "Hardcoded token/key comparison",
        re.compile(r'(token|api_key|apikey|secret|auth_key)\s*(==|!=)\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "HIGH",
        "Hardcoded Credential Bypass",
        "Authentication token or key compared against a hardcoded value — backdoor access pattern.",
    ),
    (
        "Hardcoded username comparison",
        re.compile(r'(username|user|login|account)\s*(==|!=)\s*["\'][^"\']{2,}["\']', re.IGNORECASE),
        "HIGH",
        "Hardcoded Credential Bypass",
        "Username compared against a hardcoded string — may be a hidden admin account check.",
    ),
    
    # =====================================
    # Authentication Bypass
    # =====================================
    (
        "Always-true auth condition",
        re.compile(r'if\s+(True|1\s*==\s*1|0\s*==\s*0)\s*:', re.IGNORECASE),
        "HIGH",
        "Authentication Bypass",
        "Condition always evaluates to True — any auth check here is permanently bypassed.",
    ),
    (
        "Commented-out auth check",
        re.compile(r'#.*\b(auth|authenticate|verify|check_password|login_required)\b', re.IGNORECASE),
        "MEDIUM",
        "Authentication Bypass",
        "Authentication/verification function appears to be commented out — security check may have been disabled.",
    ),
    
    # =====================================
    # Hidden Admin Account
    # =====================================
    (
        "Hardcoded admin account",
        re.compile(r'(admin|root|superuser|su|administrator)\s*(==|!=)\s*["\'][^"\']+["\']', re.IGNORECASE),
        "HIGH",
        "Hidden Admin Account",
        "Hardcoded admin/root account comparison — hidden privileged access backdoor.",
    ),
    
    # =====================================
    # Hidden Endpoint (Web)
    # =====================================
    (
        "Hidden route — suspicious path",
        re.compile(r'@(app|router|blueprint)\.(route|get|post|put|delete)\s*\(\s*["\']/(shell|backdoor|cmd|command|exec|hidden|secret|admin_[a-z]+)["\']', re.IGNORECASE),
        "HIGH",
        "Hidden Endpoint",
        "Web route registered at a suspicious path — possible hidden backdoor endpoint.",
    ),
    (
        "Hidden route — long random path",
        re.compile(r'@(app|router|blueprint)\.(route|get|post|put|delete)\s*\(\s*["\']/[a-f0-9]{16,}["\']', re.IGNORECASE),
        "HIGH",
        "Hidden Endpoint",
        "Web route at a hex-like random path — likely an undocumented backdoor endpoint.",
    ),
    
    # =====================================
    # Remote Code Execution Backdoor
    # =====================================
    (
        "Input-triggered command execution",
        re.compile(r'(os\.system|subprocess\.(run|call|Popen))\s*\([^)]*(?:request|input|arg|param|data|body)[^)]*\)', re.IGNORECASE),
        "HIGH",
        "Remote Code Execution Backdoor",
        "System command executed with what appears to be user-supplied input — remote code execution backdoor.",
    ),
    (
        "eval/exec on received data",
        re.compile(r'(eval|exec)\s*\([^)]*(?:request|recv|data|payload|body|input|arg)[^)]*\)', re.IGNORECASE),
        "HIGH",
        "Remote Code Execution Backdoor",
        "eval() or exec() called with what appears to be received/user data — allows arbitrary code execution by attacker.",
    ),
    
    # =====================================
    # Reverse Shell
    # =====================================
    (
        "Reverse shell — socket + exec",
        re.compile(r'(socket\.socket|s\.connect)\s*\(.*\)', re.IGNORECASE),
        "MEDIUM",
        "Potential Reverse Shell",
        "Socket connection pattern — combined with subprocess or exec calls this can establish a reverse shell.",
    ),
    (
        "Reverse shell — pty spawn",
        re.compile(r'pty\.spawn|os\.dup2\s*\(.*socket|bash.*-i', re.IGNORECASE),
        "HIGH",
        "Reverse Shell",
        "PTY spawn or socket duplication pattern — signature of a reverse shell payload.",
    ),
    
    # =====================================
    # Conditional Backdoor
    # =====================================
    (
        "Environment-gated backdoor",
        re.compile(r'if\s+os\.(getenv|environ)\s*\([^)]+\)\s*(==|!=|in)\s*["\'][^"\']+["\'].*:', re.IGNORECASE),
        "MEDIUM",
        "Conditional Backdoor",
        "Code execution gated on a specific environment variable value — possible environment-triggered backdoor.",
    ),
    (
        "Hostname-gated execution",
        re.compile(r'(socket\.gethostname|platform\.node)\s*\(\s*\)\s*(==|!=|in)\s*["\']', re.IGNORECASE),
        "HIGH",
        "Conditional Backdoor",
        "Code execution gated on the system hostname — will only activate on a specific target machine.",
    ),
]

# ==========================================
# AUTH FUNCTION NAMES (for AST detection)
# ==========================================

AUTH_FUNCTION_NAMES = {
    "is_admin",
    "is_authenticated",
    "check_auth",
    "verify_password",
    "authenticate",
    "is_superuser",
    "check_permission",
    "has_permission",
    "is_authorized",
    "validate_user",
    "check_credentials",
}


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "LINE_RULES",
    "AUTH_FUNCTION_NAMES",
]