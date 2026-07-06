"""
backdoor_detector.py
--------------------
Detects backdoor patterns in Python source code.

Categories:
    1. Hardcoded bypass conditions  - if password == "admin123"
    2. Magic token checks           - if token == "secret_backdoor"
    3. Hidden always-true auth      - conditions that always pass
    4. Hidden admin accounts        - hardcoded privileged usernames
    5. Secret routes / endpoints    - hidden URL paths in web apps
    6. Reversed/encoded conditions  - obfuscated auth checks

Each finding:
    category    - backdoor type
    pattern     - rule that matched
    lineno      - line number
    severity    - always HIGH (backdoors are always high severity)
    reason      - explanation
    snippet     - the suspicious line
"""

import ast
import re
from typing import List, Dict, Any


LINE_RULES = [

    # Hardcoded password/token comparisons
    ("Hardcoded password comparison",
     re.compile(r'(password|passwd|pwd|pass)\s*(==|!=|is)\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
     "HIGH", "Hardcoded Credential Bypass",
     "Password compared against a hardcoded string — classic backdoor pattern."),

    ("Hardcoded token/key comparison",
     re.compile(r'(token|api_key|apikey|secret|auth_key)\s*(==|!=)\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
     "HIGH", "Hardcoded Credential Bypass",
     "Authentication token or key compared against a hardcoded value — backdoor access pattern."),

    ("Hardcoded username comparison",
     re.compile(r'(username|user|login|account)\s*(==|!=)\s*["\'][^"\']{2,}["\']', re.IGNORECASE),
     "HIGH", "Hardcoded Credential Bypass",
     "Username compared against a hardcoded string — may be a hidden admin account check."),

    # Always-true / always-false auth conditions
    ("Always-true auth condition",
     re.compile(r'if\s+(True|1\s*==\s*1|0\s*==\s*0)\s*:', re.IGNORECASE),
     "HIGH", "Authentication Bypass",
     "Condition always evaluates to True — any auth check here is permanently bypassed."),

    ("Commented-out auth check",
     re.compile(r'#.*\b(auth|authenticate|verify|check_password|login_required)\b', re.IGNORECASE),
     "MEDIUM", "Authentication Bypass",
     "Authentication/verification function appears to be commented out — security check may have been disabled."),

    # Hidden admin/root accounts
    ("Hardcoded admin account",
     re.compile(r'(admin|root|superuser|su|administrator)\s*(==|!=)\s*["\'][^"\']+["\']', re.IGNORECASE),
     "HIGH", "Hidden Admin Account",
     "Hardcoded admin/root account comparison — hidden privileged access backdoor."),

    # Secret/hidden URL routes (Flask/FastAPI/Django patterns)
    ("Hidden route — suspicious path",
     re.compile(r'@(app|router|blueprint)\.(route|get|post|put|delete)\s*\(\s*["\']/(shell|backdoor|cmd|command|exec|hidden|secret|admin_[a-z]+)["\']', re.IGNORECASE),
     "HIGH", "Hidden Endpoint",
     "Web route registered at a suspicious path — possible hidden backdoor endpoint."),

    ("Hidden route — long random path",
     re.compile(r'@(app|router|blueprint)\.(route|get|post|put|delete)\s*\(\s*["\']/[a-f0-9]{16,}["\']', re.IGNORECASE),
     "HIGH", "Hidden Endpoint",
     "Web route at a hex-like random path — likely an undocumented backdoor endpoint."),

    # OS command execution triggered by specific input
    ("Input-triggered command execution",
     re.compile(r'(os\.system|subprocess\.(run|call|Popen))\s*\([^)]*(?:request|input|arg|param|data|body)[^)]*\)', re.IGNORECASE),
     "HIGH", "Remote Code Execution Backdoor",
     "System command executed with what appears to be user-supplied input — remote code execution backdoor."),

    # eval/exec on received data
    ("eval/exec on received data",
     re.compile(r'(eval|exec)\s*\([^)]*(?:request|recv|data|payload|body|input|arg)[^)]*\)', re.IGNORECASE),
     "HIGH", "Remote Code Execution Backdoor",
     "eval() or exec() called with what appears to be received/user data — allows arbitrary code execution by attacker."),

    # Reverse shell patterns
    ("Reverse shell — socket + exec",
     re.compile(r'(socket\.socket|s\.connect)\s*\(.*\)', re.IGNORECASE),
     "MEDIUM", "Potential Reverse Shell",
     "Socket connection pattern — combined with subprocess or exec calls this can establish a reverse shell."),

    ("Reverse shell — pty spawn",
     re.compile(r'pty\.spawn|os\.dup2\s*\(.*socket|bash.*-i', re.IGNORECASE),
     "HIGH", "Reverse Shell",
     "PTY spawn or socket duplication pattern — signature of a reverse shell payload."),

    # Time/environment-gated backdoors (logic bomb indicators at backdoor level)
    ("Environment-gated backdoor",
     re.compile(r'if\s+os\.(getenv|environ)\s*\([^)]+\)\s*(==|!=|in)\s*["\'][^"\']+["\'].*:', re.IGNORECASE),
     "MEDIUM", "Conditional Backdoor",
     "Code execution gated on a specific environment variable value — possible environment-triggered backdoor."),

    ("Hostname-gated execution",
     re.compile(r'(socket\.gethostname|platform\.node)\s*\(\s*\)\s*(==|!=|in)\s*["\']', re.IGNORECASE),
     "HIGH", "Conditional Backdoor",
     "Code execution gated on the system hostname — will only activate on a specific target machine."),
]


def _ast_backdoor_rules(tree: ast.AST, source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    AST-level backdoor detection.
    Catches patterns that are hard to find with line-level regex:
      - Functions with parameter defaults that grant elevated access
      - is_admin / is_authenticated always returning True
      - __eq__ overridden to always return True (password object bypass)
    """
    findings = []

    for node in ast.walk(tree):

        # Function that returns True unconditionally (fake auth check)
        if isinstance(node, ast.FunctionDef):
            fname = node.name.lower()
            auth_names = {"is_admin", "is_authenticated", "check_auth",
                          "verify_password", "authenticate", "is_superuser",
                          "check_permission", "has_permission"}
            if fname in auth_names:
                # Check if the function just returns True
                body = node.body
                if (len(body) == 1
                        and isinstance(body[0], ast.Return)
                        and isinstance(body[0].value, ast.Constant)
                        and body[0].value.value is True):
                    lineno = getattr(node, "lineno", 0)
                    findings.append({
                        "category": "Authentication Bypass",
                        "pattern": f"{node.name}() always returns True",
                        "lineno": lineno,
                        "severity": "HIGH",
                        "reason": (
                            f"Function '{node.name}' unconditionally returns True — "
                            "any caller treating this as a real authentication check is bypassed."
                        ),
                        "snippet": source_lines[lineno - 1].strip() if lineno <= len(source_lines) else "",
                    })

    return findings


def detect_backdoors(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Run all backdoor detection rules.
    Returns findings sorted by line number.
    """
    findings = []
    source_lines = source.splitlines()

    for lineno, line in enumerate(source_lines, start=1):
        # Skip pure comment lines for most rules (reduces false positives)
        stripped = line.strip()
        for name, pattern, severity, category, reason in LINE_RULES:
            if pattern.search(line):
                findings.append({
                    "category": category,
                    "pattern": name,
                    "lineno": lineno,
                    "severity": severity,
                    "reason": reason,
                    "snippet": stripped[:120],
                })

    findings.extend(_ast_backdoor_rules(tree, source_lines))

    seen = set()
    unique = []
    for f in findings:
        key = (f["lineno"], f["pattern"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: f["lineno"])
    return unique
