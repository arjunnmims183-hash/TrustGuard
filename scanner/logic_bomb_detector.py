"""
logic_bomb_detector.py
----------------------
Detects conditional triggers that gate malicious behavior:
  - Date/time based triggers
  - Hostname/user based triggers
  - Counter/iteration triggers
  - Environment-specific triggers
"""
import ast
import re
from typing import List, Dict, Any


LINE_RULES = [
    ("Time-based trigger — datetime comparison",
     re.compile(r'(datetime\.now|datetime\.today|time\.time|date\.today)\s*\(\s*\).*[><=!]'),
     "HIGH", "Time-Based Logic Bomb",
     "Code execution gated on the current date/time — will activate at a specific moment."),

    ("Time-based trigger — date string comparison",
     re.compile(r'["\'][12][0-9]{3}[-/][01][0-9][-/][0-3][0-9]["\']'),
     "MEDIUM", "Time-Based Logic Bomb",
     "Hardcoded date string in source — possible logic bomb trigger date."),

    ("Hostname trigger",
     re.compile(r'(socket\.gethostname|platform\.node)\s*\(\s*\)\s*(==|!=|in)'),
     "HIGH", "Host-Based Logic Bomb",
     "Execution gated on system hostname — activates only on specific target machine."),

    ("Username trigger",
     re.compile(r'(os\.getlogin|getpass\.getuser|os\.environ\[["\']USER["\'])\s*\)?\s*(==|!=|in)'),
     "HIGH", "User-Based Logic Bomb",
     "Execution gated on logged-in username — activates only for a specific user."),

    ("Counter/iteration trigger",
     re.compile(r'if\s+\w+\s*(==|>=|>)\s*\d{4,}\s*:'),
     "MEDIUM", "Counter-Based Logic Bomb",
     "Condition triggers after a large iteration count — behavior hidden until Nth execution."),

    ("Environment variable trigger",
     re.compile(r'os\.(getenv|environ\.get)\s*\([^)]+\)\s*(==|!=|is\s+None|is\s+not\s+None)'),
     "MEDIUM", "Environment-Based Logic Bomb",
     "Execution gated on a specific environment variable value or presence."),

    ("PID/process count trigger",
     re.compile(r'os\.(getpid|getppid)\s*\(\s*\)\s*(==|!=|>|<)'),
     "LOW", "Process-Based Trigger",
     "Execution gated on process ID — can be used to detect sandbox environments."),

    ("Sandbox evasion — sleep delay",
     re.compile(r'time\.sleep\s*\(\s*([6-9]\d{1,}|\d{3,})\s*\)'),
     "HIGH", "Sandbox Evasion",
     "Long sleep delay (60+ seconds) — common technique to outlast automated sandbox analysis timeouts."),

    ("Sandbox evasion — process list check",
     re.compile(r'psutil\.(process_iter|pids)\s*\(\s*\)'),
     "MEDIUM", "Sandbox Evasion",
     "Process enumeration — often used to detect analysis tools (Wireshark, OllyDbg) and halt execution."),
]


def _ast_logic_bomb_rules(tree: ast.AST, source_lines: List[str]) -> List[Dict]:
    """
    AST-level: detect if/elif bodies that only execute when a
    date/time/host comparison is true, and the body contains
    dangerous operations.
    """
    findings = []
    DANGEROUS_IN_BODY = {"eval", "exec", "subprocess", "requests", "os.system",
                          "socket", "shutil.rmtree", "os.remove"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.If,)):
            continue

        # Check if the test involves time/host/user
        test_src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        triggers = ["datetime", "time.time", "gethostname", "getlogin",
                    "getuser", "getenv", "platform.node"]

        if not any(t in test_src for t in triggers):
            continue

        # Check body for dangerous calls
        for body_node in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(body_node, ast.Call):
                from scanner.behavioral_analyzer import _call_name
                name = _call_name(body_node.func)
                if any(d in name for d in DANGEROUS_IN_BODY):
                    lineno = getattr(node, "lineno", 0)
                    findings.append({
                        "category": "Logic Bomb",
                        "pattern":  "Trigger condition gates dangerous operation (AST)",
                        "lineno":   lineno,
                        "severity": "HIGH",
                        "reason":   (
                            f"Conditional trigger ({test_src[:60]}) gates a dangerous "
                            f"operation ({name}) — classic logic bomb structure."
                        ),
                        "snippet": source_lines[lineno-1].strip() if lineno <= len(source_lines) else "",
                    })
                    break  # one finding per if block

    return findings


def detect_logic_bombs(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    findings = []
    source_lines = source.splitlines()

    for lineno, line in enumerate(source_lines, start=1):
        for name, pattern, severity, category, reason in LINE_RULES:
            if pattern.search(line):
                findings.append({
                    "category": category,
                    "pattern":  name,
                    "lineno":   lineno,
                    "severity": severity,
                    "reason":   reason,
                    "snippet":  line.strip()[:120],
                })

    findings.extend(_ast_logic_bomb_rules(tree, source_lines))

    seen = set()
    unique = []
    for f in findings:
        key = (f["lineno"], f["pattern"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: f["lineno"])
    return unique
