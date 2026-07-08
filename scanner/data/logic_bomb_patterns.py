"""
logic_bomb_patterns.py
----------------------
Logic bomb detection patterns for logic_bomb_detector.py.
Each entry: (pattern_name, regex, severity, category, reason)
"""

import re
from typing import List, Tuple, Pattern, Set

# ==========================================
# LINE-BASED LOGIC BOMB PATTERNS
# ==========================================

LINE_RULES: List[Tuple[str, Pattern, str, str, str]] = [
    # (pattern_name, compiled_regex, severity, category, reason)
    
    # =====================================
    # Time-Based Triggers
    # =====================================
    (
        "Time-based trigger — datetime comparison",
        re.compile(r'(datetime\.now|datetime\.today|time\.time|date\.today)\s*\(\s*\).*[><=!]'),
        "HIGH",
        "Time-Based Logic Bomb",
        "Code execution gated on the current date/time — will activate at a specific moment.",
    ),
    (
        "Time-based trigger — date string comparison",
        re.compile(r'["\'][12][0-9]{3}[-/][01][0-9][-/][0-3][0-9]["\']'),
        "MEDIUM",
        "Time-Based Logic Bomb",
        "Hardcoded date string in source — possible logic bomb trigger date.",
    ),
    
    # =====================================
    # Host-Based Triggers
    # =====================================
    (
        "Hostname trigger",
        re.compile(r'(socket\.gethostname|platform\.node)\s*\(\s*\)\s*(==|!=|in)'),
        "HIGH",
        "Host-Based Logic Bomb",
        "Execution gated on system hostname — activates only on specific target machine.",
    ),
    
    # =====================================
    # User-Based Triggers
    # =====================================
    (
        "Username trigger",
        re.compile(r'(os\.getlogin|getpass\.getuser|os\.environ\[["\']USER["\'])\s*\)?\s*(==|!=|in)'),
        "HIGH",
        "User-Based Logic Bomb",
        "Execution gated on logged-in username — activates only for a specific user.",
    ),
    
    # =====================================
    # Counter-Based Triggers
    # =====================================
    (
        "Counter/iteration trigger",
        re.compile(r'if\s+\w+\s*(==|>=|>)\s*\d{4,}\s*:'),
        "MEDIUM",
        "Counter-Based Logic Bomb",
        "Condition triggers after a large iteration count — behavior hidden until Nth execution.",
    ),
    
    # =====================================
    # Environment-Based Triggers
    # =====================================
    (
        "Environment variable trigger",
        re.compile(r'os\.(getenv|environ\.get)\s*\([^)]+\)\s*(==|!=|is\s+None|is\s+not\s+None)'),
        "MEDIUM",
        "Environment-Based Logic Bomb",
        "Execution gated on a specific environment variable value or presence.",
    ),
    
    # =====================================
    # Process-Based Triggers
    # =====================================
    (
        "PID/process count trigger",
        re.compile(r'os\.(getpid|getppid)\s*\(\s*\)\s*(==|!=|>|<)'),
        "LOW",
        "Process-Based Trigger",
        "Execution gated on process ID — can be used to detect sandbox environments.",
    ),
    
    # =====================================
    # Sandbox Evasion
    # =====================================
    (
        "Sandbox evasion — sleep delay",
        re.compile(r'time\.sleep\s*\(\s*([6-9]\d{1,}|\d{3,})\s*\)'),
        "HIGH",
        "Sandbox Evasion",
        "Long sleep delay (60+ seconds) — common technique to outlast automated sandbox analysis timeouts.",
    ),
    (
        "Sandbox evasion — process list check",
        re.compile(r'psutil\.(process_iter|pids)\s*\(\s*\)'),
        "MEDIUM",
        "Sandbox Evasion",
        "Process enumeration — often used to detect analysis tools (Wireshark, OllyDbg) and halt execution.",
    ),
]

# ==========================================
# DANGEROUS OPERATIONS (for AST detection)
# ==========================================

DANGEROUS_OPERATIONS: Set[str] = {
    "eval",
    "exec",
    "subprocess",
    "requests",
    "os.system",
    "socket",
    "shutil.rmtree",
    "os.remove",
    "os.unlink",
    "os.rmdir",
}

# ==========================================
# TRIGGER KEYWORDS (for AST detection)
# ==========================================

TRIGGER_KEYWORDS: Set[str] = {
    "datetime",
    "time.time",
    "gethostname",
    "getlogin",
    "getuser",
    "getenv",
    "platform.node",
    "date.today",
    "time.sleep",
}


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "LINE_RULES",
    "DANGEROUS_OPERATIONS",
    "TRIGGER_KEYWORDS",
]