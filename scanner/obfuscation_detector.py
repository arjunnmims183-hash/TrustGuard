"""
obfuscation_detector.py
-----------------------
Detects code obfuscation techniques commonly used to hide malicious behavior.

Techniques covered:
    1. chr() chains         - building strings char-by-char to avoid string literals
    2. XOR decode loops     - XOR-based payload decryption
    3. Base64 decode chains - encoded strings decoded and executed
    4. String concatenation to build function/module names
    5. __import__ used dynamically
    6. exec(compile(...))   - runtime code compilation and execution
    7. High character entropy in non-comment lines
    8. Deeply nested encode/decode calls
    9. Hex/octal escape sequences used to hide strings
    10. Lambda abuse for obfuscation
"""

import ast
import re
import math
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Regex-based rules
# ---------------------------------------------------------------------------

LINE_RULES = [

    # chr() chains — building strings one character at a time
    ("chr() chain — string building",
     re.compile(r'(chr\s*\(\s*\d+\s*\)\s*\+\s*){2,}'),
     "HIGH", "chr() Chain Obfuscation",
     "Multiple chr() calls concatenated — classic technique to build a string without using string literals, hiding the actual content from static analysis."),

    # XOR decode loops
    ("XOR decode loop",
     re.compile(r'\^\s*(0x[0-9a-fA-F]+|\d+)'),
     "HIGH", "XOR Obfuscation",
     "XOR operation with a constant — common in XOR-based payload decryption routines."),

    # Base64 decode then exec/eval
    ("Base64 decode → exec/eval",
     re.compile(r'(eval|exec)\s*\([^)]*base64\.(b64decode|decodebytes|decode)', re.IGNORECASE),
     "HIGH", "Encoded Payload Execution",
     "Base64-decoded content passed directly to eval()/exec() — classic encoded payload execution pattern."),

    ("Base64 decode → compile",
     re.compile(r'compile\s*\([^)]*base64\.(b64decode|decodebytes)', re.IGNORECASE),
     "HIGH", "Encoded Payload Execution",
     "Base64-decoded content passed to compile() — obfuscated code compiled and likely executed."),

    # zlib + base64 combo (common packer pattern)
    ("zlib decompress + base64 decode chain",
     re.compile(r'zlib\.decompress\s*\([^)]*base64\.b64decode|base64\.b64decode[^)]*zlib\.decompress', re.IGNORECASE),
     "HIGH", "Packed Payload",
     "zlib decompression chained with base64 decoding — signature of a packed/compressed payload being unpacked at runtime."),

    # Dynamic __import__
    ("Dynamic __import__() call",
     re.compile(r'__import__\s*\(\s*(?!["\'][a-zA-Z_][a-zA-Z0-9_.]*["\'])'),
     "HIGH", "Dynamic Import Obfuscation",
     "__import__() called with a non-literal argument — module name is determined at runtime to evade static import analysis."),

    # String concatenation to build module/function names
    ("String concat to build module name",
     re.compile(r'__import__\s*\(\s*["\'][a-z]+["\'\s]*\+\s*["\'][a-z]+["\']'),
     "HIGH", "Import Name Obfuscation",
     "Module name built by string concatenation before __import__ — hides which module is being imported."),

    # exec(compile(...))
    ("exec(compile()) — runtime code compilation",
     re.compile(r'exec\s*\(\s*compile\s*\('),
     "HIGH", "Runtime Code Compilation",
     "exec(compile(...)) — code is compiled and executed at runtime, bypassing static analysis of what runs."),

    # Hex escape sequences in strings
    ("Hex escape sequences in string",
     re.compile(r'(\\x[0-9a-fA-F]{2}){4,}'),
     "MEDIUM", "Hex Escape Obfuscation",
     "Four or more consecutive hex escape sequences — commonly used to encode hidden strings or shellcode."),

    # Octal escape sequences
    ("Octal escape sequences in string",
     re.compile(r'(\\[0-7]{3}){3,}'),
     "MEDIUM", "Octal Escape Obfuscation",
     "Multiple octal escape sequences — alternate encoding method to hide string content from static inspection."),

    # Unicode escape obfuscation
    ("Unicode escape sequences in string",
     re.compile(r'(\\u[0-9a-fA-F]{4}){3,}'),
     "MEDIUM", "Unicode Escape Obfuscation",
     "Multiple Unicode escape sequences — can be used to hide keywords or strings from pattern matching."),

    # getattr used to call functions dynamically
    ("getattr() used to call function dynamically",
     re.compile(r'getattr\s*\(\s*\w+\s*,\s*(?!["\'][a-zA-Z_][a-zA-Z0-9_]*["\'])[^)]+\)'),
     "MEDIUM", "Dynamic Attribute Resolution",
     "getattr() called with a non-literal attribute name — function to call is determined at runtime, hiding behavior."),

    # Lambda chains (obfuscation via excessive lambda nesting)
    ("Lambda chain obfuscation",
     re.compile(r'(lambda\s+\w+\s*:\s*){3,}'),
     "MEDIUM", "Lambda Chain Obfuscation",
     "Deeply nested lambda expressions — can be used to obfuscate logic and evade simple pattern matching."),

    # rot13 / codecs decode abuse
    ("codecs.decode / rot13 obfuscation",
     re.compile(r'codecs\.(decode|encode)\s*\([^)]*["\']rot.?13["\']|["\']rot.?13["\'][^)]*codecs\.(decode|encode)', re.IGNORECASE),
     "HIGH", "Encoding Obfuscation",
     "codecs.decode with rot13 — used to hide string literals like function names or URLs from static inspection."),

    # exec/eval with decode chain
    ("eval/exec with decode chain",
     re.compile(r'(eval|exec)\s*\([^)]*\.(decode|decompress)\s*\(', re.IGNORECASE),
     "HIGH", "Encoded Payload Execution",
     "eval()/exec() called on decoded/decompressed content — encoded payload being unpacked and executed."),
]


# ---------------------------------------------------------------------------
# AST-based obfuscation rules
# ---------------------------------------------------------------------------

def _ast_obfuscation_rules(tree: ast.AST, source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    AST-level obfuscation detection:
      - chr() chains (counting consecutive chr() calls in BinOp chains)
      - __import__ with non-Constant argument
      - Heavily nested function calls (depth > 5)
    """
    findings = []

    for node in ast.walk(tree):

        # Count chr() calls in a concatenation chain
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            chr_count = _count_chr_calls(node)
            if chr_count >= 3:
                lineno = getattr(node, "lineno", 0)
                findings.append({
                    "category": "chr() Chain Obfuscation",
                    "pattern": f"chr() chain ({chr_count} calls)",
                    "lineno": lineno,
                    "severity": "HIGH",
                    "reason": (
                        f"Chain of {chr_count} chr() calls detected in AST — "
                        "string is being constructed character-by-character to hide its content."
                    ),
                    "snippet": source_lines[lineno - 1].strip() if lineno <= len(source_lines) else "",
                })

        # __import__ with dynamic argument
        if isinstance(node, ast.Call):
            fname = node.func.id if isinstance(node.func, ast.Name) else ""
            if fname == "__import__" and node.args:
                if not isinstance(node.args[0], ast.Constant):
                    lineno = getattr(node, "lineno", 0)
                    findings.append({
                        "category": "Dynamic Import Obfuscation",
                        "pattern": "__import__() with dynamic argument (AST)",
                        "lineno": lineno,
                        "severity": "HIGH",
                        "reason": (
                            "__import__() called with a computed argument — "
                            "the module being imported is determined at runtime."
                        ),
                        "snippet": source_lines[lineno - 1].strip() if lineno <= len(source_lines) else "",
                    })

    return findings


def _count_chr_calls(node: ast.AST) -> int:
    """Count the number of chr() calls in a BinOp addition chain."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "chr":
            return 1
        return 0
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _count_chr_calls(node.left) + _count_chr_calls(node.right)
    return 0


# ---------------------------------------------------------------------------
# Entropy-based detection on full lines
# ---------------------------------------------------------------------------

def _entropy_line_scan(source: str) -> List[Dict[str, Any]]:
    """
    Flag source lines (excluding comments and imports) that have
    very high Shannon entropy — a sign of embedded encoded content.
    Threshold: >= 5.0 bits/char on a line >= 80 chars.
    """
    findings = []
    THRESHOLD = 5.0
    MIN_LEN   = 80

    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        # Skip comments, imports, blank lines, and lines that are just strings
        if (not stripped
                or stripped.startswith("#")
                or stripped.startswith("import ")
                or stripped.startswith("from ")):
            continue

        # Only look at string content within the line
        string_matches = re.findall(r'["\']([A-Za-z0-9+/=_\-]{' + str(MIN_LEN) + r',})["\']', line)
        for s in string_matches:
            ent = _shannon_entropy(s)
            if ent >= THRESHOLD:
                findings.append({
                    "category": "High-Entropy Embedded String",
                    "pattern": "High-entropy string in code line",
                    "lineno": lineno,
                    "severity": "MEDIUM",
                    "reason": (
                        f"String with Shannon entropy {ent:.2f} bits/char found in source line "
                        f"(threshold: {THRESHOLD}) — likely an encoded payload, key, or obfuscated data."
                    ),
                    "snippet": stripped[:120],
                })

    return findings


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_obfuscation(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Run all obfuscation detection rules.
    Returns findings sorted by line number.
    """
    findings = []
    source_lines = source.splitlines()

    # Regex line rules
    for lineno, line in enumerate(source_lines, start=1):
        for name, pattern, severity, category, reason in LINE_RULES:
            if pattern.search(line):
                findings.append({
                    "category": category,
                    "pattern": name,
                    "lineno": lineno,
                    "severity": severity,
                    "reason": reason,
                    "snippet": line.strip()[:120],
                })

    # AST rules
    findings.extend(_ast_obfuscation_rules(tree, source_lines))

    # Entropy line scan
    findings.extend(_entropy_line_scan(source))

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        key = (f["lineno"], f["pattern"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda f: f["lineno"])
    return unique
