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
from typing import List, Dict, Any, Set, Tuple

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.obfuscation_patterns import (
    LINE_RULES,
    ENTROPY_THRESHOLD,
    MIN_ENTROPY_LENGTH,
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy (bits per character) of a string.
    """
    if not s:
        return 0.0
    
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _format_finding(
    category: str,
    pattern: str,
    lineno: int,
    severity: str,
    reason: str,
    snippet: str = ""
) -> Dict[str, Any]:
    """
    Create a standardized finding dictionary.
    """
    return {
        "category": category,
        "pattern": pattern,
        "lineno": lineno,
        "severity": severity,
        "reason": reason,
        "snippet": snippet[:120] if snippet else "",
    }


# ==========================================
# ENTROPY-BASED SCANNING
# ==========================================

def _scan_entropy(source: str) -> List[Dict[str, Any]]:
    """
    Flag source lines (excluding comments and imports) that have
    very high Shannon entropy — a sign of embedded encoded content.
    """
    findings = []
    
    for lineno, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        
        # Skip comments, imports, blank lines
        if (not stripped
                or stripped.startswith("#")
                or stripped.startswith("import ")
                or stripped.startswith("from ")):
            continue
        
        # Look for long string literals within the line
        string_matches = re.findall(
            r'["\']([A-Za-z0-9+/=_\-]{' + str(MIN_ENTROPY_LENGTH) + r',})["\']',
            line
        )
        
        for s in string_matches:
            entropy = _shannon_entropy(s)
            if entropy >= ENTROPY_THRESHOLD:
                findings.append(_format_finding(
                    category="High-Entropy Embedded String",
                    pattern="High-entropy string in code line",
                    lineno=lineno,
                    severity="MEDIUM",
                    reason=(
                        f"String with Shannon entropy {entropy:.2f} bits/char found in source line "
                        f"(threshold: {ENTROPY_THRESHOLD}) — likely an encoded payload, key, or obfuscated data."
                    ),
                    snippet=stripped,
                ))
    
    return findings


# ==========================================
# AST-BASED RULES
# ==========================================

def _count_chr_calls(node: ast.AST) -> int:
    """
    Count the number of chr() calls in a BinOp addition chain.
    """
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "chr":
            return 1
        return 0
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _count_chr_calls(node.left) + _count_chr_calls(node.right)
    return 0


def _scan_ast_chr_chains(tree: ast.AST, source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    Detect chr() chains in AST.
    """
    findings = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            chr_count = _count_chr_calls(node)
            if chr_count >= 3:
                lineno = getattr(node, "lineno", 0)
                snippet = source_lines[lineno - 1].strip() if lineno <= len(source_lines) else ""
                
                findings.append(_format_finding(
                    category="chr() Chain Obfuscation",
                    pattern=f"chr() chain ({chr_count} calls)",
                    lineno=lineno,
                    severity="HIGH",
                    reason=(
                        f"Chain of {chr_count} chr() calls detected in AST — "
                        "string is being constructed character-by-character to hide its content."
                    ),
                    snippet=snippet,
                ))
    
    return findings


def _scan_ast_dynamic_imports(tree: ast.AST, source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    Detect __import__() with dynamic (non-constant) arguments.
    """
    findings = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = node.func.id if isinstance(node.func, ast.Name) else ""
            
            if fname == "__import__" and node.args:
                if not isinstance(node.args[0], ast.Constant):
                    lineno = getattr(node, "lineno", 0)
                    snippet = source_lines[lineno - 1].strip() if lineno <= len(source_lines) else ""
                    
                    findings.append(_format_finding(
                        category="Dynamic Import Obfuscation",
                        pattern="__import__() with dynamic argument (AST)",
                        lineno=lineno,
                        severity="HIGH",
                        reason=(
                            "__import__() called with a computed argument — "
                            "the module being imported is determined at runtime."
                        ),
                        snippet=snippet,
                    ))
    
    return findings


def _scan_ast_rules(tree: ast.AST, source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    Run all AST-level obfuscation rules.
    """
    findings = []
    
    findings.extend(_scan_ast_chr_chains(tree, source_lines))
    findings.extend(_scan_ast_dynamic_imports(tree, source_lines))
    
    return findings


# ==========================================
# LINE-BASED SCANNING
# ==========================================

def _scan_line_rules(source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    Scan each line with all regex patterns.
    """
    findings = []
    
    for lineno, line in enumerate(source_lines, start=1):
        for name, pattern, severity, category, reason in LINE_RULES:
            if pattern.search(line):
                findings.append(_format_finding(
                    category=category,
                    pattern=name,
                    lineno=lineno,
                    severity=severity,
                    reason=reason,
                    snippet=line.strip(),
                ))
    
    return findings


# ==========================================
# MAIN DETECTION FUNCTION
# ==========================================

def detect_obfuscation(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Run all obfuscation detection rules.
    Returns findings sorted by line number.
    """
    source_lines = source.splitlines()
    
    # Collect findings from all sources
    findings = []
    findings.extend(_scan_line_rules(source_lines))
    findings.extend(_scan_ast_rules(tree, source_lines))
    findings.extend(_scan_entropy(source))
    
    # Deduplicate by (lineno, pattern)
    seen = set()
    unique = []
    for f in findings:
        key = (f["lineno"], f["pattern"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    
    # Sort by line number
    unique.sort(key=lambda f: f["lineno"])
    
    return unique


# ==========================================
# LEGACY SUPPORT
# ==========================================

def detect_obfuscation_legacy(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return detect_obfuscation(tree, source)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "detect_obfuscation",
    "detect_obfuscation_legacy",
    "LINE_RULES",
]