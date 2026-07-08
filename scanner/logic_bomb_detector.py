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
from typing import List, Dict, Any, Set

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.logic_bomb_patterns import (
    LINE_RULES,
    DANGEROUS_OPERATIONS,
    TRIGGER_KEYWORDS,
)


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _call_name(node: ast.AST) -> str:
    """
    Reconstruct a dotted call name from the AST node.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


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


def _get_trigger_text(node: ast.AST) -> str:
    """
    Extract trigger text from an AST node for display.
    """
    try:
        if hasattr(ast, "unparse"):
            return ast.unparse(node.test)[:60]
    except Exception:
        pass
    return "unknown trigger"


# ==========================================
# AST-BASED RULES
# ==========================================

def _scan_ast_condition_dangerous(
    tree: ast.AST,
    source_lines: List[str]
) -> List[Dict[str, Any]]:
    """
    Detect if/elif blocks where:
        1. The condition contains a trigger (time/host/user/env)
        2. The body contains dangerous operations (eval/exec/subprocess/etc.)
    """
    findings = []
    
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        
        # Get condition text
        test_text = _get_trigger_text(node)
        
        # Check if condition contains any trigger keyword
        has_trigger = any(keyword in test_text for keyword in TRIGGER_KEYWORDS)
        if not has_trigger:
            continue
        
        # Check body for dangerous operations
        body_dangerous = []
        for body_node in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(body_node, ast.Call):
                name = _call_name(body_node.func)
                # Check if this dangerous operation is in our list
                for danger in DANGEROUS_OPERATIONS:
                    if danger in name:
                        body_dangerous.append(name)
                        break
        
        if body_dangerous:
            lineno = getattr(node, "lineno", 0)
            snippet = source_lines[lineno - 1].strip() if lineno <= len(source_lines) else ""
            
            findings.append(_format_finding(
                category="Logic Bomb",
                pattern="Trigger condition gates dangerous operation (AST)",
                lineno=lineno,
                severity="HIGH",
                reason=(
                    f"Conditional trigger ({test_text}) gates a dangerous "
                    f"operation ({', '.join(body_dangerous[:3])}) — classic logic bomb structure."
                ),
                snippet=snippet,
            ))
    
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

def detect_logic_bombs(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Run all logic bomb detection rules.
    Returns findings sorted by line number.
    """
    source_lines = source.splitlines()
    
    # Collect findings from both line-based and AST-based rules
    findings = []
    findings.extend(_scan_line_rules(source_lines))
    findings.extend(_scan_ast_condition_dangerous(tree, source_lines))
    
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

def detect_logic_bombs_legacy(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return detect_logic_bombs(tree, source)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "detect_logic_bombs",
    "detect_logic_bombs_legacy",
    "LINE_RULES",
]