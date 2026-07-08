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
from typing import List, Dict, Any

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.backdoor_patterns import LINE_RULES, AUTH_FUNCTION_NAMES


# ==========================================
# HELPER FUNCTIONS
# ==========================================

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
# AST-BASED RULES
# ==========================================

def _scan_ast_auth_functions(tree: ast.AST, source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    Detect authentication functions that always return True.
    
    Example:
        def is_admin(user):
            return True
    """
    findings = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            fname = node.name.lower()
            
            if fname in AUTH_FUNCTION_NAMES:
                body = node.body
                
                # Check if function just returns True
                if (len(body) == 1
                        and isinstance(body[0], ast.Return)
                        and isinstance(body[0].value, ast.Constant)
                        and body[0].value.value is True):
                    
                    lineno = getattr(node, "lineno", 0)
                    snippet = source_lines[lineno - 1].strip() if lineno <= len(source_lines) else ""
                    
                    findings.append(_format_finding(
                        category="Authentication Bypass",
                        pattern=f"{node.name}() always returns True",
                        lineno=lineno,
                        severity="HIGH",
                        reason=(
                            f"Function '{node.name}' unconditionally returns True — "
                            "any caller treating this as a real authentication check is bypassed."
                        ),
                        snippet=snippet,
                    ))
    
    return findings


def _scan_ast_rules(tree: ast.AST, source_lines: List[str]) -> List[Dict[str, Any]]:
    """
    Run all AST-level backdoor rules.
    """
    findings = []
    
    findings.extend(_scan_ast_auth_functions(tree, source_lines))
    
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
        stripped = line.strip()
        
        # Skip pure comment lines to reduce false positives
        if stripped.startswith('#'):
            continue
        
        for name, pattern, severity, category, reason in LINE_RULES:
            if pattern.search(line):
                findings.append(_format_finding(
                    category=category,
                    pattern=name,
                    lineno=lineno,
                    severity=severity,
                    reason=reason,
                    snippet=stripped,
                ))
    
    return findings


# ==========================================
# MAIN DETECTION FUNCTION
# ==========================================

def detect_backdoors(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Run all backdoor detection rules.
    Returns findings sorted by line number.
    """
    source_lines = source.splitlines()
    
    # Collect findings from both line-based and AST-based rules
    findings = []
    findings.extend(_scan_line_rules(source_lines))
    findings.extend(_scan_ast_rules(tree, source_lines))
    
    # Deduplicate same pattern on same line
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

def detect_backdoors_legacy(tree: ast.AST, source: str) -> List[Dict[str, Any]]:
    """
    Legacy wrapper for backward compatibility.
    """
    return detect_backdoors(tree, source)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "detect_backdoors",
    "detect_backdoors_legacy",
    "LINE_RULES",
    "AUTH_FUNCTION_NAMES",
]