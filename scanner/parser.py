"""
parser.py
---------
Reads a Python source file, builds an AST, and extracts:
  - All import statements
  - All function/method calls
  - All string literals

Everything downstream (dangerous_api, secret_scanner) works
from these extracted structures, not from raw text grep.
"""

import ast
from typing import Dict, List, Any, Optional, Tuple, Set

# ==========================================
# CONSTANTS
# ==========================================

MAX_SOURCE_SIZE = 10_000_000  # 10MB max file size


# ==========================================
# ERROR TYPES
# ==========================================

class ParseError(Exception):
    """Base exception for parsing errors."""
    pass


class FileNotFoundError(ParseError):
    """File not found error."""
    pass


class EncodingError(ParseError):
    """File encoding error."""
    pass


class SyntaxError(ParseError):
    """Python syntax error."""
    pass


class FileTooLargeError(ParseError):
    """File too large to parse."""
    pass


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _read_file(filepath: str) -> Tuple[str, int]:
    """
    Read a file and return its content and size.
    
    Args:
        filepath: Path to the file
        
    Returns:
        Tuple of (content, size_in_bytes)
        
    Raises:
        FileNotFoundError: If file doesn't exist
        EncodingError: If file can't be decoded
        FileTooLargeError: If file exceeds MAX_SOURCE_SIZE
    """
    import os
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    # Check file size
    file_size = os.path.getsize(filepath)
    if file_size > MAX_SOURCE_SIZE:
        raise FileTooLargeError(
            f"File size ({file_size} bytes) exceeds maximum ({MAX_SOURCE_SIZE} bytes)"
        )
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read(), file_size
    except UnicodeDecodeError as e:
        # Try fallback encoding
        try:
            with open(filepath, "r", encoding="latin-1") as f:
                return f.read(), file_size
        except Exception:
            raise EncodingError(f"Cannot decode file: {e}")


def _build_error_response(error_type: str, message: str) -> Dict[str, Any]:
    """
    Build a standardized error response.
    """
    return {
        "error": message,
        "error_type": error_type,
        "source": None,
        "ast_tree": None,
        "imports": [],
        "calls": [],
        "strings": [],
    }


def _is_valid_call_name(name: str) -> bool:
    """
    Check if a call name is valid (not empty and not a Python keyword).
    """
    if not name:
        return False
    # Filter out common false positives
    invalid_names = {"", "None", "True", "False", "self", "cls"}
    return name not in invalid_names


# ==========================================
# EXTRACTION FUNCTIONS
# ==========================================

def _extract_imports(tree: ast.AST) -> List[str]:
    """
    Walk the AST and collect all imported module names.

    Handles:
        import os              -> ["os"]
        import os, sys         -> ["os", "sys"]
        from subprocess import Popen -> ["subprocess"]
        from base64 import b64encode -> ["base64"]
    """
    imports = []
    seen = set()
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in seen:
                    seen.add(root)
                    imports.append(root)

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                root = node.module.split(".")[0]
                if root not in seen:
                    seen.add(root)
                    imports.append(root)

    return sorted(imports)


def _extract_calls(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Walk the AST and collect all function/method call expressions.

    For each call, record:
        name    - best-effort readable name (e.g. "os.system", "eval")
        lineno  - line number in source
        arg_count - count of positional arguments
        keywords - count of keyword arguments
    """
    calls = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name and _is_valid_call_name(name):
                calls.append({
                    "name": name,
                    "lineno": getattr(node, "lineno", 0),
                    "arg_count": len(node.args),
                    "kw_count": len(node.keywords),
                })
    
    return calls


def _call_name(node: ast.expr) -> str:
    """
    Try to reconstruct a readable name from a Call's func node.
    
    Examples:
        eval(...)         -> "eval"
        os.system(...)    -> "os.system"
        obj.method(...)   -> "obj.method"
    
    Returns empty string if we can't resolve it cleanly.
    """
    if isinstance(node, ast.Name):
        return node.id
    
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    
    if isinstance(node, ast.Call):
        # Handle cases like getattr(obj, "method")()
        return _call_name(node.func)
    
    return ""


def _extract_strings(tree: ast.AST) -> List[Dict[str, Any]]:
    """
    Walk the AST and collect all string literals (ast.Constant where value is str).

    Records:
        value   - the string value
        lineno  - line number
    """
    strings = []
    seen = set()  # Avoid duplicates
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.strip()
            # Skip empty strings and very short strings (unlikely to be secrets)
            if len(value) < 2:
                continue
            
            # Avoid duplicate entries
            key = (value[:50], getattr(node, "lineno", 0))
            if key not in seen:
                seen.add(key)
                strings.append({
                    "value": node.value,
                    "lineno": getattr(node, "lineno", 0),
                    "length": len(node.value),
                })
    
    return strings


# ==========================================
# MAIN PARSE FUNCTION
# ==========================================

def parse_file(filepath: str) -> Dict[str, Any]:
    """
    Parse a Python file into an AST and extract key features.

    Args:
        filepath: Path to Python file

    Returns:
        A dict with:
            source     - raw source code (str)
            ast_tree   - the parsed AST object
            imports    - list of imported module names
            calls      - list of function call strings (e.g. "os.system")
            strings    - list of all string literals found
            error      - None if successful, error message if parse failed
            error_type - Type of error (for debugging)
    """
    # Step 1: Read the file
    try:
        source, file_size = _read_file(filepath)
    except FileNotFoundError as e:
        return _build_error_response("file_not_found", str(e))
    except EncodingError as e:
        return _build_error_response("encoding_error", str(e))
    except FileTooLargeError as e:
        return _build_error_response("file_too_large", str(e))
    except Exception as e:
        return _build_error_response("read_error", f"Failed to read file: {e}")

    # Step 2: Parse the AST
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as e:
        return _build_error_response(
            "syntax_error",
            f"Syntax error in file: {e}\nLine {e.lineno}: {e.text}"
        )
    except Exception as e:
        return _build_error_response(
            "parse_error",
            f"Failed to parse file: {e}"
        )

    # Step 3: Extract features
    imports = _extract_imports(tree)
    calls = _extract_calls(tree)
    strings = _extract_strings(tree)

    return {
        "source": source,
        "ast_tree": tree,
        "imports": imports,
        "calls": calls,
        "strings": strings,
        "error": None,
        "error_type": None,
        "file_size": file_size,
        "file_path": filepath,
    }


# ==========================================
# CONVENIENCE FUNCTIONS
# ==========================================

def parse_file_safe(filepath: str) -> Optional[Dict[str, Any]]:
    """
    Parse a file and return the result, or None if there was an error.
    Useful for quick checks where you don't care about the error details.
    """
    result = parse_file(filepath)
    if result.get("error"):
        return None
    return result


def parse_code(code: str) -> Dict[str, Any]:
    """
    Parse Python code from a string (not a file).
    Useful for testing or handling code snippets.
    
    Args:
        code: Python source code as a string
        
    Returns:
        Same structure as parse_file(), but without file-specific fields
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return _build_error_response("syntax_error", str(e))
    
    imports = _extract_imports(tree)
    calls = _extract_calls(tree)
    strings = _extract_strings(tree)
    
    return {
        "source": code,
        "ast_tree": tree,
        "imports": imports,
        "calls": calls,
        "strings": strings,
        "error": None,
        "error_type": None,
    }


def get_call_summary(result: Dict[str, Any]) -> Dict[str, int]:
    """
    Get a summary of calls by category.
    
    Args:
        result: Result from parse_file() or parse_code()
        
    Returns:
        Dictionary with call counts by category
    """
    calls = result.get("calls", [])
    
    summary = {
        "total_calls": len(calls),
        "by_category": {},
    }
    
    for call in calls:
        name = call.get("name", "")
        if "." in name:
            category = name.split(".")[0]
        else:
            category = "builtin"
        
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
    
    return summary


def has_import(result: Dict[str, Any], module: str) -> bool:
    """
    Check if a specific module is imported.
    
    Args:
        result: Result from parse_file() or parse_code()
        module: Module name to check
        
    Returns:
        True if the module is imported
    """
    imports = result.get("imports", [])
    return module in imports


def has_call(result: Dict[str, Any], call_name: str) -> bool:
    """
    Check if a specific call exists.
    
    Args:
        result: Result from parse_file() or parse_code()
        call_name: Call name to check (e.g., "os.system")
        
    Returns:
        True if the call exists
    """
    calls = result.get("calls", [])
    return any(c.get("name") == call_name for c in calls)


# ==========================================
# LEGACY SUPPORT
# ==========================================

def parse_file_legacy(filepath: str) -> Dict[str, Any]:
    """
    Legacy wrapper for backward compatibility.
    """
    return parse_file(filepath)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "parse_file",
    "parse_file_legacy",
    "parse_file_safe",
    "parse_code",
    "get_call_summary",
    "has_import",
    "has_call",
    "ParseError",
    "FileNotFoundError",
    "EncodingError",
    "SyntaxError",
    "FileTooLargeError",
]