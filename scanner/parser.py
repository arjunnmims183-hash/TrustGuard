"""
parser_pure.py - Pure AST parser without security logic.
Just extracts raw data. Security checks will be added later.
"""

import ast
import os
from typing import Dict, List, Any

MAX_SOURCE_SIZE = 10_000_000

class Parser:
    """Pure parser - extracts raw data only. No security logic."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.tree = None
        self.source = None

    def parse(self) -> Dict[str, Any]:
        """Parse file and return raw data."""
        try:
            self.source = self._read_file()
            self.tree = ast.parse(self.source, filename=self.filepath)

            return {
                "file": self.filepath,
                "lines": len(self.source.splitlines()),
                "imports": self._get_imports(),
                "imports_detailed": self._get_imports_detailed(),
                "calls": self._get_calls(),
                "calls_detailed": self._get_calls_detailed(),
                "strings": self._get_strings(),
                "assignments": self._get_assignments(),
                "functions": self._get_functions(),
                "classes": self._get_classes(),
                "comments": self._get_comments(),
                "constants": self._get_constants(),
                "decorators": self._get_decorators(),
                "docstrings": self._get_docstrings(),
                "loops": self._get_loops(),
                "conditionals": self._get_conditionals(),
                "try_except": self._get_try_except(),
                "variables": self._get_variables(),
                "error": None,
            }
        except Exception as e:
            return {"file": self.filepath, "error": str(e), **self._empty_result()}

    def _read_file(self) -> str:
        """Read file with encoding detection."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"File not found: {self.filepath}")

        size = os.path.getsize(self.filepath)
        if size > MAX_SOURCE_SIZE:
            raise ValueError(f"File too large: {size} bytes")

        for encoding in ("utf-8", "latin-1"):
            try:
                with open(self.filepath, "r", encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        raise UnicodeDecodeError(f"Cannot decode: {self.filepath}")

    # ==========================================
    # EXTRACTORS
    # ==========================================

    def _get_imports(self) -> List[str]:
        """Get all imported module names."""
        imports = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split('.')[0])
        return sorted(imports)

    def _get_imports_detailed(self) -> List[Dict[str, Any]]:
        """Get detailed imports with line numbers."""
        imports = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({
                        "module": alias.name,
                        "alias": alias.asname,
                        "line": node.lineno,
                    })
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imports.append({
                        "module": node.module,
                        "name": alias.name,
                        "alias": alias.asname,
                        "line": node.lineno,
                    })
        return imports

    def _get_calls(self) -> List[str]:
        """Get all function/method call names."""
        calls = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self._get_name(node.func)
                if name and name not in {"", "None", "True", "False", "self", "cls"}:
                    calls.append(name)
        return calls

    def _get_calls_detailed(self) -> List[Dict[str, Any]]:
        """Get detailed calls with line numbers and args."""
        calls = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self._get_name(node.func)
                if name and name not in {"", "None", "True", "False", "self", "cls"}:
                    calls.append({
                        "name": name,
                        "line": node.lineno,
                        "arg_count": len(node.args),
                        "kw_count": len(node.keywords),
                        "args": [self._get_name(a) for a in node.args[:5]],
                        "keywords": [kw.arg for kw in node.keywords[:3] if kw.arg],
                    })
        return calls

    def _get_strings(self) -> List[Dict[str, Any]]:
        """Get all string literals."""
        strings = []
        seen = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value.strip()
                if len(value) >= 2:
                    key = (value[:50], node.lineno)
                    if key not in seen:
                        seen.add(key)
                        strings.append({
                            "value": node.value,
                            "line": node.lineno,
                            "length": len(node.value),
                        })
        return strings

    def _get_assignments(self) -> List[Dict[str, Any]]:
        """Get all variable assignments."""
        assignments = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments.append({
                            "variable": target.id,
                            "line": node.lineno,
                        })
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    assignments.append({
                        "variable": node.target.id,
                        "line": node.lineno,
                        "operation": ast.unparse(node.op).strip(),
                    })
        return assignments

    def _get_functions(self) -> List[Dict[str, Any]]:
        """Get all function definitions."""
        functions = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "defaults": len(node.args.defaults),
                    "returns": self._get_name(node.returns) if node.returns else None,
                    "is_async": False,
                })
            elif isinstance(node, ast.AsyncFunctionDef):
                functions.append({
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "defaults": len(node.args.defaults),
                    "returns": self._get_name(node.returns) if node.returns else None,
                    "is_async": True,
                })
        return functions

    def _get_classes(self) -> List[Dict[str, Any]]:
        """Get all class definitions."""
        classes = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                classes.append({
                    "name": node.name,
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "bases": [self._get_name(base) for base in node.bases],
                    "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)],
                })
        return classes

    def _get_comments(self) -> List[str]:
        """Get all comments."""
        comments = []
        for line in self.source.split('\n'):
            line = line.strip()
            if line.startswith('#'):
                comments.append(line)
        return comments

    def _get_constants(self) -> List[Dict[str, Any]]:
        """Get all constants (numbers, booleans, None)."""
        constants = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant):
                if isinstance(node.value, (int, float, bool, type(None))):
                    constants.append({
                        "value": node.value,
                        "type": type(node.value).__name__,
                        "line": node.lineno,
                    })
        return constants

    def _get_decorators(self) -> List[Dict[str, Any]]:
        """Get all decorators."""
        decorators = []
        for node in ast.walk(self.tree):
            if hasattr(node, 'decorator_list'):
                for decorator in node.decorator_list:
                    decorators.append({
                        "name": self._get_name(decorator),
                        "line": node.lineno,
                        "target": node.name if hasattr(node, 'name') else "unknown",
                    })
        return decorators

    def _get_docstrings(self) -> List[Dict[str, Any]]:
        """Get all docstrings."""
        docstrings = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                docstring = ast.get_docstring(node)
                if docstring:
                    docstrings.append({
                        "value": docstring,
                        "line": node.lineno,
                        "type": type(node).__name__.lower().replace('def', ''),
                        "name": node.name if hasattr(node, 'name') else "module",
                    })
        return docstrings

    def _get_loops(self) -> List[Dict[str, Any]]:
        """Get all loops."""
        loops = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.For):
                loops.append({
                    "type": "for",
                    "line": node.lineno,
                    "target": self._get_name(node.target),
                    "iter": self._get_name(node.iter),
                })
            elif isinstance(node, ast.While):
                loops.append({
                    "type": "while",
                    "line": node.lineno,
                    "condition": self._get_name(node.test),
                })
        return loops

    def _get_conditionals(self) -> List[Dict[str, Any]]:
        """Get all conditionals."""
        conditionals = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.If):
                conditionals.append({
                    "type": "if",
                    "line": node.lineno,
                    "condition": self._get_name(node.test),
                    "has_else": bool(node.orelse),
                })
        return conditionals

    def _get_try_except(self) -> List[Dict[str, Any]]:
        """Get all try/except blocks."""
        try_blocks = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Try):
                try_blocks.append({
                    "line": node.lineno,
                    "handlers": len(node.handlers),
                    "has_finally": bool(node.finalbody),
                    "has_else": bool(node.orelse),
                })
        return try_blocks

    def _get_variables(self) -> List[str]:
        """Get all variable names."""
        variables = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name):
                if isinstance(node.ctx, ast.Store):
                    variables.add(node.id)
        return sorted(variables)

    def _get_name(self, node) -> str:
        """Get readable name from AST node."""
        if not node:
            return ""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._get_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return self._get_name(node.func)
        if isinstance(node, ast.Constant):
            return str(node.value)
        return getattr(node, 'id', getattr(node, 'attr', getattr(node, 'name', str(node)[:30])))


# parser = Parser(r'C:\Users\Acer\Downloads\TrustGuard\test_samples\credential_theft.py')
# result = parser.parse()
# print(result)