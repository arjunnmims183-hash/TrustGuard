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
                        "args": [self._get_name(a) for a in node.args],
                        "keywords": [
                            {"arg": kw.arg, "value": self._get_name(kw.value)}
                            for kw in node.keywords if kw.arg
                        ]
                    })
        return calls

    def _get_strings(self) -> List[Dict[str, Any]]:
        """Get all string literals - UNIFORM FORMAT."""
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
                            "line": node.lineno,
                            "value": node.value,
                            "length": len(node.value),
                            "type": "string_literal",
                        })
        return strings

    def _get_assignments(self) -> List[Dict[str, Any]]:
        """Get all variable assignments with their values."""
        assignments = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        rhs = self._get_value_repr(node.value)
                        assignments.append({
                            "line": node.lineno,
                            "variable": target.id,
                            "value": rhs,
                            "operation": "=",
                            "type": "assignment",
                        })
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    op = ast.unparse(node.op).strip()
                    rhs = self._get_value_repr(node.value)
                    assignments.append({
                        "line": node.lineno,
                        "variable": node.target.id,
                        "value": rhs,
                        "operation": op,
                        "type": "augmented_assignment",
                    })
        return assignments

    def _get_value_repr(self, node) -> str:
        try:
            return ast.unparse(node)  # Python 3.9+ gives exact source text
        except Exception:
            if isinstance(node, ast.Constant):
                return repr(node.value)
            return str(node)[:50]

    def _get_functions(self) -> List[Dict[str, Any]]:
        """Get all function definitions."""
        functions = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "value": node.name,
                    "args": [arg.arg for arg in node.args.args],
                    "defaults": len(node.args.defaults),
                    "returns": self._get_name(node.returns) if node.returns else None,
                    "is_async": False,
                    "type": "function",
                })
            elif isinstance(node, ast.AsyncFunctionDef):
                functions.append({
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "value": node.name,
                    "args": [arg.arg for arg in node.args.args],
                    "defaults": len(node.args.defaults),
                    "returns": self._get_name(node.returns) if node.returns else None,
                    "is_async": True,
                    "type": "async_function",
                })
        return functions

    def _get_classes(self) -> List[Dict[str, Any]]:
        """Get all class definitions."""
        classes = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                classes.append({
                    "line": node.lineno,
                    "end_line": node.end_lineno,
                    "value": node.name,
                    "bases": [self._get_name(base) for base in node.bases],
                    "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)],
                    "type": "class",
                })
        return classes

    def _get_comments(self) -> List[Dict[str, Any]]:
        """Get all comments - UNIFORM FORMAT."""
        comments = []
        for line_num, line in enumerate(self.source.split('\n'), 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                comments.append({
                    "line": line_num,
                    "value": stripped,
                    "type": "comment",
                })
        return comments

    def _get_constants(self) -> List[Dict[str, Any]]:
        """Get all constants (numbers, booleans, None) - UNIFORM FORMAT."""
        constants = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Constant):
                if isinstance(node.value, (int, float, bool, type(None))):
                    constants.append({
                        "line": node.lineno,
                        "value": node.value,
                        "type": type(node.value).__name__,
                    })
        return constants

    def _get_decorators(self) -> List[Dict[str, Any]]:
        """Get all decorators - UNIFORM FORMAT."""
        decorators = []
        for node in ast.walk(self.tree):
            if hasattr(node, 'decorator_list') and node.decorator_list:
                for decorator in node.decorator_list:
                    decorator_value = self._get_name(decorator)
                    target_value = node.name if hasattr(node, 'name') else "unknown"
                    decorators.append({
                        "line": node.lineno,
                        "value": decorator_value,
                        "target": target_value,
                        "type": "decorator",
                    })
        return decorators

    def _get_docstrings(self) -> List[Dict[str, Any]]:
        """Get all docstrings - UNIFORM FORMAT."""
        docstrings = []
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
                docstring = ast.get_docstring(node)
                if docstring:
                    docstrings.append({
                        "line": node.lineno,
                        "value": docstring,
                        "target": node.name if hasattr(node, 'name') else "module",
                        "type": "docstring",
                    })
        return docstrings

    def _get_loops(self) -> List[Dict[str, Any]]:
        """Get all loops."""
        loops = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.For):
                loops.append({
                    "line": node.lineno,
                    "target": self._get_name(node.target),
                    "iter": self._get_name(node.iter),
                    "type": "for_loop",
                })
            elif isinstance(node, ast.While):
                loops.append({
                    "line": node.lineno,
                    "condition": self._get_name(node.test),
                    "type": "while_loop",
                })
        return loops

    def _get_conditionals(self) -> List[Dict[str, Any]]:
        """Get all conditionals."""
        conditionals = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.If):
                conditionals.append({
                    "line": node.lineno,
                    "condition": self._get_name(node.test),
                    "has_else": bool(node.orelse),
                    "type": "if_conditional",
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
                    "type": "try_except",
                })
        return try_blocks

    def _get_variables(self) -> List[Dict[str, Any]]:
        """Get all variable names - UNIFORM FORMAT."""
        variables = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                variables.add(node.id)
        return [{"value": v, "type": "variable"} for v in sorted(variables)]

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
#
#
# parser = Parser(r'C:\Users\Acer\Downloads\TrustGuard\test_samples\credential_theft.py')
# result = parser.parse()
# print(result)