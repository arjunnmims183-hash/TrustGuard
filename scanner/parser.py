"""
parser_pure.py - Pure AST parser without security logic.
Just extracts raw data. Security checks will be added later.
"""

import ast
import os
from typing import Dict, List, Any, Optional

MAX_SOURCE_SIZE = 10_000_000

class Parser:
    """Pure parser - extracts raw data only. No security logic."""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.tree = None
        self.source = None
        # For alias resolution
        self.alias_map = {}          # variable_name -> resolved_module (e.g., "my_os" -> "os")
        self.variable_values = {}    # variable_name -> constant_value (e.g., "module_name" -> "os")

    def parse(self) -> Dict[str, Any]:
        """Parse file and return raw data."""
        try:
            self.source = self._read_file()
            self.tree = ast.parse(self.source, filename=self.filepath)

            # Build alias map *before* extracting calls so that calls can be resolved
            self._build_alias_map(self.tree)

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
                "alias_map": self.alias_map,   # optional, for debugging
                "error": None,
            }
        except Exception as e:
            return {"file": self.filepath, "error": str(e), **self._empty_result()}

    def _empty_result(self) -> Dict[str, Any]:
        return {
            "lines": 0,
            "imports": [],
            "imports_detailed": [],
            "calls": [],
            "calls_detailed": [],
            "strings": [],
            "assignments": [],
            "functions": [],
            "classes": [],
            "comments": [],
            "constants": [],
            "decorators": [],
            "docstrings": [],
            "loops": [],
            "conditionals": [],
            "try_except": [],
            "variables": [],
            "alias_map": {},
        }

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

    # ------------------------------------------------------------------
    # New methods for alias resolution
    # ------------------------------------------------------------------

    def _eval_expr(self, node) -> Optional[str]:
        """
        Evaluate a constant expression (e.g., "o" + "s", variable references).
        Returns the constant value if possible, else None.
        """
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._eval_expr(node.left)
            right = self._eval_expr(node.right)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
            return None
        if isinstance(node, ast.Name):
            # Look up variable value from previously assigned constants
            return self.variable_values.get(node.id)
        # Add more operations (e.g., multiplication) if needed
        return None

    def _build_alias_map(self, tree):
        """
        Walk the AST to find dynamic imports and constant assignments.
        Populates self.alias_map and self.variable_values.
        """
        for node in ast.walk(tree):
            # Track constant assignments (e.g., module_name = "o" + "s")
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        val = self._eval_expr(node.value)
                        if val is not None:
                            self.variable_values[target.id] = val

            # Find dynamic imports: __import__(...) or importlib.import_module(...)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        call = node.value
                        if self._is_dynamic_import(call):
                            module_name = self._eval_expr(call.args[0]) if call.args else None
                            if module_name and isinstance(module_name, str):
                                self.alias_map[target.id] = module_name

    def _is_dynamic_import(self, call_node) -> bool:
        """Return True if call is __import__ or importlib.import_module."""
        func = call_node.func
        if isinstance(func, ast.Name) and func.id == '__import__':
            return True
        if isinstance(func, ast.Attribute):
            if (isinstance(func.value, ast.Name) and func.value.id == 'importlib'
                    and func.attr == 'import_module'):
                return True
        return False

    def _resolve_call_name(self, node) -> str:
        """
        Resolve an AST node that represents a callable name (e.g., my_os.getenv -> os.getenv).
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = node.value
            attr = node.attr
            # Resolve base if it's a Name and in alias_map
            if isinstance(base, ast.Name) and base.id in self.alias_map:
                resolved_base = self.alias_map[base.id]
                return f"{resolved_base}.{attr}"
            # Otherwise, recursively resolve base (e.g., a.b.c)
            resolved_base = self._resolve_call_name(base) if hasattr(base, 'id') or hasattr(base, 'value') else None
            if resolved_base:
                return f"{resolved_base}.{attr}"
            # Fallback to unparse
            return ast.unparse(node)
        # Fallback for other types
        return self._get_name(node)

    # ------------------------------------------------------------------
    # Existing methods (modified where needed)
    # ------------------------------------------------------------------

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
        """Get all function/method call names, resolved for aliases."""
        calls = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self._resolve_call_name(node.func)
                if name and name not in {"", "None", "True", "False", "self", "cls"}:
                    calls.append(name)
        return calls

    def _get_calls_detailed(self) -> List[Dict[str, Any]]:
        """Get detailed call info, with resolved names."""
        calls = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self._resolve_call_name(node.func)
                if name and name not in {"", "None", "True", "False", "self", "cls"}:
                    calls.append({
                        "name": name,
                        "line": node.lineno,
                        "arg_count": len(node.args),
                        "kw_count": len(node.keywords),
                        "args": [self._resolve_call_name(a) if isinstance(a, (ast.Name, ast.Attribute)) else self._get_name(a) for a in node.args],
                        "keywords": [
                            {"arg": kw.arg, "value": self._resolve_call_name(kw.value) if isinstance(kw.value, (ast.Name, ast.Attribute)) else self._get_name(kw.value)}
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


#For testing
#parser = Parser(r'C:\Users\naman\Mirror\Downloads\naman\MEITY\Project\trustguard_phase1+2\trustguard_v2&v3\test_samples\credential_theft.py')
#esult = parser.parse()
#print(result)