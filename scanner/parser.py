import ast
import os
from typing import Dict, List, Any, Optional

MAX_SOURCE_SIZE = 10_000_000

class Parser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.tree = None
        self.source = None
        self.alias_map = {}  # variable_name -> resolved_module (e.g., "my_os" -> "os")
        self.variable_values = {}  # variable_name -> constant_value (e.g., "module_name" -> "os")
        self.variable_chain = {}  # variable_name -> full expression chain

    def parse(self) -> Dict[str, Any]:
        try:
            self.source = self._read_file()
            self.tree = ast.parse(self.source, filename=self.filepath)

            self._build_variable_chain(self.tree)
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
                "alias_map": self.alias_map,
                "error": None,
            }
        except Exception as e:
            return {"file": self.filepath, "error": str(e)}

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
    # Alias and Variable Value Resolution
    # ------------------------------------------------------------------

    def _eval_expr(self, node) -> Optional[str]:
        """
        Evaluate a constant expression (e.g., "o" + "s", variable references).
        Returns the constant value if possible, else None.
        """
        if node is None:
            return None

        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None

        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._eval_expr(node.left)
            right = self._eval_expr(node.right)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
            return None

        if isinstance(node, ast.Name):
            return self.variable_values.get(node.id)

        return None

    def _resolve_variable_chain(self, var_name: str, visited: set = None) -> str:
        """Recursively resolve a variable to its final value."""
        if visited is None:
            visited = set()

        if var_name in visited:
            return var_name
        visited.add(var_name)

        if var_name in self.variable_chain:
            expr = self.variable_chain[var_name]
            if expr.isidentifier():
                return self._resolve_variable_chain(expr, visited)
            return self._resolve_expr_variables(expr, visited)

        if var_name in self.variable_values:
            return repr(self.variable_values[var_name])

        return var_name

    def _resolve_expr_variables(self, expr: str, visited: set = None) -> str:
        """Resolve variables inside an expression."""
        if visited is None:
            visited = set()

        if expr.isidentifier():
            return self._resolve_variable_chain(expr, visited)

        # Handle f-string
        if 'f"' in expr or "f'" in expr:
            if expr.startswith('f"') and expr.endswith('"'):
                content = expr[2:-1]
            elif expr.startswith("f'") and expr.endswith("'"):
                content = expr[2:-1]
            else:
                return expr

            import re
            def replace_var(match):
                var = match.group(1)
                resolved = self._resolve_variable_chain(var, visited)
                return resolved if resolved != var else match.group(0)

            result = re.sub(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}', replace_var, content)
            return result

        # Handle function calls
        if '(' in expr and ')' in expr:
            call_name = expr.split('(', 1)[0].strip()
            args_str = expr[expr.find('(') + 1:expr.rfind(')')]

            if args_str:
                args = []
                current = ""
                depth = 0
                in_string = False
                string_char = None

                for ch in args_str:
                    if ch in ("'", '"') and (not current or current[-1] != '\\'):
                        if not in_string:
                            in_string = True
                            string_char = ch
                        elif ch == string_char:
                            in_string = False

                    if not in_string:
                        if ch == '(':
                            depth += 1
                        elif ch == ')':
                            depth -= 1
                        elif ch == ',' and depth == 0:
                            args.append(current.strip())
                            current = ""
                            continue
                    current += ch
                if current:
                    args.append(current.strip())

                resolved_args = []
                for arg in args:
                    if arg.isidentifier():
                        resolved_args.append(self._resolve_variable_chain(arg, visited))
                    else:
                        resolved_args.append(arg)

                return f"{call_name}({', '.join(resolved_args)})"
            return expr

        # String literal
        if (expr.startswith("'") and expr.endswith("'")) or (expr.startswith('"') and expr.endswith('"')):
            return expr

        return expr

    def _build_variable_chain(self, tree):
        """Build variable chain from assignments."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        try:
                            expr_str = ast.unparse(node.value)
                            self.variable_chain[target.id] = expr_str
                            val = self._eval_expr(node.value)
                            if val is not None:
                                self.variable_values[target.id] = val
                        except:
                            pass

    def _build_alias_map(self, tree):
        """
        Build alias map for dynamic imports.
        Example: my_os = __import__(module_name) where module_name = "os"
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        call = node.value

                        if self._is_dynamic_import(call):
                            module_name = None

                            if call.args:
                                arg = call.args[0]

                                # Direct string constant
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    module_name = arg.value

                                # Variable reference (resolve it)
                                elif isinstance(arg, ast.Name):
                                    # Try variable_values first
                                    if arg.id in self.variable_values:
                                        module_name = self.variable_values[arg.id]
                                    # Try variable_chain
                                    elif arg.id in self.variable_chain:
                                        resolved = self._resolve_variable_chain(arg.id)
                                        if resolved and resolved != arg.id:
                                            module_name = resolved

                                # Binary operation like "o" + "s"
                                elif isinstance(arg, ast.BinOp):
                                    module_name = self._eval_expr(arg)

                            # If we got a module name, add to alias_map
                            if module_name and isinstance(module_name, str):
                                self.alias_map[target.id] = module_name
                                print(f"✅ Alias: {target.id} -> {module_name}")  # Debug

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
        Resolve call name with alias support.
        Example: my_os.getenv -> os.getenv
        """
        if node is None:
            return ""

        # ---- Name node ----
        if isinstance(node, ast.Name):
            if node.id in self.alias_map:
                return self.alias_map[node.id]
            return node.id

        # ---- Attribute node ----
        if isinstance(node, ast.Attribute):
            resolved_base = self._resolve_call_name(node.value)
            attr = node.attr

            # If base is an alias, it's already resolved
            if resolved_base:
                return f"{resolved_base}.{attr}"
            return attr

        # ---- Call node ----
        if isinstance(node, ast.Call):
            return self._resolve_call_name(node.func)

        # ---- Constant ----
        if isinstance(node, ast.Constant):
            return str(node.value)

        try:
            return ast.unparse(node)
        except:
            return str(type(node).__name__)

    def _resolve_value(self, node) -> str:
        """Resolve a node to its constant value if possible."""
        if node is None:
            return ""

        # ---- Name node ----
        if isinstance(node, ast.Name):
            var_name = node.id
            if var_name in self.variable_values:
                return repr(self.variable_values[var_name])
            if var_name in self.variable_chain:
                return self._resolve_variable_chain(var_name)
            return var_name

        # ---- Constant node ----
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return repr(node.value)
            return str(node.value)

        # ---- F-string ----
        if isinstance(node, ast.JoinedStr):
            result = ""
            for part in node.values:
                if isinstance(part, ast.Constant):
                    result += str(part.value)
                elif isinstance(part, ast.FormattedValue):
                    val = self._resolve_value(part.value)
                    if val.startswith("'") and val.endswith("'"):
                        val = val[1:-1]
                    elif val.startswith('"') and val.endswith('"'):
                        val = val[1:-1]
                    result += val
            return result

        if isinstance(node, ast.FormattedValue):
            return self._resolve_value(node.value)

        # ---- BinOp ----
        if isinstance(node, ast.BinOp):
            val = self._eval_expr(node)
            if val is not None:
                return repr(val)

        # ---- Call node ----
        if isinstance(node, ast.Call):
            name = self._resolve_call_name(node.func)
            args = [self._resolve_value(a) for a in node.args]
            kwargs = []
            for kw in node.keywords:
                if kw.arg:
                    kwargs.append(f"{kw.arg}={self._resolve_value(kw.value)}")
            all_args = args + kwargs
            return f"{name}({', '.join(all_args)})"

        # ---- Attribute node ----
        if isinstance(node, ast.Attribute):
            resolved_base = self._resolve_value(node.value)
            return f"{resolved_base}.{node.attr}"

        try:
            return ast.unparse(node)
        except:
            return str(type(node).__name__)

    # ------------------------------------------------------------------
    # Existing methods
    # ------------------------------------------------------------------

    def _get_imports(self) -> List[str]:
        imports = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split('.')[0])
        return sorted(imports)

    def _get_imports_detailed(self) -> List[Dict[str, Any]]:
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
        calls = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self._resolve_call_name(node.func)
                if name and name not in {"", "None", "True", "False", "self", "cls", "chr"}:
                    calls.append(name)
        return calls

    def _get_calls_detailed(self) -> List[Dict[str, Any]]:
        calls = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                name = self._resolve_call_name(node.func)
                if name and name not in {"", "None", "True", "False", "self", "cls", "chr"}:
                    resolved_args = []
                    for arg in node.args:
                        resolved_args.append(self._resolve_value(arg))

                    resolved_keywords = []
                    for kw in node.keywords:
                        if kw.arg:
                            resolved_keywords.append({
                                "arg": kw.arg,
                                "value": self._resolve_value(kw.value)
                            })

                    calls.append({
                        "name": name,
                        "line": node.lineno,
                        "arg_count": len(node.args),
                        "kw_count": len(node.keywords),
                        "args": resolved_args,
                        "keywords": resolved_keywords
                    })
        return calls

    def _get_strings(self) -> List[Dict[str, Any]]:
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
            return ast.unparse(node)
        except Exception:
            if isinstance(node, ast.Constant):
                return repr(node.value)
            return str(node)[:50]

    def _get_functions(self) -> List[Dict[str, Any]]:
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
        variables = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                variables.add(node.id)
        return [{"value": v, "type": "variable"} for v in sorted(variables)]

    def _get_name(self, node) -> str:
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