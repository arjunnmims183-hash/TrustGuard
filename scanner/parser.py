import ast
import os
from typing import Dict, List, Any, Optional, Set, Tuple

MAX_SOURCE_SIZE = 10_000_000


class Parser:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.tree = None
        self.source = None

        self.version_counter: Dict[str, int] = {}
        self.raw_to_current: Dict[str, str] = {}
        self.var_chain: Dict[str, str] = {}
        self.var_values: Dict[str, str] = {}
        self.var_versions_by_line: Dict[str, List[Tuple[int, str]]] = {}

        self.alias_map: Dict[str, str] = {}
        self.variable_values: Dict[str, str] = {}
        self.variable_chain: Dict[str, str] = {}

    def parse(self) -> Dict[str, Any]:
        try:
            self.source = self._read_file()
            self.tree = ast.parse(self.source, filename=self.filepath)

            self._build_variable_chains(self.tree)
            self._build_alias_map(self.tree)

            self._build_version_graph(self.tree)

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
                "version_chain": self.var_chain,
                "version_values": self.var_values,
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

    def _next_version(self, var: str, line: int) -> str:
        count = self.version_counter.get(var, 0) + 1
        self.version_counter[var] = count
        ver = f"{var}#{count}"
        self.raw_to_current[var] = ver
        if var not in self.var_versions_by_line:
            self.var_versions_by_line[var] = []
        self.var_versions_by_line[var].append((line, ver))
        return ver

    def _current_version(self, var: str) -> str:
        return self.raw_to_current.get(var, var)

    def _previous_version(self, var: str) -> Optional[str]:
        count = self.version_counter.get(var, 0)
        if count > 1:
            return f"{var}#{count - 1}"
        return None

    def _get_version_for_resolution(self, var: str, current_version: str = None) -> str:
        if current_version and var == current_version.split('#')[0]:
            prev = self._previous_version(var)
            if prev:
                return prev
        return self._current_version(var)

    def _get_version_at_line(self, var: str, line: int) -> str:
        if var not in self.var_versions_by_line:
            return var
        entries = self.var_versions_by_line[var]
        lo, hi = 0, len(entries)
        while lo < hi:
            mid = (lo + hi) // 2
            if entries[mid][0] < line:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            return var
        return entries[lo-1][1]

    def _safe_unparse(self, node) -> str:
        try:
            return ast.unparse(node)
        except:
            return str(type(node).__name__)

    def _eval_expr(self, node) -> Optional[str]:
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

    def _build_version_graph(self, tree):
        assignments = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments.append((node, target, node.lineno))
        assignments.sort(key=lambda x: x[2])

        for node, target, line in assignments:
            var = target.id
            version = self._next_version(var, line)
            try:
                expr = ast.unparse(node.value)
                self.var_chain[version] = expr
                resolved = self._resolve_node_value(node.value, version, line)
                if resolved is not None:
                    self.var_values[version] = resolved
            except:
                self.var_chain[version] = "<unparse_error>"

    def _resolve_node_value(self, node, current_version: str = None, line: int = None, _depth: int = 0, _visited: set = None) -> Optional[str]:
        if node is None:
            return None

        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return repr(node.value)
            return str(node.value)

        if isinstance(node, ast.Name):
            var = node.id
            if line is not None:
                ver = self._get_version_at_line(var, line)
            else:
                ver = self._get_version_for_resolution(var, current_version)

            if ver in self.var_values:
                return self.var_values[ver]
            if ver in self.var_chain:
                return self._resolve_expression_with_version(self.var_chain[ver], ver, line, _depth + 1, _visited)
            if var in self.variable_values:
                return repr(self.variable_values[var])
            return var

        if isinstance(node, ast.Call):
            # Simplify __import__('module') -> 'module'
            func_name = self._resolve_node_value(node.func, current_version, line, _depth + 1, _visited)
            if func_name == "__import__" and node.args:
                arg_val = self._resolve_node_value(node.args[0], current_version, line, _depth + 1, _visited)
                if arg_val and arg_val.startswith("'") and arg_val.endswith("'"):
                    module_name = arg_val[1:-1]
                    if module_name.isidentifier():
                        return module_name

            func_expr = self._resolve_node_value(node.func, current_version, line, _depth + 1, _visited)
            if func_expr is None:
                func_expr = self._safe_unparse(node.func)

            args = []
            for arg in node.args:
                resolved = self._resolve_node_value(arg, current_version, line, _depth + 1, _visited)
                args.append(resolved if resolved is not None else self._safe_unparse(arg))

            kwargs = []
            for kw in node.keywords:
                if kw.arg:
                    val = self._resolve_node_value(kw.value, current_version, line, _depth + 1, _visited)
                    kwargs.append(f"{kw.arg}={val if val is not None else self._safe_unparse(kw.value)}")

            all_args = args + kwargs
            return f"{func_expr}({', '.join(all_args)})"

        if isinstance(node, ast.Attribute):
            base = self._resolve_node_value(node.value, current_version, line, _depth + 1, _visited)
            if base is None or base.startswith("<"):
                base = self._safe_unparse(node.value)
            return f"{base}.{node.attr}"

        if isinstance(node, ast.BinOp):
            val = self._eval_expr(node)
            if val is not None:
                return repr(val)
            left = self._resolve_node_value(node.left, current_version, line, _depth + 1, _visited)
            right = self._resolve_node_value(node.right, current_version, line, _depth + 1, _visited)
            op = ast.unparse(node.op).strip()
            if left is None:
                left = self._safe_unparse(node.left)
            if right is None:
                right = self._safe_unparse(node.right)
            return f"{left} {op} {right}"

        if isinstance(node, ast.UnaryOp):
            operand = self._resolve_node_value(node.operand, current_version, line, _depth + 1, _visited)
            op = ast.unparse(node.op).strip()
            return f"{op}{operand if operand is not None else self._safe_unparse(node.operand)}"

        if isinstance(node, ast.JoinedStr):
            result = ""
            for part in node.values:
                if isinstance(part, ast.Constant):
                    result += str(part.value)
                elif isinstance(part, ast.FormattedValue):
                    val = self._resolve_node_value(part.value, current_version, line, _depth + 1, _visited)
                    if val and val.startswith(("'", '"')):
                        val = val[1:-1]
                    result += val if val else ""
            return result

        if isinstance(node, ast.FormattedValue):
            return self._resolve_node_value(node.value, current_version, line, _depth + 1, _visited)

        if isinstance(node, ast.List):
            elements = []
            for el in node.elts:
                val = self._resolve_node_value(el, current_version, line, _depth + 1, _visited)
                elements.append(val if val is not None else self._safe_unparse(el))
            return f"[{', '.join(elements)}]"

        if isinstance(node, ast.Tuple):
            elements = []
            for el in node.elts:
                val = self._resolve_node_value(el, current_version, line, _depth + 1, _visited)
                elements.append(val if val is not None else self._safe_unparse(el))
            return f"({', '.join(elements)})"

        if isinstance(node, ast.Dict):
            items = []
            for k, v in zip(node.keys, node.values):
                key = self._resolve_node_value(k, current_version, line, _depth + 1, _visited)
                val = self._resolve_node_value(v, current_version, line, _depth + 1, _visited)
                items.append(f"{key if key is not None else self._safe_unparse(k)}: {val if val is not None else self._safe_unparse(v)}")
            return f"{{{', '.join(items)}}}"

        if isinstance(node, ast.Subscript):
            value = self._resolve_node_value(node.value, current_version, line, _depth + 1, _visited)
            slice_val = self._resolve_node_value(node.slice, current_version, line, _depth + 1, _visited)
            return f"{value if value is not None else self._safe_unparse(node.value)}[{slice_val if slice_val is not None else self._safe_unparse(node.slice)}]"

        try:
            return ast.unparse(node)
        except:
            return None

    def _resolve_expression_with_version(self, expr: str, version: str, line: int = None, _depth: int = 0, _visited: set = None) -> str:
        if _depth > 30:
            return "<depth_limit>"

        if _visited is None:
            _visited = set()

        if expr is None:
            return ""

        expr = expr.strip()

        key = f"{expr}:{version}"
        if key in _visited:
            return "<circular>"
        _visited.add(key)

        if expr.isidentifier():
            var = expr
            if line is not None:
                ver = self._get_version_at_line(var, line)
            else:
                ver = self._get_version_for_resolution(var, version)

            if ver in self.var_values:
                return self.var_values[ver]
            if ver in self.var_chain:
                return self._resolve_expression_with_version(self.var_chain[ver], ver, line, _depth + 1, _visited)
            if var in self.variable_values:
                return repr(self.variable_values[var])
            return expr

        if '(' in expr and ')' in expr:
            try:
                call_name = expr.split('(', 1)[0].strip()
                args_str = expr[expr.find('(') + 1:expr.rfind(')')]
            except:
                return expr

            if call_name == "__import__" and args_str:
                arg = args_str.strip()
                if arg and arg.startswith("'") and arg.endswith("'"):
                    module_name = arg[1:-1]
                    if module_name.isidentifier():
                        return module_name
                if arg.isidentifier():
                    resolved = self._resolve_expression_with_version(arg, version, line, _depth + 1, _visited)
                    if resolved and resolved.startswith("'") and resolved.endswith("'"):
                        module_name = resolved[1:-1]
                        if module_name.isidentifier():
                            return module_name

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
                        resolved_args.append(self._resolve_expression_with_version(arg, version, line, _depth + 1, _visited))
                    else:
                        if '+' in arg and all(x.strip().startswith("'") for x in arg.split('+')):
                            try:
                                parts = [p.strip().strip("'") for p in arg.split('+')]
                                const_val = ''.join(parts)
                                resolved_args.append(repr(const_val))
                            except:
                                resolved_args.append(arg)
                        else:
                            resolved_args.append(arg)

                return f"{call_name}({', '.join(resolved_args)})"
            return expr

        if (expr.startswith("'") and expr.endswith("'")) or (expr.startswith('"') and expr.endswith('"')):
            return expr

        return expr

    def _build_variable_chains(self, tree):
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
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        call = node.value
                        if self._is_dynamic_import(call):
                            module_name = None
                            if call.args:
                                arg = call.args[0]
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    module_name = arg.value
                                elif isinstance(arg, ast.Name):
                                    if arg.id in self.variable_values:
                                        module_name = self.variable_values[arg.id]
                                    elif arg.id in self.variable_chain:
                                        resolved = self._resolve_expression_with_version(self.variable_chain[arg.id], "")
                                        if resolved and resolved.startswith("'") and resolved.endswith("'"):
                                            module_name = resolved[1:-1]
                                elif isinstance(arg, ast.BinOp):
                                    module_name = self._eval_expr(arg)

                            if module_name and isinstance(module_name, str):
                                self.alias_map[target.id] = module_name

    def _is_dynamic_import(self, call_node) -> bool:
        func = call_node.func
        if isinstance(func, ast.Name) and func.id == '__import__':
            return True
        if isinstance(func, ast.Attribute):
            if (isinstance(func.value, ast.Name) and func.value.id == 'importlib'
                    and func.attr == 'import_module'):
                return True
        return False

    def _resolve_call_name(self, node) -> str:
        if node is None:
            return ""

        if isinstance(node, ast.Name):
            if node.id in self.alias_map:
                return self.alias_map[node.id]
            return node.id

        if isinstance(node, ast.Attribute):
            resolved_base = self._resolve_call_name(node.value)
            attr = node.attr
            if resolved_base:
                return f"{resolved_base}.{attr}"
            return attr

        if isinstance(node, ast.Call):
            return self._resolve_call_name(node.func)

        if isinstance(node, ast.Constant):
            return str(node.value)

        try:
            return ast.unparse(node)
        except:
            return str(type(node).__name__)

    def _resolve_value(self, node, line: int = None) -> str:
        if node is None:
            return ""

        resolved = self._resolve_node_value(node, current_version=None, line=line)
        return resolved if resolved is not None else self._safe_unparse(node)

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
                    line = node.lineno
                    resolved_args = []
                    for arg in node.args:
                        resolved_args.append(self._resolve_value(arg, line=line))

                    resolved_keywords = []
                    for kw in node.keywords:
                        if kw.arg:
                            resolved_keywords.append({
                                "arg": kw.arg,
                                "value": self._resolve_value(kw.value, line=line)
                            })

                    calls.append({
                        "name": name,
                        "line": line,
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
                        var = target.id
                        line = node.lineno
                        rhs = self._get_value_repr(node.value)
                        resolved = self._resolve_value(node.value, line=line)
                        assignments.append({
                            "line": line,
                            "variable": var,
                            "value": rhs,
                            "resolved_value": resolved if resolved != rhs else None,
                            "version": self._current_version(var),
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


if __name__ == "__main__":
    import json
    parser = Parser(r'C:\Users\Acer\Downloads\TrustGuard\test_samples\credential_theft.py')
    result = parser.parse()
    print(json.dumps(result, indent=2))