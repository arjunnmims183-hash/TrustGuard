import json
from typing import Dict, Any, Optional, List, Set, Tuple

import parser
from scanner.io import import_json

class BehaviorMappings:
    def __init__(self, json_path: Optional[str] = None):
        behavior_mappings = import_json._load_json("behavior_mappings.json")
        self.mappings = behavior_mappings.get('behavior_mappings', {})
        self.FEATURES = behavior_mappings.get('feature_categories', [])

        flow_mappings = import_json._load_json("flow_mappings.json")
        self.source_functions = flow_mappings.get("source_functions", {})
        self.transform_functions = flow_mappings.get("transform_functions", {})
        self.sink_functions = flow_mappings.get("sink_functions", {})

        self.sink_call_desc = {name: info.get("description", "") for name, info in self.sink_functions.items()}
        self._reset_analysis_state()

    def _reset_analysis_state(self):
        self.version_counter: Dict[str, int] = {}
        self.raw_to_current: Dict[str, str] = {}
        self.var_metadata: Dict[str, Dict] = {}
        self.var_aliases: Dict[str, str] = {}
        self.var_transforms: Dict[str, Dict] = {}
        self.var_sources: Dict[str, Dict] = {}
        self.flows: List[Dict] = []

    def _create_feature_vector(self) -> Dict[str, Any]:
        vector = {}
        for f in self.FEATURES:
            vector[f] = {"enabled": False, "calls": [], "lines": [], "details": []}
        return vector

    def _extract_categories(self) -> Dict[str, Set[str]]:
        categories = {}
        for name, info in self.mappings.items():
            categories[name] = set(info.get('calls', []))
        return categories

    def get_category(self, call_name: str, categories: Dict[str, Set[str]]) -> Optional[str]:
        for cat, calls in categories.items():
            if call_name in calls:
                return cat
        return None

    def build_feature_vector(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
        feature_vector = self._create_feature_vector()
        categories = self._extract_categories()

        for call in parser_result.get('calls_detailed', []):
            name = call.get('name', '')
            if not name:
                continue
            category = self.get_category(name, categories)
            if category is None:
                continue
            entry = feature_vector[category]
            entry["enabled"] = True
            if name not in entry["calls"]:
                entry["calls"].append(name)
            entry["lines"].append(call.get('line', 0))
            entry["details"].append({
                "name": name,
                "line": call.get('line', 0),
                "args": call.get('args', []),
                "keywords": call.get('keywords', [])  # now list of dicts
            })
        return feature_vector

    def _next_version(self, var: str) -> str:
        count = self.version_counter.get(var, 0) + 1
        self.version_counter[var] = count
        ver = f"{var}#{count}"
        self.raw_to_current[var] = ver
        return ver

    def _is_simple_var(self, expr: str) -> bool:
        expr = expr.strip()
        return expr.isidentifier() and not expr.startswith(("'", '"', "b'", 'b"'))

    def _is_string_literal(self, rhs: str) -> bool:
        s = rhs.strip()
        return len(s) > 1 and (
                s[0] in "'\"" or s[:2] in ("b'", 'b"')
        ) and s[-1] in "'\""

    def _is_inside_string(self, expr: str) -> bool:
        if expr.startswith(("'", '"')) and expr.endswith(("'", '"')):
            return True
        return False

    def _extract_call_name(self, rhs: str) -> Optional[str]:
        name = rhs.split("(", 1)[0].strip()
        return name if "(" in rhs and name and not name.startswith(".") else None

    def _match_call_to_mapping(self, call_name: str, mapping: Dict[str, Any]) -> Optional[Tuple[str, Dict]]:
        if not call_name or not mapping:
            return None

        if call_name in mapping:
            return call_name, mapping[call_name]

        after_dot = call_name.split(".", 1)[1] if "." in call_name else call_name

        for key, info in mapping.items():
            if key.endswith("." + after_dot):
                return key, info

        return None

    def _extract_all_args(self, rhs: str) -> List[str]:
        if "(" not in rhs:
            return []

        args, current = [], ""
        depth, quote = 0, None
        for ch in rhs[rhs.find("(") + 1:]:
            if ch in "'\"":
                quote = None if quote == ch else ch
            if quote:
                current += ch
                continue
            if ch in "()":
                if ch == ")" and depth == 0:
                    break
                depth += 1 if ch == "(" else -1
            elif ch == "," and depth == 0:
                args.append(current.strip())
                current = ""
                continue
            current += ch
        if current.strip():
            args.append(current.strip())

        return [
            arg for arg in args
            if not ("=" in arg and not self._is_inside_string(arg))
        ]

    def _extract_all_kwargs(self, rhs: str) -> List[Tuple[str, str]]:
        if "(" not in rhs:
            return []

        items, current = [], ""
        depth, quote = 0, None

        for ch in rhs[rhs.find("(") + 1:]:
            if ch in "'\"":
                quote = None if quote == ch else ch

            if quote:
                current += ch
                continue
            if ch in "()":
                if ch == ")" and depth == 0:
                    break
                depth += 1 if ch == "(" else -1
            elif ch == "," and depth == 0:
                items.append(current.strip())
                current = ""
                continue
            current += ch

        if current.strip():
            items.append(current.strip())
        result = []

        for item in items:
            if "=" not in item or self._is_inside_string(item):
                continue
            key, value = map(str.strip, item.split("=", 1))
            if value[:1] in "'\"" and value[-1:] in "'\"":
                value = value[1:-1]
            result.append((key, value))

        return result

    def build_graph(self, parser_result: Dict[str, Any]):
        assignments = sorted(
            parser_result.get("assignments", []),
            key=lambda x: x.get("line", 0)
        )
        for assign in assignments:
            var = assign.get("variable")
            rhs = assign.get("value")
            if not var or rhs is None:
                continue

            version = self._next_version(var)
            self.var_metadata[version] = {"line": assign.get("line", 0)}
            self.var_transforms[version] = {}
            self.var_sources[version] = {}
            if self._is_simple_var(rhs) and rhs in self.raw_to_current:
                self.var_aliases[version] = self.raw_to_current[rhs]
                continue

            if self._is_string_literal(rhs):
                self.var_sources[version] = {
                    "type": "user_input",
                    "description": "Hardcoded string literal.",
                    "category": "recon_calls"
                }
                continue

            call_name = self._extract_call_name(rhs)
            if not call_name:
                continue

            matched = self._match_call_to_mapping(call_name, self.source_functions)

            if matched:
                matched_key, source_info = matched
                self.var_sources[version] = source_info.copy()
                self.var_sources[version]["matched_key"] = matched_key
                continue

            matched = self._match_call_to_mapping(call_name, self.transform_functions)

            if matched:
                matched_key, transform_info = matched
                input_vars = []

                import re
                method_match = re.search(r'\.([a-zA-Z_][a-zA-Z0-9_]*)\([^)]*\)$', rhs)
                if method_match:
                    method_name = method_match.group(1)

                    obj_expr = rhs[:method_match.start()].strip()

                    input_var = None

                    if obj_expr.isidentifier() and obj_expr in self.raw_to_current:
                        input_var = obj_expr
                    else:
                        input_var = self._extract_all_args(obj_expr)
                        if not input_var:
                            match = re.search(r'\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)', obj_expr)
                            if match:
                                input_var = match.group(1)

                    if input_var and input_var[0] in self.raw_to_current:
                        for var in input_var:
                            if var in self.raw_to_current:
                                input_vars.append(var.strip())

                if not input_vars:

                    if '(' in rhs and rhs.rstrip().endswith('()') and '.' in call_name:
                        obj = rhs.split('.', 1)[0].strip()
                        if obj and obj in self.raw_to_current:
                            input_vars.append(obj)
                    else:
                        args = self._extract_all_args(rhs)
                        for arg in args:
                            if arg and arg in self.raw_to_current:
                                input_vars.append(arg)

                        kwargs = self._extract_all_kwargs(rhs)
                        for kw_name, kw_value in kwargs:
                            if kw_value and kw_value in self.raw_to_current:
                                input_vars.append(kw_value)

                if input_vars:
                    input_vers = []
                    for inp in input_vars:
                        if inp in self.raw_to_current:
                            if inp == var:
                                prev_count = self.version_counter.get(var, 1) - 1
                                if prev_count > 0:
                                    input_ver = f"{var}#{prev_count}"
                                else:
                                    input_ver = self.raw_to_current[inp]
                            else:
                                input_ver = self.raw_to_current[inp]
                            input_vers.append(input_ver)
                    if input_vers:
                        self.var_transforms[version] = {
                            "transform": transform_info["type"],
                            "description": transform_info["description"],
                            "input": input_vers,
                            "macthed_key": matched_key
                        }
                continue

    def _resolve_flow(self, version: str) -> Optional[Dict]:
        visited = set()
        current = version
        transforms = []
        while current in self.var_metadata and current not in visited:
            visited.add(current)
            if self.var_sources.get(current):
                return {
                    "source": self.var_sources[current],
                    "transforms": list(reversed(transforms)),
                    "source_var": current,
                }
            if current in self.var_transforms:

                info = self.var_transforms[current]
                if info.get("transform") and info.get("input"):
                    transforms.append({
                        "type": info["transform"],
                        "matched_key": info.get("matched_key", ""),
                        "description": info.get("description", "")
                    })
                    if isinstance(info["input"], list) and info["input"]:
                        current = info["input"][0]
                    else:
                        current = info["input"]
                    continue

            if current in self.var_aliases:
                current = self.var_aliases[current]
                continue

            if current in self.raw_to_current:
                current = self.raw_to_current[current]
                continue
            break

        if not transforms and current and self._is_string_literal(current):
            return {
                "source": {
                    "type": "user_input",
                    "description": "Hardcoded string literal.",
                    "category": "recon_calls"
                },
                "transforms": [],
                "source_var": current[:30] + "..." if len(current) > 30 else current,
            }

        return None

    def _detect_sinks(self, feature_vector: Dict[str, Any]):
        for category, data in feature_vector.items():
            if not data.get("enabled", False):
                continue

            for detail in data.get("details", []):
                sink_name = detail.get("name")
                matched = self._match_call_to_mapping(sink_name, self.sink_functions)
                if matched:
                    matched_key, sink_info = matched

                    def process_arg(arg_value: str, arg_type: str, arg_name: Optional[str] = None):
                        if not arg_value:
                            return

                        if arg_value in self.raw_to_current:
                            ver = self.raw_to_current[arg_value]
                            flow = self._resolve_flow(ver)
                        else:
                            flow = self._resolve_flow(arg_value)

                        if flow:
                            flow["sink_type"] = sink_info.get("type")
                            flow["sink_call"] = sink_name
                            flow["sink_matched_key"] = matched_key
                            flow["sink_line"] = detail.get("line")
                            flow["sink_category"] = category
                            flow["sink_arg_type"] = arg_type
                            flow["sink_arg_name"] = arg_name
                            self.flows.append(flow)

                    for arg in detail.get("args", []):
                        process_arg(arg, "positional")

                    for kw in detail.get("keywords", []):
                        if kw:
                            arg_name = kw.get("arg")
                            value = kw.get("value")
                            process_arg(value, "keyword", arg_name)

    def _enrich_flow(self, flow: Dict) -> Dict:
        source_info = flow["source"]
        transforms_list = flow["transforms"]
        sink_type = flow["sink_type"]
        sink_call = flow["sink_call"]

        enriched = {
            "source": source_info.get("type", "unknown"),
            "source_description": source_info.get("description", "Unknown data source."),
            "source_matched_key": source_info.get("matched_key"),
            "transforms": [t.get("type", "unknown") for t in transforms_list],
            "transform_descriptions": [t.get("description", "Unknown transformation.") for t in transforms_list],
            "transform_matched_keys": [t.get("matched_key", "") for t in transforms_list],
            "sink": sink_type,
            "sink_description": self.sink_call_desc.get(sink_call, "Unknown data destination."),
            "sink_call": sink_call,
            "sink_call_description": self.sink_call_desc.get(sink_call, "Unknown sink function."),
            "sink_matched_key": flow.get("sink_matched_key"),
            "sink_line": flow.get("sink_line"),
            "sink_category": flow.get("sink_category"),
            "sink_arg_type": flow.get("sink_arg_type", "unknown"),
            "sink_arg_name": flow.get("sink_arg_name"),
            "source_var": flow.get("source_var").split("#")[0],
            "data_flow": " → ".join(
                [source_info.get("type", "unknown")] +
                [t.get("type", "unknown") for t in transforms_list] +
                [sink_type]
            )
        }
        return enriched

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
        feature_vector = self.build_feature_vector(parser_result)
        self._reset_analysis_state()
        self.build_graph(parser_result)
        self._detect_sinks(feature_vector)
        enriched_flows = [self._enrich_flow(f) for f in self.flows]

        return {
            "behaviour_analysis": {
                "enriched_flows": enriched_flows,
                "feature_vector": feature_vector
            }
        }

if __name__ == "__main__":
    b = BehaviorMappings()
    parser_result = parser.Parser(r'C:\Users\Acer\Downloads\TrustGuard\test_samples\credential_theft.py').parse()
    result = b.analyze_parser_result(parser_result)
    print(json.dumps(result, indent=2))