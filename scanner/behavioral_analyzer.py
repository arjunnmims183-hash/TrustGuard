import ast
import json
from typing import Dict, Any, Optional, List, Set, Tuple

import parser
from scanner.io import import_json


class BehaviorMappings:
    def __init__(self, json_path: Optional[str] = None):
        behavior_mappings = import_json._load_json("behavior_mappings.json")
        self.mappings = behavior_mappings.get('behavior_mappings', {})
        self.FEATURES = behavior_mappings.get('feature_categories', [])

        flow_mappings = import_json._load_json("behavior_mappings.json")
        self.source_functions = flow_mappings.get("source_functions", {})
        self.transform_functions = flow_mappings.get("transform_functions", {})
        self.sink_functions = flow_mappings.get("sink_functions", {})

    def _create_feature_vector(self) -> Dict[str, Any]:
        vector = {}
        for f in self.FEATURES:
            vector[f] = {"enabled": False,"calls": [],"lines": [],"details": []}
        return vector

    def _extract_categories(self):
        categories = {}
        for name, info in self.mappings.items():
            categories[name] = set(info.get('calls', []))
        return categories

    def get_category(self, call_name: str, categories: Optional[Dict] = None) -> Optional[str]:
        for cat, calls in categories.items():
            if call_name in calls:
                return cat
        return None

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
        feature_vector = self._create_feature_vector()
        categories = self._extract_categories()

        for call in parser_result.get('calls_detailed', []):
            name = call.get('name', '')
            if not name:
                continue

            category = self.get_category(name, categories)
            if category is None:
                continue

            # Update category entry
            entry = feature_vector[category]
            entry["enabled"] = True
            # Keep unique call names (for summary)
            if name not in entry["calls"]:
                entry["calls"].append(name)
            # Always append line and detail
            entry["lines"].append(call.get('line', 0))
            entry["details"].append({
                "name": name,
                "line": call.get('line', 0),
                "args": call.get('args', []),
                "keywords": call.get('keywords', [])
            })


        return feature_vector

b =BehaviorMappings()
parser_result = parser.Parser(r'C:\Users\vijen\Downloads\TrustGuard\test_samples\credential_theft.py').parse();
b.analyze_parser_result(parser_result)
