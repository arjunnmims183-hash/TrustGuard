import ast
import json
from typing import Dict, Any, Optional, List, Set, Tuple

import parser
from scanner.io import import_json


class BehaviorMappings:
    FEATURES = [""
                ""
                "","network_receive_calls","process_calls","file_read_calls","file_write_calls",
                "file_delete_calls","eval_exec_calls","obfuscation_calls","recon_calls","persistence_calls",
                "credential_access_calls","ransomware_calls","anti_forensics_calls","data_exfiltration_calls",
                "logic_bomb_patterns"]

    def __init__(self, json_path: Optional[str] = None):
        behavior_mappings = import_json._load_json("behavior_mappings.json")
        self.mappings = behavior_mappings.get('behavior_mappings', {})

    def _create_feature_vector(self) -> Dict[str, Any]:
        return {f: False for f in self.FEATURES} | {"data_flow_paths": []}

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
        calls = parser_result.get('calls', [])
        for call in set(calls):
            category = self.get_category(call, categories)
            if category is not None and category in feature_vector:
                feature_vector[category] = True

b =BehaviorMappings()
parser_result = parser.Parser(r'C:\Users\Acer\Downloads\TrustGuard\test_samples\credential_theft.py').parse();
b.analyze_parser_result(parser_result)
