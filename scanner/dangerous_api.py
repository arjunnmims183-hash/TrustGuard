import json
import os
from typing import Dict, List, Any, Optional

class DangerousAPIAnalyzer:
    def __init__(self, json_path: Optional[str] = None):
        self.dangerous_calls = self._load_json(json_path)

    def _load_json(self, json_path: Optional[str] = None) -> Dict[str, Any]:
        if json_path is None:
            for path in ["dangerous_calls.json", os.path.join(os.path.dirname(__file__), "dangerous_calls.json")]:
                if os.path.exists(path):
                    json_path = path
                    break

        if not json_path or not os.path.exists(json_path):
            return {}

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                return json.load(f).get("dangerous_calls", {})
        except Exception:
            return {}

    def analyze_parser_result(self, parser_result: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        details = {}
        for call in parser_result.get('calls_detailed', []):
            name = call.get('name', '')
            if name:
                if name not in details:
                    details[name] = {'lines': [], 'args': [], 'keywords': []}
                details[name]['lines'].append(call.get('line', 0))
                details[name]['args'] = call.get('args', [])[:3]
                details[name]['keywords'] = call.get('keywords', [])

        # Score each call
        scored = []
        for name in set(parser_result.get('calls', [])):
            info = self.dangerous_calls.get(name, {})
            d = details.get(name, {})

            scored.append({
                "name": name,
                "severity": info.get('severity', 0),
                "category": info.get('category', ''),
                "reason": info.get('reason', ''),
                "cwe": info.get('cwe', ''),
                "lines": d.get('lines', []),
                "args": d.get('args', []),
                "keywords": d.get('keywords', [])
            })

        # Sort by severity (highest first)
        scored.sort(key=lambda x: x['severity'], reverse=True)

        return result.append({
            "total_calls": len(scored),
            "scored_calls": scored
        })