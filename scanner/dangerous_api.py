from typing import Dict, List, Any, Optional
from scanner.io import import_json


class DangerousAPIAnalyzer:
    def __init__(self, json_path: Optional[str] = None):
        self.dangerous_calls = import_json._load_json("risky_calls.json").get('dangerous_calls', {})

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
        # Step 1: Aggregate details per call name
        details = {}
        for call in parser_result.get('calls_detailed', []):
            name = call.get('name', '')
            if not name:
                continue

            if name not in details:
                # Store first occurrence of args/keywords; accumulate lines
                details[name] = {
                    'lines': [],
                    'args': call.get('args', []),
                    'keywords': call.get('keywords', [])
                }
            details[name]['lines'].append(call.get('line', 0))

        # Step 2: Build scored calls list
        scored = []
        for name, d in details.items():
            info = self.dangerous_calls.get(name, {})
            scored.append({
                "name": name,
                "severity": info.get('severity', 0),
                "category": info.get('category', ''),
                "reason": info.get('reason', ''),
                "cwe": info.get('cwe', ''),
                "lines": d['lines'],
                "args": d['args'],
                "keywords": d['keywords']
            })

        # Step 3: Sort by severity descending
        scored.sort(key=lambda x: x['severity'], reverse=True)

        return {
            "api_analysis": {
                "total_calls": len(scored),
                "scored_calls": scored
            }
        }