from typing import Dict, List, Any, Optional

from scanner.io import import_json

class DangerousAPIAnalyzer:
    def __init__(self, json_path: Optional[str] = None):
        self.dangerous_calls = import_json._load_json("risky_calls.json").get('dangerous_calls', {})

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
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

        return {"api_analysis": {"total_calls": len(scored), "scored_calls": scored}}