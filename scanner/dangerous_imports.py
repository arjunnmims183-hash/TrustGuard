"""
dangerous_imports.py - Risky import analyzer.
"""

from scanner.io import import_json
from typing import Dict, List, Any, Optional

class DangerousImports:
    """Analyze risky imports from parser results."""

    def __init__(self, json_path: Optional[str] = None):
        """Initialize with risky imports JSON."""
        self.risky_imports = import_json._load_json("risky_imports.json").get('risky_imports', {})

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze parser result and score risky imports."""
        imports = parser_result.get('imports', [])
        imports_detailed = parser_result.get('imports_detailed', [])

        # Build details mapping
        details = {}
        for imp in imports_detailed:
            name = imp.get('module', '').split('.')[0]
            if name:
                if name not in details:
                    details[name] = {'lines': [], 'full_module': imp.get('module', ''), 'alias': imp.get('alias', '')}
                details[name]['lines'].append(imp.get('line', 0))

        scored = []
        for name in set(imports):
            info = self.risky_imports.get(name, {})
            d = details.get(name, {})

            scored.append({
                "name": name,
                "severity": info.get('severity', 0),
                "category": info.get('category', ''),
                "reason": info.get('reason', ''),
                "cwe": info.get('cwe', ''),
                "is_always_malicious": info.get('is_always_malicious', False),
                "context": info.get('context', ''),
                "lines": d.get('lines', []),
                "full_module": d.get('full_module', ''),
                "alias": d.get('alias', '')
            })

        scored.sort(key=lambda x: x['severity'], reverse=True)

        return {"import_analysis": {"total_imports": len(scored), "scored_imports": scored}}
