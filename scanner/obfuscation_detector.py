import re
import math
from typing import Dict, List, Any, Optional
from scanner.io import import_json

class ObfuscationDetector:
    def __init__(self):
        data = import_json._load_json("obfuscation_patterns.json")
        self.entropy_config = data.get('entropy_config', {})
        self.patterns = data.get('obfuscation_patterns', [])
        self.compiled = self._compile_patterns()

    def _compile_patterns(self):
        compiled = []
        for p in self.patterns:
            try:
                pattern = p.get('pattern', '')
                if isinstance(pattern, str):
                    compiled_pattern = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                else:
                    compiled_pattern = pattern  # Already compiled
                compiled.append({
                    'name': p.get('name', ''),
                    'pattern': compiled_pattern,
                    'severity': p.get('severity', 0),
                    'reason': p.get('reason', ''),
                    'category': p.get('category', ''),
                    'cwe': p.get('cwe', ''),
                    'false_positive_risk': p.get('false_positive_risk', ''),
                    'context': p.get('context', '')
                })
            except re.error:
                continue
        return compiled

    def _truncate(self, value: str, max_len: int = 50) -> str:
        """Truncate string for display."""
        return value if len(value) <= max_len else value[:max_len] + "..."

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy."""
        if not s:
            return 0.0
        freq = [s.count(ch) for ch in set(s)]
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in freq)

    def _get_match(self, value: str) -> Optional[Dict[str, Any]]:
        if not isinstance(value, str) or not value:
            return None

        for p in self.compiled:
            if p['pattern'].search(value):
                return p

        min_len = self.entropy_config.get('min_entropy_length', 80)
        if len(value) >= min_len:
            entropy = self._shannon_entropy(value)
            threshold = self.entropy_config.get('entropy_threshold', 5.0)
            if entropy >= threshold and self._is_mostly_secret_chars(value):
                return {
                    'name': 'High-entropy string',
                    'severity': 50,
                    'reason': f"High entropy ({entropy:.2f} bits/char) in string – likely encoded payload",
                    'category': 'High-Entropy Embedded String',
                    'cwe': 'CWE-20',
                    'false_positive_risk': 'MEDIUM',
                    'context': 'May be legitimate encoding'
                }

        return None

    def _collect(self, items: List[Dict], source: str, value_key: str = 'value', line_key: str = 'line') -> Dict:
        details = {}
        for item in items:
            value = item.get(value_key, '')
            if not value:
                continue

            match = self._get_match(value)
            if match:
                line = item.get(line_key, 0)
                key = f"{source}_{line}_{value[:20]}"
                details[key] = {
                    'source': source,
                    'value': self._truncate(value),
                    'line': line,
                    **match
                }
        return details

    def _collect_from_calls(self, calls_detailed: List[Dict]) -> Dict:
        details = {}
        for call in calls_detailed:
            line = call.get('line', 0)

            name = call.get('name', '')
            if name:
                match = self._get_match(name)
                if match:
                    key = f"calls_{line}_{name[:20]}"
                    details[key] = {
                        'source': 'calls',
                        'value': self._truncate(name),
                        'line': line,
                        'snippet': self._truncate(name, 80),
                        **match
                    }

            for idx, arg in enumerate(call.get('args', [])):
                if isinstance(arg, str):
                    match = self._get_match(arg)
                    if match:
                        key = f"calls_args_{line}_{arg[:20]}_{idx}"
                        details[key] = {
                            'source': 'calls_args',
                            'value': self._truncate(arg),
                            'line': line,
                            'snippet': self._truncate(arg, 80),
                            **match
                        }
        return details

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
        details = {}
        details.update(self._collect(parser_result.get('strings', []), 'strings', 'value', 'line'))
        details.update(self._collect(parser_result.get('assignments', []), 'assignments', 'value', 'line'))
        details.update(self._collect(parser_result.get('comments', []), 'comments', 'value', 'line'))
        details.update(self._collect(parser_result.get('constants', []), 'constants', 'value', 'line'))
        details.update(self._collect(parser_result.get('decorators', []), 'decorators', 'value', 'line'))
        details.update(self._collect(parser_result.get('docstrings', []), 'docstrings', 'value', 'line'))

        details.update(self._collect(parser_result.get('imports_detailed', []), 'imports', 'module', 'line'))

        details.update(self._collect_from_calls(parser_result.get('calls_detailed', [])))

        variables = parser_result.get('variables', [])
        if variables:
            if isinstance(variables[0], dict):
                details.update(self._collect(variables, 'variables', 'value'))
            else:
                details.update(self._collect([{'value': v} for v in variables], 'variables'))

        scored = [{
            'source': d['source'],
            'name': d['name'],
            'severity': d['severity'],
            'category': d['category'],
            'reason': d['reason'],
            'cwe': d['cwe'],
            'false_positive_risk': d['false_positive_risk'],
            'context': d['context'],
            'value': d['value'],
            'line': d['line'],
            'snippet': d.get('snippet', '')
        } for d in details.values()]

        scored.sort(key=lambda x: x['severity'], reverse=True)

        return {
            "obfuscation_analysis": {
                "total_findings": len(scored),
                "scored_findings": scored
            }
        }