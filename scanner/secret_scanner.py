import re
import math
from typing import Dict, List, Any, Optional
from scanner.io import import_json


class SecretScanner:
    def __init__(self):
        """Initialize with secret patterns JSON."""
        self.entropy_config = {
            "secret_charset": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-",
            "entropy_threshold": 4.5,
            "min_secret_length": 20
        }
        self.patterns = import_json._load_json("secret_pattern.json").get('secret_patterns', {})
        self.compiled = self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns and store all metadata."""
        compiled = []
        for p in self.patterns:
            try:
                compiled.append({
                    'name': p.get('name', ''),
                    'pattern': re.compile(p.get('pattern', '')),
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

    """Truncate string for display."""
    def _truncate(self, value: str, max_len: int = 50) -> str:
        return value if len(value) <= max_len else value[:max_len] + "..."

    """Calculate Shannon entropy."""
    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = [s.count(ch) for ch in set(s)]
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in freq)

    def _is_mostly_secret_chars(self, s: str) -> bool:
        """Check if >80% characters are secret-like."""
        charset = set(self.entropy_config.get('secret_charset', ''))
        if not s or not charset:
            return False
        secret_count = sum(1 for ch in s if ch in charset)
        return (secret_count / len(s)) >= 0.80

    """Check if value suggests sensitive data."""
    def _is_sensitive(self, value: str) -> bool:
        keywords = ['key', 'secret', 'password', 'token', 'api', 'auth', 'jwt', 'credential']
        return any(kw in value.lower() for kw in keywords)

    def _get_match(self, value: str) -> Optional[Dict[str, Any]]:
        """Get full pattern info if value matches any pattern."""
        if not isinstance(value, str) or not value:
            return None

        for p in self.compiled:
            if p['pattern'].search(value):
                return p

        min_len = self.entropy_config.get('min_secret_length', 20)
        if len(value) >= min_len:
            entropy = self._shannon_entropy(value)
            threshold = self.entropy_config.get('entropy_threshold', 4.5)
            if entropy >= threshold and self._is_mostly_secret_chars(value):
                return {
                    'name': 'High-entropy string',
                    'severity': 45,
                    'reason': f"High entropy ({entropy:.2f} bits/char) - likely encoded secret",
                    'category': 'Obfuscation',
                    'cwe': 'CWE-20',
                    'false_positive_risk': 'MEDIUM',
                    'context': 'May be legitimate encoding'
                }

        if self._is_sensitive(value):
            return {
                'name': 'Sensitive keyword',
                'severity': 40,
                'reason': 'Contains sensitive keyword',
                'category': 'Sensitive Data',
                'cwe': 'CWE-200',
                'false_positive_risk': 'HIGH',
                'context': 'May be legitimate variable name'
            }

        return None

    def _add_finding(self, details: Dict, source: str, data: Dict):
        match = self._get_pattern_match(data.get('value', ''))
        if not match:
            return

        line = data.get('line', 0)
        value = str(data.get('value', ''))[:20]
        key = f"{source}_{line}_{value}"

        finding = {
            'source': source,
            'name': match.get('name', ''),
            'severity': match.get('severity', 0),
            'category': match.get('category', ''),
            'reason': match.get('reason', ''),
            'cwe': match.get('cwe', ''),
            'false_positive_risk': match.get('false_positive_risk', ''),
            'context': match.get('context', ''),
            'value': self._truncate(value),
            'line': line,
            'identifier': data.get('identifier', '')  # Uniform field for variable/decorator/etc.
        }
        details[key] = finding

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

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
        #print(f"PARSED RESULT {parser_result}")
        details = {}
        details.update(self._collect(parser_result.get('strings', []), 'strings'))
        details.update(self._collect(parser_result.get('assignments', []), 'assignments'))
        details.update(self._collect(parser_result.get('comments', []), 'comments'))
        details.update(self._collect(parser_result.get('constants', []), 'constants'))
        details.update(self._collect(parser_result.get('decorators', []), 'decorators'))
        details.update(self._collect(parser_result.get('docstrings', []), 'docstrings'))

        variables = parser_result.get('variables', [])
        if variables and isinstance(variables[0], dict):
            details.update(self._collect(variables, 'variables', 'value'))

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
            'line': d['line']
        } for d in details.values()]

        scored.sort(key=lambda x: x['severity'], reverse=True)

        return {"secret_analysis": {"total_findings": len(scored), "scored_findings": scored}}

