import re
import math
from typing import Dict, List, Any, Optional
from scanner.io import import_json


class SecretScanner:
    def __init__(self, json_path: Optional[str] = None):
        """Initialize with secret patterns JSON."""
        self.secret_patterns = import_json._load_json("secret_patterns.json").get('secret_patterns', {})

    def analyze_parser_result(self, parser_result: Dict[str, Any]) -> Dict[str, Any]:
