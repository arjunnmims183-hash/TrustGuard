from typing import Dict, List, Any, Optional
import os
import json

def _load_json(json_file: Optional[str] = None) -> Dict[str, Any]:
    scanner_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print(f"📁 Scanner directory: {scanner_dir}")

    # Build paths relative to scanner directory
    possible_paths = [
        json_file,  # Original path
        os.path.abspath(json_file),  # Absolute from current dir
        os.path.join(scanner_dir, "data", json_file),  # scanner/data/risky_imports.json
        os.path.join(scanner_dir, json_file),  # scanner + relative path
    ]

    for path in possible_paths:
        if path and os.path.exists(path):
            print(f"✅ Found file: {path}")
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    print(f"✅ Loaded {len(data)} items")
                    return data
            except Exception as e:
                print(f"❌ Error: {e}")
                continue

    print(f"❌ Could not find JSON file")
    return {}