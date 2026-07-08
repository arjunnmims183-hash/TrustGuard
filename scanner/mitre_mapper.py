"""
mitre_mapper.py
---------------
Maps attack findings to MITRE ATT&CK techniques.
Loads mapping from mitre_attack_map.json with fallbacks.

The MITRE ATT&CK framework provides a comprehensive knowledge base
of adversary tactics and techniques.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Set

# ==========================================
# CONSTANTS
# ==========================================

BASE_DIR = Path(__file__).parent
MITRE_FILE = BASE_DIR / "data" / "mitre_attack_map.json"

# ==========================================
# DEFAULT MITRE MAPPINGS
# ==========================================

DEFAULT_MITRE_MAP: Dict[str, List[Dict[str, Any]]] = {
    # =====================================
    # Credential Access
    # =====================================
    "CREDENTIAL_THEFT": [
        {
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1552/",
            "description": "Credentials are accessed and exfiltrated"
        }
    ],
    "ADVANCED_CREDENTIAL_THEFT": [
        {
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1552/",
            "description": "Credentials are accessed and exfiltrated"
        },
        {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1027/",
            "description": "Data is obfuscated before exfiltration"
        }
    ],
    "OBFUSCATED_CREDENTIAL_EXFILTRATION": [
        {
            "technique_id": "T1552",
            "technique_name": "Unsecured Credentials",
            "tactic": "Credential Access",
            "url": "https://attack.mitre.org/techniques/T1552/",
            "description": "Credentials are accessed and exfiltrated"
        },
        {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1027/",
            "description": "Data is obfuscated before exfiltration"
        },
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1041/",
            "description": "Data is exfiltrated over C2 channel"
        }
    ],
    
    # =====================================
    # Exfiltration
    # =====================================
    "DATA_EXFILTRATION": [
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1041/",
            "description": "Data is exfiltrated over network"
        }
    ],
    "OBFUSCATED_DATA_EXFILTRATION": [
        {
            "technique_id": "T1027",
            "technique_name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1027/",
            "description": "Data is obfuscated before exfiltration"
        },
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1041/",
            "description": "Data is exfiltrated over network"
        }
    ],
    "STEALTHY_DATA_EXFILTRATION": [
        {
            "technique_id": "T1070",
            "technique_name": "Indicator Removal on Host",
            "tactic": "Defense Evasion",
            "url": "https://attack.mitre.org/techniques/T1070/",
            "description": "Anti-forensic techniques used to hide tracks"
        },
        {
            "technique_id": "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "url": "https://attack.mitre.org/techniques/T1041/",
            "description": "Data is exfiltrated over network"
        }
    ],
    
    # =====================================
    # Persistence
    # =====================================
    "BACKDOOR": [
        {
            "technique_id": "T1505",
            "technique_name": "Server Software Component",
            "tactic": "Persistence",
            "url": "https://attack.mitre.org/techniques/T1505/",
            "description": "Backdoor established for persistent access"
        }
    ],
    
    # =====================================
    # Impact
    # =====================================
    "RANSOMWARE": [
        {
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "tactic": "Impact",
            "url": "https://attack.mitre.org/techniques/T1486/",
            "description": "Files are encrypted for ransom"
        },
        {
            "technique_id": "T1490",
            "technique_name": "Inhibit System Recovery",
            "tactic": "Impact",
            "url": "https://attack.mitre.org/techniques/T1490/",
            "description": "System recovery mechanisms are disabled"
        }
    ],
    "LOGIC_BOMB": [
        {
            "technique_id": "T1490",
            "technique_name": "Inhibit System Recovery",
            "tactic": "Impact",
            "url": "https://attack.mitre.org/techniques/T1490/",
            "description": "Conditional malicious behavior detected"
        }
    ],
    
    # =====================================
    # Collection
    # =====================================
    "INPUT_COLLECTION": [
        {
            "technique_id": "T1056",
            "technique_name": "Input Capture",
            "tactic": "Collection",
            "url": "https://attack.mitre.org/techniques/T1056/",
            "description": "User input is captured and transmitted"
        }
    ],
}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def _load_mitre_map() -> Dict[str, Any]:
    """
    Load MITRE mapping from JSON file with fallback to defaults.
    
    Returns:
        MITRE attack mapping dictionary
    """
    try:
        if MITRE_FILE.exists():
            with open(MITRE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            print(f"[!] MITRE map file not found: {MITRE_FILE}")
            print("[*] Using default MITRE mappings")
            return DEFAULT_MITRE_MAP
    except (json.JSONDecodeError, IOError) as e:
        print(f"[!] Error loading MITRE map: {e}")
        print("[*] Using default MITRE mappings")
        return DEFAULT_MITRE_MAP


def _find_matching_techniques(attack_type: str, mitre_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Find MITRE techniques for an attack type with fallback matching.
    
    Args:
        attack_type: Type of attack
        mitre_map: MITRE mapping dictionary
        
    Returns:
        List of MITRE technique dictionaries
    """
    if attack_type in mitre_map:
        return mitre_map[attack_type]
    
    # Try to find matching pattern (partial match)
    for key, value in mitre_map.items():
        if attack_type.startswith(key) or key.startswith(attack_type):
            return value
    
    return []


def _is_finding_dict(item: Any) -> bool:
    """Check if item is a finding dictionary."""
    return isinstance(item, dict) and "attack_type" in item


# ==========================================
# LOAD MITRE MAP
# ==========================================

MITRE_ATTACK_MAP: Dict[str, Any] = _load_mitre_map()


# ==========================================
# MAIN MAPPING FUNCTIONS
# ==========================================

def map_to_mitre(
    finding: Union[Dict[str, Any], List[Dict[str, Any]]]
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Map an attack finding (or list of findings) to MITRE techniques.
    
    Args:
        finding: Attack finding dictionary OR list of findings
        
    Returns:
        Finding with MITRE techniques added, or list of mapped findings
    """
    # If it's a list, map each item
    if isinstance(finding, list):
        return [map_to_mitre(item) for item in finding]
    
    # If it's a dict with attack_type, map it
    if _is_finding_dict(finding):
        attack_type = finding.get("attack_type", "")
        techniques = _find_matching_techniques(attack_type, MITRE_ATTACK_MAP)
        
        finding_copy = finding.copy()
        finding_copy["mitre_techniques"] = techniques
        finding_copy["mitre"] = techniques  # Backward compatibility
        
        return finding_copy
    
    # If it's something else, return as-is
    return finding


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich attack findings with MITRE techniques.
    
    Args:
        findings: List of attack findings
        
    Returns:
        List of findings with MITRE techniques added
    """
    return map_to_mitre(findings) if isinstance(findings, list) else []


# ==========================================
# QUERY FUNCTIONS
# ==========================================

def get_mitre_techniques(attack_type: str) -> List[Dict[str, Any]]:
    """
    Get MITRE techniques for a specific attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        List of MITRE technique dictionaries
    """
    return MITRE_ATTACK_MAP.get(attack_type, [])


def get_mitre_ids(attack_type: str) -> List[str]:
    """
    Get MITRE technique IDs for a specific attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        List of MITRE technique IDs
    """
    techniques = get_mitre_techniques(attack_type)
    return [t.get("technique_id", "") for t in techniques if t.get("technique_id")]


def get_mitre_tactics(attack_type: str) -> Set[str]:
    """
    Get unique MITRE tactics for a specific attack type.
    
    Args:
        attack_type: Type of attack
        
    Returns:
        Set of tactic names
    """
    techniques = get_mitre_techniques(attack_type)
    return {t.get("tactic", "") for t in techniques if t.get("tactic")}


def get_all_attack_types() -> List[str]:
    """
    Get all attack types that have MITRE mappings.
    
    Returns:
        List of attack type names
    """
    return list(MITRE_ATTACK_MAP.keys())


def get_all_techniques() -> List[Dict[str, Any]]:
    """
    Get all unique MITRE techniques across all attack types.
    
    Returns:
        List of unique technique dictionaries
    """
    seen = set()
    techniques = []
    
    for tech_list in MITRE_ATTACK_MAP.values():
        for tech in tech_list:
            tech_id = tech.get("technique_id", "")
            if tech_id and tech_id not in seen:
                seen.add(tech_id)
                techniques.append(tech)
    
    return techniques


# ==========================================
# FORMATTING FUNCTIONS
# ==========================================

def format_mitre_techniques(techniques: List[Dict[str, Any]]) -> str:
    """
    Format MITRE techniques as a readable string.
    
    Args:
        techniques: List of MITRE technique dictionaries
        
    Returns:
        Formatted string
    """
    if not techniques:
        return "No MITRE techniques mapped"
    
    lines = []
    for t in techniques:
        tech_id = t.get("technique_id", "Unknown")
        name = t.get("technique_name", "Unknown Technique")
        tactic = t.get("tactic", "")
        
        line = f"{tech_id} - {name}"
        if tactic:
            line += f" ({tactic})"
        lines.append(line)
    
    return "\n".join(lines)


def format_mitre_summary(mappings: List[Dict[str, Any]]) -> str:
    """
    Format a summary of MITRE mappings for all findings.
    
    Args:
        mappings: List of mapped findings
        
    Returns:
        Formatted summary string
    """
    if not mappings:
        return "No MITRE mappings found"
    
    lines = []
    for finding in mappings:
        attack_type = finding.get("attack_type", "Unknown")
        techniques = finding.get("mitre_techniques", [])
        
        if techniques:
            tech_ids = [t.get("technique_id", "?") for t in techniques]
            lines.append(f"{attack_type}: {', '.join(tech_ids)}")
        else:
            lines.append(f"{attack_type}: No techniques mapped")
    
    return "\n".join(lines)


def get_mitre_statistics() -> Dict[str, Any]:
    """
    Get statistics about the MITRE mapping.
    
    Returns:
        Statistics dictionary
    """
    all_techs = get_all_techniques()
    
    return {
        "total_attack_types": len(MITRE_ATTACK_MAP),
        "total_unique_techniques": len(all_techs),
        "attack_types": list(MITRE_ATTACK_MAP.keys()),
        "technique_ids": [t.get("technique_id", "") for t in all_techs],
    }


# ==========================================
# BACKWARD COMPATIBILITY
# ==========================================

def map_to_mitre_legacy(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Legacy wrapper for backward compatibility."""
    return map_to_mitre(finding)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "map_to_mitre",
    "map_to_mitre_legacy",
    "enrich_findings",
    "get_mitre_techniques",
    "get_mitre_ids",
    "get_mitre_tactics",
    "get_all_attack_types",
    "get_all_techniques",
    "format_mitre_techniques",
    "format_mitre_summary",
    "get_mitre_statistics",
    "MITRE_ATTACK_MAP",
    "DEFAULT_MITRE_MAP",
]