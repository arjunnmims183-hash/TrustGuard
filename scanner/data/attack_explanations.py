"""
attack_explanations.py
----------------------
Human-readable explanations for attack types.
"""

from typing import Dict, Any

ATTACK_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "CREDENTIAL_THEFT": {
        "summary": "Credentials are being accessed and transmitted externally.",
        "details": "The code reads sensitive credentials from environment variables and sends them to an external endpoint.",
        "recommendation": "Review credential handling. Use secure secret management like AWS Secrets Manager.",
        "risk": "High - Credential exposure can lead to account compromise.",
    },
    "OBFUSCATED_CREDENTIAL_EXFILTRATION": {
        "summary": "Credentials are being obfuscated and exfiltrated.",
        "details": "The code reads credentials, applies obfuscation (encoding/compression), and transmits them externally.",
        "recommendation": "Immediate review required. This indicates sophisticated malicious intent.",
        "risk": "Critical - Credential theft with obfuscation is advanced malware behavior.",
    },
    "DATA_EXFILTRATION": {
        "summary": "Data is being read and transmitted externally.",
        "details": "The code reads local files and sends their contents to an external network destination.",
        "recommendation": "Review file access patterns. Ensure data only goes to authorized endpoints.",
        "risk": "Medium - Data exfiltration can lead to data breach.",
    },
    "OBFUSCATED_DATA_EXFILTRATION": {
        "summary": "Data is being obfuscated and exfiltrated.",
        "details": "The code reads files, applies obfuscation, and transmits them externally.",
        "recommendation": "Review all data transformation and transmission code.",
        "risk": "High - Obfuscated data exfiltration is a common malware technique.",
    },
    "STEALTHY_DATA_EXFILTRATION": {
        "summary": "Stealthy data exfiltration with anti-forensics detected.",
        "details": "The code reads files, applies obfuscation, and uses anti-forensic techniques to hide its tracks.",
        "recommendation": "Immediate investigation required. This is a sophisticated malicious pattern.",
        "risk": "Critical - Stealthy exfiltration with anti-forensics.",
    },
    "INPUT_COLLECTION": {
        "summary": "User input is being collected and transmitted.",
        "details": "The code collects user input and transmits it to an external endpoint.",
        "recommendation": "Review user input handling. Ensure data is only collected legitimately.",
        "risk": "Medium - Could be logging or credential harvesting.",
    },
    "BACKDOOR": {
        "summary": "Backdoor functionality detected.",
        "details": "The code creates network connections and executes subprocesses, potentially establishing a backdoor.",
        "recommendation": "Immediately review and remove any unauthorized remote access.",
        "risk": "Critical - Backdoors provide persistent unauthorized access.",
    },
    "RANSOMWARE": {
        "summary": "Ransomware-like behavior detected.",
        "details": "The code reads files, applies encryption/obfuscation, and writes modified files.",
        "recommendation": "Immediate isolation and investigation required.",
        "risk": "Critical - Ransomware can encrypt critical data.",
    },
    "LOGIC_BOMB": {
        "summary": "Logic bomb detected with conditional malicious code.",
        "details": "The code contains conditional logic that triggers malicious behavior based on specific conditions.",
        "recommendation": "Review all conditional code paths. Remove malicious triggers.",
        "risk": "Critical - Logic bombs can cause delayed damage.",
    },
    "ADVANCED_CREDENTIAL_THEFT": {
        "summary": "Advanced credential theft with multiple techniques.",
        "details": "The code combines credential access, obfuscation, and network exfiltration.",
        "recommendation": "Comprehensive review required. This is a sophisticated attempt.",
        "risk": "Critical - Advanced credential theft can bypass basic controls.",
    },
}

DEFAULT_EXPLANATION = {
    "summary": "Suspicious behavior detected.",
    "details": "The code exhibits patterns consistent with malicious or insecure behavior.",
    "recommendation": "Review the code manually and verify its intended functionality.",
    "risk": "Unknown - Further investigation required.",
}


def get_attack_explanation(attack_type: str) -> Dict[str, str]:
    """Get explanation for an attack type."""
    return ATTACK_EXPLANATIONS.get(attack_type, DEFAULT_EXPLANATION)


def get_all_attack_types() -> list:
    """Get all available attack types with explanations."""
    return list(ATTACK_EXPLANATIONS.keys())


def format_explanation(explanation: Dict[str, str]) -> str:
    """Format explanation as a readable string."""
    lines = []
    
    if explanation.get("summary"):
        lines.append(f"📋 {explanation['summary']}")
    
    if explanation.get("details"):
        lines.append(f"\n📝 {explanation['details']}")
    
    if explanation.get("recommendation"):
        lines.append(f"\n🔧 {explanation['recommendation']}")
    
    if explanation.get("risk"):
        lines.append(f"\n⚠️ {explanation['risk']}")
    
    return "\n".join(lines)


__all__ = [
    "ATTACK_EXPLANATIONS",
    "DEFAULT_EXPLANATION",
    "get_attack_explanation",
    "get_all_attack_types",
    "format_explanation",
]