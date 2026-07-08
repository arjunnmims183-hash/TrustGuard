"""
scoring.py
----------
Deterministic threat scoring engine — Section 13 of the TrustGuard proposal.

Each indicator from the scanner modules contributes a fixed number of points.
Correlation bonuses are applied when multiple indicators form a known attack chain.
The score is capped at 100 and mapped to a risk band.

This scoring is intentionally SEPARATE from the LLM explanation layer (Phase 4).
The score never changes based on LLM output — it is always rule-derived and
reproducible from the same feature set.

Risk bands (from proposal Section 13):
    0–20    Safe
    21–45   Low Risk
    46–70   Suspicious / Medium Risk
    71–100  High Risk / Critical
"""

from typing import Dict, List, Any, Set, Optional, Union

# ==========================================
# DATA IMPORTS
# ==========================================

from scanner.data.scoring_weights import (
    CATEGORY_WEIGHTS,
    SEVERITY_MULTIPLIER,
    SECRET_WEIGHT,
    VULNERABLE_DEP_WEIGHT,
    KNOWN_MALICIOUS_DEP,
    BACKDOOR_WEIGHT,
    VULNERABILITY_WEIGHTS,
    OBFUSCATION_WEIGHTS,
    CHAIN_WEIGHTS,
    LOGIC_BOMB_WEIGHT,
    CORRELATION_BONUSES,
    CAPS,
    RISK_THRESHOLDS,
    DIMINISHING_FACTOR,
)


# ==========================================
# DATA EXTRACTION HELPERS
# ==========================================

def _get_data(result: Dict, phase: str, key: str, default=None) -> Any:
    """Get data from result (supports both structured and flat formats)."""
    if phase in result and key in result[phase]:
        return result[phase][key]
    return result.get(key, default)


def _get_phase1_data(result: Dict, key: str, default=None) -> Any:
    """Get Phase 1 data."""
    return _get_data(result, "phase1", key, default)


def _get_phase2_data(result: Dict, key: str, default=None) -> Any:
    """Get Phase 2 data."""
    return _get_data(result, "phase2", key, default)


def _extract_severity(item: Dict) -> str:
    """Extract severity from an item, handling different field names."""
    sev = item.get("severity", item.get("risk", "MEDIUM"))
    return sev.upper() if isinstance(sev, str) else "MEDIUM"


def _extract_category(item: Dict) -> str:
    """Extract category from an item, handling different field names."""
    return item.get("category", item.get("type", "Unknown"))


def _get_severity_multiplier(severity: str) -> float:
    """Get multiplier for a severity level."""
    return SEVERITY_MULTIPLIER.get(severity, 0.6)


# ==========================================
# SCORING HELPERS
# ==========================================

def _calculate_weighted_score(
    items: List[Dict],
    base_weight: int,
    max_score: int,
    category_key: Optional[str] = None,
    diminishing: bool = True
) -> int:
    """
    Calculate weighted score for a list of findings.
    
    Args:
        items: List of finding dictionaries
        base_weight: Base weight per finding
        max_score: Maximum score for this category
        category_key: Key for category field (for diminishing returns)
        diminishing: Whether to apply diminishing returns
        
    Returns:
        Calculated score (capped at max_score)
    """
    if not items:
        return 0
    
    score = 0
    seen_categories = set()
    
    for item in items:
        if not isinstance(item, dict):
            score += base_weight * 0.3
            continue
        
        severity = _extract_severity(item)
        multiplier = _get_severity_multiplier(severity)
        contrib = base_weight * multiplier
        
        # Apply diminishing returns for repeated categories
        if diminishing and category_key:
            category = _extract_category(item)
            if category in seen_categories:
                contrib *= DIMINISHING_FACTOR
            seen_categories.add(category)
        
        score += contrib
    
    return round(min(score, max_score))


def _calculate_simple_score(
    items: List[Dict],
    weight: int,
    max_score: int
) -> int:
    """Calculate a simple score with weight per item."""
    if not items:
        return 0
    
    score = len(items) * weight
    return round(min(score, max_score))


def _get_risk_level(score: int) -> str:
    """Get risk level based on score."""
    if score <= RISK_THRESHOLDS["Safe"]:
        return "Safe"
    elif score <= RISK_THRESHOLDS["Low Risk"]:
        return "Low Risk"
    elif score <= RISK_THRESHOLDS["Suspicious"]:
        return "Suspicious"
    elif score <= RISK_THRESHOLDS["High Risk"]:
        return "High Risk"
    else:
        return "Critical"


# ==========================================
# CORRELATION BONUS DETECTION
# ==========================================

def _detect_correlation_bonuses(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check for known attack chains and award bonus points.
    Returns a list of {name, points, reason} dicts.
    """
    bonuses = []

    # Extract data from both structured and flat formats
    dangerous_apis = _get_phase1_data(result, "dangerous_apis", [])
    vulnerabilities = _get_phase1_data(result, "vulnerabilities", [])
    obfuscations = _get_phase1_data(result, "obfuscation", [])
    backdoors = _get_phase1_data(result, "backdoors", [])
    secrets = _get_phase1_data(result, "secrets", [])

    # Extract categories from items
    api_categories = set()
    for f in dangerous_apis:
        if isinstance(f, dict):
            api_categories.add(_extract_category(f))
    
    vuln_cats = set()
    for f in vulnerabilities:
        if isinstance(f, dict):
            vuln_cats.add(_extract_category(f))

    # Determine which flags are present
    has_file_access = "File Access" in api_categories
    has_network = "Network" in api_categories
    has_obfuscation = len(obfuscations) > 0
    has_persistence = "Persistence" in api_categories or "Persistence" in vuln_cats
    has_exec = "Code Execution" in api_categories or "Code Execution" in vuln_cats
    has_secrets = len(secrets) > 0
    has_backdoor = len(backdoors) > 0
    has_recon = "Reconnaissance" in api_categories
    has_destructive = "Destructive" in api_categories

    # Define bonus conditions
    bonus_conditions = [
        # Data exfiltration chain: file read + encode + network
        (has_file_access and has_network and has_obfuscation,
         "data_exfiltration_chain",
         "File access + obfuscation/encoding + network transmission — classic exfiltration pattern."),

        # Credential harvesting: secret/credential access + network
        (has_secrets and has_network,
         "credential_exfiltration",
         "Hardcoded credentials present + network activity — credentials may be transmitted to attacker."),

        # Backdoor + remote execution
        (has_backdoor and has_exec,
         "remote_code_execution_backdoor",
         "Backdoor pattern + code execution capability — attacker can run arbitrary commands."),

        # Persistence + network (C2 callback)
        (has_persistence and has_network,
         "persistent_c2_callback",
         "Persistence mechanism + network access — likely a persistent C2 implant."),

        # Reconnaissance + network (data exfil of system info)
        (has_recon and has_network,
         "system_fingerprinting",
         "System reconnaissance + network access — system info likely being reported to attacker."),

        # Anti-forensics: destructive API + persistence
        (has_destructive and has_persistence,
         "persistent_self_destructing",
         "Destructive file operations + persistence — payload executes then removes evidence."),

        # Full kill-chain: recon + exec + persist + network
        (has_recon and has_exec and has_persistence and has_network,
         "full_kill_chain",
         "Reconnaissance + code execution + persistence + network — all major attack stages present."),
    ]

    for condition, bonus_key, reason in bonus_conditions:
        if condition:
            bonus_info = CORRELATION_BONUSES.get(bonus_key, {})
            bonuses.append({
                "name": bonus_key.replace("_", " ").title(),
                "points": bonus_info.get("points", 20),
                "reason": reason,
            })

    return bonuses


# ==========================================
# MAIN SCORING FUNCTION
# ==========================================

def compute_score(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute the deterministic threat score from the combined scan result.

    Returns:
        threat_score    - integer 0–100
        risk_level      - "Safe" / "Low Risk" / "Suspicious" / "High Risk" / "Critical"
        breakdown       - per-category contribution dict
        bonuses         - list of correlation bonus dicts that fired
        total_raw       - uncapped score (for transparency)
    """
    breakdown = {}
    total = 0

    # ── Dangerous API contributions ──────────────────────────────────────────
    dangerous_apis = _get_phase1_data(result, "dangerous_apis", [])
    api_score = _calculate_weighted_score(
        dangerous_apis,
        base_weight=5,  # Default weight for APIs
        max_score=CAPS["dangerous_apis"],
        category_key="category",
        diminishing=True
    )
    breakdown["Dangerous APIs"] = api_score
    total += api_score

    # ── Secret contributions ─────────────────────────────────────────────────
    secrets = _get_phase1_data(result, "secrets", [])
    secret_score = _calculate_simple_score(secrets, SECRET_WEIGHT, CAPS["secrets"])
    breakdown["Secrets / Credentials"] = secret_score
    total += secret_score

    # ── Vulnerability contributions ──────────────────────────────────────────
    vulnerabilities = _get_phase1_data(result, "vulnerabilities", [])
    vuln_score = _calculate_weighted_score(
        vulnerabilities,
        base_weight=10,  # Default for vulnerabilities
        max_score=CAPS["vulnerabilities"],
        category_key="category",
        diminishing=True
    )
    breakdown["Vulnerabilities"] = vuln_score
    total += vuln_score

    # ── Backdoor contributions ───────────────────────────────────────────────
    backdoors = _get_phase1_data(result, "backdoors", [])
    backdoor_score = _calculate_simple_score(backdoors, BACKDOOR_WEIGHT, CAPS["backdoors"])
    breakdown["Backdoors"] = backdoor_score
    total += backdoor_score

    # ── Obfuscation contributions ────────────────────────────────────────────
    obfuscations = _get_phase1_data(result, "obfuscation", [])
    obf_score = _calculate_weighted_score(
        obfuscations,
        base_weight=10,  # Default for obfuscation
        max_score=CAPS["obfuscation"],
        diminishing=False
    )
    breakdown["Obfuscation"] = obf_score
    total += obf_score

    # ── Dependency contributions ─────────────────────────────────────────────
    dependencies = _get_phase1_data(result, "vulnerable_dependencies", [])
    dep_score = 0
    for f in dependencies:
        if isinstance(f, dict):
            if f.get("flag_type") == "known_malicious":
                dep_score += KNOWN_MALICIOUS_DEP
            else:
                severity = _extract_severity(f)
                multiplier = _get_severity_multiplier(severity)
                dep_score += VULNERABLE_DEP_WEIGHT * multiplier
        else:
            dep_score += VULNERABLE_DEP_WEIGHT * 0.6
    dep_score = round(min(dep_score, CAPS["dependencies"]))
    breakdown["Risky Dependencies"] = dep_score
    total += dep_score

    # ── Behavioral chains (Phase 2) ─────────────────────────────────────────
    chains = _get_phase2_data(result, "chains", [])
    chain_score = 0
    seen_chains = set()
    for c in chains:
        if isinstance(c, dict):
            ct = c.get("chain_type", c.get("type", "Unknown"))
            conf = c.get("confidence", c.get("severity", "MEDIUM"))
            conf_upper = conf.upper() if isinstance(conf, str) else "MEDIUM"
            if ct not in seen_chains:
                chain_score += CHAIN_WEIGHTS.get(conf_upper, 25)
                seen_chains.add(ct)
        else:
            chain_score += 25
    chain_score = round(min(chain_score, CAPS["behavioral_chains"]))
    breakdown["Behavioral Chains"] = chain_score
    total += chain_score

    # ── Logic bombs (Phase 2) ────────────────────────────────────────────────
    logic_bombs = _get_phase2_data(result, "logic_bombs", [])
    lb_score = _calculate_simple_score(logic_bombs, LOGIC_BOMB_WEIGHT, CAPS["logic_bombs"])
    breakdown["Logic Bombs"] = lb_score
    total += lb_score

    # ── Correlation bonuses ──────────────────────────────────────────────────
    bonuses = _detect_correlation_bonuses(result)
    bonus_total = sum(b["points"] for b in bonuses)
    bonus_total = round(min(bonus_total, CAPS["correlation_bonuses"]))
    breakdown["Correlation Bonuses"] = bonus_total
    total += bonus_total

    # ── Final score and risk band ────────────────────────────────────────────
    total_raw = total
    threat_score = min(total, 100)
    risk_level = _get_risk_level(threat_score)

    return {
        "threat_score": threat_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
        "bonuses": bonuses,
        "total_raw": total_raw,
    }


# ==========================================
# LEGACY SUPPORT
# ==========================================

def compute_score_legacy(result: Dict[str, Any]) -> Dict[str, Any]:
    """Legacy wrapper for backward compatibility."""
    return compute_score(result)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "compute_score",
    "compute_score_legacy",
]