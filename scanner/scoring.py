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

from typing import Dict, List, Any


# ---------------------------------------------------------------------------
# Per-indicator base weights
# ---------------------------------------------------------------------------

# Dangerous API weights — by category
CATEGORY_WEIGHTS = {
    "Code Execution":       25,
    "Network":              20,
    "Obfuscation":          15,
    "Unsafe Deserial.":     20,
    "Credential Theft":     20,
    "Persistence":          20,
    "Reconnaissance":        5,
    "File Access":          10,
    "System Access":         5,
    "Crypto":                5,
    "Execution":             5,
    "Destructive":          15,
}

# Severity multipliers on top of category base
SEVERITY_MULTIPLIER = {
    "HIGH":   1.0,
    "MEDIUM": 0.6,
    "LOW":    0.3,
}

# Per-finding-type weights
SECRET_WEIGHT = 15          # each hardcoded secret
VULNERABLE_DEP_WEIGHT = 15  # each risky dependency
KNOWN_MALICIOUS_DEP = 30    # known malicious package overrides the above
VULNERABILITY_WEIGHTS = {
    "SQL Injection":            25,
    "Command Injection":        25,
    "Weak Cryptography":        10,
    "Insecure Deserialization": 20,
    "Path Traversal":           15,
    "Insecure Configuration":   10,
    "Anti-Forensics":           20,
    "Persistence":              20,
    "Cryptomining":             25,
    "Code Execution":           25,
}
BACKDOOR_WEIGHT = 30        # each backdoor finding (always HIGH)
OBFUSCATION_WEIGHTS = {
    "HIGH":   20,
    "MEDIUM": 10,
    "LOW":     5,
}

# ---------------------------------------------------------------------------
# Correlation bonuses — awarded when multiple indicators chain together
# ---------------------------------------------------------------------------

def _correlation_bonuses(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Check for known attack chains and award bonus points.
    Returns a list of {name, points, reason} dicts.
    """
    bonuses = []

    api_categories = {f["category"] for f in result.get("dangerous_apis", [])}
    api_names      = {f["name"]     for f in result.get("dangerous_apis", [])}
    vuln_cats      = {f["category"] for f in result.get("vulnerabilities", [])}
    obf_findings   = result.get("obfuscation", [])
    backdoors      = result.get("backdoors", [])
    secrets        = result.get("secrets", [])

    has_file_access  = "File Access"  in api_categories
    has_network      = "Network"      in api_categories
    has_obfuscation  = len(obf_findings) > 0
    has_persistence  = "Persistence"  in api_categories or "Persistence" in vuln_cats
    has_exec         = "Code Execution" in api_categories or "Code Execution" in vuln_cats
    has_secrets      = len(secrets) > 0
    has_backdoor     = len(backdoors) > 0
    has_recon        = "Reconnaissance" in api_categories

    # Data exfiltration chain: file read + encode + network
    if has_file_access and has_network and has_obfuscation:
        bonuses.append({
            "name": "Data Exfiltration Chain",
            "points": 40,
            "reason": "File access + obfuscation/encoding + network transmission — classic exfiltration pattern.",
        })

    # Credential harvesting: secret/credential access + network
    if has_secrets and has_network:
        bonuses.append({
            "name": "Credential Exfiltration",
            "points": 35,
            "reason": "Hardcoded credentials present + network activity — credentials may be transmitted to attacker.",
        })

    # Backdoor + remote execution
    if has_backdoor and has_exec:
        bonuses.append({
            "name": "Remote Code Execution Backdoor",
            "points": 40,
            "reason": "Backdoor pattern + code execution capability — attacker can run arbitrary commands.",
        })

    # Persistence + network (C2 callback)
    if has_persistence and has_network:
        bonuses.append({
            "name": "Persistent C2 Callback",
            "points": 35,
            "reason": "Persistence mechanism + network access — likely a persistent C2 (command and control) implant.",
        })

    # Reconnaissance + network (data exfil of system info)
    if has_recon and has_network:
        bonuses.append({
            "name": "System Fingerprinting + Exfiltration",
            "points": 20,
            "reason": "System reconnaissance + network access — system info likely being reported to attacker.",
        })

    # Anti-forensics: destructive API + persistence
    if "Destructive" in api_categories and has_persistence:
        bonuses.append({
            "name": "Persistent + Self-Destructing",
            "points": 30,
            "reason": "Destructive file operations + persistence — payload executes then removes evidence.",
        })

    # Full kill-chain: recon + exec + persist + network
    if has_recon and has_exec and has_persistence and has_network:
        bonuses.append({
            "name": "Full Attack Kill-Chain Detected",
            "points": 50,
            "reason": "Reconnaissance + code execution + persistence + network — all major attack stages present.",
        })

    return bonuses


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------

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
    api_score = 0
    seen_categories = set()
    for f in result.get("dangerous_apis", []):
        cat = f["category"]
        base = CATEGORY_WEIGHTS.get(cat, 5)
        mult = SEVERITY_MULTIPLIER.get(f["severity"], 0.3)
        contrib = base * mult
        # Apply diminishing returns for the same category flagged many times
        if cat in seen_categories:
            contrib *= 0.3
        seen_categories.add(cat)
        api_score += contrib
    api_score = round(min(api_score, 40))   # cap API contribution at 40
    breakdown["Dangerous APIs"] = api_score
    total += api_score

    # ── Secret contributions ─────────────────────────────────────────────────
    secret_score = 0
    for f in result.get("secrets", []):
        sev = f.get("severity", "MEDIUM")
        secret_score += SECRET_WEIGHT * SEVERITY_MULTIPLIER.get(sev, 0.6)
    secret_score = round(min(secret_score, 25))
    breakdown["Secrets / Credentials"] = secret_score
    total += secret_score

    # ── Vulnerability contributions ──────────────────────────────────────────
    vuln_score = 0
    seen_vuln_cats = set()
    for f in result.get("vulnerabilities", []):
        cat = f["category"]
        base = VULNERABILITY_WEIGHTS.get(cat, 10)
        mult = SEVERITY_MULTIPLIER.get(f.get("severity", "MEDIUM"), 0.6)
        contrib = base * mult
        if cat in seen_vuln_cats:
            contrib *= 0.3
        seen_vuln_cats.add(cat)
        vuln_score += contrib
    vuln_score = round(min(vuln_score, 35))
    breakdown["Vulnerabilities"] = vuln_score
    total += vuln_score

    # ── Backdoor contributions ───────────────────────────────────────────────
    backdoor_score = 0
    for f in result.get("backdoors", []):
        backdoor_score += BACKDOOR_WEIGHT
    backdoor_score = round(min(backdoor_score, 40))
    breakdown["Backdoors"] = backdoor_score
    total += backdoor_score

    # ── Obfuscation contributions ────────────────────────────────────────────
    obf_score = 0
    for f in result.get("obfuscation", []):
        obf_score += OBFUSCATION_WEIGHTS.get(f.get("severity", "MEDIUM"), 10)
    obf_score = round(min(obf_score, 25))
    breakdown["Obfuscation"] = obf_score
    total += obf_score

    # ── Dependency contributions ─────────────────────────────────────────────
    dep_score = 0
    for f in result.get("vulnerable_dependencies", []):
        if f.get("flag_type") == "known_malicious":
            dep_score += KNOWN_MALICIOUS_DEP
        else:
            dep_score += VULNERABLE_DEP_WEIGHT * SEVERITY_MULTIPLIER.get(f.get("severity", "MEDIUM"), 0.6)
    dep_score = round(min(dep_score, 30))
    breakdown["Risky Dependencies"] = dep_score
    total += dep_score

    # ── Behavioral chains (Phase 2) ─────────────────────────────────────────
    chain_score = 0
    chain_weights = {"CRITICAL": 50, "HIGH": 40, "MEDIUM": 25, "LOW": 10}
    seen_chains = set()
    for c in result.get("chains", []):
        ct = c["chain_type"]
        if ct not in seen_chains:
            chain_score += chain_weights.get(c["confidence"], 25)
            seen_chains.add(ct)
    chain_score = round(min(chain_score, 60))
    breakdown["Behavioral Chains"] = chain_score
    total += chain_score

    # ── Logic bombs (Phase 2) ────────────────────────────────────────────────
    lb_score = 0
    for f in result.get("logic_bombs", []):
        lb_score += 35 * SEVERITY_MULTIPLIER.get(f.get("severity", "HIGH"), 1.0)
    lb_score = round(min(lb_score, 40))
    breakdown["Logic Bombs"] = lb_score
    total += lb_score

    # ── Correlation bonuses ──────────────────────────────────────────────────
    bonuses = _correlation_bonuses(result)
    bonus_total = sum(b["points"] for b in bonuses)
    bonus_total = round(min(bonus_total, 60))   # cap bonus at 60
    breakdown["Correlation Bonuses"] = bonus_total
    total += bonus_total

    # ── Final score and risk band ────────────────────────────────────────────
    total_raw   = total
    threat_score = min(total, 100)

    if threat_score <= 20:
        risk_level = "Safe"
    elif threat_score <= 45:
        risk_level = "Low Risk"
    elif threat_score <= 70:
        risk_level = "Suspicious"
    elif threat_score <= 89:
        risk_level = "High Risk"
    else:
        risk_level = "Critical"

    return {
        "threat_score": threat_score,
        "risk_level":   risk_level,
        "breakdown":    breakdown,
        "bonuses":      bonuses,
        "total_raw":    total_raw,
    }
