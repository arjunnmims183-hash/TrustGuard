"""
report.py
---------
Formats and prints the complete scan result to the terminal,
and optionally saves it as JSON.
Supports both flat (legacy) and structured (Phase 3) result formats.
"""

import json
import re
import shutil
from typing import Dict, Any, List, Optional, Union
from datetime import datetime

# ==========================================
# ANSI COLOR CODES
# ==========================================

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BLUE = "\033[94m"
WHITE = "\033[97m"
DIM = "\033[2m"
MAGENTA = "\033[95m"

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


# ==========================================
# CONSTANTS
# ==========================================

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": GREEN,
    "UNKNOWN": WHITE,
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "UNKNOWN": "⚪",
}

SECTION_ICONS = {
    "imports": "📦",
    "dangerous_apis": "⚠️ ",
    "secrets": "🔑",
    "vulnerabilities": "🐛",
    "backdoors": "🚪",
    "obfuscation": "🌀",
    "logic_bombs": "💣",
    "dependencies": "📚",
    "vulnerable_dependencies": "📚",
    "chains": "🔗",
    "data_flows": "🌊",
    "feature_vector": "🧬",
    "phase3": "🎯",
    "llm": "🧠",
}

# Terminal width, clamped to a sane range so output stays readable
# whether run in a narrow CI log or a wide terminal.
_TERM_WIDTH = shutil.get_terminal_size(fallback=(80, 24)).columns
SECTION_WIDTH = max(60, min(_TERM_WIDTH, 96))


# ==========================================
# LOW-LEVEL TEXT HELPERS
# ==========================================

def _visible_len(text: str) -> int:
    """Length of a string as it will appear on screen (ANSI codes stripped)."""
    return len(_ANSI_RE.sub("", text))


def _pad_visible(text: str, width: int) -> str:
    """Right-pad text to `width` visible characters, ignoring ANSI codes."""
    return text + " " * max(0, width - _visible_len(text))


def _center_visible(text: str, width: int) -> str:
    pad = max(0, width - _visible_len(text))
    left = pad // 2
    right = pad - left
    return (" " * left) + text + (" " * right)


# ==========================================
# COLOR HELPERS
# ==========================================

def _sev_color(severity: str) -> str:
    """Get color for severity level."""
    return SEVERITY_COLORS.get(severity.upper(), WHITE)


def _sev_icon(severity: str) -> str:
    """Get icon for severity level."""
    return SEVERITY_ICONS.get(severity.upper(), "⚪")


def _get_score_color(score: int) -> str:
    """Get color based on score value."""
    if score >= 80:
        return RED
    elif score >= 50:
        return YELLOW
    return GREEN


def _risk_icon(score) -> str:
    """Get risk icon based on score value."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        return "🟩"
    
    if score >= 90:
        return "🟥"
    elif score >= 71:
        return "🟧"
    elif score >= 46:
        return "🟨"
    elif score >= 21:
        return "🟦"
    return "🟩"


# ==========================================
# FORMATTING HELPERS
# ==========================================

def _rule(char: str = "─", color: str = DIM, width: Optional[int] = None) -> str:
    w = width or SECTION_WIDTH
    return f"{color}{char * w}{RESET}"


def _banner(text: str, color: str = CYAN, icon: str = "") -> None:
    """Print a bold double-line banner box with a centered title."""
    w = SECTION_WIDTH
    inner = w - 2
    label = f"{icon}  {text}" if icon else text
    print()
    print(f"{color}{BOLD}╔{'═' * inner}╗{RESET}")
    print(f"{color}{BOLD}║{_center_visible(label, inner)}║{RESET}")
    print(f"{color}{BOLD}╚{'═' * inner}╝{RESET}")


def _section(title: str, color: str = WHITE, icon: str = "", count: Optional[int] = None) -> None:
    """Print a section header with an underline sized to the title."""
    label = f"{icon}  {title}" if icon else title
    if count is not None:
        label = f"{label}  {DIM}({count}){RESET}"
    print(f"\n{BOLD}{color}{label}{RESET}")
    print(_rule("─", color, min(max(_visible_len(label), 20), SECTION_WIDTH)))


def _wrap_text(text, prefix: str = "      ", width: int = 70) -> List[str]:
    """Wrap text to fit within a certain width."""
    if not text:
        return []
    
    # Ensure text is a string
    if not isinstance(text, str):
        text = str(text)
    
    # If text is empty after conversion
    if not text.strip():
        return []
    
    effective_width = max(20, width - len(prefix))
    words = text.split()
    lines = []
    current_line = []
    current_len = 0

    for word in words:
        if current_len + len(word) + 1 > effective_width:
            if current_line:
                lines.append(" ".join(current_line))
            current_line = [word]
            current_len = len(word)
        else:
            current_line.append(word)
            current_len += len(word) + 1

    if current_line:
        lines.append(" ".join(current_line))

    return [f"{prefix}{line}" for line in lines]


def _bar(value: int, max_value: int = 100, width: int = 30, fill_color: str = GREEN) -> str:
    """Render a simple horizontal bar."""
    value = max(0, min(value, max_value))
    if max_value == 0:
        return f"{DIM}{'░' * width}{RESET}"
    filled = round((value / max_value) * width)
    return f"{fill_color}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"

def _risk_gauge(score, width: int = 40) -> str:
    """Render a single-line risk gauge."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0
    
    score = max(0, min(score, 100))
    pos = round((score / 100) * (width - 1)) if width > 1 else 0
    color = _get_score_color(score)
    track = list(f"{DIM}{'─' * width}{RESET}")
    marker = f"{color}{BOLD}●{RESET}"
    plain_track = "─" * width
    gauge = f"{DIM}{plain_track[:pos]}{RESET}{marker}{DIM}{plain_track[pos + 1:]}{RESET}"
    return gauge


# ==========================================
# FINDING ROW HELPERS
# ==========================================

def _badge(label: str, color: str, icon: str = "", width: int = 10) -> str:
    """A small fixed-width colored badge, e.g. '🔴 CRITICAL'."""
    text = f"{icon} {label}".strip() if icon else label
    return f"{color}{BOLD}{_pad_visible(text, width)}{RESET}"


def _print_finding_row(finding: Dict[str, Any], show_snippet: bool = False) -> None:
    """Print a single finding row."""
    severity = finding.get("severity", "LOW")
    color = _sev_color(severity)
    icon = _sev_icon(severity)
    name = str(finding.get("name") or finding.get("pattern") or finding.get("package") or "?")
    line = finding.get("lineno", 0)
    cat = finding.get("category", finding.get("flag_type", ""))
    
    # Handle non-integer line numbers
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 0

    badge = _badge(severity, color, icon, width=12)
    meta = f"{DIM}line {line}{RESET}"
    print(f"  {badge} {BOLD}{name}{RESET}  {DIM}·{RESET} {meta}")
    
    if cat:
        print(f"      {DIM}└─ category: {cat}{RESET}")

    reason = finding.get("reason", "")
    if reason:
        wrapped = _wrap_text(reason, prefix="      ")
        for wline in wrapped:
            print(f"{DIM}{wline}{RESET}")

    if show_snippet and finding.get("snippet"):
        snippet = str(finding["snippet"])[:80]
        print(f"      {DIM}┆ {snippet}{RESET}")

# ==========================================
# DATA EXTRACTION HELPERS
# ==========================================

def _get_value(result: Dict, *keys, default=None) -> Any:
    """Get a value using multiple possible keys (for backward compatibility)."""
    for key in keys:
        if key in result:
            return result[key]
    return default


def _get_nested(result: Dict, path: List[str], default=None) -> Any:
    """Get nested value from result."""
    current = result
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def _get_file_path(result: Dict) -> str:
    """Get file path from result (supports both formats)."""
    file_path = _get_nested(result, ["metadata", "target_file"])
    if file_path:
        return file_path
    
    # Try flat format
    file_path = result.get("file")
    if file_path:
        return file_path
    
    # Try to extract from nested
    for key in ["target_file", "filepath", "filename"]:
        file_path = _get_nested(result, ["metadata", key])
        if file_path:
            return file_path
    
    return "unknown"


def _get_phase_data(result: Dict, phase: str, key: str, default=None) -> Any:
    """Get phase-specific data (supports both formats)."""
    # Try structured format first
    phase_data = result.get(phase)
    if isinstance(phase_data, dict) and key in phase_data:
        return phase_data[key]
    # Fallback to flat format
    return result.get(key, default)

def _get_phase1_data(result: Dict, key: str, default=None) -> Any:
    """Get Phase 1 data."""
    return _get_phase_data(result, "phase1", key, default)


def _get_phase2_data(result: Dict, key: str, default=None) -> Any:
    """Get Phase 2 data."""
    return _get_phase_data(result, "phase2", key, default)


def _get_phase3_data(result: Dict, key: str, default=None) -> Any:
    """Get Phase 3 data."""
    return _get_phase_data(result, "phase3", key, default)


def _get_score_info(result: Dict) -> tuple:
    """
    Extract score information from result.

    Returns:
        Tuple of (score_value, risk_level, score_dict)
    """
    score = result.get("score", 0)

    if isinstance(score, dict):
        threat_score = score.get("threat_score", 0)
        risk_level = score.get("risk_level", "Unknown")
        return threat_score, risk_level, score
    else:
        return score if isinstance(score, int) else 0, "Unknown", None


# ==========================================
# SECTION PRINTERS
# ==========================================

def _print_header(result: Dict) -> None:
    """Print the report header."""
    file_path = _get_file_path(result)
    _banner("TrustGuard — Security Analysis Report", CYAN, "🛡️")

    score_value, risk_level, score_dict = _get_score_info(result)
    color = _get_score_color(score_value) if isinstance(score_value, int) else WHITE

    print(f"  {DIM}File{RESET}   {_pad_visible('', 1)}: {BOLD}{file_path}{RESET}")

    if isinstance(score_value, int):
        print(f"  {DIM}Score{RESET}  : {color}{BOLD}{score_value} / 100{RESET}   "
              f"{_risk_icon(score_value)} {color}{BOLD}{risk_level}{RESET}")
        print(f"  {DIM}Gauge{RESET}  : Safe {_risk_gauge(score_value)} Critical")

    scan_time = _get_nested(result, ["metadata", "scan_time"])
    if scan_time:
        try:
            dt = datetime.fromisoformat(scan_time.replace('Z', '+00:00'))
            print(f"  {DIM}Time{RESET}   : {dt.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception:
            print(f"  {DIM}Time{RESET}   : {scan_time}")


def _print_imports(result: Dict) -> None:
    """Print imports section."""
    imports = _get_phase1_data(result, "imports", [])
    _section("Imports Detected", CYAN, SECTION_ICONS["imports"], count=len(imports))
    if imports:
        display = imports[:20]
        print("  " + f"{DIM},{RESET} ".join(f"{CYAN}{i}{RESET}" for i in display))
        if len(imports) > 20:
            print(f"  {DIM}… and {len(imports) - 20} more{RESET}")
    else:
        print(f"  {DIM}None{RESET}")


def _print_findings_section(result: Dict, phase: str, key: str, title: str,
                             max_items: int = 20, icon: str = "") -> None:
    """Generic function to print a findings section."""
    if phase == "phase1":
        findings = _get_phase1_data(result, key, [])
    elif phase == "phase2":
        findings = _get_phase2_data(result, key, [])
    else:
        findings = _get_phase3_data(result, key, [])

    color = RED if findings else GREEN
    icon = icon or SECTION_ICONS.get(key, "•")
    _section(title, color, icon, count=len(findings))

    if findings:
        for f in findings[:max_items]:
            _print_finding_row(f, show_snippet=True)
        if len(findings) > max_items:
            print(f"  {DIM}… and {len(findings) - max_items} more{RESET}")
    else:
        print(f"  {GREEN}✓ None detected.{RESET}")


def _print_behavioral_chains(result: Dict) -> None:
    """Print behavioral chains section with proper formatting."""
    findings = _get_phase2_data(result, "chains", [])
    if not findings:
        findings = result.get("chains", [])

    if not findings:
        return

    _section("Behavioral Chains", RED, SECTION_ICONS["chains"], count=len(findings))
    print(f"  {DIM}Phase 2 — traces sensitive data from source to sink{RESET}")

    for chain in findings[:10]:
        if not isinstance(chain, dict):
            continue

        confidence = chain.get("confidence", "MEDIUM")
        chain_type = chain.get("chain_type", chain.get("type", "Unknown"))
        description = chain.get("description", "")

        color = RED if confidence in ("CRITICAL", "HIGH") else YELLOW
        icon = _sev_icon(confidence)
        print(f"\n  {_badge(confidence, color, icon, width=12)} {BOLD}{chain_type}{RESET}")

        if description:
            for wline in _wrap_text(description, prefix="      "):
                print(f"{DIM}{wline}{RESET}")

        steps = []
        source_var = chain.get("source_var", "")
        source_type = chain.get("source_type", "")
        transforms = chain.get("transforms", [])
        sink_call = chain.get("sink_call", "")
        has_encoding = chain.get("has_encoding", False)

        if source_type and source_var:
            steps.append(f"{source_type} '{source_var}'")
        elif source_type:
            steps.append(f"{source_type}")
        elif source_var:
            steps.append(f"'{source_var}'")

        for t in transforms:
            steps.append(t)

        if sink_call:
            steps.append(f"{sink_call}()")

        if steps:
            flow = f" {DIM}→{RESET} ".join(f"{CYAN}{s}{RESET}" for s in steps)
            print(f"      {DIM}Flow:{RESET} {flow}")
            if has_encoding and transforms:
                print(f"      {DIM}⚠ data was encoded/obfuscated along the way{RESET}")
        else:
            print(f"      {DIM}No flow details available{RESET}")

    if len(findings) > 10:
        print(f"\n  {DIM}… and {len(findings) - 10} more{RESET}")


def _print_feature_vector(result: Dict) -> None:
    """Print the feature vector section."""
    fv = _get_phase2_data(result, "feature_vector", {})
    if not fv:
        return

    _section("Behavioral Feature Vector", BLUE, SECTION_ICONS["feature_vector"])

    flags = [(k, v) for k, v in fv.items() if k != "data_flow_paths"]
    left_col = flags[: (len(flags) + 1) // 2]
    right_col = flags[(len(flags) + 1) // 2:]

    for i in range(max(len(left_col), len(right_col))):
        line = ""
        for col in (left_col, right_col):
            if i < len(col):
                k, v = col[i]
                icon = f"{RED}✓{RESET}" if v else f"{GREEN}✗{RESET}"
                label = k.replace("_", " ").title()
                line += _pad_visible(f"  {icon} {label}", 38)
        print(line)

    paths = fv.get("data_flow_paths", [])
    if paths:
        print(f"\n  {DIM}Data Flow Paths:{RESET}")
        for path in paths:
            print(f"    {CYAN}🔗 {path}{RESET}")


def _print_data_flows(result: Dict) -> None:
    """Print data flows section."""
    flows = _get_phase2_data(result, "data_flows", [])
    if not flows:
        return

    _section("Data Flows", BLUE, SECTION_ICONS["data_flows"], count=len(flows))
    for flow in flows[:10]:
        source = flow.get("source", "?")
        sink = flow.get("sink", "?")
        transforms = flow.get("transforms", [])
        transform_str = " → ".join(transforms) if transforms else "direct"
        print(f"  {CYAN}{source}{RESET} {DIM}→{RESET} {YELLOW}{transform_str}{RESET} "
              f"{DIM}→{RESET} {RED}{sink}{RESET}")

    if len(flows) > 10:
        print(f"  {DIM}… and {len(flows) - 10} more{RESET}")


def _print_phase3_findings(result: Dict) -> None:
    """Print Phase 3 attack findings."""
    findings = _get_phase3_data(result, "correlation_findings", [])
    if not findings:
        return

    _section("Attack Findings", RED if findings else GREEN, SECTION_ICONS["phase3"], count=len(findings))
    print(f"  {DIM}Phase 3 — correlated multi-stage attack patterns{RESET}")

    for f in findings[:10]:
        attack_type = f.get("attack_type", "Unknown")
        severity = f.get("severity", "UNKNOWN")
        confidence = f.get("confidence", 0)
        description = f.get("description", "")

        color = _sev_color(severity)
        icon = _sev_icon(severity)
        print(f"\n  {_badge(severity, color, icon, width=12)} {BOLD}{attack_type}{RESET}  "
              f"{DIM}confidence: {confidence}%{RESET}")

        if description:
            for wline in _wrap_text(description, prefix="      "):
                print(f"{DIM}{wline}{RESET}")

        mitre = f.get("mitre_techniques", []) or f.get("mitre", [])
        if mitre:
            print(f"      {DIM}MITRE ATT&CK:{RESET}")
            for technique in mitre[:3]:
                if isinstance(technique, dict):
                    tech_id = technique.get("technique_id", technique.get("id", "?"))
                    tech_name = technique.get("technique_name", technique.get("name", "?"))
                    print(f"        {DIM}•{RESET} {CYAN}{BOLD}{tech_id}{RESET} — {tech_name}")
            if len(mitre) > 3:
                print(f"        {DIM}… and {len(mitre) - 3} more{RESET}")

    if len(findings) > 10:
        print(f"\n  {DIM}… and {len(findings) - 10} more{RESET}")


def _print_llm_section(result: Dict) -> None:
    """Print LLM analysis section if available."""
    llm = _get_nested(result, ["phase4", "llm_analysis"], {})
    
    if not llm or llm.get("enabled") is False:
        return
    
    _section("LLM Analysis", MAGENTA, SECTION_ICONS["llm"])
    
    # ✅ Get the explanation wrapper
    explanation_wrapper = llm.get("explanation", {})
    
    # ✅ Check for explanations list (new format)
    explanations = explanation_wrapper.get("explanations", [])
    if not explanations:
        # Try direct explanations
        explanations = llm.get("explanations", [])
    
    if explanations:
        for exp in explanations:
            attack_type = exp.get("attack_type", "Unknown")
            confidence = exp.get("confidence", 0)
            severity = exp.get("severity", "UNKNOWN")
            
            print(f"\n  {BOLD}Attack Type:{RESET} {attack_type} ({severity})")
            print(f"  {DIM}Confidence:{RESET} {confidence}%")
            
            explanation = exp.get("explanation", "")
            if explanation:
                print(f"  {BOLD}Explanation:{RESET}")
                for line in explanation.split("\n"):
                    if line.strip():
                        for wline in _wrap_text(line.strip(), prefix="    "):
                            print(wline)
            
            attacker_objective = exp.get("attacker_objective", "")
            if attacker_objective:
                print(f"\n  {BOLD}Attacker Objective:{RESET}")
                for line in attacker_objective.split("\n"):
                    if line.strip():
                        for wline in _wrap_text(line.strip(), prefix="    "):
                            print(wline)
            
            remediation = exp.get("remediation", [])
            if remediation:
                print(f"\n  {BOLD}Remediation Steps:{RESET}")
                for step in remediation:
                    print(f"    • {step}")
            
            trust_score = exp.get("trust_score", 0)
            if trust_score:
                print(f"\n  {BOLD}Trust Score:{RESET} {trust_score}/100")
            
            print()  # Blank line between findings
        return
    
    # ✅ Fallback: Check if explanation is a dict with summary/details
    if isinstance(explanation_wrapper, dict):
        summary = explanation_wrapper.get("summary", "")
        if summary:
            print(f"  {BOLD}Summary:{RESET} {summary}")
        
        details = explanation_wrapper.get("details", "")
        if details:
            print(f"\n  {BOLD}Details:{RESET}")
            for line in details.split("\n"):
                if line.strip():
                    for wline in _wrap_text(line.strip(), prefix="    "):
                        print(wline)
        
        recommendation = explanation_wrapper.get("recommendation", "")
        if recommendation:
            print(f"\n  {BOLD}Recommendation:{RESET}")
            for wline in _wrap_text(recommendation, prefix="    "):
                print(wline)
    
    print()
    
    # Intent comparison
    intent = llm.get("intent", {})
    if intent and intent.get("verdict"):
        verdict = intent.get("verdict")
        color = GREEN if verdict == "MATCH" else (RED if verdict == "MISMATCH" else YELLOW)
        icon = "✓" if verdict == "MATCH" else ("✗" if verdict == "MISMATCH" else "?")
        print(f"  {BOLD}Intent Verdict{RESET}  : {color}{BOLD}{icon} {verdict}{RESET}")
        
        trust_score = intent.get("trust_score", 0)
        if isinstance(trust_score, (int, float)):
            print(f"  {BOLD}Trust Score{RESET}     : {_bar(int(trust_score), fill_color=GREEN)} {int(trust_score)}/100")
        else:
            print(f"  {BOLD}Trust Score{RESET}     : {trust_score}")
        
        if intent.get("mismatch_reason"):
            print(f"  {BOLD}Mismatch Reason{RESET} : {intent['mismatch_reason']}")


def _print_score_summary(result: Dict) -> None:
    """Print the threat score and summary section."""
    score_value, risk_level, score_dict = _get_score_info(result)
    color = _get_score_color(score_value)

    _banner("Threat Score & Summary", color, _risk_icon(score_value))

    print(f"  {BOLD}Threat Score{RESET}  : {color}{BOLD}{score_value}{RESET} / 100")
    print(f"  {BOLD}Risk Level{RESET}    : {color}{BOLD}{risk_level}{RESET}")
    print(f"  {BOLD}Gauge{RESET}         : Safe {_risk_gauge(score_value)} Critical")

    if score_dict:
        breakdown = score_dict.get("breakdown", {})
        if breakdown:
            print(f"\n  {BOLD}Score Breakdown{RESET}")
            for cat, pts in sorted(breakdown.items(), key=lambda kv: kv[1], reverse=True):
                if pts > 0:
                    bcolor = RED if pts >= 20 else (YELLOW if pts >= 10 else GREEN)
                    print(f"    {_pad_visible(cat, 26)} {_bar(pts, 40, 30, bcolor)} "
                          f"{bcolor}{BOLD}{pts:>3}{RESET} pts")

        bonuses = score_dict.get("bonuses", [])
        if bonuses:
            print(f"\n  {BOLD}Correlation Bonuses Fired{RESET}")
            for b in bonuses:
                print(f"    {RED}{BOLD}+{b.get('points', 0)} pts{RESET}  {BOLD}{b.get('name', '?')}{RESET}")
                if b.get("reason"):
                    for wline in _wrap_text(b['reason'], prefix="        "):
                        print(f"{DIM}{wline}{RESET}")

    s = result.get("summary", {})
    print(f"\n  {BOLD}Finding Counts{RESET}")
    counts = [
        ("Imports detected", s.get("total_imports", 0), CYAN),
        ("Dangerous API findings", s.get("dangerous_api_count", 0), RED),
        ("Secrets found", s.get("secrets_found", 0), RED),
        ("Vulnerabilities found", s.get("vulnerabilities_found", 0), RED),
        ("Backdoors found", s.get("backdoors_found", 0), RED),
        ("Obfuscation findings", s.get("obfuscation_found", 0), RED),
        ("Risky dependencies", s.get("risky_dependencies", 0), RED),
        ("Behavioral chains", s.get("chains_detected", 0), RED),
        ("Logic bombs found", s.get("logic_bombs_found", 0), RED),
        ("Attack findings", s.get("correlation_findings", 0), RED),
    ]
    left_col = counts[: (len(counts) + 1) // 2]
    right_col = counts[(len(counts) + 1) // 2:]
    for i in range(max(len(left_col), len(right_col))):
        line = ""
        for col in (left_col, right_col):
            if i < len(col):
                label, val, base_color = col[i]
                marker = base_color if val > 0 else GREEN
                cell = f"  {_pad_visible(label, 26)} {marker}{BOLD}{val:>3}{RESET}"
                line += _pad_visible(cell, 42)
        print(line)

    version = _get_nested(result, ["metadata", "version"])
    if version:
        print(f"\n  {DIM}TrustGuard v{version}{RESET}")

    print()
    print(_rule("─", DIM))
    print(f"  {DIM}ℹ Phase 1 is signature/rule-based only — a clean result here does{RESET}")
    print(f"  {DIM}  not guarantee safety. Phases 2–5 provide the deeper, behavior-{RESET}")
    print(f"  {DIM}  and intent-based verdict.{RESET}")
    print(_rule("─", DIM))
    print()


def _print_legend() -> None:
    """Print a one-line severity legend so colors are self-explanatory."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    parts = [f"{_sev_color(s)}{_sev_icon(s)} {s}{RESET}" for s in order]
    print(f"{DIM}Legend:{RESET} " + f"  {DIM}·{RESET}  ".join(parts))


# ==========================================
# MAIN REPORT FUNCTION
# ==========================================

def print_report(result: Dict[str, Any]) -> None:
    """
    Print a formatted report of scan results.
    Supports both flat (legacy) and structured formats.
    """
    # Header
    _print_header(result)
    _print_legend()

    # Phase 1 Sections
    _print_imports(result)
    _print_findings_section(result, "phase1", "dangerous_apis", "Dangerous API Findings")
    _print_findings_section(result, "phase1", "secrets", "Secrets / Credentials")
    _print_findings_section(result, "phase1", "vulnerabilities", "Vulnerability Findings")
    _print_findings_section(result, "phase1", "backdoors", "Backdoor Findings")
    _print_findings_section(result, "phase1", "obfuscation", "Obfuscation Findings")

    # Phase 2 Sections
    _print_behavioral_chains(result)
    _print_findings_section(result, "phase1", "logic_bombs", "Logic Bomb Findings")
    _print_data_flows(result)
    _print_feature_vector(result)

    # Phase 3 Sections
    _print_phase3_findings(result)

    # Dependencies
    _print_findings_section(result, "phase1", "vulnerable_dependencies", "Dependency Findings")

    # Phase 4 LLM
    _print_llm_section(result)

    # Score Summary
    _print_score_summary(result)


# ==========================================
# JSON EXPORT
# ==========================================

def save_json_report(result: Dict[str, Any], output_path: str) -> None:
    """
    Save report as JSON file.

    Args:
        result: Scan result dictionary
        output_path: Output file path
    """
    # Remove non-serializable items
    exportable = {k: v for k, v in result.items() if k not in ["ast_tree", "tree"]}

    def default_serializer(obj):
        if hasattr(obj, '__dict__'):
            return str(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(exportable, f, indent=2, ensure_ascii=False, default=default_serializer)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "print_report",
    "save_json_report",
]