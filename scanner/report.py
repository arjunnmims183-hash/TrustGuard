"""
report.py
---------
Formats and prints the complete Phase 1 scan result to the terminal,
and optionally saves it as JSON.
"""

import json
from typing import Dict, Any

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
MAGENTA = "\033[95m"

def _sev_color(s): return {
    "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN
}.get(s, WHITE)

def _banner(text, color=CYAN):
    w = 72
    print(f"\n{color}{BOLD}{'─'*w}{RESET}")
    print(f"{color}{BOLD}  {text}{RESET}")
    print(f"{color}{BOLD}{'─'*w}{RESET}")

def _section(title, color=WHITE):
    print(f"\n{BOLD}{color}{title}{RESET}")
    print(f"{DIM}{'·'*60}{RESET}")

def _finding_row(f, show_snippet=False):
    color = _sev_color(f.get("severity", "LOW"))
    tag   = f"[{f.get('severity','?')}]".ljust(8)
    name  = f.get("name") or f.get("pattern") or f.get("package") or "?"
    line  = f.get("lineno", 0)
    cat   = f.get("category", f.get("flag_type", ""))
    print(f"  {color}{BOLD}{tag}{RESET} {BOLD}{name}{RESET}  {DIM}line {line}{RESET}")
    if cat:
        print(f"           {DIM}Category : {cat}{RESET}")
    reason = f.get("reason", "")
    if reason:
        # Word-wrap at ~65 chars
        words = reason.split()
        line_buf, out = [], []
        for w in words:
            if sum(len(x)+1 for x in line_buf) + len(w) > 65:
                out.append(" ".join(line_buf))
                line_buf = [w]
            else:
                line_buf.append(w)
        if line_buf:
            out.append(" ".join(line_buf))
        for i, l in enumerate(out):
            prefix = "           " if i > 0 else "           "
            print(f"{prefix}{DIM}{l}{RESET}")
    if show_snippet and f.get("snippet"):
        print(f"           {DIM}Code     : {f['snippet'][:80]}{RESET}")


def print_report(result: Dict[str, Any]) -> None:
    _banner("TrustGuard Phase 1 — Static Analysis Report")
    print(f"  {DIM}File   :{RESET}  {result['file']}")

    # ── Imports ──────────────────────────────────────────────────────────────
    _section("Imports Detected", CYAN)
    if result["imports"]:
        print("  " + "  ".join(f"{CYAN}{i}{RESET}" for i in result["imports"]))
    else:
        print(f"  {DIM}None{RESET}")

    # ── Dangerous APIs ────────────────────────────────────────────────────────
    findings = result.get("dangerous_apis", [])
    _section(f"Dangerous API Findings  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for f in findings:
            _finding_row(f)
    else:
        print(f"  {GREEN}None detected.{RESET}")

    # ── Secrets ───────────────────────────────────────────────────────────────
    findings = result.get("secrets", [])
    _section(f"Secrets / Credentials  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for f in findings:
            color = _sev_color(f.get("severity","LOW"))
            tag   = f"[{f.get('severity','?')}]".ljust(8)
            print(f"  {color}{BOLD}{tag}{RESET} {BOLD}{f['pattern']}{RESET}  {DIM}line {f['lineno']}{RESET}")
            print(f"           {DIM}Value    : {f['value']}{RESET}")
            print(f"           {DIM}{f['reason']}{RESET}")
    else:
        print(f"  {GREEN}None detected.{RESET}")

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    findings = result.get("vulnerabilities", [])
    _section(f"Vulnerability Findings  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for f in findings:
            _finding_row(f, show_snippet=True)
    else:
        print(f"  {GREEN}None detected.{RESET}")

    # ── Backdoors ─────────────────────────────────────────────────────────────
    findings = result.get("backdoors", [])
    _section(f"Backdoor Findings  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for f in findings:
            _finding_row(f, show_snippet=True)
    else:
        print(f"  {GREEN}None detected.{RESET}")

    # ── Obfuscation ───────────────────────────────────────────────────────────
    findings = result.get("obfuscation", [])
    _section(f"Obfuscation Findings  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for f in findings:
            _finding_row(f, show_snippet=True)
    else:
        print(f"  {GREEN}None detected.{RESET}")

    # ── Behavioral Chains ─────────────────────────────────────────────────────
    findings = result.get("chains", [])
    _section(f"Behavioral Chains (Phase 2)  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for c in findings:
            conf = c["confidence"]
            color = RED if conf in ("CRITICAL","HIGH") else YELLOW
            print(f"  {color}{BOLD}[{conf}]{RESET}  {BOLD}{c['chain_type']}{RESET}")
            print(f"           {DIM}{c['description']}{RESET}")
            steps = [f"  {c['source_type']} '{c['source_var']}'"]
            for t in c.get("transforms", []):
                steps.append(f"  → {t}")
            steps.append(f"  → {c['sink_call']}()")
            for s in steps:
                print(f"           {CYAN}{s}{RESET}")
    else:
        print(f"  {GREEN}No chains detected.{RESET}")

    # ── Logic Bombs ───────────────────────────────────────────────────────────
    findings = result.get("logic_bombs", [])
    _section(f"Logic Bomb Findings  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for f in findings:
            _finding_row(f, show_snippet=True)
    else:
        print(f"  {GREEN}None detected.{RESET}")

    # ── Feature Vector ────────────────────────────────────────────────────────
    fv = result.get("feature_vector", {})
    if fv:
        _section("Behavioral Feature Vector (Phase 2)", BLUE)
        for k, v in fv.items():
            icon  = f"{RED}✓{RESET}" if v else f"{GREEN}✗{RESET}"
            label = k.replace("_", " ").title()
            print(f"  {icon}  {label}")

    # ── Dependencies ──────────────────────────────────────────────────────────
    findings = result.get("vulnerable_dependencies", [])
    _section(f"Dependency Findings  ({len(findings)})", RED if findings else GREEN)
    if findings:
        for f in findings:
            if "error" in f:
                print(f"  {YELLOW}[WARN]{RESET} {f['error']}")
                continue
            color = _sev_color(f.get("severity","LOW"))
            tag   = f"[{f.get('severity','?')}]".ljust(8)
            ver   = f"  ({f['version']})" if f.get("version") else ""
            print(f"  {color}{BOLD}{tag}{RESET} {BOLD}{f['package']}{ver}{RESET}  {DIM}line {f['lineno']}{RESET}")
            print(f"           {DIM}Type     : {f['flag_type']}{RESET}")
            print(f"           {DIM}{f['reason']}{RESET}")
    else:
        print(f"  {GREEN}None detected.{RESET}")

    # ── Threat Score & Summary ────────────────────────────────────────────────
    score = result.get("score", {})
    ts    = score.get("threat_score", 0)
    rl    = score.get("risk_level", "Unknown")
    bd    = score.get("breakdown", {})
    bons  = score.get("bonuses", [])

    if ts <= 20:   sc = GREEN
    elif ts <= 45: sc = YELLOW
    elif ts <= 70: sc = YELLOW
    else:          sc = RED

    _banner("Threat Score & Summary", sc)

    print(f"  {BOLD}Threat Score  :{RESET}  {sc}{BOLD}{ts} / 100{RESET}")
    print(f"  {BOLD}Risk Level    :{RESET}  {sc}{BOLD}{rl}{RESET}")

    print(f"\n  {BOLD}Score Breakdown:{RESET}")
    for cat, pts in bd.items():
        bar = "█" * pts + "░" * max(0, 40 - pts)
        color = RED if pts >= 20 else (YELLOW if pts >= 10 else GREEN)
        print(f"    {cat:<28} {color}{pts:>3} pts  {bar[:30]}{RESET}")

    if bons:
        print(f"\n  {BOLD}Correlation Bonuses Fired:{RESET}")
        for b in bons:
            print(f"    {RED}+ {b['points']} pts{RESET}  {BOLD}{b['name']}{RESET}")
            print(f"              {DIM}{b['reason']}{RESET}")

    s = result.get("summary", {})
    print(f"\n  {BOLD}Finding Counts:{RESET}")
    counts = [
        ("Imports detected",       s.get("total_imports", 0),          CYAN),
        ("Dangerous API findings",  s.get("dangerous_api_count", 0),    RED),
        ("Secrets found",          s.get("secrets_found", 0),           RED),
        ("Vulnerabilities found",  s.get("vulnerabilities_found", 0),   RED),
        ("Backdoors found",        s.get("backdoors_found", 0),         RED),
        ("Obfuscation findings",   s.get("obfuscation_found", 0),       RED),
        ("Risky dependencies",     s.get("risky_dependencies", 0),      RED),
        ("Behavioral chains",      s.get("chains_detected", 0),         RED),
        ("Logic bombs found",      s.get("logic_bombs_found", 0),       RED),
    ]
    for label, val, color in counts:
        marker = color if val > 0 else GREEN
        print(f"    {label:<30} {marker}{BOLD}{val}{RESET}")

    print(f"\n  {DIM}Note: Phase 1 is signature/rule-based only.")
    print(f"  A clean result here does not guarantee safety.")
    print(f"  Behavioral and intent analysis (Phases 2–5) provide deeper verdict.{RESET}")
    print()


def save_json_report(result: Dict[str, Any], output_path: str) -> None:
    exportable = {k: v for k, v in result.items() if k != "ast_tree"}
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(exportable, f, indent=2, ensure_ascii=False)
