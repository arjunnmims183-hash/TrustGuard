"""
TrustGuard — Phase 1 + Phase 2
Usage:
    python scan.py target.py
    python scan.py target.py --deps requirements.txt --json
"""
import argparse, sys
from scanner.parser               import parse_file
from scanner.dangerous_api        import detect_dangerous_apis
from scanner.secret_scanner       import detect_secrets
from scanner.vulnerability_scanner import scan_vulnerabilities
from scanner.backdoor_detector    import detect_backdoors
from scanner.obfuscation_detector import detect_obfuscation
from scanner.dependency_scanner   import scan_dependencies
from scanner.behavioral_analyzer  import analyze_behavior
from scanner.exfiltration_tracer  import trace_exfiltration
from scanner.logic_bomb_detector  import detect_logic_bombs
from scanner.scoring              import compute_score
from scanner.report               import print_report, save_json_report


def run_scan(filepath, deps_file=None):
    print(f"\n[*] Parsing               {filepath}")
    parsed = parse_file(filepath)
    if parsed.get("error"):
        print(f"[!] {parsed['error']}"); sys.exit(1)

    tree, source = parsed["ast_tree"], parsed["source"]

    # ── Phase 1 ──────────────────────────────────────────────────────────────
    print("[*] Dangerous API scan    ...")
    apis      = detect_dangerous_apis(tree, source)
    print("[*] Secret scanner        ...")
    secrets   = detect_secrets(source)
    print("[*] Vulnerability scanner ...")
    vulns     = scan_vulnerabilities(tree, source)
    print("[*] Backdoor detector     ...")
    backdoors = detect_backdoors(tree, source)
    print("[*] Obfuscation detector  ...")
    obf       = detect_obfuscation(tree, source)

    deps = []
    if deps_file:
        print(f"[*] Dependency scanner    ... {deps_file}")
        deps = scan_dependencies(deps_file)
    else:
        print("[*] Dependency scanner    ... skipped (no --deps)")

    # ── Phase 2 ──────────────────────────────────────────────────────────────
    print("[*] Behavioral analysis   ...")
    behavioral          = analyze_behavior(tree, source)
    print("[*] Exfiltration tracer   ...")
    chains              = trace_exfiltration(behavioral["data_flows"])
    print("[*] Logic bomb detector   ...")
    logic_bombs         = detect_logic_bombs(tree, source)

    result = {
        "file":                    filepath,
        "imports":                 parsed["imports"],
        "dangerous_apis":          apis,
        "secrets":                 secrets,
        "vulnerabilities":         vulns,
        "backdoors":               backdoors,
        "obfuscation":             obf,
        "vulnerable_dependencies": deps,
        "feature_vector":          behavioral["feature_vector"],
        "data_flows":              behavioral["data_flows"],
        "chains":                  chains,
        "logic_bombs":             logic_bombs,
    }

    print("[*] Scoring               ...")
    result["score"] = compute_score(result)
    result["summary"] = {
        "total_imports":         len(parsed["imports"]),
        "dangerous_api_count":   len(apis),
        "secrets_found":         len(secrets),
        "vulnerabilities_found": len(vulns),
        "backdoors_found":       len(backdoors),
        "obfuscation_found":     len(obf),
        "risky_dependencies":    len(deps),
        "chains_detected":       len(chains),
        "logic_bombs_found":     len(logic_bombs),
    }
    return result


def main():
    ap = argparse.ArgumentParser(description="TrustGuard Scanner")
    ap.add_argument("file")
    ap.add_argument("--deps", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    result = run_scan(args.file, args.deps)
    print_report(result)

    if args.json:
        out = args.file.replace(".py", "_trustguard.json")
        save_json_report(result, out)
        print(f"\n[+] JSON saved: {out}")


if __name__ == "__main__":
    main()
