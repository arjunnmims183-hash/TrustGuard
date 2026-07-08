"""
TrustGuard — Phase 1 + Phase 2 + Phase 3
Unified entry point for complete security analysis of AI-generated code.

Usage:
    python scan.py target.py
    python scan.py target.py --deps requirements.txt --json
    python scan.py target.py --verbose
    python scan.py target.py --llm  (future Phase 4)

Version: 3.0
"""
from scanner.llm.llm_reasoner import get_llm_reasoner
from scanner.llm.intent_comparator import IntentComparator

import ast
import argparse
import sys
import io
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, Union

# ============================================================================
# Force UTF-8 encoding for Windows console
# ============================================================================
if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    except (AttributeError, ValueError):
        pass

# ============================================================================
# Phase 1 Imports
# ============================================================================
from scanner.parser import parse_file
from scanner.dangerous_api import detect_dangerous_apis
from scanner.secret_scanner import detect_secrets
from scanner.vulnerability_scanner import scan_vulnerabilities
from scanner.backdoor_detector import detect_backdoors
from scanner.obfuscation_detector import detect_obfuscation
from scanner.dependency_scanner import scan_dependencies

# ============================================================================
# Phase 2 Imports
# ============================================================================
from scanner.behavioral_analyzer import analyze_behavior
from scanner.exfiltration_tracer import trace_exfiltration
from scanner.logic_bomb_detector import detect_logic_bombs

# ============================================================================
# Phase 3 Imports
# ============================================================================
from scanner.correlation_engine import correlate_behaviors
from scanner.attack_scorer import score_attacks
from scanner.threat_explainer import explain_threats

# MITRE Mapper (handle different function names)
try:
    from scanner.mitre_mapper import map_to_mitre
except ImportError:
    try:
        from scanner.mitre_mapper import enrich_findings as map_to_mitre
    except ImportError:
        # Fallback if neither exists
        def map_to_mitre(findings):
            return findings
        print("[!] Warning: mitre_mapper.py not found. MITRE mapping disabled.")

# Attack Graph (experimental)
try:
    from scanner.attack_graph import build_attack_graph
except ImportError:
    def build_attack_graph(*args, **kwargs):
        return {"error": "attack_graph module not available"}

# ============================================================================
# Scoring & Reporting
# ============================================================================
from scanner.scoring import compute_score
from scanner.report import print_report, save_json_report

# ============================================================================
# Constants
# ============================================================================
VERSION = "3.0"
DEPRECATION_WARNING = """
[!] DEPRECATION WARNING: Flat result keys (e.g., 'dangerous_apis', 'secrets')
    are deprecated and will be removed in TrustGuard v4.0.
    
    Please use the structured format:
        result["phase1"]["dangerous_apis"]
        result["phase2"]["feature_vector"]
        result["phase3"]["correlation_findings"]
    
    See docs/migration.md for details.
"""


# ============================================================================
# Utility Functions
# ============================================================================


def _extract_prompt_from_context(filepath: str, source: str) -> Optional[str]:
    """
    Try to extract a prompt from the code or a companion file.
    
    Looks for:
        1. A .prompt file with the same name
        2. A comment in the code starting with "Prompt:"
        3. A docstring at the top of the file
    """
    import os
    
    # Check for companion .prompt file
    prompt_file = filepath.replace('.py', '.prompt')
    if os.path.exists(prompt_file):
        try:
            with open(prompt_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    return content
        except:
            pass
    
    # Check for "Prompt:" comment in source
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith('# Prompt:'):
            return stripped.replace('# Prompt:', '').strip()
        if stripped.startswith('"""Prompt:'):
            return stripped.replace('"""Prompt:', '').strip('"""')
    
    # Check for docstring at top of file
    if source.startswith('"""'):
        end = source.find('"""', 3)
        if end > 0:
            docstring = source[3:end].strip()
            if len(docstring) > 20:  # Reasonable length
                return docstring
    
    return None


def run_stage(name: str, func, *args, **kwargs) -> Any:
    """
    Run a pipeline stage with consistent logging.
    
    Args:
        name: Display name for the stage
        func: Function to execute
        *args, **kwargs: Arguments to pass to func
        
    Returns:
        Result of func(*args, **kwargs)
    """
    print(f"[*] {name:<30} ...", end=" ", flush=True)
    try:
        result = func(*args, **kwargs)
        print("[OK]")
        return result
    except Exception as e:
        print(f"[FAIL] {str(e)}")
        raise


def safe_run_stage(name: str, func, *args, default=None, **kwargs) -> Any:
    """
    Run a pipeline stage with graceful failure.
    
    Args:
        name: Display name for the stage
        func: Function to execute
        default: Default value if stage fails
        *args, **kwargs: Arguments to pass to func
        
    Returns:
        Result of func(*args, **kwargs) or default on error
    """
    print(f"[*] {name:<30} ...", end=" ", flush=True)
    try:
        result = func(*args, **kwargs)
        print("[OK]")
        return result
    except Exception as e:
        print(f"[WARN] ({str(e)})")
        return default


def parse_file_safe(filepath: str) -> Tuple[ast.AST, str, List[str]]:
    """
    Safely parse a Python file.
    
    Args:
        filepath: Path to Python file
        
    Returns:
        Tuple of (tree, source, imports)
        
    Raises:
        RuntimeError: If parsing fails
    """
    parsed = parse_file(filepath)
    if parsed.get("error"):
        raise RuntimeError(parsed["error"])
    
    return (
        parsed["ast_tree"],
        parsed["source"],
        parsed.get("imports", [])
    )


def get_score_value(score: Union[int, float, Dict]) -> int:
    """
    Extract numeric score from various score formats.
    
    Args:
        score: Score as int, float, or dict with 'threat_score' key
        
    Returns:
        Numeric score value
    """
    if isinstance(score, (int, float)):
        return int(score)
    elif isinstance(score, dict):
        return score.get("threat_score", score.get("total", 0))
    return 0


def warn_deprecation() -> None:
    """Print deprecation warning if enabled."""
    # Uncomment the line below to enable deprecation warnings
    # print(DEPRECATION_WARNING)
    pass


# ============================================================================
# Main Scan Function
# ============================================================================

def run_scan(
    filepath: str,
    deps_file: Optional[str] = None,
    verbose: bool = False,
    llm_enabled: bool = False,
    show_deprecation_warning: bool = False
) -> Dict[str, Any]:
    """
    Run the complete TrustGuard analysis pipeline.
    
    Args:
        filepath: Path to Python file to scan
        deps_file: Optional path to requirements.txt
        verbose: Enable verbose output
        llm_enabled: Enable LLM reasoning (Phase 4)
        show_deprecation_warning: Show deprecation warning for flat keys
        
    Returns:
        Complete analysis results dictionary
    """
    if show_deprecation_warning:
        warn_deprecation()
    
    print(f"\n{'='*60}")
    print(f"TrustGuard v{VERSION} — Security Analysis")
    print(f"Target: {filepath}")
    if llm_enabled:
        print("LLM Reasoning: Enabled (Phase 4)")
    print(f"{'='*60}\n")
    
    # ========================================================================
    # Initialization
    # ========================================================================
    start_time = datetime.now()
    
    # ========================================================================
    # Parse Source File
    # ========================================================================
    print("[*] Parsing               ...", end=" ", flush=True)
    try:
        tree, source, imports = parse_file_safe(filepath)
        print("[OK]")
    except RuntimeError as e:
        print(f"[FAIL] {str(e)}")
        raise
    except Exception as e:
        print(f"[FAIL] Unexpected error: {str(e)}")
        raise
    
    # ========================================================================
    # Phase 1 — Static Analysis
    # ========================================================================
    print("\n[Phase 1 — Static Analysis]")
    print("-" * 40)
    
    dangerous_apis = run_stage(
        "Dangerous API scan",
        detect_dangerous_apis,
        tree, source
    )
    
    secrets = run_stage(
        "Secret scanner",
        detect_secrets,
        source
    )
    
    vulnerabilities = run_stage(
        "Vulnerability scanner",
        scan_vulnerabilities,
        tree, source
    )
    
    backdoors = run_stage(
        "Backdoor detector",
        detect_backdoors,
        tree, source
    )
    
    obfuscation = run_stage(
        "Obfuscation detector",
        detect_obfuscation,
        tree, source
    )
    
    # Dependency scanning (optional)
    if deps_file:
        vulnerable_deps = run_stage(
            f"Dependency scanner ({deps_file})",
            scan_dependencies,
            deps_file
        )
    else:
        print("[*] Dependency scanner        ... skipped (use --deps)")
        vulnerable_deps = []
    
    # ========================================================================
    # Phase 2 — Behavioral Analysis
    # ========================================================================
    print("\n[Phase 2 — Behavioral Analysis]")
    print("-" * 40)
    
    behavioral = run_stage(
        "Behavioral analysis",
        analyze_behavior,
        tree, source
    )
    
    exfiltration_chains = run_stage(
        "Exfiltration tracer",
        trace_exfiltration,
        behavioral.get("data_flows", [])
    )
    
    logic_bombs = run_stage(
        "Logic bomb detector",
        detect_logic_bombs,
        tree, source
    )
    
    # Extract feature vector and flows
    feature_vector = behavioral.get("feature_vector", {})
    data_flows = behavioral.get("data_flows", [])
    
    # ========================================================================
    # Phase 3 — Correlation & Scoring
    # ========================================================================
    print("\n[Phase 3 — Correlation & Threat Scoring]")
    print("-" * 40)
    
    # 3.1 Correlate behaviors
    correlation_findings = run_stage(
        "Behavior correlation",
        correlate_behaviors,
        data_flows,
        feature_vector
    )
    
    # 3.2 Build attack graph (experimental)
    try:
        attack_graph = run_stage(
            "Attack graph construction (experimental)",
            build_attack_graph,
            correlation_findings
        )
    except Exception as e:
        print(f"[*] Attack graph construction   ... [WARN] ({str(e)})")
        attack_graph = {}
    
    # 3.3 Score attacks (confidence scores, not overall risk)
    scored_attacks = run_stage(
        "Attack confidence scoring",
        score_attacks,
        correlation_findings,
        feature_vector
    )
    
    # 3.4 Map to MITRE ATT&CK
    mitre_mappings = run_stage(
        "MITRE ATT&CK mapping",
        map_to_mitre,
        correlation_findings
    )
    
    # 3.5 Generate threat explanations
    threat_explanations = run_stage(
        "Threat explanation",
        explain_threats,
        correlation_findings,
        feature_vector
    )
    
    # 3.6 Compute overall risk score (master score)
    score_result = run_stage(
        "Overall risk scoring",
        compute_score,
        {
            "dangerous_apis": dangerous_apis,
            "secrets": secrets,
            "vulnerabilities": vulnerabilities,
            "backdoors": backdoors,
            "obfuscation": obfuscation,
            "vulnerable_dependencies": vulnerable_deps,
            "feature_vector": feature_vector,
            "data_flows": data_flows,
            "chains": exfiltration_chains,
            "logic_bombs": logic_bombs,
        }
    )
    
    # Extract numeric score for display and exit code
    score_numeric = get_score_value(score_result)
    
    # ========================================================================
    # Phase 4 — LLM Reasoning
    # ========================================================================
    llm_analysis = None
    llm_intent = None
    
    if llm_enabled:
        print("\n[Phase 4 — LLM Reasoning]")
        print("-" * 40)
        
        try:
            from scanner.llm.llm_reasoner import get_llm_reasoner
            from scanner.llm.intent_comparator import IntentComparator
            
            llm_reasoner = get_llm_reasoner()
            
            if llm_reasoner.is_available():
                # 4.1: Get LLM explanation
                llm_explanation = run_stage(
                    "LLM explanation",
                    llm_reasoner.explain_findings,
                    correlation_findings,
                    feature_vector,
                    data_flows,
                    score_result
                )
                
                # 4.2: Intent comparison (if prompt available)
                if filepath:  # Use filepath as prompt source for now
                    # Try to read prompt from a companion file or extract from code
                    prompt = _extract_prompt_from_context(filepath, source)
                    if prompt:
                        intent_comparator = IntentComparator()
                        llm_intent = run_stage(
                            "Intent comparison",
                            intent_comparator.compare,
                            prompt,
                            feature_vector,
                            correlation_findings
                        )
                    else:
                        print("[*] Intent comparison        ... skipped (no prompt found)")
                        llm_intent = {"error": "No prompt provided"}
                else:
                    print("[*] Intent comparison        ... skipped (no prompt)")
                    llm_intent = {"error": "No prompt provided"}
                
                # Combine results
                llm_analysis = {
                    "explanation": llm_explanation,
                    "intent": llm_intent,
                }
            else:
                print("[*] LLM not available (Ollama not running)")
                llm_analysis = {"error": "LLM not available"}
                
        except ImportError as e:
            print(f"[*] LLM module not available: {e}")
            llm_analysis = {"error": "Module not found"}
        except Exception as e:
            print(f"[*] LLM error: {e}")
            llm_analysis = {"error": str(e)}
    else:
        llm_analysis = {"enabled": False}


    # ========================================================================
    # Build Final Result
    # ========================================================================
    end_time = datetime.now()
    scan_duration = (end_time - start_time).total_seconds()
    
    # --- MODERN STRUCTURED FORMAT (PREFERRED) ---
    result = {
        # Metadata
        "metadata": {
            "version": VERSION,
            "scan_time": end_time.isoformat(),
            "duration_seconds": scan_duration,
            "target_file": filepath,
            "llm_enabled": llm_enabled,
        },
        
        # Phase 1 Results
        "phase1": {
            "imports": imports,
            "dangerous_apis": dangerous_apis,
            "secrets": secrets,
            "vulnerabilities": vulnerabilities,
            "backdoors": backdoors,
            "obfuscation": obfuscation,
            "vulnerable_dependencies": vulnerable_deps,
        },
        
        # Phase 2 Results
        "phase2": {
            "feature_vector": feature_vector,
            "data_flows": data_flows,
            "exfiltration_chains": exfiltration_chains,
            "logic_bombs": logic_bombs,
        },
        
        # Phase 3 Results
        "phase3": {
            "correlation_findings": correlation_findings,
            "attack_graph": attack_graph,
            "scored_attacks": scored_attacks,
            "mitre_mappings": mitre_mappings,
            "threat_explanations": threat_explanations,
        },
        
        # Phase 4 Results (Future)
        "phase4": {
            "llm_analysis": llm_analysis,
        },
        
        # Master Score - Store the full dict!
        "score": score_result,
        "score_details": score_result,
        "score_numeric": score_numeric,
        
        # Summary
        "summary": {
            "total_imports": len(imports),
            "dangerous_api_count": len(dangerous_apis),
            "secrets_found": len(secrets),
            "vulnerabilities_found": len(vulnerabilities),
            "backdoors_found": len(backdoors),
            "obfuscation_found": len(obfuscation),
            "risky_dependencies": len(vulnerable_deps),
            "chains_detected": len(exfiltration_chains),
            "logic_bombs_found": len(logic_bombs),
            "correlation_findings": len(correlation_findings),
            "attack_count": len(scored_attacks),
        },
    }
    
    # ========================================================================
    # BACKWARD COMPATIBILITY LAYER (DEPRECATED - will be removed in v4.0)
    # ========================================================================
    # These flat keys are maintained for backward compatibility with:
    #   - test_phase2cv3.py, test_phase3d.py, test_full_pipeline.py
    #   - report.py (until updated)
    #   - scoring.py (until updated)
    #   - Other modules not yet migrated to structured format
    #
    # NEW CODE SHOULD USE:
    #   result["phase1"]["dangerous_apis"]
    #   result["phase2"]["feature_vector"]
    #   result["phase3"]["correlation_findings"]
    #   etc.
    #
    # These will be removed in TrustGuard v4.0
    # ========================================================================
    
    # Phase 1 legacy keys
    result["imports"] = imports
    result["dangerous_apis"] = dangerous_apis
    result["secrets"] = secrets
    result["vulnerabilities"] = vulnerabilities
    result["backdoors"] = backdoors
    result["obfuscation"] = obfuscation
    result["vulnerable_dependencies"] = vulnerable_deps
    
    # Phase 2 legacy keys
    result["feature_vector"] = feature_vector
    result["data_flows"] = data_flows
    result["chains"] = exfiltration_chains
    result["logic_bombs"] = logic_bombs
    
    # Phase 3 legacy keys
    result["correlation_findings"] = correlation_findings
    result["mitre_mappings"] = mitre_mappings
    
    # Score legacy key - keep the full dict
    result["score_numeric_legacy"] = score_numeric
    
    # ========================================================================
    # Verbose Output
    # ========================================================================
    if verbose:
        print("\n[Verbose Output]")
        print(f"  Feature Vector:")
        for key, value in feature_vector.items():
            print(f"    {key}: {value}")
        
        print(f"\n  Data Flows: {len(data_flows)}")
        for flow in data_flows[:3]:
            print(f"    {flow}")
        if len(data_flows) > 3:
            print(f"    ... and {len(data_flows) - 3} more")
        
        print(f"\n  Attack Findings: {len(correlation_findings)}")
        for finding in correlation_findings[:3]:
            print(f"    {finding}")
        if len(correlation_findings) > 3:
            print(f"    ... and {len(correlation_findings) - 3} more")
        
        print(f"\n  MITRE Techniques: {len(mitre_mappings)}")
        for mitre in mitre_mappings[:3]:
            print(f"    {mitre}")
        if len(mitre_mappings) > 3:
            print(f"    ... and {len(mitre_mappings) - 3} more")
        
        print(f"\n  Score Details:")
        print(f"    threat_score: {score_result.get('threat_score', 0)}")
        print(f"    risk_level: {score_result.get('risk_level', 'Unknown')}")
        breakdown = score_result.get('breakdown', {})
        if breakdown:
            print(f"    breakdown:")
            for key, value in breakdown.items():
                if value > 0:
                    print(f"      {key}: {value}")
        bonuses = score_result.get('bonuses', [])
        if bonuses:
            print(f"    bonuses:")
            for bonus in bonuses:
                print(f"      +{bonus.get('points', 0)} pts: {bonus.get('name', '?')}")
    
    # ========================================================================
    # Completion
    # ========================================================================
    print(f"\n{'='*60}")
    print(f"[OK] Scan complete in {scan_duration:.2f}s")
    print(f"  Findings: {len(correlation_findings)}")
    print(f"  Risk Score: {score_numeric} / 100")
    print(f"  Risk Level: {score_result.get('risk_level', 'Unknown')}")
    if llm_enabled and llm_analysis:
        print(f"  LLM Analysis: Available")
    print(f"{'='*60}\n")
    
    return result


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    """Command-line interface entry point."""
    parser = argparse.ArgumentParser(
        description="TrustGuard — AI-Assisted Forensic Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scan.py suspicious.py
    python scan.py malicious.py --json
    python scan.py sample.py --deps requirements.txt --verbose
    python scan.py sample.py --llm  (Phase 4 - requires Ollama)
    
Note: Flat result keys (e.g., 'dangerous_apis') are deprecated.
      Use structured format (e.g., 'phase1.dangerous_apis') in new code.
        """
    )
    
    parser.add_argument(
        "file",
        help="Path to Python file to analyze"
    )
    
    parser.add_argument(
        "--deps",
        default=None,
        help="Path to requirements.txt for dependency scanning"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Save results as JSON file"
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Enable LLM reasoning (Phase 4 - requires Ollama)"
    )
    
    parser.add_argument(
        "--show-deprecation",
        action="store_true",
        help="Show deprecation warning for flat keys"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"TrustGuard v{VERSION}"
    )
    
    args = parser.parse_args()
    
    try:
        # Run the scan
        result = run_scan(
            filepath=args.file,
            deps_file=args.deps,
            verbose=args.verbose,
            llm_enabled=args.llm,
            show_deprecation_warning=args.show_deprecation
        )
        
        # Print report
        print_report(result)
        
        # Save JSON if requested
        if args.json:
            json_file = args.file.replace(".py", "_trustguard.json")
            save_json_report(result, json_file)
            print(f"\n[+] JSON report saved: {json_file}")
        
        # Exit with appropriate code
        score = result.get("score", {})
        if isinstance(score, dict):
            score = score.get("threat_score", score.get("total", 0))
        elif isinstance(score, (int, float)):
            score = int(score)
        else:
            score = 0
        
        if score > 70:
            sys.exit(1)  # High risk
            
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
        
    except RuntimeError as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    "run_scan",
    "VERSION",
]


if __name__ == "__main__":
    main()