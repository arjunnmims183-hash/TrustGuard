import json
import sys

from datetime import datetime
import scanner.dangerous_imports
import scanner.dangerous_api
import scanner.secret_scanner
import scanner.obfuscation_detector
import scanner.behavioral_analyzer
import scanner.correlation_engine  

import scanner.parser as parser
from typing import Dict, Any, Optional, List, Tuple, Union
import argparse

VERSION = "3.0"

def run_stage(name: str, func, *args, **kwargs) -> Any:
    """Run pipeline stage with logging."""
    print(f"[*] {name:<30} ...", end="\n", flush=True)
    try:
        return func(*args, **kwargs)
    except Exception as e:
        raise SystemExit(f"Error in stage '{name}': {e}") from e

def run_scan(
    filepath: str,
    deps_file: Optional[str] = None,
    verbose: bool = False,
    llm_enabled: bool = False
) -> Dict[str, Any]:
    print(f"\n{'=' * 60}")
    print(f"TrustGuard v{VERSION} — Security Analysis")
    print(f"Target: {filepath}")
    if llm_enabled:
        print("LLM Reasoning: Enabled")
    print(f"{'=' * 60}\n")

    start_time = datetime.now()
    print(f"[*] Parsing               {filepath}...", end="\n", flush=True)
    try:
        parser_result = parser.Parser(filepath).parse()

        dangerousAPIAnalyzer = scanner.dangerous_api.DangerousAPIAnalyzer()
        result = [{"file": parser_result.get('file', 'unknown')}]
        result.append(run_stage("Dangerous API scan", dangerousAPIAnalyzer.analyze_parser_result,parser_result))

        dangerousCallsAnalyzer = scanner.dangerous_imports.DangerousImports()
        result.append(run_stage("Dangerous Calls scan", dangerousCallsAnalyzer.analyze_parser_result, parser_result))

        secretScanner = scanner.secret_scanner.SecretScanner()
        result.append(run_stage("Secret scan", secretScanner.analyze_parser_result, parser_result))

        obfuscationDetector = scanner.obfuscation_detector.ObfuscationDetector()
        result.append(run_stage("Obfuscation scan", obfuscationDetector.analyze_parser_result, parser_result))

        behavioralAnalyzer = scanner.behavioral_analyzer.BehaviorMappings()
        result.append(run_stage("Behavioral Analyzer scan", behavioralAnalyzer.analyze_parser_result, parser_result))
        print(result)
        
        correlationEngine = scanner.correlation_engine.CorrelationEngine()
        result.append(run_stage("Correlation Engine", correlationEngine.analyze, result))


        return result
    except RuntimeError as e:
        print(f"[FAIL] {str(e)}")
        raise
    except Exception as e:
        print(f"[FAIL] Unexpected error: {str(e)}")
        raise



def main():
    argument_parser = argparse.ArgumentParser(description="TrustGuard")
    argument_parser.add_argument("file", help="Path to Python file to analyze")
    argument_parser.add_argument("--deps", default=None, help="Path to requirements.txt for dependency scanning")
    argument_parser.add_argument("--json", action="store_true", help="Save results as JSON file")
    argument_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    argument_parser.add_argument("--llm", action="store_true", help="Enable LLM reasoning (Phase 4 - requires Ollama)")
    argument_parser.add_argument("--version", action="version", version=f"TrustGuard v{VERSION}")

    args = argument_parser.parse_args()

    try:
        result = run_scan(
            filepath=args.file,
            deps_file=args.deps,
            verbose=args.verbose,
            llm_enabled=args.llm
        )
        print(json.dumps(result, indent=2))
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

if __name__ == "__main__":
    main()
