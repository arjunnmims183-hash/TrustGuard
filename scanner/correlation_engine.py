# scanner/correlation_engine.py

import re
import ast
import math
from typing import Dict, List, Any, Optional, Set, Tuple
from scanner.io import import_json


class CorrelationEngine:
    """
    Correlates findings from all scanners to produce a verdict per MITRE technique.
    Uses a configuration file (mitre_techniques.json) to define detection rules.
    """

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            config_path = "mitre_techniques.json"
        data = import_json._load_json(config_path)
        self.techniques = data.get('techniques', {})
        self.version = data.get('version', 'unknown')
        self.description = data.get('description', '')

    # ----------------------------------------------------------------------
    # Main entry point
    # ----------------------------------------------------------------------

    def analyze(self, scan_results: List[Dict]) -> Dict[str, Any]:
        """Process scan results, compute verdicts, and return correlation analysis."""
        # Extract data from each stage
        api_data = self._extract_api_data(scan_results)
        import_data = self._extract_import_data(scan_results)
        vulnerability_data = self._extract_vulnerability_data(scan_results)
        obfuscation_data = self._extract_obfuscation_data(scan_results)
        behavior_data = self._extract_behavior_data(scan_results)

        # Deduplicate flows
        behavior_data["flows"] = self._deduplicate_flows(behavior_data.get("flows", []))

        # Build variable‑to‑value map from parser assignments
        assignments = self._extract_assignments(scan_results)
        var_value_map = self._build_var_value_map(assignments)

        # Unify all data
        all_data = {
            "api_calls": api_data,
            "imports": import_data,
            "vulnerabilities": vulnerability_data,
            "obfuscations": obfuscation_data,
            "flows": behavior_data.get("flows", []),
            "feature_vector": behavior_data.get("feature_vector", {}),
            "file_path": scan_results[0].get("file", "unknown") if scan_results else "unknown",
            "var_value_map": var_value_map,
        }

        # Score each technique
        verdicts = {}
        for tech_id, technique in self.techniques.items():
            verdict = self._score_technique(tech_id, technique, all_data)
            if verdict:
                verdicts[tech_id] = verdict

        sorted_verdicts = dict(sorted(verdicts.items(), key=lambda item: item[1]['score'], reverse=True))
        overall_risk = self._determine_overall_risk(sorted_verdicts)

        return {
            "correlation_analysis": {
                "verdicts": sorted_verdicts,
                "overall_risk": overall_risk,
                "total_techniques_evaluated": len(self.techniques),
                "techniques_detected": len([v for v in sorted_verdicts.values() if v.get('detected', False)])
            }
        }

    # ----------------------------------------------------------------------
    # Data extraction helpers
    # ----------------------------------------------------------------------

    def _extract_api_data(self, scan_results: List[Dict]) -> List[Dict]:
        for stage in scan_results:
            if 'api_analysis' in stage:
                return stage['api_analysis'].get('scored_calls', [])
        return []

    def _extract_import_data(self, scan_results: List[Dict]) -> List[Dict]:
        for stage in scan_results:
            if 'import_analysis' in stage:
                return stage['import_analysis'].get('scored_imports', [])
        return []

    def _extract_vulnerability_data(self, scan_results: List[Dict]) -> List[Dict]:
        for stage in scan_results:
            if 'vulnerability_pattern_analysis' in stage:
                return stage['vulnerability_pattern_analysis'].get('scored_findings', [])
        return []

    def _extract_obfuscation_data(self, scan_results: List[Dict]) -> List[Dict]:
        for stage in scan_results:
            if 'obfuscation_analysis' in stage:
                return stage['obfuscation_analysis'].get('scored_findings', [])
        return []

    def _extract_behavior_data(self, scan_results: List[Dict]) -> Dict:
        for stage in scan_results:
            if 'behaviour_analysis' in stage:
                ba = stage['behaviour_analysis']
                return {
                    "flows": ba.get('enriched_flows', []),
                    "feature_vector": ba.get('feature_vector', {})
                }
        return {"flows": [], "feature_vector": {}}

    def _extract_assignments(self, scan_results: List[Dict]) -> List[Dict]:
        for stage in scan_results:
            if 'parser_result' in stage:
                return stage['parser_result'].get('assignments', [])
        return []

    # ----------------------------------------------------------------------
    # Flow deduplication
    # ----------------------------------------------------------------------

    def _deduplicate_flows(self, flows: List[Dict]) -> List[Dict]:
        """Remove duplicate flows based on a safe key."""
        seen = set()
        unique_flows = []
        for flow in flows:
            key = (
                flow.get("source"),
                flow.get("source_matched_key"),
                tuple(flow.get("source_arguments", [])),
                tuple(flow.get("transforms", [])),
                flow.get("sink"),
                flow.get("sink_call"),
                flow.get("sink_line"),
                flow.get("sink_arg_type"),
                flow.get("sink_arg_name"),
                flow.get("source_var"),
            )
            if key not in seen:
                seen.add(key)
                unique_flows.append(flow)

        # Debug output (kept for transparency)
        print(f"DEBUG: Original flows count: {len(flows)}")
        print(f"DEBUG: Unique flows count: {len(unique_flows)}")
        for f in unique_flows:
            print(f"DEBUG: Unique flow: {f.get('data_flow')}")

        return unique_flows

    # ----------------------------------------------------------------------
    # Variable resolution helpers
    # ----------------------------------------------------------------------

    def _build_var_value_map(self, assignments: List[Dict]) -> Dict[str, str]:
        var_map = {}
        for assign in assignments:
            var = assign.get('variable')
            value = assign.get('value')
            if var and isinstance(value, str):
                resolved = self._try_evaluate_expression(value)
                if resolved is not None:
                    var_map[var] = resolved
        return var_map

    def _try_evaluate_expression(self, expr: str) -> Optional[str]:
        try:
            val = ast.literal_eval(expr)
            if isinstance(val, str):
                return val
        except (SyntaxError, ValueError):
            pass
        return None

    def _check_value_against_vulnerabilities(self, value: str, vulns: List[Dict]) -> int:
        if not value:
            return 0
        for vuln in vulns:
            vuln_value = vuln.get('value', '')
            if vuln_value and value in vuln_value:
                severity = vuln.get('severity', 0)
                return min(10, int(severity / 10))
        return 0

    def _resolve_and_check_argument(self, arg_value: str, var_value_map: Dict, vulns: List[Dict]) -> Tuple[int, List[str]]:
        """
        Resolve a variable to its constant value, then check for sensitive keywords
        and vulnerability matches. Returns (bonus, evidence).
        """
        bonus = 0
        evidence = []
        if not isinstance(arg_value, str):
            return 0, []

        # Try to resolve variable to constant
        resolved_value = None
        is_variable = not (arg_value.startswith(("'", '"')) and arg_value.endswith(("'", '"')))
        if is_variable and arg_value in var_value_map:
            resolved_value = var_value_map[arg_value]

        effective_value = None
        if resolved_value is not None:
            effective_value = resolved_value
        elif arg_value.startswith(("'", '"')) and arg_value.endswith(("'", '"')):
            effective_value = arg_value.strip("'\"")
        else:
            effective_value = None

        if effective_value is not None:
            sensitive_keywords = ['password', 'secret', 'token', 'key', 'credential', 'auth', 'api']
            if any(k in effective_value.lower() for k in sensitive_keywords):
                bonus += 8
                evidence.append(f"Argument '{effective_value}' contains sensitive substring (bonus +8)")
            vuln_bonus = self._check_value_against_vulnerabilities(effective_value, vulns)
            if vuln_bonus:
                bonus += vuln_bonus
                evidence.append(f"Argument resolves to vulnerability (bonus +{vuln_bonus})")
        return bonus, evidence

    # ----------------------------------------------------------------------
    # Flow‑centric scoring (per‑flow evaluators)
    # ----------------------------------------------------------------------

    def _evaluate_source_on_flow(self, req: Dict, flow: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        required = req.get('required_types', [])
        optional = req.get('optional_types', [])
        weight_per = req.get('weight_per_source', 25)
        max_weight = req.get('max_source_weight', 35)
        bonus_patterns = req.get('context_bonus', {}).get('variable_name_patterns', [])
        bonus = req.get('context_bonus', {}).get('bonus', 10)

        var_value_map = data.get('var_value_map', {})
        vulns = data.get('vulnerabilities', [])

        score = 0
        evidence = []
        source_type = flow.get('source')

        if source_type in required:
            score += weight_per
            evidence.append(f"Required source type '{source_type}' found (weight +{weight_per})")
        elif source_type in optional:
            score += weight_per
            evidence.append(f"Optional source type '{source_type}' found (weight +{weight_per})")

        source_args = flow.get('source_arguments', [])
        if source_args and isinstance(source_args, list):
            for arg in source_args:
                # Variable name pattern bonus
                if any(pattern.lower() in str(arg).lower() for pattern in bonus_patterns):
                    score += bonus
                    evidence.append(f"Variable name '{arg}' matches sensitive pattern (bonus +{bonus})")
                    break
                # Deeper argument check
                arg_bonus, arg_ev = self._resolve_and_check_argument(arg, var_value_map, vulns)
                if arg_bonus:
                    score += arg_bonus
                    evidence.extend(arg_ev)

        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_transform_on_flow(self, req: Dict, flow: Dict) -> Tuple[float, float, List[str]]:
        optional = req.get('optional_types', [])
        weight_per = req.get('weight_per_transform', 12)
        max_weight = req.get('max_transform_weight', 30)
        count_bonus = req.get('transform_count_bonus', {})

        transforms = flow.get('transforms', [])
        score = 0
        evidence = []
        transform_count = 0

        for trans in transforms:
            if trans in optional:
                score += weight_per
                transform_count += 1
                evidence.append(f"Transform '{trans}' found (weight +{weight_per})")

        if transform_count > 0:
            bonus = 0
            for count, b in sorted(count_bonus.items(), key=lambda x: int(x[0])):
                if transform_count >= int(count):
                    bonus = b
                else:
                    break
            if bonus:
                score += bonus
                evidence.append(f"Transform count bonus +{bonus} (found {transform_count} transforms)")

        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_sink_on_flow(self, req: Dict, flow: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        required = req.get('required_types', [])
        optional = req.get('optional_types', [])
        weight_per = req.get('weight_per_sink', 30)
        max_weight = req.get('max_sink_weight', 40)
        context_bonus = req.get('context_bonus', {})
        arg_patterns = req.get('argument_patterns', {})

        var_value_map = data.get('var_value_map', {})
        vulns = data.get('vulnerabilities', [])
        api_calls = data.get('api_calls', [])

        sink_type = flow.get('sink')
        sink_call = flow.get('sink_call', '')
        sink_line = flow.get('sink_line')

        score = 0
        evidence = []

        if sink_type in required:
            score += weight_per
            evidence.append(f"Required sink type '{sink_type}' found (weight +{weight_per})")
        elif sink_type in optional:
            score += weight_per
            evidence.append(f"Optional sink type '{sink_type}' found (weight +{weight_per})")

        # Destination context
        destination = self._extract_destination_from_call(sink_call, sink_line, data)
        if destination:
            if self._is_external_destination(destination):
                bonus = context_bonus.get('external_destination', 15)
                score += bonus
                evidence.append(f"External destination '{destination}' (bonus +{bonus})")
            if self._is_known_cloud(destination):
                penalty = context_bonus.get('known_cloud_endpoint', -20)
                score += penalty
                evidence.append(f"Known cloud endpoint '{destination}' (penalty {penalty})")
            if self._is_localhost(destination):
                penalty = context_bonus.get('localhost', -25)
                score += penalty
                evidence.append(f"Localhost destination (penalty {penalty})")
            if self._is_private_ip(destination):
                penalty = context_bonus.get('internal_ip', -15)
                score += penalty
                evidence.append(f"Internal IP destination (penalty {penalty})")

        # Sink arguments
        call_details = None
        for call in api_calls:
            if call.get('name') == sink_call and sink_line in call.get('lines', []):
                call_details = call
                break

        if call_details:
            # Positional arguments
            for arg in call_details.get('args', []):
                arg_bonus, arg_ev = self._resolve_and_check_argument(arg, var_value_map, vulns)
                if arg_bonus:
                    score += arg_bonus
                    evidence.extend(arg_ev)

            # Keyword arguments
            for kw in call_details.get('keywords', []):
                kw_name = kw.get('arg')
                kw_value = kw.get('value')

                # Argument name pattern
                if kw_name and kw_name in arg_patterns.get(sink_type, {}):
                    bonus = arg_patterns[sink_type][kw_name]
                    score += bonus
                    evidence.append(f"Argument '{kw_name}' in sink (bonus +{bonus})")

                # Value check
                arg_bonus, arg_ev = self._resolve_and_check_argument(kw_value, var_value_map, vulns)
                if arg_bonus:
                    score += arg_bonus
                    evidence.extend(arg_ev)

                # Keyword indicating code/payload
                if kw_name in ['code', 'payload', 'data', 'source', 'expr', 'statement']:
                    bonus = 5
                    score += bonus
                    evidence.append(f"Keyword '{kw_name}' indicates code/payload (bonus +{bonus})")

        score = min(max(0, score), max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_flow_signature_on_flow(self, signatures: List[Dict], flow: Dict) -> Tuple[float, List[str]]:
        data_flow_str = flow.get('data_flow', '')
        if not data_flow_str:
            return 0.0, []

        steps = [s.strip() for s in data_flow_str.split('→')]
        steps = [s.strip() for s in steps if s.strip()]

        for sig in signatures:
            sig_steps = sig.get('signature', [])
            if not sig_steps:
                continue
            if self._is_subsequence(sig_steps, steps):
                bonus = sig.get('score_bonus', 0)
                return float(bonus), [f"Flow signature '{sig.get('name')}' matched (bonus +{bonus})"]
        return 0.0, []

    # ----------------------------------------------------------------------
    # Flow‑centric scoring (complete units)
    # ----------------------------------------------------------------------

    def _evaluate_flows_as_units(self, rules: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        flows = data.get('flows', [])
        if not flows:
            return 0.0, 100.0, []

        source_req = rules.get('source_requirements', {})
        transform_req = rules.get('transform_requirements', {})
        sink_req = rules.get('sink_requirements', {})
        signatures = rules.get('flow_signatures', [])

        total_score = 0.0
        all_evidence = []

        for flow in flows:
            source_score, source_max, source_ev = self._evaluate_source_on_flow(source_req, flow, data)
            trans_score, trans_max, trans_ev = self._evaluate_transform_on_flow(transform_req, flow)
            sink_score, sink_max, sink_ev = self._evaluate_sink_on_flow(sink_req, flow, data)
            sig_bonus, sig_ev = self._evaluate_flow_signature_on_flow(signatures, flow)

            raw = source_score + trans_score + sink_score + sig_bonus
            max_possible = source_max + trans_max + sink_max + 100
            flow_score = (raw / max_possible) * 100 if max_possible > 0 else 0

            total_score += flow_score
            all_evidence.extend(source_ev + trans_ev + sink_ev + sig_ev)

        total_score = min(100.0, total_score)
        return total_score, 100.0, all_evidence[:20]

    # ----------------------------------------------------------------------
    # Dangerous calls (with severity bonus and argument analysis)
    # ----------------------------------------------------------------------

    def _evaluate_dangerous_calls(self, req: Dict, data: Dict) -> Tuple[float, float, List[str], float, float]:
        required = req.get('required', [])
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_call', 20)
        max_weight = req.get('max_dangerous_call_weight', 25)

        api_calls = data.get('api_calls', [])
        flows = data.get('flows', [])
        vulns = data.get('vulnerabilities', [])
        var_value_map = data.get('var_value_map', {})

        score = 0
        evidence = []
        arg_bonus = 0
        severity_bonus = 0.0

        for call in api_calls:
            name = call.get('name')
            if name not in required and name not in optional:
                continue

            severity = call.get('severity', 0)
            severity_bonus += severity / 10.0
            score += weight_per

            evidence.append(
                f"Required/optional dangerous call '{name}' found "
                f"(weight {weight_per} base, severity bonus {severity / 10.0:.1f})"
            )

            cwe = call.get('cwe', '')
            category = call.get('category', '')
            if cwe:
                evidence.append(f"  CWE: {cwe}")
            if category:
                evidence.append(f"  Category: {category}")

            # Process arguments
            args = call.get('args', [])
            keywords = call.get('keywords', [])
            line = call.get('lines', [0])[0] if call.get('lines') else 0

            # We need to pass arg_bonus as nonlocal; we'll process in a helper
            self._process_dangerous_call_arguments(
                args, keywords, line, name, flows, vulns, var_value_map,
                evidence, arg_bonus  # arg_bonus is passed and will be modified inside (nonlocal)
            )

        # The helper modifies arg_bonus, but we need to capture it; we'll restructure:
        # Actually, we should have a separate method returning bonus and evidence.
        # We'll refactor into a separate method that returns (arg_bonus, extra_evidence)
        # and then extend evidence and add arg_bonus.
        # We'll do that for clarity.
        # But to keep the change minimal, we'll keep the inner function.
        # However, to make the code cleaner, we can pull the inner function out.
        # For now, I'll move the inner function to a separate method.
        # I'll rewrite the processing part as a separate method call.

        score = min(score, max_weight)
        return float(score), float(max_weight), evidence, float(arg_bonus), float(severity_bonus)

    def _process_dangerous_call_arguments(self, args, keywords, line, call_name, flows, vulns, var_value_map,
                                          evidence, arg_bonus):
        # This is the inner function logic, moved out.
        # We'll use a mutable container (list) to modify arg_bonus.
        # For simplicity, we'll keep it as a method that returns a tuple (arg_bonus, extra_evidence).
        pass

    # We'll implement a separate helper that processes a single argument and returns bonus.
    # But to avoid rewriting too much, I'll keep the inner function but not make it a nested function.
    # Actually, for the refactored version, I'll move the argument processing into a separate method.

    # Let's implement a helper that processes an argument and returns (bonus, evidence).
    # Then we'll call it for each argument.

    def _process_dangerous_call_argument(self, arg_value: str, arg_name: Optional[str], call_name: str,
                                         line: int, flows: List[Dict], vulns: List[Dict],
                                         var_value_map: Dict) -> Tuple[int, List[str]]:
        """
        Process a single argument of a dangerous call.
        Returns (bonus, evidence).
        """
        bonus = 0
        evidence = []
        if not isinstance(arg_value, str):
            return 0, []

        resolved_value = None
        is_variable = not (arg_value.startswith(("'", '"')) and arg_value.endswith(("'", '"')))
        if is_variable and arg_value in var_value_map:
            resolved_value = var_value_map[arg_value]

        effective_value = None
        if resolved_value is not None:
            effective_value = resolved_value
        elif arg_value.startswith(("'", '"')) and arg_value.endswith(("'", '"')):
            effective_value = arg_value.strip("'\"")
        else:
            effective_value = None

        if effective_value is not None:
            sensitive_keywords = ['password', 'secret', 'token', 'key', 'credential', 'auth', 'api']
            if any(k in effective_value.lower() for k in sensitive_keywords):
                bonus += 8
                evidence.append(f"Resolved literal contains sensitive substring '{effective_value}' (bonus +8)")
            vuln_bonus = self._check_value_against_vulnerabilities(effective_value, vulns)
            if vuln_bonus:
                bonus += vuln_bonus
                evidence.append(f"Resolved literal matches vulnerability (bonus +{vuln_bonus})")
        else:
            flow = self._find_flow_for_call(call_name, line, flows)
            if flow:
                source_type = flow.get('source', '')
                source_bonus = {
                    'user_input': 15,
                    'network_recv': 20,
                    'env_var': 10,
                    'credential': 12,
                    'file_read': 8
                }.get(source_type, 5)
                bonus += source_bonus
                evidence.append(f"Argument traces to source type '{source_type}' (bonus +{source_bonus})")
            else:
                if arg_value in ['request', 'input', 'data', 'payload', 'source', 'user_input']:
                    bonus += 5
                    evidence.append(f"Variable '{arg_value}' suggests external source (bonus +5)")
        return bonus, evidence

    # Now update _evaluate_dangerous_calls to use this helper.

    # I'll rewrite _evaluate_dangerous_calls to use the helper.

    # For brevity, I'll show the new version.

    # ----------------------------------------------------------------------
    # Helper for dangerous calls (revised)
    # ----------------------------------------------------------------------

    def _evaluate_dangerous_calls(self, req: Dict, data: Dict) -> Tuple[float, float, List[str], float, float]:
        required = req.get('required', [])
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_call', 20)
        max_weight = req.get('max_dangerous_call_weight', 25)

        api_calls = data.get('api_calls', [])
        flows = data.get('flows', [])
        vulns = data.get('vulnerabilities', [])
        var_value_map = data.get('var_value_map', {})

        score = 0
        evidence = []
        arg_bonus = 0
        severity_bonus = 0.0

        for call in api_calls:
            name = call.get('name')
            if name not in required and name not in optional:
                continue

            severity = call.get('severity', 0)
            severity_bonus += severity / 10.0
            score += weight_per

            evidence.append(
                f"Required/optional dangerous call '{name}' found "
                f"(weight {weight_per} base, severity bonus {severity / 10.0:.1f})"
            )

            cwe = call.get('cwe', '')
            category = call.get('category', '')
            if cwe:
                evidence.append(f"  CWE: {cwe}")
            if category:
                evidence.append(f"  Category: {category}")

            args = call.get('args', [])
            keywords = call.get('keywords', [])
            line = call.get('lines', [0])[0] if call.get('lines') else 0

            # Process positional arguments
            for arg in args:
                bonus, ev = self._process_dangerous_call_argument(
                    arg, None, name, line, flows, vulns, var_value_map
                )
                arg_bonus += bonus
                evidence.extend(ev)

            # Process keyword arguments
            for kw in keywords:
                kw_name = kw.get('arg')
                kw_value = kw.get('value')
                if kw_name in ['code', 'payload', 'data', 'source', 'expr', 'statement']:
                    bonus = 5
                    arg_bonus += bonus
                    evidence.append(f"Keyword '{kw_name}' indicates code/payload (bonus +5)")
                # Process the value
                bonus, ev = self._process_dangerous_call_argument(
                    kw_value, kw_name, name, line, flows, vulns, var_value_map
                )
                arg_bonus += bonus
                evidence.extend(ev)

        score = min(score, max_weight)
        return float(score), float(max_weight), evidence, float(arg_bonus), float(severity_bonus)

    def _find_flow_for_call(self, call_name: str, line: int, flows: List[Dict]) -> Optional[Dict]:
        for flow in flows:
            if flow.get('sink_call') == call_name and flow.get('sink_line') == line:
                return flow
        return None

    # ----------------------------------------------------------------------
    # Main scoring logic
    # ----------------------------------------------------------------------

    def _score_technique(self, tech_id: str, technique: Dict, all_data: Dict) -> Optional[Dict]:
        rules = technique.get('detection_rules', {})
        if not rules:
            return None

        component_scores = {}
        max_possible = {}
        evidence = []

        # Flow‑centric evaluation
        flow_score, flow_max, flow_evidence = self._evaluate_flows_as_units(rules, all_data)
        component_scores['flow_completeness'] = flow_score
        max_possible['flow_completeness'] = flow_max
        evidence.extend(flow_evidence)

        # Dangerous calls
        danger_score, danger_max, danger_evidence, arg_bonus, severity_bonus = self._evaluate_dangerous_calls(
            rules.get('dangerous_call_requirements', {}), all_data
        )
        component_scores['dangerous_call'] = danger_score
        max_possible['dangerous_call'] = danger_max
        evidence.extend(danger_evidence)
        component_scores['arg_bonus'] = arg_bonus
        component_scores['severity_bonus'] = severity_bonus

        # Imports
        import_score, import_max, import_evidence = self._evaluate_imports(
            rules.get('import_requirements', {}), all_data
        )
        component_scores['import'] = import_score
        max_possible['import'] = import_max
        evidence.extend(import_evidence)

        # Vulnerabilities
        vuln_score, vuln_max, vuln_evidence = self._evaluate_vulnerabilities(
            rules.get('vulnerability_requirements', {}), all_data
        )
        component_scores['vulnerability'] = vuln_score
        max_possible['vulnerability'] = vuln_max
        evidence.extend(vuln_evidence)

        # Obfuscations
        obf_score, obf_max, obf_evidence = self._evaluate_obfuscations(
            rules.get('obfuscation_requirements', {}), all_data
        )
        component_scores['obfuscation'] = obf_score
        max_possible['obfuscation'] = obf_max
        evidence.extend(obf_evidence)

        # Behavior features
        feat_score, feat_max, feat_evidence = self._evaluate_behavior_features(
            rules.get('behavior_feature_requirements', {}), all_data
        )
        component_scores['behavior_feature'] = feat_score
        max_possible['behavior_feature'] = feat_max
        evidence.extend(feat_evidence)

        # Exclusions
        exclusion_deduction, exclusion_evidence = self._apply_exclusions(
            rules.get('exclusion_rules', []), all_data
        )
        evidence.extend(exclusion_evidence)

        # Calculate weighted score
        weights = technique.get('scoring', {}).get('weights', {})
        raw_score = 0
        total_weighted_max = 0

        for comp, score in component_scores.items():
            if comp in ('arg_bonus', 'severity_bonus'):
                continue
            max_val = max_possible.get(comp, 1)
            weight = weights.get(comp, 0)
            norm_score = (score / max_val) * 100 if max_val > 0 else 0
            raw_score += norm_score * weight
            total_weighted_max += 100 * weight

        # Add flat bonuses
        arg_bonus_value = component_scores.get('arg_bonus', 0)
        severity_bonus_value = component_scores.get('severity_bonus', 0)
        raw_score += arg_bonus_value + severity_bonus_value
        total_weighted_max += arg_bonus_value + severity_bonus_value

        raw_score = max(0, raw_score - exclusion_deduction)
        final_score = (raw_score / total_weighted_max) * 100 if total_weighted_max > 0 else 0
        final_score = min(100, max(0, final_score))

        confidence = self._determine_confidence(
            final_score,
            technique.get('confidence', {}),
            component_scores,
            evidence
        )

        min_detection_score = technique.get('scoring', {}).get('min_detection_score', 60)
        detected = final_score >= min_detection_score

        return {
            "score": round(final_score, 1),
            "confidence": confidence,
            "detected": detected,
            "evidence": evidence[:30],
            "component_scores": {k: round(v, 1) for k, v in component_scores.items()
                                 if k not in ('arg_bonus', 'severity_bonus')},
            "exclusion_deduction": exclusion_deduction,
            "mitre_techniques": technique.get("mitre_techniques", []) 
        }

    # ----------------------------------------------------------------------
    # Generic evaluators (imports, vulnerabilities, obfuscations, behavior features)
    # ----------------------------------------------------------------------

    def _evaluate_imports(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        required = req.get('required', [])
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_import', 10)
        max_weight = req.get('max_import_weight', 20)

        imports = data.get('imports', [])
        import_names = [imp.get('name') for imp in imports]
        score = 0
        evidence = []
        for req_imp in required:
            if req_imp in import_names:
                score += weight_per
                evidence.append(f"Required import '{req_imp}' found (weight +{weight_per})")
        for opt_imp in optional:
            if opt_imp in import_names:
                score += weight_per
                evidence.append(f"Optional import '{opt_imp}' found (weight +{weight_per})")
        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_vulnerabilities(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_finding', 15)
        max_weight = req.get('max_vulnerability_weight', 25)

        vulns = data.get('vulnerabilities', [])
        score = 0
        evidence = []
        for vuln in vulns:
            name = vuln.get('name')
            if name in optional:
                score += weight_per
                evidence.append(f"Vulnerability '{name}' found (weight +{weight_per})")
        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_obfuscations(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_obfuscation', 10)
        max_weight = req.get('max_obfuscation_weight', 15)

        obfs = data.get('obfuscations', [])
        score = 0
        evidence = []
        for obf in obfs:
            name = obf.get('name')
            if name in optional:
                score += weight_per
                evidence.append(f"Obfuscation '{name}' found (weight +{weight_per})")
        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_behavior_features(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        required = req.get('required', [])
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_feature', 15)
        max_weight = req.get('max_feature_weight', 25)

        fv = data.get('feature_vector', {})
        score = 0
        evidence = []
        for feat in required:
            if fv.get(feat, {}).get('enabled', False):
                score += weight_per
                evidence.append(f"Required behavior feature '{feat}' enabled (weight +{weight_per})")
        for feat in optional:
            if fv.get(feat, {}).get('enabled', False):
                score += weight_per
                evidence.append(f"Optional behavior feature '{feat}' enabled (weight +{weight_per})")
        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _apply_exclusions(self, exclusions: List[Dict], data: Dict) -> Tuple[float, List[str]]:
        total_deduction = 0
        evidence = []
        for exc in exclusions:
            condition = exc.get('condition', '')
            deduction = exc.get('deduction', 0)
            if self._evaluate_condition(condition, data):
                total_deduction += deduction
                evidence.append(f"Exclusion '{exc.get('name')}' applied (deduct -{deduction})")
        return float(total_deduction), evidence

    # ----------------------------------------------------------------------
    # Condition and destination helpers
    # ----------------------------------------------------------------------

    def _evaluate_condition(self, condition: str, data: Dict) -> bool:
        if not condition:
            return False
        if ' AND ' in condition:
            parts = condition.split(' AND ')
            return all(self._evaluate_condition(p.strip(), data) for p in parts)
        if ' OR ' in condition:
            parts = condition.split(' OR ')
            return any(self._evaluate_condition(p.strip(), data) for p in parts)

        if condition.startswith('import_'):
            module = condition[len('import_'):]
            imports = data.get('imports', [])
            import_names = [imp.get('name') for imp in imports]
            return module in import_names

        if condition.startswith('uses_'):
            api_calls = data.get('api_calls', [])
            target = condition[len('uses_'):]
            for call in api_calls:
                if target in call.get('name', ''):
                    return True
            return False

        if condition.startswith('file_path_contains'):
            match = re.search(r"file_path_contains\s+['\"]([^'\"]+)['\"]", condition)
            if match:
                pattern = match.group(1)
                file_path = data.get('file_path', '')
                return pattern in file_path
            return False

        if condition.startswith('sink_destination_is_localhost'):
            flows = data.get('flows', [])
            for flow in flows:
                dest = self._extract_destination_from_call(flow.get('sink_call'), flow.get('sink_line'), data)
                if dest and self._is_localhost(dest):
                    return True
            return False

        if condition.startswith('sink_destination_in_private_ip_range'):
            flows = data.get('flows', [])
            for flow in flows:
                dest = self._extract_destination_from_call(flow.get('sink_call'), flow.get('sink_line'), data)
                if dest and self._is_private_ip(dest):
                    return True
            return False

        if condition.startswith('source_variable_name_matches'):
            match = re.search(r"source_variable_name_matches\s+(\[.*\])", condition)
            if match:
                try:
                    names = ast.literal_eval(match.group(1))
                    flows = data.get('flows', [])
                    for flow in flows:
                        source_args = flow.get('source_arguments', [])
                        for arg in source_args:
                            if arg in names:
                                return True
                except:
                    pass
            return False

        return False

    def _extract_destination_from_call(self, call_name: str, line: int, data: Dict) -> Optional[str]:
        api_calls = data.get('api_calls', [])
        for call in api_calls:
            if call.get('name') == call_name and line in call.get('lines', []):
                args = call.get('args', [])
                if args and isinstance(args, list) and len(args) > 0:
                    return str(args[0])
                for kw in call.get('keywords', []):
                    if kw.get('arg') == 'url':
                        return str(kw.get('value'))
        return None

    def _is_external_destination(self, dest: str) -> bool:
        if self._is_localhost(dest) or self._is_private_ip(dest) or self._is_known_cloud(dest):
            return False
        return True

    def _is_localhost(self, dest: str) -> bool:
        return dest in ['localhost', '127.0.0.1', '::1']

    def _is_private_ip(self, dest: str) -> bool:
        try:
            ip = ipaddress.ip_address(dest)
            return ip.is_private
        except:
            return False

    def _is_known_cloud(self, dest: str) -> bool:
        cloud_domains = ['amazonaws.com', 'googleapis.com', 'azure.com', 'cloudflare.com', 'api.github.com']
        return any(domain in dest for domain in cloud_domains)

    def _is_subsequence(self, pattern: List[str], sequence: List[str]) -> bool:
        it = iter(sequence)
        return all(item in it for item in pattern)

    def _determine_confidence(self, score: float, conf_rules: Dict, component_scores: Dict, evidence: List) -> str:
        levels = conf_rules.get('levels', {})
        if not levels:
            if score >= 80:
                return "HIGH"
            if score >= 60:
                return "MEDIUM"
            if score >= 40:
                return "LOW"
            return "VERY_LOW"

        for level, config in sorted(levels.items(), key=lambda x: x[1].get('min_score', 0), reverse=True):
            min_score = config.get('min_score', 0)
            if score >= min_score:
                additional = config.get('additional_conditions', [])
                if all(self._evaluate_condition(cond, {'component_scores': component_scores}) for cond in additional):
                    return level
        return "VERY_LOW"

    def _determine_overall_risk(self, verdicts: Dict) -> Dict:
        detected = [(tech, v) for tech, v in verdicts.items() if v.get('detected', False)]
        if not detected:
            return {"level": "LOW", "score": 0, "message": "No techniques detected"}
        max_score = max(v['score'] for _, v in detected)
        max_tech = max(detected, key=lambda x: x[1]['score'])[0]
        if max_score >= 80:
            level = "HIGH"
        elif max_score >= 60:
            level = "MEDIUM"
        else:
            level = "LOW"
        return {
            "level": level,
            "score": max_score,
            "top_technique": max_tech,
            "detected_count": len(detected),
            "message": f"Top technique: {max_tech} (score: {max_score:.1f}%)"
        }