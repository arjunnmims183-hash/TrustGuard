# scanner/correlation_engine.py

import re, ast
import math
import json
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

        # Pre-compile regex patterns if needed (e.g., for variable name matching)
        # We'll handle simple string containment for now.

    def analyze(self, scan_results: List[Dict]) -> Dict[str, Any]:
        """
        Main entry point: processes scan results and returns correlation verdict.

        Args:
            scan_results: The list of dicts from the full scan (as printed in the sample).

        Returns:
            dict with keys:
                - "correlation_analysis": {
                    "verdicts": { technique_id: { "score", "confidence", "matched_rules", ... } },
                    "overall_risk": { ... }
                  }
        """
        # Extract data from each stage
        api_data = self._extract_api_data(scan_results)
        import_data = self._extract_import_data(scan_results)
        vulnerability_data = self._extract_vulnerability_data(scan_results)
        obfuscation_data = self._extract_obfuscation_data(scan_results)
        behavior_data = self._extract_behavior_data(scan_results)

        # Prepare all data in a unified dictionary
        all_data = {
            "api_calls": api_data,
            "imports": import_data,
            "vulnerabilities": vulnerability_data,
            "obfuscations": obfuscation_data,
            "flows": behavior_data.get("flows", []),
            "feature_vector": behavior_data.get("feature_vector", {}),
            "file_path": scan_results[0].get("file", "unknown") if scan_results else "unknown",
        }

        verdicts = {}
        for tech_id, technique in self.techniques.items():
            verdict = self._score_technique(tech_id, technique, all_data)
            if verdict:
                verdicts[tech_id] = verdict

        # Sort by score descending
        sorted_verdicts = dict(sorted(verdicts.items(), key=lambda item: item[1]['score'], reverse=True))

        # Determine overall risk
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
    # Extraction helpers
    # ----------------------------------------------------------------------

    def _extract_api_data(self, scan_results: List[Dict]) -> List[Dict]:
        """Extract scored API calls from api_analysis."""
        for stage in scan_results:
            if 'api_analysis' in stage:
                return stage['api_analysis'].get('scored_calls', [])
        return []

    def _extract_import_data(self, scan_results: List[Dict]) -> List[Dict]:
        """Extract scored imports from import_analysis."""
        for stage in scan_results:
            if 'import_analysis' in stage:
                return stage['import_analysis'].get('scored_imports', [])
        return []

    def _extract_vulnerability_data(self, scan_results: List[Dict]) -> List[Dict]:
        """Extract scored findings from vulnerability_pattern_analysis."""
        for stage in scan_results:
            if 'vulnerability_pattern_analysis' in stage:
                return stage['vulnerability_pattern_analysis'].get('scored_findings', [])
        return []

    def _extract_obfuscation_data(self, scan_results: List[Dict]) -> List[Dict]:
        """Extract scored findings from obfuscation_analysis."""
        for stage in scan_results:
            if 'obfuscation_analysis' in stage:
                return stage['obfuscation_analysis'].get('scored_findings', [])
        return []

    def _extract_behavior_data(self, scan_results: List[Dict]) -> Dict:
        """Extract flows and feature vector from behaviour_analysis."""
        for stage in scan_results:
            if 'behaviour_analysis' in stage:
                ba = stage['behaviour_analysis']
                return {
                    "flows": ba.get('enriched_flows', []),
                    "feature_vector": ba.get('feature_vector', {})
                }
        return {"flows": [], "feature_vector": {}}

    # ----------------------------------------------------------------------
    # Scoring logic
    # ----------------------------------------------------------------------

    def _score_technique(self, tech_id: str, technique: Dict, all_data: Dict) -> Optional[Dict]:
        """
        Evaluate one technique against the extracted data and produce a verdict.
        Returns dict with score, confidence, detected, evidence, etc.
        """
        rules = technique.get('detection_rules', {})
        if not rules:
            return None

        # Component scores
        component_scores = {}
        max_possible = {}
        evidence = []

        # 1. Source evaluation
        source_score, source_max, source_evidence = self._evaluate_source(rules.get('source_requirements', {}), all_data)
        component_scores['source'] = source_score
        max_possible['source'] = source_max
        evidence.extend(source_evidence)

        # 2. Transform evaluation
        trans_score, trans_max, trans_evidence = self._evaluate_transform(rules.get('transform_requirements', {}), all_data)
        component_scores['transform'] = trans_score
        max_possible['transform'] = trans_max
        evidence.extend(trans_evidence)

        # 3. Sink evaluation
        sink_score, sink_max, sink_evidence = self._evaluate_sink(rules.get('sink_requirements', {}), all_data)
        component_scores['sink'] = sink_score
        max_possible['sink'] = sink_max
        evidence.extend(sink_evidence)

        # 4. Flow signatures (bonus)
        flow_bonus, flow_evidence = self._evaluate_flow_signatures(rules.get('flow_signatures', []), all_data)
        component_scores['flow_bonus'] = flow_bonus
        max_possible['flow_bonus'] = 100  # Flow bonus is a flat addition, not a max; we'll handle later
        evidence.extend(flow_evidence)

        # 5. Dangerous calls
        danger_score, danger_max, danger_evidence = self._evaluate_dangerous_calls(rules.get('dangerous_call_requirements', {}), all_data)
        component_scores['dangerous_call'] = danger_score
        max_possible['dangerous_call'] = danger_max
        evidence.extend(danger_evidence)

        # 6. Imports
        import_score, import_max, import_evidence = self._evaluate_imports(rules.get('import_requirements', {}), all_data)
        component_scores['import'] = import_score
        max_possible['import'] = import_max
        evidence.extend(import_evidence)

        # 7. Vulnerabilities
        vuln_score, vuln_max, vuln_evidence = self._evaluate_vulnerabilities(rules.get('vulnerability_requirements', {}), all_data)
        component_scores['vulnerability'] = vuln_score
        max_possible['vulnerability'] = vuln_max
        evidence.extend(vuln_evidence)

        # 8. Obfuscations
        obf_score, obf_max, obf_evidence = self._evaluate_obfuscations(rules.get('obfuscation_requirements', {}), all_data)
        component_scores['obfuscation'] = obf_score
        max_possible['obfuscation'] = obf_max
        evidence.extend(obf_evidence)

        # 9. Behavior features
        feat_score, feat_max, feat_evidence = self._evaluate_behavior_features(rules.get('behavior_feature_requirements', {}), all_data)
        component_scores['behavior_feature'] = feat_score
        max_possible['behavior_feature'] = feat_max
        evidence.extend(feat_evidence)

        # 10. Apply exclusions
        exclusion_deduction, exclusion_evidence = self._apply_exclusions(rules.get('exclusion_rules', []), all_data)
        evidence.extend(exclusion_evidence)

        # 11. Calculate weighted score
        weights = technique.get('scoring', {}).get('weights', {})
        # Normalize: each component score is a value between 0 and its max.
        # We'll compute a raw weighted sum and then divide by the sum of (weight * max_possible) to get a percentage.
        raw_score = 0
        total_weighted_max = 0
        for comp, score in component_scores.items():
            max_val = max_possible.get(comp, 1)
            weight = weights.get(comp, 0)
            # For flow_bonus, we treat it as an addition, not a percentage; we add it raw.
            if comp == 'flow_bonus':
                raw_score += score * weight  # flow bonus is already a score, not a percentage?
                # Actually flow bonus should be a bonus added to the total, not weighted.
                # We'll handle flow_bonus separately below.
                continue
            # Normalize component score to 0-100
            norm_score = (score / max_val) * 100 if max_val > 0 else 0
            raw_score += norm_score * weight
            total_weighted_max += 100 * weight  # since each component max is 100 after normalization

        # Add flow_bonus as a flat bonus
        flow_bonus_value = component_scores.get('flow_bonus', 0)
        raw_score += flow_bonus_value
        total_weighted_max += flow_bonus_value  # to not reduce it, we add the same to max

        # Apply exclusions (subtract from raw score)
        raw_score = max(0, raw_score - exclusion_deduction)

        # Normalize to 0-100
        final_score = (raw_score / total_weighted_max) * 100 if total_weighted_max > 0 else 0
        final_score = min(100, max(0, final_score))

        # Determine confidence
        confidence_rules = technique.get('confidence', {})
        confidence = self._determine_confidence(final_score, confidence_rules, component_scores, evidence)

        # Detect if threshold met
        min_detection_score = technique.get('scoring', {}).get('min_detection_score', 60)
        detected = final_score >= min_detection_score

        # Build verdict
        return {
            "score": round(final_score, 1),
            "confidence": confidence,
            "detected": detected,
            "evidence": evidence[:10],  # limit to top 10
            "component_scores": {k: round(v, 1) for k, v in component_scores.items()},
            "exclusion_deduction": exclusion_deduction
        }

    # ----------------------------------------------------------------------
    # Component evaluators
    # ----------------------------------------------------------------------

    def _evaluate_source(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        """Evaluate source requirements using flows."""
        required = req.get('required_types', [])
        optional = req.get('optional_types', [])
        weight_per = req.get('weight_per_source', 25)
        max_weight = req.get('max_source_weight', 35)
        context_bonus = req.get('context_bonus', {})
        bonus_patterns = context_bonus.get('variable_name_patterns', [])
        bonus = context_bonus.get('bonus', 10)

        flows = data.get('flows', [])
        score = 0
        evidence = []
        matched_sources = set()

        for flow in flows:
            source_type = flow.get('source')
            if not source_type:
                continue

            # Check if source_type is required or optional
            if source_type in required:
                # Required: must have at least one; we add full weight
                score += weight_per
                matched_sources.add(source_type)
                evidence.append(f"Required source type '{source_type}' found (weight +{weight_per})")
            elif source_type in optional:
                score += weight_per
                matched_sources.add(source_type)
                evidence.append(f"Optional source type '{source_type}' found (weight +{weight_per})")

        # Apply variable name context bonus
        # Look at source_arguments for each flow
        for flow in flows:
            source_args = flow.get('source_arguments', [])
            if source_args and isinstance(source_args, list):
                for arg in source_args:
                    if any(pattern.lower() in str(arg).lower() for pattern in bonus_patterns):
                        score += bonus
                        evidence.append(f"Variable name '{arg}' matches sensitive pattern (bonus +{bonus})")
                        break  # only once per flow

        # Cap score
        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_transform(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        """Evaluate transform requirements from flows."""
        optional = req.get('optional_types', [])
        weight_per = req.get('weight_per_transform', 12)
        max_weight = req.get('max_transform_weight', 30)
        count_bonus = req.get('transform_count_bonus', {})

        flows = data.get('flows', [])
        score = 0
        evidence = []
        transform_count = 0

        for flow in flows:
            transforms = flow.get('transforms', [])
            for trans in transforms:
                if trans in optional:
                    score += weight_per
                    transform_count += 1
                    evidence.append(f"Transform '{trans}' found (weight +{weight_per})")

        # Apply count bonus
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

    def _evaluate_sink(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        """Evaluate sink requirements from flows."""
        required = req.get('required_types', [])
        optional = req.get('optional_types', [])
        weight_per = req.get('weight_per_sink', 30)
        max_weight = req.get('max_sink_weight', 40)
        context_bonus = req.get('context_bonus', {})
        arg_patterns = req.get('argument_patterns', {})

        flows = data.get('flows', [])
        score = 0
        evidence = []
        matched_sinks = set()

        for flow in flows:
            sink_type = flow.get('sink')
            sink_call = flow.get('sink_call', '')
            sink_args = flow.get('sink_arguments', [])  # might not exist; we have sink_call args from API
            if not sink_type:
                continue

            # Check required/optional
            if sink_type in required:
                score += weight_per
                matched_sinks.add(sink_type)
                evidence.append(f"Required sink type '{sink_type}' found (weight +{weight_per})")
            elif sink_type in optional:
                score += weight_per
                matched_sinks.add(sink_type)
                evidence.append(f"Optional sink type '{sink_type}' found (weight +{weight_per})")

            # Context bonus: external destination, etc.
            # We need to extract destination from sink_call args.
            # The sink_call is in flow, but sink_arguments may be in api_analysis.
            # We'll look at api calls for the same line/name.
            # We'll extract destination by scanning api_calls data (already available).
            destination = self._extract_destination_from_call(sink_call, flow.get('sink_line'), data)
            if destination:
                # Check external vs internal
                if self._is_external_destination(destination):
                    bonus = context_bonus.get('external_destination', 15)
                    score += bonus
                    evidence.append(f"External destination '{destination}' (bonus +{bonus})")
                if self._is_known_cloud(destination):
                    penalty = context_bonus.get('known_cloud_endpoint', -20)
                    score += penalty  # negative
                    evidence.append(f"Known cloud endpoint '{destination}' (penalty {penalty})")
                if self._is_localhost(destination):
                    penalty = context_bonus.get('localhost', -25)
                    score += penalty
                    evidence.append(f"Localhost destination (penalty {penalty})")
                if self._is_private_ip(destination):
                    penalty = context_bonus.get('internal_ip', -15)
                    score += penalty
                    evidence.append(f"Internal IP destination (penalty {penalty})")

            # Argument patterns: e.g., 'data', 'json', 'files'
            # We can get keywords from api_analysis for the specific call.
            # For simplicity, we'll search api_calls by name and line.
            api_calls = data.get('api_calls', [])
            for call in api_calls:
                if call.get('name') == sink_call and call.get('lines') and flow.get('sink_line') in call.get('lines', []):
                    keywords = call.get('keywords', [])
                    for kw in keywords:
                        arg_name = kw.get('arg')
                        if arg_name and arg_name in arg_patterns.get(sink_type, {}):
                            bonus = arg_patterns[sink_type][arg_name]
                            score += bonus
                            evidence.append(f"Argument '{arg_name}' in sink (bonus +{bonus})")

        score = min(max(0, score), max_weight)  # ensure not negative? We'll allow negative from penalties, but cap.
        return float(score), float(max_weight), evidence

    def _evaluate_flow_signatures(self, signatures: List[Dict], data: Dict) -> Tuple[float, List[str]]:
        """Match flow signatures against data_flow strings."""
        flows = data.get('flows', [])
        total_bonus = 0
        evidence = []
        for flow in flows:
            data_flow_str = flow.get('data_flow', '')
            if not data_flow_str:
                continue
            # Normalize: replace " → " with "->", split
            steps = [s.strip() for s in data_flow_str.split('→')]
            steps = [s.strip() for s in steps if s.strip()]
            # Remove any transform descriptions? Actually they are just type names.
            # We'll match by exact sequence of steps.
            for sig in signatures:
                sig_steps = sig.get('signature', [])
                if not sig_steps:
                    continue
                # Check if sig_steps is a subsequence of steps? For simplicity, check exact match.
                # But some flows may have extra transforms; we'll check if sig_steps is a subsequence.
                if self._is_subsequence(sig_steps, steps):
                    bonus = sig.get('score_bonus', 0)
                    total_bonus += bonus
                    evidence.append(f"Flow signature '{sig.get('name')}' matched (bonus +{bonus})")
                    break  # only one signature per flow
        return float(total_bonus), evidence

    def _evaluate_dangerous_calls(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        """Evaluate dangerous API calls."""
        required = req.get('required', [])
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_call', 20)
        max_weight = req.get('max_dangerous_call_weight', 25)

        api_calls = data.get('api_calls', [])
        score = 0
        evidence = []
        # Check required: must have all required calls
        required_found = set()
        for call in api_calls:
            name = call.get('name')
            if name in required:
                required_found.add(name)
                score += weight_per
                evidence.append(f"Required dangerous call '{name}' found (weight +{weight_per})")
            elif name in optional:
                score += weight_per
                evidence.append(f"Optional dangerous call '{name}' found (weight +{weight_per})")

        # If any required missing, we might want to treat as not detected? But we'll just add partial.
        # For simplicity, we don't enforce all required; we just add weights.

        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_imports(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        """Evaluate imports."""
        required = req.get('required', [])
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_import', 10)
        max_weight = req.get('max_import_weight', 20)

        imports = data.get('imports', [])
        import_names = [imp.get('name') for imp in imports]
        score = 0
        evidence = []
        # Required
        for req_imp in required:
            if req_imp in import_names:
                score += weight_per
                evidence.append(f"Required import '{req_imp}' found (weight +{weight_per})")
        # Optional
        for opt_imp in optional:
            if opt_imp in import_names:
                score += weight_per
                evidence.append(f"Optional import '{opt_imp}' found (weight +{weight_per})")

        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _evaluate_vulnerabilities(self, req: Dict, data: Dict) -> Tuple[float, float, List[str]]:
        """Evaluate vulnerability findings."""
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
        """Evaluate obfuscation findings."""
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
        """Evaluate behavior features from feature_vector."""
        required = req.get('required', [])
        optional = req.get('optional', [])
        weight_per = req.get('weight_per_feature', 15)
        max_weight = req.get('max_feature_weight', 25)

        fv = data.get('feature_vector', {})
        score = 0
        evidence = []
        # Required features must be enabled
        for feat in required:
            if fv.get(feat, {}).get('enabled', False):
                score += weight_per
                evidence.append(f"Required behavior feature '{feat}' enabled (weight +{weight_per})")
        # Optional
        for feat in optional:
            if fv.get(feat, {}).get('enabled', False):
                score += weight_per
                evidence.append(f"Optional behavior feature '{feat}' enabled (weight +{weight_per})")

        score = min(score, max_weight)
        return float(score), float(max_weight), evidence

    def _apply_exclusions(self, exclusions: List[Dict], data: Dict) -> Tuple[float, List[str]]:
        """Apply exclusion rules and return total deduction."""
        total_deduction = 0
        evidence = []
        # For each exclusion, evaluate condition.
        # We'll implement a simple condition evaluator that checks for certain patterns.
        for exc in exclusions:
            condition = exc.get('condition', '')
            deduction = exc.get('deduction', 0)
            if self._evaluate_condition(condition, data):
                total_deduction += deduction
                evidence.append(f"Exclusion '{exc.get('name')}' applied (deduct -{deduction})")
        return float(total_deduction), evidence

    # ----------------------------------------------------------------------
    # Helpers for conditions and destinations
    # ----------------------------------------------------------------------

    def _evaluate_condition(self, condition: str, data: Dict) -> bool:
        if not condition:
            return False
        # Handle AND
        if ' AND ' in condition:
            parts = condition.split(' AND ')
            return all(self._evaluate_condition(p.strip(), data) for p in parts)
        # Handle OR
        if ' OR ' in condition:
            parts = condition.split(' OR ')
            return any(self._evaluate_condition(p.strip(), data) for p in parts)

        # Single condition – no local imports anymore
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

        # Add more conditions as needed...
        return False

    def _extract_destination_from_call(self, call_name: str, line: int, data: Dict) -> Optional[str]:
        """
        Extract destination (URL, IP) from API call arguments.
        Looks up api_calls by name and line.
        """
        api_calls = data.get('api_calls', [])
        for call in api_calls:
            if call.get('name') == call_name and line in call.get('lines', []):
                args = call.get('args', [])
                if args and isinstance(args, list) and len(args) > 0:
                    # Often the first argument is URL
                    return str(args[0])
                # Also check keywords for 'url'?
                for kw in call.get('keywords', []):
                    if kw.get('arg') == 'url':
                        return str(kw.get('value'))
        return None

    def _is_external_destination(self, dest: str) -> bool:
        """Return True if destination is not localhost, not private IP, not known cloud."""
        if self._is_localhost(dest) or self._is_private_ip(dest) or self._is_known_cloud(dest):
            return False
        return True

    def _is_localhost(self, dest: str) -> bool:
        return dest in ['localhost', '127.0.0.1', '::1']

    def _is_private_ip(self, dest: str) -> bool:
        # Simple check for private IP ranges
        import ipaddress
        try:
            ip = ipaddress.ip_address(dest)
            return ip.is_private
        except:
            return False

    def _is_known_cloud(self, dest: str) -> bool:
        cloud_domains = ['amazonaws.com', 'googleapis.com', 'azure.com', 'cloudflare.com', 'api.github.com']
        return any(domain in dest for domain in cloud_domains)

    def _is_subsequence(self, pattern: List[str], sequence: List[str]) -> bool:
        """Check if pattern appears as a subsequence (preserving order) in sequence."""
        it = iter(sequence)
        return all(item in it for item in pattern)

    def _determine_confidence(self, score: float, conf_rules: Dict, component_scores: Dict, evidence: List) -> str:
        """Determine confidence level based on score and additional conditions."""
        levels = conf_rules.get('levels', {})
        if not levels:
            if score >= 80: return "HIGH"
            if score >= 60: return "MEDIUM"
            if score >= 40: return "LOW"
            return "VERY_LOW"

        # Check each level in descending order
        for level, config in sorted(levels.items(), key=lambda x: x[1].get('min_score', 0), reverse=True):
            min_score = config.get('min_score', 0)
            if score >= min_score:
                # Check additional conditions
                additional = config.get('additional_conditions', [])
                if all(self._evaluate_condition(cond, {'component_scores': component_scores}) for cond in additional):
                    return level
        return "VERY_LOW"

    def _determine_overall_risk(self, verdicts: Dict) -> Dict:
        """Determine overall risk from all verdicts."""
        detected = [(tech, v) for tech, v in verdicts.items() if v.get('detected', False)]
        if not detected:
            return {"level": "LOW", "score": 0, "message": "No techniques detected"}
        max_score = max(v['score'] for _, v in detected)
        max_tech = max(detected, key=lambda x: x[1]['score'])[0]
        # Map score to level
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