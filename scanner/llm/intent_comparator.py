"""
intent_comparator.py
--------------------
Compares user intent with actual code behavior.
This is the novel contribution of TrustGuard.
"""

from typing import Dict, Any, List, Optional, Set
from scanner.llm.llm_reasoner import LLMReasoner
from scanner.data.llm_config import INTENT_CATEGORIES


class IntentComparator:
    """
    Compares user intent with actual code behavior.
    
    Features:
        1. Keyword-based intent extraction
        2. Behavior comparison
        3. LLM-assisted analysis
        4. Trust scoring
    """
    
    def __init__(self):
        """Initialize the intent comparator."""
        self.reasoner = LLMReasoner()
        self.categories = INTENT_CATEGORIES
    
    def extract_intent(self, prompt: str) -> Dict[str, Any]:
        """
        Extract intent from user prompt using keyword matching.
        
        Args:
            prompt: User prompt
            
        Returns:
            Dictionary with intent categories and expected behaviors
        """
        prompt_lower = prompt.lower()
        intent = {
            "categories": [],
            "expected_behaviors": [],
            "forbidden_behaviors": [],
        }
        
        # Check each category
        for category, keywords in self.categories.items():
            if any(k in prompt_lower for k in keywords):
                intent["categories"].append(category)
                
                # Define expected behaviors for each category
                if category == "backup":
                    intent["expected_behaviors"].extend(["file_read", "file_write"])
                elif category == "network":
                    intent["expected_behaviors"].append("network_request")
                elif category == "file":
                    intent["expected_behaviors"].extend(["file_read", "file_write"])
                elif category == "system":
                    intent["expected_behaviors"].append("subprocess")
                elif category == "credential":
                    intent["expected_behaviors"].append("credential_access")
                elif category == "encryption":
                    intent["expected_behaviors"].extend(["obfuscation", "file_read", "file_write"])
        
        # Define forbidden behaviors (always suspicious)
        intent["forbidden_behaviors"] = [
            "anti_forensics",
            "persistence_attempt",
            "credential_access",  # Unless the intent explicitly asks for it
        ]
        
        # Remove duplicates
        intent["expected_behaviors"] = list(set(intent["expected_behaviors"]))
        
        return intent
    
    def compare(
        self,
        prompt: str,
        feature_vector: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compare intent with actual behavior.
        
        Args:
            prompt: User prompt
            feature_vector: Behavioral feature vector
            findings: Detected findings
            
        Returns:
            Comparison result with trust score
        """
        # 1. Extract intent
        intent = self.extract_intent(prompt)
        
        # 2. Analyze behavior
        behavior_analysis = self._analyze_behavior(feature_vector, intent)
        
        # 3. Get LLM analysis (if available)
        llm_analysis = self._get_llm_analysis(prompt, feature_vector, findings)
        
        # 4. Calculate trust score
        trust_score = self._calculate_trust_score(
            behavior_analysis,
            llm_analysis,
            findings
        )
        
        # 5. Determine verdict
        verdict = self._determine_verdict(trust_score, behavior_analysis)
        
        return {
            "verdict": verdict,
            "trust_score": trust_score,
            "intent": intent,
            "behavior_analysis": behavior_analysis,
            "llm_analysis": llm_analysis,
            "findings": findings,
            "mismatch_reason": self._get_mismatch_reason(behavior_analysis),
        }
    
    def _analyze_behavior(
        self,
        feature_vector: Dict[str, Any],
        intent: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze behavior against intent.
        
        Returns:
            Dictionary with matches, mismatches, and extra behaviors
        """
        expected = set(intent.get("expected_behaviors", []))
        forbidden = set(intent.get("forbidden_behaviors", []))
        
        # Get actual behaviors
        actual = {
            k for k, v in feature_vector.items()
            if v is True and k != "data_flow_paths"
        }
        
        # Find matches (expected behaviors that are present)
        matches = expected & actual
        
        # Find missing (expected behaviors that are absent)
        missing = expected - actual
        
        # Find extra (unexpected behaviors that are present)
        extra = actual - expected
        
        # Find forbidden (forbidden behaviors that are present)
        violations = actual & forbidden
        
        # Calculate metrics
        completeness = len(matches) / len(expected) if expected else 1.0
        suspiciousness = len(violations) + len(extra)
        
        return {
            "matches": list(matches),
            "missing": list(missing),
            "extra": list(extra),
            "violations": list(violations),
            "completeness": round(completeness * 100, 2),
            "suspiciousness": suspiciousness,
            "has_mismatch": len(missing) > 0 or len(violations) > 0,
        }
    
    def _get_llm_analysis(
        self,
        prompt: str,
        feature_vector: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Get LLM analysis of intent vs behavior.
        """
        if not self.reasoner.is_available():
            return {"verdict": "UNKNOWN", "reasoning": "LLM not available"}
        
        try:
            return self.reasoner.compare_intent(prompt, feature_vector, findings)
        except Exception as e:
            return {"verdict": "ERROR", "reasoning": str(e)}
    
    def _calculate_trust_score(
        self,
        behavior_analysis: Dict[str, Any],
        llm_analysis: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> int:
        """
        Calculate trust score (0-100).
        
        Higher score = more trustworthy (matches intent)
        """
        score = 50  # Start neutral
        
        # 1. Behavioral completeness (0-30 points)
        completeness = behavior_analysis.get("completeness", 0)
        score += (completeness / 100) * 30
        
        # 2. Violations penalty (0-30 points)
        violations = len(behavior_analysis.get("violations", []))
        score -= min(violations * 10, 30)
        
        # 3. Extra behaviors penalty (0-20 points)
        extra = len(behavior_analysis.get("extra", []))
        score -= min(extra * 5, 20)
        
        # 4. LLM verdict (0-20 points)
        llm_verdict = llm_analysis.get("verdict", "UNKNOWN")
        if llm_verdict == "MATCH":
            score += 20
        elif llm_verdict == "PARTIAL_MATCH":
            score += 10
        elif llm_verdict == "MISMATCH":
            score -= 20
        
        # 5. Finding severity penalty
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            if severity == "CRITICAL":
                score -= 15
            elif severity == "HIGH":
                score -= 10
            elif severity == "MEDIUM":
                score -= 5
        
        # Clamp to 0-100
        return max(0, min(100, score))
    
    def _determine_verdict(
        self,
        trust_score: int,
        behavior_analysis: Dict[str, Any]
    ) -> str:
        """
        Determine the final verdict.
        """
        if behavior_analysis.get("has_mismatch", False):
            if trust_score < 40:
                return "CRITICAL_MISMATCH"
            elif trust_score < 60:
                return "SIGNIFICANT_MISMATCH"
            else:
                return "PARTIAL_MATCH"
        
        if trust_score >= 80:
            return "MATCH"
        elif trust_score >= 60:
            return "PARTIAL_MATCH"
        else:
            return "MISMATCH"
    
    def _get_mismatch_reason(self, behavior_analysis: Dict[str, Any]) -> str:
        """
        Generate a human-readable mismatch reason.
        """
        reasons = []
        
        missing = behavior_analysis.get("missing", [])
        if missing:
            reasons.append(f"Missing expected behaviors: {', '.join(missing)}")
        
        extra = behavior_analysis.get("extra", [])
        if extra:
            reasons.append(f"Unexpected behaviors: {', '.join(extra)}")
        
        violations = behavior_analysis.get("violations", [])
        if violations:
            reasons.append(f"Forbidden behaviors detected: {', '.join(violations)}")
        
        return " | ".join(reasons) if reasons else "Behavior matches intent"


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "IntentComparator",
]