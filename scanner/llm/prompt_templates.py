"""
prompt_templates.py
--------------------
Prompt templates for LLM interaction.
"""

from typing import Dict, Any

# ==========================================
# SYSTEM PROMPTS
# ==========================================

SYSTEM_PROMPT = """
You are TrustGuard, an AI security assistant for analyzing AI-generated code.
Your role is to explain security findings in plain English, help developers
understand risks, and provide actionable recommendations.

Rules:
1. Never modify the deterministic score - only explain it
2. Base explanations on the evidence provided
3. Be clear, concise, and actionable
4. Focus on security implications
5. Provide specific remediation steps when possible
"""

# ==========================================
# EXPLANATION PROMPTS
# ==========================================

EXPLANATION_PROMPT = """
You are analyzing code for security issues. Here are the findings:

=== FINDINGS ===
{findings}

=== FEATURE VECTOR ===
{feature_vector}

=== DATA FLOW ===
{data_flows}

=== SCORE ===
{score}

Please provide:
1. A brief summary of what the code appears to do
2. The main security concerns
3. What attack type this most resembles
4. Specific recommendations for remediation
5. Your confidence in this assessment (HIGH/MEDIUM/LOW)

Be concise but thorough. Focus on actionable insights.
"""

INTENT_COMPARISON_PROMPT = """
You are analyzing if the generated code matches the user's intent.

=== USER PROMPT ===
{prompt}

=== CODE BEHAVIOR ===
{behavior}

=== DETECTED THREATS ===
{threats}

Please analyze:
1. Does the code do what the user asked?
2. Are there behaviors that don't match the intent?
3. What additional capabilities does the code have?
4. Is there a trust mismatch?

Provide a clear verdict: MATCH, MISMATCH, or PARTIAL_MATCH
Explain your reasoning with evidence from the code behavior.
"""

REMEDIATION_PROMPT = """
You are providing remediation advice for security issues found in code.

=== ISSUE ===
{issue}

=== SEVERITY ===
{severity}

=== CONTEXT ===
{context}

Please provide:
1. A clear explanation of the risk
2. Specific code-level fixes
3. Alternative safer approaches
4. Additional security considerations

Be practical and actionable.
"""

# ==========================================
# HELPERS
# ==========================================

def format_findings(findings: list) -> str:
    """Format findings for LLM prompt."""
    if not findings:
        return "No findings detected."
    
    lines = []
    for f in findings:
        attack_type = f.get("attack_type", "Unknown")
        severity = f.get("severity", "UNKNOWN")
        description = f.get("description", "")
        confidence = f.get("confidence", 0)
        
        lines.append(f"- [{severity}] {attack_type} (confidence: {confidence}%)")
        if description:
            lines.append(f"  {description}")
    
    return "\n".join(lines)


def format_flows(flows: list) -> str:
    """Format data flows for LLM prompt."""
    if not flows:
        return "No data flows detected."
    
    lines = []
    for flow in flows:
        source = flow.get("source", "?")
        sink = flow.get("sink", "?")
        transforms = flow.get("transforms", [])
        transform_str = " → ".join(transforms) if transforms else "direct"
        
        lines.append(f"  {source} → {transform_str} → {sink}")
    
    return "\n".join(lines)


def format_feature_vector(fv: dict) -> str:
    """Format feature vector for LLM prompt."""
    if not fv:
        return "No features detected."
    
    enabled = [k for k, v in fv.items() if v is True and k != "data_flow_paths"]
    if not enabled:
        return "No suspicious behaviors detected."
    
    return "\n".join(f"  - {k}" for k in enabled)


# ==========================================
# EXPORTS
# ==========================================

__all__ = [
    "SYSTEM_PROMPT",
    "EXPLANATION_PROMPT",
    "INTENT_COMPARISON_PROMPT",
    "REMEDIATION_PROMPT",
    "format_findings",
    "format_flows",
    "format_feature_vector",
]