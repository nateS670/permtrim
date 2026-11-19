"""LLM remediation (Task 4): propose → guardrail → verified Terraform.

Public surface:
    PolicyProposer / OllamaProposer / DeterministicProposer  — draft generators
    Guardrail / GuardrailVerdict                              — validation
    Tightener / TightenerResult                               — orchestration
    policy_to_hcl                                             — Terraform rendering
"""

from .guardrails import Guardrail, GuardrailVerdict, SimulatorCallable
from .proposer import DeterministicProposer, OllamaProposer, PolicyProposer
from .terraform import policy_to_hcl, terraform_sanitize_name
from .tightener import PrincipalOutcome, Tightener, TightenerConfig, TightenResult

__all__ = [
    "PolicyProposer",
    "OllamaProposer",
    "DeterministicProposer",
    "Guardrail",
    "GuardrailVerdict",
    "SimulatorCallable",
    "Tightener",
    "TightenerConfig",
    "TightenResult",
    "PrincipalOutcome",
    "policy_to_hcl",
    "terraform_sanitize_name",
]
