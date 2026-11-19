"""Permission analyzer (Task 2): permission-vs-usage deltas per principal.

Public surface:
    Analyzer / AnalyzerConfig  — the analysis engine
    ActionRegistry             — bundled IAM action dataset (policy_sentry)
    PolicySet / Statement      — IAM statement evaluation (wildcards, NotAction, Deny)
"""

from .action_registry import ActionRegistry, load_default_registry
from .engine import Analyzer, AnalyzerConfig
from .findings import (
    AnalysisReport,
    GrantedAction,
    PrincipalFinding,
    VerifiedPolicy,
)
from .matcher import PolicySet, Statement

__all__ = [
    "ActionRegistry",
    "load_default_registry",
    "Analyzer",
    "AnalyzerConfig",
    "AnalysisReport",
    "GrantedAction",
    "PrincipalFinding",
    "VerifiedPolicy",
    "PolicySet",
    "Statement",
]
