"""Policy proposers: backends that draft tightened IAM policies (Task 4).

permtrim deliberately treats the LLM as a *proposal generator*, never as the
source of truth. Whatever a proposer returns is validated by the guardrail
(:mod:`permtrim.llm.guardrails`) before it is shown to the user, and a
deterministic offline proposer is always available so the pipeline works
without any model running.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any, Protocol

from ..analyzer.action_registry import ActionRegistry
from ..analyzer.findings import PrincipalFinding

__all__ = ["PolicyProposer", "OllamaProposer", "DeterministicProposer", "PROPOSER_TIMEOUT_S"]

LOGGER = logging.getLogger(__name__)

PROPOSER_TIMEOUT_S = 120

_SYSTEM_PROMPT = """You are an AWS IAM least-privilege engineer.
Given a principal's observed API usage, propose a tightened IAM policy that
allows ONLY the observed working actions. Rules:
- Output STRICT JSON only, no prose, no markdown fences. Shape:
  {"Statement": [{"Effect": "Allow", "Action": ["service:Action"], "Resource": "*"}], "Version": "2012-10-17"}
- Action names must be REAL IAM action names, exactly as given in the payload.
  Never invent or rename actions.
- Include every action from used_actions, and nothing else.
- Do not add Actions that appear only in unused_examples.
- Never use NotAction or NotResource; list actions and resources explicitly.
- When used_action_resources maps an action to resource ARNs, use exactly
  those ARNs as its Resource (never widen them to "*").
"""


class PolicyProposer(Protocol):
    """Anything that can draft a tightened policy for one finding."""

    name: str

    def propose(self, finding: PrincipalFinding, feedback: str | None = None) -> dict[str, Any] | None:
        """Return a draft policy document (``{"Version": ..., "Statement": [...]}``).

        Args:
            finding: The excess-permission finding to remediate.
            feedback: Guardrail feedback from the previous rejected attempt
                (a failed draft is retried with this context).

        Returns:
            The draft policy document, or ``None`` when the proposer gives up.
        """
        ...


# --------------------------------------------------------------------------- #
# Ollama (local LLM; e.g. `ollama pull llama3.2` then `ollama serve`)
# --------------------------------------------------------------------------- #


class OllamaProposer:
    """Draft policies with a local Ollama model (default: llama3.2).

    The model is only ever asked for JSON; its output is parsed defensively
    (markdown fences stripped, JSON extracted from surrounding prose) because
    small local models frequently wrap JSON in text despite instructions.
    """

    def __init__(
        self,
        model: str = "llama3.2",
        host: str = "http://127.0.0.1:11434",
        timeout_s: int = PROPOSER_TIMEOUT_S,
    ) -> None:
        self.name = f"ollama:{model}"
        self._model = model
        self._host = host.rstrip("/")
        self._timeout = timeout_s

    def propose(self, finding: PrincipalFinding, feedback: str | None = None) -> dict[str, Any] | None:
        payload = finding.to_proposer_payload()
        prompt = f"Draft the tightened IAM policy JSON for this principal:\n{json.dumps(payload, indent=2)}"
        if feedback:
            prompt += (
                f"\n\nYour previous draft was rejected by the validator:\n{feedback}\n"
                "Fix those problems and return corrected JSON only."
            )
        raw = self._chat(prompt)
        if raw is None:
            return None
        return _extract_json_object(raw)

    def _chat(self, prompt: str) -> str | None:
        """One round-trip to ``POST /api/chat``; returns assistant text or None."""
        body = json.dumps(
            {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "stream": False,
                "format": "json",
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._host + "/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            content = data.get("message", {}).get("content", "")
            LOGGER.debug("ollama replied %d chars for %s", len(content), self._model)
            return content if content.strip() else None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            LOGGER.warning("Ollama call failed (%s); falling back", exc)
            return None


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of a model reply (fences/prose tolerant)."""
    if not text:
        return None
    cleaned = re.sub(r"```(?:json)?|```", "", text)
    start = cleaned.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(cleaned)):
        char = cleaned[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = cleaned[start : index + 1]
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError:
                    return None
                return parsed if isinstance(parsed, dict) else None
    return None


# --------------------------------------------------------------------------- #
# Deterministic proposer (offline, always available)
# --------------------------------------------------------------------------- #


class DeterministicProposer:
    """Offline proposer: policy = the principal's observed working actions.

    This is not a placeholder — for the least-privilege objective the
    observed-action set IS the correct answer, and it is what an ideal LLM
    would converge to. It doubles as the reference implementation the LLM
    path is measured against, and as the guaranteed-working fallback when no
    model is reachable.

    Provider-aware output: AWS findings get an IAM statement document,
    Azure findings get a custom role definition (``permissions`` entries,
    the shape ``az role definition create`` consumes).
    """

    def __init__(self, registry: ActionRegistry | None = None, azure_subscription: str | None = None) -> None:
        self.name = "deterministic"
        self._registry = registry
        self._azure_subscription = azure_subscription

    def propose(self, finding: PrincipalFinding, feedback: str | None = None) -> dict[str, Any] | None:
        if not finding.used_actions:
            return None  # idle principals get no tightened policy (nothing to allow)
        actions = self._canonicalize(finding.used_actions)
        if finding.provider == "azure":
            return self._azure_role(finding, actions)
        return {
            "Version": "2012-10-17",
            "Statement": self._statements_for(finding, actions),
        }

    @staticmethod
    def _statements_for(finding: PrincipalFinding, actions: list[str]) -> list[dict[str, Any]]:
        """One Allow statement per distinct original resource scope set.

        Grouping matters: unioning different actions' scopes into a single
        statement would widen a narrowly-scoped action to another action's
        broad scope (the guardrail would rightly reject that, and this
        proposer doubles as the guaranteed fallback). With no recorded
        provenance (Azure snapshots, older collectors) everything shares one
        ``Resource: "*"`` statement, flagged for review in the Terraform
        header.
        """
        provenance = finding.used_action_resources
        if not provenance:
            return [{"Effect": "Allow", "Action": actions, "Resource": "*"}]
        groups: dict[tuple[str, ...], list[str]] = {}
        for action in actions:
            scopes = tuple(sorted(provenance.get(action.lower(), ())) or ("*",))
            groups.setdefault(scopes, []).append(action)
        if not groups:
            return [{"Effect": "Allow", "Action": actions, "Resource": "*"}]
        return [
            {"Effect": "Allow", "Action": group_actions, "Resource": list(scopes)}
            for scopes, group_actions in sorted(groups.items())
        ]

    def _azure_role(self, finding: PrincipalFinding, actions: list[str]) -> dict[str, Any]:
        """Custom role definition JSON for one principal's observed actions.

        The control/data-plane split is taken from the finding itself
        (``PrincipalFinding.used_data_plane_actions``), which the analyzer
        derived from the ``dataActions`` clause the original role used. The
        earlier ``microsoft.storage/blob/`` prefix hardcode was wrong for any
        other data-plane resource provider (Key Vault data actions, Cosmos DB
        item operations, ...): those would have landed in ``actions`` and the
        tightened role would have re-granted them on the control plane. Using
        the finding's own classification means a data-plane grant stays a
        data-plane grant regardless of the resource provider.
        """
        data_plane_set = set(finding.used_data_plane_actions)
        control_plane = [a for a in actions if a not in data_plane_set]
        data_plane = [a for a in actions if a in data_plane_set]
        permissions: dict[str, list[str]] = {}
        if control_plane:
            permissions["actions"] = control_plane
        if data_plane:
            permissions["dataActions"] = data_plane
        return {
            "Name": f"permtrim-{finding.kind}-{_slug(finding.name)}",
            "Description": "Generated by permtrim (least-privilege tightening from observed usage).",
            "IsCustom": True,
            "AssignableScopes": [f"/subscriptions/{self._azure_subscription or '{subscription}'}"],
            "permissions": [permissions] if permissions else [],
        }

    def _canonicalize(self, actions: list[str]) -> list[str]:
        """Prefer dataset casing (``s3:GetObject``); keep lowercase for unknowns."""
        if self._registry is None:
            return sorted(actions)
        return sorted(self._registry.canonical(action) or action for action in actions)


def _slug(name: str) -> str:
    """Principal name -> a safe role-name slug (UPNs, GUIDs, ...)."""
    slug = "".join(char if char.isalnum() else "-" for char in name.lower())
    return "-".join(part for part in slug.split("-") if part)[:40]
