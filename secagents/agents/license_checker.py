"""Agent 12/21 — LicenseCheckerAgent.

Scans your dependency manifest for OSS licenses considered risky for your project (e.g. copyleft licenses in a closed-source codebase).

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class LicenseCheckerAgent(BaseAgent):
    name = "license_checker"
    category = "code"
    description = "Scans your dependency manifest for OSS licenses considered risky for your project (e.g. copyleft licenses in a closed-source codebase)."
    target_type = "path"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/license_checker.py to build it out.",
            target=target,
        )]
