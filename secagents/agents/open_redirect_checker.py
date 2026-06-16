"""Agent 8/21 — OpenRedirectCheckerAgent.

Checks your own web app for common misconfigurations: open redirects, exposed directory listings, default/sample pages left enabled.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class OpenRedirectCheckerAgent(BaseAgent):
    name = "open_redirect_checker"
    category = "web"
    description = "Checks your own web app for common misconfigurations: open redirects, exposed directory listings, default/sample pages left enabled."
    target_type = "network"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/open_redirect_checker.py to build it out.",
            target=target,
        )]
