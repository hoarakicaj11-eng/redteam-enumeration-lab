"""Agent 7/21 — CookieSecurityAgent.

Checks Set-Cookie headers on your own site for Secure, HttpOnly, and SameSite flags.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class CookieSecurityAgent(BaseAgent):
    name = "cookie_security"
    category = "web"
    description = "Checks Set-Cookie headers on your own site for Secure, HttpOnly, and SameSite flags."
    target_type = "network"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/cookie_security.py to build it out.",
            target=target,
        )]
