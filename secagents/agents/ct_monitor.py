"""Agent 9/21 — CTMonitorAgent.

Queries public Certificate Transparency logs (crt.sh) for certificates issued against your own domain, to catch unauthorized/mis-issued certs.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class CTMonitorAgent(BaseAgent):
    name = "ct_monitor"
    category = "web"
    description = "Queries public Certificate Transparency logs (crt.sh) for certificates issued against your own domain, to catch unauthorized/mis-issued certs."
    target_type = "network"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/ct_monitor.py to build it out.",
            target=target,
        )]
