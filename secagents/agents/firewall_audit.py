"""Agent 5/21 — FirewallAuditAgent.

Parses a user-supplied firewall rule export (iptables/ufw/cloud security-group JSON) and flags overly permissive rules (e.g. 0.0.0.0/0 allow-all on sensitive ports).

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class FirewallAuditAgent(BaseAgent):
    name = "firewall_audit"
    category = "network"
    description = "Parses a user-supplied firewall rule export (iptables/ufw/cloud security-group JSON) and flags overly permissive rules (e.g. 0.0.0.0/0 allow-all on sensitive ports)."
    target_type = "path"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/firewall_audit.py to build it out.",
            target=target,
        )]
