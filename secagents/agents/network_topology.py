"""Agent 6/21 — NetworkTopologyAgent.

Traceroute/latency mapping across your own authorized hosts to visualize network paths.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class NetworkTopologyAgent(BaseAgent):
    name = "network_topology"
    category = "network"
    description = "Traceroute/latency mapping across your own authorized hosts to visualize network paths."
    target_type = "network"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/network_topology.py to build it out.",
            target=target,
        )]
