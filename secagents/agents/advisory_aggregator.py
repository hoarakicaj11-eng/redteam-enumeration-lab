"""Agent 15/21 — AdvisoryAggregatorAgent.

Aggregates GitHub Security Advisories relevant to your detected dependencies.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class AdvisoryAggregatorAgent(BaseAgent):
    name = "advisory_aggregator"
    category = "threat_intel"
    description = "Aggregates GitHub Security Advisories relevant to your detected dependencies."
    target_type = "none"
    requires_target = False

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/advisory_aggregator.py to build it out.",
            target=target,
        )]
