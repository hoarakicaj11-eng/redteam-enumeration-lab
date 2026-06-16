"""Agent 17/21 — ThreatActorTrackerAgent.

Aggregates public threat-intel summaries (e.g. CISA advisories) on active campaigns relevant to your stack.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class ThreatActorTrackerAgent(BaseAgent):
    name = "threat_actor_tracker"
    category = "threat_intel"
    description = "Aggregates public threat-intel summaries (e.g. CISA advisories) on active campaigns relevant to your stack."
    target_type = "none"
    requires_target = False

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/threat_actor_tracker.py to build it out.",
            target=target,
        )]
