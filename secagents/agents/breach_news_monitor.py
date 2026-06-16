"""Agent 16/21 — BreachNewsMonitorAgent.

Aggregates public breach-disclosure headlines from reputable security news sources.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class BreachNewsMonitorAgent(BaseAgent):
    name = "breach_news_monitor"
    category = "threat_intel"
    description = "Aggregates public breach-disclosure headlines from reputable security news sources."
    target_type = "none"
    requires_target = False

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/breach_news_monitor.py to build it out.",
            target=target,
        )]
