"""Agent 18/21 — LogAnomalyAgent.

Parses a user-supplied log file (auth.log, access.log) for patterns suggesting brute force attempts, scanning activity, or other anomalies.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class LogAnomalyAgent(BaseAgent):
    name = "log_anomaly"
    category = "monitoring"
    description = "Parses a user-supplied log file (auth.log, access.log) for patterns suggesting brute force attempts, scanning activity, or other anomalies."
    target_type = "path"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/log_anomaly.py to build it out.",
            target=target,
        )]
