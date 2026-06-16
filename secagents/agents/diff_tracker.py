"""Agent 19/21 — DiffTrackerAgent.

Compares the current scan's findings against the previous run's saved report to highlight what's new (newly opened ports, new CVEs, expired certs, etc.).

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class DiffTrackerAgent(BaseAgent):
    name = "diff_tracker"
    category = "monitoring"
    description = "Compares the current scan's findings against the previous run's saved report to highlight what's new (newly opened ports, new CVEs, expired certs, etc.)."
    target_type = "path"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/diff_tracker.py to build it out.",
            target=target,
        )]
