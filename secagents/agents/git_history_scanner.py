"""Agent 13/21 — GitHistoryScannerAgent.

Scans full git commit history (not just the working tree) for secrets that were committed and later removed but still live in history.

STATUS: scaffolded, not yet implemented. The interface is wired up so the
orchestrator can call it once the logic is filled in — see _run() below.
"""

from __future__ import annotations
from agents.base import BaseAgent, Finding, Severity


class GitHistoryScannerAgent(BaseAgent):
    name = "git_history_scanner"
    category = "code"
    description = "Scans full git commit history (not just the working tree) for secrets that were committed and later removed but still live in history."
    target_type = "path"
    requires_target = True

    def _run(self, target: str | None) -> list[Finding]:
        # TODO: implement. Return a list[Finding] like the other agents.
        return [Finding(
            agent=self.name,
            title="Not yet implemented",
            severity=Severity.INFO,
            detail="This agent is scaffolded — see agents/git_history_scanner.py to build it out.",
            target=target,
        )]
