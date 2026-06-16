"""
Base classes shared by every agent in the system.

Every agent that operates against a network target, domain, or hostname
MUST go through `authorized(target)` before doing anything. This is the
single technical enforcement point for the authorization boundary —
agents are not allowed to act on targets outside config.yaml's
`authorized_targets` list. CLI flags cannot bypass this; it must be
edited in config.yaml directly, which keeps a deliberate paper trail.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    agent: str
    title: str
    severity: Severity
    detail: str = ""
    target: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "title": self.title,
            "severity": self.severity.value,
            "detail": self.detail,
            "target": self.target,
            "raw": self.raw,
        }


class AgentNotImplemented(Exception):
    """Raised by scaffolded agents that haven't been built out yet."""


class BaseAgent:
    name: str = "base_agent"
    category: str = "uncategorized"
    description: str = ""
    requires_target: bool = True  # False for agents like cve_feed that aren't target-scoped

    # "network": target is a hostname/IP -> gated by authorized_targets allowlist.
    # "path": target is a local file/directory the user already has access to
    #         (their own repo) -> not network-authorization-gated.
    # "none": agent ignores target entirely (e.g. feed aggregators).
    target_type: str = "network"

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.authorized_targets = set(config.get("authorized_targets", []))

    def authorized(self, target: str) -> bool:
        """The one and only authorization gate for network-scoped agents."""
        if not self.requires_target or self.target_type != "network":
            return True
        return target in self.authorized_targets

    def run(self, target: str | None = None) -> list[Finding]:
        if self.requires_target:
            if target is None:
                raise ValueError(f"{self.name} requires a target")
            if not self.authorized(target):
                return [Finding(
                    agent=self.name,
                    title="Target not authorized — skipped",
                    severity=Severity.INFO,
                    detail=f"'{target}' is not in config.yaml authorized_targets. "
                            f"Add it explicitly to scan it.",
                    target=target,
                )]
        return self._run(target)

    def _run(self, target: str | None) -> list[Finding]:
        raise AgentNotImplemented(f"{self.name} is scaffolded but not yet implemented")
