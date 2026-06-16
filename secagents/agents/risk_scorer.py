"""Agent 21/21 — Risk Scorer.

Consumes the full findings list and computes a single 0-100 health score,
weighted by severity. Simple and transparent on purpose — the formula is
visible right here, not a black box.
"""

from __future__ import annotations
from agents.base import Finding, Severity

WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def compute_score(findings: list[Finding]) -> dict:
    penalty = sum(WEIGHTS[f.severity] for f in findings)
    score = max(0, 100 - penalty)

    if score >= 90:
        grade = "A — strong posture"
    elif score >= 75:
        grade = "B — minor issues to address"
    elif score >= 50:
        grade = "C — notable gaps, prioritize fixes"
    elif score >= 25:
        grade = "D — significant exposure"
    else:
        grade = "F — critical exposure, act immediately"

    return {"score": score, "grade": grade, "penalty_applied": penalty}
