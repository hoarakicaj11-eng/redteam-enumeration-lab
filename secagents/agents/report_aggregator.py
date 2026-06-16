"""Agent 20/21 — Report Aggregator.

Not target-scoped — this one consumes the findings produced by every
other agent in a run and renders a single unified report (Markdown + JSON).
"""

from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime, timezone

from agents.base import Finding, Severity

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵", Severity.INFO: "⚪",
}


def aggregate(findings: list[Finding]) -> dict:
    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f.severity].append(f)

    counts = {s.value: len(by_severity[s]) for s in SEVERITY_ORDER}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "counts_by_severity": counts,
        "findings": [f.to_dict() for f in findings],
    }


def render_markdown(report: dict) -> str:
    lines = ["# Security Health Report", ""]
    lines.append(f"_Generated {report['generated_at']}_")
    lines.append("")
    lines.append("## Summary")
    for sev in SEVERITY_ORDER:
        count = report["counts_by_severity"].get(sev.value, 0)
        lines.append(f"- {SEVERITY_EMOJI[sev]} **{sev.value.upper()}**: {count}")
    lines.append("")
    lines.append("## Findings")

    by_agent = defaultdict(list)
    for f in report["findings"]:
        by_agent[f["agent"]].append(f)

    for agent_name, agent_findings in sorted(by_agent.items()):
        lines.append(f"\n### {agent_name}")
        for f in sorted(agent_findings, key=lambda x: SEVERITY_ORDER.index(Severity(x["severity"]))):
            emoji = SEVERITY_EMOJI[Severity(f["severity"])]
            target_str = f" (`{f['target']}`)" if f.get("target") else ""
            lines.append(f"- {emoji} **{f['title']}**{target_str}")
            if f.get("detail"):
                lines.append(f"  - {f['detail']}")

    return "\n".join(lines)


def write_report(findings: list[Finding], json_path: str | None = None, md_path: str | None = None):
    report = aggregate(findings)
    if json_path:
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
    if md_path:
        with open(md_path, "w") as f:
            f.write(render_markdown(report))
    return report
