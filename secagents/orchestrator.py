#!/usr/bin/env python3
"""
orchestrator.py — entry point for the security health scanning system.

Loads config.yaml, runs every enabled agent against every authorized
target it applies to, and produces a unified report.

LEGAL NOTICE: every network-scoped agent refuses to run against a target
that isn't explicitly listed in config.yaml's authorized_targets. This is
enforced in agents/base.py, not just documented here. Only add targets you
own or have explicit written permission to test.
"""

from __future__ import annotations
import argparse
import importlib
import sys
import yaml

from agents.base import Finding
from agents import report_aggregator, risk_scorer

# (module_name, ClassName) for the 19 BaseAgent-derived agents.
# report_aggregator and risk_scorer are meta-agents called separately below.
AGENT_REGISTRY = [
    ("port_scanner", "PortScannerAgent"),
    ("tls_checker", "TLSCheckerAgent"),
    ("dns_health", "DNSHealthAgent"),
    ("firewall_audit", "FirewallAuditAgent"),
    ("network_topology", "NetworkTopologyAgent"),
    ("http_headers", "HTTPHeadersAgent"),
    ("cookie_security", "CookieSecurityAgent"),
    ("open_redirect_checker", "OpenRedirectCheckerAgent"),
    ("ct_monitor", "CTMonitorAgent"),
    ("secrets_scanner", "SecretsScannerAgent"),
    ("dependency_checker", "DependencyCheckerAgent"),
    ("license_checker", "LicenseCheckerAgent"),
    ("git_history_scanner", "GitHistoryScannerAgent"),
    ("cve_feed", "CVEFeedAgent"),
    ("advisory_aggregator", "AdvisoryAggregatorAgent"),
    ("breach_news_monitor", "BreachNewsMonitorAgent"),
    ("threat_actor_tracker", "ThreatActorTrackerAgent"),
    ("log_anomaly", "LogAnomalyAgent"),
    ("diff_tracker", "DiffTrackerAgent"),
]


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def load_agent_classes():
    classes = {}
    for module_name, class_name in AGENT_REGISTRY:
        module = importlib.import_module(f"agents.{module_name}")
        classes[module_name] = getattr(module, class_name)
    return classes


def main():
    parser = argparse.ArgumentParser(description="Multi-agent security health scanner")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--json-out", default="report.json", help="Path to write JSON report")
    parser.add_argument("--md-out", default="report.md", help="Path to write Markdown report")
    args = parser.parse_args()

    config = load_config(args.config)
    enabled = config.get("enabled_agents", [])
    authorized_targets = config.get("authorized_targets", [])
    path_targets = config.get("path_targets", {})  # e.g. {"secrets_scanner": "./", "dependency_checker": "./"}

    if not authorized_targets and not path_targets:
        print("WARNING: config.yaml has no authorized_targets or path_targets configured.")
        print("Network/path agents will be skipped until you add some. See config.yaml.example.\n")

    agent_classes = load_agent_classes()
    all_findings: list[Finding] = []

    for module_name, AgentClass in agent_classes.items():
        if enabled and module_name not in enabled:
            continue
        agent = AgentClass(config)
        print(f"[*] Running {agent.name} ({agent.category})...")

        if agent.target_type == "none":
            findings = agent.run(None)
            all_findings.extend(findings)
        elif agent.target_type == "path":
            target_path = path_targets.get(module_name, path_targets.get("default"))
            if not target_path:
                print(f"    skipped — no path configured for {module_name} in config.yaml path_targets")
                continue
            all_findings.extend(agent.run(target_path))
        else:  # "network"
            for target in authorized_targets:
                all_findings.extend(agent.run(target))

        print(f"    {len(all_findings)} cumulative findings so far")

    report = report_aggregator.write_report(all_findings, json_path=args.json_out, md_path=args.md_out)
    score = risk_scorer.compute_score(all_findings)
    report["risk_score"] = score

    # re-write JSON now that risk_score is attached
    import json
    with open(args.json_out, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nDone. {report['total_findings']} total findings.")
    print(f"Risk score: {score['score']}/100 ({score['grade']})")
    print(f"Reports written to {args.json_out} and {args.md_out}")


if __name__ == "__main__":
    sys.exit(main())
