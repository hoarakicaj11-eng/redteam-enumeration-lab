"""Agent 11/21 — Dependency Vulnerability Checker.

Parses requirements.txt / package.json in a local repo and checks each
pinned version against the OSV.dev public vulnerability database
(https://osv.dev — no API key required).
"""

from __future__ import annotations
import json
import os
import re

from agents.base import BaseAgent, Finding, Severity

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _parse_requirements_txt(path: str) -> list[tuple[str, str]]:
    pkgs = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)", line)
            if match:
                pkgs.append((match.group(1), match.group(2)))
    return pkgs


def _parse_package_json(path: str) -> list[tuple[str, str]]:
    pkgs = []
    try:
        with open(path, "r", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return pkgs
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean_version = re.sub(r"^[^\d]*", "", version)  # strip ^ ~ etc.
            if clean_version:
                pkgs.append((name, clean_version))
    return pkgs


class DependencyCheckerAgent(BaseAgent):
    name = "dependency_checker"
    category = "code"
    description = "Checks pinned dependency versions against the OSV.dev vulnerability database"
    target_type = "path"

    def _run(self, target: str) -> list[Finding]:
        if requests is None:
            return [Finding(self.name, "requests not installed", Severity.INFO, target=target)]

        packages: list[tuple[str, str, str]] = []  # (name, version, ecosystem)
        req_txt = os.path.join(target, "requirements.txt")
        pkg_json = os.path.join(target, "package.json")

        if os.path.isfile(req_txt):
            packages += [(n, v, "PyPI") for n, v in _parse_requirements_txt(req_txt)]
        if os.path.isfile(pkg_json):
            packages += [(n, v, "npm") for n, v in _parse_package_json(pkg_json)]

        if not packages:
            return [Finding(self.name, "No requirements.txt or package.json found", Severity.INFO, target=target)]

        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v} for n, v, eco in packages]
        try:
            resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=10)
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except Exception as e:
            return [Finding(self.name, "Could not reach OSV.dev", Severity.INFO, detail=str(e), target=target)]

        findings: list[Finding] = []
        for (name, version, eco), result in zip(packages, results):
            vulns = result.get("vulns", [])
            if vulns:
                ids = ", ".join(v.get("id", "?") for v in vulns)
                findings.append(Finding(
                    agent=self.name,
                    title=f"Vulnerable dependency: {name}=={version} ({eco})",
                    severity=Severity.HIGH,
                    detail=f"Known advisories: {ids}",
                    target=target,
                ))

        if not findings:
            findings.append(Finding(self.name, f"No known vulnerabilities in {len(packages)} checked packages",
                                      Severity.INFO, target=target))
        return findings
