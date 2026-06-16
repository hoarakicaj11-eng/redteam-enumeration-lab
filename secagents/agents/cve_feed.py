"""Agent 14/21 — CVE Feed Aggregator.

Pulls recently published CVEs from the public NVD API
(https://nvd.nist.gov — no API key required for light usage) and
optionally filters by keyword (e.g. software names detected by other
agents) to surface only what's relevant to your stack.
"""

from __future__ import annotations

from agents.base import BaseAgent, Finding, Severity

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVEFeedAgent(BaseAgent):
    name = "cve_feed"
    category = "threat_intel"
    description = "Recent CVEs from the public NVD feed, optionally filtered by keyword"
    requires_target = False
    target_type = "none"

    def _run(self, target: str | None) -> list[Finding]:
        if requests is None:
            return [Finding(self.name, "requests not installed", Severity.INFO)]

        keywords = self.config.get("cve_feed", {}).get("keywords", [])
        results_per_page = self.config.get("cve_feed", {}).get("limit", 10)

        params = {"resultsPerPage": results_per_page}
        if keywords:
            params["keywordSearch"] = " ".join(keywords)

        try:
            resp = requests.get(NVD_URL, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            return [Finding(self.name, "Could not reach NVD API", Severity.INFO, detail=str(e))]

        findings: list[Finding] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "unknown")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            severity = Severity.INFO
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    base_score = metrics[key][0]["cvssData"]["baseScore"]
                    if base_score >= 9:
                        severity = Severity.CRITICAL
                    elif base_score >= 7:
                        severity = Severity.HIGH
                    elif base_score >= 4:
                        severity = Severity.MEDIUM
                    else:
                        severity = Severity.LOW
                    break
            findings.append(Finding(
                agent=self.name,
                title=f"{cve_id}",
                severity=severity,
                detail=desc[:300],
            ))

        if not findings:
            findings.append(Finding(self.name, "No matching CVEs found", Severity.INFO))
        return findings
