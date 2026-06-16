"""Agent 3/21 — DNS Health Checker.

Checks core DNS records and email-authentication hygiene (SPF/DMARC).
Requires dnspython (see requirements.txt).
"""

from __future__ import annotations

from agents.base import BaseAgent, Finding, Severity

try:
    import dns.resolver
except ImportError:  # pragma: no cover
    dns = None


class DNSHealthAgent(BaseAgent):
    name = "dns_health"
    category = "network"
    description = "DNS record sanity check and SPF/DMARC presence check"

    def _run(self, target: str) -> list[Finding]:
        if dns is None:
            return [Finding(self.name, "dnspython not installed", Severity.INFO,
                             detail="pip install dnspython", target=target)]

        findings: list[Finding] = []
        resolver = dns.resolver.Resolver()

        for record_type in ("A", "MX", "NS"):
            try:
                answers = resolver.resolve(target, record_type)
                values = ", ".join(str(r) for r in answers)
                findings.append(Finding(self.name, f"{record_type} record present", Severity.INFO,
                                         detail=values, target=target))
            except dns.resolver.NoAnswer:
                sev = Severity.LOW if record_type == "MX" else Severity.INFO
                findings.append(Finding(self.name, f"No {record_type} record found", sev, target=target))
            except Exception as e:
                findings.append(Finding(self.name, f"{record_type} lookup failed", Severity.INFO,
                                         detail=str(e), target=target))

        # SPF
        try:
            txts = resolver.resolve(target, "TXT")
            spf_found = any("v=spf1" in str(r) for r in txts)
        except Exception:
            spf_found = False
        findings.append(Finding(
            self.name, "SPF record present" if spf_found else "No SPF record found",
            Severity.INFO if spf_found else Severity.MEDIUM, target=target,
        ))

        # DMARC
        try:
            dmarc_txts = resolver.resolve(f"_dmarc.{target}", "TXT")
            dmarc_found = any("v=DMARC1" in str(r) for r in dmarc_txts)
        except Exception:
            dmarc_found = False
        findings.append(Finding(
            self.name, "DMARC record present" if dmarc_found else "No DMARC record found",
            Severity.INFO if dmarc_found else Severity.MEDIUM, target=target,
        ))

        return findings
