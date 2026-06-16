"""Agent 2/21 — TLS / Certificate Auditor.

Connects to a host's HTTPS port and checks certificate expiry, signature
issues, and weak protocol negotiation.
"""

from __future__ import annotations
import socket
import ssl
from datetime import datetime, timezone

from agents.base import BaseAgent, Finding, Severity


class TLSCheckerAgent(BaseAgent):
    name = "tls_checker"
    category = "network"
    description = "Certificate expiry and TLS protocol/cipher strength check"

    def _run(self, target: str) -> list[Finding]:
        port = self.config.get("tls_checker", {}).get("port", 443)
        findings: list[Finding] = []

        context = ssl.create_default_context()
        try:
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                    cert = tls_sock.getpeercert()
                    proto = tls_sock.version()
                    cipher = tls_sock.cipher()
        except Exception as e:
            return [Finding(self.name, "Could not establish TLS connection", Severity.INFO,
                             detail=str(e), target=target)]

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append(Finding(self.name, "Certificate has expired", Severity.CRITICAL,
                                     detail=f"Expired {abs(days_left)} day(s) ago", target=target))
        elif days_left < 14:
            findings.append(Finding(self.name, "Certificate expiring very soon", Severity.HIGH,
                                     detail=f"{days_left} day(s) remaining", target=target))
        elif days_left < 30:
            findings.append(Finding(self.name, "Certificate expiring soon", Severity.MEDIUM,
                                     detail=f"{days_left} day(s) remaining", target=target))
        else:
            findings.append(Finding(self.name, "Certificate validity OK", Severity.INFO,
                                     detail=f"{days_left} day(s) remaining", target=target))

        if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(Finding(self.name, f"Outdated protocol negotiated: {proto}", Severity.HIGH,
                                     detail="Disable legacy protocol versions on the server", target=target))
        else:
            findings.append(Finding(self.name, f"Protocol OK: {proto}", Severity.INFO, target=target))

        if cipher:
            findings.append(Finding(self.name, f"Cipher: {cipher[0]}", Severity.INFO, target=target))

        return findings
