"""Agent 4/21 — HTTP Security Headers Checker.

Fetches the target over HTTPS (falls back to HTTP) and checks for the
presence of standard browser security headers.
"""

from __future__ import annotations

from agents.base import BaseAgent, Finding, Severity

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

EXPECTED_HEADERS = {
    "Strict-Transport-Security": Severity.MEDIUM,
    "Content-Security-Policy": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.LOW,
    "X-Frame-Options": Severity.LOW,
    "Referrer-Policy": Severity.LOW,
    "Permissions-Policy": Severity.LOW,
}


class HTTPHeadersAgent(BaseAgent):
    name = "http_headers"
    category = "web"
    description = "Checks for missing standard browser security headers"

    def _run(self, target: str) -> list[Finding]:
        if requests is None:
            return [Finding(self.name, "requests not installed", Severity.INFO,
                             detail="pip install requests", target=target)]

        url = target if target.startswith("http") else f"https://{target}"
        try:
            resp = requests.get(url, timeout=5, allow_redirects=True)
        except Exception:
            try:
                url = f"http://{target}"
                resp = requests.get(url, timeout=5, allow_redirects=True)
            except Exception as e:
                return [Finding(self.name, "Could not fetch target over HTTP(S)", Severity.INFO,
                                 detail=str(e), target=target)]

        findings: list[Finding] = []
        for header, severity in EXPECTED_HEADERS.items():
            if header in resp.headers:
                findings.append(Finding(self.name, f"{header} present", Severity.INFO,
                                         detail=resp.headers[header][:150], target=target))
            else:
                findings.append(Finding(self.name, f"Missing header: {header}", severity, target=target))

        server_header = resp.headers.get("Server")
        if server_header:
            findings.append(Finding(self.name, f"Server header reveals: {server_header}", Severity.LOW,
                                     detail="Consider suppressing version info in the Server header",
                                     target=target))

        return findings
