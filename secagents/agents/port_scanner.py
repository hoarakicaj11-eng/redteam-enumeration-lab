"""Agent 1/21 — Port & Service Scanner.

Threaded TCP connect scan with lightweight banner grabbing. This is the
core network-facing agent; everything else in the Network & Infrastructure
category builds on top of what this one discovers.
"""

from __future__ import annotations
import concurrent.futures
import socket

from agents.base import BaseAgent, Finding, Severity

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Ports flagged as higher risk when found open on the public internet
RISKY_PORTS = {23: "Telnet (unencrypted)", 3389: "RDP", 445: "SMB", 6379: "Redis (often unauthenticated)"}


def _grab_banner(sock: socket.socket, port: int) -> str | None:
    try:
        sock.settimeout(1.0)
        if port in (80, 8080, 443, 8443):
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner[:200] if banner else None
    except Exception:
        return None


def _scan_port(ip: str, port: int, timeout: float):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return port, True, _grab_banner(s, port)
            return port, False, None
    except Exception:
        return port, False, None


class PortScannerAgent(BaseAgent):
    name = "port_scanner"
    category = "network"
    description = "TCP connect scan with service/banner detection"

    def _run(self, target: str) -> list[Finding]:
        port_range = self.config.get("port_scanner", {}).get("ports", "1-1024")
        threads = self.config.get("port_scanner", {}).get("threads", 50)
        timeout = self.config.get("port_scanner", {}).get("timeout", 1.0)

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            return [Finding(self.name, "Could not resolve target", Severity.INFO, target=target)]

        ports = self._parse_ports(port_range)
        findings: list[Finding] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(_scan_port, ip, p, timeout) for p in ports]
            for future in concurrent.futures.as_completed(futures):
                port, is_open, banner = future.result()
                if not is_open:
                    continue
                service = COMMON_PORTS.get(port, "unknown")
                severity = Severity.MEDIUM if port in RISKY_PORTS else Severity.INFO
                detail = banner or f"Service identified as {service}"
                if port in RISKY_PORTS:
                    detail += f" — {RISKY_PORTS[port]} flagged as commonly risky when internet-facing"
                findings.append(Finding(
                    agent=self.name,
                    title=f"Open port {port}/tcp ({service})",
                    severity=severity,
                    detail=detail,
                    target=target,
                    raw={"port": port, "service": service, "banner": banner},
                ))

        if not findings:
            findings.append(Finding(self.name, "No open ports found in scanned range", Severity.INFO, target=target))
        return findings

    @staticmethod
    def _parse_ports(port_arg: str) -> list[int]:
        ports: list[int] = []
        for part in port_arg.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports
