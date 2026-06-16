"""Agent 10/21 — Secrets Scanner.

Walks a local directory (your own repo) looking for common patterns of
accidentally-committed credentials: API keys, private keys, tokens, etc.
Operates on a local path you already own, so it is not network-authorization
-gated — but it never reads outside the given path.
"""

from __future__ import annotations
import os
import re

from agents.base import BaseAgent, Finding, Severity

PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key": re.compile(r"(?i)(api[_-]?key|secret[_-]?key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "Generic Bearer Token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}"),
}

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".lock"}
MAX_FILE_SIZE = 2_000_000  # skip files over ~2MB


class SecretsScannerAgent(BaseAgent):
    name = "secrets_scanner"
    category = "code"
    description = "Regex-based scan for exposed API keys, tokens, and private keys"
    target_type = "path"

    def _run(self, target: str) -> list[Finding]:
        if not os.path.isdir(target):
            return [Finding(self.name, "Target path not found or not a directory", Severity.INFO, target=target)]

        findings: list[Finding] = []
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if os.path.splitext(fname)[1].lower() in SKIP_EXT:
                    continue
                path = os.path.join(root, fname)
                try:
                    if os.path.getsize(path) > MAX_FILE_SIZE:
                        continue
                    with open(path, "r", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                for label, pattern in PATTERNS.items():
                    for match in pattern.finditer(content):
                        line_no = content[:match.start()].count("\n") + 1
                        findings.append(Finding(
                            agent=self.name,
                            title=f"Possible {label} found",
                            severity=Severity.HIGH,
                            detail=f"{os.path.relpath(path, target)}:{line_no}",
                            target=target,
                        ))

        if not findings:
            findings.append(Finding(self.name, "No obvious secrets found", Severity.INFO, target=target))
        return findings
