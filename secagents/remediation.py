"""Remediation actions — apply common hardening fixes to YOUR OWN machine.

Every function here changes real system state (firewall rules, remote
access settings, account status) and most require admin/root. None of
them prompt for confirmation themselves — by design, the caller (CLI or
Jarvis) must get explicit user confirmation before calling any of these,
exactly like the original tool's askyesno() dialogs.

Cross-platform where the underlying OS concept actually exists; clearly
returns "not supported on this OS" rather than guessing when it doesn't
(e.g. there's no real Windows-RDP equivalent on Linux).
"""

from __future__ import annotations
import platform
import subprocess


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return True, result.stdout.strip()
        return False, result.stderr.strip() or result.stdout.strip()
    except Exception as e:
        return False, str(e)


def block_ip(ip: str) -> tuple[bool, str]:
    system = platform.system()
    if system == "Windows":
        return _run(["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"])
    if system == "Linux":
        return _run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    if system == "Darwin":
        # macOS's pf needs an anchor file set up beforehand; flagging as manual step.
        return False, ("macOS firewall blocking requires a pf anchor rule — "
                        "see README for the one-time pf setup, then re-run.")
    return False, f"Unsupported OS: {system}"


def block_port(port: int) -> tuple[bool, str]:
    system = platform.system()
    if system == "Windows":
        return _run(["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name=Block_Port_{port}", "dir=in", "action=block",
                      "protocol=TCP", f"localport={port}"])
    if system == "Linux":
        return _run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])
    if system == "Darwin":
        return False, "macOS port blocking requires a pf anchor rule — see README."
    return False, f"Unsupported OS: {system}"


def disable_remote_access() -> tuple[bool, str]:
    """Disables RDP on Windows, or Remote Login (SSH) on macOS."""
    system = platform.system()
    if system == "Windows":
        return _run(["reg", "add",
                      "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                      "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"])
    if system == "Darwin":
        return _run(["sudo", "systemsetup", "-f", "-setremotelogin", "off"])
    if system == "Linux":
        return _run(["sudo", "systemctl", "stop", "ssh"])
    return False, f"Unsupported OS: {system}"


def enable_firewall() -> tuple[bool, str]:
    system = platform.system()
    if system == "Windows":
        return _run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
    if system == "Darwin":
        return _run(["sudo", "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"])
    if system == "Linux":
        return _run(["sudo", "ufw", "enable"])
    return False, f"Unsupported OS: {system}"


def disable_account(username: str) -> tuple[bool, str]:
    system = platform.system()
    if system == "Windows":
        return _run(["net", "user", username, "/active:no"])
    if system == "Linux":
        return _run(["sudo", "usermod", "-L", username])
    if system == "Darwin":
        return _run(["sudo", "sysadminctl", "-deleteUser", username, "-keepHome"])
    return False, f"Unsupported OS: {system}"
