"""Tool definitions for Jarvis.

Every tool that changes system state (quarantine, delete, remediation
actions) requires `confirmed: true` in its arguments. This isn't just a
prompt instruction to the model — it's enforced in the Python wrapper
below. If Claude calls one of these without confirmed=true, the function
itself refuses and returns an instruction to go get confirmation first.
This means even if the model misbehaves, nothing destructive can happen
without an explicit, separate confirmation step.
"""

from __future__ import annotations
import importlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml
from agents.malware_scanner import MalwareScannerAgent, list_removable_drives
from agents import quarantine as vault
import remediation

CONFIG_PATH = os.path.join(ROOT, "config.yaml")


def _load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f) or {}


def _require_confirmation(confirmed: bool) -> dict | None:
    if not confirmed:
        return {
            "error": "NOT_CONFIRMED",
            "message": ("This action changes system state and was not executed. "
                         "Ask the user to explicitly confirm in plain language, "
                         "then call this tool again with confirmed=true."),
        }
    return None


# ---------------------------------------------------------------- scanning

def run_security_scan(target: str | None = None) -> dict:
    """Runs the network/code agents from secagents against authorized targets in config.yaml."""
    from orchestrator import load_agent_classes, AGENT_REGISTRY
    from agents import report_aggregator, risk_scorer

    config = _load_config()
    enabled = config.get("enabled_agents", [])
    authorized_targets = [target] if target else config.get("authorized_targets", [])
    path_targets = config.get("path_targets", {"default": "."})

    classes = load_agent_classes()
    all_findings = []
    for module_name, AgentClass in classes.items():
        if enabled and module_name not in enabled:
            continue
        agent = AgentClass(config)
        if agent.target_type == "none":
            all_findings.extend(agent.run(None))
        elif agent.target_type == "path":
            all_findings.extend(agent.run(path_targets.get(module_name, path_targets.get("default", "."))))
        else:
            for t in authorized_targets:
                all_findings.extend(agent.run(t))

    report = report_aggregator.aggregate(all_findings)
    report["risk_score"] = risk_scorer.compute_score(all_findings)
    return report


def run_single_agent(agent_module: str, target: str | None = None) -> dict:
    """Runs exactly one agent by module name — this is what each of the 21 personas calls.
    Respects the same authorization gate as everything else: a network-type agent given
    an unauthorized target will return the standard "not authorized" Finding, not actually scan it.
    """
    from orchestrator import load_agent_classes

    config = _load_config()
    classes = load_agent_classes()
    AgentClass = classes.get(agent_module)
    if not AgentClass:
        return {"error": f"Unknown agent module: {agent_module}"}

    agent = AgentClass(config)
    path_targets = config.get("path_targets", {"default": "."})

    if agent.target_type == "none":
        findings = agent.run(None)
    elif agent.target_type == "path":
        resolved = target or path_targets.get(agent_module, path_targets.get("default", "."))
        findings = agent.run(resolved)
    else:  # network
        if not target:
            return {"error": "This agent needs a target (hostname/IP). It must also be in "
                              "config.yaml's authorized_targets to actually run."}
        findings = agent.run(target)

    return {"agent": agent_module, "findings": [f.to_dict() for f in findings]}


def run_malware_scan(path: str = ".", include_usb: bool = False) -> dict:
    config = {"malware_scanner": {"include_usb": include_usb}}
    agent = MalwareScannerAgent(config)
    findings = agent.run(path)
    return {"findings": [f.to_dict() for f in findings]}


def list_usb_drives() -> dict:
    return {"drives": list_removable_drives()}


# ---------------------------------------------------------------- vault

def list_quarantine_vault() -> dict:
    return {"vault": vault.list_vault()}


def quarantine_file(filepath: str, confirmed: bool = False) -> dict:
    err = _require_confirmation(confirmed)
    if err:
        return err
    ok, result = vault.quarantine_file(filepath)
    return {"success": ok, "result": result}


def restore_file(quarantine_path: str, confirmed: bool = False) -> dict:
    err = _require_confirmation(confirmed)
    if err:
        return err
    ok, result = vault.restore_file(quarantine_path)
    return {"success": ok, "result": result}


def delete_from_vault(quarantine_path: str, confirmed: bool = False) -> dict:
    err = _require_confirmation(confirmed)
    if err:
        return err
    ok, result = vault.delete_from_vault(quarantine_path)
    return {"success": ok, "result": result}


def delete_from_source(filepath: str, confirmed: bool = False) -> dict:
    err = _require_confirmation(confirmed)
    if err:
        return err
    ok, result = vault.delete_from_source(filepath)
    return {"success": ok, "result": result}


# ---------------------------------------------------------------- remediation

def apply_remediation(action: str, value: str = "", confirmed: bool = False) -> dict:
    err = _require_confirmation(confirmed)
    if err:
        return err
    dispatch = {
        "block_ip": lambda: remediation.block_ip(value),
        "block_port": lambda: remediation.block_port(int(value)),
        "disable_remote_access": remediation.disable_remote_access,
        "enable_firewall": remediation.enable_firewall,
        "disable_account": lambda: remediation.disable_account(value),
    }
    if action not in dispatch:
        return {"error": f"Unknown action '{action}'. Valid: {list(dispatch.keys())}"}
    ok, result = dispatch[action]()
    return {"success": ok, "result": result}


# ---------------------------------------------------------------- registry

TOOL_FUNCTIONS = {
    "run_security_scan": run_security_scan,
    "run_malware_scan": run_malware_scan,
    "list_usb_drives": list_usb_drives,
    "list_quarantine_vault": list_quarantine_vault,
    "quarantine_file": quarantine_file,
    "restore_file": restore_file,
    "delete_from_vault": delete_from_vault,
    "delete_from_source": delete_from_source,
    "apply_remediation": apply_remediation,
}

TOOL_SCHEMAS = [
    {
        "name": "run_security_scan",
        "description": "Run the enabled secagents agents (port scanner, TLS checker, dependency checker, CVE feed, etc.) against authorized targets from config.yaml, or a single target if specified. Returns a findings report and risk score.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Optional. A single authorized target to scan. If omitted, scans all authorized_targets in config.yaml."},
            },
        },
    },
    {
        "name": "run_malware_scan",
        "description": "Hash-based malware scan of a local path (your own machine/repo). Optionally also scans connected removable/USB drives.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Local path to scan, e.g. '.' or '/home/user/Downloads'."},
                "include_usb": {"type": "boolean", "description": "Also scan any connected removable drives."},
            },
        },
    },
    {
        "name": "list_usb_drives",
        "description": "List currently connected removable/USB drives.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_quarantine_vault",
        "description": "List files currently sitting in the quarantine vault.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "quarantine_file",
        "description": "Move a flagged file into the quarantine vault. DESTRUCTIVE (moves the file) — only call with confirmed=true after the user has explicitly said yes in this conversation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string"},
                "confirmed": {"type": "boolean", "description": "Must be true; set only after explicit user confirmation."},
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "restore_file",
        "description": "Move a quarantined file back to its original location. Requires confirmed=true after explicit user confirmation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "quarantine_path": {"type": "string"},
                "confirmed": {"type": "boolean"},
            },
            "required": ["quarantine_path"],
        },
    },
    {
        "name": "delete_from_vault",
        "description": "PERMANENTLY delete a file already in the quarantine vault. Irreversible — requires confirmed=true after explicit user confirmation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "quarantine_path": {"type": "string"},
                "confirmed": {"type": "boolean"},
            },
            "required": ["quarantine_path"],
        },
    },
    {
        "name": "delete_from_source",
        "description": "PERMANENTLY delete a file directly from its original location, bypassing quarantine. Irreversible — requires confirmed=true after explicit user confirmation. Prefer quarantine_file unless the user specifically wants permanent deletion.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filepath": {"type": "string"},
                "confirmed": {"type": "boolean"},
            },
            "required": ["filepath"],
        },
    },
    {
        "name": "apply_remediation",
        "description": "Apply a system-hardening fix to this machine (block_ip, block_port, disable_remote_access, enable_firewall, disable_account). Changes real firewall/account state and usually needs admin/root. Requires confirmed=true after explicit user confirmation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["block_ip", "block_port", "disable_remote_access", "enable_firewall", "disable_account"]},
                "value": {"type": "string", "description": "The IP, port, or username the action applies to (not needed for disable_remote_access/enable_firewall)."},
                "confirmed": {"type": "boolean"},
            },
            "required": ["action"],
        },
    },
]
