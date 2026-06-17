"""Quarantine vault — move flagged files somewhere safe instead of
deleting them outright, with a log of where they came from so they can
be restored. Every destructive action here requires the caller to have
already confirmed with the user; this module does not prompt itself, so
it's usable both from the CLI and from Jarvis.
"""

from __future__ import annotations
import json
import os
import shutil
import time

VAULT_DIR = os.path.join(os.path.expanduser("~"), ".secagents_vault")
LOG_PATH = os.path.join(VAULT_DIR, "quarantine_log.json")


def _ensure_vault():
    os.makedirs(VAULT_DIR, exist_ok=True)
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "w") as f:
            json.dump([], f)


def _load_log() -> list[dict]:
    _ensure_vault()
    try:
        with open(LOG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_log(log: list[dict]):
    with open(LOG_PATH, "w") as f:
        json.dump(log, f, indent=2)


def quarantine_file(filepath: str) -> tuple[bool, str]:
    """Move a file into the vault. Returns (success, vault_path_or_error)."""
    _ensure_vault()
    if not os.path.isfile(filepath):
        return False, f"File not found: {filepath}"

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    safe_name = f"{timestamp}_{os.path.basename(filepath)}"
    vault_path = os.path.join(VAULT_DIR, safe_name)

    try:
        shutil.move(filepath, vault_path)
    except Exception as e:
        return False, str(e)

    log = _load_log()
    log.append({
        "original_path": filepath,
        "quarantine_path": vault_path,
        "timestamp": timestamp,
    })
    _save_log(log)
    return True, vault_path


def list_vault() -> list[dict]:
    """Returns log entries for files still present in the vault."""
    return [entry for entry in _load_log() if os.path.exists(entry["quarantine_path"])]


def restore_file(quarantine_path: str) -> tuple[bool, str]:
    """Move a quarantined file back to its original location."""
    log = _load_log()
    entry = next((e for e in log if e["quarantine_path"] == quarantine_path), None)
    if not entry:
        return False, "Not found in quarantine log"
    if not os.path.exists(quarantine_path):
        return False, "File missing from vault on disk"
    try:
        os.makedirs(os.path.dirname(entry["original_path"]), exist_ok=True)
        shutil.move(quarantine_path, entry["original_path"])
    except Exception as e:
        return False, str(e)
    log.remove(entry)
    _save_log(log)
    return True, entry["original_path"]


def delete_from_vault(quarantine_path: str) -> tuple[bool, str]:
    """Permanently delete a file already sitting in the vault."""
    if not os.path.exists(quarantine_path):
        return False, "File not found in vault"
    try:
        os.remove(quarantine_path)
    except Exception as e:
        return False, str(e)
    log = [e for e in _load_log() if e["quarantine_path"] != quarantine_path]
    _save_log(log)
    return True, "deleted"


def delete_from_source(filepath: str) -> tuple[bool, str]:
    """Permanently delete a file directly from its original location (no quarantine step)."""
    if not os.path.isfile(filepath):
        return False, "File not found"
    try:
        os.remove(filepath)
        return True, "deleted"
    except Exception as e:
        return False, str(e)
