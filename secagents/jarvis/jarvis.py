#!/usr/bin/env python3
"""
jarvis.py — the conversational front-end for this project.

Talk to it in plain English; it calls the security agents, malware
scanner, quarantine vault, and remediation actions on your behalf. Every
destructive action (quarantine, delete, firewall/account changes) needs
you to explicitly say yes before it actually happens — that's enforced
in code (see tools.py), not just left to the model's judgment.

Setup:
    pip install anthropic
    export ANTHROPIC_API_KEY=sk-ant-...   (get one at console.anthropic.com)
    python3 jarvis/jarvis.py
"""

from __future__ import annotations
import json
import os
import sys

try:
    import anthropic
except ImportError:
    print("Missing dependency. Run: pip install anthropic")
    sys.exit(1)

from tools import TOOL_SCHEMAS, TOOL_FUNCTIONS

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")

SYSTEM_PROMPT = """You are Jarvis, a security operations assistant running locally on the \
user's own machine(s) and lab environment. You have tools to run security scans, scan for \
malware, manage a quarantine vault, and apply system remediation actions (firewall rules, \
disabling remote access, disabling accounts).

Hard rules:
1. Only ever act on systems the user owns or has explicit authorization to test. The \
   underlying tools already enforce an authorized_targets allowlist from config.yaml for \
   network scans — don't try to talk your way around it.
2. quarantine_file, restore_file, delete_from_vault, delete_from_source, and \
   apply_remediation all change real state on the user's machine. Before calling any of \
   them, explain in plain language exactly what will happen and ask the user to confirm. \
   Only call the tool with confirmed=true after the user has clearly said yes in this \
   conversation. Never set confirmed=true preemptively or speculatively.
3. When a scan finds something, summarize it clearly (what was found, how severe, what it \
   means) before suggesting next steps. Don't just dump raw JSON at the user.
4. Be direct and concise. This is a working security tool, not a chatbot performance.
"""


def call_tool(name: str, tool_input: dict) -> str:
    fn = TOOL_FUNCTIONS.get(name)
    if not fn:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        result = fn(**tool_input)
    except Exception as e:
        result = {"error": str(e)}
    return json.dumps(result, default=str)


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ANTHROPIC_API_KEY is not set.")
        print("Get one at https://console.anthropic.com/settings/keys, then:")
        print("    export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    messages: list[dict] = []

    print("Jarvis is ready. Type a request, or 'exit' to quit.\n")

    while True:
        try:
            user_input = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if user_input.lower() in ("exit", "quit"):
            break
        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})

        while True:
            response = client.messages.create(
                model=MODEL,
                max_tokens=2000,
                system=SYSTEM_PROMPT,
                tools=TOOL_SCHEMAS,
                messages=messages,
            )

            text_parts = [block.text for block in response.content if block.type == "text"]
            tool_uses = [block for block in response.content if block.type == "tool_use"]

            if text_parts:
                print(f"jarvis> {' '.join(text_parts)}\n")

            messages.append({"role": "assistant", "content": response.content})

            if not tool_uses:
                break

            tool_results = []
            for tool_use in tool_uses:
                print(f"  [running {tool_use.name}...]")
                result_text = call_tool(tool_use.name, tool_use.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": result_text,
                })
            messages.append({"role": "user", "content": tool_results})
            # loop again so Claude can react to the tool result(s)


if __name__ == "__main__":
    main()
