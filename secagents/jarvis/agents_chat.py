#!/usr/bin/env python3
"""
agents_chat.py — pick one of the 21 specialist personas and talk to just them.

Each persona only has access to its own agent's scan function (plus a
couple of extras for Hunter, the malware specialist). They stay in their
lane on purpose — ask Recon about TLS certs and it'll point you to Cipher
instead of guessing.

Setup is the same as jarvis.py:
    pip install anthropic
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 jarvis/agents_chat.py
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

import tools
from personas import PERSONAS, PERSONA_BY_ID

MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")


def _agent_target_type(agent_module: str) -> str:
    import importlib
    mod = importlib.import_module(f"agents.{agent_module}")
    cls = next(v for k, v in vars(mod).items()
               if isinstance(v, type) and getattr(v, "name", None) == agent_module)
    return cls.target_type


def build_persona(persona: dict) -> tuple[str, list[dict], dict]:
    """Returns (system_prompt, tool_schemas, tool_functions) for one persona."""
    name = persona["name"]
    tagline = persona["tagline"]
    voice = persona["voice"]

    if persona.get("is_overview"):
        system_prompt = (
            f"You are {name}, the overview specialist in a 21-agent security toolkit. "
            f"{voice} Your job: {tagline}. You have one tool, run_overview, which runs every "
            f"enabled agent from config.yaml and returns a full findings report plus a 0-100 "
            f"risk score. Summarize results clearly — what was found, how severe, what matters "
            f"most — rather than dumping raw JSON. If the user asks about one specific narrow "
            f"topic (e.g. just DNS, or just malware), tell them which specialist persona covers "
            f"that and suggest they talk to that one directly for more depth."
        )
        schemas = [{
            "name": "run_overview",
            "description": "Run all enabled agents and return the full report + risk score.",
            "input_schema": {"type": "object", "properties": {
                "target": {"type": "string", "description": "Optional single target; omit to scan everything in config.yaml."},
            }},
        }]
        functions = {"run_overview": lambda target=None: tools.run_security_scan(target)}
        return system_prompt, schemas, functions

    agent_module = persona["agent_module"]
    target_type = _agent_target_type(agent_module)

    if target_type == "network":
        target_hint = ("This agent scans a network host. The target must be a hostname/IP "
                        "already listed in config.yaml's authorized_targets — if it isn't, "
                        "the scan will be refused automatically. Ask the user for the target "
                        "if they haven't given you one.")
    elif target_type == "path":
        target_hint = ("This agent scans a local file/directory the user owns. Ask for a path "
                        "if they haven't given you one, or use '.' for the current directory.")
    else:
        target_hint = "This agent doesn't take a target — it pulls from a public feed."

    system_prompt = (
        f"You are {name}, one of 21 specialist personas in a security toolkit. "
        f"{voice} Your specialty: {tagline}. {target_hint}\n\n"
        f"Stay in character and stay in your lane — you only know about your own specialty. "
        f"If the user asks about something outside it (e.g. they ask you about TLS certs but "
        f"you're the DNS specialist), tell them which other persona covers that and suggest "
        f"they switch. Summarize findings clearly in your own words rather than dumping raw "
        f"JSON at them."
    )

    schemas = [{
        "name": "run_check",
        "description": f"Run your {agent_module} check.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string", "description": target_hint},
        }},
    }]
    functions = {"run_check": lambda target=None: tools.run_single_agent(agent_module, target)}

    if "extra_tools" in persona:
        for tool_name in persona["extra_tools"]:
            schema = next(t for t in tools.TOOL_SCHEMAS if t["name"] == tool_name)
            schemas.append(schema)
            functions[tool_name] = tools.TOOL_FUNCTIONS[tool_name]
        system_prompt += (
            "\n\nYou also have quarantine tools. Before calling quarantine_file, explain what "
            "will happen and get explicit confirmation from the user, then call it with "
            "confirmed=true only after they've said yes."
        )

    return system_prompt, schemas, functions


def call_tool(functions: dict, name: str, tool_input: dict) -> str:
    fn = functions.get(name)
    if not fn:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        result = fn(**tool_input)
    except Exception as e:
        result = {"error": str(e)}
    return json.dumps(result, default=str)


def show_menu():
    print("\nPick a specialist:\n")
    for i, p in enumerate(PERSONAS, 1):
        print(f"  {i:>2}. {p['name']:<11} — {p['tagline']}")
    print()


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ANTHROPIC_API_KEY is not set. Get one at console.anthropic.com, then:")
        print("    export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)
    client = anthropic.Anthropic(api_key=api_key)

    show_menu()
    choice = input("Talk to (number or name): ").strip().lower()

    persona = None
    if choice.isdigit() and 1 <= int(choice) <= len(PERSONAS):
        persona = PERSONAS[int(choice) - 1]
    else:
        persona = next((p for p in PERSONAS if p["id"] == choice or p["name"].lower() == choice), None)

    if not persona:
        print("Didn't recognize that — run again and pick a number from the list.")
        sys.exit(1)

    system_prompt, schemas, functions = build_persona(persona)
    print(f"\nYou're now talking to {persona['name']} — {persona['tagline']}")
    print("Type 'exit' to quit, or 'switch' to pick a different specialist.\n")

    messages: list[dict] = []
    while True:
        try:
            user_input = input(f"you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if user_input.lower() in ("exit", "quit"):
            break
        if user_input.lower() == "switch":
            return main()
        if not user_input:
            continue

        messages.append({"role": "user", "content": user_input})

        while True:
            response = client.messages.create(
                model=MODEL, max_tokens=2000, system=system_prompt,
                tools=schemas, messages=messages,
            )
            text_parts = [b.text for b in response.content if b.type == "text"]
            tool_uses = [b for b in response.content if b.type == "tool_use"]

            if text_parts:
                print(f"{persona['name']}> {' '.join(text_parts)}\n")

            messages.append({"role": "assistant", "content": response.content})

            if not tool_uses:
                break

            tool_results = []
            for tu in tool_uses:
                print(f"  [{persona['name']} is running {tu.name}...]")
                result_text = call_tool(functions, tu.name, tu.input)
                tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": result_text})
            messages.append({"role": "user", "content": tool_results})


if __name__ == "__main__":
    main()
