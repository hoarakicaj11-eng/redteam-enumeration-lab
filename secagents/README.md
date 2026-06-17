# secagents — multi-agent security health scanner + Jarvis

A modular security toolkit for your own infrastructure, code, and
endpoints — with a natural-language assistant ("Jarvis") sitting on top
so you can drive it conversationally instead of editing YAML and running
scripts by hand. Built to be cloned, configured, and run against
**systems you own or are explicitly authorized to test**.

## Talking to Jarvis

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # get one at console.anthropic.com/settings/keys
cd jarvis
python3 jarvis.py
```

```
you> scan my downloads folder for malware
  [running run_malware_scan...]
jarvis> Scanned 142 files in ~/Downloads. No threats found.

you> what's open on my htb box
jarvis> I'll need that IP added to authorized_targets in config.yaml first —
        want me to walk you through that?
```

Jarvis can run security scans, malware scans, list/restore/delete from
the quarantine vault, and apply remediation fixes (block an IP/port,
disable remote access, enable the firewall, disable an account) — but
every destructive action requires you to explicitly confirm in the
conversation first. That's not just a prompt instruction; it's enforced
in `jarvis/tools.py` itself, so even if the model gets it wrong, nothing
destructive fires without a separate `confirmed=true` step that only
happens after you've said yes.

If you'd rather not run an LLM in the loop, every piece below also works
standalone from the command line — Jarvis is a convenience layer, not a
requirement.

## ⚠️ Authorization, not optional

Every network-scoped agent (port scanner, TLS checker, DNS health, etc.)
refuses to run against any host that isn't explicitly listed in your
`config.yaml`'s `authorized_targets`. This is enforced in `agents/base.py`,
not just written here as a promise. Scanning systems you don't own or
don't have explicit written permission to test may violate computer crime
laws (the U.S. CFAA, the UK Computer Misuse Act, and equivalents
elsewhere) — that's on you, not the tool.

## Quick start (without Jarvis)

```bash
git clone <your-repo-url>
cd secagents
pip install -r requirements.txt
cp config.yaml.example config.yaml
# edit config.yaml: add your own host(s)/domain(s) and local repo path(s)
python3 orchestrator.py
```

Output: `report.md` (human-readable) and `report.json` (machine-readable),
plus a 0–100 risk score printed to the console.

## Architecture

```
orchestrator.py        loads config.yaml, runs enabled agents, writes report
remediation.py          OS-aware fix actions (firewall, remote access, accounts)
agents/base.py          BaseAgent class + the authorization gate
agents/quarantine.py     vault: quarantine / restore / delete flagged files
agents/<agent>.py        one file per agent (22 total)
jarvis/jarvis.py         conversational front-end (Claude + tool use)
jarvis/tools.py           tool schemas + the confirmation gate for destructive actions
config.yaml.example     template — copy to config.yaml and fill in your own targets
```

Each agent returns a list of `Finding` objects (title, severity, detail,
target). The orchestrator collects all of them, then hands them to the
report aggregator and risk scorer to produce the final output. Jarvis
calls the exact same functions under the hood — it's not a separate
implementation.

## The agents

Status legend: ✅ implemented and tested · 🚧 scaffolded (interface wired up, logic is a TODO)

**Network & Infrastructure**
| Agent | Status | Does |
|---|---|---|
| `port_scanner` | ✅ | Threaded TCP connect scan + banner grabbing |
| `tls_checker` | ✅ | Certificate expiry, protocol/cipher strength |
| `dns_health` | ✅ | A/MX/NS records, SPF/DMARC presence |
| `firewall_audit` | 🚧 | Parse firewall rule exports, flag overly permissive rules |
| `network_topology` | 🚧 | Traceroute/latency mapping of your own hosts |

**Web Application**
| Agent | Status | Does |
|---|---|---|
| `http_headers` | ✅ | Checks for missing security headers (CSP, HSTS, etc.) |
| `cookie_security` | 🚧 | Secure/HttpOnly/SameSite flag checks |
| `open_redirect_checker` | 🚧 | Open redirects, exposed dir listings, default pages |
| `ct_monitor` | 🚧 | Certificate Transparency log monitoring (crt.sh) |

**Code & Supply Chain**
| Agent | Status | Does |
|---|---|---|
| `secrets_scanner` | ✅ | Regex scan of a local repo for exposed keys/tokens |
| `dependency_checker` | ✅ | Checks pinned versions against OSV.dev |
| `license_checker` | 🚧 | Flags risky OSS licenses in dependencies |
| `git_history_scanner` | 🚧 | Scans full git history for removed-but-leaked secrets |

**Endpoint**
| Agent | Status | Does |
|---|---|---|
| `malware_scanner` | ✅ | Hash-based scan + autorun check, optionally including USB drives |

**Threat Intelligence**
| Agent | Status | Does |
|---|---|---|
| `cve_feed` | ✅ | Recent CVEs from the public NVD feed, keyword-filterable |
| `advisory_aggregator` | 🚧 | GitHub Security Advisories for your dependencies |
| `breach_news_monitor` | 🚧 | Public breach-disclosure headlines |
| `threat_actor_tracker` | 🚧 | Public threat-intel summaries (e.g. CISA advisories) |

**Monitoring & Reporting**
| Agent | Status | Does |
|---|---|---|
| `log_anomaly` | 🚧 | Parses logs for brute-force/scan patterns |
| `diff_tracker` | 🚧 | Diffs this run's report against the last one |
| `report_aggregator` | ✅ | Builds the unified Markdown + JSON report |
| `risk_scorer` | ✅ | Computes the 0–100 weighted risk score |

9 agents are fully implemented and tested; 12 are scaffolded with a clean
interface so they're straightforward to fill in (each has a `# TODO`
exactly where the logic goes). PRs welcome.

## Quarantine vault and remediation

`agents/quarantine.py` holds flagged files in `~/.secagents_vault`
(outside the repo) along with a log of their original location, so they
can be restored. Nothing gets permanently deleted without going through
this — or you can call `delete_from_source` directly if you really want
to skip quarantine.

`remediation.py` applies real, OS-aware hardening fixes: blocking an IP
or port at the firewall, disabling remote access (RDP on Windows, Remote
Login/SSH on macOS/Linux), enabling the firewall, or disabling a user
account. Most need admin/root. None of them prompt for confirmation
themselves by design — that responsibility sits one layer up, in the CLI
or in Jarvis, so the same confirm-then-execute pattern is consistent
everywhere.

## Adding your own agent

1. Create `agents/your_agent.py`, subclass `BaseAgent`, implement `_run()`.
2. Set `target_type` to `"network"` (gated by `authorized_targets`),
   `"path"` (local file/dir you already own), or `"none"` (no target,
   e.g. a feed aggregator).
3. Register it in `AGENT_REGISTRY` in `orchestrator.py`.
4. Add it to `enabled_agents` in your `config.yaml`.
5. If you want Jarvis to be able to call it conversationally, add a
   schema + dispatch entry in `jarvis/tools.py`.

## License

MIT — see [LICENSE](LICENSE).
