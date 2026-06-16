# secagents — multi-agent security health scanner

A modular, 21-agent system that audits your own infrastructure and code,
and cross-references public threat intelligence so you know what's
relevant to your stack. Built to be cloned, configured, and run against
**systems you own or are explicitly authorized to test**.

## ⚠️ Authorization, not optional

Every network-scoped agent (port scanner, TLS checker, DNS health, etc.)
refuses to run against any host that isn't explicitly listed in your
`config.yaml`'s `authorized_targets`. This is enforced in `agents/base.py`,
not just written here as a promise. Scanning systems you don't own or
don't have explicit written permission to test may violate computer crime
laws (the U.S. CFAA, the UK Computer Misuse Act, and equivalents
elsewhere) — that's on you, not the tool.

## Quick start

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
agents/base.py          BaseAgent class + the authorization gate
agents/<agent>.py        one file per agent (21 total)
config.yaml.example     template — copy to config.yaml and fill in your own targets
```

Each agent returns a list of `Finding` objects (title, severity, detail,
target). The orchestrator collects all of them, then hands them to the
report aggregator and risk scorer to produce the final output.

## The 21 agents

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

8 agents are fully implemented and tested; 12 are scaffolded with a clean
interface so they're straightforward to fill in (each has a `# TODO`
exactly where the logic goes). PRs welcome.

## Adding your own agent

1. Create `agents/your_agent.py`, subclass `BaseAgent`, implement `_run()`.
2. Set `target_type` to `"network"` (gated by `authorized_targets`),
   `"path"` (local file/dir you already own), or `"none"` (no target,
   e.g. a feed aggregator).
3. Register it in `AGENT_REGISTRY` in `orchestrator.py`.
4. Add it to `enabled_agents` in your `config.yaml`.

## License

MIT — see [LICENSE](LICENSE).
