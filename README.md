# 👻 Ghost Tracker

> IP Intelligence Platform for network reconnaissance and red team engagements.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Category](https://img.shields.io/badge/Category-OSINT%20%7C%20Recon-red?style=flat-square)

---

## What it does

Ghost Tracker performs passive IP intelligence gathering using public OSINT APIs.
Given a single IP address it returns:

- **Geolocation** — country, region, city, coordinates, postal code, timezone
- **Network identity** — ASN, organisation, hostname resolution
- **Risk scoring** — automatic 0–100 score based on VPN/proxy/datacenter indicators
- **Connection flags** — VPN, Tor exit node, datacenter, mobile network, proxy detection
- **Batch analysis** — process a list of IPs from a file
- **Report export** — saves structured JSON reports per target

**No third-party libraries required.** Pure Python 3 standard library only.

---

## Demo

```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
  ...

  [*] Querying intelligence database for 8.8.8.8... done

  ══════════════════════════════════════════════════════════
  TARGET  8.8.8.8
  ══════════════════════════════════════════════════════════
  Hostname       dns.google
  Location       🇺🇸 Mountain View, California, United States (US)
  Coordinates    37.386, -122.0838  →  maps.google.com/@37.386,-122.0838,12z
  Postal code    94035
  Timezone       America/Los_Angeles
  In EU          No
  ASN            AS15169
  Organisation   AS15169 Google LLC
  ──────────────────────────────────────────────────────────
  Risk score     LOW    5/100
  ──────────────────────────────────────────────────────────
  Flags
    • No obvious anonymisation detected
  ══════════════════════════════════════════════════════════
```

---

## Installation

```bash
# Clone the repo
git clone https://github.com/YOUR-USERNAME/ghost-tracker.git
cd ghost-tracker

# No dependencies to install — runs on Python 3.8+
python3 ghost_tracker.py --help
```

---

## Usage

```bash
# Single IP lookup
python3 ghost_tracker.py 8.8.8.8

# Look up your own public IP
python3 ghost_tracker.py --me

# Verbose output (extended country data)
python3 ghost_tracker.py 1.1.1.1 --verbose

# Save JSON report to ./reports/
python3 ghost_tracker.py 8.8.8.8 --save

# Raw JSON output (pipe-friendly)
python3 ghost_tracker.py 8.8.8.8 --json

# Batch mode — one IP per line in a text file
python3 ghost_tracker.py --batch targets.txt --save

# Combined
python3 ghost_tracker.py 185.220.101.1 --verbose --save
```

### Batch file format (`targets.txt`)
```
# Lines starting with # are ignored
8.8.8.8
1.1.1.1
208.67.222.222
```

---

## Output files

Reports are saved to `./reports/` as JSON:

```
reports/
  ghost_8.8.8.8_20250601_143022.json
  ghost_1.1.1.1_20250601_143025.json
```

Each report contains:
- `generated` — ISO timestamp
- `risk_score` — 0–100 integer
- `flags` — list of detected indicators
- `raw` — full API response

---

## Risk scoring

| Score | Level  | Indicators                                   |
|-------|--------|----------------------------------------------|
| 70+   | HIGH   | VPN, proxy, Tor exit node detected            |
| 35–69 | MEDIUM | Datacenter/hosting IP, unresolved hostname    |
| 0–34  | LOW    | Residential or clean commercial IP            |

---

## Ethical use

This tool uses **passive, public OSINT only** — no active scanning, no packet injection, no exploitation.

- All data comes from the public [ipapi.co](https://ipapi.co) geolocation API
- IP geolocation is **approximate** (city-level at best) — not precise tracking
- Only use on IPs you own or have explicit authorisation to investigate
- Respect the API's rate limits (1 req/sec in batch mode is enforced)

---

## Project structure

```
ghost-tracker/
├── ghost_tracker.py   # Main CLI tool
├── requirements.txt   # Empty — no external deps
├── targets.txt        # Example batch file
├── reports/           # Auto-created on --save
└── README.md
```

---

## Part of my Red Team Portfolio

This tool is part of my cybersecurity portfolio demonstrating:

- OSINT and passive reconnaissance techniques
- Python CLI tooling and argument parsing
- API integration and structured data handling
- Professional report generation

**Portfolio:** [github.com/YOUR-USERNAME](https://github.com/YOUR-USERNAME)

---

## License

MIT — free to use, modify, and distribute. Attribution appreciated.
