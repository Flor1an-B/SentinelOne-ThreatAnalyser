# SentinelOne Threats Analyzer

> **Deep-dive forensic threat analysis from a single SentinelOne Storyline ID.**

SentinelOne Threats Analyzer is a Python CLI tool that connects to your SentinelOne console, pulls every available piece of forensic data for a given threat (events, timeline, agent info), analyses it, and produces four output formats simultaneously:

| Format | Description |
|--------|-------------|
| **Terminal** | Rich-powered interactive report with colour-coded tables, process tree, and SOC recommendations |
| **HTML** | Self-contained interactive dashboard — dark SOC theme, sidebar navigation, search, charts, VT/Shodan links |
| **Markdown** | Structured analyst report for ticket systems, wikis, and documentation |
| **CSV** | Raw events export for SIEM ingestion or custom analysis |

---

## Features

### Analysis Engine
- **Intelligent Narrative** — dynamic phase-by-phase incident reconstruction (Initial Execution → Process Chain → File System → Registry → Network/C2 → Credentials → Persistence → Ransomware → MITRE Kill Chain → Detection & Response), adapts to whatever data is available, no LLM required
- **Executive Summary** — auto-generated plain-English narrative answering *What happened, When, Where, and How*
- **Attack Type Classification** — heuristic cascade: Ransomware → Process Injection → Lateral Movement → RAT/C2 → Persistence → Credential Access → MITRE fallback → Generic Malware
- **MITRE ATT&CK Mapping** — extracted from SentinelOne indicators with tactic/technique/link
- **Process Tree Reconstruction** — full parent-child execution chain from `processUniqueKey` / `parentProcessUniqueKey`
- **Encryption / Ransomware Detection** — `.locked` extension heuristic + high file-modification volume from threat processes
- **IOC Extraction** — network IOCs (IPs, domains, URLs), file hash IOCs (SHA1, SHA256, MD5), suspicious registry keys
- **Threat Process Scope** — strict seed-based filtering (`core_process_keys`) prevents sibling and descendant benign processes (browsers, AI tools, git, etc.) from polluting IOC and narrative evidence, even when SentinelOne marks the entire storyline `relatedToThreat`
- **SOC Recommendations** — contextual, prioritised action items (CRITICAL/HIGH/MEDIUM/LOW) generated from findings

### HTML Report
- Dark glassmorphism SOC dashboard (zero external dependencies — pure CSS + vanilla JS)
- Sidebar navigation with per-section event count badges
- Animated stat counters and event type distribution bar chart
- Sortable tables with live search filter in every section
- Copy-to-clipboard on all hashes, IPs, paths, and commands
- **VirusTotal** and **Shodan** external lookup links on all IOC values
- **Triggers-only toggle** in All Events — isolates detection-relevant events instantly
- **Scheduled Tasks** dedicated tab
- **Login anomaly detection** — highlights FAILED logins and SUSPICIOUS accounts (admin, INTERACTIVE from threat process, NETWORK/BATCH/SERVICE)
- Keyboard shortcuts: `1`–`0` jump to sections, `Ctrl+F` focuses active search, `?` opens shortcuts modal
- Print-friendly CSS

### Terminal Report
- Rich-powered with colour-coded severity, Unicode tree view, key/value panels
- Executive summary with When? / Origin? / Key Indicators panels
- Commands that triggered detection table
- SOC Recommendations with priority colours
- Login anomaly warnings with FAILED/SUSPICIOUS flags
- Per-category event tables filtered to threat-relevant processes

---

## Requirements

- Python **3.9+**
- SentinelOne console access with an API token

```
requests>=2.31.0
rich>=13.7.0
python-dateutil>=2.8.2
urllib3>=2.0.0
```

Install:
```bash
pip install -r requirements.txt
```

---

## Quick Start

### 1. Set your API token (recommended)
```bash
# Linux / macOS
export S1_API_KEY="your_api_token_here"

# Windows (PowerShell)
$env:S1_API_KEY = "your_api_token_here"

# Windows (CMD)
set S1_API_KEY=your_api_token_here
```

### 2. Run the analyser
```bash
python main.py \
  --url https://your-console.sentinelone.net \
  --storyline 0000C2E97648XXXX
```

If `S1_API_KEY` is not set, you will be prompted securely (input is hidden, never stored).

### 3. Find your reports
All reports are saved in a dedicated subfolder:
```
<output_dir>/YYYY-MM-DD_HH-MM-SS_<storyline>/
  S1_Events_<storyline>_<ts>.csv
  S1_ThreatReport_<storyline>_<ts>.md
  S1_ThreatReport_<storyline>_<ts>.html
```

Example: `./reports/2026-02-25_14-30-00_0000C2E97648XXXX/`

---

## Usage

```
usage: sentinelone_threats_analyzer [-h] -u SERVER_URL -s STORYLINE_ID
                          [-o DIR]
                          [--no-csv] [--no-markdown] [--no-html] [--no-terminal]
                          [-v]

required arguments:
  -u, --url SERVER_URL        SentinelOne console URL (e.g. https://your-console.sentinelone.net)
  -s, --storyline STORYLINE_ID
                              Storyline ID of the threat to analyse

output options:
  -o, --output DIR            Output directory (default: current directory)
  --no-csv                    Skip CSV export
  --no-markdown               Skip Markdown report
  --no-html                   Skip HTML report
  --no-terminal               Skip terminal output
  -v, --verbose               Show full API errors and HTTP debug details
```

### Examples

```bash
# Basic analysis, all reports
python main.py -u https://acme.sentinelone.net -s 0000C2E97648XXXX

# Save reports to a specific folder, skip terminal output
python main.py -u https://acme.sentinelone.net -s 0000C2E97648XXXX -o /var/reports --no-terminal

# HTML only with verbose API logging
python main.py -u https://acme.sentinelone.net -s 0000C2E97648XXXX --no-csv --no-markdown -v

# CI / non-interactive mode
S1_API_KEY="$TOKEN" python main.py -u "$S1_URL" -s "$STORYLINE" --no-terminal
```

---

## API Token Requirements

The API token must have the following SentinelOne permissions:

| Scope | Permission |
|-------|-----------|
| Threats | View |
| Endpoint Forensics | View |
| Threat Forensics | View |

> The token is **never accepted as a CLI argument** to prevent it from appearing in shell history, `/proc/PID/cmdline`, or log files.

---

## Project Structure

```
S1_ThreatAnalyser/
├── main.py                        # CLI entry point
├── requirements.txt
├── README.md
├── CHANGELOG.md
├── LICENSE
│
└── s1_analyser/
    ├── __init__.py
    ├── api_client.py              # SentinelOne REST API v2.1 client
    │                              #   – pagination, retry, rate-limit handling
    ├── data_collector.py          # Orchestrates API calls → AnalysisBundle
    ├── analyzer.py                # Core analysis engine
    │                              #   – event categorisation
    │                              #   – IOC extraction
    │                              #   – MITRE ATT&CK mapping
    │                              #   – ExecutiveSummary generation
    │                              #   – SocRecommendation engine
    │                              #   – threat process scoping
    ├── process_tree.py            # ProcessNode tree from event keys
    │
    └── reporters/
        ├── terminal_reporter.py   # Rich-powered console output
        ├── csv_reporter.py        # Raw events CSV export
        ├── markdown_reporter.py   # Structured Markdown analyst report
        └── html_reporter.py      # Self-contained interactive HTML dashboard
```

---

## How It Works

```
 SentinelOne API v2.1
        │
        ▼
  DataCollector
  ┌─────────────────────────────────────────────┐
  │  GET /threats?storyline__contains=<id>       │  → threat info, agent info
  │  GET /threats/{id}/explore/events (paginated)│  → all forensic events
  │  GET /threats/{id}/timeline                  │  → activity timeline
  └─────────────────────────────────────────────┘
        │
        ▼ AnalysisBundle
  ThreatAnalyzer
  ┌─────────────────────────────────────────────┐
  │  categorise_events()     → by objectType     │
  │  build_threat_keys()     → seed + ancestors  │
  │  detect_encryption()     → ransomware heur.  │
  │  extract_mitre()         → techniques/links  │
  │  build_iocs()            → net + file hashes │
  │  build_executive_summary()→ narrative, chain │
  │  build_soc_recommendations()→ action items  │
  └─────────────────────────────────────────────┘
        │
        ▼ AnalysisResult
  ┌──────────┬─────────┬─────────────┬──────────┐
  │ Terminal │   CSV   │  Markdown   │   HTML   │
  └──────────┴─────────┴─────────────┴──────────┘
```

---

## Output Details

### HTML Dashboard Sections

| Key | Section | Description |
|-----|---------|-------------|
| `1` | Overview | Exec summary, SOC recs, alerts, threat & host details, detection triggers |
| `2` | Narrative | Phase-by-phase intelligent incident reconstruction with severity badges and MITRE tags |
| `3` | Process Tree | Interactive collapsible tree — red = malicious/trigger |
| `4` | All Events | Full timeline with search + Triggers-only toggle |
| `5` | Files | File creation/modification/rename/deletion events |
| `6` | Registry | Registry operations (persistence keys highlighted) |
| `7` | Network | Connections and DNS lookups |
| `8` | Login | Account activity with anomaly detection |
| `9` | Sched. Tasks | Scheduled task creation/modification events |
| `0` | IOCs | Network IOCs (IPs, domains), file hashes, suspicious registry keys |
| — | MITRE ATT&CK | Technique cards grouped by tactic |

### Markdown Report Sections
1. Executive Summary (narrative + When/Origin/Key Indicators sub-sections)
2. Incident Narrative (phase-by-phase reconstruction)
3. Threat Details
4. Host Information
5. Detection Analysis
6. MITRE ATT&CK Mapping
7. Process Tree (ASCII)
8. File Activity
9. Registry Activity
10. Network Activity
11. Login & Account Activity
12. Scheduled Tasks
13. Ransomware / Encryption Indicators
14. Indicators of Compromise
15. SOC Analyst Recommendations
16. Attack Timeline (first 100 events)
17. Appendix: Statistics

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `Connection failed` | Wrong URL or expired token | Verify console URL includes `https://`; check token expiry |
| `No threat found for storyline` | Wrong ID or missing permission | Check Storyline ID for leading/trailing spaces; verify *Threats View* permission |
| Zero events collected | Missing forensics permission | Add *Endpoint Forensics* + *Threat Forensics View* to the API token |
| Garbled terminal output on Windows | Console encoding issue | The tool patches stdout to UTF-8; if still broken, run `chcp 65001` first |
| Empty process tree | Events still processing | Wait a few minutes and re-run; some agents batch-upload events |

---

## Security Notes

- The API token is **never** stored to disk, logged, or passed as a CLI argument
- All generated HTML reports are **fully self-contained** (no external CDN calls at render time) — safe for air-gapped environments
- External links (VirusTotal, Shodan) in HTML reports point outward only when a user explicitly clicks them — no automatic outbound calls

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

**Florian Bertaux**

> Built with [Rich](https://github.com/Textualize/rich) for terminal rendering and the [SentinelOne Management API v2.1](https://usea1-partners.sentinelone.net/api-doc/overview).
