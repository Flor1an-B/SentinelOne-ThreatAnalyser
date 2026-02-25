# Changelog

All notable changes to **SentinelOne Threats Analyzer** are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.5.0] — 2026-02-25

### Added
- **Intelligent Narrative** — dynamic, phase-by-phase incident reconstruction engine (`_build_rich_narrative()` in `analyzer.py`). Generates up to 10 contextual phases (Initial Execution, Process Execution, File System Activity, Registry Manipulation, Network/C2 Communication, Credential & Login Activity, Persistence Mechanisms, Ransomware/Encryption, MITRE Kill Chain, Detection & Response). Each phase only appears when relevant data is present, includes evidence bullet-points and MITRE ATT&CK tags, and is severity-rated (critical / high / medium / low / info).
  - **HTML**: dedicated `Narrative` section (key `2`) with severity-coloured phase cards and MITRE badge chips
  - **Markdown**: `## Incident Narrative` section after Executive Summary
  - **Terminal**: Rich `Panel` per phase with coloured border matching severity
- **`core_process_keys`** — new `Set[str]` field on `AnalysisResult`, computed once in `analyze()` by `_build_core_process_keys()`. Provides a strict, malicious-seed-based process scope used by IOC extraction, encryption detection, and the narrative. Separates confirmed attack processes from context-only ancestors and unrelated sibling processes.
- **Benign process exclusion list** (`_BENIGN_PROC_NAMES`) — known-benign applications (browsers: Brave, Chrome, Edge, Firefox; AI tools: claude.exe; version control: git; IDEs: VS Code; system helpers: conhost, dwm, audiodg, …) are automatically removed from `core_process_keys` after BFS expansion, **unless** SentinelOne explicitly flagged them as `processIsMalicious=True` (e.g. process-hollowing). Eliminates false-positive IOCs and narrative evidence from legitimate apps that happen to share a process-tree ancestor with the attack chain.

### Changed
- **Output folder format** — renamed from `<storyline>_<YYYYMMDD_HHMMSS>` to `<YYYY-MM-DD_HH-MM-SS>_<storyline>` for natural chronological sorting in file explorers. Storyline length limit raised from 32 to 64 characters.
- **`_build_core_process_keys()` seed selection (Seed B)** — fallback seed now restricted to PROCESS-CREATION events (`objectType=process` or `eventType=PROCESSCREATION`) that carry a `createdAt` timestamp. File and network events are excluded as potential seeds; they may lack `createdAt` and can cause a noise process to sort first and incorrectly become the chain root.
- **`_build_iocs()` and `_detect_encryption()`** — both now use `result.core_process_keys` as the primary process filter (replacing the previous `relatedToThreat`-only check), eliminating false IOCs and inflated file-modification counts from unrelated processes in wide-scope detections.

### Fixed
- Narrative evidence showing unrelated applications (Brave Browser, claude.exe, git-remote-https.exe) when SentinelOne marks all 20 000+ events `relatedToThreat=True` in a wide-scope detection — root cause: previous `relatedToThreat`-based filter was effectively a no-op when every event carries the flag.
- `_detect_encryption()` counting file modifications from benign apps (e.g. "4 180 files by claude.exe") as ransomware indicators.
- Network/C2 narrative phase listing connections from benign processes (claude.exe, git) as C2 communication evidence.

---

## [1.4.0] — 2026-02-24

### Added
- **Scheduled Tasks tab** in HTML report — sortable table, search bar, threat-trigger highlighting and alert banner
- **SOC Analyst Recommendations engine** — contextual, prioritised action cards (CRITICAL / HIGH / MEDIUM / LOW) generated from analysis findings: host isolation, backup protection, C2 blocking, persistence removal, credential reset, lateral movement hunting, TI enrichment
- **SOC Recommendations section** in Markdown report with priority emojis
- **SOC Recommendations section** in terminal output with coloured priority indicators
- **Login anomaly detection** — `_classify_login()` flags FAILED events and SUSPICIOUS logins (admin accounts, INTERACTIVE from threat processes, NETWORK/BATCH/SERVICE types) with coloured row highlighting in HTML and terminal
- **VirusTotal / Shodan external links** — `_vt_link()` helper auto-detects IP → VT + Shodan, SHA1/SHA256/MD5 → VT, domain → VT links in the IOC sections of the HTML report
- **Trigger-only toggle filter** in All Events HTML tab — `⚡ Triggers Only` button with live count badge, cooperative with search bar
- **Executive summary — When? sub-section** in Markdown report (First Event, Last Event, Detection Time, Duration)
- **Executive summary — Origin? sub-section** in Markdown report (Host, User, Threat File, Process Chain)
- **Executive summary — Key Indicators sub-section** in Markdown report
- **Terminal footer** — version + developer credit + generation timestamp at end of report
- **Developer credit** — "Florian Bertaux" in HTML sidebar footer, main footer and terminal footer

### Changed
- Bumped version to **v1.4.0** across `main.py`, `html_reporter.py`, `markdown_reporter.py`, `terminal_reporter.py`
- Terminal executive summary panel titles: removed bilingual French/English text, now English-only with Unicode icons
- Login section in HTML: added search bar, sortable columns, Flag column
- All Events section: `section-actions` area now hosts trigger toggle + row count

### Fixed
- Python octal escape bug: `"\2192"` → `"\u2192"` in CSS `content:` for SOC recommendation arrow bullets

---

## [1.3.0] — 2026-02-24

### Added
- **Executive Summary** — auto-generated narrative answering 4 key SOC questions (What, When, Where, How)
- `ExecutiveSummary` dataclass with: attack type/confidence, threat name, classification, mitigation status, narrative, host, user, threat file path, process chain, key indicators, MITRE tactic names, timestamps, duration, trigger commands
- Attack type heuristic cascade: Ransomware → Process Injection → Lateral Movement → RAT/C2 → Persistence → Credential Access → MITRE fallback → Generic Malware
- Process chain reconstruction (walks UP from earliest malicious/related seed to root, max 10 hops)
- Auto-generated plain-text narrative (no LLM, no Rich markup)
- `_select_trigger_commands()` prioritises events with processCmd
- Executive summary rendered in terminal (narrative panel, When/Origin panels, trigger table, key indicators)
- Executive summary rendered in HTML (dark gradient card at top of Overview tab)
- Dedicated output subfolder per analysis: `<output>/<storyline_short>_<YYYYMMDD_HHMMSS>/`

### Changed
- HTML report redesigned: sidebar navigation, animated stat counters, event distribution chart, copy-to-clipboard on all values, toast notifications, keyboard shortcuts modal, print CSS

---

## [1.2.0] — 2026-02-24

### Fixed
- `_build_threat_process_keys()` — seed = `processIsMalicious OR relatedToThreat`; walk UP for context, DOWN from seeds only (prevents sibling process false positives)
- `_detect_encryption()` — only counts file modifications from threat processes; `reason` field is plain text (no Rich markup)
- `_build_iocs()` — file hash IOCs collected only from threat processes or directly flagged events
- `_categorize_events()` — detection triggers are now ONLY `relatedToThreat OR processIsMalicious` (removed `parentProcessIsMalicious`)
- `_extract_mitre()` — deduplicated by `(tactic, technique)` key, events deduplicated per entry

---

## [1.1.0] — 2026-02-24

### Added
- Terminal IOC layout fix: panels printed sequentially (not side-by-side) to prevent layout collapse with long hashes; capped at 30 hashes with "see HTML/CSV" note
- All API endpoints verified against SentinelOne v2.1 documentation

### Fixed
- `verify_connection()` now uses `/web/api/v2.1/threats?limit=1&countOnly=true` (reliable endpoint)
- Terminal reporter: replaced all `max_width=N` with `overflow="fold"`, removed inline string slicing

---

## [1.0.0] — 2026-02-24

### Added
- Initial release
- SentinelOne API v2.1 client with pagination, retry, rate-limit handling
- `DataCollector` — fetches threat info, events (paginated), timeline
- `ThreatAnalyzer` — categorises events, extracts IOCs, MITRE techniques, encryption indicators, process tree keys
- `ProcessTreeBuilder` — reconstructs execution tree from `processUniqueKey` / `parentProcessUniqueKey` chain
- Four report formats: Terminal (Rich), CSV, Markdown, HTML
- Secure API key handling: env var `S1_API_KEY` or interactive `getpass` prompt (never CLI argument)
- `--verbose` flag for full API debug output
- Windows UTF-8 console patching for Unicode / emoji support
