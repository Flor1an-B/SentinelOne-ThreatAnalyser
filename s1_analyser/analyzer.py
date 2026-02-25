"""
Analyzer - Transforms raw API data into structured, analyst-ready findings.

Produces:
  - Categorised event lists (process, file, registry, network, login, task …)
  - Detection-trigger events (relatedToThreat / processIsMalicious)
  - Statistical summaries per category
  - MITRE ATT&CK indicator mapping
  - Encryption / ransomware heuristic detection
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .data_collector import AnalysisBundle

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EVENT_TYPE_LABELS: Dict[str, str] = {
    # Object types
    "process": "Process",
    "file": "File",
    "registry": "Registry",
    "ip": "Network",
    "dns": "DNS",
    "url": "URL",
    "login": "Login",
    "scheduled_task": "Scheduled Task",
    "module": "Module Load",
    "cross_process": "Cross-Process",
    "command_script": "Script Execution",
    # Subtypes
    "PROCESSCREATION": "Process Creation",
    "PROCESSRENAMED": "Process Renamed",
    "PROCESSTERMINATED": "Process Terminated",
    "FILECREATION": "File Creation",
    "FILEMODIFICATION": "File Modification",
    "FILEDELETION": "File Deletion",
    "FILERENAME": "File Rename",
    "REGISTRYCREATION": "Registry Creation",
    "REGISTRYMODIFICATION": "Registry Modification",
    "REGISTRYDELETION": "Registry Deletion",
    "NETWORKCONNECTION": "Network Connection",
    "NETWORKIN": "Network Inbound",
    "NETWORKOUT": "Network Outbound",
    "DNSLOOKUP": "DNS Lookup",
    "LOGINFAILED": "Login Failed",
    "LOGINSUCCESS": "Login Success",
    "TASKSCHEDULED": "Scheduled Task Created",
    "MODULELOADED": "Module Loaded",
    "CROSSPROCESSOPENED": "Cross-Process Open",
    "CROSSPROCESSDUPLICATEDTHREAD": "Cross-Process Thread Dup",
    "CROSSPROCESSDUPLICATEDHANDLE": "Cross-Process Handle Dup",
    "CROSSPROCESSINJECTION": "Process Injection",
    "BROWSEROPENFILE": "Browser File Open",
    "COMMANDSCRIPT": "Command/Script",
    # Real S1 Deep Visibility event types (title-case with spaces, stripped)
    "BEHAVIORALINDICATOR": "Behavioral Indicator",
    "BEHAVIORALINDICATORS": "Behavioral Indicator",
    "FILEOPEN": "File Open",
    "PROCESSOPEN": "Process Open",
    "TASKDELETE": "Scheduled Task Deleted",
    "TASKUPDATE": "Scheduled Task Updated",
    "LOGINLOGOUT": "Logout",
    "NETWORKCLOSING": "Network Close",
    "MODULELOADEDFAILED": "Module Load Failed",
    "REGISTRYEXPORT": "Registry Export",
    "REGISTRYIMPORT": "Registry Import",
}

EVENT_TYPE_ICONS: Dict[str, str] = {
    "process": "⚙",
    "file": "📄",
    "registry": "🔑",
    "ip": "🌐",
    "dns": "🔍",
    "url": "🔗",
    "login": "👤",
    "scheduled_task": "⏰",
    "module": "📦",
    "cross_process": "↔",
    "command_script": "💻",
    "PROCESSCREATION": "⚙",
    "FILECREATION": "📄",
    "FILEMODIFICATION": "✏",
    "FILEDELETION": "🗑",
    "FILERENAME": "📝",
    "REGISTRYCREATION": "🔑",
    "REGISTRYMODIFICATION": "🔑",
    "REGISTRYDELETION": "🔑",
    "NETWORKCONNECTION": "🌐",
    "NETWORKIN": "⬇",
    "NETWORKOUT": "⬆",
    "DNSLOOKUP": "🔍",
    "LOGINFAILED": "⛔",
    "LOGINSUCCESS": "🔓",
    "TASKSCHEDULED": "⏰",
    "MODULELOADED": "📦",
    "CROSSPROCESSINJECTION": "💉",
    "CROSSPROCESSOPENED": "↔",
}

# Known encryption-related file extensions (ransomware indicators)
ENCRYPTION_EXTENSIONS: Set[str] = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypted",
    ".WNCRY", ".WCRY", ".WNRY", ".locky", ".zepto", ".cerber",
    ".xxx", ".ttt", ".micro", ".vvv", ".aaa", ".abc", ".xyz",
    ".id-", ".onion", ".ccc", ".zzz",
}

# Known-benign process names excluded from core_process_keys unless explicitly
# flagged as processIsMalicious=True by SentinelOne (e.g. process-hollowing).
# Prevents legitimate user applications that happen to be descendants of the
# attack chain from polluting IOC extraction, encryption detection, and the
# narrative evidence.
_BENIGN_PROC_NAMES: frozenset = frozenset({
    # Browsers
    "brave.exe", "chrome.exe", "chromium.exe", "firefox.exe",
    "msedge.exe", "opera.exe", "iexplore.exe", "safari.exe",
    "vivaldi.exe", "arc.exe",
    # AI / IDE / developer tools
    "claude.exe",
    "code.exe", "code-tunnel.exe",
    "cursor.exe",
    # Version control
    "git.exe", "git-remote-https.exe", "git-credential-manager.exe",
    "git-credential-helper.exe",
    # Runtimes / package managers (only ones unlikely to be weaponised directly)
    "node.exe",
    # Communication & productivity (user-facing apps)
    "discord.exe", "slack.exe", "teams.exe",
    "spotify.exe", "vlc.exe",
    "outlook.exe", "thunderbird.exe",
    # System helpers that are almost never malicious themselves
    # (excluded here only as child/descendant nodes — S1 will mark malicious
    #  if truly injected/weaponised, so processIsMalicious guard still applies)
    "fontdrvhost.exe", "audiodg.exe", "dwm.exe",
    "searchindexer.exe", "searchprotocolhost.exe",
    "backgroundtaskhost.exe", "runtimebroker.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe",
    "conhost.exe",
})

# Suspicious registry paths (persistence heuristics)
SUSPICIOUS_REGISTRY_PATHS: List[str] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Classes\exefile\shell\open\command",
]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CategorizedEvents:
    process: List[Dict] = field(default_factory=list)
    file: List[Dict] = field(default_factory=list)
    registry: List[Dict] = field(default_factory=list)
    network: List[Dict] = field(default_factory=list)
    dns: List[Dict] = field(default_factory=list)
    login: List[Dict] = field(default_factory=list)
    scheduled_task: List[Dict] = field(default_factory=list)
    module: List[Dict] = field(default_factory=list)
    cross_process: List[Dict] = field(default_factory=list)
    other: List[Dict] = field(default_factory=list)
    detection_triggers: List[Dict] = field(default_factory=list)

    def all_events(self) -> List[Dict]:
        return (
            self.process + self.file + self.registry + self.network +
            self.dns + self.login + self.scheduled_task + self.module +
            self.cross_process + self.other
        )


@dataclass
class ExecutiveSummary:
    """
    User-friendly distillation of the most important findings.
    Answers the four key SOC questions:
      1. What happened?  (attack_type, narrative)
      2. When?           (first_event_ts, last_event_ts, detection_ts, duration_seconds)
      3. What is the origin?  (hostname, username, process_chain, threat_file_path)
      4. What commands triggered the detection?  (trigger_commands)
    """
    # Q1 — What happened?
    attack_type: str = ""           # e.g. "Ransomware", "Persistence Mechanism", "Generic Malware"
    attack_confidence: str = ""     # mirrors threat_info.confidenceLevel
    threat_name: str = ""           # threat_info.threatName or sha1 fallback
    classification: str = ""        # threat_info.classification
    mitigation_status: str = ""     # threat_info.mitigationStatus
    narrative: str = ""             # 2–3 sentence auto-generated plain-text description

    # Q2 — When?
    first_event_ts: Optional[str] = None     # ISO timestamp of earliest event
    last_event_ts: Optional[str] = None      # ISO timestamp of latest event
    detection_ts: Optional[str] = None       # threat_info.identifiedAt
    duration_seconds: Optional[float] = None # computed from first/last timestamps

    # Q3 — What is the origin?
    hostname: str = ""
    username: str = ""
    threat_file_path: str = ""
    process_chain: List[str] = field(default_factory=list)  # ["explorer.exe","cmd.exe","dropper.exe"]

    # Q4 — What commands triggered detection?
    trigger_commands: List[Dict] = field(default_factory=list)  # up to 5 {ts, process_name, command, event_type, flags}

    # Supporting context
    key_indicators: List[str] = field(default_factory=list)   # plain-text bullet points
    mitre_tactic_names: List[str] = field(default_factory=list)


@dataclass
class SocRecommendation:
    """
    A single actionable recommendation for the SOC analyst.
    Generated contextually from the analysis findings.
    """
    priority: str        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    category: str        # "Containment", "Investigation", "Remediation", "Threat Hunt"
    title: str
    details: str
    actions: List[str]   # specific, ordered action items


@dataclass
class AnalysisResult:
    bundle: AnalysisBundle
    categorized: CategorizedEvents = field(default_factory=CategorizedEvents)

    # Summary metrics
    total_events: int = 0
    event_type_counts: Dict[str, int] = field(default_factory=dict)
    unique_processes: int = 0
    unique_hosts: int = 0

    # Key findings
    detection_triggers: List[Dict] = field(default_factory=list)
    suspicious_registry: List[Dict] = field(default_factory=list)
    network_iocs: List[Dict] = field(default_factory=list)       # IPs/domains
    file_iocs: List[Dict] = field(default_factory=list)          # hashes/paths
    encryption_indicators: List[Dict] = field(default_factory=list)
    lateral_movement_indicators: List[Dict] = field(default_factory=list)
    account_creation_events: List[Dict] = field(default_factory=list)

    # MITRE techniques
    mitre_techniques: List[Dict] = field(default_factory=list)

    # Timeline (sorted events)
    timeline_sorted: List[Dict] = field(default_factory=list)

    # Threat-context process keys — set of processUniqueKey values for all
    # processes in the threat's process tree (used to filter noise in reporters)
    threat_process_keys: Set[str] = field(default_factory=set)

    # Core process keys — strict subset of threat_process_keys.
    # Seeds = processIsMalicious=True + execution chain process names + BFS descendants.
    # Used where accuracy matters (IOC extraction, encryption detection, narrative evidence)
    # to avoid noise from unrelated processes when ALL events are relatedToThreat=True.
    core_process_keys: Set[str] = field(default_factory=set)

    # Executive summary — pre-computed SOC-ready answers to the four key questions
    executive_summary: Optional[ExecutiveSummary] = field(default=None)

    # SOC recommendations — contextual, prioritised action items
    soc_recommendations: List[SocRecommendation] = field(default_factory=list)

    # Intelligent narrative — ordered list of incident phases with evidence
    # Each phase: {"id", "phase", "severity", "icon", "title", "text", "evidence", "mitre"}
    narrative_phases: List[Dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class ThreatAnalyzer:
    """
    Performs all analysis on a collected AnalysisBundle.

    Usage:
        result = ThreatAnalyzer().analyze(bundle)
    """

    def analyze(self, bundle: AnalysisBundle) -> AnalysisResult:
        result = AnalysisResult(bundle=bundle)
        if not bundle.events and not bundle.threat:
            return result

        self._categorize_events(bundle.events, result)
        self._build_threat_process_keys(bundle.events, result)
        self._build_core_process_keys(result)
        self._build_iocs(result)
        self._detect_encryption(result)
        self._extract_mitre(bundle, result)
        self._build_sorted_timeline(result)
        result.executive_summary = self._build_executive_summary(result)
        result.soc_recommendations = self._build_soc_recommendations(result)
        result.narrative_phases = self._build_rich_narrative(result)

        result.total_events = len(bundle.events)
        result.unique_processes = len(
            {e.get("processUniqueKey") for e in bundle.events if e.get("processUniqueKey")}
        )
        result.event_type_counts = dict(Counter(
            (e.get("objectType") or e.get("eventType") or "unknown").lower()
            for e in bundle.events
        ))

        return result

    # ------------------------------------------------------------------
    # Categorisation
    # ------------------------------------------------------------------

    def _categorize_events(
        self, events: List[Dict], result: AnalysisResult
    ) -> None:
        cat = result.categorized

        for evt in events:
            obj_type = (evt.get("objectType") or "").lower()
            evt_type = (evt.get("eventType") or "").lower()
            evt_subtype = (evt.get("eventSubType") or "").upper()

            # Detection trigger — only flag events directly tied to the threat
            if evt.get("relatedToThreat") or evt.get("processIsMalicious"):
                cat.detection_triggers.append(evt)
                result.detection_triggers.append(evt)

            # Route to category
            if "process" in obj_type or "process" in evt_type:
                cat.process.append(evt)
            elif "file" in obj_type or "file" in evt_type or evt_subtype in (
                "FILECREATION", "FILEMODIFICATION", "FILEDELETION", "FILERENAME"
            ):
                cat.file.append(evt)
            elif "registry" in obj_type or "registry" in evt_type or evt_subtype.startswith("REGISTRY"):
                cat.registry.append(evt)
            elif "dns" in obj_type or "dns" in evt_type or evt.get("dnsRequest"):
                cat.dns.append(evt)
            elif obj_type in ("ip", "url") or "network" in obj_type or "network" in evt_type or evt.get("dstIp"):
                cat.network.append(evt)
            elif "login" in obj_type or "login" in evt_type or evt.get("loginsBaseType"):
                cat.login.append(evt)
            elif "task" in obj_type or evt.get("taskName"):
                cat.scheduled_task.append(evt)
            elif "module" in obj_type or "module" in evt_type:
                cat.module.append(evt)
            elif "cross" in obj_type or "injection" in (evt_subtype or "").lower():
                cat.cross_process.append(evt)
            else:
                cat.other.append(evt)

        # Account creation heuristic: login events with 'new user' or NET USER
        for evt in cat.login:
            cmd = (evt.get("processCmd") or "").lower()
            login_type = (evt.get("loginsBaseType") or "").lower()
            if "net user" in cmd or "useradd" in cmd or "new_credentials" in login_type:
                result.account_creation_events.append(evt)

    # ------------------------------------------------------------------
    # Threat process tree context
    # ------------------------------------------------------------------

    @staticmethod
    def _build_threat_process_keys(
        events: List[Dict], result: AnalysisResult
    ) -> None:
        """
        Build the set of processUniqueKey values for the threat's process tree.

        Algorithm:
          1. Seed: processes with processIsMalicious=True OR relatedToThreat=True.
          2. Walk UP ancestors of seed processes (for context — show parent chain).
          3. Walk DOWN from seed processes ONLY (not from context ancestors).

        Step 3 is critical: by expanding descendants only from the actual threat
        seeds (not from every ancestor), we avoid including unrelated sibling
        processes that share a common parent (e.g. explorer.exe children like
        brave.exe, claude.exe that happen to be co-workers of the malware).
        """
        # Build parent/child adjacency maps
        parent_of: Dict[str, str] = {}
        children_of: Dict[str, Set[str]] = defaultdict(set)

        for evt in events:
            key = evt.get("processUniqueKey") or ""
            parent = evt.get("parentProcessUniqueKey") or ""
            if key and parent:
                parent_of[key] = parent
                children_of[parent].add(key)

        # 1. Seed: directly malicious or threat-related process keys only
        seed_keys: Set[str] = {
            evt.get("processUniqueKey")
            for evt in events
            if (evt.get("processIsMalicious") or evt.get("relatedToThreat"))
            and evt.get("processUniqueKey")
        }

        if not seed_keys:
            # No explicit threat markers → include everything to avoid hiding data
            result.threat_process_keys = {
                e.get("processUniqueKey") for e in events if e.get("processUniqueKey")
            }
            return

        all_keys: Set[str] = set(seed_keys)

        # 2. Walk UP: include all ancestors (for process-tree context only)
        queue = list(seed_keys)
        while queue:
            k = queue.pop()
            p = parent_of.get(k)
            if p and p not in all_keys:
                all_keys.add(p)
                queue.append(p)

        # 3. Walk DOWN from seeds only — NOT from context ancestors
        #    This ensures sibling processes of malware are NOT included.
        queue = list(seed_keys)
        visited_down: Set[str] = set(seed_keys)
        while queue:
            k = queue.pop()
            for child in children_of.get(k, set()):
                if child not in visited_down:
                    visited_down.add(child)
                    all_keys.add(child)
                    queue.append(child)

        result.threat_process_keys = all_keys

    # ------------------------------------------------------------------
    # Core process key computation (strict filter for evidence quality)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_core_process_keys(result: AnalysisResult) -> None:
        """
        Build result.core_process_keys — a strict subset of threat_process_keys.

        Algorithm:
          1. Seed A: processIsMalicious=True events (highest-confidence signal).
          2. Seed B (fallback): earliest PROCESS-CREATION event (objectType=process
             or eventType=PROCESSCREATION) that is relatedToThreat/processIsMalicious
             AND has a createdAt timestamp.  File/network events are excluded to
             prevent noise processes (brave.exe, claude.exe) from becoming the
             chain root via an event without a timestamp.
          3. Walk UP ancestors from A∪B seeds: include the full parent chain.
          4. BFS DOWN from initial seeds only (not from ancestors): include all
             descendant attack processes.

        Why this matters:
          When SentinelOne marks ALL events relatedToThreat=True (wide-scope
          detections), threat_process_keys includes every process on the system
          (explorer.exe children like brave.exe, claude.exe, git, …).
          core_process_keys stays focused on the actual attack subtree, so IOC
          extraction and encryption detection don't pick up unrelated processes.

        Fallback: if no seeds are found, falls back to threat_process_keys so that
        reports still contain data even with minimal threat metadata.
        """
        events = result.bundle.events

        # Build adjacency maps
        children_of: Dict[str, Set[str]] = defaultdict(set)
        key_to_parent: Dict[str, str] = {}
        for ev in events:
            k = ev.get("processUniqueKey") or ""
            p = ev.get("parentProcessUniqueKey") or ""
            if k and p:
                children_of[p].add(k)
                if k not in key_to_parent:
                    key_to_parent[k] = p

        # Seed A — confirmed malicious processes
        initial_seeds: Set[str] = {
            ev.get("processUniqueKey")
            for ev in events
            if ev.get("processIsMalicious") and ev.get("processUniqueKey")
        }

        # Seed B — earliest PROCESS-CREATION event with a timestamp (fallback only)
        # File/network events intentionally excluded: they may lack createdAt and
        # could name unrelated processes as the chain root.
        if not initial_seeds:
            proc_evts = [
                ev for ev in events
                if (
                    (ev.get("objectType") or "").lower() == "process"
                    or (ev.get("eventType") or "").upper().replace(" ", "") == "PROCESSCREATION"
                )
                and ev.get("processUniqueKey")
                and (ev.get("relatedToThreat") or ev.get("processIsMalicious"))
                and ev.get("createdAt")          # must have timestamp — prevents
                                                 # events without createdAt from
                                                 # sorting first as chain root
            ]
            if proc_evts:
                earliest = min(proc_evts, key=lambda e: e.get("createdAt", ""))
                initial_seeds.add(earliest["processUniqueKey"])

        # Start core with initial seeds, then walk UP their ancestor chain
        core: Set[str] = set(initial_seeds)
        for seed in list(initial_seeds):
            current = seed
            for _ in range(10):
                parent = key_to_parent.get(current)
                if not parent or parent == current or parent in core:
                    break
                core.add(parent)
                current = parent

        # BFS DOWN from initial seeds only (not from ancestors) so that sibling
        # processes sharing the same parent are not included.
        frontier = set(initial_seeds)
        for _ in range(10):
            next_level: Set[str] = set()
            for ck in frontier:
                for child in children_of.get(ck, set()):
                    if child not in core:
                        core.add(child)
                        next_level.add(child)
            if not next_level:
                break
            frontier = next_level

        # Remove known-benign processes from core unless S1 explicitly flagged
        # them as malicious (e.g. a process-hollowed browser).  Browsers, AI
        # tools, git, etc. should never appear as IOC/narrative evidence even
        # when they happen to be descendants of the attack chain (e.g. a
        # legitimate update script spawning claude.exe or brave.exe).
        if core:
            key_to_procname: Dict[str, str] = {}
            for ev in events:
                k = ev.get("processUniqueKey") or ""
                n = (ev.get("processName") or "").lower()
                if k and n:
                    key_to_procname[k] = n
            core = {
                k for k in core
                if k in initial_seeds                          # always keep confirmed malicious
                or key_to_procname.get(k, "") not in _BENIGN_PROC_NAMES
            }

        # Fallback: empty → use threat_process_keys (better than nothing)
        result.core_process_keys = core if core else result.threat_process_keys

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------

    def _build_iocs(self, result: AnalysisResult) -> None:
        cat = result.categorized
        threat_keys = result.threat_process_keys

        # Network IOCs – unique IPs and domains (network events already filtered upstream)
        seen_net: Set[str] = set()
        for evt in cat.network + cat.dns:
            for field_name in ("dstIp", "srcIp", "dnsRequest", "networkUrl"):
                val = evt.get(field_name)
                if val and val not in seen_net:
                    seen_net.add(val)
                    result.network_iocs.append(
                        {"value": val, "type": field_name, "event": evt}
                    )

        # File IOCs – unique hashes from core threat processes only.
        # Uses core_process_keys (strict: malicious + chain + descendants) so that
        # unrelated processes (browsers, editors) are excluded even when they all
        # carry relatedToThreat=True in wide-scope detections.
        core_keys = result.core_process_keys or threat_keys
        seen_file: Set[str] = set()
        for evt in cat.file + cat.process:
            proc_key = evt.get("processUniqueKey")
            if core_keys and proc_key not in core_keys:
                if not evt.get("processIsMalicious"):
                    continue
            for hash_field in ("fileSha1", "fileSha256", "fileMd5", "sha1", "sha256"):
                val = evt.get(hash_field)
                # Skip absent, duplicate, or all-zero hashes (S1 uses zeros when no hash computed)
                if not val or val in seen_file or not val.strip("0"):
                    continue
                seen_file.add(val)
                result.file_iocs.append(
                    {"value": val, "type": hash_field, "event": evt}
                )

        # Suspicious registry keys
        for evt in cat.registry:
            path = (evt.get("registryPath") or "").upper()
            for susp_path in SUSPICIOUS_REGISTRY_PATHS:
                if susp_path.upper() in path:
                    result.suspicious_registry.append(evt)
                    break

        # Lateral movement heuristic: cross-process injection or remote network access
        for evt in cat.cross_process:
            if evt.get("relatedToThreat") or evt.get("processIsMalicious"):
                result.lateral_movement_indicators.append(evt)

    # ------------------------------------------------------------------
    # Ransomware / Encryption heuristic
    # ------------------------------------------------------------------

    def _detect_encryption(self, result: AnalysisResult) -> None:
        cat = result.categorized
        threat_keys = result.threat_process_keys

        # Build processUniqueKey → processName lookup
        proc_name_map: Dict[str, str] = {}
        for evt in result.bundle.events:
            k = evt.get("processUniqueKey") or ""
            n = evt.get("processName") or ""
            if k and n:
                proc_name_map[k] = n

        # Use core_process_keys for strict attribution: avoids counting file
        # modifications from unrelated processes (browsers, editors, etc.) as
        # encryption indicators when relatedToThreat=True on all events.
        core_keys = result.core_process_keys or threat_keys

        def _is_threat_evt(evt: Dict) -> bool:
            """Return True if event belongs to a core threat process."""
            if evt.get("processIsMalicious"):
                return True
            key = evt.get("processUniqueKey")
            if core_keys:
                return bool(key and key in core_keys)
            # Fallback: no core/threat keys available → include if flagged
            return bool(evt.get("relatedToThreat"))

        # 1. File rename/creation to suspicious extension (threat processes only)
        for evt in cat.file:
            if not _is_threat_evt(evt):
                continue
            new_name = (evt.get("fileFullName") or "").lower()
            for ext in ENCRYPTION_EXTENSIONS:
                if new_name.endswith(ext.lower()):
                    result.encryption_indicators.append(
                        {
                            "reason": f"Suspicious extension: {ext}  —  {evt.get('fileFullName', '')}",
                            "event": evt,
                        }
                    )
                    break

        # 2. Very high file-modification count from a single threat process
        mod_per_process: Counter = Counter()
        for evt in cat.file:
            if not _is_threat_evt(evt):
                continue
            subtype = (evt.get("eventSubType") or evt.get("eventType") or "").upper()
            if "MODIF" in subtype or "CREATION" in subtype:
                key = evt.get("processUniqueKey") or evt.get("processName", "?")
                mod_per_process[key] += 1

        for proc_key, count in mod_per_process.items():
            if count >= 50:
                proc_name = proc_name_map.get(proc_key) or proc_key
                result.encryption_indicators.append(
                    {
                        # Plain text — no Rich markup so it renders correctly in all reporters
                        "reason": f"High-volume file modifications ({count}) by {proc_name}",
                        "proc_name": proc_name,
                        "proc_key": proc_key,
                        "count": count,
                        "event": {},
                    }
                )

    # ------------------------------------------------------------------
    # MITRE ATT&CK
    # ------------------------------------------------------------------

    def _extract_mitre(
        self, bundle: AnalysisBundle, result: AnalysisResult
    ) -> None:
        """
        Build deduplicated MITRE ATT&CK technique entries from threat indicators.

        Multiple indicators can map to the same (tactic, technique) pair; we
        deduplicate by that pair and merge their triggered-event lists so the
        final table has one row per unique technique.
        """
        # Deduplicated map: (tactic_name, technique_name) → entry dict
        tech_map: Dict[tuple, Dict] = {}

        # Lookup for event annotation: (indicator_category, indicator_description) → entries
        indicator_lookup: Dict[tuple, List[Dict]] = defaultdict(list)

        for ind in bundle.indicators:
            ind_cat  = ind.get("category", "")
            ind_desc = ind.get("description", "")
            for tactic in ind.get("tactics") or []:
                tactic_name = tactic.get("name", "")
                for tech in tactic.get("techniques") or []:
                    tech_name = tech.get("name", "")
                    dedup_key = (tactic_name, tech_name)
                    if dedup_key not in tech_map:
                        entry = {
                            "tactic":      tactic_name,
                            "technique":   tech_name,
                            "link":        tech.get("link", ""),
                            "description": ind_desc,
                            "category":    ind_cat,
                            "events":      [],
                            "_seen_evts":  set(),   # internal: avoid duplicate events
                        }
                        tech_map[dedup_key] = entry
                        result.mitre_techniques.append(entry)
                    # Always register this (cat, desc) → entry mapping for event lookup
                    indicator_lookup[(ind_cat, ind_desc)].append(tech_map[dedup_key])

        # Annotate events with their MITRE tag and populate per-technique event lists
        for evt in bundle.events:
            evt_cat  = evt.get("indicatorCategory") or evt.get("indicatorName") or ""
            evt_desc = evt.get("indicatorDescription") or ""
            if not evt_cat and not evt_desc:
                continue
            # Try exact match first, then category-only fallback
            matches = (
                indicator_lookup.get((evt_cat, evt_desc))
                or indicator_lookup.get((evt_cat, ""))
                or []
            )
            # Deduplicate: each event added at most once per technique entry
            seen_entries: set = set()
            for entry in matches:
                eid = id(entry)
                if eid not in seen_entries:
                    seen_entries.add(eid)
                    evt_id = id(evt)
                    if evt_id not in entry["_seen_evts"]:
                        entry["_seen_evts"].add(evt_id)
                        entry["events"].append(evt)
            # Store compact MITRE tag on the event itself for table display
            if matches:
                m = matches[0]
                evt["_mitre_tag"] = f"{m['tactic']} / {m['technique']}"

    # ------------------------------------------------------------------
    # Executive summary builder
    # ------------------------------------------------------------------

    def _build_executive_summary(self, result: AnalysisResult) -> ExecutiveSummary:
        """Build a user-friendly summary answering the four key SOC questions."""
        ti  = result.bundle.threat_info
        adi = result.bundle.agent_detection_info
        ari = result.bundle.agent_realtime_info

        hostname     = ari.get("agentComputerName") or adi.get("agentIpV4") or "Unknown Host"
        username     = (
            ti.get("initiatingUsername")
            or adi.get("agentLastLoggedInUserName")
            or "Unknown User"
        )
        threat_name  = ti.get("threatName") or ti.get("sha1") or "Unknown Threat"

        first_ts = result.timeline_sorted[0].get("createdAt") if result.timeline_sorted else None
        last_ts  = result.timeline_sorted[-1].get("createdAt") if result.timeline_sorted else None

        attack_type   = self._classify_attack_type(result)
        process_chain = self._extract_process_chain(result)
        trigger_cmds  = self._select_trigger_commands(result)
        key_indicators = self._build_key_indicators(result)
        duration       = self._compute_duration(first_ts, last_ts)
        mitre_tactics  = sorted({
            t.get("tactic", "") for t in result.mitre_techniques if t.get("tactic")
        })

        narrative = self._build_narrative(
            attack_type   = attack_type,
            threat_name   = threat_name,
            confidence    = ti.get("confidenceLevel") or "unknown",
            hostname      = hostname,
            username      = username,
            chain         = process_chain,
            first_ts      = first_ts,
            detection_ts  = ti.get("identifiedAt"),
            mitigation    = ti.get("mitigationStatus") or "",
        )

        return ExecutiveSummary(
            attack_type        = attack_type,
            attack_confidence  = ti.get("confidenceLevel") or "unknown",
            threat_name        = threat_name,
            classification     = ti.get("classification") or "N/A",
            mitigation_status  = ti.get("mitigationStatus") or "N/A",
            narrative          = narrative,
            first_event_ts     = first_ts,
            last_event_ts      = last_ts,
            detection_ts       = ti.get("identifiedAt"),
            duration_seconds   = duration,
            hostname           = hostname,
            username           = username,
            threat_file_path   = ti.get("filePath") or "N/A",
            process_chain      = process_chain,
            trigger_commands   = trigger_cmds,
            key_indicators     = key_indicators,
            mitre_tactic_names = mitre_tactics,
        )

    @staticmethod
    def _classify_attack_type(result: AnalysisResult) -> str:
        """Classify the primary attack type via heuristic cascade."""
        # Highest-signal indicators first
        if result.encryption_indicators:
            return "Ransomware"
        if any(
            "inject" in (e.get("eventSubType") or "").lower()
            for e in result.detection_triggers
        ):
            return "Process Injection"
        if result.lateral_movement_indicators:
            return "Lateral Movement"
        # C2: network contact from a trigger process
        trigger_keys = {e.get("processUniqueKey") for e in result.detection_triggers}
        if any(
            e.get("processUniqueKey") in trigger_keys
            for e in result.categorized.network
        ):
            return "RAT / C2 Backdoor"
        if result.suspicious_registry:
            return "Persistence Mechanism"
        if result.account_creation_events:
            return "Credential / Account Manipulation"
        # MITRE tactic fallback
        mitre_tactics = {t.get("tactic", "") for t in result.mitre_techniques}
        if "Impact" in mitre_tactics:
            return "Destructive / Impact"
        if "Exfiltration" in mitre_tactics:
            return "Data Exfiltration"
        if "Collection" in mitre_tactics:
            return "Data Collection"
        # Fallback to SentinelOne classification
        s1_class = result.bundle.threat_info.get("classification")
        return s1_class or "Generic Malware"

    @staticmethod
    def _extract_process_chain(result: AnalysisResult) -> List[str]:
        """
        Walk from the earliest malicious/related process up to its root ancestor.
        Returns a list of names in order, e.g. ["explorer.exe", "cmd.exe", "dropper.exe"].
        """
        events = result.bundle.events
        key_to_name:   Dict[str, str] = {}
        key_to_parent: Dict[str, str] = {}

        for evt in events:
            k = evt.get("processUniqueKey") or ""
            if k:
                if not key_to_name.get(k):
                    key_to_name[k] = evt.get("processName") or ""
                p = evt.get("parentProcessUniqueKey") or ""
                if p:
                    key_to_parent[k] = p
                    if not key_to_name.get(p):
                        key_to_name[p] = evt.get("parentProcessName") or ""

        # Seed: pick the earliest threat-flagged process
        seeds = sorted(
            [
                e for e in events
                if (e.get("processIsMalicious") or e.get("relatedToThreat"))
                and e.get("processUniqueKey")
            ],
            key=lambda e: e.get("createdAt") or "",
        )
        if not seeds:
            origin = result.bundle.threat_info.get("originatorProcess")
            return [origin] if origin else []

        seed_key = seeds[0]["processUniqueKey"]

        # Walk UP to root (max 10 hops to guard against loops)
        chain_keys: List[str] = [seed_key]
        current = seed_key
        for _ in range(10):
            parent = key_to_parent.get(current)
            if not parent or parent == current or parent in chain_keys:
                break
            chain_keys.insert(0, parent)
            current = parent

        # Convert to names, dropping empties and de-duplicating
        seen: Set[str] = set()
        chain: List[str] = []
        for k in chain_keys:
            name = key_to_name.get(k) or k
            if name and name not in seen:
                seen.add(name)
                chain.append(name)
        return chain

    @staticmethod
    def _select_trigger_commands(result: AnalysisResult) -> List[Dict]:
        """
        Select up to 5 detection-trigger events for the 'what triggered it' table.
        Priority: events with a command line first, then any other trigger event.
        """
        triggers = sorted(
            result.detection_triggers,
            key=lambda e: e.get("createdAt") or "",
        )
        with_cmd    = [e for e in triggers if e.get("processCmd")]
        without_cmd = [e for e in triggers if not e.get("processCmd")]
        ordered = with_cmd + without_cmd

        out: List[Dict] = []
        seen_cmds: Set[str] = set()

        for evt in ordered[:10]:  # inspect up to 10, take best 5
            cmd = evt.get("processCmd") or ""
            if not cmd:
                # Fallback: show the primary observable for this event type
                cmd = (
                    evt.get("fileFullName")
                    or evt.get("registryPath")
                    or (f"{evt.get('dstIp')}:{evt.get('dstPort')}" if evt.get("dstIp") else "")
                    or evt.get("dnsRequest")
                    or event_label(evt)
                )
            dedup_key = f"{evt.get('processName')}::{cmd}"
            if dedup_key in seen_cmds:
                continue
            seen_cmds.add(dedup_key)

            flags: List[str] = []
            if evt.get("relatedToThreat"):
                flags.append("relatedToThreat")
            if evt.get("processIsMalicious"):
                flags.append("processMalicious")

            out.append({
                "ts":           evt.get("createdAt") or "",
                "process_name": evt.get("processName") or "",
                "command":      cmd,
                "event_type":   _infer_event_type(evt),
                "flags":        flags,
            })
            if len(out) >= 5:
                break

        return out

    @staticmethod
    def _build_key_indicators(result: AnalysisResult) -> List[str]:
        """Build a plain-text list of the most impactful findings."""
        indicators: List[str] = []

        if result.encryption_indicators:
            indicators.append(
                f"Ransomware/encryption: {len(result.encryption_indicators)} indicator(s) detected"
            )

        if result.network_iocs:
            ips = [i["value"] for i in result.network_iocs if i["type"] == "dstIp"][:3]
            dns = [i["value"] for i in result.network_iocs if i["type"] == "dnsRequest"][:2]
            if ips:
                indicators.append(f"C2 connections to: {', '.join(ips)}")
            if dns:
                indicators.append(f"Suspicious DNS queries: {', '.join(dns)}")

        if result.suspicious_registry:
            indicators.append(
                f"Persistence: {len(result.suspicious_registry)} suspicious registry key(s) modified"
            )

        if result.lateral_movement_indicators:
            indicators.append(
                f"Lateral movement: {len(result.lateral_movement_indicators)} cross-process event(s)"
            )

        if result.account_creation_events:
            indicators.append(
                f"Account activity: {len(result.account_creation_events)} manipulation event(s)"
            )

        task_triggers = [
            e for e in result.categorized.scheduled_task
            if e.get("relatedToThreat") or e.get("processIsMalicious")
        ]
        if task_triggers:
            names = ", ".join(e.get("taskName", "?") for e in task_triggers[:2])
            indicators.append(f"Scheduled task(s) created: {names}")

        if result.file_iocs:
            indicators.append(f"{len(result.file_iocs)} unique file hash IOC(s) associated with threat")

        return indicators[:8]  # cap at 8 bullets

    @staticmethod
    def _compute_duration(first_ts: Optional[str], last_ts: Optional[str]) -> Optional[float]:
        if not first_ts or not last_ts:
            return None
        try:
            t0 = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            return max(0.0, (t1 - t0).total_seconds())
        except Exception:
            return None

    @staticmethod
    def _build_narrative(
        attack_type: str,
        threat_name: str,
        confidence: str,
        hostname: str,
        username: str,
        chain: List[str],
        first_ts: Optional[str],
        detection_ts: Optional[str],
        mitigation: str,
    ) -> str:
        """Generate a 2–3 sentence plain-English description of the incident."""
        severity_word = {
            "malicious":   "malicious",
            "suspicious":  "suspicious",
        }.get(confidence.lower(), "potentially malicious")

        display_name = f'"{threat_name}"' if threat_name not in ("Unknown Threat", "N/A") else "an unknown threat"
        chain_str    = " → ".join(chain) if chain else "an unknown process"

        first_str    = fmt_ts(first_ts)     if first_ts     else "an unknown time"
        detect_str   = fmt_ts(detection_ts) if detection_ts else "an unknown time"
        mit_str      = mitigation or "pending"

        return (
            f"SentinelOne identified a {severity_word} {attack_type} threat {display_name} "
            f"on host \"{hostname}\" under user account \"{username}\". "
            f"The execution chain was: {chain_str}. "
            f"Activity began at {first_str} and was detected at {detect_str}. "
            f"Mitigation status: {mit_str}."
        )

    # ------------------------------------------------------------------
    # SOC recommendations
    # ------------------------------------------------------------------

    @staticmethod
    def _build_soc_recommendations(result: AnalysisResult) -> List[SocRecommendation]:
        """
        Generate contextual, prioritised SOC action items from analysis findings.
        Recommendations are ordered: CRITICAL → HIGH → MEDIUM → LOW.
        """
        recs: List[SocRecommendation] = []
        ti  = result.bundle.threat_info
        es  = result.executive_summary

        confidence  = (ti.get("confidenceLevel") or "").lower()
        mit_status  = (ti.get("mitigationStatus") or "").lower()
        is_mitigated = any(k in mit_status for k in ("remediat", "quarantin", "killed", "mitigated"))
        hostname    = es.hostname if es else "Unknown Host"
        username    = es.username if es else "Unknown User"
        threat_name = es.threat_name if es else "Unknown Threat"

        # ── CRITICAL ──────────────────────────────────────────────────────────

        # Malicious + not mitigated → isolate immediately
        if confidence == "malicious" and not is_mitigated:
            recs.append(SocRecommendation(
                priority="CRITICAL",
                category="Containment",
                title="Isolate the host immediately",
                details=(
                    f"The threat \"{threat_name}\" is confirmed malicious and has NOT been "
                    f"mitigated. Host \"{hostname}\" may still be actively compromised."
                ),
                actions=[
                    f"Trigger network isolation from the S1 console: Actions → Isolate \"{hostname}\"",
                    f"Identify all active sessions on {hostname} and terminate them",
                    "Document the isolation timestamp for the incident timeline",
                    "Notify the asset owner and escalate to the IR team",
                ],
            ))

        # Ransomware / encryption detected
        if result.encryption_indicators:
            recs.append(SocRecommendation(
                priority="CRITICAL",
                category="Remediation",
                title="Ransomware indicators — protect backups before acting",
                details=(
                    f"{len(result.encryption_indicators)} file encryption indicator(s) detected. "
                    "Verify backup integrity immediately before any remediation attempt."
                ),
                actions=[
                    "DO NOT reboot or run automated remediation until backup status is confirmed",
                    "Verify offline/air-gapped backup integrity — ransomware targets VSS and network shares",
                    "Check for shadow-copy deletion (vssadmin, wbadmin in the process events)",
                    "Identify and scope all potentially encrypted files before attempting recovery",
                    "Contact your Backup/DR team and open a P1 incident immediately",
                ],
            ))

        # ── HIGH ──────────────────────────────────────────────────────────────

        # C2 network connections
        c2_ips     = [i["value"] for i in result.network_iocs if i["type"] == "dstIp"]
        c2_domains = [i["value"] for i in result.network_iocs if i["type"] == "dnsRequest"]
        if c2_ips or c2_domains:
            ip_str  = ", ".join(c2_ips[:5])
            dom_str = ", ".join(c2_domains[:3])
            actions = []
            if ip_str:
                actions.append(f"Block at firewall/proxy (destination IPs): {ip_str}")
            if dom_str:
                actions.append(f"Block at DNS/web proxy (domains): {dom_str}")
            actions += [
                "Search your SIEM/NDR for other hosts connecting to these endpoints",
                "Submit IPs and domains to VirusTotal, Shodan, or your TIP",
                "Review outbound traffic volume to estimate potential data exfiltration",
            ]
            recs.append(SocRecommendation(
                priority="HIGH",
                category="Containment",
                title="Block C2 endpoints at the network perimeter",
                details=(
                    f"Outbound C2 connections detected to {len(c2_ips)} IP(s) and "
                    f"{len(c2_domains)} domain(s). Block these and hunt for lateral spread."
                ),
                actions=actions,
            ))

        # Persistence (registry Run keys + malicious scheduled tasks)
        task_triggers = [
            e for e in result.categorized.scheduled_task
            if e.get("relatedToThreat") or e.get("processIsMalicious")
        ]
        if result.suspicious_registry or task_triggers:
            recs.append(SocRecommendation(
                priority="HIGH",
                category="Remediation",
                title="Remove persistence mechanisms before remediation",
                details=(
                    f"{len(result.suspicious_registry)} suspicious registry key(s) and "
                    f"{len(task_triggers)} malicious scheduled task(s) detected. "
                    "These ensure the malware survives reboots."
                ),
                actions=[
                    "Review and remove all Run/RunOnce registry entries added by this threat",
                    "Delete malicious scheduled tasks found in the Scheduled Tasks events section",
                    "Verify removal success by auditing the registry paths post-cleanup",
                    "Search for the same persistence indicators across all endpoints in the site",
                ],
            ))

        # Credential Access MITRE tactic or account creation
        mitre_tactics = {t.get("tactic", "") for t in result.mitre_techniques}
        if "Credential Access" in mitre_tactics or result.account_creation_events:
            recs.append(SocRecommendation(
                priority="HIGH",
                category="Remediation",
                title="Reset potentially compromised credentials",
                details=(
                    f"Credential Access or account manipulation was detected. "
                    f"Credentials for \"{username}\" and other accounts on this host "
                    "may be compromised."
                ),
                actions=[
                    f"Force an immediate password reset for user \"{username}\"",
                    "Revoke and rotate all API keys and service account tokens on this host",
                    "Check for new local accounts created during the attack window",
                    "Enable MFA if not already active for affected accounts",
                    "Review AD / Entra ID sign-in logs for suspicious activity from these accounts",
                ],
            ))

        # Lateral movement
        if result.lateral_movement_indicators:
            recs.append(SocRecommendation(
                priority="HIGH",
                category="Threat Hunt",
                title="Investigate scope of lateral movement",
                details=(
                    f"{len(result.lateral_movement_indicators)} lateral movement indicator(s) "
                    "detected. The attacker may have pivoted to additional hosts."
                ),
                actions=[
                    "Review cross-process injection events to identify targeted processes",
                    "Check authentication logs for unusual login patterns originating from this host",
                    "Search for the same IOCs on other endpoints in your environment (EDR sweeping)",
                    "Prioritise hosts that had network connections to/from this host during the window",
                ],
            ))

        # ── MEDIUM ────────────────────────────────────────────────────────────

        # File IOCs → threat intel enrichment
        if result.file_iocs:
            recs.append(SocRecommendation(
                priority="MEDIUM",
                category="Investigation",
                title="Enrich file IOCs via threat intelligence platforms",
                details=(
                    f"{len(result.file_iocs)} unique file hash IOC(s) associated with this threat. "
                    "Cross-reference against threat intel to identify the malware family and TTPs."
                ),
                actions=[
                    "Submit SHA1/SHA256 hashes to VirusTotal, Malware Bazaar, or your TIP",
                    "Search your EDR for any other hosts that executed or loaded these hashes",
                    "If samples are available, submit to your sandbox for dynamic analysis",
                    "Add hashes to your SIEM IOC watchlist for retrospective hunting",
                ],
            ))

        # Collect forensic evidence before remediation (when malicious but not yet cleaned)
        if confidence in ("malicious", "suspicious") and not is_mitigated:
            recs.append(SocRecommendation(
                priority="MEDIUM",
                category="Investigation",
                title="Collect forensic artefacts before remediation",
                details=(
                    "Before running automated remediation, collect memory and disk artefacts "
                    "to preserve evidence needed for root-cause analysis and legal proceedings."
                ),
                actions=[
                    "Capture a full memory image (e.g. WinPmem, or use S1 Remote Shell → memory dump)",
                    "Export the complete event log from S1 for this storyline",
                    "Retrieve prefetch files, relevant registry hives, and scheduled task XML files",
                    "Document exact remediation steps taken for the incident report and post-mortem",
                ],
            ))

        # ── LOW ───────────────────────────────────────────────────────────────

        # Review MITRE kill chain coverage
        if len(result.mitre_techniques) >= 2:
            tactic_names = sorted(mitre_tactics - {""})
            recs.append(SocRecommendation(
                priority="LOW",
                category="Investigation",
                title="Review the full MITRE ATT&CK kill chain",
                details=(
                    f"{len(result.mitre_techniques)} MITRE technique(s) mapped across "
                    f"{len(tactic_names)} tactic(s): {', '.join(tactic_names)}. "
                    "Review the Navigator to understand the complete attack chain and identify gaps."
                ),
                actions=[
                    "Map all detected techniques in the MITRE ATT&CK Navigator",
                    "Identify kill-chain phases that are covered vs. potentially missed",
                    "Use technique IDs to query threat intel for known associated campaigns",
                    "Review your detection coverage for techniques that did NOT generate alerts",
                ],
            ))

        return recs

    # ------------------------------------------------------------------
    # Intelligent narrative builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_rich_narrative(result: AnalysisResult) -> List[Dict]:
        """
        Build an ordered list of incident phase dicts describing what happened.

        Each dict:
          "id"       — CSS anchor id
          "phase"    — Phase name  (e.g. "Initial Execution")
          "severity" — "critical" | "high" | "medium" | "low" | "info"
          "icon"     — emoji icon
          "title"    — Short descriptive title adapting to the data
          "text"     — 2-3 sentence plain-English narrative
          "evidence" — List[str] of specific IOCs / commands / paths
          "mitre"    — List[str] of relevant "technique (tactic)" strings

        Only phases with relevant data are generated (except Phase 1 and final).
        """
        phases: List[Dict] = []
        ti  = result.bundle.threat_info
        es  = result.executive_summary
        cat = result.categorized

        hostname    = es.hostname    if es else "Unknown Host"
        username    = es.username    if es else "Unknown User"
        threat_name = es.threat_name if es else "Unknown Threat"
        attack_type = es.attack_type if es else "Malware"

        confidence  = (ti.get("confidenceLevel") or "unknown").lower()
        mit_status  = (ti.get("mitigationStatus") or "not_mitigated")
        sev_word    = {"malicious": "malicious", "suspicious": "suspicious"}.get(
            confidence, "potentially malicious"
        )

        # Use pre-computed core_process_keys (computed once in analyze() by
        # _build_core_process_keys, shared with _build_iocs and _detect_encryption).
        core_keys: Set[str] = result.core_process_keys or result.threat_process_keys

        def _is_core(e: Dict) -> bool:
            """Return True if event belongs to a confirmed threat process."""
            if e.get("processIsMalicious"):
                return True
            k = e.get("processUniqueKey")
            return bool(k and k in core_keys)

        # Helper: collect unique MITRE technique strings for given tactic names
        def _mitre_for(*tactics: str) -> List[str]:
            out: List[str] = []
            for t in result.mitre_techniques:
                if t.get("tactic") in tactics and t.get("technique"):
                    s = f"{t['technique']}  ({t['tactic']})"
                    if s not in out:
                        out.append(s)
            return out[:4]

        # ── Phase 1: Initial Execution ─────────────────────────────────────
        chain_str   = " → ".join(es.process_chain) if es and es.process_chain else "unknown process chain"
        first_str   = fmt_ts(es.first_event_ts) if es and es.first_event_ts else "unknown time"
        detect_str  = fmt_ts(es.detection_ts)   if es and es.detection_ts   else "unknown time"
        threat_path = ti.get("filePath") or ""
        engines     = ti.get("detectionEngines") or []
        engine_keys = [e.get("key", "") for e in engines if e.get("key")]

        exec_evidence: List[str] = []
        if chain_str:
            exec_evidence.append(f"Execution chain: {chain_str}")
        if threat_path:
            exec_evidence.append(f"Threat file: {threat_path}")
        if engine_keys:
            exec_evidence.append(f"Detection engine(s): {', '.join(engine_keys)}")
        # First trigger command as evidence
        if es and es.trigger_commands:
            cmd0 = es.trigger_commands[0].get("command", "")
            if cmd0:
                exec_evidence.append(f"First trigger: {cmd0[:120]}")

        exec_sev = "critical" if confidence == "malicious" else (
            "high" if confidence == "suspicious" else "medium"
        )
        phases.append({
            "id":       "narrative-exec",
            "phase":    "Initial Execution",
            "severity": exec_sev,
            "icon":     "\U0001f6a8",   # 🚨
            "title":    f"{sev_word.capitalize()} {attack_type} detected on {hostname}",
            "text": (
                f"SentinelOne identified a {sev_word} {attack_type} threat "
                f"\"{threat_name}\" on host \"{hostname}\" under user account \"{username}\". "
                f"Activity began at {first_str} and was detected at {detect_str}. "
                f"The attack progressed through the following process chain: {chain_str}."
            ),
            "evidence": exec_evidence,
            "mitre":    _mitre_for("Initial Access", "Execution"),
        })

        # ── Phase 2: Process Execution ─────────────────────────────────────
        if cat.process:
            mal_procs   = [e for e in cat.process if e.get("processIsMalicious")]
            # For evidence: use strictly core processes (chain + malicious)
            core_procs  = [e for e in cat.process if _is_core(e)]
            ordered     = core_procs if core_procs else [
                e for e in cat.process if e.get("relatedToThreat")
            ]
            seen_pn: Set[str] = set()
            proc_evidence: List[str] = []
            for e in ordered:
                pn  = e.get("processName", "")
                cmd = e.get("processCmd", "")
                if pn and pn not in seen_pn:
                    seen_pn.add(pn)
                    proc_evidence.append(
                        f"{pn}: {cmd[:100]}" if cmd else f"Process: {pn} (PID {e.get('pid', '?')})"
                    )
                if len(proc_evidence) >= 5:
                    break

            proc_sev   = "critical" if mal_procs else ("high" if core_procs else "low")
            core_names = list(dict.fromkeys(
                e.get("processName","") for e in core_procs if e.get("processName")
            ))[:5]
            text_parts = [f"{len(cat.process)} process event(s) recorded in this storyline."]
            if mal_procs:
                mal_names = list(dict.fromkeys(
                    e.get("processName","?") for e in mal_procs if e.get("processName")
                ))[:4]
                text_parts.append(
                    f"{len(mal_procs)} process(es) confirmed malicious: {', '.join(mal_names)}."
                )
            elif core_names:
                text_parts.append(
                    f"Key threat chain process(es): {', '.join(core_names)}."
                )
            if es and es.process_chain and len(es.process_chain) > 1:
                text_parts.append(
                    f"Execution chain: {es.process_chain[0]} \u2192 {es.process_chain[-1]}."
                )
            phases.append({
                "id":       "narrative-process",
                "phase":    "Process Execution",
                "severity": proc_sev,
                "icon":     "\u2699\ufe0f",   # ⚙️
                "title": (
                    f"{len(mal_procs)} malicious, {len(core_procs)} in threat chain "
                    f"({len(cat.process)} total process event(s))"
                ),
                "text":     " ".join(text_parts),
                "evidence": proc_evidence,
                "mitre":    _mitre_for("Execution", "Defense Evasion", "Privilege Escalation"),
            })

        # ── Phase 3: File System Activity ──────────────────────────────────
        if cat.file:
            # Strict filter: core threat processes only; fall back to relatedToThreat
            core_file = [e for e in cat.file if _is_core(e)]
            thr_file  = core_file or [
                e for e in cat.file if e.get("relatedToThreat") or e.get("processIsMalicious")
            ]
            # Count stats from core events only (avoids inflated numbers from unrelated procs)
            subtype_ctr: Counter = Counter(
                (e.get("eventSubType") or e.get("eventType") or "").upper().replace(" ", "")
                for e in (core_file or cat.file)
            )
            created  = subtype_ctr.get("FILECREATION", 0)
            modified = subtype_ctr.get("FILEMODIFICATION", 0)
            renamed  = subtype_ctr.get("FILERENAME", 0)
            deleted  = subtype_ctr.get("FILEDELETION", 0)

            file_stats = [
                part for part in [
                    f"{created} created"  if created  else "",
                    f"{modified} modified" if modified else "",
                    f"{renamed} renamed"  if renamed  else "",
                    f"{deleted} deleted"  if deleted  else "",
                ] if part
            ]
            stats_str = ", ".join(file_stats) if file_stats else f"{len(cat.file)} operations"

            # Evidence from core processes only
            file_evidence: List[str] = []
            seen_fp: Set[str] = set()
            for e in thr_file:
                fp = e.get("fileFullName") or e.get("oldFileName") or ""
                if fp and fp not in seen_fp:
                    seen_fp.add(fp)
                    sub = (e.get("eventSubType") or e.get("eventType") or "").upper().replace(" ","")
                    label = EVENT_TYPE_LABELS.get(sub, "File Op")
                    file_evidence.append(f"{label}: {fp[:120]}")
                if len(file_evidence) >= 5:
                    break

            file_sev = "critical" if result.encryption_indicators else ("high" if core_file else "medium")
            text_parts = [f"{len(cat.file)} file system event(s) recorded ({stats_str} by threat process(es))."]
            if result.encryption_indicators:
                text_parts.append(
                    f"Encryption/ransomware indicators were detected "
                    f"({len(result.encryption_indicators)} indicator(s))."
                )
            elif thr_file:
                dp = [e.get("fileFullName","") for e in thr_file if e.get("fileFullName")][:2]
                if dp:
                    text_parts.append(f"Key files: {'; '.join(dp[:2])}.")

            phases.append({
                "id":       "narrative-file",
                "phase":    "File System Activity",
                "severity": file_sev,
                "icon":     "\U0001f4c4",   # 📄
                "title":    f"File system: {stats_str} across {len(cat.file)} event(s)",
                "text":     " ".join(text_parts),
                "evidence": file_evidence,
                "mitre":    _mitre_for("Collection", "Impact", "Defense Evasion"),
            })

        # ── Phase 4: Registry Manipulation ────────────────────────────────
        if cat.registry:
            thr_reg    = [e for e in cat.registry if e.get("relatedToThreat") or e.get("processIsMalicious")]
            reg_sev    = "high" if result.suspicious_registry else ("medium" if thr_reg else "low")
            reg_evidence: List[str] = []
            for e in (result.suspicious_registry + thr_reg)[:6]:
                rp = e.get("registryPath") or ""
                if rp and rp not in reg_evidence:
                    sub = (e.get("eventSubType") or e.get("eventType") or "").upper().replace(" ","")
                    label = EVENT_TYPE_LABELS.get(sub, "Registry Op")
                    reg_evidence.append(f"{label}: {rp[:120]}")
                if len(reg_evidence) >= 5:
                    break

            text_parts = [f"{len(cat.registry)} registry event(s) observed during the incident."]
            if result.suspicious_registry:
                susp_paths = [e.get("registryPath","") for e in result.suspicious_registry[:2]]
                text_parts.append(
                    f"{len(result.suspicious_registry)} suspicious key(s) associated with "
                    f"persistence (Run/RunOnce, service install, Winlogon, etc.)."
                )
                if susp_paths and susp_paths[0]:
                    text_parts.append(f"Example: {susp_paths[0][:100]}")

            phases.append({
                "id":       "narrative-registry",
                "phase":    "Registry Manipulation",
                "severity": reg_sev,
                "icon":     "\U0001f511",   # 🔑
                "title": (
                    f"{len(cat.registry)} registry event(s), "
                    f"{len(result.suspicious_registry)} suspicious persistence key(s)"
                ),
                "text":     " ".join(text_parts),
                "evidence": reg_evidence,
                "mitre":    _mitre_for("Persistence", "Defense Evasion"),
            })

        # ── Phase 5: Network / C2 Communication ───────────────────────────
        if cat.network or cat.dns:
            all_net   = cat.network + cat.dns
            # Strict: core threat processes only; fall back to relatedToThreat
            core_net  = [e for e in all_net if _is_core(e)]
            thr_net   = core_net or [
                e for e in all_net if e.get("relatedToThreat") or e.get("processIsMalicious")
            ]
            # Evidence IPs/domains from core processes only
            ev_net    = core_net or all_net
            uniq_ips  = list(dict.fromkeys(e.get("dstIp","") for e in ev_net if e.get("dstIp")))
            uniq_doms = list(dict.fromkeys(e.get("dnsRequest","") for e in ev_net if e.get("dnsRequest")))
            net_evidence: List[str] = []
            for ip in uniq_ips[:4]:
                port  = next((e.get("dstPort","") for e in ev_net if e.get("dstIp") == ip), "")
                proto = next((e.get("protocol","") for e in ev_net if e.get("dstIp") == ip), "")
                proc  = next((e.get("processName","") for e in ev_net if e.get("dstIp") == ip), "")
                line  = f"Connection: {ip}"
                if port:  line += f":{port}"
                if proto: line += f" ({proto})"
                if proc:  line += f" \u2190 {proc}"
                net_evidence.append(line)
            for dom in uniq_doms[:3]:
                resp = next((e.get("dnsResponse","") for e in ev_net if e.get("dnsRequest") == dom), "")
                proc = next((e.get("processName","") for e in ev_net if e.get("dnsRequest") == dom), "")
                line = f"DNS: {dom}"
                if resp: line += f" \u2192 {resp}"
                if proc: line += f" \u2190 {proc}"
                net_evidence.append(line)

            net_sev    = "critical" if core_net else ("high" if thr_net else "medium")
            text_parts = [
                f"{len(all_net)} total network event(s): {len(uniq_ips)} IP(s) and "
                f"{len(uniq_doms)} domain(s) contacted by threat chain process(es)."
            ]
            if thr_net:
                thr_procs = list(dict.fromkeys(
                    e.get("processName","") for e in thr_net if e.get("processName")
                ))[:3]
                text_parts.append(
                    f"Outbound traffic from: {', '.join(thr_procs) if thr_procs else 'unknown'}."
                )
            if uniq_ips:
                text_parts.append(f"Destination IPs: {', '.join(uniq_ips[:3])}.")
            if uniq_doms:
                text_parts.append(f"DNS queries: {', '.join(uniq_doms[:3])}.")

            phases.append({
                "id":       "narrative-network",
                "phase":    "Network / C2 Communication",
                "severity": net_sev,
                "icon":     "\U0001f310",   # 🌐
                "title": (
                    f"{len(uniq_ips)} destination IP(s) and {len(uniq_doms)} domain(s) "
                    "by threat chain process(es)"
                ),
                "text":     " ".join(text_parts),
                "evidence": net_evidence,
                "mitre":    _mitre_for("Command and Control", "Exfiltration", "Discovery"),
            })

        # ── Phase 6: Credential & Login Activity ──────────────────────────
        if cat.login:
            failed_logins  = [
                e for e in cat.login
                if (e.get("eventType") or "").upper().replace(" ","") == "LOGINFAILED"
            ]
            success_logins = [
                e for e in cat.login
                if (e.get("eventType") or "").upper().replace(" ","") == "LOGINSUCCESS"
            ]
            # Strict: core threat processes first; fall back to relatedToThreat
            core_logins = [e for e in cat.login if _is_core(e)]
            susp_logins = core_logins or [
                e for e in cat.login
                if e.get("relatedToThreat") or e.get("processIsMalicious")
            ]
            login_evidence: List[str] = []
            seen_lu: Set[str] = set()
            for e in (susp_logins or cat.login):
                usr = e.get("loginsUserName") or e.get("processUserName") or ""
                lt  = e.get("loginsBaseType") or ""
                if usr and usr not in seen_lu:
                    seen_lu.add(usr)
                    line = f"Login: {usr}"
                    if lt:  line += f" ({lt})"
                    if e in failed_logins: line += " [FAILED]"
                    login_evidence.append(line)
                if len(login_evidence) >= 5:
                    break

            login_sev  = "high" if (susp_logins or result.account_creation_events) else (
                "medium" if failed_logins else "low"
            )
            text_parts = [
                f"{len(cat.login)} login event(s): "
                f"{len(success_logins)} successful, {len(failed_logins)} failed."
            ]
            if susp_logins:
                lu_names = list(dict.fromkeys(
                    e.get("loginsUserName","") for e in susp_logins if e.get("loginsUserName")
                ))[:3]
                text_parts.append(
                    f"{len(susp_logins)} login event(s) directly associated with the threat "
                    f"(user(s): {', '.join(lu_names) if lu_names else 'unknown'})."
                )
            if result.account_creation_events:
                text_parts.append(
                    f"{len(result.account_creation_events)} potential account "
                    "creation/manipulation event(s) detected."
                )

            phases.append({
                "id":       "narrative-login",
                "phase":    "Credential & Login Activity",
                "severity": login_sev,
                "icon":     "\U0001f464",   # 👤
                "title": (
                    f"{len(cat.login)} login event(s): "
                    f"{len(success_logins)} success, {len(failed_logins)} failed"
                ),
                "text":     " ".join(text_parts),
                "evidence": login_evidence,
                "mitre":    _mitre_for("Credential Access", "Privilege Escalation", "Lateral Movement"),
            })

        # ── Phase 7: Persistence Mechanisms ───────────────────────────────
        task_trig = [
            e for e in cat.scheduled_task
            if e.get("relatedToThreat") or e.get("processIsMalicious")
        ]
        if result.suspicious_registry or task_trig:
            pers_evidence: List[str] = []
            for e in result.suspicious_registry[:3]:
                rp = e.get("registryPath","")
                if rp:
                    pers_evidence.append(f"Run key: {rp[:120]}")
            for e in task_trig[:3]:
                tn = e.get("taskName","?")
                tp = e.get("taskPath","")
                line = f"Scheduled task: {tn}"
                if tp: line += f" \u2192 {tp[:80]}"
                pers_evidence.append(line)

            pers_sev   = "critical" if (result.suspicious_registry and task_trig) else "high"
            text_parts = []
            if result.suspicious_registry:
                text_parts.append(
                    f"{len(result.suspicious_registry)} registry-based persistence mechanism(s) "
                    "detected (Run/RunOnce keys, service install, Winlogon)."
                )
            if task_trig:
                tn_names = [e.get("taskName","?") for e in task_trig[:3]]
                text_parts.append(
                    f"{len(task_trig)} malicious scheduled task(s) created: "
                    f"{', '.join(tn_names)}. "
                    "These ensure the threat survives system reboots."
                )

            phases.append({
                "id":       "narrative-persistence",
                "phase":    "Persistence Mechanisms",
                "severity": pers_sev,
                "icon":     "\U0001f512",   # 🔒
                "title": (
                    f"{len(result.suspicious_registry)} registry key(s) + "
                    f"{len(task_trig)} scheduled task(s) — persistence confirmed"
                ),
                "text":     " ".join(text_parts),
                "evidence": pers_evidence,
                "mitre":    _mitre_for("Persistence"),
            })

        # ── Phase 8: Ransomware / Encryption ──────────────────────────────
        if result.encryption_indicators:
            ext_inds = [
                i for i in result.encryption_indicators
                if "extension" in i.get("reason","").lower()
            ]
            vol_inds = [i for i in result.encryption_indicators if i.get("count")]
            ransom_evidence: List[str] = []
            for ind in ext_inds[:3]:
                ransom_evidence.append(ind.get("reason","")[:120])
            for ind in vol_inds[:2]:
                ransom_evidence.append(
                    f"High-volume modifications: {ind.get('count',0)} files "
                    f"by {ind.get('proc_name','?')}"
                )

            text_parts = [
                f"{len(result.encryption_indicators)} encryption/ransomware indicator(s) detected."
            ]
            if ext_inds:
                text_parts.append(
                    "Files renamed with ransomware-typical extensions "
                    "(.locked, .enc, .crypt, etc.) were observed."
                )
            if vol_inds:
                total_mods = sum(i.get("count",0) for i in vol_inds)
                text_parts.append(
                    f"Anomalously high file modification volume: {total_mods} files in a short "
                    "window — consistent with bulk encryption behavior."
                )

            phases.append({
                "id":       "narrative-ransomware",
                "phase":    "Ransomware / Encryption",
                "severity": "critical",
                "icon":     "\U0001f510",   # 🔐
                "title":    f"{len(result.encryption_indicators)} encryption indicator(s) detected",
                "text":     " ".join(text_parts),
                "evidence": ransom_evidence,
                "mitre":    _mitre_for("Impact"),
            })

        # ── Phase 9: MITRE ATT&CK Kill Chain ──────────────────────────────
        if result.mitre_techniques:
            tactics = sorted({
                t.get("tactic","") for t in result.mitre_techniques if t.get("tactic")
            })
            mitre_evidence = [
                f"{t['technique']}  \u2014  {t['tactic']}"
                for t in result.mitre_techniques[:8]
            ]
            # Build kill-chain order
            KILL_CHAIN_ORDER = [
                "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Collection", "Command and Control", "Exfiltration", "Impact",
            ]
            kill_chain = [t for t in KILL_CHAIN_ORDER if t in tactics]
            text_parts = [
                f"{len(result.mitre_techniques)} MITRE ATT&CK technique(s) identified "
                f"across {len(tactics)} tactic(s): {', '.join(tactics)}."
            ]
            if kill_chain:
                text_parts.append(
                    f"Kill-chain phases observed: {' \u2192 '.join(kill_chain)}."
                )

            mitre_sev = "high" if len(tactics) >= 3 else "medium"
            phases.append({
                "id":       "narrative-mitre",
                "phase":    "MITRE ATT\u0026CK Kill Chain",
                "severity": mitre_sev,
                "icon":     "\U0001f3af",   # 🎯
                "title":    f"{len(result.mitre_techniques)} technique(s) across {len(tactics)} tactic(s)",
                "text":     " ".join(text_parts),
                "evidence": mitre_evidence,
                "mitre":    [],
            })

        # ── Phase 10: Detection & Response (always) ───────────────────────
        is_mitigated = any(
            k in mit_status.lower()
            for k in ("remediat","quarantin","killed","mitigated")
        )
        incident_status = ti.get("incidentStatus") or "unresolved"
        det_evidence = [
            f"Detection time: {detect_str}",
            f"Confidence: {confidence}",
            f"Mitigation: {mit_status}",
            f"Incident status: {incident_status}",
        ]
        if engine_keys:
            det_evidence.insert(1, f"Detection engine(s): {', '.join(engine_keys)}")

        text_parts = [
            f"SentinelOne detected \"{threat_name}\" with {confidence} confidence at {detect_str}."
        ]
        if engine_keys:
            text_parts.append(f"Detection engine(s): {', '.join(engine_keys)}.")
        if is_mitigated:
            text_parts.append(f"Threat has been mitigated (status: {mit_status}).")
        else:
            text_parts.append(
                f"Mitigation status is \"{mit_status}\" — immediate analyst action recommended."
            )

        det_sev = "low" if is_mitigated else (
            "critical" if confidence == "malicious" else "medium"
        )
        phases.append({
            "id":       "narrative-detection",
            "phase":    "Detection & Response",
            "severity": det_sev,
            "icon":     "\U0001f6e1\ufe0f",   # 🛡️
            "title":    f"Detected with {confidence} confidence — mitigation: {mit_status}",
            "text":     " ".join(text_parts),
            "evidence": det_evidence,
            "mitre":    [],
        })

        return phases

    # ------------------------------------------------------------------
    # Sorted timeline
    # ------------------------------------------------------------------

    def _build_sorted_timeline(self, result: AnalysisResult) -> None:
        def _ts(evt: Dict) -> str:
            return evt.get("createdAt") or evt.get("processStartTime") or ""

        result.timeline_sorted = sorted(result.bundle.events, key=_ts)


# ---------------------------------------------------------------------------
# Utilities used by reporters
# ---------------------------------------------------------------------------

def fmt_ts(iso_ts: Optional[str]) -> str:
    """Format an ISO 8601 timestamp to a human-readable string."""
    if not iso_ts:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso_ts


def event_icon(evt: Dict) -> str:
    obj_type = (evt.get("objectType") or "").lower()
    subtype = (evt.get("eventSubType") or evt.get("eventType") or "").upper()
    subtype_norm = subtype.replace(" ", "")   # "PROCESS CREATION" → "PROCESSCREATION"
    return (EVENT_TYPE_ICONS.get(subtype)
            or EVENT_TYPE_ICONS.get(subtype_norm)
            or EVENT_TYPE_ICONS.get(obj_type)
            or "•")


def event_label(evt: Dict) -> str:
    subtype = evt.get("eventSubType") or evt.get("eventType") or ""
    subtype_norm = subtype.upper().replace(" ", "")   # "File Creation" → "FILECREATION"
    obj_type = evt.get("objectType") or ""
    return (
        EVENT_TYPE_LABELS.get(subtype)
        or EVENT_TYPE_LABELS.get(subtype.upper())
        or EVENT_TYPE_LABELS.get(subtype_norm)
        or EVENT_TYPE_LABELS.get(obj_type.lower())
        or subtype
        or obj_type
        or "Event"
    )


def _infer_event_type(evt: Dict) -> str:
    """
    Return the most informative event-type label available.

    S1's real API sometimes returns objectType ("process", "file", …) without
    populating eventType/eventSubType.  In that case event_label() falls back
    to generic names like "Process".  This function adds field-presence
    heuristics so the trigger-commands table always shows something useful.
    """
    raw = evt.get("eventSubType") or evt.get("eventType") or ""
    if raw:
        # We have a raw type — map it if possible, else show it as-is
        return (
            EVENT_TYPE_LABELS.get(raw)
            or EVENT_TYPE_LABELS.get(raw.upper())
            or raw
        )

    # No raw type — infer from objectType + available fields
    obj = (evt.get("objectType") or "").lower()
    if obj == "process":
        return "Process Creation"
    if obj == "file":
        subtype = (evt.get("eventSubType") or "").upper()
        return EVENT_TYPE_LABELS.get(subtype) or "File Operation"
    if obj in ("ip", "url"):
        return "Network Connection"
    if obj == "dns":
        return "DNS Lookup"
    if obj == "registry":
        return "Registry Operation"
    if obj == "login":
        return "Login Event"
    if obj == "scheduled_task":
        return "Scheduled Task"
    return event_label(evt)
