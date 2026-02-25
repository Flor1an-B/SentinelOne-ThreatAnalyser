"""
Data Collector - Orchestrates all API calls and packages raw data
into a structured AnalysisBundle.

Key responsibility: after fetching events, _normalize_event() maps the
SentinelOne Deep Visibility field naming convention (srcProc*, tgtProc*,
tgtFile*, netConn*, networkDns*, registryKeyPath, loginUserName, etc.)
to the internal canonical names used throughout the rest of the codebase.
This keeps the rest of the code clean and also compatible with mock data.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from .api_client import S1APIClient, S1APIError

logger = logging.getLogger(__name__)
_console = Console(highlight=False)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AnalysisBundle:
    """All raw data collected from the SentinelOne API for one threat."""

    storyline_id: str
    threat: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # --- Convenience accessors ---

    @property
    def threat_id(self) -> str:
        return self.threat.get("id", "")

    @property
    def threat_info(self) -> Dict:
        return self.threat.get("threatInfo", {})

    @property
    def agent_detection_info(self) -> Dict:
        return self.threat.get("agentDetectionInfo", {})

    @property
    def agent_realtime_info(self) -> Dict:
        return self.threat.get("agentRealtimeInfo", {})

    @property
    def indicators(self) -> List[Dict]:
        return self.threat.get("indicators", [])


# ---------------------------------------------------------------------------
# Field-name normalisation for Deep Visibility events
# ---------------------------------------------------------------------------

def _normalize_event(evt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add canonical field aliases for SentinelOne Deep Visibility events.

    The explore/events endpoint uses prefixed field names:
      srcProc*  — the process that performed the action (source)
      tgtProc*  — the process that was created (for PROCESSCREATION only)
      tgtFile*  — file that was acted upon
      netConn*  — network connection details
      networkDns* — DNS query details
      registryKeyPath — registry key (not registryPath)
      loginUserName / loginType — login details

    We add un-prefixed aliases (e.g. processName, fileFullName, dstIp …)
    so all downstream code (analyzer, reporters, process tree) works
    unchanged, and mock data (which already uses canonical names) is
    unaffected (setdefault semantics: only set if the key is absent/empty).
    """

    def _bool(val: Any) -> bool:
        if isinstance(val, bool):
            return val
        if isinstance(val, str):
            return val.upper() in ("TRUE", "YES", "1")
        return bool(val)

    def _add(canon: str, *src_keys: str) -> None:
        """Set evt[canon] from the first non-empty src_key, only if canon is absent."""
        if evt.get(canon):          # already present → keep (mock data or prior normalization)
            return
        for k in src_keys:
            v = evt.get(k)
            if v is not None and v != "":
                evt[canon] = v
                return

    # Normalise eventType: strip spaces so "Process Creation" == "PROCESSCREATION"
    evt_type = (evt.get("eventType") or "").upper().replace(" ", "")

    # ------------------------------------------------------------------
    # Process fields
    # ------------------------------------------------------------------
    if evt_type == "PROCESSCREATION":
        # tgt* = the newly created child process
        # src* = the parent process that spawned it
        _add("processUniqueKey",       "tgtProcUniqueKey")
        _add("processName",            "tgtProcName", "tgtProcDisplayName")
        _add("pid",                    "tgtProcPid")
        _add("processCmd",             "tgtProcCmdLine")
        _add("processImagePath",       "tgtProcImagePath")
        _add("processStartTime",       "tgtProcStartTime")
        _add("processIntegrityLevel",  "tgtProcIntegrityLevel")
        _add("processUserName",        "tgtProcUser", "srcProcUser")
        _add("publisher",              "tgtProcPublisher", "srcProcPublisher")
        _add("signedStatus",           "tgtProcSignedStatus", "srcProcSignedStatus")
        _add("parentProcessUniqueKey", "srcProcUniqueKey")
        _add("parentProcessName",      "srcProcName", "srcProcDisplayName")
        _add("parentPid",              "srcProcPid")
        if not evt.get("processIsMalicious"):
            evt["processIsMalicious"] = _bool(evt.get("tgtProcIsMalicious"))
        if not evt.get("parentProcessIsMalicious"):
            evt["parentProcessIsMalicious"] = _bool(evt.get("srcProcIsMalicious"))
    else:
        # src* = the process that performed the action
        _add("processUniqueKey",       "srcProcUniqueKey")
        _add("processName",            "srcProcName", "srcProcDisplayName")
        _add("pid",                    "srcProcPid")
        _add("processCmd",             "srcProcCmdLine")
        _add("processImagePath",       "srcProcImagePath")
        _add("processStartTime",       "srcProcStartTime")
        _add("processIntegrityLevel",  "srcProcIntegrityLevel")
        _add("processUserName",        "srcProcUser")
        _add("publisher",              "srcProcPublisher")
        _add("signedStatus",           "srcProcSignedStatus")
        _add("parentProcessUniqueKey", "srcProcParentUniqueKey")
        _add("parentProcessName",      "srcProcParentName")
        _add("parentPid",              "srcProcParentPid")
        if not evt.get("processIsMalicious"):
            evt["processIsMalicious"] = _bool(evt.get("srcProcIsMalicious"))
        if not evt.get("parentProcessIsMalicious"):
            evt["parentProcessIsMalicious"] = _bool(evt.get("srcProcParentIsMalicious"))

    # ------------------------------------------------------------------
    # File fields  (tgt = target file that was acted upon)
    # ------------------------------------------------------------------
    _add("fileFullName", "tgtFilePath")
    _add("oldFileName",  "tgtFileOldPath")
    _add("fileSha1",     "tgtFileSha1")
    _add("fileSha256",   "tgtFileSha256")
    _add("fileMd5",      "tgtFileMd5")
    _add("fileSize",     "tgtFileSize")
    _add("fileType",     "tgtFileType")
    _add("fileIsSigned", "tgtFileIsSigned")

    # ------------------------------------------------------------------
    # Network fields
    # ------------------------------------------------------------------
    _add("dstIp",    "netConnDstIp")
    _add("srcIp",    "netConnSrcIp")
    _add("dstPort",  "netConnDstPort")
    _add("srcPort",  "netConnSrcPort")
    _add("protocol", "netConnProtocol")
    # netConnDirection is kept under its original name (IN / OUT)

    # ------------------------------------------------------------------
    # DNS fields
    # ------------------------------------------------------------------
    _add("dnsRequest",  "networkDnsRequest")
    _add("dnsResponse", "networkDnsResponse")

    # ------------------------------------------------------------------
    # Registry fields
    # ------------------------------------------------------------------
    _add("registryPath",  "registryKeyPath")
    # registryValue, registryData, registryNewValue — unchanged

    # ------------------------------------------------------------------
    # Login fields
    # ------------------------------------------------------------------
    _add("loginsUserName", "loginUserName")
    _add("loginsBaseType", "loginType")

    # ------------------------------------------------------------------
    # Boolean normalisation  (API may return "TRUE"/"FALSE" strings)
    # ------------------------------------------------------------------
    for bool_field in ("relatedToThreat", "processIsMalicious", "parentProcessIsMalicious"):
        val = evt.get(bool_field)
        if val is not None:
            evt[bool_field] = _bool(val)

    return evt


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class DataCollector:
    """
    Collects all threat data from SentinelOne and returns an AnalysisBundle.

    Usage:
        collector = DataCollector(client)
        bundle    = collector.collect(storyline_id)
    """

    def __init__(self, client: S1APIClient) -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def collect(self, storyline_id: str) -> AnalysisBundle:
        """Collect all data for *storyline_id* and return an AnalysisBundle."""
        bundle = AnalysisBundle(storyline_id=storyline_id)

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description:<45}"),
            BarColumn(bar_width=28),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=_console,
            transient=False,
        )

        with progress:
            # Step 1 – Locate threat
            t1 = progress.add_task("Locating threat ...", total=None)
            self._collect_threat(bundle, progress, t1)

            if not bundle.threat:
                bundle.errors.append(
                    f"No threat found for storyline: {storyline_id}"
                )
                return bundle

            # Step 2 – Events
            t2 = progress.add_task("Fetching events ...", total=None)
            self._collect_events(bundle, progress, t2)

            # Step 3 – Timeline
            t3 = progress.add_task("Fetching timeline ...", total=None)
            self._collect_timeline(bundle, progress, t3)

        return bundle

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _collect_threat(
        self,
        bundle: AnalysisBundle,
        progress: Progress,
        task_id,
    ) -> None:
        try:
            threats = self._client.get_threats_by_storyline(bundle.storyline_id)
            if not threats:
                return
            exact = [
                t for t in threats
                if t.get("threatInfo", {}).get("storyline") == bundle.storyline_id
            ]
            bundle.threat = exact[0] if exact else threats[0]
            threat_name = bundle.threat_info.get("threatName") or bundle.threat_id
            progress.update(
                task_id,
                total=1,
                completed=1,
                description=f"Threat located: {threat_name[:38]}",
            )
        except S1APIError as exc:
            msg = f"Threat fetch error: {exc}"
            bundle.errors.append(msg)
            logger.error(msg)
            progress.update(task_id, description="[red]Threat fetch FAILED")

    def _collect_events(
        self,
        bundle: AnalysisBundle,
        progress: Progress,
        task_id,
    ) -> None:
        total_holder: List[int] = [0]

        def _cb(fetched_count: int, total: int) -> None:
            total_holder[0] = total or fetched_count
            progress.update(
                task_id,
                total=total_holder[0],
                completed=fetched_count,
                description=f"Fetching events ... ({fetched_count}/{total_holder[0]})",
            )

        try:
            raw = self._client.get_threat_events(
                bundle.threat_id,
                progress_callback=_cb,
            )
            # Normalise field names for Deep Visibility events
            bundle.events = [_normalize_event(e) for e in raw]
            progress.update(
                task_id,
                total=len(bundle.events) or 1,
                completed=len(bundle.events) or 1,
                description=f"Events collected: {len(bundle.events)} events",
            )
        except S1APIError as exc:
            msg = (
                f"Events fetch error: {exc}\n"
                "  --> Check that your token has 'Endpoint Forensics View' or "
                "'Threat Forensics View' permission."
            )
            bundle.errors.append(msg)
            logger.error(msg)
            progress.update(task_id, description="[red]Events fetch FAILED (permission?)")

    def _collect_timeline(
        self,
        bundle: AnalysisBundle,
        progress: Progress,
        task_id,
    ) -> None:
        total_holder: List[int] = [0]

        def _cb(fetched_count: int, total: int) -> None:
            total_holder[0] = total or fetched_count
            progress.update(
                task_id,
                total=total_holder[0],
                completed=fetched_count,
                description=f"Fetching timeline ... ({fetched_count}/{total_holder[0]})",
            )

        try:
            fetched = self._client.get_threat_timeline(
                bundle.threat_id,
                progress_callback=_cb,
            )
            bundle.timeline = fetched
            progress.update(
                task_id,
                total=len(fetched) or 1,
                completed=len(fetched) or 1,
                description=f"Timeline collected: {len(fetched)} entries",
            )
        except S1APIError as exc:
            msg = f"Timeline fetch error: {exc}"
            bundle.errors.append(msg)
            logger.error(msg)
            progress.update(task_id, description="[red]Timeline fetch FAILED")
