"""
CSV Reporter - Exports all events to a flat CSV file.

The CSV contains every field from the events API response,
normalised to snake_case columns. This serves as the working
base for further investigation (SIEM import, Excel pivot, etc.).
"""
from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..analyzer import AnalysisResult, fmt_ts


# Ordered set of columns we always include (even if empty) – plus all
# dynamic keys discovered in the event data.
CANONICAL_COLUMNS = [
    "createdAt",
    "objectType",
    "eventType",
    "eventSubType",
    "relatedToThreat",
    "processIsMalicious",
    "parentProcessIsMalicious",
    # Process
    "processName",
    "processDisplayName",
    "processCmd",
    "processImagePath",
    "processUniqueKey",
    "parentProcessUniqueKey",
    "pid",
    "parentPid",
    "processStartTime",
    "processUserName",
    "processIntegrityLevel",
    "processSessionId",
    "processRoot",
    "processIsWow64",
    "publisher",
    "signedStatus",
    "verifiedStatus",
    # File
    "fileFullName",
    "fileId",
    "fileMd5",
    "fileSha1",
    "fileSha256",
    "fileSize",
    "fileType",
    "oldFileName",
    "oldFileMd5",
    "oldFileSha1",
    "oldFileSha256",
    # Registry
    "registryPath",
    "registryClassification",
    "registryId",
    # Network
    "dstIp",
    "dstPort",
    "srcIp",
    "srcPort",
    "protocol",
    "direction",
    "connectionStatus",
    "networkUrl",
    "networkSource",
    "networkMethod",
    # DNS
    "dnsRequest",
    "dnsResponse",
    # Login
    "loginsUserName",
    "loginsBaseType",
    # Task
    "taskName",
    "taskPath",
    # Indicators
    "indicatorName",
    "indicatorCategory",
    "indicatorDescription",
    "indicatorMetadata",
    # Agent
    "agentId",
    "agentName",
    "agentOs",
    "agentIp",
    "agentVersion",
    "siteId",
    "siteName",
    "storyline",
    "id",
    "sha1",
    "sha256",
    "md5",
    "user",
    "rpid",
    "tid",
]


class CSVReporter:

    def write(self, result: AnalysisResult, output_dir: str) -> str:
        """
        Write all events to a CSV file.

        Returns:
            Absolute path of the written file.
        """
        events = result.bundle.events
        if not events:
            return ""

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        storyline = result.bundle.storyline_id.replace("/", "_").replace("\\", "_")
        filename = f"S1_Events_{storyline}_{timestamp}.csv"
        filepath = os.path.join(output_dir, filename)

        # Discover all keys present in the data
        all_keys: set = set(CANONICAL_COLUMNS)
        for evt in events:
            all_keys.update(evt.keys())

        # Build ordered fieldnames: canonical first, then extras
        extra_keys = sorted(all_keys - set(CANONICAL_COLUMNS))
        fieldnames = CANONICAL_COLUMNS + extra_keys

        with open(filepath, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=fieldnames,
                extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
            )
            writer.writeheader()

            for evt in sorted(events, key=lambda e: e.get("createdAt") or ""):
                # Flatten nested objects to string
                row: Dict[str, Any] = {}
                for key in fieldnames:
                    val = evt.get(key)
                    if isinstance(val, (dict, list)):
                        val = str(val)
                    row[key] = val if val is not None else ""
                writer.writerow(row)

        return filepath
