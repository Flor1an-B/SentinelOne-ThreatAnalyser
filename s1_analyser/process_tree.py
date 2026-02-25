"""
Process Tree Builder - Reconstructs the process hierarchy from events.

The SentinelOne events API provides:
  processUniqueKey       → unique identifier for a process instance
  parentProcessUniqueKey → parent's unique key
  processName            → image name
  pid / parentPid        → PIDs
  processStartTime       → when the process was created
  processCmd             → full command line
  processImagePath       → path on disk
  processUserName        → user context
  relatedToThreat        → whether any event in this process triggered detection
  processIsMalicious     → SentinelOne marked process as malicious
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .analyzer import fmt_ts, event_icon, event_label


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ProcessNode:
    """One process in the tree."""
    unique_key: str
    name: str = "unknown"
    pid: str = ""
    parent_pid: str = ""
    parent_unique_key: str = ""
    start_time: str = ""
    cmd: str = ""
    image_path: str = ""
    user: str = ""
    integrity_level: str = ""
    is_malicious: bool = False
    parent_is_malicious: bool = False
    related_to_threat: bool = False
    publisher: str = ""
    signed_status: str = ""

    children: List["ProcessNode"] = field(default_factory=list)
    events: List[Dict] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.is_malicious or self.related_to_threat

    @property
    def display_name(self) -> str:
        name = self.name or "unknown"
        pid_str = f" (PID:{self.pid})" if self.pid else ""
        return f"{name}{pid_str}"


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class ProcessTreeBuilder:
    """
    Builds a forest (list of root nodes) from a flat list of events.

    Algorithm:
      1. Walk events, create/update ProcessNode for each unique process key.
      2. Link parent → child using parentProcessUniqueKey.
      3. Roots = nodes whose parent key is absent from the node map.
      4. Sort children chronologically by start_time.
    """

    def build(self, events: List[Dict]) -> List[ProcessNode]:
        """Return a list of root ProcessNode objects."""
        node_map: Dict[str, ProcessNode] = {}

        for evt in events:
            key = evt.get("processUniqueKey") or ""
            if not key:
                continue

            # Create node if new
            if key not in node_map:
                node_map[key] = self._make_node(evt)
            else:
                self._update_node(node_map[key], evt)

            # Attach event to its owning process
            node_map[key].events.append(evt)

            # Ensure parent node exists (may be created as a stub)
            parent_key = evt.get("parentProcessUniqueKey") or ""
            if parent_key and parent_key not in node_map:
                node_map[parent_key] = ProcessNode(
                    unique_key=parent_key,
                    name=evt.get("parentProcessName") or "unknown",
                    pid=evt.get("parentPid") or "",
                )

        # Wire parent → child links
        for key, node in node_map.items():
            parent_key = node.parent_unique_key
            if parent_key and parent_key in node_map:
                parent = node_map[parent_key]
                if node not in parent.children:
                    parent.children.append(node)

        # Sort children by start time
        for node in node_map.values():
            node.children.sort(key=lambda n: n.start_time or "")

        # Find roots: nodes whose parent key is not in the map
        roots: List[ProcessNode] = []
        for key, node in node_map.items():
            if not node.parent_unique_key or node.parent_unique_key not in node_map:
                roots.append(node)

        roots.sort(key=lambda n: n.start_time or "")
        return roots

    # ------------------------------------------------------------------

    @staticmethod
    def _make_node(evt: Dict) -> ProcessNode:
        return ProcessNode(
            unique_key=evt.get("processUniqueKey", ""),
            name=evt.get("processName") or evt.get("processDisplayName") or "unknown",
            pid=str(evt.get("pid") or ""),
            parent_pid=str(evt.get("parentPid") or ""),
            parent_unique_key=evt.get("parentProcessUniqueKey") or "",
            start_time=evt.get("processStartTime") or evt.get("createdAt") or "",
            cmd=evt.get("processCmd") or "",
            image_path=evt.get("processImagePath") or "",
            user=evt.get("processUserName") or evt.get("user") or "",
            integrity_level=evt.get("processIntegrityLevel") or "",
            is_malicious=bool(evt.get("processIsMalicious")),
            parent_is_malicious=bool(evt.get("parentProcessIsMalicious")),
            related_to_threat=bool(evt.get("relatedToThreat")),
            publisher=evt.get("publisher") or "",
            signed_status=evt.get("signedStatus") or "",
        )

    @staticmethod
    def _update_node(node: ProcessNode, evt: Dict) -> None:
        """Enrich an existing node with data from a later event."""
        if not node.name or node.name == "unknown":
            node.name = evt.get("processName") or evt.get("processDisplayName") or node.name
        if not node.cmd:
            node.cmd = evt.get("processCmd") or ""
        if not node.image_path:
            node.image_path = evt.get("processImagePath") or ""
        if not node.user:
            node.user = evt.get("processUserName") or evt.get("user") or ""
        if not node.start_time:
            node.start_time = evt.get("processStartTime") or evt.get("createdAt") or ""
        if not node.integrity_level:
            node.integrity_level = evt.get("processIntegrityLevel") or ""
        if not node.publisher:
            node.publisher = evt.get("publisher") or ""
        if not node.signed_status:
            node.signed_status = evt.get("signedStatus") or ""
        # OR-accumulate flags
        if evt.get("processIsMalicious"):
            node.is_malicious = True
        if evt.get("parentProcessIsMalicious"):
            node.parent_is_malicious = True
        if evt.get("relatedToThreat"):
            node.related_to_threat = True


# ---------------------------------------------------------------------------
# ASCII renderer (used by Markdown / plain text reporters)
# ---------------------------------------------------------------------------

def render_ascii_tree(
    roots: List[ProcessNode],
    max_depth: int = 20,
    max_events_per_node: int = 5,
) -> List[str]:
    """Return a list of strings representing the ASCII process tree."""
    lines: List[str] = []

    def _render(node: ProcessNode, prefix: str = "", depth: int = 0) -> None:
        if depth > max_depth:
            return

        # Node header
        flag = " [DETECTION TRIGGER]" if node.related_to_threat else ""
        mal = " [MALICIOUS]" if node.is_malicious else ""
        ts = f" @ {fmt_ts(node.start_time)}" if node.start_time else ""
        user = f"  user:{node.user}" if node.user else ""
        prefix_marker = "[!]" if node.is_suspicious else "[ ]"
        label = f"{prefix_marker} {node.display_name}{ts}{user}{flag}{mal}"

        lines.append(f"{prefix}{label}")

        # Selected events under this node
        child_prefix = prefix.replace("+-- ", "|   ").replace("\\-- ", "    ")
        shown = 0
        for evt in sorted(node.events, key=lambda e: e.get("createdAt") or ""):
            if shown >= max_events_per_node:
                remaining = len(node.events) - shown
                lines.append(f"{child_prefix}    ... +{remaining} more events")
                break
            lbl = event_label(evt)
            ts_e = fmt_ts(evt.get("createdAt") or "")
            detail = _event_detail(evt)
            trigger = " <-- TRIGGER" if evt.get("relatedToThreat") else ""
            lines.append(f"{child_prefix}    [{ts_e}] {lbl}: {detail}{trigger}")
            shown += 1

        # Recurse children
        for i, child in enumerate(node.children):
            is_last = i == len(node.children) - 1
            connector = "\\-- " if is_last else "+-- "
            _render(child, child_prefix + connector, depth + 1)

    for i, root in enumerate(roots):
        is_last = i == len(roots) - 1
        connector = "\\-- " if is_last else "+-- "
        _render(root, connector)
        if not is_last:
            lines.append("|")

    return lines


def _event_detail(evt: Dict) -> str:
    """Return a short human-readable detail for an event."""
    # File
    if evt.get("fileFullName"):
        name = evt.get("fileFullName", "")
        old = evt.get("oldFileName")
        if old:
            return f"{old} -> {name}"
        return name
    # Registry
    if evt.get("registryPath"):
        return evt["registryPath"]
    # Network
    if evt.get("dstIp"):
        port = evt.get("dstPort", "")
        proto = evt.get("protocol", "")
        return f"{evt['dstIp']}:{port} ({proto})"
    # DNS
    if evt.get("dnsRequest"):
        return evt["dnsRequest"]
    # Login
    if evt.get("loginsUserName"):
        return evt["loginsUserName"]
    # Scheduled task
    if evt.get("taskName"):
        return evt.get("taskName", "")
    # Command line fallback
    cmd = evt.get("processCmd") or ""
    return cmd[:100] if cmd else ""
