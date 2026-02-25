"""
Terminal Reporter - Rich-powered console output for SOC analysts.

Renders a full forensic report directly in the terminal:
  - Threat & agent overview
  - Detection triggers table
  - Interactive process tree
  - Per-category event tables (file, registry, network, login, tasks)
  - Encryption / ransomware indicators
  - MITRE ATT&CK mapping
  - IOC summary
  - Collection statistics
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ..analyzer import AnalysisResult, fmt_ts, event_icon, event_label
from ..process_tree import ProcessNode, ProcessTreeBuilder, _event_detail

_default_console = Console(highlight=False)

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

C_GOOD    = "green"
C_BAD     = "bold red"
C_WARN    = "yellow"
C_DIM     = "dim"
C_CYAN    = "bold cyan"
C_BLUE    = "bold blue"
C_PURPLE  = "bold purple"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section(con: Console, title: str, colour: str = "cyan") -> None:
    con.print()
    con.print(Rule(f"[bold {colour}]  {title}  ", style=colour))
    con.print()


def _kv_table(rows: List[tuple], label_style: str = "bold dim", value_style: str = "white") -> Table:
    """Build a compact key-value grid (no box, pure padding)."""
    tbl = Table.grid(padding=(0, 3))
    tbl.add_column(style=label_style, justify="right", min_width=22)
    tbl.add_column(style=value_style, overflow="fold")
    for label, value, *rest in rows:
        style = rest[0] if rest else value_style
        tbl.add_row(label, Text(str(value) if value else "\u2014", style=style))
    return tbl


# ---------------------------------------------------------------------------
# Main reporter
# ---------------------------------------------------------------------------

class TerminalReporter:

    def __init__(self, con: Optional[Console] = None) -> None:
        self.con = con or _default_console

    def render(self, result: AnalysisResult) -> None:
        """Render the full forensic terminal report."""
        self.con.print()
        self._render_executive_summary(result)
        self._render_narrative(result)
        self._render_threat_summary(result)
        self._render_detection_triggers(result)
        self._render_process_tree(result)
        self._render_file_events(result)
        self._render_registry_events(result)
        self._render_network_events(result)
        self._render_login_events(result)
        self._render_task_events(result)
        self._render_encryption_indicators(result)
        self._render_soc_recommendations(result)
        self._render_mitre(result)
        self._render_iocs(result)
        self._render_stats(result)
        self._render_footer()

    # ------------------------------------------------------------------
    # 0. Executive summary
    # ------------------------------------------------------------------

    def _render_executive_summary(self, result: AnalysisResult) -> None:
        es = result.executive_summary
        if es is None:
            return

        conf_colour = C_BAD if es.attack_confidence == "malicious" else C_WARN

        def _dur(secs):
            if secs is None:
                return "\u2014"
            if secs < 60:
                return f"{secs:.0f}s"
            if secs < 3600:
                return f"{secs/60:.1f} min"
            return f"{secs/3600:.1f} h"

        self.con.print(Rule(
            f"[bold white]  EXECUTIVE SUMMARY  ",
            style="red",
            characters="═",
        ))
        self.con.print()

        # --- Narrative panel ---
        self.con.print(Panel(
            f"[white]{es.narrative}[/white]",
            title=(
                f"[{conf_colour}]{es.attack_confidence.upper()}[/{conf_colour}]"
                f"  [bold red]{es.attack_type}[/bold red]"
                f"  [dim]—[/dim]  [bold yellow]{es.threat_name}[/bold yellow]"
            ),
            border_style="red",
            padding=(1, 2),
        ))

        # --- When? / Origin? panels side by side ---
        when_rows = [
            ("First Event",         fmt_ts(es.first_event_ts) or "\u2014",  "white"),
            ("Last Event",          fmt_ts(es.last_event_ts)  or "\u2014",  "white"),
            ("S1 Detection",        fmt_ts(es.detection_ts)   or "\u2014",  "bold yellow"),
            ("Duration",            _dur(es.duration_seconds),               "bold cyan"),
            ("Mitigation",          es.mitigation_status or "\u2014",        "green"),
        ]

        chain_str = "  \u2192  ".join(es.process_chain) if es.process_chain else "\u2014"
        origin_rows = [
            ("Host",          es.hostname          or "\u2014", "bold green"),
            ("User",          es.username          or "\u2014", "yellow"),
            ("Threat File",   es.threat_file_path  or "\u2014", "dim"),
            ("Process Chain", chain_str,                         "bold red"),
        ]

        self.con.print(Columns([
            Panel(
                _kv_table(when_rows, "bold dim"),
                title="[bold cyan]\u23f1 When?",
                border_style="cyan",
                padding=(1, 2),
            ),
            Panel(
                _kv_table(origin_rows, "bold dim"),
                title="[bold green]\U0001f3af Origin?",
                border_style="green",
                padding=(1, 2),
            ),
        ], equal=True))

        # --- Commands that triggered detection ---
        if es.trigger_commands:
            tbl = Table(
                box=box.SIMPLE_HEAD,
                border_style="red",
                show_lines=False,
                expand=True,
                title="[bold red]\u26a1 Commands That Triggered Detection",
            )
            tbl.add_column("Timestamp",  style="dim",        no_wrap=True,    min_width=20)
            tbl.add_column("Event Type", style="cyan",        no_wrap=True,    min_width=18)
            tbl.add_column("Process",    style="bold white",  no_wrap=True,    min_width=16)
            tbl.add_column("Command / Detail", style="yellow", overflow="fold", ratio=4)
            tbl.add_column("Flags",      style="bold red",    overflow="fold", ratio=1)

            for tc in es.trigger_commands:
                tbl.add_row(
                    fmt_ts(tc["ts"]),
                    tc["event_type"],
                    tc["process_name"] or "\u2014",
                    tc["command"]      or "\u2014",
                    ", ".join(tc["flags"]),
                )
            self.con.print(tbl)

        # --- Key indicators ---
        if es.key_indicators:
            bullets = "\n".join(
                f"  [yellow]\u2022[/yellow]  {ind}" for ind in es.key_indicators
            )
            mitre_str = (
                "  [dim]|[/dim]  ".join(
                    f"[bold cyan]{t}[/bold cyan]" for t in es.mitre_tactic_names
                )
                if es.mitre_tactic_names else "[dim]None identified[/dim]"
            )
            self.con.print(Panel(
                f"{bullets}\n\n  [dim]MITRE Tactics:[/dim]  {mitre_str}",
                title="[bold yellow]\U0001f50d Key Indicators",
                border_style="yellow",
                padding=(1, 2),
            ))

        self.con.print()

    # ------------------------------------------------------------------
    # 0b. Intelligent Narrative
    # ------------------------------------------------------------------

    def _render_narrative(self, result: AnalysisResult) -> None:
        phases = result.narrative_phases
        if not phases:
            return

        SEV_STYLE = {
            "critical": "bold red",
            "high":     "bold yellow",
            "medium":   "yellow",
            "low":      "bold green",
            "info":     "dim cyan",
        }
        SEV_BORDER = {
            "critical": "red",
            "high":     "dark_orange",
            "medium":   "yellow",
            "low":      "green",
            "info":     "cyan",
        }
        SEV_BADGE = {
            "critical": "[bold red]CRITICAL[/bold red]",
            "high":     "[bold yellow]HIGH[/bold yellow]",
            "medium":   "[yellow]MEDIUM[/yellow]",
            "low":      "[green]LOW[/green]",
            "info":     "[cyan]INFO[/cyan]",
        }

        _section(self.con, "INCIDENT NARRATIVE", "purple")

        for i, ph in enumerate(phases, 1):
            sev     = ph.get("severity", "info")
            border  = SEV_BORDER.get(sev, "cyan")
            badge   = SEV_BADGE.get(sev, "[cyan]INFO[/cyan]")
            s_style = SEV_STYLE.get(sev, "dim cyan")

            # Build panel body
            body_parts: List[str] = []

            # Narrative text
            body_parts.append(f"[white]{ph.get('text','')}[/white]")

            # Evidence bullets
            evidence = ph.get("evidence") or []
            if evidence:
                body_parts.append("\n[bold dim]Evidence:[/bold dim]")
                for ev in evidence:
                    body_parts.append(f"  [{s_style}]\u2022[/{s_style}]  [dim]{ev}[/dim]")

            # MITRE tags
            mitre = ph.get("mitre") or []
            if mitre:
                mitre_str = "  [dim]|[/dim]  ".join(
                    f"[bold cyan]{t}[/bold cyan]" for t in mitre
                )
                body_parts.append(f"\n[dim]MITRE:[/dim]  {mitre_str}")

            self.con.print(Panel(
                "\n".join(body_parts),
                title=(
                    f"[dim]{i}/{len(phases)}[/dim]  "
                    f"{ph.get('icon','')}  "
                    f"[bold white]{ph.get('phase','')}[/bold white]  "
                    f"{badge}"
                ),
                subtitle=f"[{s_style}]{ph.get('title','')}[/{s_style}]",
                border_style=border,
                padding=(1, 2),
            ))

        self.con.print()

    # ------------------------------------------------------------------
    # 1. Threat & agent summary
    # ------------------------------------------------------------------

    def _render_threat_summary(self, result: AnalysisResult) -> None:
        bundle = result.bundle
        ti  = bundle.threat_info
        adi = bundle.agent_detection_info
        ari = bundle.agent_realtime_info

        _section(self.con, "THREAT OVERVIEW", "cyan")

        conf = ti.get("confidenceLevel") or ""
        conf_style = C_BAD if conf == "malicious" else C_WARN

        # --- Left: threat details ---
        threat_rows = [
            ("Threat Name",       ti.get("threatName") or ti.get("sha1") or "N/A",      "bold yellow"),
            ("Threat ID",         bundle.threat_id,                                       "white"),
            ("Storyline",         bundle.storyline_id,                                    "white"),
            ("Classification",    ti.get("classification") or "N/A",                      "white"),
            ("Confidence",        conf or "N/A",                                           conf_style),
            ("Incident Status",   ti.get("incidentStatus") or "N/A",                      "white"),
            ("Mitigation Status", ti.get("mitigationStatus") or "N/A",                    "white"),
            ("Analyst Verdict",   ti.get("analystVerdict") or "N/A",                      "white"),
            ("Detection Type",    ti.get("detectionType") or "N/A",                       "white"),
            ("File Path",         ti.get("filePath") or "N/A",                            "white"),
            ("SHA1",              ti.get("sha1") or "N/A",                                 C_DIM),
            ("SHA256",            ti.get("sha256") or "N/A",                               C_DIM),
            ("MD5",               ti.get("md5") or "N/A",                                  C_DIM),
            ("File Size",         f"{ti.get('fileSize', '?')} bytes",                      "white"),
            ("Initiated By",      ti.get("initiatingUsername") or ti.get("initiatedBy") or "N/A", "white"),
            ("Identified At",     fmt_ts(ti.get("identifiedAt") or ti.get("createdAt")),   "white"),
            ("Updated At",        fmt_ts(ti.get("updatedAt")),                              "white"),
        ]

        # --- Right: agent details ---
        agent_rows = [
            ("Hostname",          ari.get("agentComputerName") or adi.get("agentIpV4") or "N/A", "bold green"),
            ("Agent ID",          adi.get("agentUuid") or "N/A",                                  "white"),
            ("OS",                adi.get("agentOsName") or "N/A",                               "white"),
            ("OS Version",        adi.get("agentOsRevision") or "N/A",                           "white"),
            ("Agent Version",     adi.get("agentVersion") or "N/A",                              "white"),
            ("Domain",            adi.get("agentDomain") or "N/A",                               "white"),
            ("IPv4",              adi.get("agentIpV4") or "N/A",                                  "white"),
            ("IPv6",              adi.get("agentIpV6") or "N/A",                                  "white"),
            ("External IP",       adi.get("externalIp") or "N/A",                                 "white"),
            ("Last Logged User",  adi.get("agentLastLoggedInUserName") or "N/A",                  "yellow"),
            ("Site",              adi.get("siteName") or "N/A",                                   "white"),
            ("Group",             adi.get("groupName") or "N/A",                                  "white"),
            ("Account",           adi.get("accountName") or "N/A",                                "white"),
            ("Machine Type",      ari.get("agentMachineType") or "N/A",                           "white"),
            ("Network Status",    ari.get("agentNetworkStatus") or "N/A",                         "white"),
            ("Agent Active",      "Yes" if ari.get("agentIsActive") else "No",                    "bold green" if ari.get("agentIsActive") else "dim"),
            ("Decommissioned",    "Yes" if ari.get("agentIsDecommissioned") else "No",            "bold red" if ari.get("agentIsDecommissioned") else "dim"),
            ("Pre-Exec Mitig.",   "Yes" if ti.get("mitigatedPreemptively") else "No",             "white"),
            ("Reboot Required",   "Yes" if ti.get("rebootRequired") else "No",                    "white"),
        ]

        self.con.print(Columns([
            Panel(
                _kv_table(threat_rows, "bold cyan"),
                title="[bold cyan]Threat Details",
                border_style="cyan",
                padding=(1, 2),
            ),
            Panel(
                _kv_table(agent_rows, "bold blue"),
                title="[bold blue]Agent / Host Info",
                border_style="blue",
                padding=(1, 2),
            ),
        ], equal=False))

        # Detection engines
        engines = ti.get("detectionEngines") or []
        if engines:
            eng_text = ", ".join(
                (e.get("key") or str(e)) if isinstance(e, dict) else str(e)
                for e in engines
            )
            self.con.print(
                Panel(
                    f"[bold yellow]{eng_text}",
                    title="[bold yellow]Detection Engines",
                    border_style="yellow",
                    padding=(0, 2),
                )
            )

    # ------------------------------------------------------------------
    # 2. Detection triggers
    # ------------------------------------------------------------------

    def _render_detection_triggers(self, result: AnalysisResult) -> None:
        triggers = result.detection_triggers
        if not triggers:
            return

        _section(self.con, f"DETECTION TRIGGERS  ({len(triggers)} events)", "red")

        tbl = Table(
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
            expand=True,
        )
        tbl.add_column("Timestamp",   style="yellow",     no_wrap=True,  min_width=20)
        tbl.add_column("Type",        style="cyan",        no_wrap=True,  min_width=18)
        tbl.add_column("Process",     style="bold white",  no_wrap=True,  min_width=18)
        tbl.add_column("Detail",      style="white",       overflow="fold", ratio=3)
        tbl.add_column("Flags",       style="bold red",    overflow="fold", ratio=1)

        for evt in sorted(triggers, key=lambda e: e.get("createdAt") or "")[:200]:
            flags = []
            if evt.get("relatedToThreat"):
                flags.append("relatedToThreat")
            if evt.get("processIsMalicious"):
                flags.append("procMalicious")
            if evt.get("parentProcessIsMalicious"):
                flags.append("parentMalicious")
            tbl.add_row(
                fmt_ts(evt.get("createdAt")),
                f"{event_icon(evt)} {event_label(evt)}",
                evt.get("processName") or "\u2014",
                _event_detail(evt) or evt.get("processCmd") or "\u2014",
                "\n".join(flags),
            )

        self.con.print(tbl)
        if len(triggers) > 200:
            self.con.print(f"[dim]  ... {len(triggers) - 200} more trigger events (see CSV/HTML)[/dim]")

    # ------------------------------------------------------------------
    # 3. Process tree
    # ------------------------------------------------------------------

    def _render_process_tree(self, result: AnalysisResult) -> None:
        if not result.bundle.events:
            return

        _section(self.con, "PROCESS TREE VIEW", "green")

        roots = ProcessTreeBuilder().build(result.bundle.events)
        if not roots:
            self.con.print("[dim]  No process tree data available.[/dim]")
            return

        tree = Tree("[bold cyan]Process Execution Tree", guide_style="dim cyan")

        def _add_node(node: ProcessNode, parent: Tree, depth: int = 0) -> None:
            if depth > 20:
                return

            label = Text()
            if node.is_suspicious:
                label.append("[!] ", style=C_BAD)
                node_style = C_BAD
            else:
                label.append("[ ] ", style=C_GOOD)
                node_style = C_GOOD

            label.append(node.display_name, style=f"bold {node_style}")

            if node.start_time:
                label.append(f"  @ {fmt_ts(node.start_time)}", style=C_DIM)
            if node.user:
                label.append(f"  user:{node.user}", style="blue")
            if node.integrity_level:
                label.append(f"  [{node.integrity_level}]", style=C_DIM)
            if node.is_malicious:
                label.append("  [MALICIOUS]", style=C_BAD)
            if node.related_to_threat:
                label.append("  << DETECTION TRIGGER >>", style="bold red on white")

            subtree = parent.add(label)

            # Command line (full, folded)
            if node.cmd:
                subtree.add(Text(f"  cmd: {node.cmd}", style=C_DIM))

            # Image path if different from name
            if node.image_path and node.image_path.lower() not in node.cmd.lower():
                subtree.add(Text(f"  img: {node.image_path}", style=C_DIM))

            # Show events (up to 8 per node to keep tree readable)
            sorted_evts = sorted(node.events, key=lambda e: e.get("createdAt") or "")
            shown = 0
            for evt in sorted_evts:
                if shown >= 8:
                    remaining = len(sorted_evts) - shown
                    subtree.add(Text(f"  ... +{remaining} more events", style=C_DIM))
                    break
                lbl      = event_label(evt)
                ts_e     = fmt_ts(evt.get("createdAt") or "")
                detail   = _event_detail(evt) or ""
                trigger  = "  << TRIGGER" if evt.get("relatedToThreat") else ""
                evt_style = "bold red" if evt.get("relatedToThreat") else C_DIM
                subtree.add(Text(f"  [{ts_e}] {lbl}: {detail}{trigger}", style=evt_style))
                shown += 1

            for child in node.children:
                _add_node(child, subtree, depth + 1)

        for root in roots:
            _add_node(root, tree)

        self.con.print(tree)

    # ------------------------------------------------------------------
    # Helper: filter events to threat-relevant processes only
    # ------------------------------------------------------------------

    @staticmethod
    def _threat_events(events: list, result: AnalysisResult) -> tuple:
        """Return (filtered_list, filtered_out_count)."""
        keys = result.threat_process_keys
        if not keys:
            return events, 0
        filtered = [
            e for e in events
            if e.get("processUniqueKey") in keys
            or e.get("relatedToThreat")
            or e.get("processIsMalicious")
        ]
        return filtered, len(events) - len(filtered)

    # ------------------------------------------------------------------
    # 4. File events
    # ------------------------------------------------------------------

    def _render_file_events(self, result: AnalysisResult) -> None:
        events = result.categorized.file
        if not events:
            return

        events, noise = self._threat_events(events, result)
        _section(self.con, f"FILE ACTIVITY  ({len(events)} events from threat processes)", "yellow")
        if noise:
            self.con.print(f"  [dim]{noise} events from unrelated processes filtered out[/dim]")
            self.con.print()

        tbl = Table(box=box.SIMPLE_HEAD, border_style="yellow", show_lines=False, expand=True)
        tbl.add_column("Timestamp",   style="dim",         no_wrap=True,  min_width=20)
        tbl.add_column("Operation",   style="cyan",        no_wrap=True,  min_width=20)
        tbl.add_column("Process",     style="green",       no_wrap=True,  min_width=16)
        tbl.add_column("File / Path", style="white",       overflow="fold", ratio=3)
        tbl.add_column("Old Name",    style="dim",         overflow="fold", ratio=2)
        tbl.add_column("Size",        style="dim",         min_width=9)
        tbl.add_column("SHA1",        style="dim",         min_width=12)
        tbl.add_column("T",           style="bold red",    width=2)

        shown_limit = 500
        for evt in sorted(events, key=lambda e: e.get("createdAt") or "")[:shown_limit]:
            sha1 = evt.get("fileSha1") or ""
            size = evt.get("fileSize")
            size_str = f"{int(size):,} B" if size else "\u2014"
            tbl.add_row(
                fmt_ts(evt.get("createdAt")),
                f"{event_icon(evt)} {event_label(evt)}",
                evt.get("processName") or "\u2014",
                evt.get("fileFullName") or "\u2014",
                evt.get("oldFileName") or "\u2014",
                size_str,
                sha1[:16] if sha1 else "\u2014",
                "T" if evt.get("relatedToThreat") else "",
            )

        self.con.print(tbl)
        if len(events) > shown_limit:
            self.con.print(f"[dim]  ... {len(events) - shown_limit} more file events not shown — see CSV/HTML[/dim]")

    # ------------------------------------------------------------------
    # 5. Registry events
    # ------------------------------------------------------------------

    def _render_registry_events(self, result: AnalysisResult) -> None:
        events = result.categorized.registry
        if not events:
            return

        events, noise = self._threat_events(events, result)
        _section(self.con, f"REGISTRY ACTIVITY  ({len(events)} events from threat processes)", "magenta")
        if noise:
            self.con.print(f"  [dim]{noise} events from unrelated processes filtered out[/dim]")
            self.con.print()

        tbl = Table(box=box.SIMPLE_HEAD, border_style="magenta", show_lines=False, expand=True)
        tbl.add_column("Timestamp",          style="dim",        no_wrap=True, min_width=20)
        tbl.add_column("Operation",          style="cyan",       no_wrap=True, min_width=22)
        tbl.add_column("Process",            style="green",      no_wrap=True, min_width=16)
        tbl.add_column("Registry Key / Path",style="yellow",     overflow="fold", ratio=3)
        tbl.add_column("Value Name",         style="dim white",  overflow="fold", ratio=1)
        tbl.add_column("Data",               style="dim",        overflow="fold", ratio=1)
        tbl.add_column("T",                  style="bold red",   width=2)

        _susp = {"CURRENTVERSION\\RUN", "WINLOGON", "SERVICES"}

        shown_limit = 300
        for evt in sorted(events, key=lambda e: e.get("createdAt") or "")[:shown_limit]:
            path = evt.get("registryPath") or "\u2014"
            suspicious = any(s in path.upper() for s in _susp)
            path_style = "bold red" if suspicious else "yellow"
            tbl.add_row(
                fmt_ts(evt.get("createdAt")),
                f"{event_icon(evt)} {event_label(evt)}",
                evt.get("processName") or "\u2014",
                Text(path, style=path_style),
                evt.get("registryValue") or evt.get("registryNewValue") or "\u2014",
                evt.get("registryData") or "\u2014",
                "T" if evt.get("relatedToThreat") else "",
            )

        self.con.print(tbl)
        if len(events) > shown_limit:
            self.con.print(f"[dim]  ... {len(events) - shown_limit} more registry events not shown — see CSV/HTML[/dim]")

    # ------------------------------------------------------------------
    # 6. Network events
    # ------------------------------------------------------------------

    def _render_network_events(self, result: AnalysisResult) -> None:
        events = sorted(
            result.categorized.network + result.categorized.dns,
            key=lambda e: e.get("createdAt") or "",
        )
        if not events:
            return

        events, noise = self._threat_events(events, result)
        _section(self.con, f"NETWORK ACTIVITY  ({len(events)} events from threat processes)", "blue")
        if noise:
            self.con.print(f"  [dim]{noise} events from unrelated processes filtered out[/dim]")
            self.con.print()

        tbl = Table(box=box.SIMPLE_HEAD, border_style="blue", show_lines=False, expand=True)
        tbl.add_column("Timestamp",  style="dim",        no_wrap=True, min_width=20)
        tbl.add_column("Type",       style="cyan",       no_wrap=True, min_width=18)
        tbl.add_column("Direction",  style="dim",        no_wrap=True, min_width=5)
        tbl.add_column("Process",    style="green",      no_wrap=True, min_width=16)
        tbl.add_column("Src IP",     style="dim white",  no_wrap=True, min_width=16)
        tbl.add_column("Dst IP",     style="bold white", no_wrap=True, min_width=16)
        tbl.add_column("Port",       style="yellow",     no_wrap=True, min_width=7)
        tbl.add_column("Proto",      style="dim",        no_wrap=True, min_width=6)
        tbl.add_column("DNS / URL",  style="white",      overflow="fold", ratio=2)
        tbl.add_column("T",          style="bold red",   width=2)

        shown_limit = 300
        for evt in events[:shown_limit]:
            direction = evt.get("netConnDirection") or ""
            dir_style = "bold cyan" if direction == "INCOMING" else "bold yellow" if direction == "OUTGOING" else ""
            tbl.add_row(
                fmt_ts(evt.get("createdAt")),
                f"{event_icon(evt)} {event_label(evt)}",
                Text(direction, style=dir_style) if direction else "\u2014",
                evt.get("processName") or "\u2014",
                evt.get("srcIp") or "\u2014",
                evt.get("dstIp") or "\u2014",
                str(evt.get("dstPort") or ""),
                evt.get("protocol") or "\u2014",
                evt.get("dnsRequest") or evt.get("networkUrl") or "\u2014",
                "T" if evt.get("relatedToThreat") else "",
            )

        self.con.print(tbl)
        if len(events) > shown_limit:
            self.con.print(f"[dim]  ... {len(events) - shown_limit} more network events not shown — see CSV/HTML[/dim]")

    # ------------------------------------------------------------------
    # 7. Login / account activity
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_login(evt: dict, threat_keys: set) -> str:
        evt_type = (evt.get("eventType") or "").upper()
        if "FAIL" in evt_type or "DENIED" in evt_type:
            return "fail"
        username   = (evt.get("loginsUserName") or evt.get("user") or "").lower()
        login_type = (evt.get("loginsBaseType") or "").upper()
        proc_key   = evt.get("processUniqueKey") or ""
        if (
            "admin" in username
            or (login_type == "INTERACTIVE" and proc_key in threat_keys)
            or login_type in ("NETWORK", "BATCH", "SERVICE")
        ):
            return "susp"
        return ""

    def _render_login_events(self, result: AnalysisResult) -> None:
        events = result.categorized.login
        if not events:
            return

        threat_keys = result.threat_process_keys or set()
        _section(self.con, f"LOGIN / ACCOUNT ACTIVITY  ({len(events)} events)", "green")

        fail_count = sum(1 for e in events if self._classify_login(e, threat_keys) == "fail")
        susp_count = sum(1 for e in events if self._classify_login(e, threat_keys) == "susp")
        if fail_count or susp_count:
            parts = []
            if fail_count:
                parts.append(f"[bold red]{fail_count} FAILED[/bold red]")
            if susp_count:
                parts.append(f"[bold yellow]{susp_count} SUSPICIOUS[/bold yellow]")
            self.con.print(f"  \u26a0\ufe0f  Login anomalies detected: {', '.join(parts)}")
            self.con.print()

        tbl = Table(box=box.SIMPLE_HEAD, border_style="green", show_lines=False, expand=True)
        tbl.add_column("Timestamp",  style="dim",        no_wrap=True, min_width=20)
        tbl.add_column("Type",       style="cyan",       no_wrap=True, min_width=18)
        tbl.add_column("Username",   style="bold white", overflow="fold", ratio=2)
        tbl.add_column("Login Type", style="yellow",     no_wrap=True, min_width=14)
        tbl.add_column("Process",    style="green",      no_wrap=True, min_width=16)
        tbl.add_column("Flag",       style="bold",       no_wrap=True, min_width=12)

        for evt in sorted(events, key=lambda e: e.get("createdAt") or ""):
            cls = self._classify_login(evt, threat_keys)
            flag_text  = Text("FAILED",     style="bold red")    if cls == "fail" else \
                         Text("SUSPICIOUS", style="bold yellow") if cls == "susp" else \
                         Text("")
            username = evt.get("loginsUserName") or evt.get("user") or "\u2014"
            u_style  = "bold red" if cls == "fail" else "bold yellow" if cls == "susp" else "bold white"
            tbl.add_row(
                fmt_ts(evt.get("createdAt")),
                f"{event_icon(evt)} {event_label(evt)}",
                Text(username, style=u_style),
                evt.get("loginsBaseType") or "\u2014",
                evt.get("processName") or "\u2014",
                flag_text,
            )

        self.con.print(tbl)

    # ------------------------------------------------------------------
    # 8. Scheduled tasks
    # ------------------------------------------------------------------

    def _render_task_events(self, result: AnalysisResult) -> None:
        events = result.categorized.scheduled_task
        if not events:
            return

        _section(self.con, f"SCHEDULED TASKS  ({len(events)} events)", "red")

        tbl = Table(box=box.SIMPLE_HEAD, border_style="red", show_lines=False, expand=True)
        tbl.add_column("Timestamp", style="dim",        no_wrap=True, min_width=20)
        tbl.add_column("Task Name", style="bold yellow", overflow="fold", ratio=2)
        tbl.add_column("Task Path", style="white",       overflow="fold", ratio=2)
        tbl.add_column("Process",   style="green",       no_wrap=True, min_width=16)
        tbl.add_column("Command",   style="dim",         overflow="fold", ratio=2)

        for evt in sorted(events, key=lambda e: e.get("createdAt") or ""):
            tbl.add_row(
                fmt_ts(evt.get("createdAt")),
                evt.get("taskName") or "\u2014",
                evt.get("taskPath") or "\u2014",
                evt.get("processName") or "\u2014",
                evt.get("processCmd") or "\u2014",
            )

        self.con.print(tbl)

    # ------------------------------------------------------------------
    # 9. Encryption / ransomware indicators
    # ------------------------------------------------------------------

    def _render_encryption_indicators(self, result: AnalysisResult) -> None:
        indicators = result.encryption_indicators
        if not indicators:
            return

        _section(self.con, "RANSOMWARE / ENCRYPTION INDICATORS", "red")

        lines = []
        for i in indicators:
            proc_name = i.get("proc_name")
            if proc_name:
                # Use structured fields for rich formatting in terminal
                count = i.get("count", "?")
                lines.append(
                    f"  [yellow]*[/yellow]  High-volume file modifications "
                    f"([bold yellow]{count}[/bold yellow]) by "
                    f"[bold red]{proc_name}[/bold red]"
                )
            else:
                lines.append(f"  [yellow]*[/yellow]  {i['reason']}")

        self.con.print(
            Panel(
                f"[bold red]{len(indicators)} potential encryption/ransomware indicator(s) detected![/bold red]\n\n"
                + "\n".join(lines),
                border_style="red",
                padding=(1, 2),
            )
        )

    # ------------------------------------------------------------------
    # 10. MITRE ATT&CK
    # ------------------------------------------------------------------

    def _render_mitre(self, result: AnalysisResult) -> None:
        techniques = result.mitre_techniques
        if not techniques:
            return

        _section(self.con, f"MITRE ATT&CK TECHNIQUES  ({len(techniques)} unique)", "red")

        # Group by tactic and render one table per tactic
        tactic_groups: dict = {}
        for t in techniques:
            tactic = t.get("tactic") or "Other"
            tactic_groups.setdefault(tactic, []).append(t)

        for tactic_name in sorted(tactic_groups.keys()):
            group = tactic_groups[tactic_name]

            self.con.print(
                f"  [bold cyan]{tactic_name}[/bold cyan]"
                f"  [dim]({len(group)} technique{'s' if len(group) != 1 else ''})[/dim]"
            )

            tbl = Table(
                box=box.SIMPLE_HEAD,
                border_style="dim cyan",
                show_lines=False,
                expand=True,
                show_header=True,
                padding=(0, 1),
            )
            tbl.add_column("Technique",        style="bold yellow", overflow="fold", ratio=2)
            tbl.add_column("Description",      style="white",       overflow="fold", ratio=3)
            tbl.add_column("Triggered Events", style="dim",         overflow="fold", ratio=2)
            tbl.add_column("Ref",              style="dim blue",    overflow="fold", ratio=1)

            for t in group:
                t_events = t.get("events") or []
                if t_events:
                    ev_lines = []
                    for e in sorted(t_events, key=lambda x: x.get("createdAt") or "")[:3]:
                        ev_lines.append(
                            f"[{fmt_ts(e.get('createdAt'))}] "
                            f"{event_label(e)}: "
                            f"{e.get('processName') or ''}"
                        )
                    if len(t_events) > 3:
                        ev_lines.append(f"+{len(t_events)-3} more")
                    ev_cell = "\n".join(ev_lines)
                else:
                    ev_cell = "\u2014"

                tbl.add_row(
                    t.get("technique") or "\u2014",
                    t.get("description") or "\u2014",
                    ev_cell,
                    t.get("link") or "\u2014",
                )

            self.con.print(tbl)
            self.con.print()

    # ------------------------------------------------------------------
    # 11. IOC summary
    # ------------------------------------------------------------------

    def _render_iocs(self, result: AnalysisResult) -> None:
        net_iocs  = result.network_iocs
        file_iocs = result.file_iocs

        if not net_iocs and not file_iocs:
            return

        _section(self.con, "INDICATORS OF COMPROMISE (IOC)", "yellow")

        # --- Network IOCs ---
        if net_iocs:
            net_tbl = Table(box=box.SIMPLE_HEAD, border_style="blue", expand=False)
            net_tbl.add_column("Type",    style="cyan",       no_wrap=True, min_width=10)
            net_tbl.add_column("Value",   style="bold white", overflow="fold", min_width=18)
            net_tbl.add_column("Process", style="dim green",  overflow="fold", min_width=14)
            for ioc in net_iocs:
                proc = ioc.get("event", {}).get("processName") or ""
                net_tbl.add_row(ioc["type"], ioc["value"], proc)
            self.con.print(Panel(
                net_tbl,
                title=f"[bold blue]Network IOCs ({len(net_iocs)})",
                border_style="blue",
            ))

        # --- File Hash IOCs (capped at 30 in terminal — full list in HTML/CSV) ---
        if file_iocs:
            _TERM_LIMIT = 30
            valid_iocs = [i for i in file_iocs if i["value"].strip("0")]
            file_tbl = Table(box=box.SIMPLE_HEAD, border_style="yellow", expand=False)
            file_tbl.add_column("Type",      style="cyan",  no_wrap=True,  min_width=10)
            file_tbl.add_column("Hash",      style="yellow", overflow="fold", min_width=42)
            file_tbl.add_column("File Name", style="dim",   overflow="fold", min_width=20)
            for ioc in valid_iocs[:_TERM_LIMIT]:
                fname = ioc.get("event", {}).get("fileFullName") or "\u2014"
                file_tbl.add_row(ioc["type"], ioc["value"], fname)
            note = ""
            if len(valid_iocs) > _TERM_LIMIT:
                note = (f"\n  [dim]... {len(valid_iocs) - _TERM_LIMIT} more hash IOCs — "
                        f"full list available in the HTML report and CSV export.[/dim]")
            self.con.print(Panel(
                file_tbl,
                title=f"[bold yellow]File Hash IOCs ({len(valid_iocs)} valid hashes)",
                border_style="yellow",
            ))
            if note:
                self.con.print(note)

    # ------------------------------------------------------------------
    # 11b. SOC Analyst Recommendations
    # ------------------------------------------------------------------

    def _render_soc_recommendations(self, result: AnalysisResult) -> None:
        recs = result.soc_recommendations
        if not recs:
            return

        _pri_style = {
            "CRITICAL": ("bold red",     "\U0001f534"),
            "HIGH":     ("bold yellow",  "\U0001f7e0"),
            "MEDIUM":   ("bold blue",    "\U0001f535"),
            "LOW":      ("bold green",   "\U0001f7e2"),
        }

        _section(self.con, f"SOC ANALYST RECOMMENDATIONS  ({len(recs)} items)", "red")

        for rec in recs:
            style, dot = _pri_style.get(rec.priority.upper(), ("white", "\u25cf"))
            self.con.print(
                f"  {dot}  [{style}][{rec.priority}][/{style}]"
                f"  [bold white]{rec.title}[/bold white]"
                f"  [dim]\u2014 {rec.category}[/dim]"
            )
            self.con.print(f"       [dim]{rec.details}[/dim]")
            for action in rec.actions:
                self.con.print(f"       [dim cyan]\u2192[/dim cyan]  {action}")
            self.con.print()

    # ------------------------------------------------------------------
    # 12. Collection summary (statistics)
    # ------------------------------------------------------------------

    def _render_stats(self, result: AnalysisResult) -> None:
        _section(self.con, "COLLECTION SUMMARY", "cyan")

        cat = result.categorized

        stats = [
            ("Total Events",        result.total_events,                          "bold cyan"),
            ("Unique Processes",     result.unique_processes,                      "green"),
            ("Detection Triggers",   len(result.detection_triggers),               "bold red"),
            ("File Events",          len(cat.file),                                "yellow"),
            ("Registry Events",      len(cat.registry),                            "magenta"),
            ("Network Events",       len(cat.network) + len(cat.dns),              "blue"),
            ("Login Events",         len(cat.login),                               "green"),
            ("Scheduled Tasks",      len(cat.scheduled_task),                      "red"),
            ("Module Load Events",   len(cat.module),                              "dim white"),
            ("Cross-Process Events", len(cat.cross_process),                       "dim white"),
            ("MITRE Techniques",     len({(t["tactic"], t["technique"]) for t in result.mitre_techniques}), "yellow"),
            ("Network IOCs",         len(result.network_iocs),                     "cyan"),
            ("File Hash IOCs",       len(result.file_iocs),                        "yellow"),
            ("Encryption Indicators",len(result.encryption_indicators),            "bold red"),
            ("Timeline Entries",     len(result.bundle.timeline),                  "dim white"),
        ]

        # Split into two columns for a compact display
        half = (len(stats) + 1) // 2
        left_stats  = stats[:half]
        right_stats = stats[half:]

        def _make_stat_table(rows) -> Table:
            tbl = Table(box=box.SIMPLE_HEAD, border_style="cyan", show_header=True, padding=(0, 2))
            tbl.add_column("Metric",  style="bold dim white", min_width=22)
            tbl.add_column("Count",   style="bold",           justify="right", min_width=8)
            for label, value, colour in rows:
                tbl.add_row(label, Text(str(value), style=colour))
            return tbl

        self.con.print(
            Columns([
                _make_stat_table(left_stats),
                _make_stat_table(right_stats),
            ])
        )
        self.con.print()

    # ------------------------------------------------------------------
    # Footer
    # ------------------------------------------------------------------

    def _render_footer(self) -> None:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.con.print(Rule(style="purple"))
        self.con.print(
            f"  [dim]SentinelOne Threats Analyzer[/dim]  [bold purple]v1.4.0[/bold purple]"
            f"  [dim]\u2014  Developed by[/dim]  [bold]Florian Bertaux[/bold]"
            f"  [dim]\u2014  Report generated:[/dim]  [dim cyan]{ts}[/dim cyan]",
            justify="center",
        )
        self.con.print(Rule(style="purple"))
        self.con.print()
