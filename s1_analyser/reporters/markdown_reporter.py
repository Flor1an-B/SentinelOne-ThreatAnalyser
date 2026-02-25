"""
Markdown Reporter - Generates a detailed analyst report in Markdown format.

Structure:
  1. Executive Summary
  2. Threat Details
  3. Host Information
  4. Detection Analysis (what triggered it, why)
  5. MITRE ATT&CK Mapping
  6. Process Tree
  7. File Activity
  8. Registry Activity
  9. Network Activity
  10. Login / Account Activity
  11. Scheduled Tasks
  12. Encryption / Ransomware Indicators
  13. Indicators of Compromise
  14. Timeline (top 100)
  15. Appendix: Statistics
"""
from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any, List, Dict

from ..analyzer import AnalysisResult, fmt_ts, event_icon, event_label, SocRecommendation
from ..process_tree import ProcessNode, ProcessTreeBuilder, render_ascii_tree, _event_detail


class MarkdownReporter:

    def write(self, result: AnalysisResult, output_dir: str) -> str:
        """Write the Markdown report and return the file path."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        storyline = result.bundle.storyline_id.replace("/", "_").replace("\\", "_")
        filename = f"S1_ThreatReport_{storyline}_{timestamp}.md"
        filepath = os.path.join(output_dir, filename)

        lines: List[str] = []
        self._add_header(result, lines)
        self._add_executive_summary(result, lines)
        self._add_narrative(result, lines)
        self._add_threat_details(result, lines)
        self._add_host_info(result, lines)
        self._add_detection_analysis(result, lines)
        self._add_mitre(result, lines)
        self._add_process_tree(result, lines)
        self._add_file_events(result, lines)
        self._add_registry_events(result, lines)
        self._add_network_events(result, lines)
        self._add_login_events(result, lines)
        self._add_task_events(result, lines)
        self._add_encryption_indicators(result, lines)
        self._add_iocs(result, lines)
        self._add_soc_recommendations(result, lines)
        self._add_timeline(result, lines)
        self._add_stats(result, lines)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        return filepath

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _h(level: int, text: str) -> str:
        return f"{'#' * level} {text}"

    @staticmethod
    def _row(*cols) -> str:
        return "| " + " | ".join(str(c) if c is not None else "—" for c in cols) + " |"

    @staticmethod
    def _sep(n: int) -> str:
        return "|" + "|".join(["---"] * n) + "|"

    def _table(self, lines: List[str], headers: List[str], rows: List[List[Any]]) -> None:
        lines.append(self._row(*headers))
        lines.append(self._sep(len(headers)))
        for row in rows:
            lines.append(self._row(*row))
        lines.append("")

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _add_header(self, result: AnalysisResult, lines: List[str]) -> None:
        ti = result.bundle.threat_info
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines += [
            f"# SentinelOne Threat Analysis Report",
            f"",
            f"> **Generated:** {ts}  ",
            f"> **Storyline ID:** `{result.bundle.storyline_id}`  ",
            f"> **Threat Name:** {ti.get('threatName') or 'N/A'}  ",
            f"> **Tool:** SentinelOne Threats Analyzer v1.4.0",
            f"",
            "---",
            "",
        ]

    def _add_executive_summary(self, result: AnalysisResult, lines: List[str]) -> None:
        ti  = result.bundle.threat_info
        adi = result.bundle.agent_detection_info
        ari = result.bundle.agent_realtime_info
        es  = result.executive_summary

        confidence = ti.get("confidenceLevel") or "unknown"
        confidence_emoji = "🔴" if confidence == "malicious" else "🟡" if confidence == "suspicious" else "⚪"

        lines += [self._h(2, "Executive Summary"), ""]

        # Narrative from analyzer
        if es and es.narrative:
            lines += [f"> {es.narrative}", ""]

        # Status table
        lines += [
            f"| Field | Value |",
            f"|---|---|",
            f"| Confidence Level | {confidence_emoji} **{confidence.upper()}** |",
            f"| Classification | {ti.get('classification') or 'N/A'} |",
            f"| Detection Type | {ti.get('detectionType') or 'N/A'} |",
            f"| Incident Status | {ti.get('incidentStatus') or 'N/A'} |",
            f"| Mitigation Status | {ti.get('mitigationStatus') or 'N/A'} |",
            f"| Pre-execution Block | {'✅ Yes' if ti.get('mitigatedPreemptively') else '❌ No'} |",
            f"| Total Events Collected | {len(result.bundle.events)} |",
            f"| Detection Triggers | {len(result.detection_triggers)} |",
            f"| Unique Processes | {result.unique_processes} |",
            f"",
        ]

        # ── When? ──────────────────────────────────────────────────────────
        if es:
            def _dur(secs):
                if secs is None: return "—"
                if secs < 60:    return f"{secs:.0f}s"
                if secs < 3600:  return f"{secs/60:.1f} min"
                return f"{secs/3600:.1f} h"

            lines += [
                self._h(3, "⏱ When?"),
                "",
                "| Field | Value |",
                "|---|---|",
                f"| First Event | {fmt_ts(es.first_event_ts) or 'N/A'} |",
                f"| Last Event | {fmt_ts(es.last_event_ts) or 'N/A'} |",
                f"| Detection Time | {fmt_ts(es.detection_ts) or 'N/A'} |",
                f"| Duration | {_dur(es.duration_seconds)} |",
                "",
            ]

            # ── Origin? ────────────────────────────────────────────────────
            lines += [
                self._h(3, "🎯 Origin?"),
                "",
                "| Field | Value |",
                "|---|---|",
                f"| Host | {es.hostname or 'N/A'} |",
                f"| User | {es.username or 'N/A'} |",
                f"| Threat File | `{es.threat_file_path or 'N/A'}` |",
            ]
            if es.process_chain:
                chain_str = " → ".join(es.process_chain)
                lines.append(f"| Process Chain | `{chain_str}` |")
            lines.append("")

            # ── Key Indicators ─────────────────────────────────────────────
            if es.key_indicators:
                lines += [self._h(3, "🔍 Key Indicators"), ""]
                for ind in es.key_indicators:
                    lines.append(f"- {ind}")
                lines.append("")

            if es.mitre_tactic_names:
                lines.append(f"**MITRE ATT&CK Tactics:** {', '.join(es.mitre_tactic_names)}\n")

        if result.encryption_indicators:
            lines.append(
                f"> ⚠️ **RANSOMWARE INDICATORS DETECTED** — "
                f"{len(result.encryption_indicators)} potential encryption activities found.\n"
            )

        lines.append("---\n")

    def _add_narrative(self, result: AnalysisResult, lines: List[str]) -> None:
        """Render the intelligent narrative as a multi-phase incident story."""
        phases = result.narrative_phases
        if not phases:
            return

        SEV_EMOJI = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🟢",
            "info":     "🔵",
        }

        lines += [self._h(2, "Incident Narrative"), ""]
        lines.append(
            "_An automatic phase-by-phase reconstruction of the attack based on collected evidence._"
        )
        lines.append("")

        for i, ph in enumerate(phases, 1):
            sev_emoji = SEV_EMOJI.get(ph.get("severity","info"), "⚪")
            lines += [
                self._h(3, f"{sev_emoji} Phase {i}: {ph['phase']}"),
                "",
                f"**{ph.get('title','')}**",
                "",
                ph.get("text",""),
                "",
            ]
            evidence = ph.get("evidence") or []
            if evidence:
                lines.append("**Evidence:**")
                lines.append("")
                for ev in evidence:
                    lines.append(f"- `{ev}`")
                lines.append("")
            mitre = ph.get("mitre") or []
            if mitre:
                lines.append(f"**MITRE ATT&CK:** {', '.join(mitre)}")
                lines.append("")
            lines.append("---")
            lines.append("")

    def _add_threat_details(self, result: AnalysisResult, lines: List[str]) -> None:
        ti = result.bundle.threat_info
        lines += [
            self._h(2, "Threat Details"),
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Threat ID | `{result.bundle.threat_id}` |",
            f"| Storyline | `{result.bundle.storyline_id}` |",
            f"| Threat Name | {ti.get('threatName') or 'N/A'} |",
            f"| Classification | {ti.get('classification') or 'N/A'} |",
            f"| Classification Source | {ti.get('classificationSource') or 'N/A'} |",
            f"| Confidence Level | {ti.get('confidenceLevel') or 'N/A'} |",
            f"| Detection Type | {ti.get('detectionType') or 'N/A'} |",
            f"| File Path | `{ti.get('filePath') or 'N/A'}` |",
            f"| File Extension | {ti.get('fileExtension') or 'N/A'} |",
            f"| File Size | {ti.get('fileSize') or 'N/A'} bytes |",
            f"| SHA1 | `{ti.get('sha1') or 'N/A'}` |",
            f"| SHA256 | `{ti.get('sha256') or 'N/A'}` |",
            f"| MD5 | `{ti.get('md5') or 'N/A'}` |",
            f"| Certificate ID | {ti.get('certificateId') or 'N/A'} |",
            f"| Publisher Name | {ti.get('publisherName') or 'N/A'} |",
            f"| Valid Certificate | {'Yes' if ti.get('isValidCertificate') else 'No'} |",
            f"| Is Fileless | {'Yes' if ti.get('isFileless') else 'No'} |",
            f"| Initiated By | {ti.get('initiatedBy') or 'N/A'} |",
            f"| Initiating Username | {ti.get('initiatingUsername') or 'N/A'} |",
            f"| Originated Process | {ti.get('originatorProcess') or 'N/A'} |",
            f"| Malicious Cmd Args | `{ti.get('maliciousProcessArguments') or 'N/A'}` |",
            f"| Process User | {ti.get('processUser') or 'N/A'} |",
            f"| Identified At | {fmt_ts(ti.get('identifiedAt'))} |",
            f"| Created At | {fmt_ts(ti.get('createdAt'))} |",
            f"| Updated At | {fmt_ts(ti.get('updatedAt'))} |",
            f"| Reboot Required | {'Yes' if ti.get('rebootRequired') else 'No'} |",
            f"| Analyst Verdict | {ti.get('analystVerdict') or 'N/A'} |",
            f"| Incident Status | {ti.get('incidentStatus') or 'N/A'} |",
            f"| Mitigation Status | {ti.get('mitigationStatus') or 'N/A'} |",
            f"| Events Limit Reached | {'Yes ⚠️' if ti.get('reachedEventsLimit') else 'No'} |",
            "",
        ]

        engines = ti.get("detectionEngines") or []
        if engines:
            engine_str = ", ".join(
                (e.get("key") or str(e)) if isinstance(e, dict) else str(e)
                for e in engines
            )
            lines.append(f"**Detection Engines:** {engine_str}\n")

        lines.append("---\n")

    def _add_host_info(self, result: AnalysisResult, lines: List[str]) -> None:
        adi = result.bundle.agent_detection_info
        ari = result.bundle.agent_realtime_info
        lines += [
            self._h(2, "Host Information"),
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Computer Name | {ari.get('agentComputerName') or 'N/A'} |",
            f"| Agent UUID | `{adi.get('agentUuid') or 'N/A'}` |",
            f"| OS Name | {adi.get('agentOsName') or 'N/A'} |",
            f"| OS Revision | {adi.get('agentOsRevision') or 'N/A'} |",
            f"| Agent Version | {adi.get('agentVersion') or 'N/A'} |",
            f"| Domain | {adi.get('agentDomain') or 'N/A'} |",
            f"| IPv4 | {adi.get('agentIpV4') or 'N/A'} |",
            f"| IPv6 | {adi.get('agentIpV6') or 'N/A'} |",
            f"| External IP | {adi.get('externalIp') or 'N/A'} |",
            f"| Last Logged User | {adi.get('agentLastLoggedInUserName') or 'N/A'} |",
            f"| Last Logged UPN | {adi.get('agentLastLoggedInUpn') or 'N/A'} |",
            f"| Site | {adi.get('siteName') or 'N/A'} |",
            f"| Group | {adi.get('groupName') or 'N/A'} |",
            f"| Account | {adi.get('accountName') or 'N/A'} |",
            f"| Mitigation Mode | {adi.get('agentMitigationMode') or 'N/A'} |",
            f"| Machine Type | {ari.get('agentMachineType') or 'N/A'} |",
            f"| Network Status | {ari.get('agentNetworkStatus') or 'N/A'} |",
            f"| Agent Active | {'Yes' if ari.get('agentIsActive') else 'No'} |",
            f"| Decommissioned | {'Yes' if ari.get('agentIsDecommissioned') else 'No'} |",
            "",
            "---",
            "",
        ]

    def _add_detection_analysis(self, result: AnalysisResult, lines: List[str]) -> None:
        triggers = result.detection_triggers
        lines += [
            self._h(2, "Detection Analysis — Why Was This Detected?"),
            "",
        ]

        if not triggers:
            lines.append("_No explicit detection-trigger events found in the collected data._\n")
        else:
            lines += [
                f"SentinelOne flagged **{len(triggers)} event(s)** as directly related to the threat detection.",
                "These are the actions that caused the alert to fire:",
                "",
                "| Timestamp | Event Type | Process | Detail | Flags |",
                "|---|---|---|---|---|",
            ]
            for evt in sorted(triggers, key=lambda e: e.get("createdAt") or "")[:50]:
                flags = []
                if evt.get("relatedToThreat"):
                    flags.append("`relatedToThreat`")
                if evt.get("processIsMalicious"):
                    flags.append("`processMalicious`")
                if evt.get("parentProcessIsMalicious"):
                    flags.append("`parentMalicious`")
                lines.append(
                    f"| {fmt_ts(evt.get('createdAt'))} "
                    f"| {event_label(evt)} "
                    f"| `{evt.get('processName') or '—'}` "
                    f"| {_event_detail(evt) or '—'} "
                    f"| {' '.join(flags)} |"
                )

        lines.append("\n---\n")

    def _add_mitre(self, result: AnalysisResult, lines: List[str]) -> None:
        techniques = result.mitre_techniques
        if not techniques:
            return

        lines += [
            self._h(2, "MITRE ATT&CK Mapping"),
            "",
            "| Tactic | Technique | Category | Description | Link |",
            "|---|---|---|---|---|",
        ]

        seen = set()
        for t in techniques:
            key = (t.get("tactic"), t.get("technique"))
            if key in seen:
                continue
            seen.add(key)
            desc = (t.get("description") or "")[:100]
            link = f"[{t.get('link') or ''}]({t.get('link') or '#'})" if t.get("link") else "—"
            lines.append(
                f"| {t.get('tactic') or '—'} "
                f"| **{t.get('technique') or '—'}** "
                f"| {t.get('category') or '—'} "
                f"| {desc} "
                f"| {link} |"
            )

        lines.append("\n---\n")

    def _add_process_tree(self, result: AnalysisResult, lines: List[str]) -> None:
        lines += [
            self._h(2, "Process Tree View"),
            "",
            "> 🔴 Red = Detection trigger / malicious  |  ⚙ Normal process",
            "",
            "```",
        ]

        roots = ProcessTreeBuilder().build(result.bundle.events)
        tree_lines = render_ascii_tree(roots)
        lines.extend(tree_lines if tree_lines else ["(No process data available)"])
        lines += ["```", "", "---", ""]

    def _add_file_events(self, result: AnalysisResult, lines: List[str]) -> None:
        events = result.categorized.file
        if not events:
            return

        lines += [
            self._h(2, f"File Activity ({len(events)} events)"),
            "",
            "| Timestamp | Operation | Process | File Path | Old Name | SHA1 | Trigger |",
            "|---|---|---|---|---|---|---|",
        ]

        for evt in sorted(events, key=lambda e: e.get("createdAt") or "")[:200]:
            trigger = "🔴 Yes" if evt.get("relatedToThreat") else ""
            lines.append(
                f"| {fmt_ts(evt.get('createdAt'))} "
                f"| {event_label(evt)} "
                f"| `{evt.get('processName') or '—'}` "
                f"| `{evt.get('fileFullName') or '—'}` "
                f"| `{evt.get('oldFileName') or '—'}` "
                f"| `{(evt.get('fileSha1') or '')[:16]}` "
                f"| {trigger} |"
            )

        if len(events) > 200:
            lines.append(f"\n_... {len(events) - 200} more events in CSV_")

        lines.append("\n---\n")

    def _add_registry_events(self, result: AnalysisResult, lines: List[str]) -> None:
        events = result.categorized.registry
        if not events:
            return

        lines += [
            self._h(2, f"Registry Activity ({len(events)} events)"),
            "",
            "| Timestamp | Operation | Process | Registry Key | Trigger |",
            "|---|---|---|---|---|",
        ]

        for evt in sorted(events, key=lambda e: e.get("createdAt") or "")[:150]:
            trigger = "🔴 Yes" if evt.get("relatedToThreat") else ""
            lines.append(
                f"| {fmt_ts(evt.get('createdAt'))} "
                f"| {event_label(evt)} "
                f"| `{evt.get('processName') or '—'}` "
                f"| `{evt.get('registryPath') or '—'}` "
                f"| {trigger} |"
            )

        lines.append("\n---\n")

    def _add_network_events(self, result: AnalysisResult, lines: List[str]) -> None:
        events = result.categorized.network + result.categorized.dns
        if not events:
            return

        lines += [
            self._h(2, f"Network Activity ({len(events)} events)"),
            "",
            "| Timestamp | Type | Process | Destination IP | Port | Protocol | DNS / URL | Trigger |",
            "|---|---|---|---|---|---|---|---|",
        ]

        for evt in sorted(events, key=lambda e: e.get("createdAt") or "")[:150]:
            trigger = "🔴 Yes" if evt.get("relatedToThreat") else ""
            lines.append(
                f"| {fmt_ts(evt.get('createdAt'))} "
                f"| {event_label(evt)} "
                f"| `{evt.get('processName') or '—'}` "
                f"| {evt.get('dstIp') or evt.get('srcIp') or '—'} "
                f"| {evt.get('dstPort') or '—'} "
                f"| {evt.get('protocol') or '—'} "
                f"| {evt.get('dnsRequest') or evt.get('networkUrl') or '—'} "
                f"| {trigger} |"
            )

        lines.append("\n---\n")

    def _add_login_events(self, result: AnalysisResult, lines: List[str]) -> None:
        events = result.categorized.login
        if not events:
            return

        lines += [
            self._h(2, f"Login & Account Activity ({len(events)} events)"),
            "",
            "| Timestamp | Type | Username | Login Type | Process | Command |",
            "|---|---|---|---|---|---|",
        ]

        for evt in sorted(events, key=lambda e: e.get("createdAt") or ""):
            lines.append(
                f"| {fmt_ts(evt.get('createdAt'))} "
                f"| {event_label(evt)} "
                f"| {evt.get('loginsUserName') or evt.get('user') or '—'} "
                f"| {evt.get('loginsBaseType') or '—'} "
                f"| `{evt.get('processName') or '—'}` "
                f"| `{(evt.get('processCmd') or '')[:60]}` |"
            )

        lines.append("\n---\n")

    def _add_task_events(self, result: AnalysisResult, lines: List[str]) -> None:
        events = result.categorized.scheduled_task
        if not events:
            return

        lines += [
            self._h(2, f"Scheduled Tasks ({len(events)} events)"),
            "",
            "| Timestamp | Task Name | Task Path | Process |",
            "|---|---|---|---|",
        ]

        for evt in sorted(events, key=lambda e: e.get("createdAt") or ""):
            lines.append(
                f"| {fmt_ts(evt.get('createdAt'))} "
                f"| `{evt.get('taskName') or '—'}` "
                f"| `{evt.get('taskPath') or '—'}` "
                f"| `{evt.get('processName') or '—'}` |"
            )

        lines.append("\n---\n")

    def _add_encryption_indicators(self, result: AnalysisResult, lines: List[str]) -> None:
        indicators = result.encryption_indicators
        if not indicators:
            return

        lines += [
            self._h(2, "⚠️ Ransomware / Encryption Indicators"),
            "",
            "> **WARNING:** The following patterns suggest potential ransomware or encryption activity.",
            "",
        ]
        for ind in indicators:
            lines.append(f"- **{ind['reason']}**")
            evt = ind.get("event") or {}
            if evt.get("fileFullName"):
                lines.append(f"  - File: `{evt['fileFullName']}`")
            if evt.get("processName"):
                lines.append(f"  - Process: `{evt['processName']}`")
            if evt.get("createdAt"):
                lines.append(f"  - Time: {fmt_ts(evt['createdAt'])}")

        lines.append("\n---\n")

    def _add_iocs(self, result: AnalysisResult, lines: List[str]) -> None:
        net_iocs = result.network_iocs[:50]
        file_iocs = result.file_iocs[:30]

        if not net_iocs and not file_iocs:
            return

        lines += [self._h(2, "Indicators of Compromise (IOC)"), ""]

        if net_iocs:
            lines += [
                self._h(3, "Network IOCs"),
                "",
                "| Type | Value |",
                "|---|---|",
            ]
            for ioc in net_iocs:
                lines.append(f"| {ioc['type']} | `{ioc['value']}` |")
            lines.append("")

        if file_iocs:
            lines += [
                self._h(3, "File Hash IOCs"),
                "",
                "| Type | Hash |",
                "|---|---|",
            ]
            for ioc in file_iocs:
                lines.append(f"| {ioc['type']} | `{ioc['value']}` |")
            lines.append("")

        if result.suspicious_registry:
            lines += [
                self._h(3, "Suspicious Registry Keys"),
                "",
                "| Timestamp | Path | Process |",
                "|---|---|---|",
            ]
            for evt in result.suspicious_registry[:30]:
                lines.append(
                    f"| {fmt_ts(evt.get('createdAt'))} "
                    f"| `{evt.get('registryPath') or '—'}` "
                    f"| `{evt.get('processName') or '—'}` |"
                )
            lines.append("")

        lines.append("---\n")

    def _add_soc_recommendations(self, result: AnalysisResult, lines: List[str]) -> None:
        recs = result.soc_recommendations
        if not recs:
            return

        _pri_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟢"}

        lines += [
            self._h(2, "SOC Analyst Recommendations"),
            "",
            f"*{len(recs)} action item(s) based on threat analysis findings.*",
            "",
        ]

        for rec in recs:
            emoji = _pri_emoji.get(rec.priority.upper(), "⚪")
            lines += [
                self._h(3, f"{emoji} [{rec.priority}] {rec.title}"),
                "",
                f"**Category:** {rec.category}",
                "",
                rec.details,
                "",
            ]
            for action in rec.actions:
                lines.append(f"- {action}")
            lines.append("")

        lines.append("---\n")

    def _add_timeline(self, result: AnalysisResult, lines: List[str]) -> None:
        timeline = result.timeline_sorted[:100]
        if not timeline:
            return

        lines += [
            self._h(2, "Attack Timeline (first 100 events)"),
            "",
            "| # | Timestamp | Type | Process | Detail | Trigger |",
            "|---|---|---|---|---|---|",
        ]

        for idx, evt in enumerate(timeline, 1):
            trigger = "🔴" if evt.get("relatedToThreat") else ""
            lines.append(
                f"| {idx} "
                f"| {fmt_ts(evt.get('createdAt'))} "
                f"| {event_icon(evt)} {event_label(evt)} "
                f"| `{evt.get('processName') or '—'}` "
                f"| {_event_detail(evt) or '—'} "
                f"| {trigger} |"
            )

        if len(result.timeline_sorted) > 100:
            lines.append(
                f"\n_... {len(result.timeline_sorted) - 100} more events. See CSV for the complete timeline._"
            )

        lines.append("\n---\n")

    def _add_stats(self, result: AnalysisResult, lines: List[str]) -> None:
        cat = result.categorized
        lines += [
            self._h(2, "Appendix: Collection Statistics"),
            "",
            "| Category | Count |",
            "|---|---|",
            f"| Total Events | **{result.total_events}** |",
            f"| Unique Processes | {result.unique_processes} |",
            f"| Process Events | {len(cat.process)} |",
            f"| File Events | {len(cat.file)} |",
            f"| Registry Events | {len(cat.registry)} |",
            f"| Network Events | {len(cat.network)} |",
            f"| DNS Events | {len(cat.dns)} |",
            f"| Login Events | {len(cat.login)} |",
            f"| Scheduled Task Events | {len(cat.scheduled_task)} |",
            f"| Module Load Events | {len(cat.module)} |",
            f"| Cross-Process Events | {len(cat.cross_process)} |",
            f"| Other Events | {len(cat.other)} |",
            f"| Detection Triggers | **{len(result.detection_triggers)}** |",
            f"| MITRE Techniques | {len({(t['tactic'], t['technique']) for t in result.mitre_techniques})} |",
            f"| Network IOCs | {len(result.network_iocs)} |",
            f"| File Hash IOCs | {len(result.file_iocs)} |",
            f"| Encryption Indicators | {len(result.encryption_indicators)} |",
            "",
            "_Report generated by SentinelOne Threats Analyzer v1.4.0 — Developed by Florian Bertaux_",
        ]
