#!/usr/bin/env python3
"""
SentinelOne Threats Analyzer — SentinelOne Forensic Threat Intelligence Tool
=====================================================

Usage:
    # API token via environment variable (recommended)
    export S1_API_KEY="your_token_here"
    python main.py --url https://your-console.sentinelone.net --storyline "0000C2E97648XXXX"

    # API token via interactive secure prompt (never stored)
    python main.py --url https://your-console.sentinelone.net --storyline "0000C2E97648XXXX"

Author: Florian Bertaux — Made by Claude AI
Version: 1.4.0
"""
from __future__ import annotations

import argparse
import getpass
import io
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 on Windows console to support Unicode symbols / emojis
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except AttributeError:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns

# Bootstrap: ensure the package is importable even when run from another cwd
sys.path.insert(0, str(Path(__file__).parent))

from s1_analyser.api_client import S1APIClient, S1APIError
from s1_analyser.data_collector import DataCollector
from s1_analyser.analyzer import ThreatAnalyzer
from s1_analyser.reporters.terminal_reporter import TerminalReporter
from s1_analyser.reporters.csv_reporter import CSVReporter
from s1_analyser.reporters.markdown_reporter import MarkdownReporter
from s1_analyser.reporters.html_reporter import HTMLReporter

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("s1_analyser")

# Wide console — no artificial wrapping
console = Console(highlight=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinelone_threats_analyzer",
        description="SentinelOne Threats Analyzer — deep-dive forensic analysis from a Storyline ID",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    required = p.add_argument_group("required arguments")
    required.add_argument(
        "-u", "--url",
        required=True,
        metavar="SERVER_URL",
        help="SentinelOne console URL  (e.g. https://your-console.sentinelone.net)",
    )
    required.add_argument(
        "-s", "--storyline",
        required=True,
        metavar="STORYLINE_ID",
        help="Storyline ID of the threat to analyse",
    )

    output = p.add_argument_group("output options")
    output.add_argument(
        "-o", "--output",
        default=".",
        metavar="DIR",
        help="Output directory for generated files (default: current directory)",
    )
    output.add_argument("--no-csv",      action="store_true", help="Skip CSV export")
    output.add_argument("--no-markdown", action="store_true", help="Skip Markdown report")
    output.add_argument("--no-html",     action="store_true", help="Skip HTML report")
    output.add_argument("--no-terminal", action="store_true", help="Skip terminal output")
    output.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show full API errors and HTTP debug details",
    )

    return p


# ---------------------------------------------------------------------------
# Secure API-key resolution  (never exposed in CLI args / process list)
# ---------------------------------------------------------------------------

def _resolve_api_key() -> str:
    """
    Resolve the API token using this priority chain:
      1. S1_API_KEY environment variable  (recommended for scripts / CI)
      2. Interactive getpass prompt         (default for interactive use)

    The key is NEVER accepted via command-line argument to prevent it from
    appearing in shell history, /proc/PID/cmdline, or log files.
    """
    env_key = os.environ.get("S1_API_KEY", "").strip()
    if env_key:
        console.print("[dim]  API token loaded from [bold]S1_API_KEY[/bold] environment variable.[/dim]")
        return env_key

    console.print(
        "[dim]  Tip: set the [bold]S1_API_KEY[/bold] environment variable "
        "to skip this prompt.[/dim]"
    )
    key = getpass.getpass("  API Token (hidden): ").strip()
    console.print()
    return key


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------

def _step(num: int, total: int, label: str) -> None:
    console.print(f"\n[bold cyan]  [{num}/{total}]  {label}[/bold cyan]")


def _ok(msg: str) -> None:
    console.print(f"        [bold green]✓[/bold green]  {msg}")


def _warn(msg: str) -> None:
    console.print(f"        [bold yellow]⚠[/bold yellow]  {msg}")


def _err(msg: str) -> None:
    console.print(f"        [bold red]✗[/bold red]  {msg}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    base_dir   = os.path.abspath(args.output)
    # Create a dedicated subfolder: <base>/YYYY-MM-DD_HH-MM-SS_<storyline>/
    _ts_folder = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    _sl_clean  = args.storyline.replace("/", "_").replace("\\", "_")[:64]
    out_dir    = os.path.join(base_dir, f"{_ts_folder}_{_sl_clean}")
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------
    console.print()
    console.print(Rule(style="purple"))
    console.print(
        "  [bold purple]███████╗[/bold purple]  [bold cyan]SENTINELONE THREATS ANALYZER[/bold cyan]  "
        "[bold purple]███████╗[/bold purple]",
        justify="center",
    )
    console.print(
        "  [dim]SentinelOne Forensic Threat Intelligence Platform  v1.4.0[/dim]",
        justify="center",
    )
    console.print(
        "  [dim]Developed by [bold]Florian Bertaux[/bold][/dim]",
        justify="center",
    )
    console.print(Rule(style="purple"))
    console.print()

    info = [
        ("Server   ", args.url),
        ("Storyline", args.storyline),
        ("Output   ", out_dir),
    ]
    for k, v in info:
        console.print(f"  [bold dim]{k}[/bold dim]  [white]{v}[/white]")
    console.print(f"  [dim]  All reports will be saved in the folder above.[/dim]")
    console.print()

    # ------------------------------------------------------------------
    # Step 1 — API key (secure)
    # ------------------------------------------------------------------
    _step(1, 5, "Securing API credentials")
    api_key = _resolve_api_key()
    if not api_key:
        _err("No API token provided. Aborting.")
        return 1
    _ok("API token acquired (not stored, not logged).")

    # ------------------------------------------------------------------
    # Step 2 — Connectivity
    # ------------------------------------------------------------------
    _step(2, 5, "Connecting to SentinelOne console")
    client = S1APIClient(server_url=args.url, api_key=api_key, verbose=args.verbose)

    ok, detail = client.verify_connection()
    if not ok:
        _err(f"Connection failed: {detail}")
        console.print(
            "\n  [yellow]Troubleshooting:[/yellow]\n"
            "  • Check the server URL (include https://)\n"
            "  • Verify the API token is valid and not expired\n"
            "  • Ensure the token has at least 'Threats View' + 'Endpoint Forensics' permissions\n"
        )
        return 1
    _ok(f"Connected  ·  {detail}")

    # ------------------------------------------------------------------
    # Step 3 — Data collection
    # ------------------------------------------------------------------
    _step(3, 5, "Collecting threat data from API")
    collector = DataCollector(client)
    bundle = collector.collect(args.storyline)

    # Show all errors prominently
    if bundle.errors:
        console.print()
        for err in bundle.errors:
            _warn(err)
        if args.verbose:
            console.print(
                "\n  [dim]Run with [bold]--verbose[/bold] already active. "
                "Check log output above for HTTP details.[/dim]"
            )

    if not bundle.threat:
        console.print()
        _err(f"No threat found for storyline: [bold white]{args.storyline}[/bold white]")
        console.print(
            "\n  [yellow]Possible causes:[/yellow]\n"
            "  • Wrong Storyline ID (check for leading/trailing spaces)\n"
            "  • Token lacks 'Threats View' permission\n"
            "  • Threat was deleted or moved to another scope\n"
        )
        return 2

    _ok(
        f"Threat found  ·  ID: [cyan]{bundle.threat_id}[/cyan]  ·  "
        f"Events: [cyan]{len(bundle.events)}[/cyan]  ·  "
        f"Timeline entries: [cyan]{len(bundle.timeline)}[/cyan]"
    )

    if len(bundle.events) == 0:
        _warn(
            "Zero events collected. Possible causes:\n"
            "          • Token missing 'Endpoint Forensics' or 'Threat Forensics View' permission\n"
            "          • Threat events expired from the platform\n"
            "          • Events are still processing on the agent\n"
            "          Run with --verbose to see the raw API error."
        )

    # ------------------------------------------------------------------
    # Step 4 — Analysis
    # ------------------------------------------------------------------
    _step(4, 5, "Analysing collected data")
    result = ThreatAnalyzer().analyze(bundle)
    _ok(
        f"Analysis complete  ·  "
        f"Triggers: [red]{len(result.detection_triggers)}[/red]  ·  "
        f"MITRE: [yellow]{len(result.mitre_techniques)}[/yellow]  ·  "
        f"Encryption indicators: [red]{len(result.encryption_indicators)}[/red]  ·  "
        f"Net IOCs: [cyan]{len(result.network_iocs)}[/cyan]"
    )

    # ------------------------------------------------------------------
    # Step 5 — Report generation
    # ------------------------------------------------------------------
    _step(5, 5, "Generating reports")
    generated: list[str] = []

    def _write(label: str, fn) -> None:
        try:
            path = fn()
            if path:
                generated.append(path)
                size_kb = os.path.getsize(path) / 1024
                _ok(f"{label}  →  [white]{path}[/white]  [dim]({size_kb:.0f} KB)[/dim]")
        except Exception as exc:
            _warn(f"{label} generation failed: {exc}")

    if not args.no_csv:
        _write("CSV ", lambda: CSVReporter().write(result, out_dir))
    if not args.no_markdown:
        _write("MD  ", lambda: MarkdownReporter().write(result, out_dir))
    if not args.no_html:
        _write("HTML", lambda: HTMLReporter().write(result, out_dir))

    # ------------------------------------------------------------------
    # Terminal rich report
    # ------------------------------------------------------------------
    if not args.no_terminal:
        console.print()
        console.print(Rule(style="dim"))
        TerminalReporter(console).render(result)

    # ------------------------------------------------------------------
    # Footer
    # ------------------------------------------------------------------
    elapsed = time.time() - start_time
    console.print()
    console.print(Rule(style="green"))
    console.print(
        f"  [bold green]Analysis complete[/bold green]  ·  "
        f"[dim]Duration: {elapsed:.1f}s[/dim]  ·  "
        f"[dim]Reports: {len(generated)} file(s)[/dim]"
    )
    for f in generated:
        console.print(f"    [dim]•[/dim] [white]{f}[/white]")
    console.print(Rule(style="green"))
    console.print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
