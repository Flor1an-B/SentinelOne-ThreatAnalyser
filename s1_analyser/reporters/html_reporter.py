"""
HTML Reporter - Generates a self-contained, interactive HTML report.

Features:
  - Sidebar navigation with section count badges
  - Animated stat counters on load
  - Event type distribution bar chart
  - Copy-to-clipboard on all hashes, IPs, paths, commands
  - Toast notifications for copy feedback
  - Keyboard shortcuts modal (press ?)
  - Expand / Collapse All for the process tree
  - Dark glassmorphism SOC theme
  - Print CSS for clean printing
  - Zero external dependencies (pure CSS + vanilla JS, all inline)
"""
from __future__ import annotations

import html
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..analyzer import AnalysisResult, SocRecommendation, fmt_ts, event_label, event_icon
from ..process_tree import ProcessNode, ProcessTreeBuilder, _event_detail

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
/* ===== VARIABLES ===== */
:root {
  --bg:           #090c13;
  --bg-card:      #0f1420;
  --bg-card2:     #141928;
  --bg-hover:     #1a2035;
  --border:       #1c2438;
  --border-lt:    #263050;
  --sidebar-w:    220px;
  --topbar-h:     56px;
  --purple:       #7c3aed;
  --purple-lt:    #a78bfa;
  --purple-dim:   #3b1f8c;
  --cyan:         #06b6d4;
  --cyan-lt:      #22d3ee;
  --green:        #10b981;
  --green-lt:     #34d399;
  --red:          #ef4444;
  --red-lt:       #f87171;
  --yellow:       #f59e0b;
  --yellow-lt:    #fbbf24;
  --orange:       #f97316;
  --blue:         #3b82f6;
  --blue-lt:      #60a5fa;
  --dim:          #6272a4;
  --text:         #cdd6f4;
  --text-dim:     #8892b0;
  --radius:       10px;
  --radius-sm:    6px;
  --shadow:       0 4px 24px rgba(0,0,0,.45);
  --shadow-lg:    0 8px 48px rgba(0,0,0,.65);
  --ease:         .18s ease;
}
*,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
html { scroll-behavior:smooth; }
body {
  font-family:'Segoe UI','Inter',system-ui,-apple-system,sans-serif;
  background:var(--bg); color:var(--text); font-size:14px; line-height:1.6;
  display:flex; min-height:100vh;
}
a { color:var(--purple-lt); text-decoration:none; }
a:hover { text-decoration:underline; color:var(--cyan-lt); }
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--border-lt); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:var(--purple-dim); }

/* ===== SIDEBAR ===== */
.sidebar {
  width:var(--sidebar-w); min-height:100vh;
  background:linear-gradient(180deg,#0b0e1c 0%,#090c13 100%);
  border-right:1px solid var(--border);
  display:flex; flex-direction:column;
  position:fixed; top:0; left:0; z-index:200; overflow-y:auto;
}
.sidebar-brand {
  padding:18px 14px 14px; border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:10px; flex-shrink:0;
}
.brand-logo {
  width:36px; height:36px; flex-shrink:0;
  background:linear-gradient(135deg,var(--purple),var(--purple-dim));
  border-radius:9px; display:flex; align-items:center; justify-content:center;
  font-size:13px; font-weight:900; color:#fff;
  box-shadow:0 0 16px rgba(124,58,237,.4);
}
.brand-text  { font-size:.82rem; font-weight:700; color:var(--purple-lt); letter-spacing:.04em; }
.brand-sub   { font-size:.66rem; color:var(--dim); margin-top:1px; }
.sidebar-nav { padding:10px 7px; flex:1; }
.nav-group-label {
  font-size:.6rem; color:var(--dim); font-weight:700;
  text-transform:uppercase; letter-spacing:.1em; padding:8px 10px 3px;
}
.nav-item {
  display:flex; align-items:center; gap:8px; padding:8px 11px;
  border-radius:var(--radius-sm); cursor:pointer; transition:all var(--ease);
  margin-bottom:2px; color:var(--dim); font-size:.81rem; font-weight:500;
  border:none; background:none; width:100%; text-align:left;
  border-left:2px solid transparent;
}
.nav-item:hover  { background:var(--bg-hover); color:var(--text); }
.nav-item.active { background:rgba(124,58,237,.14); color:var(--purple-lt);
                   border-left-color:var(--purple); }
.nav-icon  { font-size:.95rem; min-width:20px; text-align:center; }
.nav-label { flex:1; }
.nav-badge {
  font-size:.62rem; font-weight:700; padding:1px 6px; border-radius:999px;
  background:var(--bg-card2); color:var(--dim);
}
.nav-badge.danger { background:rgba(239,68,68,.14);  color:var(--red-lt); }
.nav-badge.warn   { background:rgba(245,158,11,.12); color:var(--yellow-lt); }
.nav-badge.info   { background:rgba(6,182,212,.1);   color:var(--cyan-lt); }
.nav-badge.ok     { background:rgba(16,185,129,.1);  color:var(--green-lt); }
.sidebar-footer {
  padding:11px 13px; border-top:1px solid var(--border);
  display:flex; align-items:center; justify-content:space-between; flex-shrink:0;
}
.sidebar-footer span { font-size:.7rem; color:var(--dim); }
.btn-print {
  background:var(--bg-card2); border:1px solid var(--border-lt);
  border-radius:var(--radius-sm); color:var(--text-dim);
  font-size:.7rem; padding:4px 9px; cursor:pointer; transition:all var(--ease);
}
.btn-print:hover { background:var(--purple-dim); color:#fff; border-color:var(--purple); }

/* ===== MAIN WRAPPER ===== */
.main-wrapper { margin-left:var(--sidebar-w); flex:1; display:flex; flex-direction:column; min-height:100vh; }

/* ===== TOPBAR ===== */
.topbar {
  height:var(--topbar-h);
  background:linear-gradient(135deg,#0c0f1e 0%,#090c13 100%);
  border-bottom:1px solid var(--border);
  display:flex; align-items:center; padding:0 24px; gap:14px;
  position:sticky; top:0; z-index:100; flex-shrink:0;
}
.topbar-threat { flex:1; min-width:0; }
.topbar-name  { font-size:1rem; font-weight:700; color:var(--text); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.topbar-meta  { font-size:.7rem; color:var(--dim); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.topbar-actions { display:flex; align-items:center; gap:8px; flex-shrink:0; }
.topbar-btn {
  background:var(--bg-card2); border:1px solid var(--border-lt);
  border-radius:var(--radius-sm); color:var(--text-dim);
  font-size:.76rem; padding:5px 11px; cursor:pointer; transition:all var(--ease); white-space:nowrap;
}
.topbar-btn:hover { background:var(--bg-hover); color:var(--text); border-color:var(--purple); }

/* ===== BADGES ===== */
.badge {
  display:inline-block; padding:2px 9px; border-radius:999px;
  font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.03em;
}
.badge-red    { background:rgba(239,68,68,.12);  color:var(--red-lt);    border:1px solid rgba(239,68,68,.3); }
.badge-yellow { background:rgba(245,158,11,.1);  color:var(--yellow-lt); border:1px solid rgba(245,158,11,.3); }
.badge-green  { background:rgba(16,185,129,.1);  color:var(--green-lt);  border:1px solid rgba(16,185,129,.3); }
.badge-blue   { background:rgba(59,130,246,.1);  color:var(--blue-lt);   border:1px solid rgba(59,130,246,.3); }
.badge-purple { background:rgba(124,58,237,.12); color:var(--purple-lt); border:1px solid rgba(124,58,237,.3); }
.badge-orange { background:rgba(249,115,22,.1);  color:var(--orange);    border:1px solid rgba(249,115,22,.3); }
.badge-cyan   { background:rgba(6,182,212,.1);   color:var(--cyan-lt);   border:1px solid rgba(6,182,212,.3); }
.badge-orange { background:rgba(249,115,22,.1);  color:var(--orange);    border:1px solid rgba(249,115,22,.3); }

/* ===== CONTENT SECTIONS ===== */
.main-content { flex:1; }
.section { display:none; padding:22px 26px; }
.section.active { display:block; animation:fadeIn .22s ease; }
@keyframes fadeIn { from { opacity:0; transform:translateY(5px); } to { opacity:1; transform:translateY(0); } }

/* ===== STAT CARDS ===== */
.stat-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:12px; margin-bottom:22px; }
.stat-card {
  background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius);
  padding:15px 16px; position:relative; overflow:hidden;
  transition:transform var(--ease), box-shadow var(--ease);
}
.stat-card:hover { transform:translateY(-2px); box-shadow:var(--shadow); }
.stat-card::before { content:''; position:absolute; top:0; left:0; width:100%; height:3px; }
.stat-card.red::before    { background:var(--red); }
.stat-card.cyan::before   { background:var(--cyan); }
.stat-card.purple::before { background:var(--purple-lt); }
.stat-card.yellow::before { background:var(--yellow); }
.stat-card.orange::before { background:var(--orange); }
.stat-card.blue::before   { background:var(--blue); }
.stat-card.green::before  { background:var(--green); }
.stat-icon   { font-size:1.3rem; margin-bottom:7px; display:block; }
.stat-value  { font-size:1.9rem; font-weight:800; line-height:1; margin-bottom:3px; }
.stat-card.red    .stat-value { color:var(--red-lt); }
.stat-card.cyan   .stat-value { color:var(--cyan-lt); }
.stat-card.purple .stat-value { color:var(--purple-lt); }
.stat-card.yellow .stat-value { color:var(--yellow-lt); }
.stat-card.orange .stat-value { color:var(--orange); }
.stat-card.blue   .stat-value { color:var(--blue-lt); }
.stat-card.green  .stat-value { color:var(--green-lt); }
.stat-label { font-size:.7rem; color:var(--dim); font-weight:500; text-transform:uppercase; letter-spacing:.05em; }
.stat-bg    { position:absolute; bottom:-4px; right:6px; font-size:2.8rem; opacity:.05; pointer-events:none; }

/* ===== EVENT CHART ===== */
.chart-container {
  background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius);
  padding:16px 20px; margin-bottom:22px;
}
.chart-title { font-size:.72rem; font-weight:700; color:var(--dim); text-transform:uppercase; letter-spacing:.07em; margin-bottom:12px; }
.chart-row   { display:flex; align-items:center; gap:10px; margin-bottom:7px; font-size:.75rem; }
.chart-label { color:var(--text-dim); min-width:160px; text-align:right; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.chart-track { flex:1; height:16px; background:var(--bg-card2); border-radius:4px; overflow:hidden; }
.chart-fill  { height:100%; border-radius:4px; width:0; transition:width 1.1s cubic-bezier(.22,1,.36,1);
               display:flex; align-items:center; padding-right:5px; justify-content:flex-end; }
.chart-count { color:rgba(255,255,255,.65); font-size:.66rem; font-weight:700; white-space:nowrap; }

/* ===== SECTION HEADER ===== */
.section-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:18px; padding-bottom:10px; border-bottom:1px solid var(--border); gap:10px; flex-wrap:wrap; }
.section-title  { font-size:.95rem; font-weight:700; color:var(--purple-lt); display:flex; align-items:center; gap:8px; }
.section-actions { display:flex; gap:7px; align-items:center; flex-wrap:wrap; }

/* ===== DETAIL GRID ===== */
.detail-grid  { display:grid; grid-template-columns:repeat(auto-fill,minmax(310px,1fr)); gap:14px; margin-bottom:22px; }
.detail-block { background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius); padding:15px 17px; border-top:3px solid var(--border-lt); }
.detail-block h4 { margin-bottom:13px; font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.08em; display:flex; align-items:center; gap:7px; padding-bottom:9px; border-bottom:1px solid var(--border); }
.detail-block.dp { border-top-color:var(--purple-dim); } .detail-block.dp h4 { color:var(--purple-lt); }
.detail-block.dy { border-top-color:var(--yellow); }     .detail-block.dy h4 { color:var(--yellow-lt); }
.detail-block.dr { border-top-color:var(--red); }        .detail-block.dr h4 { color:var(--red-lt); }
.detail-block.db { border-top-color:var(--blue); }       .detail-block.db h4 { color:var(--blue-lt); }
/* Status mini-cards (reused in detail blocks) */
.status-items { display:grid; grid-template-columns:1fr 1fr; gap:6px; margin-bottom:10px; }
.status-item  { background:rgba(15,20,32,.9); border:1px solid var(--border); border-radius:var(--radius-sm); padding:8px 10px; }
.status-lbl   { font-size:.59rem; color:var(--dim); text-transform:uppercase; letter-spacing:.08em; font-weight:700; margin-bottom:3px; }
.status-val   { font-size:.78rem; font-weight:700; line-height:1.3; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.status-val.bad  { color:var(--red-lt); }
.status-val.good { color:var(--green-lt); }
.status-val.warn { color:var(--yellow-lt); }
.status-val.muted{ color:var(--dim); font-weight:400; }

/* ===== KV ROWS ===== */
.kv { display:flex; gap:8px; padding:5px 0; border-bottom:1px solid #111825; align-items:baseline; }
.kv:last-child { border:none; }
.kv .k { color:var(--dim); font-size:.79rem; min-width:150px; flex-shrink:0; }
.kv .v { color:var(--text); font-size:.81rem; word-break:break-all; min-width:0; flex:1; }
.kv .v.mono { font-family:'Consolas','Cascadia Code',monospace; font-size:.76rem; color:var(--yellow-lt); }
.kv .v.bad  { color:var(--red-lt); font-weight:600; }
.kv .v.good { color:var(--green-lt); }
.kv .v.warn { color:var(--yellow-lt); }

/* ===== COPY BUTTON ===== */
.copy-btn {
  display:inline-flex; align-items:center; justify-content:center;
  width:18px; height:18px; border-radius:3px; border:1px solid transparent;
  background:transparent; color:var(--dim); cursor:pointer; opacity:0;
  transition:all var(--ease); font-size:.7rem; vertical-align:middle;
  margin-left:3px; flex-shrink:0; padding:0; line-height:1;
}
.copy-btn:hover       { background:var(--bg-hover); border-color:var(--border-lt); color:var(--text); opacity:1 !important; }
tr:hover  .copy-btn,
.kv:hover .copy-btn,
.ioc-pill .copy-btn   { opacity:.7; }

/* ===== BUTTONS ===== */
.btn {
  background:var(--bg-card2); border:1px solid var(--border-lt); border-radius:var(--radius-sm);
  color:var(--text-dim); font-size:.76rem; padding:5px 11px; cursor:pointer;
  transition:all var(--ease); white-space:nowrap; display:inline-flex; align-items:center; gap:5px;
}
.btn:hover { background:var(--bg-hover); color:var(--text); border-color:var(--purple); }

/* ===== ALERTS ===== */
.alert { border-radius:var(--radius); padding:11px 15px; margin-bottom:14px; border-left:4px solid; font-size:.84rem; }
.alert-red    { background:rgba(239,68,68,.05);  border-color:var(--red);    color:var(--text); }
.alert-yellow { background:rgba(245,158,11,.05); border-color:var(--yellow); color:var(--text); }
.alert-green  { background:rgba(16,185,129,.05); border-color:var(--green);  color:var(--text); }
.alert strong { color:var(--red-lt); }

/* ===== TABLES ===== */
.tbl-wrap { overflow-x:auto; margin-bottom:14px; border-radius:var(--radius); border:1px solid var(--border); }
table { width:100%; border-collapse:collapse; font-size:.79rem; }
th {
  background:var(--bg-card2); color:var(--text-dim); padding:8px 12px;
  text-align:left; font-weight:600; font-size:.7rem; text-transform:uppercase; letter-spacing:.06em;
  border-bottom:1px solid var(--border); position:sticky; top:0;
  white-space:nowrap; cursor:pointer; user-select:none;
}
th:hover { color:var(--text); background:var(--bg-hover); }
td { padding:6px 12px; border-bottom:1px solid #0e1220; vertical-align:top; word-break:break-word; max-width:310px; }
tr:last-child td { border-bottom:none; }
tr:hover td { background:var(--bg-hover); }
tr.trigger td { background:rgba(239,68,68,.035); }
tr.trigger td:first-child { border-left:3px solid rgba(239,68,68,.7); }
.mono { font-family:'Consolas','Cascadia Code',monospace; color:var(--yellow-lt); font-size:.75rem; }
.dim  { color:var(--dim); }
.trig-badge {
  background:rgba(239,68,68,.12); color:var(--red-lt);
  border:1px solid rgba(239,68,68,.25); border-radius:3px;
  padding:1px 6px; font-size:.64rem; font-weight:700; text-transform:uppercase; letter-spacing:.03em; white-space:nowrap;
}

/* ===== SEARCH BAR ===== */
.search-bar { display:flex; gap:10px; margin-bottom:11px; align-items:center; }
.search-input {
  flex:1; background:var(--bg-card); border:1px solid var(--border);
  border-radius:var(--radius-sm); padding:7px 13px 7px 32px;
  color:var(--text); font-size:.82rem; outline:none; max-width:340px;
  transition:border-color var(--ease);
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='13' height='13' viewBox='0 0 24 24' fill='none' stroke='%236272a4' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E");
  background-repeat:no-repeat; background-position:10px center;
}
.search-input:focus { border-color:var(--purple); }
.row-count { color:var(--dim); font-size:.77rem; white-space:nowrap; }

/* ===== PROCESS TREE ===== */
.proc-tree  { font-family:'Consolas','Cascadia Code',monospace; font-size:.79rem; }
.proc-node  { margin-left:0; }
.proc-node .node-header {
  display:flex; align-items:flex-start; gap:6px; cursor:pointer;
  padding:5px 8px; border-radius:var(--radius-sm); transition:background var(--ease);
  user-select:none; border-left:2px solid transparent;
}
.proc-node .node-header:hover { background:var(--bg-hover); }
.proc-node .node-toggle { color:var(--dim); min-width:14px; transition:transform .15s; }
.proc-node .node-icon   { color:var(--green-lt); }
.proc-node.malicious>.node-header  { border-left-color:var(--red);    background:rgba(239,68,68,.06); }
.proc-node.malicious>.node-header .node-icon { color:var(--red-lt); }
.proc-node.malicious>.node-header .node-name { color:var(--red-lt); font-weight:700; }
.proc-node.related>.node-header    { border-left-color:#f59e0b; background:rgba(245,158,11,.05); }
.proc-node.related>.node-header .node-icon   { color:#f59e0b; }
.proc-node.related>.node-header .node-name   { color:#fbbf24; font-weight:600; }
.node-name     { color:var(--green-lt); font-weight:600; }
.node-time     { color:var(--dim); margin-left:6px; font-size:.72rem; }
.node-user     { color:var(--blue-lt); margin-left:6px; font-size:.72rem; }
.node-badge    { display:inline-block; background:rgba(239,68,68,.12); color:var(--red-lt); border:1px solid rgba(239,68,68,.25); border-radius:3px; padding:0 5px; font-size:.63rem; margin-left:5px; font-weight:700; }
.node-children { margin-left:20px; border-left:1px dashed var(--border-lt); padding-left:10px; }
.node-events   { margin-left:26px; }
.node-event    { color:var(--dim); font-size:.73rem; padding:1px 0; }
.node-event.trigger { color:var(--red-lt); font-weight:600; }
.node-cmd      { color:#2e3a54; font-size:.71rem; margin-left:26px; word-break:break-all; }

/* ===== MITRE ===== */
.mitre-section { margin-bottom:26px; }
.mitre-tactic-header {
  font-size:.73rem; font-weight:700; color:var(--cyan-lt); text-transform:uppercase;
  letter-spacing:.09em; padding:9px 0 9px 2px; margin-bottom:11px;
  border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px;
}
.tactic-count { background:var(--bg-card2); color:var(--dim); border-radius:999px; padding:1px 8px; font-size:.67rem; font-weight:600; }
.mitre-grid { display:flex; flex-wrap:wrap; gap:11px; }
.mitre-card {
  background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius);
  padding:13px 15px; min-width:210px; max-width:330px; flex:1;
  transition:border-color var(--ease), box-shadow var(--ease);
  border-top:3px solid var(--purple-dim);
}
.mitre-card:hover { border-color:var(--purple); box-shadow:0 0 14px rgba(124,58,237,.15); }
.mitre-card .technique { color:var(--text); font-size:.84rem; font-weight:600; margin-bottom:3px; }
.mitre-card .desc      { color:var(--dim); font-size:.74rem; margin-top:3px; line-height:1.5; }
.mitre-card a { color:var(--purple-lt); }
.mitre-card a:hover { color:var(--cyan-lt); }

/* ===== IOC PILLS ===== */
.ioc-list { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:14px; }
.ioc-pill {
  background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-sm);
  padding:4px 9px; font-family:'Consolas',monospace; font-size:.76rem; color:var(--yellow-lt);
  cursor:pointer; transition:all var(--ease); display:inline-flex; align-items:center; gap:5px;
}
.ioc-pill:hover { border-color:var(--yellow); background:rgba(245,158,11,.07); }
.ioc-type-lbl { color:var(--dim); font-size:.67rem; font-weight:700; text-transform:uppercase; }

/* ===== TOAST ===== */
.toast {
  position:fixed; bottom:24px; right:24px; background:var(--bg-card2);
  border:1px solid var(--green); border-radius:var(--radius); padding:9px 16px;
  color:var(--green-lt); font-size:.8rem; font-weight:600;
  box-shadow:var(--shadow-lg); z-index:9999;
  transform:translateY(60px); opacity:0;
  transition:transform .28s ease, opacity .28s ease; pointer-events:none;
}
.toast.show { transform:translateY(0); opacity:1; }

/* ===== SHORTCUTS MODAL ===== */
.modal-overlay {
  position:fixed; inset:0; background:rgba(0,0,0,.72); z-index:9000;
  display:none; align-items:center; justify-content:center;
}
.modal-overlay.show { display:flex; }
.modal-box {
  background:var(--bg-card); border:1px solid var(--border-lt); border-radius:14px;
  padding:26px 30px; min-width:320px; max-width:460px; box-shadow:var(--shadow-lg);
}
.modal-box h3 { color:var(--purple-lt); font-size:.95rem; margin-bottom:14px; }
.shortcut-row { display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--border); font-size:.81rem; }
.shortcut-row:last-of-type { border:none; }
.shortcut-row kbd { background:var(--bg-card2); border:1px solid var(--border-lt); border-radius:4px; padding:1px 7px; font-size:.74rem; color:var(--cyan-lt); font-family:monospace; }
.modal-close { margin-top:16px; width:100%; }

/* ===== EXEC SUMMARY ===== */
.exec-summary {
  background:linear-gradient(135deg,#130c24 0%,#090c13 100%);
  border:1px solid rgba(124,58,237,.28); border-radius:14px;
  padding:20px 24px; margin-bottom:24px;
  box-shadow:0 0 28px rgba(124,58,237,.07);
}
.exec-summary .es-type-badge { font-size:.95rem; font-weight:800; color:var(--red-lt); margin-bottom:3px; }
.exec-summary .es-subtitle   { color:var(--yellow-lt); font-size:.83rem; margin-bottom:13px; display:flex; align-items:center; gap:7px; flex-wrap:wrap; }
.exec-summary .es-narrative  { color:var(--text); font-size:.86rem; line-height:1.75; padding:11px 15px; background:rgba(239,68,68,.05); border-left:3px solid rgba(239,68,68,.35); border-radius:0 var(--radius-sm) var(--radius-sm) 0; margin-bottom:16px; }
.es-grid { display:grid; grid-template-columns:minmax(240px,1fr) minmax(230px,1fr) minmax(250px,1.6fr); gap:11px; margin-bottom:16px; }
@media (max-width:860px) { .es-grid { grid-template-columns:1fr 1fr; } }
@media (max-width:560px) { .es-grid { grid-template-columns:1fr; } }
.es-block { background:rgba(15,20,32,.75); border:1px solid var(--border); border-radius:var(--radius-sm); padding:14px 15px; overflow:hidden; min-width:0; }
.es-block h5 { font-size:.66rem; font-weight:700; margin-bottom:10px; text-transform:uppercase; letter-spacing:.09em; display:flex; align-items:center; gap:6px; }
.es-block-when   h5 { color:var(--cyan-lt); }
.es-block-origin h5 { color:var(--yellow-lt); }
.es-block-indic  h5 { color:var(--purple-lt); }
/* When block — 2×2 mini timestamp cards */
.when-items { display:grid; grid-template-columns:1fr 1fr; gap:7px; }
.when-item  { background:rgba(6,182,212,.05); border:1px solid rgba(6,182,212,.1); border-radius:var(--radius-sm); padding:8px 10px; }
.when-item.dur { background:rgba(124,58,237,.07); border-color:rgba(124,58,237,.18); }
.when-lbl   { font-size:.6rem; color:var(--dim); text-transform:uppercase; letter-spacing:.08em; font-weight:700; margin-bottom:3px; }
.when-val   { font-size:.75rem; font-weight:700; color:var(--cyan-lt); font-feature-settings:"tnum"; white-space:nowrap; line-height:1.3; }
.when-val.warn { color:var(--yellow-lt); }
.when-val.accent { color:var(--purple-lt); font-size:.96rem; letter-spacing:.01em; }
/* Origin block */
.es-block .kv .k { min-width:95px; font-size:.76rem; flex-shrink:0; color:var(--dim); }
.es-block .kv .v { font-size:.79rem; word-break:break-word; overflow-wrap:break-word; min-width:0; flex:1; }
.v-path { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:block; max-width:100%; cursor:help; font-family:'Consolas','Cascadia Code',monospace; font-size:.74rem; color:var(--yellow-lt); }
.proc-chain { font-family:monospace; font-size:.79rem; color:var(--red-lt); font-weight:600; word-break:break-all; }
.proc-chain .arr { color:var(--dim); margin:0 4px; }
/* Indicators block */
.es-indicators-list { list-style:none; padding:0; margin:0; }
.es-indicators-list li { display:flex; align-items:baseline; gap:6px; padding:4px 0; font-size:.78rem; color:var(--text); word-break:break-word; border-bottom:1px solid #0c101b; line-height:1.5; }
.es-indicators-list li:last-child { border-bottom:none; }
.ind-icon { font-size:.82rem; flex-shrink:0; }
.mitre-footer { margin-top:9px; font-size:.74rem; color:var(--dim); border-top:1px solid var(--border); padding-top:8px; line-height:1.6; }
.es-trigger-title { font-size:.72rem; font-weight:700; color:var(--red-lt); margin-bottom:7px; text-transform:uppercase; letter-spacing:.05em; display:flex; align-items:center; gap:6px; }

/* ===== SOC RECOMMENDATIONS ===== */
.soc-rec-section { margin-bottom:20px; }
.soc-rec-header-row { display:flex; align-items:center; justify-content:space-between; margin-bottom:11px; }
.soc-rec-section-title { font-size:.82rem; font-weight:700; color:var(--red-lt); display:flex; align-items:center; gap:7px; text-transform:uppercase; letter-spacing:.05em; }
.soc-rec-count { font-size:.68rem; color:var(--dim); }
.soc-rec-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:11px; }
.soc-rec-card {
  background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius);
  padding:13px 15px; border-left:4px solid var(--border);
  transition:box-shadow var(--ease), transform var(--ease);
}
.soc-rec-card:hover { box-shadow:var(--shadow); transform:translateY(-1px); }
.soc-rec-card.critical { border-left-color:var(--red);    background:rgba(239,68,68,.04); }
.soc-rec-card.high     { border-left-color:var(--orange);  background:rgba(249,115,22,.03); }
.soc-rec-card.medium   { border-left-color:var(--blue);    background:rgba(59,130,246,.03); }
.soc-rec-card.low      { border-left-color:var(--green);   background:rgba(16,185,129,.03); }
.soc-rec-meta { display:flex; align-items:center; gap:7px; margin-bottom:7px; }
.soc-rec-priority {
  font-size:.6rem; font-weight:800; padding:2px 7px; border-radius:999px;
  text-transform:uppercase; letter-spacing:.05em; white-space:nowrap;
}
.pri-critical { background:rgba(239,68,68,.14);  color:var(--red-lt);    border:1px solid rgba(239,68,68,.3); }
.pri-high     { background:rgba(249,115,22,.12); color:var(--orange);    border:1px solid rgba(249,115,22,.3); }
.pri-medium   { background:rgba(59,130,246,.1);  color:var(--blue-lt);   border:1px solid rgba(59,130,246,.3); }
.pri-low      { background:rgba(16,185,129,.1);  color:var(--green-lt);  border:1px solid rgba(16,185,129,.3); }
.soc-rec-category { font-size:.65rem; color:var(--dim); font-weight:600; text-transform:uppercase; letter-spacing:.06em; }
.soc-rec-title { font-size:.85rem; font-weight:700; color:var(--text); margin-bottom:5px; line-height:1.4; }
.soc-rec-details { font-size:.77rem; color:var(--text-dim); line-height:1.6; margin-bottom:9px; }
.soc-rec-actions { list-style:none; padding:0; margin:0; border-top:1px solid var(--border); padding-top:8px; }
.soc-rec-actions li {
  font-size:.75rem; color:var(--text); padding:4px 0 4px 18px;
  position:relative; border-bottom:1px solid #0c101b; line-height:1.5;
}
.soc-rec-actions li:last-child { border-bottom:none; }
.soc-rec-actions li::before { content:"\u2192"; position:absolute; left:0; color:var(--purple-lt); font-weight:700; }

/* ===== LOGIN FLAGS ===== */
tr.login-fail td { color:var(--red-lt) !important; }
tr.login-fail { background:rgba(239,68,68,.05); }
tr.login-susp td { color:var(--yellow-lt) !important; }
tr.login-susp { background:rgba(245,158,11,.04); }
.login-badge-fail { background:rgba(239,68,68,.14); color:var(--red-lt); border:1px solid rgba(239,68,68,.3); border-radius:3px; padding:1px 7px; font-size:.64rem; font-weight:700; text-transform:uppercase; white-space:nowrap; }
.login-badge-susp { background:rgba(245,158,11,.12); color:var(--yellow-lt); border:1px solid rgba(245,158,11,.3); border-radius:3px; padding:1px 7px; font-size:.64rem; font-weight:700; text-transform:uppercase; white-space:nowrap; }

/* ===== EXTERNAL LINKS (VT / Shodan) ===== */
.ext-link {
  display:inline-flex; align-items:center; font-size:.65rem; padding:1px 6px;
  border-radius:3px; background:var(--bg-card2); border:1px solid var(--border-lt);
  color:var(--dim); text-decoration:none; margin-left:3px; white-space:nowrap;
  transition:all var(--ease); vertical-align:middle;
}
.ext-link:hover { border-color:var(--cyan); color:var(--cyan-lt); background:rgba(6,182,212,.07); text-decoration:none; }

/* ===== FOOTER ===== */
.site-footer { text-align:center; padding:18px; color:var(--dim); font-size:.73rem; border-top:1px solid var(--border); margin-top:36px; }

/* ===== PRINT ===== */
@media print {
  .sidebar,.topbar,.topbar-btn,.copy-btn,.btn,.btn-print { display:none !important; }
  .main-wrapper { margin-left:0 !important; }
  .section { display:block !important; page-break-before:always; }
  .section:first-child { page-break-before:auto; }
  body { background:#fff; color:#000; font-size:11pt; }
  .exec-summary,.detail-block,.stat-card,.chart-container,.tbl-wrap { border:1px solid #ccc !important; background:#fff !important; }
  .badge,.trig-badge { border:1px solid #999 !important; }
  a { color:#000; }
  th { background:#f0f0f0 !important; color:#000 !important; }
  td { color:#222 !important; }
  .dim,.text-dim { color:#555 !important; }
  .mono { color:#333 !important; }
}
"""

# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

_JS = """
// ===== NAVIGATION =====
function showSection(id) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const sec = document.getElementById('sec-' + id);
  if (sec) sec.classList.add('active');
  const nav = document.querySelector('[data-section="' + id + '"]');
  if (nav) nav.classList.add('active');
  window._cur = id;
}

// ===== COPY =====
function copyText(text, btn) {
  const t = typeof text === 'string' ? text : String(text);
  const done = () => {
    showToast('\u2713 Copied: ' + t.substring(0, 60) + (t.length > 60 ? '\u2026' : ''));
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '\u2713';
      btn.style.color = 'var(--green-lt)';
      setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
    }
  };
  if (navigator.clipboard) {
    navigator.clipboard.writeText(t).then(done).catch(() => fallbackCopy(t, done));
  } else { fallbackCopy(t, done); }
}
function fallbackCopy(text, cb) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;';
  document.body.appendChild(ta); ta.focus(); ta.select();
  try { document.execCommand('copy'); } catch(e) {}
  document.body.removeChild(ta);
  if (cb) cb();
}
function copyAll(containerId) {
  const vals = Array.from(document.querySelectorAll('#' + containerId + ' [data-v]'))
                    .map(el => el.dataset.v).filter(Boolean);
  if (vals.length) copyText(vals.join('\\n'));
}

// ===== TOAST =====
let _tt = null;
function showToast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.classList.add('show');
  clearTimeout(_tt);
  _tt = setTimeout(() => el.classList.remove('show'), 2600);
}

// ===== TRIGGER TOGGLE =====
let _showOnlyTriggers = false;
function toggleTriggerFilter(btn) {
  _showOnlyTriggers = !_showOnlyTriggers;
  btn.style.borderColor = _showOnlyTriggers ? 'var(--red)' : '';
  btn.style.color = _showOnlyTriggers ? 'var(--red-lt)' : '';
  filterTable('search-events', 'tbl-events', 'count-events');
}

// ===== FILTER TABLE =====
function filterTable(inputId, tableId, countId) {
  const q = document.getElementById(inputId).value.toLowerCase().trim();
  const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
  const trigOnly = _showOnlyTriggers && tableId === 'tbl-events';
  let shown = 0;
  rows.forEach(r => {
    const m = (!q || r.textContent.toLowerCase().includes(q))
              && (!trigOnly || r.classList.contains('trigger'));
    r.style.display = m ? '' : 'none';
    if (m) shown++;
  });
  const el = document.getElementById(countId);
  if (el) el.textContent = shown + ' rows';
}

// ===== SORT TABLE =====
function sortTable(tableId, col) {
  const tbl = document.getElementById(tableId); if (!tbl) return;
  const tbody = tbl.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const dir = tbl.dataset.sd === 'a' ? 'd' : 'a'; tbl.dataset.sd = dir;
  rows.sort((a, b) => {
    const av = a.cells[col]?.textContent.trim() || '';
    const bv = b.cells[col]?.textContent.trim() || '';
    return dir === 'a' ? av.localeCompare(bv, undefined, {numeric:true})
                       : bv.localeCompare(av, undefined, {numeric:true});
  });
  tbody.append(...rows);
}

// ===== PROCESS TREE =====
function toggleNode(id) {
  const el = document.getElementById(id); if (!el) return;
  const hidden = el.style.display === 'none';
  el.style.display = hidden ? '' : 'none';
  const hdr = el.previousElementSibling;
  if (hdr) {
    const tog = hdr.querySelector('.node-toggle');
    if (tog) tog.textContent = hidden ? '\u25be' : '\u25b8';
  }
}
function expandAll() {
  document.querySelectorAll('.node-children').forEach(el => el.style.display = '');
  document.querySelectorAll('.node-toggle').forEach(t => { if (t.textContent === '\u25b8') t.textContent = '\u25be'; });
}
function collapseAll() {
  document.querySelectorAll('.node-children').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.node-toggle').forEach(t => { if (t.textContent === '\u25be') t.textContent = '\u25b8'; });
}

// ===== ANIMATED COUNTERS =====
function animateCounters() {
  document.querySelectorAll('[data-count]').forEach(el => {
    const target = parseInt(el.dataset.count, 10);
    if (isNaN(target) || target === 0) { el.textContent = '0'; return; }
    const dur = Math.min(900, 200 + target * 2);
    const start = performance.now();
    (function step(now) {
      const p = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(eased * target).toLocaleString();
      if (p < 1) requestAnimationFrame(step);
    })(performance.now());
  });
}

// ===== ANIMATE CHART BARS =====
function animateBars() {
  document.querySelectorAll('.chart-fill[data-pct]').forEach(el => {
    setTimeout(() => { el.style.width = el.dataset.pct + '%'; }, 120);
  });
}

// ===== SHORTCUTS MODAL =====
function showShortcuts() { document.getElementById('shortcuts-modal').classList.add('show'); }
function closeShortcuts() { document.getElementById('shortcuts-modal').classList.remove('show'); }

// ===== KEYBOARD =====
const _sections = ['overview','narrative','process','events','files','registry','network','login','tasks','iocs','mitre'];
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeShortcuts(); return; }
  if (e.key === '?' && !e.ctrlKey && !e.metaKey) { showShortcuts(); return; }
  if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
    const inp = document.querySelector('.section.active .search-input');
    if (inp) { e.preventDefault(); inp.focus(); }
    return;
  }
  if (!e.ctrlKey && !e.metaKey && !e.altKey && !e.shiftKey) {
    const idx = parseInt(e.key, 10) - 1;
    if (idx >= 0 && idx < _sections.length) showSection(_sections[idx]);
  }
});

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  animateCounters();
  animateBars();
});
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(s: Any) -> str:
    return html.escape(str(s) if s is not None else "")


def _badge(text: str, colour: str = "blue") -> str:
    return f'<span class="badge badge-{colour}">{_e(text)}</span>'


def _confidence_badge(level: str) -> str:
    colour = {"malicious": "red", "suspicious": "yellow"}.get(level, "green")
    return _badge(level.upper() if level else "UNKNOWN", colour)


def _copy_btn(value: str) -> str:
    ev = _e(value)
    return f'<button class="copy-btn" onclick="copyText(this.dataset.v,this)" data-v="{ev}" title="Copy">\u29c9</button>'


def _vt_link(value: str) -> str:
    """Return VirusTotal / Shodan external link HTML anchors for an IOC value."""
    if not value:
        return ""
    v = value.strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        vt = f"https://www.virustotal.com/gui/ip-address/{v}"
        sh = f"https://www.shodan.io/host/{v}"
        return (
            f'<a class="ext-link" href="{_e(vt)}" target="_blank" rel="noopener noreferrer">VT</a>'
            f'<a class="ext-link" href="{_e(sh)}" target="_blank" rel="noopener noreferrer">SH</a>'
        )
    if re.match(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$', v):
        vt = f"https://www.virustotal.com/gui/file/{v}"
        return f'<a class="ext-link" href="{_e(vt)}" target="_blank" rel="noopener noreferrer">VT</a>'
    # Domain / hostname
    vt = f"https://www.virustotal.com/gui/domain/{v}"
    return f'<a class="ext-link" href="{_e(vt)}" target="_blank" rel="noopener noreferrer">VT</a>'


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class HTMLReporter:

    def write(self, result: AnalysisResult, output_dir: str) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        storyline = result.bundle.storyline_id.replace("/", "_").replace("\\", "_")
        filename = f"S1_ThreatReport_{storyline}_{timestamp}.html"
        filepath = os.path.join(output_dir, filename)
        doc = self._build_document(result)
        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(doc)
        return filepath

    # ------------------------------------------------------------------
    # Document skeleton
    # ------------------------------------------------------------------

    def _build_document(self, result: AnalysisResult) -> str:
        ti  = result.bundle.threat_info
        adi = result.bundle.agent_detection_info
        ari = result.bundle.agent_realtime_info
        cat = result.categorized
        gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        threat_name = ti.get("threatName") or ti.get("sha1") or "Unknown Threat"
        hostname    = ari.get("agentComputerName") or adi.get("agentComputerName") or "?"
        username    = adi.get("agentLastLoggedInUserName") or "?"
        confidence  = ti.get("confidenceLevel") or ""
        mit_status  = ti.get("mitigationStatus") or "unknown"
        net_count   = len(cat.network) + len(cat.dns)
        mitre_count = len(result.mitre_techniques)
        ioc_count   = len(result.network_iocs) + len(result.file_iocs)

        narrative_phase_count = len(result.narrative_phases)
        nav_items = [
            ("overview",   "⚡", "Overview",         str(len(result.detection_triggers)), "danger"),
            ("narrative",  "📖", "Narrative",         str(narrative_phase_count),          "ok"),
            ("process",    "🌳", "Process Tree",      str(result.unique_processes),        "info"),
            ("events",    "📋", "All Events",    str(len(result.bundle.events)),       "info"),
            ("files",     "📄", "Files",         str(len(cat.file)),                   "warn"),
            ("registry",  "🔑", "Registry",      str(len(cat.registry)),               "warn"),
            ("network",   "🌐", "Network",       str(net_count),                       "info"),
            ("login",     "👤", "Login",         str(len(cat.login)),                  "ok"),
            ("tasks",     "⏰", "Sched. Tasks",  str(len(cat.scheduled_task)),          "warn"),
            ("iocs",      "🎯", "IOCs",          str(ioc_count),                       "danger"),
            ("mitre",     "⚔",  "MITRE ATT&CK",  str(mitre_count),                     "ok"),
        ]

        nav_html = "\n".join(
            f'<button class="nav-item{"  active" if sid=="overview" else ""}" '
            f'data-section="{sid}" onclick="showSection(\'{sid}\')">'
            f'<span class="nav-icon">{icon}</span>'
            f'<span class="nav-label">{label}</span>'
            f'<span class="nav-badge {bcls}">{cnt}</span>'
            f'</button>'
            for sid, icon, label, cnt, bcls in nav_items
        )

        conf_col = {"malicious": "red", "suspicious": "yellow"}.get(confidence, "green")
        mit_col  = "green" if any(k in mit_status.lower() for k in ("remediat","quarantin")) else "yellow"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SentinelOne Threats Analyzer \u2014 {_e(threat_name)}</title>
<style>{_CSS}</style>
</head>
<body>

<!-- ===== SIDEBAR ===== -->
<aside class="sidebar">
  <div class="sidebar-brand">
    <div class="brand-logo">S1</div>
    <div>
      <div class="brand-text">Threats Analyzer</div>
      <div class="brand-sub">SentinelOne Intel</div>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-group-label">Navigation</div>
    {nav_html}
  </nav>
  <div class="sidebar-footer">
    <div>
      <div style="font-size:.68rem;color:var(--dim);">v1.4.0</div>
      <div style="font-size:.62rem;color:var(--purple-lt);font-weight:600;margin-top:1px;">F. Bertaux</div>
    </div>
    <button class="btn-print" onclick="window.print()">&#128424; Print</button>
  </div>
</aside>

<!-- ===== MAIN ===== -->
<div class="main-wrapper">

  <!-- Topbar -->
  <header class="topbar">
    <div class="topbar-threat">
      <div class="topbar-name">{_e(threat_name)}</div>
      <div class="topbar-meta">
        Host: {_e(hostname)}&nbsp;&nbsp;&#183;&nbsp;&nbsp;User: {_e(username)}&nbsp;&nbsp;&#183;&nbsp;&nbsp;Storyline: {_e(result.bundle.storyline_id)}&nbsp;&nbsp;&#183;&nbsp;&nbsp;{_e(gen_ts)}
      </div>
    </div>
    <div class="topbar-actions">
      <span class="badge badge-{conf_col}">{_e(confidence.upper() if confidence else "UNKNOWN")}</span>
      <span class="badge badge-{mit_col}">{_e(mit_status)}</span>
      <button class="topbar-btn" onclick="window.print()">&#128424; Print</button>
      <button class="topbar-btn" onclick="showShortcuts()">&#9000; Shortcuts</button>
    </div>
  </header>

  <!-- Sections -->
  <main class="main-content">

    <section id="sec-overview" class="section active">
      {self._build_stat_cards(result)}
      {self._build_event_chart(result)}
      {self._tab_overview(result)}
    </section>

    <section id="sec-narrative" class="section">
      {self._tab_narrative(result)}
    </section>

    <section id="sec-process" class="section">
      {self._tab_process_tree(result)}
    </section>

    <section id="sec-events" class="section">
      {self._tab_all_events(result)}
    </section>

    <section id="sec-files" class="section">
      {self._tab_files(result)}
    </section>

    <section id="sec-registry" class="section">
      {self._tab_registry(result)}
    </section>

    <section id="sec-network" class="section">
      {self._tab_network(result)}
    </section>

    <section id="sec-login" class="section">
      {self._tab_login(result)}
    </section>

    <section id="sec-tasks" class="section">
      {self._tab_scheduled_tasks(result)}
    </section>

    <section id="sec-iocs" class="section">
      {self._tab_iocs(result)}
    </section>

    <section id="sec-mitre" class="section">
      {self._tab_mitre(result)}
    </section>

  </main>

  <footer class="site-footer">
    Generated by <strong>SentinelOne Threats Analyzer v1.4.0</strong> &mdash; {_e(gen_ts)}
    &nbsp;&nbsp;&#183;&nbsp;&nbsp; Developed by <strong style="color:var(--purple-lt)">Florian Bertaux</strong>
  </footer>
</div>

<!-- Toast -->
<div id="toast" class="toast">Copied!</div>

<!-- Shortcuts modal -->
<div id="shortcuts-modal" class="modal-overlay" onclick="if(event.target===this)closeShortcuts()">
  <div class="modal-box">
    <h3>&#9000; Keyboard Shortcuts</h3>
    <div class="shortcut-row"><span>Navigate to section</span><span><kbd>1</kbd>&ndash;<kbd>9</kbd></span></div>
    <div class="shortcut-row"><span>Search in current section</span><span><kbd>Ctrl</kbd>+<kbd>F</kbd></span></div>
    <div class="shortcut-row"><span>Show this panel</span><span><kbd>?</kbd></span></div>
    <div class="shortcut-row"><span>Close modal</span><span><kbd>Esc</kbd></span></div>
    <button class="btn modal-close" onclick="closeShortcuts()">Close</button>
  </div>
</div>

<script>{_JS}</script>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Stat cards
    # ------------------------------------------------------------------

    @staticmethod
    def _build_stat_cards(result: AnalysisResult) -> str:
        cat = result.categorized
        net_count = len(cat.network) + len(cat.dns)
        ioc_count = len(result.network_iocs) + len(result.file_iocs)
        cards_data = [
            ("📋", len(result.bundle.events),       "Total Events",       "cyan"),
            ("🔴", len(result.detection_triggers),  "Detection Triggers", "red"),
            ("🌳", result.unique_processes,          "Unique Processes",   "purple"),
            ("📄", len(cat.file),                    "File Events",        "yellow"),
            ("🔑", len(cat.registry),                "Registry Events",    "orange"),
            ("🌐", net_count,                        "Network Events",     "blue"),
            ("🎯", ioc_count,                        "IOCs Found",         "red"),
            ("⚔",  len(result.mitre_techniques),    "MITRE Techniques",   "green"),
        ]
        cards_html = "".join(
            f'<div class="stat-card {col}">'
            f'<span class="stat-icon">{icon}</span>'
            f'<div class="stat-value" data-count="{val}">0</div>'
            f'<div class="stat-label">{label}</div>'
            f'<span class="stat-bg">{icon}</span>'
            f'</div>'
            for icon, val, label, col in cards_data
        )
        return f'<div class="stat-grid">{cards_html}</div>'

    # ------------------------------------------------------------------
    # Event distribution chart
    # ------------------------------------------------------------------

    @staticmethod
    def _build_event_chart(result: AnalysisResult) -> str:
        type_counts: Counter = Counter(event_label(e) for e in result.bundle.events)
        if not type_counts:
            return ""
        top = type_counts.most_common(8)
        max_c = top[0][1] if top else 1
        color_map = {
            "process": "#7c3aed", "creation": "#7c3aed",
            "file": "#f59e0b", "write": "#f59e0b", "rename": "#f97316",
            "network": "#3b82f6", "connect": "#3b82f6",
            "dns": "#06b6d4",
            "registry": "#f97316",
            "login": "#10b981",
            "scheduled": "#a78bfa",
        }
        rows = ""
        for label, count in top:
            pct = round((count / max_c) * 100, 1) if max_c else 0
            color = "#6272a4"
            for key, col in color_map.items():
                if key in label.lower():
                    color = col
                    break
            rows += (
                f'<div class="chart-row">'
                f'<div class="chart-label">{_e(label)}</div>'
                f'<div class="chart-track">'
                f'<div class="chart-fill" data-pct="{pct}" style="background:{color};">'
                f'<span class="chart-count">{count}</span>'
                f'</div></div></div>'
            )
        return (
            f'<div class="chart-container">'
            f'<div class="chart-title">&#128202; Event Type Distribution</div>'
            f'{rows}</div>'
        )

    # ------------------------------------------------------------------
    # Executive summary
    # ------------------------------------------------------------------

    def _build_executive_summary_html(self, result: AnalysisResult) -> str:
        es = result.executive_summary
        if es is None:
            return ""

        def _dur(secs):
            if secs is None: return "—"
            if secs < 60:    return f"{secs:.0f}s"
            if secs < 3600:  return f"{secs/60:.1f} min"
            return f"{secs/3600:.1f} h"

        # ── WHEN? block — 2×2 timestamp mini-cards ──────────────────────────
        when_block = f"""<div class="es-block es-block-when">
  <h5>&#9203; When?</h5>
  <div class="when-items">
    <div class="when-item">
      <div class="when-lbl">First Event</div>
      <div class="when-val">{_e(fmt_ts(es.first_event_ts))}</div>
    </div>
    <div class="when-item">
      <div class="when-lbl">Last Event</div>
      <div class="when-val">{_e(fmt_ts(es.last_event_ts))}</div>
    </div>
    <div class="when-item">
      <div class="when-lbl">S1 Detection</div>
      <div class="when-val warn">{_e(fmt_ts(es.detection_ts))}</div>
    </div>
    <div class="when-item dur">
      <div class="when-lbl">Duration</div>
      <div class="when-val accent">{_e(_dur(es.duration_seconds))}</div>
    </div>
  </div>
</div>"""

        # ── ORIGIN? block — truncated path with hover tooltip ────────────────
        chain_html = (
            '<span class="arr">\u2192</span>'.join(
                f'<span style="color:var(--red-lt);font-weight:600;">{_e(p)}</span>'
                for p in es.process_chain
            ) if es.process_chain else '<span class="dim">\u2014</span>'
        )
        threat_path = es.threat_file_path or ""
        origin_block = f"""<div class="es-block es-block-origin">
  <h5>&#127919; Origin?</h5>
  <div class="kv"><span class="k">Host</span><span class="v good">{_e(es.hostname)}</span></div>
  <div class="kv"><span class="k">User</span><span class="v warn">{_e(es.username)}</span></div>
  <div class="kv">
    <span class="k">Threat File</span>
    <span class="v-path" title="{_e(threat_path)}">{_e(threat_path)}</span>
    {_copy_btn(threat_path) if threat_path else ""}
  </div>
  <div class="kv"><span class="k">Process Chain</span><span class="v"><span class="proc-chain">{chain_html}</span></span></div>
</div>"""

        # ── KEY INDICATORS block — icon per category ─────────────────────────
        def _ind_icon(text: str) -> str:
            s = text.lower()
            if "ransom" in s or "encrypt" in s: return "&#128274;"   # 🔒
            if "c2" in s or "connection" in s:  return "&#127760;"   # 🌐
            if "dns" in s:                       return "&#128269;"   # 🔍
            if "persist" in s or "registry" in s: return "&#128273;" # 🔑
            if "lateral" in s:                   return "&#8596;"    # ↔
            if "account" in s or "credential" in s: return "&#128100;"  # 👤
            if "schedule" in s or "task" in s:   return "&#9200;"    # ⏰
            if "hash" in s or "ioc" in s:        return "&#127919;"  # 🎯
            return "&#9679;"  # ●

        indicators_block = ""
        if es.key_indicators:
            ind_items = "".join(
                f'<li><span class="ind-icon">{_ind_icon(ind)}</span>{_e(ind)}</li>'
                for ind in es.key_indicators
            )
            mitre_str = (
                "&nbsp;<span style='color:var(--border-lt)'>|</span>&nbsp;".join(
                    f'<span style="color:var(--cyan-lt);font-weight:600;">{_e(t)}</span>'
                    for t in es.mitre_tactic_names
                ) if es.mitre_tactic_names else '<span class="dim">\u2014</span>'
            )
            indicators_block = f"""<div class="es-block es-block-indic">
  <h5>&#128205; Key Indicators</h5>
  <ul class="es-indicators-list">{ind_items}</ul>
  <div class="mitre-footer">MITRE Tactics:&nbsp;{mitre_str}</div>
</div>"""

        # ── TRIGGER COMMANDS table ────────────────────────────────────────────
        trigger_block = ""
        if es.trigger_commands:
            def _flag_badges(flags):
                return "".join(
                    f'<span class="trig-badge">{_e(flag)}</span>' for flag in flags
                )
            rows = "".join(
                f"<tr>"
                f'<td class="mono dim">{_e(fmt_ts(tc["ts"]))}</td>'
                f'<td>{_e(tc["event_type"])}</td>'
                f'<td class="mono">{_e(tc["process_name"] or "\u2014")}</td>'
                f'<td class="mono" style="color:var(--yellow-lt);word-break:break-all;">'
                f'{_e(tc["command"] or "\u2014")}'
                f'{_copy_btn(tc["command"] or "") if tc.get("command") else ""}</td>'
                f'<td>{_flag_badges(tc["flags"])}</td>'
                f"</tr>"
                for tc in es.trigger_commands
            )
            trigger_block = f"""
<div class="es-trigger-title">&#9889; Commands That Triggered Detection</div>
<div class="tbl-wrap">
<table>
<thead><tr>
  <th>Timestamp</th><th>Event Type</th><th>Process</th><th>Command / Detail</th><th>Flags</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""

        return f"""
<div class="exec-summary">
  <div class="es-type-badge">
    {_confidence_badge(es.attack_confidence)}
    &nbsp;&nbsp;{_e(es.attack_type)}
  </div>
  <div class="es-subtitle">
    {_e(es.threat_name)}
    &nbsp;{_badge(_e(es.classification), "blue")}
    &nbsp;Mitigation:&nbsp;<strong style="color:{'var(--green-lt)' if 'mitigat' in (es.mitigation_status or '').lower() else 'var(--yellow-lt)'};">{_e(es.mitigation_status)}</strong>
  </div>

  <div class="es-narrative">{_e(es.narrative)}</div>

  <div class="es-grid">
    {when_block}
    {origin_block}
    {indicators_block}
  </div>
  {trigger_block}
</div>"""

    # ------------------------------------------------------------------
    # Overview tab
    # ------------------------------------------------------------------

    def _tab_overview(self, result: AnalysisResult) -> str:
        ti  = result.bundle.threat_info
        adi = result.bundle.agent_detection_info
        ari = result.bundle.agent_realtime_info

        def _kv(k: str, v: Any, cls: str = "") -> str:
            val = _e(v) if v else '<span class="dim">\u2014</span>'
            return f'<div class="kv"><span class="k">{_e(k)}</span><span class="v {cls}">{val}</span></div>'

        def _kvh(k: str, v_html: str, cls: str = "") -> str:
            """Like _kv but v_html is pre-built HTML — NOT escaped."""
            val = v_html if v_html else '<span class="dim">\u2014</span>'
            return f'<div class="kv"><span class="k">{_e(k)}</span><span class="v {cls}">{val}</span></div>'

        def _kvm(k: str, v: Any) -> str:
            val = (f'<span class="mono">{_e(v)}</span>{_copy_btn(str(v))}'
                   if v else '<span class="dim">\u2014</span>')
            return f'<div class="kv"><span class="k">{_e(k)}</span><span class="v">{val}</span></div>'

        alerts_html = ""
        if result.encryption_indicators:
            items = "".join(f"<li>{_e(i['reason'])}</li>" for i in result.encryption_indicators)
            alerts_html += (
                f'<div class="alert alert-red"><strong>&#9888; RANSOMWARE / ENCRYPTION INDICATORS DETECTED</strong>'
                f'<ul style="margin-top:7px;padding-left:18px;">{items}</ul></div>'
            )
        if result.detection_triggers:
            alerts_html += (
                f'<div class="alert alert-yellow"><strong>&#9889; {len(result.detection_triggers)} detection-trigger event(s)</strong>'
                f' identified \u2014 these are the actions that caused SentinelOne to alert.</div>'
            )

        engines = ti.get("detectionEngines") or []
        eng_str = ", ".join(
            (e.get("key") or str(e)) if isinstance(e, dict) else str(e) for e in engines
        ) or "\u2014"
        mit_status = ti.get("mitigationStatus") or ""

        # ── Status mini-card helper ──────────────────────────────────────────
        def _sc(lbl: str, val: str, cls: str = "muted") -> str:
            safe = _e(val) if val else '<span style="opacity:.4">\u2014</span>'
            return (
                f'<div class="status-item">'
                f'<div class="status-lbl">{_e(lbl)}</div>'
                f'<div class="status-val {cls}">{safe}</div>'
                f'</div>'
            )

        inc_status  = ti.get("incidentStatus")  or ""
        mit_val     = ti.get("mitigationStatus") or ""
        verdict_val = ti.get("analystVerdict")   or ""
        conf_val    = ti.get("confidenceLevel")  or ""

        inc_cls  = "good" if "resolv" in inc_status.lower()  else ("warn" if inc_status else "muted")
        mit_cls  = "good" if any(k in mit_val.lower() for k in ("remediat","quarantin","killed")) else "warn" if mit_val else "muted"
        conf_cls = "bad"  if conf_val == "malicious" else ("warn" if conf_val == "suspicious" else "muted")

        # File path — truncated + tooltip
        fpath = ti.get("filePath") or ""
        fpath_html = (
            f'<span class="v-path" title="{_e(fpath)}">{_e(fpath)}</span>{_copy_btn(fpath)}'
            if fpath else '<span class="dim">\u2014</span>'
        )

        return f"""
{self._build_executive_summary_html(result)}
{self._build_soc_recommendations_html(result)}
{alerts_html}

<div class="section-header">
  <div class="section-title">&#128737; Threat Details</div>
</div>
<div class="detail-grid">

  <div class="detail-block dp">
    <h4>&#9888;&#xFE0F; Identification</h4>
    {_kv("Threat Name",       ti.get("threatName") or ti.get("sha1"), "warn")}
    {_kv("Threat ID",         result.bundle.threat_id)}
    {_kv("Storyline ID",      result.bundle.storyline_id)}
    {_kv("Classification",    ti.get("classification"))}
    {_kv("Confidence Level",  conf_val, conf_cls)}
    {_kv("Detection Type",    ti.get("detectionType"))}
    {_kv("Initiated By",      ti.get("initiatedBy"))}
    {_kv("Initiating User",   ti.get("initiatingUsername"))}
    {_kv("Originated Process",ti.get("originatorProcess"))}
    {_kv("Identified At",     fmt_ts(ti.get("identifiedAt")))}
    {_kv("Created At",        fmt_ts(ti.get("createdAt")))}
    {_kv("Updated At",        fmt_ts(ti.get("updatedAt")))}
  </div>

  <div class="detail-block dy">
    <h4>&#128196; File Information</h4>
    <div class="kv"><span class="k">File Path</span>{fpath_html}</div>
    {_kv("File Extension",   ti.get("fileExtension"))}
    {_kv("File Size",        f"{ti.get('fileSize') or '?'} bytes")}
    {_kvm("SHA1",   ti.get("sha1"))}
    {_kvm("SHA256", ti.get("sha256"))}
    {_kvm("MD5",    ti.get("md5"))}
    {_kv("Publisher",        ti.get("publisherName"))}
    {_kvh("Valid Certificate","&#9989; Yes" if ti.get("isValidCertificate") else "&#10060; No",
          "good" if ti.get("isValidCertificate") else "bad")}
    {_kv("Is Fileless",      "Yes" if ti.get("isFileless") else "No")}
    {_kv("Malicious Args",   ti.get("maliciousProcessArguments"))}
  </div>

  <div class="detail-block dr">
    <h4>&#128737; Status &amp; Mitigation</h4>
    <div class="status-items">
      {_sc("Incident Status",   inc_status  or "\u2014", inc_cls)}
      {_sc("Mitigation Status", mit_val     or "\u2014", mit_cls)}
      {_sc("Analyst Verdict",   verdict_val or "\u2014", "warn" if verdict_val and verdict_val not in ("true_positive","false_positive") else "muted")}
      {_sc("Confidence",        conf_val    or "\u2014", conf_cls)}
    </div>
    {_kv("Detection Engines",  eng_str)}
    {_kvh("Pre-Execution Block","&#9989; Yes" if ti.get("mitigatedPreemptively") else "&#10060; No",
          "good" if ti.get("mitigatedPreemptively") else "")}
    {_kvh("Reboot Required",   "&#9888; Yes" if ti.get("rebootRequired") else "No",
          "warn" if ti.get("rebootRequired") else "")}
    {_kv("Events Limit Hit",  "Yes &#9888;" if ti.get("reachedEventsLimit") else "No",
         "warn" if ti.get("reachedEventsLimit") else "")}
  </div>

  <div class="detail-block db">
    <h4>&#128187; Host Information</h4>
    {_kv("Computer Name",    ari.get("agentComputerName"), "good")}
    {_kv("Agent UUID",       adi.get("agentUuid"))}
    {_kv("OS Name",          adi.get("agentOsName"))}
    {_kv("OS Revision",      adi.get("agentOsRevision"))}
    {_kv("Agent Version",    adi.get("agentVersion"))}
    {_kv("Domain",           adi.get("agentDomain"))}
    {_kv("IPv4",             adi.get("agentIpV4"))}
    {_kv("IPv6",             adi.get("agentIpV6"))}
    {_kv("External IP",      adi.get("externalIp"))}
    {_kv("Last Logged User", adi.get("agentLastLoggedInUserName"), "warn")}
    {_kv("Site",             adi.get("siteName"))}
    {_kv("Group",            adi.get("groupName"))}
    {_kv("Account",          adi.get("accountName"))}
    {_kv("Mitigation Mode",  adi.get("agentMitigationMode"))}
    {_kv("Machine Type",     ari.get("agentMachineType"))}
    {_kv("Network Status",   ari.get("agentNetworkStatus"))}
    {_kvh("Agent Active",     "&#9989; Yes" if ari.get("agentIsActive") else ("&#10060; No" if ari.get("agentIsActive") is not None else None),
          "good" if ari.get("agentIsActive") else "")}
    {_kvh("Decommissioned",   "&#9888; Yes" if ari.get("agentIsDecommissioned") else ("No" if ari.get("agentIsDecommissioned") is not None else None),
          "warn" if ari.get("agentIsDecommissioned") else "")}
  </div>

</div>

<div class="section-header">
  <div class="section-title">&#128220; Detection Trigger Timeline</div>
</div>
{self._detection_trigger_table(result)}
"""

    # ------------------------------------------------------------------
    # SOC Recommendations
    # ------------------------------------------------------------------

    @staticmethod
    def _build_soc_recommendations_html(result: AnalysisResult) -> str:
        recs = result.soc_recommendations
        if not recs:
            return ""

        _pri_cls = {
            "CRITICAL": ("critical", "pri-critical"),
            "HIGH":     ("high",     "pri-high"),
            "MEDIUM":   ("medium",   "pri-medium"),
            "LOW":      ("low",      "pri-low"),
        }

        cards_html = ""
        for rec in recs:
            card_cls, badge_cls = _pri_cls.get(rec.priority.upper(), ("low", "pri-low"))
            actions_html = "".join(
                f"<li>{_e(a)}</li>" for a in rec.actions if a
            )
            cards_html += f"""<div class="soc-rec-card {card_cls}">
  <div class="soc-rec-meta">
    <span class="soc-rec-priority {badge_cls}">{_e(rec.priority)}</span>
    <span class="soc-rec-category">{_e(rec.category)}</span>
  </div>
  <div class="soc-rec-title">{_e(rec.title)}</div>
  <div class="soc-rec-details">{_e(rec.details)}</div>
  <ul class="soc-rec-actions">{actions_html}</ul>
</div>"""

        crit_count = sum(1 for r in recs if r.priority == "CRITICAL")
        high_count = sum(1 for r in recs if r.priority == "HIGH")
        badge_extra = ""
        if crit_count:
            badge_extra += f' &nbsp;<span class="badge badge-red">{crit_count} CRITICAL</span>'
        if high_count:
            badge_extra += f' &nbsp;<span class="badge badge-orange">{high_count} HIGH</span>'

        return f"""<div class="soc-rec-section">
  <div class="soc-rec-header-row">
    <div class="soc-rec-section-title">&#128270; SOC Analyst Recommendations{badge_extra}</div>
    <span class="soc-rec-count">{len(recs)} action item(s) based on findings</span>
  </div>
  <div class="soc-rec-grid">{cards_html}</div>
</div>"""

    def _detection_trigger_table(self, result: AnalysisResult) -> str:
        triggers = result.detection_triggers
        if not triggers:
            return '<div class="alert alert-green">No explicit detection triggers found.</div>'

        rows = ""
        for evt in sorted(triggers, key=lambda e: e.get("createdAt") or "")[:50]:
            flags = ""
            if evt.get("relatedToThreat"):
                flags += '<span class="trig-badge">RELATED</span>'
            if evt.get("processIsMalicious"):
                flags += '<span class="trig-badge">MALICIOUS</span>'
            detail = _e(_event_detail(evt) or "")
            cmd    = evt.get("processCmd") or ""
            rows += (
                f'<tr class="trigger">'
                f'<td class="mono">{_e(fmt_ts(evt.get("createdAt")))}</td>'
                f'<td>{_e(event_label(evt))}</td>'
                f'<td class="mono">{_e(evt.get("processName") or "\u2014")}</td>'
                f'<td>{detail}</td>'
                f'<td class="mono dim">{_e(cmd[:80])}{_copy_btn(cmd) if cmd else ""}</td>'
                f'<td>{flags}</td>'
                f'</tr>'
            )

        return f"""
<div class="tbl-wrap">
<table id="tbl-triggers">
<thead><tr>
  <th onclick="sortTable('tbl-triggers',0)">Timestamp \u21d5</th>
  <th onclick="sortTable('tbl-triggers',1)">Event Type \u21d5</th>
  <th onclick="sortTable('tbl-triggers',2)">Process \u21d5</th>
  <th>Detail</th><th>Command</th><th>Flags</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""

    # ------------------------------------------------------------------
    # Process tree
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Narrative tab
    # ------------------------------------------------------------------

    def _tab_narrative(self, result: AnalysisResult) -> str:
        """Render the intelligent multi-phase incident narrative."""
        phases = result.narrative_phases
        if not phases:
            return '<p class="dim">No narrative phases available.</p>'

        SEV_COLOR = {
            "critical": "var(--red)",
            "high":     "var(--orange)",
            "medium":   "var(--yellow)",
            "low":      "var(--green)",
            "info":     "var(--cyan)",
        }
        SEV_BG = {
            "critical": "rgba(239,68,68,.08)",
            "high":     "rgba(249,115,22,.07)",
            "medium":   "rgba(245,158,11,.07)",
            "low":      "rgba(16,185,129,.06)",
            "info":     "rgba(6,182,212,.06)",
        }
        SEV_BADGE_CLS = {
            "critical": "badge-red",
            "high":     "badge-yellow",
            "medium":   "badge-yellow",
            "low":      "badge-green",
            "info":     "badge-ok",
        }

        cards_html = ""
        for i, ph in enumerate(phases, 1):
            sev   = ph.get("severity","info")
            color = SEV_COLOR.get(sev,"var(--cyan)")
            bg    = SEV_BG.get(sev,"rgba(6,182,212,.06)")
            bcls  = SEV_BADGE_CLS.get(sev,"badge-ok")

            # Evidence list
            evidence = ph.get("evidence") or []
            ev_html = ""
            if evidence:
                items = "".join(
                    f'<li style="margin:.3rem 0;font-family:monospace;font-size:.78rem;">'
                    f'<span style="color:{color};">\u2022</span>&nbsp;{_e(ev)}</li>'
                    for ev in evidence
                )
                ev_html = (
                    f'<div style="margin-top:.9rem;">'
                    f'<div style="font-size:.72rem;color:var(--dim);text-transform:uppercase;'
                    f'letter-spacing:.06em;margin-bottom:.4rem;">Evidence</div>'
                    f'<ul style="list-style:none;padding:0;">{items}</ul></div>'
                )

            # MITRE tags
            mitre = ph.get("mitre") or []
            mitre_html = ""
            if mitre:
                tags = "".join(
                    f'<span style="display:inline-block;background:rgba(124,58,237,.2);'
                    f'color:var(--purple-lt);border-radius:4px;padding:.15rem .5rem;'
                    f'font-size:.72rem;margin:.2rem .2rem 0 0;">{_e(t)}</span>'
                    for t in mitre
                )
                mitre_html = (
                    f'<div style="margin-top:.7rem;">'
                    f'<span style="font-size:.7rem;color:var(--dim);">MITRE ATT&amp;CK: </span>'
                    f'{tags}</div>'
                )

            cards_html += f"""
<div style="border-left:3px solid {color};background:{bg};border-radius:0 var(--radius) var(--radius) 0;
  padding:1.1rem 1.4rem;margin-bottom:1.2rem;">
  <div style="display:flex;align-items:center;gap:.7rem;margin-bottom:.6rem;flex-wrap:wrap;">
    <span style="font-size:1.1rem;">{ph.get('icon','')}</span>
    <span style="color:var(--dim);font-size:.75rem;">Phase {i}/{len(phases)}</span>
    <span style="font-weight:700;color:var(--text);">{_e(ph.get('phase',''))}</span>
    <span class="badge {bcls}" style="font-size:.66rem;">{_e(sev.upper())}</span>
  </div>
  <div style="color:{color};font-weight:600;font-size:.88rem;margin-bottom:.5rem;">{_e(ph.get('title',''))}</div>
  <div style="color:var(--text);line-height:1.65;font-size:.85rem;">{_e(ph.get('text',''))}</div>
  {ev_html}
  {mitre_html}
</div>"""

        intro = (
            '<div style="color:var(--dim);font-size:.82rem;margin-bottom:1.4rem;">'
            'Automatic phase-by-phase reconstruction of the attack based on collected evidence. '
            'Phases are only shown when relevant data is present.</div>'
        )
        return (
            '<div class="section-header"><h2 class="section-title">&#128214; Incident Narrative</h2></div>'
            + intro
            + cards_html
        )

    # ------------------------------------------------------------------

    def _tab_process_tree(self, result: AnalysisResult) -> str:
        if not result.bundle.events:
            return "<p>No event data available.</p>"
        roots = ProcessTreeBuilder().build(result.bundle.events)
        if not roots:
            return "<p>No process tree data available.</p>"
        node_html = self._render_node_list(roots, counter=[0])
        return f"""
<div class="section-header">
  <div class="section-title">&#127795; Interactive Process Tree</div>
  <div class="section-actions">
    <button class="btn" onclick="expandAll()">&#11206; Expand All</button>
    <button class="btn" onclick="collapseAll()">&#11206; Collapse All</button>
  </div>
</div>
<p style="color:var(--dim);margin-bottom:14px;font-size:.79rem;">
  Click a process to expand/collapse. &nbsp;
  <span style="color:var(--red-lt);">&#128308; Red = malicious (processIsMalicious=True).</span>
  &nbsp;<span style="color:#fbbf24;">&#128992; Orange = related to threat (relatedToThreat=True).</span>
  &nbsp; Press <kbd style="background:var(--bg-card2);border:1px solid var(--border-lt);border-radius:3px;padding:1px 5px;font-size:.72rem;color:var(--cyan-lt);">1</kbd>&ndash;<kbd style="background:var(--bg-card2);border:1px solid var(--border-lt);border-radius:3px;padding:1px 5px;font-size:.72rem;color:var(--cyan-lt);">9</kbd> to jump between sections.
</p>
<div class="proc-tree">{node_html}</div>"""

    def _render_node_list(self, nodes: List[ProcessNode], counter: List[int]) -> str:
        return "\n".join(self._render_node(n, counter) for n in nodes)

    def _render_node(self, node: ProcessNode, counter: List[int]) -> str:
        counter[0] += 1
        nid = f"pn{counter[0]}"
        cid = f"pc{counter[0]}"

        mal_class   = (" malicious" if node.is_malicious
                        else " related" if node.related_to_threat
                        else "")
        icon        = "&#128308;" if node.is_malicious else "&#128992;" if node.related_to_threat else "&#9881;"
        has_ch      = bool(node.children)
        toggle_icon = "\u25be" if has_ch else "\u2022"
        toggle_fn   = f'onclick="toggleNode(\'{cid}\')"' if has_ch else ""

        ts_span  = f'<span class="node-time">[{_e(fmt_ts(node.start_time))}]</span>' if node.start_time else ""
        usr_span = f'<span class="node-user">&#128100; {_e(node.user)}</span>'         if node.user       else ""
        badge    = '<span class="node-badge">TRIGGER</span>'  if node.related_to_threat else ""
        mbadge   = '<span class="node-badge">MALICIOUS</span>' if node.is_malicious     else ""

        events_html = ""
        for i, evt in enumerate(sorted(node.events, key=lambda e: e.get("createdAt") or "")):
            if i >= 8:
                events_html += f'<div class="node-event dim">\u2026 +{len(node.events)-8} more events</div>'
                break
            lbl    = _e(event_label(evt))
            ts_e   = _e(fmt_ts(evt.get("createdAt") or ""))
            detail = _e((_event_detail(evt) or "")[:100])
            trig   = evt.get("relatedToThreat")
            ev_cls = "node-event trigger" if trig else "node-event"
            tmark  = ' <span class="trig-badge">TRIGGER</span>' if trig else ""
            events_html += f'<div class="{ev_cls}">{_e(event_icon(evt))} [{ts_e}] {lbl}: {detail}{tmark}</div>'

        cmd_html = f'<div class="node-cmd">$ {_e(node.cmd)}</div>' if node.cmd else ""
        children_html = (
            f'<div id="{cid}" class="node-children">{self._render_node_list(node.children, counter)}</div>'
            if has_ch else ""
        )

        return f"""<div class="proc-node{mal_class}" id="{nid}">
  <div class="node-header" {toggle_fn}>
    <span class="node-toggle">{toggle_icon}</span>
    <span class="node-icon">{icon}</span>
    <span class="node-name">{_e(node.display_name)}</span>
    {ts_span}{usr_span}{badge}{mbadge}
  </div>
  {cmd_html}
  <div class="node-events">{events_html}</div>
  {children_html}
</div>"""

    # ------------------------------------------------------------------
    # All events
    # ------------------------------------------------------------------

    def _tab_all_events(self, result: AnalysisResult) -> str:
        events = result.timeline_sorted[:1000]
        rows = ""
        for evt in events:
            trig    = evt.get("relatedToThreat")
            tr_cls  = ' class="trigger"' if trig else ""
            detail  = _e(_event_detail(evt) or "")
            trig_c  = '<span class="trig-badge">TRIGGER</span>' if trig else ""
            cmd     = evt.get("processCmd") or ""
            rows += (
                f"<tr{tr_cls}>"
                f'<td class="mono">{_e(fmt_ts(evt.get("createdAt")))}</td>'
                f'<td>{_e(evt.get("objectType") or "")}</td>'
                f'<td>{_e(event_label(evt))}</td>'
                f'<td class="mono">{_e(evt.get("processName") or "\u2014")}</td>'
                f"<td>{detail}</td>"
                f'<td class="mono dim">{_e(cmd[:80])}{_copy_btn(cmd) if cmd else ""}</td>'
                f"<td>{trig_c}</td>"
                f"</tr>"
            )
        total = len(result.bundle.events)
        trigger_count = sum(1 for e in events if e.get("relatedToThreat"))
        note  = (f'<div style="color:var(--dim);margin-top:7px;font-size:.78rem;">'
                 f'Showing first 1,000 of {total} events. See CSV for full export.</div>'
                 if total > 1000 else "")
        return f"""
<div class="section-header">
  <div class="section-title">&#128203; All Events</div>
  <div class="section-actions">
    <button class="btn" id="btn-trigger-toggle" onclick="toggleTriggerFilter(this)">
      &#9889; Triggers Only
      <span style="background:rgba(239,68,68,.14);color:var(--red-lt);border:1px solid rgba(239,68,68,.3);
                   border-radius:999px;padding:0 7px;font-size:.62rem;margin-left:3px;">{trigger_count}</span>
    </button>
    <span class="row-count" id="count-events">{len(events)} rows</span>
  </div>
</div>
<div class="search-bar">
  <input type="text" class="search-input" id="search-events" placeholder="Filter events\u2026"
         oninput="filterTable('search-events','tbl-events','count-events')">
</div>
<div class="tbl-wrap">
<table id="tbl-events">
<thead><tr>
  <th onclick="sortTable('tbl-events',0)">Timestamp \u21d5</th>
  <th onclick="sortTable('tbl-events',1)">Object \u21d5</th>
  <th onclick="sortTable('tbl-events',2)">Event Type \u21d5</th>
  <th onclick="sortTable('tbl-events',3)">Process \u21d5</th>
  <th>Detail</th><th>Command</th><th>Trigger</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>{note}"""

    # ------------------------------------------------------------------
    # Files
    # ------------------------------------------------------------------

    def _tab_files(self, result: AnalysisResult) -> str:
        keys   = result.threat_process_keys
        all_f  = result.categorized.file
        events = [e for e in all_f
                  if not keys or e.get("processUniqueKey") in keys
                  or e.get("relatedToThreat") or e.get("processIsMalicious")]
        noise  = len(all_f) - len(events)
        events = events[:500]
        rows   = ""
        for evt in sorted(events, key=lambda e: e.get("createdAt") or ""):
            trig   = evt.get("relatedToThreat")
            tr_cls = ' class="trigger"' if trig else ""
            trig_c = '<span class="trig-badge">TRIGGER</span>' if trig else ""
            old    = evt.get("oldFileName") or ""
            size   = evt.get("fileSize")
            size_s = f"{int(size):,} B" if size else "\u2014"
            sha1   = evt.get("fileSha1") or ""
            sha1_d = (sha1[:16] + "\u2026") if sha1 and sha1.strip("0") else "\u2014"
            path   = evt.get("fileFullName") or "\u2014"
            rows += (
                f"<tr{tr_cls}>"
                f'<td class="mono">{_e(fmt_ts(evt.get("createdAt")))}</td>'
                f"<td>{_e(event_label(evt))}</td>"
                f'<td class="mono">{_e(evt.get("processName") or "\u2014")}</td>'
                f'<td class="mono">{_e(path)}{_copy_btn(path) if path != "\u2014" else ""}</td>'
                f'<td class="mono dim">{_e(old) if old else "\u2014"}</td>'
                f'<td class="dim">{_e(size_s)}</td>'
                f'<td class="mono dim">{_e(sha1_d)}{_copy_btn(sha1) if sha1 and sha1.strip("0") else ""}</td>'
                f"<td>{trig_c}</td>"
                f"</tr>"
            )
        noise_note = (f' <span style="color:var(--dim);font-size:.76rem;">({noise} unrelated filtered)</span>'
                      if noise else "")
        return f"""
<div class="section-header">
  <div class="section-title">&#128196; File Activity ({len(all_f)} total \u2014 {len(events)} from threat processes{noise_note})</div>
  <span class="row-count" id="count-files">{len(events)} rows</span>
</div>
<div class="search-bar">
  <input type="text" class="search-input" id="search-files" placeholder="Filter by path, process\u2026"
         oninput="filterTable('search-files','tbl-files','count-files')">
</div>
<div class="tbl-wrap">
<table id="tbl-files">
<thead><tr>
  <th onclick="sortTable('tbl-files',0)">Timestamp \u21d5</th>
  <th onclick="sortTable('tbl-files',1)">Operation \u21d5</th>
  <th onclick="sortTable('tbl-files',2)">Process \u21d5</th>
  <th>File Path</th><th>Old Name</th><th>Size</th><th>SHA1</th><th>Trigger</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def _tab_registry(self, result: AnalysisResult) -> str:
        keys   = result.threat_process_keys
        all_r  = result.categorized.registry
        events = [e for e in all_r
                  if not keys or e.get("processUniqueKey") in keys
                  or e.get("relatedToThreat") or e.get("processIsMalicious")]
        noise  = len(all_r) - len(events)
        events = events[:300]
        rows   = ""
        for evt in sorted(events, key=lambda e: e.get("createdAt") or ""):
            trig   = evt.get("relatedToThreat")
            tr_cls = ' class="trigger"' if trig else ""
            trig_c = '<span class="trig-badge">TRIGGER</span>' if trig else ""
            rpath  = evt.get("registryPath") or "\u2014"
            rows += (
                f"<tr{tr_cls}>"
                f'<td class="mono">{_e(fmt_ts(evt.get("createdAt")))}</td>'
                f"<td>{_e(event_label(evt))}</td>"
                f'<td class="mono">{_e(evt.get("processName") or "\u2014")}</td>'
                f'<td class="mono">{_e(rpath)}{_copy_btn(rpath) if rpath != "\u2014" else ""}</td>'
                f'<td class="dim">{_e(evt.get("registryValue") or evt.get("registryNewValue") or "\u2014")}</td>'
                f'<td class="mono dim">{_e(evt.get("registryData") or "\u2014")}</td>'
                f"<td>{trig_c}</td>"
                f"</tr>"
            )
        noise_note = (f' <span style="color:var(--dim);font-size:.76rem;">({noise} unrelated filtered)</span>'
                      if noise else "")
        return f"""
<div class="section-header">
  <div class="section-title">&#128273; Registry Activity ({len(all_r)} total \u2014 {len(events)} from threat processes{noise_note})</div>
  <span class="row-count" id="count-reg">{len(events)} rows</span>
</div>
<div class="search-bar">
  <input type="text" class="search-input" id="search-reg" placeholder="Filter registry keys\u2026"
         oninput="filterTable('search-reg','tbl-reg','count-reg')">
</div>
<div class="tbl-wrap">
<table id="tbl-reg">
<thead><tr>
  <th onclick="sortTable('tbl-reg',0)">Timestamp \u21d5</th>
  <th onclick="sortTable('tbl-reg',1)">Operation \u21d5</th>
  <th onclick="sortTable('tbl-reg',2)">Process \u21d5</th>
  <th>Registry Key</th><th>Value Name</th><th>Data</th><th>Trigger</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def _tab_network(self, result: AnalysisResult) -> str:
        keys   = result.threat_process_keys
        all_n  = result.categorized.network + result.categorized.dns
        events = [e for e in all_n
                  if not keys or e.get("processUniqueKey") in keys
                  or e.get("relatedToThreat") or e.get("processIsMalicious")]
        noise  = len(all_n) - len(events)
        events = sorted(events, key=lambda e: e.get("createdAt") or "")[:300]
        rows   = ""
        for evt in events:
            trig   = evt.get("relatedToThreat")
            tr_cls = ' class="trigger"' if trig else ""
            trig_c = '<span class="trig-badge">TRIGGER</span>' if trig else ""
            dip    = evt.get("dstIp") or ""
            dns    = evt.get("dnsRequest") or evt.get("networkUrl") or ""
            rows += (
                f"<tr{tr_cls}>"
                f'<td class="mono">{_e(fmt_ts(evt.get("createdAt")))}</td>'
                f"<td>{_e(event_label(evt))}</td>"
                f'<td class="dim">{_e(evt.get("netConnDirection") or "")}</td>'
                f'<td class="mono">{_e(evt.get("processName") or "\u2014")}</td>'
                f'<td class="mono dim">{_e(evt.get("srcIp") or "\u2014")}</td>'
                f'<td class="mono">{_e(dip)}{_copy_btn(dip) if dip else ""}</td>'
                f'<td>{_e(str(evt.get("dstPort") or ""))}</td>'
                f'<td class="dim">{_e(evt.get("protocol") or "\u2014")}</td>'
                f'<td>{_e(dns)}{_copy_btn(dns) if dns else ""}</td>'
                f"<td>{trig_c}</td>"
                f"</tr>"
            )
        noise_note = (f' <span style="color:var(--dim);font-size:.76rem;">({noise} unrelated filtered)</span>'
                      if noise else "")
        return f"""
<div class="section-header">
  <div class="section-title">&#127760; Network Activity ({len(all_n)} total \u2014 {len(events)} from threat processes{noise_note})</div>
  <span class="row-count" id="count-net">{len(events)} rows</span>
</div>
<div class="search-bar">
  <input type="text" class="search-input" id="search-net" placeholder="Filter by IP, domain, process\u2026"
         oninput="filterTable('search-net','tbl-net','count-net')">
</div>
<div class="tbl-wrap">
<table id="tbl-net">
<thead><tr>
  <th onclick="sortTable('tbl-net',0)">Timestamp \u21d5</th>
  <th onclick="sortTable('tbl-net',1)">Type \u21d5</th>
  <th>Dir</th>
  <th onclick="sortTable('tbl-net',3)">Process \u21d5</th>
  <th>Src IP</th>
  <th onclick="sortTable('tbl-net',5)">Dst IP \u21d5</th>
  <th>Port</th><th>Proto</th><th>DNS / URL</th><th>Trigger</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_login(evt: dict, threat_process_keys: set) -> str:
        """Return 'fail', 'susp', or '' for a login event."""
        evt_type = (evt.get("eventType") or "").upper()
        if "FAIL" in evt_type or "DENIED" in evt_type:
            return "fail"
        username   = (evt.get("loginsUserName") or evt.get("user") or "").lower()
        login_type = (evt.get("loginsBaseType") or "").upper()
        proc_key   = evt.get("processUniqueKey") or ""
        if (
            "admin" in username
            or (login_type == "INTERACTIVE" and proc_key in threat_process_keys)
            or login_type in ("NETWORK", "BATCH", "SERVICE")
        ):
            return "susp"
        return ""

    def _tab_login(self, result: AnalysisResult) -> str:
        events = sorted(result.categorized.login, key=lambda e: e.get("createdAt") or "")
        if not events:
            return '<div class="alert alert-green">No login events recorded in this storyline.</div>'

        threat_keys = result.threat_process_keys or set()
        fail_count  = 0
        susp_count  = 0
        rows = ""
        for evt in events:
            cls = self._classify_login(evt, threat_keys)
            if cls == "fail":   fail_count += 1
            elif cls == "susp": susp_count += 1
            tr_cls   = f' class="login-{cls}"' if cls else ""
            flag_html = (
                '<span class="login-badge-fail">FAILED</span>'    if cls == "fail" else
                '<span class="login-badge-susp">SUSPICIOUS</span>' if cls == "susp" else ""
            )
            username = evt.get("loginsUserName") or evt.get("user") or "\u2014"
            rows += (
                f"<tr{tr_cls}>"
                f'<td class="mono">{_e(fmt_ts(evt.get("createdAt")))}</td>'
                f"<td>{_e(event_label(evt))}</td>"
                f'<td class="mono">{_e(username)}{_copy_btn(username) if username != "\u2014" else ""}</td>'
                f'<td>{_e(evt.get("loginsBaseType") or "\u2014")}</td>'
                f'<td class="mono">{_e(evt.get("processName") or "\u2014")}</td>'
                f'<td class="mono dim">{_e((evt.get("processCmd") or "")[:80])}</td>'
                f"<td>{flag_html}</td>"
                f"</tr>"
            )

        alert_html = ""
        if fail_count or susp_count:
            alert_html = '<div class="alert alert-yellow"><strong>&#9888; Login Anomalies Detected</strong>&nbsp;&nbsp;'
            if fail_count:
                alert_html += f'<span class="login-badge-fail">{fail_count} FAILED</span>&nbsp;'
            if susp_count:
                alert_html += f'<span class="login-badge-susp">{susp_count} SUSPICIOUS</span>'
            alert_html += "</div>"

        return f"""
{alert_html}
<div class="section-header">
  <div class="section-title">&#128100; Login &amp; Account Activity ({len(events)} events)</div>
  <span class="row-count" id="count-login">{len(events)} rows</span>
</div>
<div class="search-bar">
  <input type="text" class="search-input" id="search-login" placeholder="Filter by user, type, process\u2026"
         oninput="filterTable('search-login','tbl-login','count-login')">
</div>
<div class="tbl-wrap">
<table id="tbl-login">
<thead><tr>
  <th onclick="sortTable('tbl-login',0)">Timestamp \u21d5</th>
  <th onclick="sortTable('tbl-login',1)">Type \u21d5</th>
  <th onclick="sortTable('tbl-login',2)">Username \u21d5</th>
  <th onclick="sortTable('tbl-login',3)">Login Type \u21d5</th>
  <th>Process</th><th>Command</th><th>Flag</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def _tab_iocs(self, result: AnalysisResult) -> str:
        parts = []

        if result.encryption_indicators:
            items = "".join(
                f'<li style="margin-bottom:5px;"><strong>{_e(i["reason"])}</strong></li>'
                for i in result.encryption_indicators
            )
            parts.append(
                f'<div class="section-header"><div class="section-title">&#9888;&#65039; Ransomware / Encryption Indicators</div></div>'
                f'<div class="alert alert-red"><ul style="padding-left:18px;">{items}</ul></div>'
            )

        if result.network_iocs:
            pills = "".join(
                f'<span style="display:inline-flex;align-items:center;margin-bottom:4px;">'
                f'<span class="ioc-pill" onclick="copyText(this.dataset.v)" data-v="{_e(i["value"])}" title="Click to copy">'
                f'<span class="ioc-type-lbl">{_e(i["type"])}</span>'
                f'<span>{_e(i["value"])}</span>'
                f'</span>'
                f'{_vt_link(i["value"])}'
                f'</span>'
                for i in result.network_iocs[:100]
            )
            parts.append(
                f'<div class="section-header">'
                f'<div class="section-title">&#127760; Network IOCs ({len(result.network_iocs)})</div>'
                f'<div class="section-actions">'
                f'<button class="btn" onclick="copyAll(\'net-ioc-list\')">&#128203; Copy All</button>'
                f'</div></div>'
                f'<div class="ioc-list" id="net-ioc-list">{pills}</div>'
            )

        if result.file_iocs:
            rows_ioc  = ""
            shown     = 0
            for i in result.file_iocs:
                if shown >= 100:
                    break
                val = i["value"]
                if not val.strip("0"):
                    continue
                fname = i.get("event", {}).get("fileFullName") or "\u2014"
                rows_ioc += (
                    f'<tr>'
                    f'<td class="dim">{_e(i["type"])}</td>'
                    f'<td class="mono" style="color:var(--yellow-lt);">{_e(val)}{_copy_btn(val)}</td>'
                    f'<td class="mono dim">{_e(fname)}{_copy_btn(fname) if fname != "\u2014" else ""}</td>'
                    f'<td style="white-space:nowrap;">{_vt_link(val)}</td>'
                    f'</tr>'
                )
                shown += 1
            parts.append(
                f'<div class="section-header">'
                f'<div class="section-title">&#128196; File Hash IOCs ({shown} shown)</div>'
                f'</div>'
                f'<div class="tbl-wrap"><table>'
                f'<thead><tr><th>Type</th><th>Hash</th><th>File Path</th><th>Links</th></tr></thead>'
                f'<tbody>{rows_ioc}</tbody></table></div>'
            )

        if result.suspicious_registry:
            rows = "".join(
                f'<tr>'
                f'<td class="mono">{_e(fmt_ts(e.get("createdAt")))}</td>'
                f'<td class="mono" style="color:var(--yellow-lt);">'
                f'{_e(e.get("registryPath") or e.get("registryKeyPath") or "\u2014")}'
                f'{_copy_btn(e.get("registryPath") or e.get("registryKeyPath") or "")}</td>'
                f'<td class="mono">{_e(e.get("processName") or "\u2014")}</td>'
                f'</tr>'
                for e in result.suspicious_registry[:50]
            )
            parts.append(
                f'<div class="section-header">'
                f'<div class="section-title">&#128273; Suspicious Registry Keys ({len(result.suspicious_registry)})</div>'
                f'</div>'
                f'<div class="tbl-wrap"><table>'
                f'<thead><tr><th>Timestamp</th><th>Registry Path</th><th>Process</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>'
            )

        return "\n".join(parts) if parts else '<div class="alert alert-green">No IOCs identified.</div>'

    # ------------------------------------------------------------------
    # Scheduled Tasks
    # ------------------------------------------------------------------

    def _tab_scheduled_tasks(self, result: AnalysisResult) -> str:
        events = sorted(result.categorized.scheduled_task, key=lambda e: e.get("createdAt") or "")
        if not events:
            return '<div class="alert alert-green">No scheduled task events recorded in this storyline.</div>'

        rows = ""
        for evt in events:
            trig   = evt.get("relatedToThreat")
            tr_cls = ' class="trigger"' if trig else ""
            trig_c = '<span class="trig-badge">TRIGGER</span>' if trig else ""
            tname  = evt.get("taskName") or "\u2014"
            tpath  = evt.get("taskPath") or "\u2014"
            rows += (
                f"<tr{tr_cls}>"
                f'<td class="mono">{_e(fmt_ts(evt.get("createdAt")))}</td>'
                f"<td>{_e(event_label(evt))}</td>"
                f'<td class="mono">{_e(evt.get("processName") or "\u2014")}</td>'
                f'<td class="mono" style="color:var(--yellow-lt);">'
                f'{_e(tname)}{_copy_btn(tname) if tname != "\u2014" else ""}</td>'
                f'<td class="mono dim">'
                f'{_e(tpath)}{_copy_btn(tpath) if tpath != "\u2014" else ""}</td>'
                f"<td>{trig_c}</td>"
                f"</tr>"
            )

        alert_html = ""
        trig_count = sum(1 for e in events if e.get("relatedToThreat"))
        if trig_count:
            alert_html = (
                f'<div class="alert alert-yellow">'
                f'<strong>&#9888; {trig_count} task event(s) related to threat</strong>'
                f' \u2014 review these scheduled tasks for persistence mechanisms.</div>'
            )

        return f"""
{alert_html}
<div class="section-header">
  <div class="section-title">&#9200; Scheduled Tasks ({len(events)} events)</div>
  <span class="row-count" id="count-tasks">{len(events)} rows</span>
</div>
<div class="search-bar">
  <input type="text" class="search-input" id="search-tasks" placeholder="Filter by task name, process\u2026"
         oninput="filterTable('search-tasks','tbl-tasks','count-tasks')">
</div>
<div class="tbl-wrap">
<table id="tbl-tasks">
<thead><tr>
  <th onclick="sortTable('tbl-tasks',0)">Timestamp \u21d5</th>
  <th onclick="sortTable('tbl-tasks',1)">Operation \u21d5</th>
  <th onclick="sortTable('tbl-tasks',2)">Process \u21d5</th>
  <th>Task Name</th><th>Task Path</th><th>Trigger</th>
</tr></thead>
<tbody>{rows}</tbody>
</table></div>"""

    # ------------------------------------------------------------------
    # MITRE
    # ------------------------------------------------------------------

    def _tab_mitre(self, result: AnalysisResult) -> str:
        techniques = result.mitre_techniques
        if not techniques:
            return '<div class="alert alert-green">No MITRE ATT&CK techniques identified.</div>'

        tactic_groups: Dict[str, List[Dict]] = {}
        for t in techniques:
            tact = t.get("tactic") or "Other"
            tactic_groups.setdefault(tact, []).append(t)

        sections = ""
        for tact_name in sorted(tactic_groups.keys()):
            group = tactic_groups[tact_name]
            cards = ""
            for t in group:
                link     = t.get("link") or ""
                tech_name = _e(t.get("technique") or "\u2014")
                link_html = (f'<a href="{_e(link)}" target="_blank" rel="noopener">{tech_name}</a>'
                             if link else tech_name)
                desc      = _e(t.get("description") or "")
                t_evts    = t.get("events") or []
                ev_html   = ""
                if t_evts:
                    items = ""
                    for e in sorted(t_evts, key=lambda x: x.get("createdAt") or "")[:3]:
                        items += (
                            f'<li style="font-size:.71rem;color:var(--dim);margin-bottom:2px;">'
                            f'[{_e(fmt_ts(e.get("createdAt") or ""))}] {_e(event_label(e))}: {_e(e.get("processName") or "")}</li>'
                        )
                    if len(t_evts) > 3:
                        items += f'<li style="font-size:.71rem;color:var(--dim);">+{len(t_evts)-3} more</li>'
                    ev_html = f'<ul style="margin-top:6px;padding-left:13px;list-style:disc;">{items}</ul>'
                cards += (
                    f'<div class="mitre-card">'
                    f'<div class="technique">{link_html}</div>'
                    f'<div class="desc">{desc}</div>'
                    f'{ev_html}</div>'
                )
            sections += (
                f'<div class="mitre-section">'
                f'<div class="mitre-tactic-header">'
                f'{_e(tact_name)}'
                f'<span class="tactic-count">{len(group)} technique{"s" if len(group)!=1 else ""}</span>'
                f'</div>'
                f'<div class="mitre-grid">{cards}</div>'
                f'</div>'
            )

        return f"""
<div class="section-header">
  <div class="section-title">&#9876; MITRE ATT&amp;CK ({len(techniques)} unique techniques)</div>
</div>
{sections}"""
