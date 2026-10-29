"""
Tk GUI for the HVAC Network Scanner.

A thin wrapper over the shared ScanEngine, so the CLI and GUI produce
identical results from the same inputs. Standard library only: ttk with a
custom dark theme, no third-party widgets.

Threading: the scan runs on a worker thread and never touches Tk. Everything
it reports — log lines, finished devices, progress — goes onto a queue that
the Tk thread drains every 100 ms (`_pump`). Until v2.7 each log line was a
separate `root.after(0, ...)` call made from the worker thread, which Tk does
not promise to tolerate, and which on a large deep scan meant thousands of
individual redraws of the log.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from typing import Any, Optional

from . import __version__
from . import settings as settings_mod
from .engine import ScanEngine, ScanOptions


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
class Colors:
    BG_DARK      = "#0d1117"
    BG_PANEL     = "#161b22"
    BG_CARD      = "#1c2333"
    BG_ROW_ALT   = "#202938"
    BG_INPUT     = "#21262d"
    BORDER       = "#30363d"
    TEXT         = "#e6edf3"
    TEXT_DIM     = "#8b949e"
    ACCENT       = "#58a6ff"
    ACCENT_HOVER = "#79c0ff"
    ACCENT_DEEP  = "#1f6feb"
    GREEN        = "#3fb950"
    YELLOW       = "#d29922"
    RED          = "#f85149"
    ORANGE       = "#db6d28"
    PURPLE       = "#bc8cff"
    CYAN         = "#39c5cf"
    TEAL         = "#2ea043"


# What each protocol is drawn in, wherever it is named.
PROTOCOL_COLORS = {
    'BACnet': Colors.GREEN, 'MS/TP': Colors.CYAN, 'Modbus': Colors.YELLOW,
    'Services': Colors.ORANGE, 'SNMP': Colors.PURPLE, 'Points': Colors.ACCENT,
}

# Settings the GUI remembers between runs (see settings.py).
_ADVANCED_DEFAULTS = {
    'timeout': "5", 'rate_limit': "0", 'whois_chunk': "0", 'workers': "4",
    'unicast': "auto", 'bbmd': "", 'broadcast': "", 'max_objects': "",
    'communities': "public",
}

_LOG_MAX_LINES = 20000
_HEADING = re.compile(r"[A-Z][A-Z /]{6,}")      # BACNET/IP DISCOVERY, not "SNMP:  1"


def _pick_font(candidates: list[str], fallback: str) -> str:
    try:
        families = set(tkfont.families())
    except tk.TclError:
        return fallback
    for name in candidates:
        if name in families:
            return name
    return tkfont.nametofont(fallback).actual('family')


class HVACNetworkScannerGUI:
    def __init__(self, root: "tk.Tk | tk.Toplevel",
                 settings_path: "Path | None" = None):
        self.root = root
        self.root.title(f"HVAC Network Scanner {__version__}")
        # Fit smaller laptop screens (leave room for the taskbar).
        w = min(1480, self.root.winfo_screenwidth() - 40)
        h = min(920, self.root.winfo_screenheight() - 90)
        self.root.geometry(f"{w}x{h}+20+20")
        self.root.configure(bg=Colors.BG_DARK)
        self.root.minsize(1100, 680)

        self.settings_path = settings_path
        self.result = None
        self._streamed: set[int] = set()
        self._streamed_points = 0
        self.scan_running = False
        self.stop_event = threading.Event()
        self._events: "queue.Queue[tuple[str, Any]]" = queue.Queue()
        self._sort_state: dict[str, tuple[str, bool]] = {}
        self._rows: dict[str, list[str]] = {}          # tree -> every row, in order
        self._shown: dict[str, int] = {}               # tree -> rows currently visible
        self._row_tags: dict[str, tuple] = {}           # iid -> tags besides striping
        self._flagged_points = 0
        self._dev_by_iid: dict[str, dict] = {}
        self._raw_dirty = False
        self._filter_after: Optional[str] = None
        self._pump_id: Optional[str] = None
        self._live_counts = {k: 0 for k in ('bacnet', 'mstp', 'modbus', 'services', 'snmp')}

        self.ui_font = _pick_font(["Segoe UI", "SF Pro Text", "Cantarell", "DejaVu Sans"],
                                  "TkDefaultFont")
        self.mono_font = _pick_font(["Cascadia Mono", "Consolas", "SF Mono", "DejaVu Sans Mono"],
                                    "TkFixedFont")

        self._set_icon()
        self._setup_styles()
        self._build_ui()
        self._bind_keys()
        self._apply_settings(settings_mod.load(settings_path))

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.bind("<Destroy>", self._on_destroy, add="+")
        self._pump_id = self.root.after(100, self._pump)

    # -- styling ----------------------------------------------------------

    def _set_icon(self) -> None:
        try:
            from .icon import png_bytes
            self._icons = [tk.PhotoImage(data=base64.b64encode(png_bytes(n)))
                           for n in (64, 32, 16)]
            self.root.iconphoto(True, *self._icons)
        except (tk.TclError, ImportError):
            self._icons = []

    def _f(self, size: int = 10, weight: str = "normal", mono: bool = False):
        return (self.mono_font if mono else self.ui_font, size, weight)

    def _setup_styles(self) -> None:
        C = Colors
        style = ttk.Style(self.root)
        style.theme_use('clam')
        row_h = tkfont.Font(root=self.root, font=self._f(10)).metrics('linespace') + 10

        style.configure(".", background=C.BG_DARK, foreground=C.TEXT,
                        fieldbackground=C.BG_INPUT, bordercolor=C.BORDER,
                        lightcolor=C.BORDER, darkcolor=C.BORDER, troughcolor=C.BG_PANEL,
                        focuscolor=C.ACCENT, selectbackground=C.ACCENT_DEEP,
                        selectforeground=C.TEXT, insertcolor=C.TEXT, font=self._f(10))
        style.configure("Dark.TFrame", background=C.BG_DARK)
        style.configure("Card.TFrame", background=C.BG_PANEL)
        style.configure("Title.TLabel", background=C.BG_DARK, foreground=C.TEXT,
                        font=self._f(17, "bold"))
        style.configure("Version.TLabel", background=C.BG_DARK, foreground=C.TEXT_DIM,
                        font=self._f(10))
        style.configure("Header.TLabel", background=C.BG_PANEL, foreground=C.TEXT,
                        font=self._f(10, "bold"))
        style.configure("Info.TLabel", background=C.BG_PANEL, foreground=C.TEXT,
                        font=self._f(10))
        style.configure("Dim.TLabel", background=C.BG_PANEL, foreground=C.TEXT_DIM,
                        font=self._f(9))
        style.configure("DarkDim.TLabel", background=C.BG_DARK, foreground=C.TEXT_DIM,
                        font=self._f(9))
        style.configure("Status.TLabel", background=C.BG_DARK, foreground=C.GREEN,
                        font=self._f(10, "bold"))

        # Buttons
        for name, bg, fg, active in (
                ("Accent", C.ACCENT, "#0b1220", C.ACCENT_HOVER),
                ("Danger", C.RED, "#0b1220", "#ff7b72"),
                ("Ghost", C.BG_INPUT, C.TEXT, C.BORDER)):
            style.configure(f"{name}.TButton", background=bg, foreground=fg,
                            bordercolor=bg if name != "Ghost" else C.BORDER,
                            lightcolor=bg, darkcolor=bg, focusthickness=0,
                            font=self._f(10, "bold" if name != "Ghost" else "normal"),
                            padding=(16, 6))
            style.map(f"{name}.TButton",
                      background=[("disabled", C.BG_PANEL), ("pressed", active), ("active", active)],
                      foreground=[("disabled", C.TEXT_DIM)],
                      bordercolor=[("disabled", C.BORDER)],
                      lightcolor=[("disabled", C.BG_PANEL), ("active", active)],
                      darkcolor=[("disabled", C.BG_PANEL), ("active", active)])
        style.configure("Ghost.TMenubutton", background=C.BG_INPUT, foreground=C.TEXT,
                        bordercolor=C.BORDER, lightcolor=C.BG_INPUT, darkcolor=C.BG_INPUT,
                        arrowcolor=C.TEXT_DIM, padding=(14, 6), font=self._f(10))
        style.map("Ghost.TMenubutton",
                  background=[("disabled", C.BG_PANEL), ("active", C.BORDER)],
                  foreground=[("disabled", C.TEXT_DIM)])
        style.configure("Link.TButton", background=C.BG_PANEL, foreground=C.ACCENT,
                        bordercolor=C.BG_PANEL, lightcolor=C.BG_PANEL, darkcolor=C.BG_PANEL,
                        padding=(6, 2), font=self._f(9))
        style.map("Link.TButton", foreground=[("active", C.ACCENT_HOVER)],
                  background=[("active", C.BG_PANEL)])

        # Inputs
        style.configure("TEntry", fieldbackground=C.BG_INPUT, foreground=C.TEXT,
                        bordercolor=C.BORDER, lightcolor=C.BG_INPUT, darkcolor=C.BG_INPUT,
                        insertcolor=C.TEXT, padding=(6, 4))
        style.map("TEntry", bordercolor=[("focus", C.ACCENT)],
                  lightcolor=[("focus", C.ACCENT)])
        style.configure("Error.TEntry", fieldbackground="#3a1d1d", bordercolor=C.RED)
        style.configure("TCheckbutton", background=C.BG_PANEL, foreground=C.TEXT,
                        indicatorbackground=C.BG_INPUT, indicatorforeground=C.ACCENT,
                        indicatorrelief="flat", focuscolor=C.BG_PANEL, font=self._f(10))
        style.map("TCheckbutton",
                  background=[("active", C.BG_PANEL)],
                  foreground=[("disabled", C.TEXT_DIM)],
                  indicatorbackground=[("selected", C.ACCENT_DEEP), ("active", C.BORDER)],
                  indicatorforeground=[("selected", "#ffffff")])
        style.configure("TCombobox", fieldbackground=C.BG_INPUT, background=C.BG_INPUT,
                        foreground=C.TEXT, arrowcolor=C.TEXT_DIM, bordercolor=C.BORDER,
                        lightcolor=C.BG_INPUT, darkcolor=C.BG_INPUT, padding=(6, 3))
        style.map("TCombobox", fieldbackground=[("readonly", C.BG_INPUT)],
                  foreground=[("readonly", C.TEXT)], bordercolor=[("focus", C.ACCENT)],
                  selectbackground=[("readonly", C.BG_INPUT)],
                  selectforeground=[("readonly", C.TEXT)])
        self.root.option_add("*TCombobox*Listbox.background", C.BG_INPUT)
        self.root.option_add("*TCombobox*Listbox.foreground", C.TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", C.ACCENT_DEEP)
        self.root.option_add("*TCombobox*Listbox.font", self._f(10))

        # Tables
        style.configure("Treeview", background=C.BG_CARD, foreground=C.TEXT,
                        fieldbackground=C.BG_CARD, rowheight=row_h, borderwidth=0,
                        font=self._f(10))
        style.configure("Treeview.Heading", background=C.BG_PANEL, foreground=C.TEXT_DIM,
                        relief="flat", borderwidth=0, padding=(6, 6), font=self._f(9, "bold"))
        style.map("Treeview.Heading", background=[("active", C.BG_INPUT)],
                  foreground=[("active", C.TEXT)])
        style.map("Treeview", background=[("selected", C.ACCENT_DEEP)],
                  foreground=[("selected", "#ffffff")])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        style.configure("TNotebook", background=C.BG_DARK, borderwidth=0,
                        tabmargins=(0, 4, 0, 0))
        style.configure("TNotebook.Tab", background=C.BG_DARK, foreground=C.TEXT_DIM,
                        padding=(16, 7), borderwidth=0, font=self._f(10))
        style.map("TNotebook.Tab",
                  background=[("selected", C.BG_CARD), ("active", C.BG_PANEL)],
                  foreground=[("selected", C.TEXT), ("active", C.TEXT)],
                  lightcolor=[("selected", C.ACCENT)])

        style.configure("TScrollbar", background=C.BG_INPUT, troughcolor=C.BG_CARD,
                        bordercolor=C.BG_CARD, arrowcolor=C.TEXT_DIM,
                        lightcolor=C.BG_INPUT, darkcolor=C.BG_INPUT, gripcount=0)
        style.map("TScrollbar", background=[("active", C.BORDER)])
        style.configure("Horizontal.TProgressbar", troughcolor=C.BG_INPUT,
                        background=C.ACCENT, bordercolor=C.BG_PANEL,
                        lightcolor=C.ACCENT, darkcolor=C.ACCENT, thickness=6)
        style.configure("TPanedwindow", background=C.BG_DARK)
        style.configure("Sash", sashthickness=6, gripcount=0, background=C.BG_DARK)

    # -- layout -----------------------------------------------------------

    def _build_ui(self) -> None:
        C = Colors
        # Header
        hdr = ttk.Frame(self.root, style="Dark.TFrame")
        hdr.pack(fill=tk.X, padx=18, pady=(14, 6))
        if self._icons:
            tk.Label(hdr, image=self._icons[1], bg=C.BG_DARK).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(hdr, text="HVAC Network Scanner", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(hdr, text=f"v{__version__}   BACnet/IP · MS/TP · Modbus TCP · "
                            f"services · SNMP",
                  style="Version.TLabel").pack(side=tk.LEFT, padx=(12, 0), pady=(6, 0))
        ttk.Button(hdr, text="About", style="Ghost.TButton",
                   command=self._show_about).pack(side=tk.RIGHT)
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(hdr, textvariable=self.status_var, style="Status.TLabel")
        self.status_label.pack(side=tk.RIGHT, padx=(0, 16))

        # Controls card
        cfg = ttk.Frame(self.root, style="Card.TFrame")
        cfg.pack(fill=tk.X, padx=18, pady=(2, 6))

        row1 = ttk.Frame(cfg, style="Card.TFrame")
        row1.pack(fill=tk.X, padx=14, pady=(12, 0))
        ttk.Label(row1, text="Targets", style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 10))
        self.scan_btn = ttk.Button(row1, text="▶  Scan", style="Accent.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side=tk.RIGHT, padx=(6, 0))
        self.stop_btn = ttk.Button(row1, text="■  Stop", style="Danger.TButton",
                                   command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side=tk.RIGHT, padx=(6, 0))
        self.network_entry = ttk.Entry(row1, font=self._f(11, mono=True))
        self.network_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.network_entry.insert(0, "192.168.1.0/24")
        self.network_entry.bind("<Key>", lambda _e: self.network_entry.configure(style="TEntry"))

        hint = ttk.Frame(cfg, style="Card.TFrame")
        hint.pack(fill=tk.X, padx=14, pady=(3, 0))
        ttk.Label(hint, text="CIDR, host, or range — mix freely, comma-separated:   "
                             "10.0.0.0/24   10.0.0.5   10.0.0.2-100   10.0.0.2-10.0.0.12",
                  style="Dim.TLabel").pack(side=tk.LEFT, padx=(64, 0))

        row2 = ttk.Frame(cfg, style="Card.TFrame")
        row2.pack(fill=tk.X, padx=14, pady=(8, 10))

        self.scan_bacnet    = tk.BooleanVar(value=True)
        self.scan_mstp      = tk.BooleanVar(value=True)
        self.scan_modbus    = tk.BooleanVar(value=True)
        self.scan_services  = tk.BooleanVar(value=False)  # v2.1.1: default off (TVs/printers flood)
        self.scan_snmp      = tk.BooleanVar(value=True)
        self.deep_scan      = tk.BooleanVar(value=True)
        self.use_rpm        = tk.BooleanVar(value=True)

        ttk.Label(row2, text="Protocols", style="Header.TLabel").pack(side=tk.LEFT, padx=(0, 8))
        self.mstp_cb = None
        for text, var in [("BACnet/IP", self.scan_bacnet), ("MS/TP", self.scan_mstp),
                          ("Modbus TCP", self.scan_modbus), ("Services", self.scan_services),
                          ("SNMP", self.scan_snmp)]:
            cb = ttk.Checkbutton(row2, text=text, variable=var)
            cb.pack(side=tk.LEFT, padx=(4, 10))
            if text == "MS/TP":
                self.mstp_cb = cb

        # MS/TP discovery lives inside the BACnet pass; it does nothing without it.
        def _update_mstp_enabled(*_args):
            self.mstp_cb.state(['!disabled'] if self.scan_bacnet.get() else ['disabled'])
        self.scan_bacnet.trace_add('write', _update_mstp_enabled)
        _update_mstp_enabled()

        ttk.Label(row2, text="Depth", style="Header.TLabel").pack(side=tk.LEFT, padx=(18, 6))
        self.scan_depth_var = tk.StringVar(value="normal")
        ttk.Combobox(row2, textvariable=self.scan_depth_var, width=8, state="readonly",
                     values=["quick", "normal", "full"]).pack(side=tk.LEFT)

        self.adv_btn = ttk.Button(row2, text="Advanced ▾", style="Link.TButton",
                                  command=self._toggle_advanced)
        self.adv_btn.pack(side=tk.LEFT, padx=(14, 0))

        self.compare_btn = ttk.Button(row2, text="Compare…", style="Ghost.TButton",
                                      command=self.compare_to_baseline, state='disabled')
        self.compare_btn.pack(side=tk.RIGHT, padx=(6, 0))
        self.export_btn = ttk.Menubutton(row2, text="Export", style="Ghost.TMenubutton",
                                         state='disabled')
        export_menu = self._menu(self.export_btn)
        export_menu.add_command(label="Survey report (HTML)…", command=lambda: self._export('html'))
        export_menu.add_separator()
        export_menu.add_command(label="Devices (CSV)…", command=lambda: self._export('csv'))
        export_menu.add_command(label="Point list (CSV)…", command=lambda: self._export('points'))
        export_menu.add_command(label="Full results (JSON)…", command=lambda: self._export('json'))
        export_menu.add_separator()
        export_menu.add_command(label="Classification report (TXT)…",
                                command=lambda: self._export('txt'))
        self.export_btn['menu'] = export_menu
        self.export_btn.pack(side=tk.RIGHT, padx=(6, 0))

        self._build_advanced(cfg)

        # Summary chips + progress
        summary = ttk.Frame(self.root, style="Dark.TFrame")
        summary.pack(fill=tk.X, padx=18, pady=(0, 4))
        self.chips: dict[str, tk.Label] = {}
        for key, label in (('bacnet', 'BACnet'), ('mstp', 'MS/TP'), ('modbus', 'Modbus'),
                           ('services', 'Services'), ('snmp', 'SNMP'), ('points', 'Points'),
                           ('flagged', 'Flagged')):
            chip = tk.Label(summary, text=f"{label}  –", bg=C.BG_PANEL,
                            fg=PROTOCOL_COLORS.get(label, C.YELLOW), padx=12, pady=4,
                            font=self._f(9, "bold"))
            chip.pack(side=tk.LEFT, padx=(0, 6))
            self.chips[key] = chip
        self.progress_label = ttk.Label(summary, text="", style="DarkDim.TLabel")
        self.progress_label.pack(side=tk.RIGHT)
        self.progress = ttk.Progressbar(summary, mode="determinate", length=260,
                                        style="Horizontal.TProgressbar")
        self.progress.pack(side=tk.RIGHT, padx=(0, 10))

        # Results and log
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=18, pady=(4, 4))

        top_frame = ttk.Frame(paned, style="Dark.TFrame")
        paned.add(top_frame, weight=4)

        filt = ttk.Frame(top_frame, style="Dark.TFrame")
        filt.pack(fill=tk.X, pady=(0, 4))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(filt, textvariable=self.filter_var, width=40)
        self.filter_entry.pack(side=tk.RIGHT)
        ttk.Label(filt, text="Filter  (Ctrl+F)", style="DarkDim.TLabel").pack(side=tk.RIGHT, padx=(0, 8))
        self.filter_count = ttk.Label(filt, text="", style="DarkDim.TLabel")
        self.filter_count.pack(side=tk.LEFT)
        self.filter_var.trace_add('write', lambda *_a: self._schedule_filter())

        self.notebook = ttk.Notebook(top_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self._build_devices_tab()
        self._build_points_tab()
        self._build_registers_tab()
        self._build_services_tab()
        self._build_raw_tab()

        bot_frame = ttk.Frame(paned, style="Card.TFrame")
        paned.add(bot_frame, weight=1)
        log_header = ttk.Frame(bot_frame, style="Card.TFrame")
        log_header.pack(fill=tk.X)
        ttk.Label(log_header, text="Scan log", style="Header.TLabel").pack(side=tk.LEFT, padx=10, pady=5)
        for text, cmd in (("Clear", self._clear_log), ("Copy", self._copy_log),
                          ("Save…", self._save_log)):
            ttk.Button(log_header, text=text, style="Link.TButton",
                       command=cmd).pack(side=tk.RIGHT, padx=(0, 4))
        log_body = ttk.Frame(bot_frame, style="Card.TFrame")
        log_body.pack(fill=tk.BOTH, expand=True)
        self.log_text = tk.Text(log_body, bg=C.BG_CARD, fg=C.TEXT_DIM,
                                font=self._f(9, mono=True), insertbackground=C.TEXT,
                                height=9, padx=10, pady=6, relief=tk.FLAT,
                                highlightthickness=0, wrap=tk.NONE, state='disabled')
        log_scroll = ttk.Scrollbar(log_body, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        for tag, color in (("error", C.RED), ("success", C.GREEN), ("warn", C.YELLOW),
                           ("info", C.ACCENT), ("plain", C.TEXT)):
            self.log_text.tag_configure(tag, foreground=color)
        self.log_text.tag_configure("heading", foreground=C.ACCENT, font=self._f(9, "bold", mono=True))

        sbar = ttk.Frame(self.root, style="Dark.TFrame")
        sbar.pack(fill=tk.X, padx=18, pady=(0, 10))
        self.stats_var = tk.StringVar(value="No scan performed yet")
        ttk.Label(sbar, textvariable=self.stats_var, style="DarkDim.TLabel").pack(side=tk.LEFT)
        ttk.Label(sbar, text="Ctrl+Enter scan · Esc stop · Ctrl+F filter · Ctrl+S save JSON",
                  style="DarkDim.TLabel").pack(side=tk.RIGHT)

        self.log_message(f"HVAC Network Scanner v{__version__}")
        self.log_message("  Enter the network(s) to scan above and press Scan (Ctrl+Enter).")
        self.log_message("  Only scan networks you own or are authorized to assess.")
        self.log_message("")

    def _build_advanced(self, parent) -> None:
        """Advanced settings, folded away until asked for."""
        self.adv_frame = ttk.Frame(parent, style="Card.TFrame")
        self.adv_vars: dict[str, tk.StringVar] = {
            k: tk.StringVar(value=v) for k, v in _ADVANCED_DEFAULTS.items()}

        def field(row, col, label, key, width=8, tip="", combo=None):
            ttk.Label(self.adv_frame, text=label, style="Info.TLabel").grid(
                row=row, column=col * 3, sticky="e", padx=(14 if col else 0, 6), pady=4)
            if combo:
                w = ttk.Combobox(self.adv_frame, textvariable=self.adv_vars[key],
                                 values=combo, width=width, state="readonly")
            else:
                w = ttk.Entry(self.adv_frame, textvariable=self.adv_vars[key], width=width,
                              font=self._f(10, mono=True))
            w.grid(row=row, column=col * 3 + 1, sticky="w", pady=4)
            if tip:
                ttk.Label(self.adv_frame, text=tip, style="Dim.TLabel").grid(
                    row=row, column=col * 3 + 2, sticky="w", padx=(6, 0))
            return w

        self.timeout_entry = field(0, 0, "Timeout (s)", 'timeout', tip="per request")
        self.rate_limit_entry = field(0, 1, "Rate limit (ms)", 'rate_limit',
                                      tip="between packets to one device")
        self.workers_entry = field(0, 2, "Parallel devices", 'workers', width=5,
                                   tip="deep scans at once")
        field(1, 0, "Unicast discovery", 'unicast', combo=["auto", "always", "off"],
              tip="for other subnets")
        self.whois_chunk_entry = field(1, 1, "Who-Is chunk", 'whois_chunk',
                                       tip="0 = one broadcast")
        field(1, 2, "Max objects", 'max_objects', width=7, tip="per device, blank = profile")
        field(2, 0, "BBMD", 'bbmd', width=16, tip="register as foreign device")
        field(2, 1, "Broadcast", 'broadcast', width=16, tip="blank = automatic")
        field(2, 2, "SNMP communities", 'communities', width=16, tip="comma-separated")
        chk = ttk.Frame(self.adv_frame, style="Card.TFrame")
        chk.grid(row=3, column=0, columnspan=9, sticky="w", pady=(4, 0))
        ttk.Checkbutton(chk, text="Deep scan (read points and registers)",
                        variable=self.deep_scan).pack(side=tk.LEFT, padx=(0, 18))
        ttk.Checkbutton(chk, text="ReadPropertyMultiple",
                        variable=self.use_rpm).pack(side=tk.LEFT)
        self._adv_open = False

    def _toggle_advanced(self, show: Optional[bool] = None) -> None:
        self._adv_open = (not self._adv_open) if show is None else show
        if self._adv_open:
            self.adv_frame.pack(fill=tk.X, padx=14, pady=(0, 12))
            self.adv_btn.configure(text="Advanced ▴")
        else:
            self.adv_frame.pack_forget()
            self.adv_btn.configure(text="Advanced ▾")

    def _menu(self, parent) -> tk.Menu:
        return tk.Menu(parent, tearoff=0, bg=Colors.BG_PANEL, fg=Colors.TEXT,
                       activebackground=Colors.ACCENT_DEEP, activeforeground="#ffffff",
                       relief=tk.FLAT, bd=1, font=self._f(10))

    def _make_tree(self, parent, name: str, columns) -> ttk.Treeview:
        frame = ttk.Frame(parent, style="Dark.TFrame")
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree = ttk.Treeview(frame, columns=[c for c, _t, _w in columns],
                            show="headings", selectmode="extended")
        for col, text, width in columns:
            self._setup_sortable(tree, col, text)
            tree.column(col, width=width, minwidth=40, stretch=(col == columns[-1][0]))
        ys = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        xs.pack(side=tk.BOTTOM, fill=tk.X)
        ys.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree.tag_configure("alt", background=Colors.BG_ROW_ALT)
        tree._hvac_name = name                       # type: ignore[attr-defined]
        self._rows[name] = []
        self._shown[name] = 0
        tree.bind("<Control-c>", lambda _e, t=tree: self._copy_rows(t))
        tree.bind("<Control-a>", lambda _e, t=tree: t.selection_set(t.get_children()))
        return tree

    def _build_devices_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(tab, text="Devices")
        split = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        split.pack(fill=tk.BOTH, expand=True)
        left = ttk.Frame(split, style="Dark.TFrame")
        split.add(left, weight=4)
        self.device_tree = self._make_tree(left, "devices", [
            ("protocol", "Protocol", 100), ("ip", "IP Address", 115),
            ("address", "Device ID", 165), ("name", "Name", 150),
            ("model", "Model", 190), ("vendor", "Vendor", 160),
            ("device_type", "Type", 140), ("web_url", "Web UI", 140),
            ("default_creds", "Default Creds", 170), ("description", "Description", 300),
        ])
        self.device_tree.bind("<<TreeviewSelect>>", lambda _e: self._show_selected_details())
        self.device_tree.bind("<Double-1>", self._on_device_double_click)
        self.device_tree.bind("<Button-3>", self._on_device_right_click)
        self.device_tree.bind("<Return>", self._on_device_double_click)

        right = ttk.Frame(split, style="Card.TFrame")
        split.add(right, weight=0)          # keeps its natural width
        ttk.Label(right, text="Device details", style="Header.TLabel").pack(anchor="w", padx=12, pady=(10, 4))
        btns = ttk.Frame(right, style="Card.TFrame")
        btns.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=8)
        btns.columnconfigure((0, 1), weight=1, uniform="b")
        for i, (text, cmd) in enumerate((("Web UI", self._ctx_open_web),
                                         ("Show points", self._ctx_show_points),
                                         ("Copy IP", self._ctx_copy_ip),
                                         ("Ping", self._ctx_ping))):
            ttk.Button(btns, text=text, style="Ghost.TButton", command=cmd).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=2, pady=2)
        self.details_text = tk.Text(right, bg=Colors.BG_PANEL, fg=Colors.TEXT, wrap=tk.WORD,
                                    font=self._f(9, mono=True), relief=tk.FLAT, width=46,
                                    highlightthickness=0, padx=12, pady=4, state='disabled')
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.tag_configure("h", foreground=Colors.ACCENT, font=self._f(9, "bold", mono=True))
        self.details_text.tag_configure("k", foreground=Colors.TEXT_DIM)
        self.details_text.tag_configure("creds", foreground=Colors.YELLOW)
        # Continuation lines of a wrapped value line up under the value.
        self.details_text.tag_configure("v", lmargin2=tkfont.Font(
            root=self.root, font=self._f(9, mono=True)).measure("x" * 15))
        self._set_details(None)

        self.ctx_menu = self._menu(self.root)
        self.ctx_menu.add_command(label="Open Web UI", command=self._ctx_open_web)
        self.ctx_menu.add_command(label="Open Web UI (HTTP)",
                                  command=lambda: self._ctx_open_web(force_http=True))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Show points", command=self._ctx_show_points)
        self.ctx_menu.add_command(label="Copy IP Address", command=self._ctx_copy_ip)
        self.ctx_menu.add_command(label="Copy Default Credentials", command=self._ctx_copy_creds)
        self.ctx_menu.add_command(label="Copy row(s)", command=lambda: self._copy_rows(self.device_tree))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Ping Device", command=self._ctx_ping)

    def _build_points_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(tab, text="BACnet Points")
        self.points_tree = self._make_tree(tab, "points", [
            ("device", "Device", 170), ("type", "Object Type", 140),
            ("address", "Instance", 80), ("name", "Name", 300),
            ("value", "Present Value", 120), ("units", "Units", 80),
            ("status", "Status", 150), ("description", "Description", 320),
        ])
        # Points needing attention stand out: alarm and fault in red,
        # overridden and out of service in amber.
        self.points_tree.tag_configure("alarm", foreground=Colors.RED)
        self.points_tree.tag_configure("flag", foreground=Colors.YELLOW)
        # Double-click a point for its full name / description / value.
        self.points_tree.bind("<Double-Button-1>", self._on_point_double_click)
        self.points_menu = self._menu(self.root)
        self.points_menu.add_command(label="Copy row(s)", command=lambda: self._copy_rows(self.points_tree))
        self.points_menu.add_command(label="Show details", command=lambda: self._on_point_double_click(None))
        self.points_tree.bind("<Button-3>", lambda e: self._popup_for(self.points_tree, self.points_menu, e))

    def _on_point_double_click(self, _event) -> None:
        sel = self.points_tree.selection()
        if not sel:
            return
        vals = self.points_tree.item(sel[0]).get('values', [])
        if len(vals) < 8:
            return
        device, obj_type, instance, name, value, units, status, description = vals

        popup = tk.Toplevel(self.root)
        popup.title(f"Point — {obj_type} {instance}")
        popup.configure(bg=Colors.BG_DARK)
        popup.geometry("680x400")
        popup.transient(self.root)

        for label, val in [("Device", device), ("Object Type", obj_type),
                           ("Instance", instance), ("Name", name),
                           ("Present Value", f"{value} {units}".strip()),
                           ("Status", status or "normal"),
                           ("Description", description)]:
            row = tk.Frame(popup, bg=Colors.BG_DARK)
            row.pack(fill=tk.X, padx=14, pady=4)
            tk.Label(row, text=label, bg=Colors.BG_DARK, fg=Colors.TEXT_DIM,
                     font=self._f(9, "bold"), width=14, anchor='nw').pack(side=tk.LEFT)
            # A read-only Text so long values wrap and can be selected and copied
            txt = tk.Text(row, bg=Colors.BG_INPUT, fg=Colors.TEXT,
                          font=self._f(10), height=2, wrap=tk.WORD,
                          relief=tk.FLAT, highlightthickness=0, padx=6, pady=3)
            txt.insert("1.0", str(val))
            txt.configure(state='disabled')
            txt.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(popup, text="Close", style="Ghost.TButton",
                   command=popup.destroy).pack(pady=10)
        popup.bind("<Escape>", lambda _e: popup.destroy())

    def _build_registers_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(tab, text="Modbus Registers")
        self.reg_tree = self._make_tree(tab, "registers", [
            ("device", "Device", 180), ("reg_type", "Register Type", 130),
            ("address", "Address", 80), ("value_dec", "Value (Dec)", 100),
            ("value_hex", "Value (Hex)", 100), ("value_bin", "Value (Bin)", 200),
        ])

    def _build_services_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(tab, text="Services")
        self.svc_tree = self._make_tree(tab, "services", [
            ("ip", "IP Address", 120), ("port", "Port", 60),
            ("service", "Service", 140), ("vendor", "Vendor", 160),
            ("product", "Product", 170), ("title", "Page Title", 220),
            ("tls", "TLS Certificate", 260), ("banner", "Banner", 320),
        ])

    def _build_raw_tab(self) -> None:
        tab = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(tab, text="Raw JSON")
        self._raw_tab = tab
        self.raw_text = tk.Text(tab, bg=Colors.BG_CARD, fg=Colors.TEXT,
                                font=self._f(9, mono=True), insertbackground=Colors.TEXT,
                                wrap=tk.NONE, padx=10, pady=8, relief=tk.FLAT,
                                highlightthickness=0)
        raw_hscroll = ttk.Scrollbar(tab, orient="horizontal", command=self.raw_text.xview)
        raw_vscroll = ttk.Scrollbar(tab, orient="vertical", command=self.raw_text.yview)
        self.raw_text.configure(xscrollcommand=raw_hscroll.set, yscrollcommand=raw_vscroll.set)
        raw_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        raw_vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.raw_text.pack(fill=tk.BOTH, expand=True)

    def _bind_keys(self) -> None:
        r = self.root
        r.bind("<Control-Return>", lambda _e: self.start_scan())
        r.bind("<F5>", lambda _e: self.start_scan())
        r.bind("<Escape>", lambda _e: self.stop_scan() if self.scan_running else None)
        r.bind("<Control-f>", lambda _e: (self.filter_entry.focus_set(),
                                          self.filter_entry.select_range(0, tk.END)))
        r.bind("<Control-s>", lambda _e: self._export('json'))
        self.network_entry.bind("<Return>", lambda _e: self.start_scan())

    # -- rows, sorting and filtering -------------------------------------

    def _insert(self, tree: ttk.Treeview, values, tags: tuple = ()) -> str:
        name = tree._hvac_name                       # type: ignore[attr-defined]
        iid = tree.insert("", tk.END, values=values, tags=tags)
        self._rows[name].append(iid)
        if tags:
            self._row_tags[iid] = tuple(tags)
        terms = self._filter_terms()
        if terms and not self._matches(values, terms):
            tree.detach(iid)
        else:
            if self._shown[name] % 2:
                tree.item(iid, tags=tuple(tags) + ("alt",))
            self._shown[name] += 1
        return iid

    def _clear_tree(self, tree: ttk.Treeview) -> None:
        name = tree._hvac_name                       # type: ignore[attr-defined]
        tree.delete(*self._rows[name])
        for iid in self._rows[name]:
            self._row_tags.pop(iid, None)
        self._rows[name] = []
        self._shown[name] = 0
        self._sort_state.pop(name, None)

    def _setup_sortable(self, tree: ttk.Treeview, col: str, display_name: str) -> None:
        tree.heading(col, text=display_name, anchor="w",
                     command=lambda: self._sort_treeview(tree, col))
        tree.column(col, anchor="w")

    @staticmethod
    def _sort_key(val):
        # IP addresses sort numerically by octet, numbers numerically, text
        # case-insensitively.
        if isinstance(val, str) and val.count(".") == 3 and all(p.isdigit() for p in val.split(".")):
            return (0, tuple(int(p) for p in val.split(".")), "")
        try:
            return (1, (float(str(val).split()[0]),), "")
        except (ValueError, TypeError, IndexError):
            return (2, (), str(val).lower())

    def _sort_treeview(self, tree: ttk.Treeview, col: str) -> None:
        name = tree._hvac_name                       # type: ignore[attr-defined]
        prev_col, prev_reverse = self._sort_state.get(name, (None, False))
        reverse = not prev_reverse if prev_col == col else False
        self._sort_state[name] = (col, reverse)

        rows = self._rows[name]
        rows.sort(key=lambda iid: self._sort_key(tree.set(iid, col)), reverse=reverse)
        self._apply_filter_to(tree)

        arrow = " ▼" if reverse else " ▲"
        for c in tree["columns"]:
            clean = tree.heading(c, "text").rstrip(" ▲▼")
            tree.heading(c, text=clean + arrow if c == col else clean)

    def _filter_terms(self) -> list[str]:
        return self.filter_var.get().lower().split()

    @staticmethod
    def _matches(values, terms: list[str]) -> bool:
        hay = " ".join(str(v) for v in values).lower()
        return all(t in hay for t in terms)

    def _current_tree(self) -> Optional[ttk.Treeview]:
        try:
            idx = self.notebook.index(self.notebook.select())
        except tk.TclError:
            return None
        return [self.device_tree, self.points_tree, self.reg_tree, self.svc_tree, None][idx]

    def _schedule_filter(self) -> None:
        if self._filter_after:
            self.root.after_cancel(self._filter_after)
        self._filter_after = self.root.after(180, self._apply_filter)

    def _apply_filter(self) -> None:
        self._filter_after = None
        for tree in (self.device_tree, self.points_tree, self.reg_tree, self.svc_tree):
            self._apply_filter_to(tree)

    def _apply_filter_to(self, tree: ttk.Treeview) -> None:
        name = tree._hvac_name                       # type: ignore[attr-defined]
        terms = self._filter_terms()
        shown = 0
        for iid in self._rows[name]:
            if not terms or self._matches(tree.item(iid, 'values'), terms):
                tree.move(iid, "", shown)
                tree.item(iid, tags=self._row_tags.get(iid, ()) + (("alt",) if shown % 2 else ()))
                shown += 1
            else:
                tree.detach(iid)
        self._shown[name] = shown
        self._update_filter_count()

    def _update_filter_count(self) -> None:
        tree = self._current_tree()
        if tree is None:
            self.filter_count.configure(text="")
            return
        total = len(self._rows[tree._hvac_name])     # type: ignore[attr-defined]
        shown = len(tree.get_children())
        text = f"{shown:,} row(s)" if shown == total else f"showing {shown:,} of {total:,}"
        self.filter_count.configure(text=text)

    def _on_tab_changed(self, _event=None) -> None:
        try:
            if self.notebook.select() == str(self._raw_tab) and self._raw_dirty:
                self._fill_raw()
        except tk.TclError:
            return
        self._update_filter_count()

    def _copy_rows(self, tree: ttk.Treeview) -> str:
        sel = tree.selection()
        if not sel:
            return "break"
        heads = [tree.heading(c, "text").rstrip(" ▲▼") for c in tree["columns"]]
        lines = ["\t".join(heads)] + ["\t".join(str(v) for v in tree.item(i, 'values'))
                                      for i in sel]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self._set_status(f"Copied {len(sel)} row(s)", Colors.TEXT_DIM)
        return "break"

    def _popup_for(self, tree: ttk.Treeview, menu: tk.Menu, event) -> None:
        iid = tree.identify_row(event.y)
        if iid:
            if iid not in tree.selection():
                tree.selection_set(iid)
            menu.post(event.x_root, event.y_root)

    # -- logging ----------------------------------------------------------

    def log_message(self, msg: str) -> None:
        """Queue a log line. Safe from any thread."""
        self._events.put(('log', msg))

    @staticmethod
    def _log_tag(msg: str) -> Optional[str]:
        low = msg.lower()
        stripped = msg.strip()
        if stripped.startswith("====") or _HEADING.fullmatch(stripped):
            return "heading"
        if "error" in low or "traceback" in low:
            return "error"
        if "[!]" in msg or "failed" in low or "could not" in low:
            return "warn"
        if (stripped.startswith(("Found", "Discovered", "Identified", "Scan complete",
                                 "Read ", "Unicast discovery found"))
                or "points from device" in low):
            return "success"
        if stripped.startswith(("Scanning", "Broadcasting", "Probing", "Deep-scanning",
                                "BACnet/IP scan", "Modbus scan", "Service scan", "SNMP scan")):
            return "info"
        if stripped.startswith(("Device ", "HVAC Network Scanner")):
            return "plain"
        return None

    def _write_log(self, lines: list[str]) -> None:
        t = self.log_text
        at_end = t.yview()[1] >= 0.999
        t.configure(state='normal')
        for line in lines:
            t.insert(tk.END, line + "\n", self._log_tag(line))
        excess = int(t.index('end-1c').split('.')[0]) - _LOG_MAX_LINES
        if excess > 0:
            t.delete("1.0", f"{excess + 1}.0")
        t.configure(state='disabled')
        if at_end:
            t.see(tk.END)

    def _clear_log(self) -> None:
        self.log_text.configure(state='normal')
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state='disabled')

    def _copy_log(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get("1.0", tk.END))
        self._set_status("Log copied", Colors.TEXT_DIM)

    def _save_log(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".log", filetypes=[("Log", "*.log"), ("Text", "*.txt")],
            initialfile=f"hvac_scan_{datetime.now():%Y%m%d_%H%M%S}.log")
        if path:
            try:
                Path(path).write_text(self.log_text.get("1.0", tk.END), encoding='utf-8')
            except OSError as e:
                messagebox.showerror("Save log", str(e))

    # -- the event pump -----------------------------------------------------

    def _pump(self) -> None:
        """Drain the worker's queue on the Tk thread, batching log output."""
        self._pump_id = None
        lines: list[str] = []
        progress = None
        done = None
        try:
            for _ in range(5000):
                kind, payload = self._events.get_nowait()
                if kind == 'log':
                    lines.append(payload)
                elif kind == 'device':
                    if lines:
                        self._write_log(lines)
                        lines = []
                    self._stream_device(payload)
                elif kind == 'progress':
                    progress = payload
                elif kind == 'done':
                    done = payload
                    break
        except queue.Empty:
            pass
        try:
            if lines:
                self._write_log(lines)
            if progress:
                self._show_progress(*progress)
            if done is not None:
                self._scan_finished(*done)
            self._pump_id = self.root.after(100, self._pump)
        except tk.TclError:
            return                                   # window is gone

    def _on_destroy(self, event) -> None:
        if event.widget is self.root and self._pump_id:
            try:
                self.root.after_cancel(self._pump_id)
            except tk.TclError:
                pass
            self._pump_id = None

    def _show_progress(self, phase: str, done: int, total: int) -> None:
        if total > 0:
            if str(self.progress['mode']) != 'determinate':
                self.progress.stop()
                self.progress.configure(mode='determinate')
            self.progress.configure(maximum=total, value=min(done, total))
            self.progress_label.configure(text=f"{phase}  {done:,} / {total:,}")
        else:
            if str(self.progress['mode']) != 'indeterminate':
                self.progress.configure(mode='indeterminate')
                self.progress.start(12)
            self.progress_label.configure(text=phase)

    def _set_status(self, text: str, color: str) -> None:
        self.status_var.set(text)
        ttk.Style(self.root).configure("Status.TLabel", foreground=color)

    # -- scan control -----------------------------------------------------

    def start_scan(self) -> None:
        if self.scan_running:
            return
        self.stop_event = threading.Event()
        # Rows arrive during the scan, so remember which devices have already
        # been drawn and how much has landed.
        self._streamed: set[int] = set()
        self._streamed_points = 0

        opts = self._build_options()
        if opts is None:
            return

        self.scan_running = True
        self.result = None
        self.scan_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.export_btn.configure(state='disabled')
        self.compare_btn.configure(state='disabled')
        self._set_status("Scanning…", Colors.ACCENT)
        self._live_counts = {k: 0 for k in self._live_counts}
        self._flagged_points = 0
        self._update_chips()

        for tree in (self.device_tree, self.points_tree, self.reg_tree, self.svc_tree):
            self._clear_tree(tree)
        self._dev_by_iid.clear()
        self._set_details(None)
        self.raw_text.delete("1.0", tk.END)
        self._raw_dirty = False
        self._show_progress("Starting", 0, 0)
        self.log_message("")
        self.log_message(f"Scan started {datetime.now():%Y-%m-%d %H:%M:%S}: "
                         f"{', '.join(opts.networks)}")
        self._save_settings()

        threading.Thread(target=self._run_scan, args=(opts,), daemon=True,
                         name="hvac-scan").start()

    def stop_scan(self) -> None:
        if not self.scan_running:
            return
        self.stop_event.set()
        self.stop_btn.configure(state='disabled')
        self._set_status("Stopping…", Colors.YELLOW)
        self.log_message("Scan stop requested — finishing the current step…")

    def _read_number(self, entry, label: str, default, cast, minimum=None):
        """Read a numeric entry field, falling back to `default` on junk input.

        Previously the timeout field was parsed with a bare float(), so a typo
        raised out of _run_scan and the user got a traceback in the log instead
        of a scan. The chunk field was guarded and the timeout field was not.
        """
        raw = (entry.get() or "").strip()
        if not raw:
            return default
        try:
            value = cast(raw)
        except (TypeError, ValueError):
            self.log_message(f"  [!] {label} {raw!r} is not a number — using {default}")
            return default
        if minimum is not None and value < minimum:
            self.log_message(f"  [!] {label} {value} is below {minimum} — using {default}")
            return default
        return value

    def _build_options(self) -> Optional[ScanOptions]:
        """ScanOptions from the controls, or None (with the reason shown) if a
        field is unusable. Nothing is sent until every field checks out."""
        from .netrange import parse_targets, InvalidTargetSyntaxError

        networks = [n.strip() for n in self.network_entry.get().split(",") if n.strip()]
        if not networks:
            return self._reject("Enter at least one target network.", self.network_entry)
        for n in networks:
            try:
                if not parse_targets(n):
                    raise InvalidTargetSyntaxError("no addresses")
            except InvalidTargetSyntaxError as e:
                return self._reject(f"Invalid target {n!r}: {e}", self.network_entry)

        def ip_or_none(key: str, label: str):
            raw = self.adv_vars[key].get().strip()
            if not raw:
                return None
            try:
                ipaddress.IPv4Address(raw)
            except ValueError:
                self._toggle_advanced(True)
                raise ValueError(f"{label} {raw!r} is not an IPv4 address")
            return raw

        try:
            bbmd = ip_or_none('bbmd', "BBMD")
            broadcast = ip_or_none('broadcast', "Broadcast")
        except ValueError as e:
            return self._reject(str(e))

        max_objects = self._read_number(self.adv_vars['max_objects'], "Max objects",
                                        None, int, minimum=1)
        communities = [c.strip() for c in self.adv_vars['communities'].get().split(",")
                       if c.strip()] or ["public"]
        return ScanOptions(
            networks=networks,
            timeout=self._read_number(self.timeout_entry, "Timeout", 5.0, float, minimum=0.1),
            scan_bacnet=self.scan_bacnet.get(),
            scan_mstp=self.scan_mstp.get(),
            scan_modbus=self.scan_modbus.get(),
            scan_services=self.scan_services.get(),
            scan_snmp=self.scan_snmp.get(),
            deep_scan=self.deep_scan.get(),
            use_rpm=self.use_rpm.get(),
            whois_chunk_size=self._read_number(self.whois_chunk_entry, "Who-Is chunk", 0,
                                               int, minimum=0),
            rate_limit_ms=self._read_number(self.rate_limit_entry, "Rate limit", 0, int,
                                            minimum=0),
            scan_depth=self.scan_depth_var.get(),
            bacnet_workers=self._read_number(self.workers_entry, "Parallel devices", 4,
                                             int, minimum=1),
            unicast_discovery=self.adv_vars['unicast'].get() or "auto",
            bbmd=bbmd,
            bacnet_broadcast=broadcast,
            max_objects_per_device=max_objects,
            snmp_communities=communities,
        )

    def _reject(self, reason: str, widget=None) -> None:
        self.log_message(f"  [!] {reason}")
        self._set_status(reason if len(reason) < 60 else "Check the settings", Colors.RED)
        if widget is not None:
            widget.configure(style="Error.TEntry")
            widget.focus_set()
        return None

    def _run_scan(self, opts: ScanOptions) -> None:
        """Worker thread: run the engine, report everything through the queue."""
        result, error = None, None
        try:
            engine = ScanEngine(
                opts,
                callback=self.log_message,
                stop_event=self.stop_event,
                device_callback=self._on_device_found,
                progress_callback=lambda p, d, t: self._events.put(('progress', (p, d, t))),
            )
            result = engine.run()
        except Exception as e:                       # pragma: no cover - defensive
            import traceback
            error = str(e)
            self.log_message(f"Scan error: {e}")
            self.log_message(traceback.format_exc())
        self._events.put(('done', (result, error)))

    def _scan_finished(self, result, error) -> None:
        self.scan_running = False
        self.result = result
        self.progress.stop()
        self.progress.configure(mode='determinate', maximum=1, value=1 if result else 0)
        self.scan_btn.configure(state='normal')
        self.stop_btn.configure(state='disabled')
        has_devices = bool(result and result.devices)
        self.export_btn.configure(state='normal' if has_devices else 'disabled')
        self.compare_btn.configure(state='normal' if has_devices else 'disabled')
        if result:
            self._populate_results()
        if error:
            self._set_status("Scan failed — see the log", Colors.RED)
            self.progress_label.configure(text="")
        elif self.stop_event.is_set():
            self._set_status("Stopped — partial results", Colors.YELLOW)
            self.progress_label.configure(text="Stopped")
        else:
            n = len({d.get('ip') for d in result.devices if d.get('ip')}) if result else 0
            self._set_status(f"Scan complete — {n} host(s)", Colors.GREEN)
            self.progress_label.configure(
                text=f"Done in {result.elapsed:.1f}s" if result else "")
            try:
                self.root.bell()
            except tk.TclError:
                pass

    # -- baseline comparison ------------------------------------------------

    def compare_to_baseline(self) -> None:
        """Compare the scan just finished against a saved JSON export.

        The CLI has --baseline for scheduled runs; this is the same comparison
        for someone working interactively, so the feature does not require
        dropping to a terminal to be useful.
        """
        if not self.result or not self.result.devices:
            messagebox.showinfo("Compare", "Run a scan first.")
            return

        path = filedialog.askopenfilename(
            title="Select a previous scan (JSON) to compare against",
            filetypes=[("Scan JSON", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return

        from . import diff as diffmod
        try:
            baseline = diffmod.load_scan(path)
        except (OSError, ValueError) as e:
            messagebox.showerror("Compare", f"Could not read {path}:\n{e}")
            return

        d = diffmod.diff_scans(baseline, self.result.to_dict())
        self._show_diff_window(d, path)

    def _show_diff_window(self, d, baseline_path: str) -> None:
        from . import diff as diffmod

        win = tk.Toplevel(self.root)
        win.title("Baseline comparison")
        win.geometry("940x620")
        win.configure(bg=Colors.BG_DARK)
        win.transient(self.root)

        header = ttk.Frame(win, style="Card.TFrame")
        header.pack(fill=tk.X, padx=12, pady=(12, 6))
        for text, n, color in (("new", len(d.added), Colors.GREEN),
                               ("not responding", len(d.removed), Colors.RED),
                               ("changed", len(d.changed), Colors.YELLOW),
                               ("unchanged", d.unchanged, Colors.TEXT_DIM)):
            tk.Label(header, text=f"{n} {text}", bg=Colors.BG_PANEL, fg=color,
                     font=self._f(10, "bold"), padx=10, pady=6).pack(side=tk.LEFT)
        ttk.Label(header, text=f"vs {baseline_path}", style="Dim.TLabel").pack(side=tk.LEFT, padx=8)

        text = tk.Text(win, bg=Colors.BG_PANEL, fg=Colors.TEXT, wrap="none",
                       font=self._f(10, mono=True), relief=tk.FLAT, highlightthickness=0,
                       padx=10, pady=8)
        ysb = ttk.Scrollbar(win, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=ysb.set)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 6))
        for line in diffmod.format_text(d).splitlines():
            tag = ("added" if line.lstrip().startswith("+ ") else
                   "removed" if line.lstrip().startswith("- ") else
                   "changed" if line.lstrip().startswith("~ ") else None)
            text.insert(tk.END, line + "\n", tag)
        text.tag_configure("added", foreground=Colors.GREEN)
        text.tag_configure("removed", foreground=Colors.RED)
        text.tag_configure("changed", foreground=Colors.YELLOW)
        text.configure(state="disabled")

        btns = ttk.Frame(win, style="Dark.TFrame")
        btns.pack(fill=tk.X, padx=12, pady=(0, 12))

        def _save_report():
            out = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text report", "*.txt"), ("JSON", "*.json")])
            if not out:
                return
            try:
                if out.lower().endswith(".json"):
                    diffmod.write_json(d, out)
                else:
                    diffmod.write_text(d, out)
                self.log_message(f"Wrote comparison report: {out}")
            except OSError as e:
                messagebox.showerror("Compare", f"Could not write {out}:\n{e}")

        def _save_baseline():
            out = filedialog.asksaveasfilename(
                defaultextension=".json", filetypes=[("Scan JSON", "*.json")])
            if not out:
                return
            try:
                self.result.write_json(out)
                self.log_message(f"Saved this scan as baseline: {out}")
            except OSError as e:
                messagebox.showerror("Compare", f"Could not write {out}:\n{e}")

        ttk.Button(btns, text="Save report…", style="Ghost.TButton",
                   command=_save_report).pack(side=tk.LEFT)
        ttk.Button(btns, text="Save this scan as new baseline…", style="Ghost.TButton",
                   command=_save_baseline).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Close", style="Ghost.TButton",
                   command=win.destroy).pack(side=tk.RIGHT)
        win.bind("<Escape>", lambda _e: win.destroy())

    # -- live results ------------------------------------------------------

    def _on_device_found(self, dev: dict) -> None:
        """Called from the scan thread as each device finishes. Queued for the
        Tk thread; nothing here touches a widget."""
        self._events.put(('device', dev))

    def _stream_device(self, dev: dict) -> None:
        """Draw one finished device. Runs on the Tk thread.

        Service rows go to the Services tab now but wait for the final pass
        before joining the device list: deduplicating them against the
        primary device rows needs the whole result set, and a host that
        answers on BACnet should not also appear as four separate service
        rows.
        """
        key = id(dev)
        if key in self._streamed:
            return
        self._streamed.add(key)
        proto = dev.get('protocol')

        try:
            if proto == 'Service':
                self._add_service_row(dev)
                self._live_counts['services'] += 1
            else:
                self._add_device_to_tree(dev)
                self._streamed_points += self._add_points_for(dev)
                self._add_registers_for(dev)
                bucket = {'BACnet/IP': 'bacnet', 'BACnet/MSTP': 'mstp',
                          'Modbus TCP': 'modbus', 'SNMP': 'snmp'}.get(proto)
                if bucket:
                    self._live_counts[bucket] += 1
        except tk.TclError:
            return          # window closed mid-scan

        n = sum(1 for _ in self._dev_by_iid)
        self.status_var.set(
            f"Scanning… {n} device(s), {self._streamed_points} point(s) so far")
        self._update_chips(points=self._streamed_points)
        self._update_filter_count()

    def _update_chips(self, counts: Optional[dict] = None, points: Optional[int] = None) -> None:
        counts = counts or self._live_counts
        labels = {'bacnet': 'BACnet', 'mstp': 'MS/TP', 'modbus': 'Modbus',
                  'services': 'Services', 'snmp': 'SNMP', 'points': 'Points',
                  'flagged': 'Flagged'}
        for key, chip in self.chips.items():
            n = points if key == 'points' else counts.get(key)
            if key == 'points' and points is None:
                n = counts.get('points')
            if key == 'flagged':
                seen = self.scan_running or self.result is not None or self._flagged_points
                n = self._flagged_points if seen else None
            chip.configure(text=f"{labels[key]}  {n:,}" if n is not None else f"{labels[key]}  –")

    def _device_label(self, dev: dict) -> str:
        """Prefer the device's own BACnet objectName over ip (instance)."""
        ip = dev.get('ip', '?')
        props = dev.get('properties', {}) or {}
        name = (props.get('object_name') or '').strip()
        return f"{name} ({ip})" if name else f"{ip} ({dev.get('instance', '?')})"

    def _add_points_for(self, dev: dict) -> int:
        label = self._device_label(dev)
        count = 0
        for pt in dev.get('objects', []) or []:
            status = pt.get('status', '')
            tags = ()
            if status:
                self._flagged_points += 1
                tags = ("alarm",) if ('alarm' in status or 'fault' in status) else ("flag",)
            self._insert(self.points_tree, (
                label, pt.get('type', '?'), pt.get('instance', '?'),
                pt.get('name', ''), pt.get('present_value', ''),
                pt.get('units', ''), status, pt.get('description', ''),
            ), tags)
            count += 1
        return count

    def _add_registers_for(self, dev: dict) -> None:
        if dev.get('protocol') != 'Modbus TCP':
            return
        label = f"{dev['ip']}:{dev['port']} unit {dev.get('unit_id')}"
        for reg in dev.get('holding_registers', []) or []:
            self._insert(self.reg_tree, (label, "Holding (FC3)", reg['register'],
                                         reg['value'], reg['hex'], format(reg['value'], '016b')))
        for reg in dev.get('input_registers', []) or []:
            self._insert(self.reg_tree, (label, "Input (FC4)", reg['register'],
                                         reg['value'], reg['hex'], format(reg['value'], '016b')))
        for coil in dev.get('coils', []) or []:
            self._insert(self.reg_tree, (label, "Coil (FC1)", coil['coil'],
                                         coil['value'], f"0x{coil['value']:04X}", coil['state']))

    def _add_service_row(self, dev: dict) -> None:
        self._insert(self.svc_tree, (
            dev.get('ip', '?'), dev.get('port', '?'),
            dev.get('service', '?'), dev.get('vendor', ''),
            dev.get('product', ''), dev.get('title', ''),
            dev.get('tls_summary', ''), dev.get('banner', ''),
        ))

    def _populate_results(self) -> None:
        if not self.result:
            return

        # Devices tab - deduplicate service ports into their owning device.
        # An IP that responds on BACnet gets ONE row (the BACnet row) even if
        # it also has HTTP/HTTPS/FTP/Telnet. The service detail still shows in
        # the Services tab; this just keeps the primary device view clean.
        primary_ips = {d.get('ip') for d in self.result.devices
                       if d.get('protocol') in ('BACnet/IP', 'BACnet/MSTP', 'Modbus TCP', 'SNMP')}
        # One row per service-only host, so a gateway with four open ports
        # shows once, not four times.
        seen_service_ips: set[str] = set()
        streamed = getattr(self, '_streamed', set())
        for dev in self.result.devices:
            proto = dev.get('protocol')
            ip = dev.get('ip')
            if proto == 'Service':
                if id(dev) not in streamed:
                    self._add_service_row(dev)
                if ip in primary_ips or ip in seen_service_ips:
                    continue
                seen_service_ips.add(ip)
            elif id(dev) in streamed:
                continue      # already drawn while the scan was running
            self._add_device_to_tree(dev)
            if proto != 'Service':
                self._add_points_for(dev)
                self._add_registers_for(dev)

        # Fingerprints are computed at the very end of the scan, after the
        # rows were streamed; refresh the identification columns.
        for iid, dev in self._dev_by_iid.items():
            self.device_tree.item(iid, values=self._device_values(dev))
        # Rows arrived in whatever order devices finished. Unless the user has
        # sorted already, settle on address order, each router followed by the
        # MS/TP devices behind it.
        if 'devices' not in self._sort_state:
            def order(iid):
                dev = self._dev_by_iid.get(iid, {})
                inst = dev.get('instance')
                return (self._sort_key(dev.get('ip', '')),
                        dev.get('protocol') != 'BACnet/IP',
                        inst if isinstance(inst, int) else -1)
            self._rows['devices'].sort(key=order)
        self._apply_filter_to(self.device_tree)

        self._raw_dirty = True
        if self.notebook.select() == str(self._raw_tab):
            self._fill_raw()

        c = self.result.counts
        self._update_chips(counts=c)
        unique_ips = len({d.get('ip') for d in self.result.devices if d.get('ip')})
        self.stats_var.set(
            f"Hosts {unique_ips}   ·   BACnet {c['bacnet']}   MS/TP {c['mstp']}   "
            f"Modbus {c['modbus']}   Service ports {c['services']}   SNMP {c['snmp']}   "
            f"·   Points {c['points']:,}   ·   {self.result.elapsed:.1f}s"
        )
        self._show_selected_details()

    def _fill_raw(self) -> None:
        self._raw_dirty = False
        self.raw_text.delete("1.0", tk.END)
        if self.result:
            self.raw_text.insert("1.0", json.dumps(self.result.to_dict(), indent=2, default=str))

    def _device_values(self, dev: dict[str, Any]) -> tuple:
        protocol = dev.get('protocol', '?')
        fp = dev.get('_fingerprint', {}) or {}
        props = dev.get('properties', {}) or {}

        if str(protocol).startswith('BACnet'):
            address = str(dev.get('instance', '?'))
            if dev.get('source_network'):
                address = f"{address}  (MS/TP {dev['source_network']}:{dev.get('source_address', '?')})"
            vendor = dev.get('vendor_name', '?')
        elif protocol == 'Modbus TCP':
            address = f"unit {dev.get('unit_id', '?')}"
            if dev.get('answers_any_unit'):
                address += " (any)"
            vendor = dev.get('vendor', '?')
        elif protocol == 'SNMP':
            address = ''
            vendor = dev.get('vendor', '')
        else:
            address = f":{dev.get('port', '?')}"
            vendor = dev.get('vendor', '') or fp.get('vendor', '')

        model = props.get('model_name', '') or fp.get('model', '')
        description = props.get('description', '') or fp.get('description', '')
        return (protocol, dev.get('ip', '?'), address, props.get('object_name', ''),
                model, vendor, fp.get('device_type', ''), fp.get('web_url', ''),
                fp.get('default_creds', ''), description)

    def _add_device_to_tree(self, dev: dict[str, Any]) -> None:
        iid = self._insert(self.device_tree, self._device_values(dev))
        self._dev_by_iid[iid] = dev

    # -- device details and actions ---------------------------------------

    def _selected_device(self) -> Optional[dict]:
        sel = self.device_tree.selection()
        return self._dev_by_iid.get(sel[0]) if sel else None

    def _get_selected_vals(self) -> tuple | None:
        selection = self.device_tree.selection()
        if not selection:
            return None
        return self.device_tree.item(selection[0])['values']

    def _show_selected_details(self) -> None:
        self._set_details(self._selected_device())

    def _set_details(self, dev: Optional[dict]) -> None:
        t = self.details_text
        t.configure(state='normal')
        t.delete("1.0", tk.END)
        if dev is None:
            t.insert(tk.END, "\nSelect a device to see everything the scan learned "
                             "about it.\n\nDouble-click a device to list its points.", "k")
            t.configure(state='disabled')
            return
        for kind, a, b in self._detail_lines(dev):
            if kind == 'h':
                t.insert(tk.END, f"\n{a}\n", "h")
            else:
                t.insert(tk.END, f"{a:<15}", ("k", "v"))
                t.insert(tk.END, f"{b}\n", ("v", "creds") if a == "Default creds" and b else "v")
        t.configure(state='disabled')

    def _detail_lines(self, dev: dict) -> list[tuple[str, str, str]]:
        fp = dev.get('_fingerprint', {}) or {}
        props = dev.get('properties', {}) or {}
        out: list[tuple[str, str, str]] = []

        def kv(k, v):
            if v not in (None, ''):
                out.append(('kv', k, str(v)))

        out.append(('h', str(props.get('object_name') or dev.get('ip', '?')), ''))
        kv("Protocol", dev.get('protocol'))
        kv("IP address", dev.get('ip'))
        kv("Port", dev.get('port'))
        kv("Instance", dev.get('instance') if str(dev.get('protocol', '')).startswith('BACnet') else None)
        kv("Unit ID", dev.get('unit_id'))
        if dev.get('answers_any_unit'):
            kv("Note", "answers every unit ID")
        if dev.get('source_network'):
            kv("MS/TP net", dev.get('source_network'))
            kv("MS/TP MAC", dev.get('source_address'))
            kv("Via router", dev.get('ip'))
        kv("Found by", "unicast probe" if dev.get('discovered_via') == 'unicast' else None)
        out.append(('h', "Identification", ''))
        kv("Model", props.get('model_name') or fp.get('model'))
        kv("Type", fp.get('device_type'))
        kv("Vendor", dev.get('vendor_name') or dev.get('vendor'))
        kv("Vendor ID", dev.get('vendor_id'))
        kv("Firmware", props.get('firmware_revision'))
        kv("App version", props.get('application_software_version'))
        kv("Location", props.get('location'))
        kv("Description", props.get('description') or fp.get('description'))
        out.append(('h', "Access", ''))
        kv("Web UI", fp.get('web_url') or "none detected")
        kv("Default creds", fp.get('default_creds'))
        if dev.get('max_apdu') or dev.get('segmentation'):
            out.append(('h', "BACnet", ''))
            kv("Max APDU", dev.get('max_apdu'))
            kv("Segmentation", dev.get('segmentation'))
            kv("Protocol rev", props.get('protocol_revision'))
            kv("Points read", len(dev.get('objects') or []))
            flags = dev.get('point_flags') or {}
            kv("Point status", ", ".join(f"{n} {f}" for f, n in flags.items()) or "all normal"
               if dev.get('objects') else None)
            c = dev.get('_classification') or {}
            kv("Profile", c.get('explanation'))
        if dev.get('banner') or dev.get('title') or dev.get('tls_summary'):
            out.append(('h', "Service", ''))
            kv("Service", dev.get('service'))
            kv("Title", dev.get('title'))
            kv("Server", dev.get('server'))
            kv("Banner", dev.get('banner'))
            kv("TLS", dev.get('tls_summary'))
        if dev.get('sys_descr'):
            out.append(('h', "SNMP", ''))
            kv("sysDescr", dev.get('sys_descr'))
        if self.result:
            others = [d for d in self.result.devices
                      if d.get('ip') == dev.get('ip') and d.get('protocol') == 'Service']
            if others:
                out.append(('h', "Open service ports", ''))
                for s in others:
                    kv(f":{s.get('port')}", " ".join(x for x in (s.get('service'), s.get('title')) if x))
        return out

    def _on_device_double_click(self, _event=None) -> None:
        # v2.1.1: double-click does not open the web UI — for MSTP devices the
        # row's IP is the router's IP. It lists the device's points instead.
        self._ctx_show_points()

    def _on_device_right_click(self, event) -> None:
        self._popup_for(self.device_tree, self.ctx_menu, event)

    def _ctx_show_points(self) -> None:
        dev = self._selected_device()
        if not dev:
            return
        if dev.get('protocol') == 'Modbus TCP':
            self.notebook.select(2)
            self.filter_var.set(dev.get('ip', ''))
        else:
            self.notebook.select(1)
            self.filter_var.set(self._device_label(dev))
        self._apply_filter()

    def _ctx_show_details(self) -> None:
        self._show_selected_details()

    def _ctx_open_web(self, force_http: bool = False) -> None:
        dev = self._selected_device()
        if not dev:
            return
        web_url = (dev.get('_fingerprint') or {}).get('web_url', '')
        ip = dev.get('ip')
        if force_http:
            webbrowser.open(f"http://{ip}")
        elif web_url and str(web_url).startswith('http'):
            webbrowser.open(str(web_url))
        else:
            webbrowser.open(f"https://{ip}")

    def _ctx_copy_ip(self) -> None:
        dev = self._selected_device()
        if dev:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(dev.get('ip', '')))
            self._set_status("IP address copied", Colors.TEXT_DIM)

    def _ctx_copy_creds(self) -> None:
        dev = self._selected_device()
        creds = ((dev or {}).get('_fingerprint') or {}).get('default_creds')
        if creds:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(creds))

    def _ctx_ping(self) -> None:
        dev = self._selected_device()
        if not dev:
            return
        ip = str(dev.get('ip'))
        self.log_message(f"Pinging {ip}...")

        def _do_ping():
            try:
                windows = os.name == 'nt'
                result = subprocess.run(
                    ['ping', '-n' if windows else '-c', '4', ip],
                    capture_output=True, text=True, timeout=15,
                    # The packaged GUI has no console; without this, ping
                    # flashes one up on Windows.
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0) if windows else 0)
                for line in result.stdout.strip().splitlines():
                    if line.strip():
                        self.log_message(f"  {line}")
            except Exception as e:
                self.log_message(f"  Ping error: {e}")

        threading.Thread(target=_do_ping, daemon=True).start()

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About HVAC Network Scanner",
            f"HVAC Network Scanner {__version__}\n\n"
            "Multi-protocol discovery for building automation networks: "
            "BACnet/IP and MS/TP, Modbus TCP, HVAC service ports and SNMP. "
            "Standard library only.\n\n"
            "Only scan networks you own or are authorized to assess. Small "
            "field controllers can misbehave under probe load; use the rate "
            "limit in Advanced on fragile sites.\n\n"
            "https://github.com/jamesccupps/HVAC-Network-Scanner",
            parent=self.root)

    # -- export -----------------------------------------------------------

    def _export(self, kind: str) -> None:
        if not self.result or not self.result.devices:
            messagebox.showinfo("Export", "Run a scan first.")
            return
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        spec = {
            'csv': ("Devices CSV", ".csv", f"hvac_scan_{stamp}_devices", self.result.write_csv),
            'points': ("Point list CSV", ".csv", f"hvac_scan_{stamp}_points",
                       self.result.write_points_csv),
            'json': ("Scan JSON", ".json", f"hvac_scan_{stamp}", self.result.write_json),
            'html': ("Survey report", ".html", f"hvac_survey_{stamp}", self.result.write_html),
            'txt': ("Classification report", ".txt", f"hvac_scan_{stamp}_classification",
                    self.result.write_classification_report),
        }[kind]
        label, ext, initial, writer = spec
        path = filedialog.asksaveasfilename(
            defaultextension=ext, initialfile=initial + ext,
            filetypes=[(label, f"*{ext}"), ("All files", "*.*")])
        if not path:
            return
        try:
            writer(path)
        except Exception as e:
            self.log_message(f"Export error: {e}")
            messagebox.showerror("Export", str(e))
            return
        self.log_message(f"Exported {label.lower()}: {path}")
        self._set_status(f"Saved {Path(path).name}", Colors.GREEN)
        if kind == 'html':
            webbrowser.open(Path(path).resolve().as_uri())

    def export_results(self) -> None:
        """Pick the format from the file name (kept for older callers)."""
        if not self.result or not self.result.devices:
            messagebox.showinfo("Export", "No data to export")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"),
                       ("Classification report", "*.txt"), ("All files", "*.*")],
            initialfile=f"hvac_scan_{datetime.now():%Y%m%d_%H%M%S}",
        )
        if not filepath:
            return
        lower = filepath.lower()
        if lower.endswith('.json'):
            self.result.write_json(filepath)
        elif lower.endswith('.txt'):
            self.result.write_classification_report(filepath)
        else:
            self.result.write_csv(filepath)
        self.log_message(f"Exported to {filepath}")

    # -- settings ---------------------------------------------------------

    _PROTOCOL_VARS = ('scan_bacnet', 'scan_mstp', 'scan_modbus', 'scan_services',
                      'scan_snmp', 'deep_scan', 'use_rpm')

    def _collect_settings(self) -> dict[str, Any]:
        data = {
            'targets': self.network_entry.get(),
            'depth': self.scan_depth_var.get(),
            'advanced_open': self._adv_open,
            'advanced': {k: v.get() for k, v in self.adv_vars.items()},
            'toggles': {k: getattr(self, k).get() for k in self._PROTOCOL_VARS},
        }
        try:
            if self.root.state() == 'normal':
                data['geometry'] = self.root.geometry()
        except tk.TclError:
            pass
        return data

    def _apply_settings(self, data: dict[str, Any]) -> None:
        if not data:
            return
        if isinstance(data.get('targets'), str) and data['targets'].strip():
            self.network_entry.delete(0, tk.END)
            self.network_entry.insert(0, data['targets'])
        if data.get('depth') in ("quick", "normal", "full"):
            self.scan_depth_var.set(data['depth'])
        for k, v in (data.get('advanced') or {}).items():
            if k in self.adv_vars and isinstance(v, str):
                self.adv_vars[k].set(v)
        for k, v in (data.get('toggles') or {}).items():
            if k in self._PROTOCOL_VARS and isinstance(v, bool):
                getattr(self, k).set(v)
        if data.get('advanced_open'):
            self._toggle_advanced(True)
        geo = data.get('geometry')
        if isinstance(geo, str) and geo.count('x') == 1:
            try:
                self.root.geometry(geo)
            except tk.TclError:
                pass

    def _save_settings(self) -> None:
        settings_mod.save(self.settings_path, self._collect_settings())

    def _on_close(self) -> None:
        if self.scan_running:
            if not messagebox.askyesno("Scan running",
                                       "A scan is still running. Stop it and quit?",
                                       parent=self.root):
                return
            self.stop_event.set()
        self._save_settings()
        self.root.destroy()


def main() -> None:
    # Windows DPI awareness — must be before Tk() creation
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass
    if sys.platform.startswith('win'):
        # Group the taskbar button under our own icon, not python.exe's.
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "jamesccupps.HVACNetworkScanner")
        except (AttributeError, OSError):
            pass

    root = tk.Tk()
    try:
        dpi = root.winfo_fpixels('1i')
        root.tk.call('tk', 'scaling', dpi / 72.0)
    except Exception:
        pass

    HVACNetworkScannerGUI(root, settings_path=settings_mod.default_path())
    root.mainloop()


if __name__ == "__main__":
    main()
