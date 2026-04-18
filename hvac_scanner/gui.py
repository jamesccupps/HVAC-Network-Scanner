"""
Tk GUI for the HVAC Network Scanner.

This is the same UX as v1, but now a thin wrapper over the shared
ScanEngine. That means the CLI and GUI are guaranteed to produce
identical results from the same inputs.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .engine import ScanEngine, ScanOptions


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
class Colors:
    BG_DARK      = "#0d1117"
    BG_PANEL     = "#161b22"
    BG_CARD      = "#1c2333"
    BG_INPUT     = "#21262d"
    BORDER       = "#30363d"
    TEXT         = "#e6edf3"
    TEXT_DIM     = "#8b949e"
    ACCENT       = "#58a6ff"
    ACCENT_HOVER = "#79c0ff"
    GREEN        = "#3fb950"
    YELLOW       = "#d29922"
    RED          = "#f85149"
    ORANGE       = "#db6d28"
    PURPLE       = "#bc8cff"
    CYAN         = "#39d353"
    TEAL         = "#2ea043"


class HVACNetworkScannerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("HVAC Network Scanner v2.0 - Full Protocol Discovery")
        self.root.geometry("1440x920")
        self.root.configure(bg=Colors.BG_DARK)
        self.root.minsize(1100, 700)

        self.result = None
        self.scan_running = False
        self.stop_event = threading.Event()
        self._sort_state: dict[int, tuple[str, bool]] = {}

        self._setup_styles()
        self._build_ui()

    # -- styling ----------------------------------------------------------

    def _setup_styles(self) -> None:
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(".", background=Colors.BG_DARK, foreground=Colors.TEXT,
                        fieldbackground=Colors.BG_INPUT, borderwidth=0)
        style.configure("Dark.TFrame", background=Colors.BG_DARK)
        style.configure("Card.TFrame", background=Colors.BG_PANEL)
        style.configure("Title.TLabel", background=Colors.BG_DARK, foreground=Colors.ACCENT,
                        font=("Consolas", 18, "bold"))
        style.configure("Subtitle.TLabel", background=Colors.BG_DARK, foreground=Colors.TEXT_DIM,
                        font=("Consolas", 9))
        style.configure("Header.TLabel", background=Colors.BG_PANEL, foreground=Colors.ACCENT,
                        font=("Consolas", 11, "bold"))
        style.configure("Info.TLabel", background=Colors.BG_PANEL, foreground=Colors.TEXT,
                        font=("Consolas", 10))
        style.configure("Dim.TLabel", background=Colors.BG_PANEL, foreground=Colors.TEXT_DIM,
                        font=("Consolas", 9))
        style.configure("Status.TLabel", background=Colors.BG_DARK, foreground=Colors.GREEN,
                        font=("Consolas", 9))
        style.configure("Accent.TButton", background=Colors.ACCENT, foreground="#000",
                        font=("Consolas", 10, "bold"), padding=(12, 6))
        style.map("Accent.TButton",
                  background=[("active", Colors.ACCENT_HOVER), ("disabled", Colors.BORDER)])
        style.configure("Danger.TButton", background=Colors.RED, foreground="#000",
                        font=("Consolas", 10, "bold"), padding=(12, 6))
        style.map("Danger.TButton",
                  background=[("active", "#ff6e6e"), ("disabled", Colors.BORDER)])
        style.configure("Export.TButton", background=Colors.TEAL, foreground="#000",
                        font=("Consolas", 10, "bold"), padding=(12, 6))
        style.map("Export.TButton",
                  background=[("active", Colors.GREEN), ("disabled", Colors.BORDER)])
        style.configure("Treeview", background=Colors.BG_CARD, foreground=Colors.TEXT,
                        fieldbackground=Colors.BG_CARD, rowheight=24, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=Colors.BG_INPUT, foreground=Colors.ACCENT,
                        font=("Consolas", 9, "bold"))
        style.map("Treeview",
                  background=[("selected", Colors.ACCENT)], foreground=[("selected", "#000")])
        style.configure("TNotebook", background=Colors.BG_DARK)
        style.configure("TNotebook.Tab", background=Colors.BG_PANEL, foreground=Colors.TEXT_DIM,
                        font=("Consolas", 10), padding=(12, 6))
        style.map("TNotebook.Tab",
                  background=[("selected", Colors.BG_CARD)], foreground=[("selected", Colors.ACCENT)])

    # -- UI layout --------------------------------------------------------

    def _build_ui(self) -> None:
        hdr = ttk.Frame(self.root, style="Dark.TFrame")
        hdr.pack(fill=tk.X, padx=16, pady=(12, 4))
        ttk.Label(hdr, text="HVAC Network Scanner", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(hdr, text="BACnet/IP  MSTP  Modbus  Services  SNMP",
                  style="Subtitle.TLabel").pack(side=tk.LEFT, padx=(12, 0), pady=(6, 0))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(hdr, textvariable=self.status_var, style="Status.TLabel").pack(side=tk.RIGHT)

        # config row
        cfg = ttk.Frame(self.root, style="Card.TFrame")
        cfg.pack(fill=tk.X, padx=16, pady=(4, 4))
        inner = ttk.Frame(cfg, style="Card.TFrame")
        inner.pack(fill=tk.X, padx=12, pady=8)

        ttk.Label(inner, text="Target Network(s):", style="Info.TLabel").pack(side=tk.LEFT)
        self.network_entry = ttk.Entry(inner, width=44, font=("Consolas", 10))
        self.network_entry.pack(side=tk.LEFT, padx=(6, 16))
        self.network_entry.insert(0, "192.168.1.0/24")

        ttk.Label(inner, text="Timeout:", style="Dim.TLabel").pack(side=tk.LEFT)
        self.timeout_entry = ttk.Entry(inner, width=4, font=("Consolas", 10))
        self.timeout_entry.pack(side=tk.LEFT, padx=(4, 12))
        self.timeout_entry.insert(0, "5")

        ttk.Label(inner, text="Chunk:", style="Dim.TLabel").pack(side=tk.LEFT)
        self.whois_chunk_entry = ttk.Entry(inner, width=6, font=("Consolas", 10))
        self.whois_chunk_entry.pack(side=tk.LEFT, padx=(4, 12))
        self.whois_chunk_entry.insert(0, "0")  # 0 = single broadcast (default)

        self.scan_bacnet    = tk.BooleanVar(value=True)
        self.scan_mstp      = tk.BooleanVar(value=True)
        self.scan_modbus    = tk.BooleanVar(value=True)
        self.scan_services  = tk.BooleanVar(value=True)
        self.scan_snmp      = tk.BooleanVar(value=True)
        self.deep_scan      = tk.BooleanVar(value=True)
        self.use_rpm        = tk.BooleanVar(value=True)

        cb_frame = ttk.Frame(inner, style="Card.TFrame")
        cb_frame.pack(side=tk.LEFT, padx=(0, 12))
        for text, var, color in [
            ("BACnet",   self.scan_bacnet,   Colors.GREEN),
            ("MSTP",     self.scan_mstp,     Colors.CYAN),
            ("Modbus",   self.scan_modbus,   Colors.YELLOW),
            ("Services", self.scan_services, Colors.ORANGE),
            ("SNMP",     self.scan_snmp,     Colors.PURPLE),
            ("Deep",     self.deep_scan,     Colors.ACCENT),
            ("RPM",      self.use_rpm,       Colors.TEAL),
        ]:
            tk.Checkbutton(cb_frame, text=text, variable=var, bg=Colors.BG_PANEL, fg=color,
                           selectcolor=Colors.BG_INPUT, activebackground=Colors.BG_PANEL,
                           activeforeground=color, font=("Consolas", 9)).pack(side=tk.LEFT, padx=3)

        self.scan_btn = ttk.Button(inner, text="SCAN", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.pack(side=tk.RIGHT, padx=4)
        self.stop_btn = ttk.Button(inner, text="STOP", style="Danger.TButton",
                                   command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side=tk.RIGHT, padx=4)
        self.export_btn = ttk.Button(inner, text="EXPORT", style="Export.TButton",
                                     command=self.export_results, state='disabled')
        self.export_btn.pack(side=tk.RIGHT, padx=4)

        # tabs
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=16, pady=4)

        top_frame = ttk.Frame(paned, style="Dark.TFrame")
        paned.add(top_frame, weight=3)
        self.notebook = ttk.Notebook(top_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_devices_tab()
        self._build_points_tab()
        self._build_registers_tab()
        self._build_services_tab()
        self._build_raw_tab()

        # log console
        bot_frame = ttk.Frame(paned, style="Dark.TFrame")
        paned.add(bot_frame, weight=1)
        log_header = ttk.Frame(bot_frame, style="Card.TFrame")
        log_header.pack(fill=tk.X)
        ttk.Label(log_header, text=" Scan Log", style="Header.TLabel").pack(side=tk.LEFT, padx=8, pady=4)
        self.log_text = tk.Text(bot_frame, bg=Colors.BG_CARD, fg=Colors.TEXT_DIM,
                                font=("Consolas", 9), insertbackground=Colors.TEXT,
                                height=8, padx=8, pady=4)
        log_scroll = ttk.Scrollbar(bot_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_configure("error",   foreground=Colors.RED)
        self.log_text.tag_configure("success", foreground=Colors.GREEN)
        self.log_text.tag_configure("warn",    foreground=Colors.YELLOW)
        self.log_text.tag_configure("info",    foreground=Colors.ACCENT)

        sbar = ttk.Frame(self.root, style="Card.TFrame")
        sbar.pack(fill=tk.X, padx=16, pady=(0, 8))
        self.stats_var = tk.StringVar(value="No scan performed yet")
        ttk.Label(sbar, textvariable=self.stats_var, style="Dim.TLabel").pack(side=tk.LEFT, padx=8, pady=4)

        self.log_message("HVAC Network Scanner v2.0 - Full Protocol Discovery")
        self.log_message("  BACnet/IP | BACnet MSTP (via routers) | Modbus TCP")
        self.log_message("  Niagara Fox | OPC UA | KNX | LonWorks | EtherNet/IP | S7")
        self.log_message("  HTTP/HTTPS banner grab | SNMP | SSH/Telnet/FTP")
        self.log_message("  Enter your HVAC network CIDR(s) above and click SCAN")
        self.log_message("")

    def _build_devices_tab(self) -> None:
        dev_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(dev_frame, text="  All Devices  ")
        columns = ("protocol", "ip", "port", "address", "model", "device_type",
                   "vendor", "web_url", "default_creds", "description")
        self.device_tree = ttk.Treeview(dev_frame, columns=columns, show="headings", selectmode="browse")
        for col, text, width in [
            ("protocol", "Protocol", 85),     ("ip", "IP Address", 115),
            ("port", "Port", 50),             ("address", "Device ID", 85),
            ("model", "Model", 200),          ("device_type", "Type", 130),
            ("vendor", "Vendor", 140),        ("web_url", "Web UI", 130),
            ("default_creds", "Default Creds", 160), ("description", "Description", 320),
        ]:
            self._setup_sortable(self.device_tree, col, text)
            self.device_tree.column(col, width=width, minwidth=40)
        dev_scroll = ttk.Scrollbar(dev_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=dev_scroll.set)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dev_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.bind("<Double-1>", self._on_device_double_click)
        self.device_tree.bind("<Button-3>", self._on_device_right_click)

        self.ctx_menu = tk.Menu(self.root, tearoff=0, bg=Colors.BG_PANEL, fg=Colors.TEXT,
                                activebackground=Colors.ACCENT, activeforeground="#000",
                                font=("Consolas", 10))
        self.ctx_menu.add_command(label="Open Web UI", command=self._ctx_open_web)
        self.ctx_menu.add_command(label="Open Web UI (HTTP)",
                                  command=lambda: self._ctx_open_web(force_http=True))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Copy IP Address", command=self._ctx_copy_ip)
        self.ctx_menu.add_command(label="Copy Default Credentials", command=self._ctx_copy_creds)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Show Device Details", command=self._ctx_show_details)
        self.ctx_menu.add_command(label="Ping Device", command=self._ctx_ping)

    def _build_points_tab(self) -> None:
        pts_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(pts_frame, text="  BACnet Points  ")
        pts_columns = ("device", "type", "address", "name", "value", "units", "description")
        self.points_tree = ttk.Treeview(pts_frame, columns=pts_columns, show="headings", selectmode="browse")
        for col, text, width in [
            ("device", "Device", 130), ("type", "Object Type", 130),
            ("address", "Instance", 80), ("name", "Name", 240),
            ("value", "Present Value", 100), ("units", "Units", 70),
            ("description", "Description", 280),
        ]:
            self._setup_sortable(self.points_tree, col, text)
            self.points_tree.column(col, width=width, minwidth=50)
        pts_scroll = ttk.Scrollbar(pts_frame, orient="vertical", command=self.points_tree.yview)
        self.points_tree.configure(yscrollcommand=pts_scroll.set)
        self.points_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pts_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_registers_tab(self) -> None:
        reg_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(reg_frame, text="  Modbus Registers  ")
        reg_columns = ("device", "reg_type", "address", "value_dec", "value_hex", "value_bin")
        self.reg_tree = ttk.Treeview(reg_frame, columns=reg_columns, show="headings", selectmode="browse")
        for col, text, width in [
            ("device", "Device", 150), ("reg_type", "Register Type", 120),
            ("address", "Address", 70), ("value_dec", "Value (Dec)", 90),
            ("value_hex", "Value (Hex)", 90), ("value_bin", "Value (Bin)", 170),
        ]:
            self._setup_sortable(self.reg_tree, col, text)
            self.reg_tree.column(col, width=width, minwidth=50)
        reg_scroll = ttk.Scrollbar(reg_frame, orient="vertical", command=self.reg_tree.yview)
        self.reg_tree.configure(yscrollcommand=reg_scroll.set)
        self.reg_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        reg_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_services_tab(self) -> None:
        svc_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(svc_frame, text="  Services  ")
        svc_columns = ("ip", "port", "service", "vendor", "product", "title", "banner")
        self.svc_tree = ttk.Treeview(svc_frame, columns=svc_columns, show="headings", selectmode="browse")
        for col, text, width in [
            ("ip", "IP Address", 130), ("port", "Port", 55),
            ("service", "Service", 130), ("vendor", "Vendor", 160),
            ("product", "Product", 160), ("title", "Page Title", 200),
            ("banner", "Banner", 300),
        ]:
            self._setup_sortable(self.svc_tree, col, text)
            self.svc_tree.column(col, width=width, minwidth=50)
        svc_scroll = ttk.Scrollbar(svc_frame, orient="vertical", command=self.svc_tree.yview)
        self.svc_tree.configure(yscrollcommand=svc_scroll.set)
        self.svc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        svc_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _build_raw_tab(self) -> None:
        raw_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(raw_frame, text="  { } Raw Data  ")
        self.raw_text = tk.Text(raw_frame, bg=Colors.BG_CARD, fg=Colors.TEXT,
                                font=("Consolas", 9), insertbackground=Colors.TEXT,
                                wrap=tk.NONE, padx=8, pady=8)
        raw_hscroll = ttk.Scrollbar(raw_frame, orient="horizontal", command=self.raw_text.xview)
        raw_vscroll = ttk.Scrollbar(raw_frame, orient="vertical", command=self.raw_text.yview)
        self.raw_text.configure(xscrollcommand=raw_hscroll.set, yscrollcommand=raw_vscroll.set)
        raw_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        raw_vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.raw_text.pack(fill=tk.BOTH, expand=True)

    # -- sorting ----------------------------------------------------------

    def _setup_sortable(self, tree: ttk.Treeview, col: str, display_name: str) -> None:
        tree.heading(col, text=display_name,
                     command=lambda: self._sort_treeview(tree, col))

    def _sort_treeview(self, tree: ttk.Treeview, col: str) -> None:
        tree_id = id(tree)
        prev_col, prev_reverse = self._sort_state.get(tree_id, (None, False))
        reverse = not prev_reverse if prev_col == col else False
        self._sort_state[tree_id] = (col, reverse)

        items = [(tree.set(iid, col), iid) for iid in tree.get_children("")]

        def sort_key(item):
            val = item[0]
            # IP address
            if isinstance(val, str) and val.count(".") == 3 and all(p.isdigit() for p in val.split(".")):
                return (0, tuple(int(p) for p in val.split(".")))
            try:
                return (1, float(val))
            except (ValueError, TypeError):
                return (2, str(val).lower())

        try:
            items.sort(key=sort_key, reverse=reverse)
        except TypeError:
            items.sort(key=lambda x: str(x[0]).lower(), reverse=reverse)

        for idx, (_, iid) in enumerate(items):
            tree.move(iid, "", idx)

        arrow = " \u25bc" if reverse else " \u25b2"
        for c in tree["columns"]:
            current = tree.heading(c, "text")
            clean = current.rstrip(" \u25b2\u25bc")
            tree.heading(c, text=clean + arrow if c == col else clean)

    # -- logging ----------------------------------------------------------

    def log_message(self, msg: str) -> None:
        def _append():
            tag = None
            low = msg.lower()
            if "error" in low:
                tag = "error"
            elif "Found" in msg and "device" in low:
                tag = "success"
            elif "in use" in low or "failed" in low:
                tag = "warn"
            elif any(k in msg for k in ("Scanning", "Sending", "Probing")):
                tag = "info"
            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
        self.root.after(0, _append)

    # -- scan control -----------------------------------------------------

    def start_scan(self) -> None:
        if self.scan_running:
            return
        self.scan_running = True
        self.stop_event = threading.Event()
        self.scan_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.export_btn.configure(state='disabled')
        self.status_var.set("Scanning...")

        for tree in (self.device_tree, self.points_tree, self.reg_tree, self.svc_tree):
            for item in tree.get_children():
                tree.delete(item)
        self.raw_text.delete("1.0", tk.END)

        threading.Thread(target=self._run_scan, daemon=True).start()

    def stop_scan(self) -> None:
        self.stop_event.set()
        self.log_message("Scan stop requested...")

    def _run_scan(self) -> None:
        try:
            networks = [n.strip() for n in self.network_entry.get().split(",") if n.strip()]
            timeout = float(self.timeout_entry.get() or "5")
            try:
                chunk = int(self.whois_chunk_entry.get() or "0")
            except ValueError:
                chunk = 0
            opts = ScanOptions(
                networks=networks,
                timeout=timeout,
                scan_bacnet=self.scan_bacnet.get(),
                scan_mstp=self.scan_mstp.get(),
                scan_modbus=self.scan_modbus.get(),
                scan_services=self.scan_services.get(),
                scan_snmp=self.scan_snmp.get(),
                deep_scan=self.deep_scan.get(),
                use_rpm=self.use_rpm.get(),
                whois_chunk_size=chunk,
            )

            engine = ScanEngine(opts, callback=self.log_message,
                                stop_event=self.stop_event)
            self.result = engine.run()

            # Populate UI
            self.root.after(0, self._populate_results)

        except Exception as e:
            self.log_message(f"Scan error: {e}")
            import traceback
            self.log_message(traceback.format_exc())
        finally:
            self.scan_running = False
            self.root.after(0, lambda: self.scan_btn.configure(state='normal'))
            self.root.after(0, lambda: self.stop_btn.configure(state='disabled'))
            self.root.after(0, lambda: self.export_btn.configure(state='normal'))
            self.root.after(0, lambda: self.status_var.set("Scan complete"))

    def _populate_results(self) -> None:
        if not self.result:
            return

        # All Devices tab - deduplicate service ports into their owning device.
        # An IP that responds on BACnet gets ONE row (the BACnet row) even if
        # it also has HTTP/HTTPS/FTP/Telnet. The service detail still shows in
        # the Services tab; this just keeps the primary device view clean.
        primary_ips = {d.get('ip') for d in self.result.devices
                       if d.get('protocol') in ('BACnet/IP', 'BACnet/MSTP', 'Modbus TCP', 'SNMP')}
        # Track which IPs we've already added a "Service-only" row for, so
        # one Ubiquiti gateway with 4 open ports shows once, not 4 times.
        seen_service_ips: set[str] = set()
        for dev in self.result.devices:
            proto = dev.get('protocol')
            ip = dev.get('ip')
            if proto == 'Service':
                if ip in primary_ips:
                    continue  # dedup: BACnet/Modbus/SNMP row already represents this host
                if ip in seen_service_ips:
                    continue  # dedup: first service row for this IP already shown
                seen_service_ips.add(ip)
            self._add_device_to_tree(dev)

        # Points tab
        for dev in self.result.devices:
            ip = dev.get('ip', '?')
            instance = dev.get('instance', '?')
            for pt in dev.get('objects', []):
                self.points_tree.insert("", tk.END, values=(
                    f"{ip} ({instance})", pt.get('type', '?'),
                    pt.get('instance', '?'), pt.get('name', ''),
                    pt.get('present_value', ''), pt.get('units', ''),
                    pt.get('description', ''),
                ))

        # Registers tab
        for dev in self.result.devices:
            if dev.get('protocol') != 'Modbus TCP':
                continue
            label = f"{dev['ip']}:{dev['port']} u={dev.get('unit_id')}"
            for reg in dev.get('holding_registers', []):
                self.reg_tree.insert("", tk.END, values=(
                    label, "Holding (FC3)", reg['register'],
                    reg['value'], reg['hex'], format(reg['value'], '016b')))
            for reg in dev.get('input_registers', []):
                self.reg_tree.insert("", tk.END, values=(
                    label, "Input (FC4)", reg['register'],
                    reg['value'], reg['hex'], format(reg['value'], '016b')))
            for coil in dev.get('coils', []):
                self.reg_tree.insert("", tk.END, values=(
                    label, "Coil (FC1)", coil['coil'],
                    coil['value'], f"0x{coil['value']:04X}", coil['state']))

        # Services tab
        for dev in self.result.devices:
            if dev.get('protocol') != 'Service':
                continue
            self.svc_tree.insert("", tk.END, values=(
                dev.get('ip', '?'), dev.get('port', '?'),
                dev.get('service', '?'), dev.get('vendor', ''),
                dev.get('product', ''), dev.get('title', ''),
                dev.get('banner', ''),
            ))

        # Raw JSON tab
        self.raw_text.delete("1.0", tk.END)
        self.raw_text.insert("1.0", json.dumps(self.result.to_dict(), indent=2, default=str))

        c = self.result.counts
        unique_ips = len({d.get('ip') for d in self.result.devices if d.get('ip')})
        self.stats_var.set(
            f"Hosts: {unique_ips}  |  BACnet: {c['bacnet']}  MSTP: {c['mstp']}  "
            f"Modbus: {c['modbus']}  Service ports: {c['services']}  SNMP: {c['snmp']}  "
            f"Points: {c['points']}  |  {self.result.elapsed:.1f}s"
        )

    def _add_device_to_tree(self, dev: dict[str, Any]) -> None:
        protocol = dev.get('protocol', '?')
        ip = dev.get('ip', '?')
        port = dev.get('port', '?')
        fp = dev.get('_fingerprint', {})

        if str(protocol).startswith('BACnet'):
            address = str(dev.get('instance', '?'))
            if dev.get('source_network'):
                address = f"{address} (MSTP {dev['source_network']}:{dev.get('source_address', '?')})"
            vendor = dev.get('vendor_name', '?')
        elif protocol == 'Modbus TCP':
            address = f"Unit {dev.get('unit_id', '?')}"
            vendor = dev.get('vendor', '?')
        elif protocol == 'SNMP':
            address = ''
            vendor = dev.get('vendor', '')
        else:
            address = f":{port}"
            vendor = dev.get('vendor', '') or fp.get('vendor', '')

        model = dev.get('properties', {}).get('model_name', '') or fp.get('model', '')
        description = dev.get('properties', {}).get('description', '') or fp.get('description', '')
        self.device_tree.insert("", tk.END, values=(
            protocol, ip, port, address,
            model, fp.get('device_type', ''),
            vendor, fp.get('web_url', ''),
            fp.get('default_creds', ''), description,
        ))

    # -- context menu / interaction ---------------------------------------

    def _get_selected_vals(self) -> tuple | None:
        selection = self.device_tree.selection()
        if not selection:
            return None
        return self.device_tree.item(selection[0])['values']

    def _on_device_double_click(self, _event) -> None:
        vals = self._get_selected_vals()
        if not vals:
            return
        web_url = vals[7]
        if web_url and str(web_url).startswith('http'):
            webbrowser.open(str(web_url))
        else:
            webbrowser.open(f"https://{vals[1]}")

    def _on_device_right_click(self, event) -> None:
        iid = self.device_tree.identify_row(event.y)
        if iid:
            self.device_tree.selection_set(iid)
            self.ctx_menu.post(event.x_root, event.y_root)

    def _ctx_open_web(self, force_http: bool = False) -> None:
        vals = self._get_selected_vals()
        if not vals:
            return
        web_url = vals[7]
        ip = vals[1]
        if web_url and str(web_url).startswith('http') and not force_http:
            webbrowser.open(str(web_url))
        elif force_http:
            webbrowser.open(f"http://{ip}")
        else:
            webbrowser.open(f"https://{ip}")

    def _ctx_copy_ip(self) -> None:
        vals = self._get_selected_vals()
        if vals:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(vals[1]))

    def _ctx_copy_creds(self) -> None:
        vals = self._get_selected_vals()
        if vals and vals[8]:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(vals[8]))

    def _ctx_ping(self) -> None:
        vals = self._get_selected_vals()
        if not vals:
            return
        ip = str(vals[1])
        self.log_message(f"Pinging {ip}...")

        def _do_ping():
            try:
                param = '-n' if os.name == 'nt' else '-c'
                result = subprocess.run(['ping', param, '4', ip],
                                        capture_output=True, text=True, timeout=10)
                for line in result.stdout.strip().split('\n'):
                    self.log_message(f"  {line}")
            except Exception as e:
                self.log_message(f"  Ping error: {e}")

        threading.Thread(target=_do_ping, daemon=True).start()

    def _ctx_show_details(self) -> None:
        vals = self._get_selected_vals()
        if not vals or not self.result:
            return
        ip = str(vals[1])
        port = str(vals[2])
        instance = str(vals[3]).split(' ')[0] if vals[3] else ''

        # Prefer matching on (ip, port, instance) to handle MSTP devices at same IP
        dev = next(
            (d for d in self.result.devices
             if d.get('ip') == ip
             and str(d.get('port', '')) == port
             and (not instance or str(d.get('instance', '')) == instance)),
            None,
        )
        if dev is None:
            return

        fp = dev.get('_fingerprint', {})
        lines = [
            "=" * 50,
            f"  DEVICE DETAILS: {ip}",
            "=" * 50,
            "",
            f"  Protocol:    {dev.get('protocol', '?')}",
            f"  IP Address:  {ip}",
            f"  Port:        {dev.get('port', '?')}",
        ]
        if dev.get('instance'):
            lines.append(f"  Instance:    {dev.get('instance')}")
        if dev.get('source_network'):
            lines.append(f"  MSTP Net:    {dev.get('source_network')}")
            lines.append(f"  MSTP MAC:    {dev.get('source_address', '?')}")
        if dev.get('via_router'):
            lines.append(f"  Via Router:  {dev.get('via_router')}")
        lines += [
            "",
            "  --- Identification ---",
            f"  Model:       {fp.get('model', '?')}",
            f"  Type:        {fp.get('device_type', '?')}",
            f"  Vendor:      {dev.get('vendor_name', dev.get('vendor', '?'))}",
            f"  Vendor ID:   {dev.get('vendor_id', '?')}",
            f"  Description: {fp.get('description', '')}",
            "",
            "  --- Access ---",
            f"  Web UI:      {fp.get('web_url', 'None detected')}",
            f"  Def. Creds:  {fp.get('default_creds', 'Unknown')}",
        ]
        if dev.get('max_apdu'):
            lines.append(f"  Max APDU:    {dev.get('max_apdu')}")
        if dev.get('segmentation'):
            lines.append(f"  Segmentation:{dev.get('segmentation')}")

        props = dev.get('properties', {})
        if props:
            lines += ["", "  --- BACnet Properties ---"]
            for k, v in props.items():
                if k != 'object_list' and v:
                    lines.append(f"  {k}: {v}")
            ol = props.get('object_list', [])
            if ol:
                lines.append(f"  Objects: {len(ol)} points")

        if dev.get('banner'):
            lines += ["", "  --- Service Info ---",
                      f"  Banner:  {dev.get('banner', '')}",
                      f"  Title:   {dev.get('title', '')}",
                      f"  Server:  {dev.get('server', '')}"]
        if dev.get('sys_descr'):
            lines += ["", "  --- SNMP ---",
                      f"  sysDescr: {dev.get('sys_descr', '')}"]
        lines += ["", "=" * 50]

        # popup
        detail_win = tk.Toplevel(self.root)
        detail_win.title(f"Device Details - {ip}")
        detail_win.geometry("620x520")
        detail_win.configure(bg=Colors.BG_DARK)

        text = tk.Text(detail_win, bg=Colors.BG_CARD, fg=Colors.TEXT,
                       font=("Consolas", 10), insertbackground=Colors.TEXT,
                       padx=12, pady=12, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        text.insert("1.0", '\n'.join(lines))
        text.configure(state='disabled')

        btn_frame = tk.Frame(detail_win, bg=Colors.BG_DARK)
        btn_frame.pack(fill=tk.X, padx=8, pady=(0, 8))
        if fp.get('web_url'):
            tk.Button(btn_frame, text="Open Web UI", bg=Colors.ACCENT, fg="#000",
                      font=("Consolas", 10, "bold"), padx=12, pady=4,
                      command=lambda: webbrowser.open(fp['web_url'])).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Copy IP", bg=Colors.BG_INPUT, fg=Colors.TEXT,
                  font=("Consolas", 10), padx=12, pady=4,
                  command=lambda: (self.root.clipboard_clear(),
                                   self.root.clipboard_append(ip))).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Close", bg=Colors.BORDER, fg=Colors.TEXT,
                  font=("Consolas", 10), padx=12, pady=4,
                  command=detail_win.destroy).pack(side=tk.RIGHT, padx=4)

    # -- export -----------------------------------------------------------

    def export_results(self) -> None:
        if not self.result or not self.result.devices:
            messagebox.showinfo("Export", "No data to export")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"hvac_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        )
        if not filepath:
            return
        try:
            if filepath.lower().endswith('.json'):
                self.result.write_json(filepath)
            else:
                self.result.write_csv(filepath)
            self.log_message(f"Exported to {filepath}")
            messagebox.showinfo("Export", f"Saved to:\n{filepath}")
        except Exception as e:
            self.log_message(f"Export error: {e}")
            messagebox.showerror("Export Error", str(e))


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

    root = tk.Tk()
    try:
        dpi = root.winfo_fpixels('1i')
        root.tk.call('tk', 'scaling', dpi / 72.0)
    except Exception:
        pass

    HVACNetworkScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
