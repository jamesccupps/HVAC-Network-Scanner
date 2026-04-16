#!/usr/bin/env python3
"""
HVAC Network Scanner - Full Protocol Discovery Tool
=====================================================
Discovers and enumerates all HVAC-related devices on building automation networks.

Protocols & Services:
  - BACnet/IP (Who-Is broadcast, I-Am parsing, device property reads)
  - BACnet MSTP (via router discovery - Who-Is-Router-To-Network)
  - Modbus TCP (port 502, Device ID, register/coil reads)
  - Tridium Niagara Fox (ports 1911, 4911)
  - OPC UA (port 4840)
  - KNXnet/IP (port 3671)
  - LonWorks/IP (port 1628)
  - EtherNet/IP CIP (port 44818)
  - Siemens S7 ISO-TSAP (port 102)
  - MQTT (ports 1883, 8883)
  - SNMP (port 161 UDP)
  - Web interfaces (80, 443, 8080, 8443) with banner/title grabbing
  - Management services (SSH 22, Telnet 23, FTP 21)

Requirements:
    pip install pymodbus --break-system-packages  (optional, for Modbus deep scan)

Author: github.com/your-username/hvac-network-scanner
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import json
import csv
import socket
import struct
import time
import ipaddress
import os
import ssl
import re
import http.client
import webbrowser
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- BACnet Constants ---
BACNET_PORT = 47808

BACNET_OBJ_TYPES = {
    0: "Analog Input", 1: "Analog Output", 2: "Analog Value",
    3: "Binary Input", 4: "Binary Output", 5: "Binary Value",
    6: "Calendar", 7: "Command", 8: "Device",
    9: "Event Enrollment", 10: "File", 11: "Group",
    12: "Loop", 13: "Multi-State Input", 14: "Multi-State Output",
    15: "Notification Class", 16: "Program", 17: "Schedule",
    18: "Averaging", 19: "Multi-State Value", 20: "Trend Log",
    21: "Life Safety Point", 22: "Life Safety Zone",
    23: "Accumulator", 24: "Pulse Converter",
    25: "Event Log", 26: "Global Group", 27: "Trend Log Multiple",
    28: "Load Control", 29: "Structured View",
    30: "Access Door", 31: "Timer", 54: "Lighting Output",
    57: "Network Port", 58: "Elevator Group", 59: "Escalator",
}

BACNET_UNITS = {
    0: "sqm", 1: "sqft", 2: "mA", 3: "A", 4: "ohm",
    5: "V", 6: "kV", 7: "MV", 8: "VA", 9: "kVA",
    17: "psi", 18: "bar", 19: "kPa", 20: "cmH2O", 21: "inH2O",
    24: "BTU/lb", 29: "W", 30: "kW", 31: "MW", 32: "BTU/h",
    33: "hp", 34: "ton", 40: "lux", 41: "fc",
    62: "C", 63: "K", 64: "F",
    65: "C-day", 66: "F-day", 67: "J", 68: "kJ", 70: "kWh",
    71: "BTU", 75: "L", 76: "gal", 77: "ft3", 78: "m3",
    80: "L/s", 81: "L/min", 82: "L/h", 84: "CFM",
    85: "m3/h", 86: "m3/s", 90: "m/s", 93: "ft/s", 94: "ft/min",
    95: "Pa", 96: "kPa", 97: "mmHg", 98: "%", 99: "%/s",
    100: "%RH", 105: "mm", 106: "cm", 107: "m", 108: "in", 109: "ft",
    110: "hr", 111: "RPM", 112: "Hz", 116: "ppm", 117: "ppb",
    118: "L/min", 119: "gal/min", 120: "s", 121: "min", 122: "h",
    145: "inWC",
}

# --- HVAC Service Definitions ---
HVAC_SERVICES = [
    (47808, "BACnet/IP", "udp"),
    (502,   "Modbus TCP", "tcp"),
    (1911,  "Niagara Fox", "tcp"),
    (4911,  "Niagara Fox TLS", "tcp"),
    (4840,  "OPC UA", "tcp"),
    (4843,  "OPC UA TLS", "tcp"),
    (3671,  "KNXnet/IP", "udp"),
    (1628,  "LonWorks/IP", "tcp"),
    (44818, "EtherNet/IP CIP", "tcp"),
    (2222,  "EtherNet/IP Config", "tcp"),
    (102,   "Siemens S7 / ISO-TSAP", "tcp"),
    (1883,  "MQTT", "tcp"),
    (8883,  "MQTT TLS", "tcp"),
    (80,    "HTTP", "tcp"),
    (443,   "HTTPS", "tcp"),
    (8080,  "HTTP-Alt", "tcp"),
    (8443,  "HTTPS-Alt", "tcp"),
    (8000,  "HTTP-8000", "tcp"),
    (8888,  "HTTP-8888", "tcp"),
    (22,    "SSH", "tcp"),
    (23,    "Telnet", "tcp"),
    (21,    "FTP", "tcp"),
    (161,   "SNMP", "udp"),
    (9090,  "WebCTRL", "tcp"),
    (9100,  "Building Ctrl", "tcp"),
    (10001, "Metasys/JCI", "tcp"),
    (11001, "Metasys ADX", "tcp"),
    (47820, "BACnet/SC", "tcp"),
]

HVAC_TCP_PORTS = sorted(set(p for p, _, t in HVAC_SERVICES if t == "tcp"))

PORT_TO_SERVICE = {}
for _p, _n, _t in HVAC_SERVICES:
    PORT_TO_SERVICE[(_p, _t)] = _n

# --- Vendor Database ---
BACNET_VENDORS = {
    0: "ASHRAE", 1: "NIST", 2: "The Trane Company", 3: "McQuay International",
    4: "PolarSoft", 5: "Johnson Controls", 6: "American Auto-Matrix",
    7: "Siemens Building Technologies", 8: "Metasys (JCI)",
    9: "Andover Controls", 10: "TAC (Schneider)", 14: "Honeywell",
    15: "Alerton", 24: "Carrier", 25: "Automated Logic (ALC)",
    27: "KMC Controls", 36: "Reliable Controls", 47: "Siemens",
    58: "Tridium / Niagara", 78: "EasyIO", 86: "Carel",
    95: "Distech Controls", 115: "Schneider Electric",
    142: "Belimo", 182: "Delta Controls", 200: "Daikin",
    260: "Trane", 343: "Siemens Desigo", 389: "Loytec",
    404: "ABB", 485: "Contemporary Controls",
}

HTTP_FINGERPRINTS = [
    (r"trane|tracer", "Trane"),
    (r"siemens|desigo", "Siemens"),
    (r"honeywell|webs|spyder|tridium|niagara", "Honeywell / Tridium"),
    (r"johnson.?controls|metasys|fec|nae", "Johnson Controls"),
    (r"schneider|ecostruxure|smartx", "Schneider Electric"),
    (r"carrier|i-?vu|alerton", "Carrier / ALC"),
    (r"automated.?logic|webctrl", "Automated Logic"),
    (r"daikin", "Daikin"),
    (r"distech", "Distech Controls"),
    (r"delta.?controls", "Delta Controls"),
    (r"reliable.?controls", "Reliable Controls"),
    (r"kmc|flexstat|bac-?net", "KMC Controls"),
    (r"carel|pco", "Carel"),
    (r"belimo", "Belimo"),
    (r"easyio", "EasyIO"),
    (r"loytec", "Loytec"),
    (r"beckhoff", "Beckhoff"),
    (r"wago", "WAGO"),
    (r"emerson|copeland|vertiv", "Emerson"),
    (r"danfoss", "Danfoss"),
    (r"mitsubishi.?electric|melco|city.?multi", "Mitsubishi Electric"),
    (r"lg.?electronics|lgap|multi.?v", "LG Electronics"),
    (r"samsung|dvm", "Samsung HVAC"),
]

# --- Device Fingerprint Engine ---
# Maps (vendor_id, clues) -> (model_guess, device_type, description)
def fingerprint_device(dev, all_services=None):
    """Analyze a device dict and return enriched info:
    model, device_type, description, web_url, default_creds."""
    info = {'model': '', 'device_type': '', 'description': '', 'web_url': '', 'default_creds': ''}
    ip = dev.get('ip', '')
    vendor_id = dev.get('vendor_id')
    instance = dev.get('instance', 0)
    protocol = dev.get('protocol', '')
    max_apdu = dev.get('max_apdu', 0)
    snet = dev.get('source_network')
    banner = dev.get('banner', '')
    title = dev.get('title', '')
    service = dev.get('service', '')
    port = dev.get('port', 0)

    # Collect all services for this IP
    ip_services = {}
    if all_services:
        for s in all_services:
            if s.get('ip') == ip and s.get('protocol') == 'Service':
                ip_services[s.get('port')] = s

    has_nucleus_ftp = any('nucleus' in ip_services.get(p, {}).get('banner', '').lower() for p in [21])
    has_nginx = any('nginx' in ip_services.get(p, {}).get('server', '').lower() for p in [80, 443])
    has_telnet = 23 in ip_services
    has_ftp = 21 in ip_services
    has_s7 = 102 in ip_services
    has_lonworks = 1628 in ip_services
    has_http = 80 in ip_services or 443 in ip_services

    # --- Trane ---
    if vendor_id == 2:
        if max_apdu == 1024 and instance in (33333, 22222):
            info['model'] = 'Trane Tracer SC+'
            info['device_type'] = 'Supervisory Controller'
            info['description'] = 'BACnet supervisory controller with integrated web server and LonWorks gateway'
            info['default_creds'] = 'admin / Tracer1$'
            if has_http:
                info['web_url'] = f"https://{ip}"
        elif max_apdu == 1024:
            info['model'] = 'Trane Tracer SC/SC+'
            info['device_type'] = 'Supervisory Controller'
            info['description'] = 'Trane BACnet supervisory controller'
            info['default_creds'] = 'admin / Tracer1$'
            if has_http:
                info['web_url'] = f"https://{ip}"
        elif max_apdu == 1476 and instance < 1000:
            info['model'] = 'Trane Tracer UC800/UC600'
            info['device_type'] = 'Unitary Controller'
            info['description'] = 'Trane unitary controller for AHU/RTU/chiller control'
            if has_http:
                info['web_url'] = f"http://{ip}"
        elif snet and max_apdu == 480:
            info['model'] = 'Trane Tracer UC400/MP581'
            info['device_type'] = 'MSTP Field Controller'
            info['description'] = f'Trane MSTP field controller on network {snet}'
        else:
            info['model'] = 'Trane Controller'
            info['device_type'] = 'Controller'

    # --- Siemens ---
    elif vendor_id == 7:
        inst_prefix = instance // 1000
        # Automation stations (x000 instances)
        if instance % 1000 == 0 and has_nucleus_ftp:
            info['model'] = 'Siemens Desigo PXC Automation Station'
            info['device_type'] = 'Automation Station'
            info['description'] = f'Desigo PXC primary automation station (Nucleus RTOS). Manages sub-controllers in the {inst_prefix}xxx range.'
            info['default_creds'] = 'ADMIN / SBTAdmin!1 | admin / admin'
            info['web_url'] = f"http://{ip}"
        elif instance % 1000 == 0:
            info['model'] = 'Siemens Desigo PXC Automation Station'
            info['device_type'] = 'Automation Station'
            info['description'] = f'Desigo PXC automation station for the {inst_prefix}xxx controller group'
            info['default_creds'] = 'ADMIN / SBTAdmin!1'
            if has_http:
                info['web_url'] = f"https://{ip}"
        # Management stations with S7
        elif has_s7:
            info['model'] = 'Siemens Desigo CC / Insight'
            info['device_type'] = 'Management Station'
            info['description'] = 'Desigo CC or Insight management workstation with S7 communication'
            info['default_creds'] = 'Check Desigo CC application login'
            if has_http:
                info['web_url'] = f"https://{ip}"
        # High instance numbers 9997/9998
        elif instance > 9000 and instance < 10000:
            info['model'] = 'Siemens Desigo CC Server'
            info['device_type'] = 'Management Station'
            info['description'] = 'Desigo CC building management server'
            if has_http:
                info['web_url'] = f"https://{ip}"
        # Field controllers with nginx (PXC Compact/Modular)
        elif has_nginx and max_apdu == 1476:
            info['model'] = 'Siemens Desigo PXC Compact/Modular'
            info['device_type'] = 'Field Controller'
            info['description'] = 'Desigo PXC field-level controller with embedded web server'
            info['default_creds'] = 'ADMIN / SBTAdmin!1'
            info['web_url'] = f"https://{ip}"
        # FTP+Telnet only (older PXC or TX-I/O)
        elif has_ftp and has_telnet and not has_nginx:
            info['model'] = 'Siemens Desigo PXC/TX-I/O'
            info['device_type'] = 'I/O Module or Legacy Controller'
            info['description'] = 'Older Desigo PXC or TX-I/O module (Nucleus RTOS, no web UI)'
            info['default_creds'] = 'FTP: admin / admin | Telnet: (varies)'
        else:
            info['model'] = 'Siemens Desigo PXC'
            info['device_type'] = 'Field Controller'
            info['description'] = 'Desigo PXC series controller'
            if has_http:
                info['web_url'] = f"https://{ip}"

    # --- Johnson Controls ---
    elif vendor_id == 5:
        if snet:
            info['model'] = 'JCI FEC/FAC Controller'
            info['device_type'] = 'MSTP Field Controller'
            info['description'] = f'Johnson Controls field equipment controller on MSTP network {snet}'
            info['default_creds'] = 'admin / admin'
        else:
            info['model'] = 'JCI Metasys Controller'
            info['device_type'] = 'Controller'
            info['default_creds'] = 'MetasysAgent / (site-specific)'

    # --- Contemporary Controls ---
    elif vendor_id == 245:
        info['model'] = 'Contemporary Controls BASRT-B'
        info['device_type'] = 'BACnet Router'
        info['description'] = 'BACnet/IP to MS/TP router (Ethernut platform)'
        info['default_creds'] = 'admin / admin'
        if has_http:
            info['web_url'] = f"http://{ip}"

    # --- Cimetrics ---
    elif vendor_id == 514:
        info['model'] = 'Cimetrics BACstac Device'
        info['device_type'] = 'Gateway / Analyzer'
        info['description'] = 'Cimetrics BACstac-based protocol gateway or analyzer'

    # --- Service-only devices ---
    elif protocol == 'Service':
        if 'unifi' in title.lower():
            info['model'] = 'Ubiquiti UniFi Gateway'
            info['device_type'] = 'Network Infrastructure'
            info['description'] = 'UniFi network gateway/controller'
            info['web_url'] = f"https://{ip}"
        elif 'basrt' in title.lower():
            info['model'] = 'Contemporary Controls BASRT-B'
            info['device_type'] = 'BACnet Router'
            info['description'] = 'BACnet/IP to MS/TP router'
            info['web_url'] = f"http://{ip}"
        elif 'nucleus' in banner.lower():
            info['model'] = 'Siemens Desigo PXC (via FTP)'
            info['device_type'] = 'Automation Station'
            info['description'] = 'Siemens controller identified by Nucleus RTOS FTP server'

    # --- SNMP devices ---
    elif protocol == 'SNMP':
        descr = dev.get('sys_descr', '').lower()
        if 'siemens' in descr or 'desigo' in descr:
            info['model'] = 'Siemens Desigo Controller'
            info['device_type'] = 'Controller'
        elif 'trane' in descr or 'tracer' in descr:
            info['model'] = 'Trane Controller'
            info['device_type'] = 'Controller'

    # Fallback
    if not info['model'] and vendor_id is not None:
        info['model'] = BACNET_VENDORS.get(vendor_id, f'Vendor #{vendor_id}') + ' Controller'
        info['device_type'] = 'Controller'

    # Generate web URL if we know there's a web interface
    if not info['web_url'] and has_http:
        if 443 in ip_services:
            info['web_url'] = f"https://{ip}"
        elif 80 in ip_services:
            info['web_url'] = f"http://{ip}"

    return info

# --- Default Credentials Database ---
DEFAULT_CREDS = {
    'Trane Tracer SC': 'admin / Tracer1$  |  Trane / Tr@n3',
    'Trane Tracer SC+': 'admin / Tracer1$',
    'Trane Tracer UC': '(no default auth on web UI)',
    'Siemens Desigo PXC': 'ADMIN / SBTAdmin!1',
    'Siemens Desigo CC': 'Application login (site-configured)',
    'Siemens Desigo Insight': 'admin / (site-configured)',
    'Johnson Controls Metasys': 'MetasysAgent / MetasysAgent  |  admin / JCI-admin',
    'Johnson Controls FEC': 'admin / admin',
    'Honeywell Tridium Niagara': 'admin / (set at install)',
    'Schneider EcoStruxure': 'USER1 / USER1  |  admin / admin',
    'Automated Logic WebCTRL': 'admin / admin',
    'Contemporary Controls BASRT-B': 'admin / admin',
    'Carrier i-Vu': 'admin / admin',
    'KMC Controls': 'admin / admin',
    'Distech Controls': 'admin / admin',
    'Reliable Controls': 'admin / admin',
    'Delta Controls': 'admin / admin',
    'Carel pCO': 'admin / admin  |  user / user',
    'Belimo': 'admin / belimo',
    'EasyIO': 'admin / admin',
    'Daikin': 'admin / admin',
    'Nucleus FTP (Siemens)': 'admin / admin  |  ADMIN / SBTAdmin!1',
}


# --- Color Palette ---
class Colors:
    BG_DARK = "#0d1117"
    BG_PANEL = "#161b22"
    BG_CARD = "#1c2333"
    BG_INPUT = "#21262d"
    BORDER = "#30363d"
    TEXT = "#e6edf3"
    TEXT_DIM = "#8b949e"
    ACCENT = "#58a6ff"
    ACCENT_HOVER = "#79c0ff"
    GREEN = "#3fb950"
    YELLOW = "#d29922"
    RED = "#f85149"
    ORANGE = "#db6d28"
    PURPLE = "#bc8cff"
    CYAN = "#39d353"
    TEAL = "#2ea043"


# --- BACnet Raw Protocol Scanner ---
class BACnetScanner:
    """Low-level BACnet/IP scanner with MSTP router discovery."""

    def __init__(self, callback=None, timeout=3):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.devices = []
        self.mstp_networks = []
        self.routers = []

    def log(self, msg):
        self.callback(msg)

    def _bind_socket(self, sock):
        """Try port 47808 first (some devices hardcode I-Am to 47808).
        Fall back to ephemeral if 47808 is already in use."""
        try:
            sock.bind(("", BACNET_PORT))
            self.log(f"  Bound to BACnet port {BACNET_PORT}")
            return BACNET_PORT
        except OSError:
            sock.bind(("", 0))
            port = sock.getsockname()[1]
            self.log(f"  Port 47808 in use, bound to ephemeral port {port}")
            return port

    def discover_devices(self, target_network=None, low_limit=None, high_limit=None):
        """Send Who-Is broadcast and collect I-Am responses."""
        self.devices = []
        self.log("Sending BACnet Who-Is broadcast...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)

            whois = self._build_whois(low_limit, high_limit)
            targets = [(target_network or "255.255.255.255", BACNET_PORT)]

            self._bind_socket(sock)

            for target in targets:
                self.log(f"  -> Broadcasting to {target[0]}:{target[1]}")
                sock.sendto(whois, target)

            seen = set()
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_iam(data, addr)
                    if device:
                        key = (device['ip'], device['instance'])
                        if key not in seen:
                            seen.add(key)
                            self.devices.append(device)
                            net_str = f" (MSTP net {device['source_network']})" if device.get('source_network') else ""
                            self.log(f"  Found device {device['instance']} at {addr[0]}{net_str}")
                except socket.timeout:
                    break
                except Exception as e:
                    self.log(f"  Parse error: {e}")

            sock.close()
        except Exception as e:
            self.log(f"BACnet discovery error: {e}")

        self.log(f"Found {len(self.devices)} BACnet device(s)")
        return self.devices

    def discover_mstp_networks(self, target_network=None):
        """Send Who-Is-Router-To-Network to find BACnet routers and MSTP networks."""
        self.mstp_networks = []
        self.routers = []
        self.log("Sending Who-Is-Router-To-Network...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)

            self._bind_socket(sock)

            # BVLC broadcast + NPDU network message type 0x06 (Who-Is-Router-To-Network)
            npdu = b'\x01\x80\x06'
            bvlc = struct.pack('!BBH', 0x81, 0x0b, 4 + len(npdu))
            packet = bvlc + npdu

            target = (target_network or "255.255.255.255", BACNET_PORT)
            self.log(f"  -> Broadcasting to {target[0]}:{target[1]}")
            sock.sendto(packet, target)

            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    networks = self._parse_iam_router(data, addr)
                    if networks:
                        self.routers.append({'ip': addr[0], 'port': addr[1], 'networks': networks})
                        self.mstp_networks.extend(networks)
                        self.log(f"  Router at {addr[0]} -> networks: {networks}")
                except socket.timeout:
                    break
                except Exception as e:
                    self.log(f"  Router parse error: {e}")

            sock.close()
        except Exception as e:
            self.log(f"Router discovery error: {e}")

        self.mstp_networks = sorted(set(self.mstp_networks))
        self.log(f"Found {len(self.routers)} router(s), {len(self.mstp_networks)} remote network(s)")
        return self.mstp_networks

    def discover_mstp_devices(self, target_network_bcast=None):
        """Send Who-Is targeted to each discovered MSTP network number."""
        if not self.mstp_networks:
            self.log("  No MSTP networks discovered")
            return []

        mstp_devices = []
        self.log(f"Probing {len(self.mstp_networks)} MSTP/remote network(s)...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout + 2)

            self._bind_socket(sock)

            target = (target_network_bcast or "255.255.255.255", BACNET_PORT)

            for net_num in self.mstp_networks:
                self.log(f"  -> Who-Is to DNET {net_num}...")
                whois = self._build_whois_to_network(net_num)
                sock.sendto(whois, target)
                time.sleep(0.1)

            seen = set()
            deadline = time.time() + self.timeout + 2
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_iam(data, addr)
                    if device:
                        key = (device.get('source_network', 0),
                               device.get('source_address', ''),
                               device['instance'])
                        if key not in seen:
                            seen.add(key)
                            device['via_router'] = addr[0]
                            mstp_devices.append(device)
                            snet = device.get('source_network', '?')
                            sadr = device.get('source_address', '?')
                            self.log(f"  MSTP device {device['instance']} net={snet} mac={sadr} (via {addr[0]})")
                except socket.timeout:
                    break
                except Exception:
                    pass

            sock.close()
        except Exception as e:
            self.log(f"MSTP discovery error: {e}")

        self.log(f"Found {len(mstp_devices)} MSTP/routed device(s)")
        return mstp_devices

    def _build_whois(self, low=None, high=None):
        if low is not None and high is not None:
            npdu = b'\x01\x20\xff\xff\x00\xff'
            apdu = b'\x10\x08'
            apdu += self._encode_context_unsigned(0, low)
            apdu += self._encode_context_unsigned(1, high)
        else:
            npdu = b'\x01\x20\xff\xff\x00\xff'
            apdu = b'\x10\x08'
        payload = npdu + apdu
        bvlc = struct.pack('!BBH', 0x81, 0x0b, 4 + len(payload))
        return bvlc + payload

    def _build_whois_to_network(self, dnet):
        npdu = bytearray()
        npdu.append(0x01)
        npdu.append(0x20)
        npdu += struct.pack('!H', dnet)
        npdu.append(0x00)
        npdu.append(0xFF)
        apdu = b'\x10\x08'
        payload = bytes(npdu) + apdu
        bvlc = struct.pack('!BBH', 0x81, 0x0b, 4 + len(payload))
        return bvlc + payload

    def _encode_context_unsigned(self, tag, value):
        if value < 0x100:
            return bytes([0x09 | (tag << 4), value & 0xFF])
        elif value < 0x10000:
            return bytes([0x0A | (tag << 4), (value >> 8) & 0xFF, value & 0xFF])
        elif value < 0x1000000:
            return bytes([0x0B | (tag << 4), (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
        else:
            return bytes([0x0C | (tag << 4), (value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])

    def _parse_iam(self, data, addr):
        try:
            if len(data) < 4 or data[0] != 0x81:
                return None
            idx = 4
            if idx >= len(data) or data[idx] != 0x01:
                return None
            npdu_ctrl = data[idx + 1]
            idx += 2

            source_network = None
            source_address = None

            if npdu_ctrl & 0x20:
                idx += 2
                dlen = data[idx]
                idx += 1 + dlen

            if npdu_ctrl & 0x08:
                source_network = struct.unpack('!H', data[idx:idx + 2])[0]
                idx += 2
                slen = data[idx]
                idx += 1
                if slen > 0:
                    sadr_bytes = data[idx:idx + slen]
                    source_address = str(sadr_bytes[0]) if slen == 1 else ':'.join(f'{b:02X}' for b in sadr_bytes)
                    idx += slen

            if npdu_ctrl & 0x20:
                idx += 1

            if idx >= len(data) or data[idx] != 0x10:
                return None
            idx += 1
            if idx >= len(data) or data[idx] != 0x00:
                return None
            idx += 1

            device = {
                'ip': addr[0], 'port': addr[1], 'instance': None,
                'max_apdu': None, 'segmentation': None, 'vendor_id': None,
                'source_network': source_network, 'source_address': source_address,
                'objects': [], 'properties': {},
            }

            if idx < len(data) and (data[idx] & 0xF0) == 0xC0:
                oid_len = data[idx] & 0x07
                idx += 1
                if oid_len >= 4:
                    oid_raw = struct.unpack('!I', data[idx:idx + 4])[0]
                    device['instance'] = oid_raw & 0x3FFFFF
                    idx += oid_len

            if idx < len(data) and (data[idx] & 0xF0) == 0x20:
                vlen = data[idx] & 0x07
                idx += 1
                if vlen <= 4 and idx + vlen <= len(data):
                    device['max_apdu'] = int.from_bytes(data[idx:idx + vlen], 'big')
                    idx += vlen

            if idx < len(data) and (data[idx] & 0xF0) == 0x90:
                vlen = data[idx] & 0x07
                idx += 1
                if vlen <= 4 and idx + vlen <= len(data):
                    val = int.from_bytes(data[idx:idx + vlen], 'big')
                    seg_map = {0: "Both", 1: "Transmit", 2: "Receive", 3: "None"}
                    device['segmentation'] = seg_map.get(val, str(val))
                    idx += vlen

            if idx < len(data) and (data[idx] & 0xF0) == 0x20:
                vlen = data[idx] & 0x07
                idx += 1
                if vlen <= 4 and idx + vlen <= len(data):
                    device['vendor_id'] = int.from_bytes(data[idx:idx + vlen], 'big')
                    idx += vlen

            if device['instance'] is not None:
                return device
        except Exception:
            pass
        return None

    def _parse_iam_router(self, data, addr):
        try:
            if len(data) < 4 or data[0] != 0x81:
                return None
            idx = 4
            if idx >= len(data) or data[idx] != 0x01:
                return None
            npdu_ctrl = data[idx + 1]
            idx += 2
            if not (npdu_ctrl & 0x80):
                return None
            if npdu_ctrl & 0x08:
                idx += 2
                slen = data[idx]
                idx += 1 + slen
            if idx >= len(data):
                return None
            msg_type = data[idx]
            idx += 1
            if msg_type != 0x01:
                return None
            networks = []
            while idx + 1 < len(data):
                net = struct.unpack('!H', data[idx:idx + 2])[0]
                networks.append(net)
                idx += 2
            return networks if networks else None
        except Exception:
            return None


# --- Raw BACnet ReadProperty Scanner (no dependencies) ---
class RawBACnetReader:
    """Read BACnet properties using raw UDP packets. No BAC0/bacpypes needed."""

    OBJ_TYPE_MAP = {
        'analogInput': 0, 'analogOutput': 1, 'analogValue': 2,
        'binaryInput': 3, 'binaryOutput': 4, 'binaryValue': 5,
        'device': 8, 'multiStateInput': 13, 'multiStateOutput': 14,
        'multiStateValue': 19, 'schedule': 17, 'trendLog': 20,
        'notificationClass': 15, 'loop': 12, 'program': 16,
    }
    OBJ_TYPE_NAMES = {v: k for k, v in OBJ_TYPE_MAP.items()}
    OBJ_TYPE_NAMES.update(BACNET_OBJ_TYPES)  # merge with our display names

    PROP_MAP = {
        'objectName': 77, 'objectList': 76, 'presentValue': 85,
        'description': 28, 'units': 117, 'vendorName': 121,
        'modelName': 70, 'firmwareRevision': 44,
        'applicationSoftwareVersion': 12, 'objectIdentifier': 75,
        'protocolVersion': 98, 'protocolRevision': 139,
        # Aliases for convenience
        'object-name': 77, 'vendor-name': 121, 'model-name': 70,
        'firmware-revision': 44, 'application-software-version': 12,
        'protocol-version': 98, 'protocol-revision': 139,
    }

    def __init__(self, callback=None, timeout=3):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self._invoke_id = 0

    def log(self, msg):
        self.callback(msg)

    def connect(self):
        self.log("Using raw BACnet ReadProperty (no BAC0 needed)")
        return True

    def disconnect(self):
        pass

    def _next_invoke_id(self):
        self._invoke_id = (self._invoke_id + 1) % 256
        return self._invoke_id

    # Reverse map: display name -> numeric type (e.g. "Analog Input" -> 0)
    OBJ_NAME_TO_NUM = {v: k for k, v in BACNET_OBJ_TYPES.items()}
    # Also add camelCase and lowercase variants
    for _k, _v in list(OBJ_TYPE_MAP.items()):
        OBJ_NAME_TO_NUM[_k] = _v
        OBJ_NAME_TO_NUM[_k.lower()] = _v

    def _encode_object_id(self, obj_type, obj_instance):
        """Encode a BACnet Object Identifier as 4 bytes."""
        if isinstance(obj_type, str):
            # Try exact match first, then display name, then camelCase, then lowercase
            if obj_type in self.OBJ_NAME_TO_NUM:
                obj_type = self.OBJ_NAME_TO_NUM[obj_type]
            elif obj_type in self.OBJ_TYPE_MAP:
                obj_type = self.OBJ_TYPE_MAP[obj_type]
            elif obj_type.lower() in self.OBJ_NAME_TO_NUM:
                obj_type = self.OBJ_NAME_TO_NUM[obj_type.lower()]
            else:
                # Try to extract numeric type from "type-N" format
                import re as _re
                m = _re.match(r'type-(\d+)', obj_type)
                obj_type = int(m.group(1)) if m else 8
        oid = ((obj_type & 0x3FF) << 22) | (obj_instance & 0x3FFFFF)
        return struct.pack('!I', oid)

    def _encode_property_id(self, prop):
        """Encode a property identifier."""
        if isinstance(prop, str):
            prop = self.PROP_MAP.get(prop, 85)
        if prop < 0x100:
            return bytes([prop])
        else:
            return struct.pack('!H', prop)

    def _build_read_property(self, obj_type, obj_instance, prop_id, array_index=None):
        """Build a complete BACnet ReadProperty packet."""
        invoke_id = self._next_invoke_id()

        # NPDU: version=1, control=0x04 (expecting reply)
        npdu = b'\x01\x04'

        # APDU: Confirmed Request
        # PDU type 0, segmented=0, more=0, segmented-resp-accepted=0
        # max-segments=0 (unspecified), max-apdu=5 (1476 bytes)
        apdu = bytes([0x00, 0x05, invoke_id, 0x0C])  # service choice 12 = ReadProperty

        # Context tag 0: Object Identifier (4 bytes, context class)
        oid_bytes = self._encode_object_id(obj_type, obj_instance)
        apdu += bytes([0x0C]) + oid_bytes  # tag 0, length 4, context

        # Context tag 1: Property Identifier
        prop_val = self.PROP_MAP.get(prop_id, prop_id) if isinstance(prop_id, str) else prop_id
        if prop_val < 0x100:
            apdu += bytes([0x19, prop_val])  # tag 1, length 1
        else:
            apdu += bytes([0x1A, (prop_val >> 8) & 0xFF, prop_val & 0xFF])

        # Context tag 2: Array Index (optional)
        if array_index is not None:
            if array_index < 0x100:
                apdu += bytes([0x29, array_index])
            else:
                apdu += bytes([0x2A, (array_index >> 8) & 0xFF, array_index & 0xFF])

        payload = npdu + apdu
        # BVLC: Original-Unicast-NPDU (function 0x0a)
        bvlc = struct.pack('!BBH', 0x81, 0x0a, 4 + len(payload))
        return bvlc + payload, invoke_id

    def read_property(self, ip, obj_type, obj_instance, prop_name, array_index=None):
        """Send ReadProperty and parse the response. Returns value or None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.bind(("", 0))

            packet, invoke_id = self._build_read_property(obj_type, obj_instance, prop_name, array_index)
            sock.sendto(packet, (ip, BACNET_PORT))

            data, addr = sock.recvfrom(4096)
            sock.close()

            return self._parse_read_property_response(data)

        except socket.timeout:
            return None
        except Exception:
            return None

    def _parse_read_property_response(self, data):
        """Parse a ReadProperty-ACK and extract the value."""
        try:
            if len(data) < 4 or data[0] != 0x81:
                return None

            idx = 4  # skip BVLC
            if idx >= len(data) or data[idx] != 0x01:
                return None

            npdu_ctrl = data[idx + 1]
            idx += 2

            # Skip SNET/SADR if present
            if npdu_ctrl & 0x08:
                idx += 2
                slen = data[idx]
                idx += 1 + slen

            if idx >= len(data):
                return None

            pdu_type = (data[idx] >> 4) & 0x0F

            # Complex-ACK (type 3)
            if pdu_type == 3:
                idx += 1  # skip pdu type/flags
                idx += 1  # skip invoke id
                service = data[idx]
                idx += 1

                if service != 12:  # Not ReadProperty-ACK
                    return None

                # Skip object identifier (context tag 0, 4 bytes)
                if idx < len(data) and data[idx] == 0x0C:
                    idx += 5  # tag byte + 4 bytes OID

                # Skip property identifier (context tag 1)
                if idx < len(data) and (data[idx] & 0xF8) == 0x18:
                    plen = data[idx] & 0x07
                    idx += 1 + plen

                # Skip optional array index (context tag 2)
                if idx < len(data) and (data[idx] & 0xF8) == 0x28:
                    plen = data[idx] & 0x07
                    idx += 1 + plen

                # Opening tag 3 for property value
                if idx < len(data) and data[idx] == 0x3E:
                    idx += 1
                    return self._parse_application_value(data, idx)

            # Error response (type 5)
            elif pdu_type == 5:
                return None

        except Exception:
            return None
        return None

    def _parse_application_value(self, data, idx):
        """Parse a BACnet application-tagged value."""
        if idx >= len(data):
            return None

        tag_byte = data[idx]
        tag_class = (tag_byte >> 3) & 0x01  # 0=application, 1=context
        tag_num = (tag_byte >> 4) & 0x0F
        length = tag_byte & 0x07

        # Extended length
        if length == 5 and idx + 1 < len(data):
            idx += 1
            length = data[idx]

        idx += 1

        if idx + length > len(data):
            return None

        value_bytes = data[idx:idx + length]

        if tag_class == 0:  # Application tag
            if tag_num == 0:  # Null
                return None
            elif tag_num == 1:  # Boolean
                return bool(length)
            elif tag_num == 2:  # Unsigned Integer
                return int.from_bytes(value_bytes, 'big')
            elif tag_num == 3:  # Signed Integer
                return int.from_bytes(value_bytes, 'big', signed=True)
            elif tag_num == 4:  # Real (float)
                if length == 4:
                    return struct.unpack('!f', value_bytes)[0]
                return None
            elif tag_num == 5:  # Double
                if length == 8:
                    return struct.unpack('!d', value_bytes)[0]
                return None
            elif tag_num == 6:  # Octet String
                return value_bytes.hex()
            elif tag_num == 7:  # Character String
                if len(value_bytes) > 0:
                    encoding = value_bytes[0]
                    text = value_bytes[1:]
                    if encoding == 0:  # UTF-8
                        return text.decode('utf-8', errors='replace')
                    else:
                        return text.decode('latin-1', errors='replace')
                return ""
            elif tag_num == 8:  # Bit String
                return value_bytes.hex()
            elif tag_num == 9:  # Enumerated
                val = int.from_bytes(value_bytes, 'big')
                return val
            elif tag_num == 12:  # Object Identifier
                if length >= 4:
                    oid = struct.unpack('!I', value_bytes[:4])[0]
                    obj_type = (oid >> 22) & 0x3FF
                    obj_inst = oid & 0x3FFFFF
                    type_name = self.OBJ_TYPE_NAMES.get(obj_type, f"type-{obj_type}")
                    return (type_name, obj_inst)

        return value_bytes.hex()

    def read_object_list(self, ip, device_instance):
        """Read the object list from a device. Returns list of (type, instance) tuples."""
        objects = []

        # First read objectList length (array index 0)
        count = self.read_property(ip, 8, device_instance, 'objectList', array_index=0)
        if count is None or not isinstance(count, int):
            self.log(f"    Could not read object list count (got: {count})")
            return []

        if count == 0:
            return []

        self.log(f"    Object list has {count} entries")
        cap = min(count, 500)

        # Read each object one by one
        for i in range(1, cap + 1):
            result = self.read_property(ip, 8, device_instance, 'objectList', array_index=i)
            if result and isinstance(result, tuple):
                objects.append(result)

        self.log(f"    Successfully read {len(objects)} of {count} objects")
        return objects


# --- Modbus TCP Scanner ---
class ModbusScanner:
    COMMON_UNIT_IDS = [1, 2, 3, 4, 5, 10, 100, 247]

    def __init__(self, callback=None, timeout=1.0):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.devices = []

    def log(self, msg):
        self.callback(msg)

    def scan_host(self, ip, port=502, unit_ids=None):
        if unit_ids is None:
            unit_ids = self.COMMON_UNIT_IDS
        results = []
        for uid in unit_ids:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                req = struct.pack('!HHHBBBB', 0x0001, 0x0000, 0x0005, uid, 0x2B, 0x0E, 0x01, 0x00)
                sock.send(req)
                resp = sock.recv(1024)
                if resp and len(resp) >= 9:
                    device_info = self._parse_device_id_response(resp)
                    device_info.update({'ip': ip, 'port': port, 'unit_id': uid})
                    results.append(device_info)
                    self.log(f"  Modbus device at {ip}:{port} unit={uid}")
                sock.close()
            except (socket.timeout, ConnectionRefusedError, OSError):
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(self.timeout)
                    sock2.connect((ip, port))
                    req2 = struct.pack('!HHHBBHH', 0x0001, 0x0000, 0x0006, uid, 0x03, 0x0000, 0x0001)
                    sock2.send(req2)
                    resp2 = sock2.recv(1024)
                    if resp2 and len(resp2) >= 9:
                        fc = resp2[7]
                        detected = None
                        if fc == 0x03:
                            detected = 'holding_register_read'
                        elif fc == 0x83:
                            detected = 'exception_response'
                        if detected:
                            results.append({'ip': ip, 'port': port, 'unit_id': uid,
                                           'vendor': 'Unknown', 'product': 'Unknown',
                                           'version': 'Unknown', 'detected_via': detected})
                            self.log(f"  Modbus device at {ip}:{port} unit={uid} ({detected})")
                    sock2.close()
                except Exception:
                    pass
            except Exception:
                pass
        return results

    def scan_network(self, network_cidr, port=502, unit_ids=None, max_workers=50):
        self.devices = []
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError as e:
            self.log(f"Invalid network: {e}")
            return []
        hosts = list(network.hosts())
        self.log(f"Scanning {len(hosts)} hosts for Modbus TCP on port {port}...")
        open_hosts = []
        def check_port(ip):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                result = s.connect_ex((str(ip), port))
                s.close()
                if result == 0:
                    return str(ip)
            except Exception:
                pass
            return None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check_port, h): h for h in hosts}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    open_hosts.append(result)
                    self.log(f"  -> Port {port} open on {result}")
        self.log(f"  Found {len(open_hosts)} host(s) with port {port} open")
        for ip in open_hosts:
            devs = self.scan_host(ip, port, unit_ids)
            self.devices.extend(devs)
        self.log(f"Found {len(self.devices)} Modbus device(s)")
        return self.devices

    def read_registers(self, ip, port, unit_id, start=0, count=10, func_code=3):
        results = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            req = struct.pack('!HHHBBHH', 0x0001, 0x0000, 0x0006, unit_id, func_code, start, count)
            sock.send(req)
            resp = sock.recv(4096)
            if resp and len(resp) >= 9:
                fc = resp[7]
                if fc == func_code:
                    byte_count = resp[8]
                    data = resp[9:9 + byte_count]
                    for i in range(0, len(data), 2):
                        if i + 1 < len(data):
                            val = struct.unpack('!H', data[i:i + 2])[0]
                            results.append({'register': start + (i // 2), 'value': val, 'hex': f"0x{val:04X}"})
            sock.close()
        except Exception as e:
            self.log(f"  Register read error: {e}")
        return results

    def read_coils(self, ip, port, unit_id, start=0, count=16):
        results = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            req = struct.pack('!HHHBBHH', 0x0001, 0x0000, 0x0006, unit_id, 0x01, start, count)
            sock.send(req)
            resp = sock.recv(4096)
            if resp and len(resp) >= 9 and resp[7] == 0x01:
                byte_count = resp[8]
                data = resp[9:9 + byte_count]
                for i in range(count):
                    byte_idx = i // 8
                    bit_idx = i % 8
                    if byte_idx < len(data):
                        val = (data[byte_idx] >> bit_idx) & 1
                        results.append({'coil': start + i, 'value': val, 'state': 'ON' if val else 'OFF'})
            sock.close()
        except Exception as e:
            self.log(f"  Coil read error: {e}")
        return results

    def _parse_device_id_response(self, resp):
        info = {'vendor': 'Unknown', 'product': 'Unknown', 'version': 'Unknown', 'detected_via': 'device_id'}
        try:
            if len(resp) < 15:
                return info
            idx = 13
            num_objects = resp[idx] if idx < len(resp) else 0
            idx += 1
            obj_names = {0: 'vendor', 1: 'product', 2: 'version', 3: 'vendor_url', 4: 'product_name', 5: 'model_name'}
            for _ in range(num_objects):
                if idx + 2 > len(resp):
                    break
                obj_id = resp[idx]
                obj_len = resp[idx + 1]
                idx += 2
                if idx + obj_len > len(resp):
                    break
                val = resp[idx:idx + obj_len].decode('ascii', errors='replace')
                key = obj_names.get(obj_id)
                if key:
                    info[key] = val
                idx += obj_len
        except Exception:
            pass
        return info


# --- HVAC Service Scanner ---
class HVACServiceScanner:
    """Scan for HVAC-related TCP services: Niagara, OPC UA, KNX, HTTP banners, etc."""

    def __init__(self, callback=None, timeout=1.5):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.services = []

    def log(self, msg):
        self.callback(msg)

    def scan_network(self, network_cidr, ports=None, max_workers=80, stop_event=None):
        self.services = []
        if ports is None:
            ports = HVAC_TCP_PORTS
        ports = [p for p in ports if p not in (47808, 502)]
        if not ports:
            return []
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError as e:
            self.log(f"Invalid network: {e}")
            return []
        hosts = [str(h) for h in network.hosts()]
        self.log(f"Scanning {len(hosts)} hosts x {len(ports)} HVAC service ports...")
        targets = [(ip, port) for ip in hosts for port in ports]

        def probe(target):
            if stop_event and stop_event.is_set():
                return None
            ip, port = target
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    return (ip, port)
            except Exception:
                pass
            return None

        open_services = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(probe, t): t for t in targets}
            for f in as_completed(futures):
                if stop_event and stop_event.is_set():
                    break
                result = f.result()
                if result:
                    ip, port = result
                    svc_name = PORT_TO_SERVICE.get((port, "tcp"), f"TCP/{port}")
                    open_services.append((ip, port, svc_name))
                    self.log(f"  {ip}:{port} - {svc_name}")

        self.log(f"  Found {len(open_services)} open HVAC service port(s)")

        for ip, port, svc_name in open_services:
            if stop_event and stop_event.is_set():
                break
            service_info = {
                'ip': ip, 'port': port, 'service': svc_name,
                'protocol': 'Service', 'vendor': '', 'product': '',
                'version': '', 'banner': '', 'title': '',
            }

            if port in (80, 8080, 8000, 8888, 9090):
                service_info.update(self._http_banner(ip, port, use_ssl=False))
            elif port in (443, 8443):
                service_info.update(self._http_banner(ip, port, use_ssl=True))
            elif port in (1911, 4911):
                service_info.update(self._probe_niagara_fox(ip, port))
            elif port == 4840:
                service_info['product'] = 'OPC UA Server'
            elif port == 102:
                service_info.update(self._probe_s7(ip, port))
            elif port == 44818:
                service_info.update(self._probe_ethernet_ip(ip, port))
            elif port in (22, 23, 21):
                service_info['banner'] = self._tcp_banner(ip, port)
            elif port in (1883, 8883):
                service_info['product'] = 'MQTT Broker'

            all_text = ' '.join([service_info.get(k, '') for k in ('banner', 'title', 'server', 'product')]).lower()
            for pattern, vendor in HTTP_FINGERPRINTS:
                if re.search(pattern, all_text):
                    service_info['vendor'] = vendor
                    break

            self.services.append(service_info)

        self.log(f"Identified {len(self.services)} HVAC service(s)")
        return self.services

    def _http_banner(self, ip, port, use_ssl=False):
        info = {'server': '', 'title': '', 'banner': ''}
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(ip, port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=self.timeout)
            conn.request("GET", "/", headers={"User-Agent": "HVAC-Scanner/1.0"})
            resp = conn.getresponse()
            info['server'] = resp.getheader('Server', '')
            info['banner'] = f"HTTP/{resp.status} {resp.reason} | Server: {info['server']}"
            body = resp.read(4096).decode('utf-8', errors='replace')
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
            if title_match:
                info['title'] = title_match.group(1).strip()
            if not info['title']:
                login_match = re.search(r'(login|sign.?in|webctrl|niagara|metasys|desigo)', body, re.IGNORECASE)
                if login_match:
                    info['title'] = f"[Login Page: {login_match.group(1)}]"
            conn.close()
        except Exception:
            pass
        return info

    def _probe_niagara_fox(self, ip, port):
        info = {'product': 'Niagara Fox', 'vendor': 'Honeywell / Tridium'}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.send(b'fox a 1 -1 fox hello\n')
            resp = sock.recv(2048).decode('ascii', errors='replace')
            if 'fox' in resp.lower():
                info['banner'] = resp.strip()[:200]
                for line in resp.split('\n'):
                    if 'version' in line.lower():
                        info['version'] = line.strip()
                    elif 'host' in line.lower():
                        info['product'] = f"Niagara ({line.strip()})"
            sock.close()
        except Exception:
            pass
        return info

    def _probe_s7(self, ip, port):
        info = {'vendor': 'Siemens', 'product': 'S7 Controller'}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            cotp_cr = bytes([0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
                             0x00, 0x01, 0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02,
                             0x01, 0x00, 0xC2, 0x02, 0x01, 0x02])
            sock.send(cotp_cr)
            resp = sock.recv(1024)
            if resp and len(resp) >= 4 and resp[0] == 0x03:
                info['banner'] = f"S7 ISO-TSAP response ({len(resp)} bytes)"
            sock.close()
        except Exception:
            pass
        return info

    def _probe_ethernet_ip(self, ip, port):
        info = {'product': 'EtherNet/IP Device'}
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            list_id = struct.pack('<HHIHIQ', 0x0063, 0x0000, 0x00000000, 0x00000000, 0x00000000, 0)
            sock.send(list_id)
            resp = sock.recv(4096)
            if resp and len(resp) >= 26:
                cmd = struct.unpack('<H', resp[0:2])[0]
                if cmd == 0x0063:
                    info['banner'] = f"CIP List Identity ({len(resp)} bytes)"
                    try:
                        ascii_parts = re.findall(rb'[\x20-\x7E]{4,}', resp)
                        if ascii_parts:
                            info['product'] = ascii_parts[0].decode('ascii')[:64]
                    except Exception:
                        pass
            sock.close()
        except Exception:
            pass
        return info

    def _tcp_banner(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode('ascii', errors='replace').strip()
            sock.close()
            return banner[:200]
        except Exception:
            return ""


# --- SNMP Scanner ---
class SNMPScanner:
    """Raw UDP SNMP v1/v2c scanner."""

    def __init__(self, callback=None, timeout=1.5):
        self.callback = callback or (lambda msg: None)
        self.timeout = timeout
        self.devices = []

    def log(self, msg):
        self.callback(msg)

    def scan_network(self, network_cidr, community=b'public', max_workers=50, stop_event=None):
        self.devices = []
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
        except ValueError:
            return []
        hosts = [str(h) for h in network.hosts()]
        self.log(f"Scanning {len(hosts)} hosts for SNMP...")

        def probe_snmp(ip):
            if stop_event and stop_event.is_set():
                return None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                pkt = self._build_snmp_get(community)
                sock.sendto(pkt, (ip, 161))
                resp, _ = sock.recvfrom(4096)
                sock.close()
                descr = self._parse_snmp_response(resp)
                if descr is not None:
                    return {'ip': ip, 'port': 161, 'sys_descr': descr}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(probe_snmp, h): h for h in hosts}
            for f in as_completed(futures):
                if stop_event and stop_event.is_set():
                    break
                result = f.result()
                if result:
                    self.devices.append(result)
                    self.log(f"  SNMP at {result['ip']}: {result['sys_descr'][:80]}")

        self.log(f"Found {len(self.devices)} SNMP device(s)")
        return self.devices

    def _build_snmp_get(self, community):
        oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        null_val = bytes([0x05, 0x00])
        varbind = oid + null_val
        varbind_seq = bytes([0x30, len(varbind)]) + varbind
        varbind_list = bytes([0x30, len(varbind_seq)]) + varbind_seq
        request_id = bytes([0x02, 0x01, 0x01])
        error_status = bytes([0x02, 0x01, 0x00])
        error_index = bytes([0x02, 0x01, 0x00])
        pdu_content = request_id + error_status + error_index + varbind_list
        pdu = bytes([0xA0, len(pdu_content)]) + pdu_content
        version = bytes([0x02, 0x01, 0x00])
        comm = bytes([0x04, len(community)]) + community
        msg_content = version + comm + pdu
        message = bytes([0x30, len(msg_content)]) + msg_content
        return message

    def _parse_snmp_response(self, data):
        try:
            oid_marker = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
            pos = data.find(oid_marker)
            if pos < 0:
                return None
            idx = pos - 2
            oid_len = data[idx + 1]
            idx = idx + 2 + oid_len
            if idx >= len(data):
                return None
            val_tag = data[idx]
            val_len = data[idx + 1]
            idx += 2
            if val_tag == 0x04:
                return data[idx:idx + val_len].decode('ascii', errors='replace')
            elif val_tag == 0x02:
                return str(int.from_bytes(data[idx:idx + val_len], 'big'))
        except Exception:
            pass
        return None


# --- Main GUI Application ---
class HVACNetworkScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("HVAC Network Scanner - Full Protocol Discovery")
        self.root.geometry("1440x920")
        self.root.configure(bg=Colors.BG_DARK)
        self.root.minsize(1100, 700)

        self.all_devices = []
        self.scan_running = False
        self.stop_event = threading.Event()
        self._sort_state = {}

        self.bacnet_scanner = BACnetScanner(callback=self.log_message)
        self.modbus_scanner = ModbusScanner(callback=self.log_message)
        self.service_scanner = HVACServiceScanner(callback=self.log_message)
        self.snmp_scanner = SNMPScanner(callback=self.log_message)

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(".", background=Colors.BG_DARK, foreground=Colors.TEXT, fieldbackground=Colors.BG_INPUT, borderwidth=0)
        style.configure("Dark.TFrame", background=Colors.BG_DARK)
        style.configure("Card.TFrame", background=Colors.BG_PANEL)
        style.configure("Title.TLabel", background=Colors.BG_DARK, foreground=Colors.ACCENT, font=("Consolas", 18, "bold"))
        style.configure("Subtitle.TLabel", background=Colors.BG_DARK, foreground=Colors.TEXT_DIM, font=("Consolas", 9))
        style.configure("Header.TLabel", background=Colors.BG_PANEL, foreground=Colors.ACCENT, font=("Consolas", 11, "bold"))
        style.configure("Info.TLabel", background=Colors.BG_PANEL, foreground=Colors.TEXT, font=("Consolas", 10))
        style.configure("Dim.TLabel", background=Colors.BG_PANEL, foreground=Colors.TEXT_DIM, font=("Consolas", 9))
        style.configure("Status.TLabel", background=Colors.BG_DARK, foreground=Colors.GREEN, font=("Consolas", 9))
        style.configure("Accent.TButton", background=Colors.ACCENT, foreground="#000", font=("Consolas", 10, "bold"), padding=(12, 6))
        style.map("Accent.TButton", background=[("active", Colors.ACCENT_HOVER), ("disabled", Colors.BORDER)])
        style.configure("Danger.TButton", background=Colors.RED, foreground="#000", font=("Consolas", 10, "bold"), padding=(12, 6))
        style.map("Danger.TButton", background=[("active", "#ff6e6e"), ("disabled", Colors.BORDER)])
        style.configure("Export.TButton", background=Colors.TEAL, foreground="#000", font=("Consolas", 10, "bold"), padding=(12, 6))
        style.map("Export.TButton", background=[("active", Colors.GREEN), ("disabled", Colors.BORDER)])
        style.configure("Treeview", background=Colors.BG_CARD, foreground=Colors.TEXT, fieldbackground=Colors.BG_CARD, rowheight=24, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=Colors.BG_INPUT, foreground=Colors.ACCENT, font=("Consolas", 9, "bold"))
        style.map("Treeview", background=[("selected", Colors.ACCENT)], foreground=[("selected", "#000")])
        style.configure("TNotebook", background=Colors.BG_DARK)
        style.configure("TNotebook.Tab", background=Colors.BG_PANEL, foreground=Colors.TEXT_DIM, font=("Consolas", 10), padding=(12, 6))
        style.map("TNotebook.Tab", background=[("selected", Colors.BG_CARD)], foreground=[("selected", Colors.ACCENT)])

    def _build_ui(self):
        hdr = ttk.Frame(self.root, style="Dark.TFrame")
        hdr.pack(fill=tk.X, padx=16, pady=(12, 4))
        ttk.Label(hdr, text="HVAC Network Scanner", style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(hdr, text="BACnet/IP  MSTP  Modbus  Services  SNMP", style="Subtitle.TLabel").pack(side=tk.LEFT, padx=(12, 0), pady=(6, 0))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(hdr, textvariable=self.status_var, style="Status.TLabel").pack(side=tk.RIGHT)

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

        self.scan_bacnet = tk.BooleanVar(value=True)
        self.scan_mstp = tk.BooleanVar(value=True)
        self.scan_modbus = tk.BooleanVar(value=True)
        self.scan_services = tk.BooleanVar(value=True)
        self.scan_snmp = tk.BooleanVar(value=True)
        self.deep_scan = tk.BooleanVar(value=True)

        cb_frame = ttk.Frame(inner, style="Card.TFrame")
        cb_frame.pack(side=tk.LEFT, padx=(0, 12))
        for text, var, color in [("BACnet", self.scan_bacnet, Colors.GREEN), ("MSTP", self.scan_mstp, Colors.CYAN),
                                  ("Modbus", self.scan_modbus, Colors.YELLOW), ("Services", self.scan_services, Colors.ORANGE),
                                  ("SNMP", self.scan_snmp, Colors.PURPLE), ("Deep", self.deep_scan, Colors.ACCENT)]:
            tk.Checkbutton(cb_frame, text=text, variable=var, bg=Colors.BG_PANEL, fg=color,
                           selectcolor=Colors.BG_INPUT, activebackground=Colors.BG_PANEL,
                           activeforeground=color, font=("Consolas", 9)).pack(side=tk.LEFT, padx=3)

        self.scan_btn = ttk.Button(inner, text="SCAN", style="Accent.TButton", command=self.start_scan)
        self.scan_btn.pack(side=tk.RIGHT, padx=4)
        self.stop_btn = ttk.Button(inner, text="STOP", style="Danger.TButton", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side=tk.RIGHT, padx=4)
        self.export_btn = ttk.Button(inner, text="EXPORT", style="Export.TButton", command=self.export_results, state='disabled')
        self.export_btn.pack(side=tk.RIGHT, padx=4)

        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=16, pady=4)

        top_frame = ttk.Frame(paned, style="Dark.TFrame")
        paned.add(top_frame, weight=3)
        self.notebook = ttk.Notebook(top_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: All Devices
        dev_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(dev_frame, text="  All Devices  ")
        columns = ("protocol", "ip", "port", "address", "model", "device_type", "vendor", "web_url", "default_creds", "description")
        self.device_tree = ttk.Treeview(dev_frame, columns=columns, show="headings", selectmode="browse")
        for col, text, width in [("protocol", "Protocol", 85), ("ip", "IP Address", 115), ("port", "Port", 50),
                                  ("address", "Device ID", 85), ("model", "Model", 200),
                                  ("device_type", "Type", 130), ("vendor", "Vendor", 140),
                                  ("web_url", "Web UI", 130), ("default_creds", "Default Creds", 160),
                                  ("description", "Description", 320)]:
            self._setup_sortable(self.device_tree, col, text)
            self.device_tree.column(col, width=width, minwidth=40)
        dev_scroll = ttk.Scrollbar(dev_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=dev_scroll.set)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        dev_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.bind("<<TreeviewSelect>>", self._on_device_select)
        self.device_tree.bind("<Double-1>", self._on_device_double_click)
        self.device_tree.bind("<Button-3>", self._on_device_right_click)

        # Context menu for device tree
        self.ctx_menu = tk.Menu(self.root, tearoff=0, bg=Colors.BG_PANEL, fg=Colors.TEXT,
                                activebackground=Colors.ACCENT, activeforeground="#000",
                                font=("Consolas", 10))
        self.ctx_menu.add_command(label="Open Web UI", command=self._ctx_open_web)
        self.ctx_menu.add_command(label="Open Web UI (HTTP)", command=lambda: self._ctx_open_web(force_http=True))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Copy IP Address", command=self._ctx_copy_ip)
        self.ctx_menu.add_command(label="Copy Default Credentials", command=self._ctx_copy_creds)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Show Device Details", command=self._ctx_show_details)
        self.ctx_menu.add_command(label="Ping Device", command=self._ctx_ping)

        # Tab 2: BACnet Points
        pts_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(pts_frame, text="  BACnet Points  ")
        pts_columns = ("device", "type", "address", "name", "value", "units", "description")
        self.points_tree = ttk.Treeview(pts_frame, columns=pts_columns, show="headings", selectmode="browse")
        for col, text, width in [("device", "Device", 130), ("type", "Object Type", 130), ("address", "Instance", 80),
                                  ("name", "Name", 240), ("value", "Present Value", 100),
                                  ("units", "Units", 70), ("description", "Description", 280)]:
            self._setup_sortable(self.points_tree, col, text)
            self.points_tree.column(col, width=width, minwidth=50)
        pts_scroll = ttk.Scrollbar(pts_frame, orient="vertical", command=self.points_tree.yview)
        self.points_tree.configure(yscrollcommand=pts_scroll.set)
        self.points_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        pts_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 3: Modbus Registers
        reg_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(reg_frame, text="  Modbus Registers  ")
        reg_columns = ("device", "reg_type", "address", "value_dec", "value_hex", "value_bin")
        self.reg_tree = ttk.Treeview(reg_frame, columns=reg_columns, show="headings", selectmode="browse")
        for col, text, width in [("device", "Device", 150), ("reg_type", "Register Type", 120),
                                  ("address", "Address", 70), ("value_dec", "Value (Dec)", 90),
                                  ("value_hex", "Value (Hex)", 90), ("value_bin", "Value (Bin)", 170)]:
            self._setup_sortable(self.reg_tree, col, text)
            self.reg_tree.column(col, width=width, minwidth=50)
        reg_scroll = ttk.Scrollbar(reg_frame, orient="vertical", command=self.reg_tree.yview)
        self.reg_tree.configure(yscrollcommand=reg_scroll.set)
        self.reg_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        reg_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 4: Services
        svc_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(svc_frame, text="  Services  ")
        svc_columns = ("ip", "port", "service", "vendor", "product", "title", "banner")
        self.svc_tree = ttk.Treeview(svc_frame, columns=svc_columns, show="headings", selectmode="browse")
        for col, text, width in [("ip", "IP Address", 130), ("port", "Port", 55), ("service", "Service", 130),
                                  ("vendor", "Vendor", 160), ("product", "Product", 160),
                                  ("title", "Page Title", 200), ("banner", "Banner", 300)]:
            self._setup_sortable(self.svc_tree, col, text)
            self.svc_tree.column(col, width=width, minwidth=50)
        svc_scroll = ttk.Scrollbar(svc_frame, orient="vertical", command=self.svc_tree.yview)
        self.svc_tree.configure(yscrollcommand=svc_scroll.set)
        self.svc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        svc_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Tab 5: Raw JSON
        raw_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(raw_frame, text="  { } Raw Data  ")
        self.raw_text = tk.Text(raw_frame, bg=Colors.BG_CARD, fg=Colors.TEXT, font=("Consolas", 9),
                                insertbackground=Colors.TEXT, wrap=tk.NONE, padx=8, pady=8)
        raw_hscroll = ttk.Scrollbar(raw_frame, orient="horizontal", command=self.raw_text.xview)
        raw_vscroll = ttk.Scrollbar(raw_frame, orient="vertical", command=self.raw_text.yview)
        self.raw_text.configure(xscrollcommand=raw_hscroll.set, yscrollcommand=raw_vscroll.set)
        raw_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        raw_vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.raw_text.pack(fill=tk.BOTH, expand=True)

        # Log Console
        bot_frame = ttk.Frame(paned, style="Dark.TFrame")
        paned.add(bot_frame, weight=1)
        log_header = ttk.Frame(bot_frame, style="Card.TFrame")
        log_header.pack(fill=tk.X)
        ttk.Label(log_header, text=" Scan Log", style="Header.TLabel").pack(side=tk.LEFT, padx=8, pady=4)
        self.log_text = tk.Text(bot_frame, bg=Colors.BG_CARD, fg=Colors.TEXT_DIM, font=("Consolas", 9),
                                insertbackground=Colors.TEXT, height=8, padx=8, pady=4)
        log_scroll = ttk.Scrollbar(bot_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_configure("error", foreground=Colors.RED)
        self.log_text.tag_configure("success", foreground=Colors.GREEN)
        self.log_text.tag_configure("warn", foreground=Colors.YELLOW)
        self.log_text.tag_configure("info", foreground=Colors.ACCENT)

        sbar = ttk.Frame(self.root, style="Card.TFrame")
        sbar.pack(fill=tk.X, padx=16, pady=(0, 8))
        self.stats_var = tk.StringVar(value="No scan performed yet")
        ttk.Label(sbar, textvariable=self.stats_var, style="Dim.TLabel").pack(side=tk.LEFT, padx=8, pady=4)

        self.log_message("HVAC Network Scanner initialized - Full Protocol Discovery")
        self.log_message("  BACnet/IP | BACnet MSTP (via routers) | Modbus TCP")
        self.log_message("  Niagara Fox | OPC UA | KNX | LonWorks | EtherNet/IP | S7")
        self.log_message("  HTTP/HTTPS banner grab | SNMP | SSH/Telnet/FTP")
        self.log_message("  Enter your HVAC network CIDR(s) above and click SCAN")
        self.log_message("")

    # --- Column Sorting ---
    def _make_sort_command(self, tree, col, display_name):
        return lambda: self._sort_treeview(tree, col, display_name)

    def _setup_sortable(self, tree, col, display_name):
        tree.heading(col, text=display_name, command=self._make_sort_command(tree, col, display_name))

    def _sort_treeview(self, tree, col, display_name):
        tree_id = id(tree)
        prev_col, prev_reverse = self._sort_state.get(tree_id, (None, False))
        reverse = not prev_reverse if prev_col == col else False
        self._sort_state[tree_id] = (col, reverse)
        items = [(tree.set(iid, col), iid) for iid in tree.get_children("")]

        def sort_key(item):
            val = item[0]
            try:
                if val.count(".") == 3 and all(p.isdigit() for p in val.split(".")):
                    return (0, tuple(int(p) for p in val.split(".")))
            except Exception:
                pass
            try:
                return (1, float(val))
            except (ValueError, TypeError):
                pass
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

    # --- Logging ---
    def log_message(self, msg):
        def _append():
            tag = None
            if "error" in msg.lower() or "Error" in msg:
                tag = "error"
            elif "Found" in msg and "device" in msg.lower():
                tag = "success"
            elif "in use" in msg.lower() or "failed" in msg.lower():
                tag = "warn"
            elif "Scanning" in msg or "Sending" in msg or "Probing" in msg:
                tag = "info"
            self.log_text.insert(tk.END, msg + "\n", tag)
            self.log_text.see(tk.END)
        self.root.after(0, _append)

    # --- Scan Control ---
    def start_scan(self):
        if self.scan_running:
            return
        self.scan_running = True
        self.stop_event.clear()
        self.scan_btn.configure(state='disabled')
        self.stop_btn.configure(state='normal')
        self.export_btn.configure(state='disabled')
        self.status_var.set("Scanning...")
        self.all_devices.clear()
        for tree in [self.device_tree, self.points_tree, self.reg_tree, self.svc_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.raw_text.delete("1.0", tk.END)
        threading.Thread(target=self._run_scan, daemon=True).start()

    def stop_scan(self):
        self.stop_event.set()
        self.log_message("Scan stop requested...")

    def _run_scan(self):
        try:
            networks = [n.strip() for n in self.network_entry.get().split(",") if n.strip()]
            timeout = float(self.timeout_entry.get() or "5")
            self.bacnet_scanner.timeout = timeout
            self.modbus_scanner.timeout = min(timeout, 2.0)
            self.service_scanner.timeout = min(timeout, 2.0)
            self.snmp_scanner.timeout = min(timeout, 2.0)

            start_time = time.time()
            counts = {'bacnet': 0, 'mstp': 0, 'modbus': 0, 'services': 0, 'snmp': 0, 'points': 0}

            # === BACnet/IP ===
            if self.scan_bacnet.get() and not self.stop_event.is_set():
                self.log_message("=" * 65)
                self.log_message("BACNET/IP DISCOVERY")
                self.log_message("=" * 65)
                reader = RawBACnetReader(callback=self.log_message, timeout=timeout)
                use_reader = reader.connect()

                for network in networks:
                    if self.stop_event.is_set():
                        break
                    try:
                        net = ipaddress.ip_network(network, strict=False)
                        bcast = str(net.broadcast_address)
                    except ValueError:
                        bcast = network
                    self.log_message(f"\nBACnet/IP scan: {network}")
                    devices = self.bacnet_scanner.discover_devices(target_network=bcast)
                    for dev in devices:
                        if self.stop_event.is_set():
                            break
                        dev['vendor_name'] = BACNET_VENDORS.get(dev.get('vendor_id', -1), f"Vendor #{dev.get('vendor_id', '?')}")
                        dev['protocol'] = 'BACnet/IP'
                        if self.deep_scan.get() and use_reader:
                            self.log_message(f"  Deep scan device {dev['instance']} at {dev['ip']}...")
                            props = self._deep_read_bacnet(reader, dev['ip'], dev['instance'])
                            dev['properties'] = props
                            dev['objects'] = props.get('object_list', [])
                            counts['points'] += len(dev.get('objects', []))
                        self.all_devices.append(dev)
                        counts['bacnet'] += 1
                        self._add_device_to_tree(dev)

                # === BACnet MSTP ===
                if self.scan_mstp.get() and not self.stop_event.is_set():
                    self.log_message("\n" + "=" * 65)
                    self.log_message("BACNET MSTP / REMOTE NETWORK DISCOVERY")
                    self.log_message("=" * 65)
                    for network in networks:
                        if self.stop_event.is_set():
                            break
                        try:
                            net = ipaddress.ip_network(network, strict=False)
                            bcast = str(net.broadcast_address)
                        except ValueError:
                            bcast = network
                        self.bacnet_scanner.discover_mstp_networks(target_network=bcast)
                        if self.bacnet_scanner.mstp_networks:
                            mstp_devices = self.bacnet_scanner.discover_mstp_devices(target_network_bcast=bcast)
                            existing = {(d['ip'], d['instance']) for d in self.all_devices if d.get('protocol', '').startswith('BACnet')}
                            for dev in mstp_devices:
                                if self.stop_event.is_set():
                                    break
                                key = (dev['ip'], dev['instance'])
                                if key in existing:
                                    continue
                                dev['vendor_name'] = BACNET_VENDORS.get(dev.get('vendor_id', -1), f"Vendor #{dev.get('vendor_id', '?')}")
                                dev['protocol'] = 'BACnet/MSTP'
                                if self.deep_scan.get() and use_reader and dev.get('source_network'):
                                    self.log_message(f"  Deep scan MSTP device {dev['instance']}...")
                                    props = self._deep_read_bacnet(reader, dev['ip'], dev['instance'])
                                    dev['properties'] = props
                                    dev['objects'] = props.get('object_list', [])
                                    counts['points'] += len(dev.get('objects', []))
                                self.all_devices.append(dev)
                                counts['mstp'] += 1
                                self._add_device_to_tree(dev)

                if use_reader:
                    reader.disconnect()

            # === Modbus TCP ===
            if self.scan_modbus.get() and not self.stop_event.is_set():
                self.log_message("\n" + "=" * 65)
                self.log_message("MODBUS TCP DISCOVERY")
                self.log_message("=" * 65)
                for network in networks:
                    if self.stop_event.is_set():
                        break
                    self.log_message(f"\nModbus scan: {network}")
                    devices = self.modbus_scanner.scan_network(network)
                    for dev in devices:
                        if self.stop_event.is_set():
                            break
                        dev['protocol'] = 'Modbus TCP'
                        dev['instance'] = dev.get('unit_id', '?')
                        if self.deep_scan.get():
                            self.log_message(f"  Reading registers from {dev['ip']} unit={dev['unit_id']}...")
                            dev['holding_registers'] = self.modbus_scanner.read_registers(dev['ip'], dev['port'], dev['unit_id'], start=0, count=50, func_code=3)
                            dev['input_registers'] = self.modbus_scanner.read_registers(dev['ip'], dev['port'], dev['unit_id'], start=0, count=50, func_code=4)
                            dev['coils'] = self.modbus_scanner.read_coils(dev['ip'], dev['port'], dev['unit_id'], start=0, count=16)
                            counts['points'] += len(dev.get('holding_registers', [])) + len(dev.get('input_registers', [])) + len(dev.get('coils', []))
                            self._add_registers_to_tree(dev)
                        self.all_devices.append(dev)
                        counts['modbus'] += 1
                        self._add_device_to_tree(dev)

            # === HVAC Services ===
            if self.scan_services.get() and not self.stop_event.is_set():
                self.log_message("\n" + "=" * 65)
                self.log_message("HVAC SERVICE DISCOVERY")
                self.log_message("=" * 65)
                for network in networks:
                    if self.stop_event.is_set():
                        break
                    self.log_message(f"\nService scan: {network}")
                    services = self.service_scanner.scan_network(network, stop_event=self.stop_event)
                    for svc in services:
                        if self.stop_event.is_set():
                            break
                        self.all_devices.append(svc)
                        counts['services'] += 1
                        self._add_device_to_tree(svc)
                        self._add_service_to_tree(svc)

            # === SNMP ===
            if self.scan_snmp.get() and not self.stop_event.is_set():
                self.log_message("\n" + "=" * 65)
                self.log_message("SNMP DISCOVERY")
                self.log_message("=" * 65)
                for network in networks:
                    if self.stop_event.is_set():
                        break
                    self.log_message(f"\nSNMP scan: {network}")
                    snmp_devs = self.snmp_scanner.scan_network(network, stop_event=self.stop_event)
                    for dev in snmp_devs:
                        if self.stop_event.is_set():
                            break
                        dev['protocol'] = 'SNMP'
                        dev['vendor'] = ''
                        dev['product'] = dev.get('sys_descr', '')[:80]
                        descr = dev.get('sys_descr', '').lower()
                        for pattern, vendor in HTTP_FINGERPRINTS:
                            if re.search(pattern, descr):
                                dev['vendor'] = vendor
                                break
                        self.all_devices.append(dev)
                        counts['snmp'] += 1
                        self._add_device_to_tree(dev)

            # === Re-fingerprint with full service context ===
            if not self.stop_event.is_set():
                self.log_message("\nRe-fingerprinting devices with full service data...")
                for tree_item in self.device_tree.get_children():
                    self.device_tree.delete(tree_item)
                for dev in self.all_devices:
                    fp = fingerprint_device(dev, self.all_devices)
                    dev['_fingerprint'] = fp
                    self._add_device_to_tree(dev)
                self.log_message("  Fingerprinting complete")

            # === Summary ===
            elapsed = time.time() - start_time
            total = counts['bacnet'] + counts['mstp'] + counts['modbus'] + counts['services'] + counts['snmp']
            self.log_message("\n" + "=" * 65)
            self.log_message(f"Scan complete in {elapsed:.1f}s")
            self.log_message(f"  BACnet/IP:   {counts['bacnet']}")
            self.log_message(f"  BACnet/MSTP: {counts['mstp']}")
            self.log_message(f"  Modbus TCP:  {counts['modbus']}")
            self.log_message(f"  Services:    {counts['services']}")
            self.log_message(f"  SNMP:        {counts['snmp']}")
            self.log_message(f"  Total:       {total} devices, {counts['points']} points/registers")
            self.log_message("=" * 65)
            self._update_raw_json()
            self.root.after(0, lambda: self.stats_var.set(
                f"BACnet: {counts['bacnet']}  MSTP: {counts['mstp']}  Modbus: {counts['modbus']}  "
                f"Services: {counts['services']}  SNMP: {counts['snmp']}  Points: {counts['points']}  |  {elapsed:.1f}s"))
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

    def _deep_read_bacnet(self, reader, ip, instance):
        props = {}
        for prop_name, key in [('object-name', 'name'), ('vendor-name', 'vendor_name'),
                                ('model-name', 'model_name'), ('firmware-revision', 'firmware'),
                                ('application-software-version', 'app_version'), ('description', 'description'),
                                ('protocol-version', 'protocol_version'), ('protocol-revision', 'protocol_revision')]:
            val = reader.read_property(ip, 'device', instance, prop_name)
            if val is not None:
                props[key] = str(val)
        if props:
            self.log_message(f"    Device props: {', '.join(f'{k}={v[:30]}' for k,v in props.items())}")
        else:
            self.log_message(f"    No device properties returned (ReadProperty may be failing)")
        obj_list = reader.read_object_list(ip, instance)
        if obj_list:
            props['object_list'] = []
            parsed_objects = []
            for obj in obj_list:
                try:
                    if isinstance(obj, tuple) and len(obj) == 2:
                        parsed_objects.append({'type': str(obj[0]), 'instance': int(obj[1])})
                    elif isinstance(obj, str):
                        parts = obj.replace('(', '').replace(')', '').split(',')
                        if len(parts) == 2:
                            parsed_objects.append({'type': parts[0].strip(), 'instance': int(parts[1].strip())})
                except Exception:
                    parsed_objects.append({'type': str(obj), 'instance': 0})
            for pobj in parsed_objects[:200]:
                if self.stop_event.is_set():
                    break
                obj_type = pobj['type']
                obj_inst = pobj['instance']
                if obj_type.lower() == 'device':
                    continue
                point_info = {'type': obj_type, 'instance': obj_inst}
                for prop, key in [('presentValue', 'present_value'), ('objectName', 'name'),
                                   ('units', 'units'), ('description', 'description')]:
                    val = reader.read_property(ip, obj_type, obj_inst, prop)
                    if val is not None:
                        if key == 'units' and isinstance(val, int):
                            point_info[key] = BACNET_UNITS.get(val, str(val))
                        elif key == 'present_value' and isinstance(val, float):
                            point_info[key] = f"{val:.1f}"
                        else:
                            point_info[key] = str(val)
                props['object_list'].append(point_info)
                self._add_point_to_tree(ip, instance, point_info)
            self.log_message(f"    Read {len(parsed_objects)} objects from device {instance}")
        return props

    # --- Tree Updates ---
    def _add_device_to_tree(self, dev):
        def _update():
            protocol = dev.get('protocol', '?')
            ip = dev.get('ip', '?')
            port = dev.get('port', '?')

            # Run fingerprint engine
            fp = fingerprint_device(dev, self.all_devices)
            dev['_fingerprint'] = fp  # Store for later lookup

            if protocol.startswith('BACnet'):
                address = dev.get('instance', '?')
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

            model = fp.get('model', '') or dev.get('properties', {}).get('model_name', '')
            device_type = fp.get('device_type', '')
            web_url = fp.get('web_url', '')
            default_creds = fp.get('default_creds', '')
            description = fp.get('description', '')

            self.device_tree.insert("", tk.END, values=(
                protocol, ip, port, address, model, device_type,
                vendor, web_url, default_creds, description))
        self.root.after(0, _update)

    def _add_point_to_tree(self, ip, device_instance, point_info):
        def _update():
            self.points_tree.insert("", tk.END, values=(
                f"{ip} ({device_instance})", point_info.get('type', '?'),
                point_info.get('instance', '?'), point_info.get('name', ''),
                point_info.get('present_value', ''), point_info.get('units', ''),
                point_info.get('description', '')))
        self.root.after(0, _update)

    def _add_registers_to_tree(self, dev):
        def _update():
            label = f"{dev['ip']}:{dev['port']} u={dev['unit_id']}"
            for reg in dev.get('holding_registers', []):
                self.reg_tree.insert("", tk.END, values=(label, "Holding (FC3)", reg['register'], reg['value'], reg['hex'], format(reg['value'], '016b')))
            for reg in dev.get('input_registers', []):
                self.reg_tree.insert("", tk.END, values=(label, "Input (FC4)", reg['register'], reg['value'], reg['hex'], format(reg['value'], '016b')))
            for coil in dev.get('coils', []):
                self.reg_tree.insert("", tk.END, values=(label, "Coil (FC1)", coil['coil'], coil['value'], f"0x{coil['value']:04X}", coil['state']))
        self.root.after(0, _update)

    def _add_service_to_tree(self, svc):
        def _update():
            self.svc_tree.insert("", tk.END, values=(
                svc.get('ip', '?'), svc.get('port', '?'), svc.get('service', '?'),
                svc.get('vendor', ''), svc.get('product', ''),
                svc.get('title', ''), svc.get('banner', '')))
        self.root.after(0, _update)

    def _update_raw_json(self):
        def _update():
            export_data = {'scan_time': datetime.now().isoformat(), 'devices': []}
            for dev in self.all_devices:
                d = {}
                for k, v in dev.items():
                    if k.startswith('_'):
                        continue
                    try:
                        json.dumps(v)
                        d[k] = v
                    except (TypeError, ValueError):
                        d[k] = str(v)
                # Add fingerprint data
                fp = dev.get('_fingerprint', {})
                if fp:
                    d['identified_model'] = fp.get('model', '')
                    d['device_type'] = fp.get('device_type', '')
                    d['web_url'] = fp.get('web_url', '')
                    d['default_creds'] = fp.get('default_creds', '')
                    d['description'] = fp.get('description', '')
                export_data['devices'].append(d)
            self.raw_text.delete("1.0", tk.END)
            self.raw_text.insert("1.0", json.dumps(export_data, indent=2, default=str))
        self.root.after(0, _update)

    # --- Device Interaction ---
    def _get_selected_device_vals(self):
        selection = self.device_tree.selection()
        if not selection:
            return None
        return self.device_tree.item(selection[0])['values']

    def _on_device_select(self, event):
        pass  # No auto-tab-switch — user can navigate manually

    def _on_device_double_click(self, event):
        """Double-click opens the web UI if available."""
        vals = self._get_selected_device_vals()
        if not vals:
            return
        web_url = vals[7]  # web_url column
        if web_url and str(web_url).startswith('http'):
            webbrowser.open(str(web_url))
        else:
            ip = vals[1]
            # Try HTTPS then HTTP
            webbrowser.open(f"https://{ip}")

    def _on_device_right_click(self, event):
        """Show context menu on right-click."""
        iid = self.device_tree.identify_row(event.y)
        if iid:
            self.device_tree.selection_set(iid)
            self.ctx_menu.post(event.x_root, event.y_root)

    def _ctx_open_web(self, force_http=False):
        vals = self._get_selected_device_vals()
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

    def _ctx_copy_ip(self):
        vals = self._get_selected_device_vals()
        if vals:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(vals[1]))

    def _ctx_copy_creds(self):
        vals = self._get_selected_device_vals()
        if vals and vals[8]:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(vals[8]))

    def _ctx_ping(self):
        vals = self._get_selected_device_vals()
        if not vals:
            return
        ip = str(vals[1])
        self.log_message(f"Pinging {ip}...")
        def _do_ping():
            import subprocess
            try:
                # Windows: ping -n 4; Linux: ping -c 4
                param = '-n' if os.name == 'nt' else '-c'
                result = subprocess.run(['ping', param, '4', ip],
                                        capture_output=True, text=True, timeout=10)
                for line in result.stdout.strip().split('\n'):
                    self.log_message(f"  {line}")
            except Exception as e:
                self.log_message(f"  Ping error: {e}")
        threading.Thread(target=_do_ping, daemon=True).start()

    def _ctx_show_details(self):
        vals = self._get_selected_device_vals()
        if not vals:
            return
        ip = str(vals[1])
        # Find the device in all_devices
        dev = None
        for d in self.all_devices:
            if d.get('ip') == ip and str(d.get('port', '')) == str(vals[2]):
                dev = d
                break
        if not dev:
            return

        fp = dev.get('_fingerprint', {})
        # Build detail text
        lines = []
        lines.append(f"{'='*50}")
        lines.append(f"  DEVICE DETAILS: {ip}")
        lines.append(f"{'='*50}")
        lines.append(f"")
        lines.append(f"  Protocol:    {dev.get('protocol', '?')}")
        lines.append(f"  IP Address:  {ip}")
        lines.append(f"  Port:        {dev.get('port', '?')}")
        if dev.get('instance'):
            lines.append(f"  Instance:    {dev.get('instance')}")
        if dev.get('source_network'):
            lines.append(f"  MSTP Net:    {dev.get('source_network')}")
            lines.append(f"  MSTP MAC:    {dev.get('source_address', '?')}")
        if dev.get('via_router'):
            lines.append(f"  Via Router:  {dev.get('via_router')}")
        lines.append(f"")
        lines.append(f"  --- Identification ---")
        lines.append(f"  Model:       {fp.get('model', '?')}")
        lines.append(f"  Type:        {fp.get('device_type', '?')}")
        lines.append(f"  Vendor:      {dev.get('vendor_name', dev.get('vendor', '?'))}")
        lines.append(f"  Vendor ID:   {dev.get('vendor_id', '?')}")
        lines.append(f"  Description: {fp.get('description', '')}")
        lines.append(f"")
        lines.append(f"  --- Access ---")
        lines.append(f"  Web UI:      {fp.get('web_url', 'None detected')}")
        lines.append(f"  Def. Creds:  {fp.get('default_creds', 'Unknown')}")
        if dev.get('max_apdu'):
            lines.append(f"  Max APDU:    {dev.get('max_apdu')}")
        if dev.get('segmentation'):
            lines.append(f"  Segmentation:{dev.get('segmentation')}")
        # Properties from deep scan
        props = dev.get('properties', {})
        if props:
            lines.append(f"")
            lines.append(f"  --- BACnet Properties ---")
            for k, v in props.items():
                if k != 'object_list' and v:
                    lines.append(f"  {k}: {v}")
            obj_list = props.get('object_list', [])
            if obj_list:
                lines.append(f"  Objects: {len(obj_list)} points")
        # Service info
        if dev.get('banner'):
            lines.append(f"")
            lines.append(f"  --- Service Info ---")
            lines.append(f"  Banner:  {dev.get('banner', '')}")
            lines.append(f"  Title:   {dev.get('title', '')}")
            lines.append(f"  Server:  {dev.get('server', '')}")
        if dev.get('sys_descr'):
            lines.append(f"")
            lines.append(f"  --- SNMP ---")
            lines.append(f"  sysDescr: {dev.get('sys_descr', '')}")
        lines.append(f"")
        lines.append(f"{'='*50}")

        # Show in a popup window
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
                  command=lambda: (self.root.clipboard_clear(), self.root.clipboard_append(ip))).pack(side=tk.LEFT, padx=4)

        tk.Button(btn_frame, text="Close", bg=Colors.BORDER, fg=Colors.TEXT,
                  font=("Consolas", 10), padx=12, pady=4,
                  command=detail_win.destroy).pack(side=tk.RIGHT, padx=4)

    # --- Export ---
    def export_results(self):
        if not self.all_devices:
            messagebox.showinfo("Export", "No data to export")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"hvac_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        if not filepath:
            return
        try:
            if filepath.endswith('.json'):
                self._export_json(filepath)
            else:
                self._export_csv(filepath)
            self.log_message(f"Exported to {filepath}")
            messagebox.showinfo("Export", f"Saved to:\n{filepath}")
        except Exception as e:
            self.log_message(f"Export error: {e}")
            messagebox.showerror("Export Error", str(e))

    def _export_json(self, filepath):
        export_data = {'scan_time': datetime.now().isoformat(), 'scanner': 'HVAC Network Scanner v2', 'devices': []}
        for dev in self.all_devices:
            d = {}
            for k, v in dev.items():
                try:
                    json.dumps(v)
                    d[k] = v
                except (TypeError, ValueError):
                    d[k] = str(v)
            export_data['devices'].append(d)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)

    def _export_csv(self, filepath):
        with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow(['Protocol', 'IP', 'Port', 'Device ID', 'Identified Model', 'Device Type',
                             'Vendor', 'Web UI URL', 'Default Credentials', 'Description',
                             'BACnet Instance', 'MSTP Network', 'MSTP MAC', 'Max APDU',
                             'Segmentation', 'Vendor ID', 'Banner', 'Page Title'])
            for dev in self.all_devices:
                fp = dev.get('_fingerprint', {})
                protocol = dev.get('protocol', '?')
                ip = dev.get('ip', '?')
                port = dev.get('port', '?')
                row = [
                    protocol, ip, port,
                    dev.get('instance', dev.get('unit_id', '')),
                    fp.get('model', ''),
                    fp.get('device_type', ''),
                    dev.get('vendor_name', dev.get('vendor', '')),
                    fp.get('web_url', ''),
                    fp.get('default_creds', ''),
                    fp.get('description', ''),
                    dev.get('instance', ''),
                    dev.get('source_network', ''),
                    dev.get('source_address', ''),
                    dev.get('max_apdu', ''),
                    dev.get('segmentation', ''),
                    dev.get('vendor_id', ''),
                    dev.get('banner', ''),
                    dev.get('title', ''),
                ]
                writer.writerow(row)


def main():
    # --- Windows DPI awareness (must be before Tk() creation) ---
    try:
        import ctypes
        # Per-monitor DPI aware (Windows 8.1+)
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except (AttributeError, OSError):
        try:
            # System DPI aware fallback (Windows Vista+)
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass  # Not on Windows or older version

    root = tk.Tk()

    # Apply DPI-aware scaling for tk widgets
    try:
        dpi = root.winfo_fpixels('1i')  # actual DPI
        scale = dpi / 72.0
        root.tk.call('tk', 'scaling', scale)
    except Exception:
        pass

    try:
        root.iconbitmap(default='')
    except Exception:
        pass
    app = HVACNetworkScanner(root)
    root.mainloop()


if __name__ == "__main__":
    main()
