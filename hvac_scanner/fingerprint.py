"""
Device fingerprinting engine.

Cross-references vendor ID, max-APDU, instance number, MSTP routing, and
service banners to identify specific controller models.

Extracted from v1 into a standalone module so it can be unit-tested and
extended without touching scan logic.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .constants import BACNET_VENDORS


def fingerprint_device(dev: dict[str, Any],
                       all_services: Optional[Iterable[dict[str, Any]]] = None
                       ) -> dict[str, str]:
    """Identify a device's model, type, default creds, and web URL.

    dev is a scanner-produced device dict. all_services is the list of
    discovered Service entries — used to check which ports the same IP
    exposes (e.g. Siemens Desigo identified by having BOTH BACnet vendor 7
    AND a Nucleus FTP banner on port 21).
    """
    info = {
        'model': '', 'device_type': '', 'description': '',
        'web_url': '', 'default_creds': '',
    }
    ip = dev.get('ip', '')
    vendor_id = dev.get('vendor_id')
    instance = dev.get('instance', 0) or 0
    protocol = dev.get('protocol', '')
    max_apdu = dev.get('max_apdu', 0)
    snet = dev.get('source_network')
    banner = (dev.get('banner') or '').lower()
    title = (dev.get('title') or '').lower()

    # Collect same-IP services
    ip_services: dict[int, dict[str, Any]] = {}
    if all_services:
        for s in all_services:
            if s.get('ip') == ip and s.get('protocol') == 'Service':
                ip_services[s.get('port', 0)] = s

    def _svc_text(port: int, key: str) -> str:
        return (ip_services.get(port, {}).get(key) or '').lower()

    has_nucleus_ftp = 'nucleus' in _svc_text(21, 'banner')
    has_nginx = any('nginx' in _svc_text(p, 'server') for p in (80, 443))
    has_telnet = 23 in ip_services
    has_ftp = 21 in ip_services
    has_s7 = 102 in ip_services
    has_http = 80 in ip_services or 443 in ip_services

    # --- Trane --------------------------------------------------------
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

    # --- Siemens ------------------------------------------------------
    elif vendor_id == 7:
        inst_prefix = instance // 1000 if instance else 0

        if instance and instance % 1000 == 0 and has_nucleus_ftp:
            info['model'] = 'Siemens Desigo PXC Automation Station'
            info['device_type'] = 'Automation Station'
            info['description'] = f'Desigo PXC primary automation station (Nucleus RTOS). Manages sub-controllers in the {inst_prefix}xxx range.'
            info['default_creds'] = 'ADMIN / SBTAdmin!1 | admin / admin'
            info['web_url'] = f"http://{ip}"
        elif instance and instance % 1000 == 0:
            info['model'] = 'Siemens Desigo PXC Automation Station'
            info['device_type'] = 'Automation Station'
            info['description'] = f'Desigo PXC automation station for the {inst_prefix}xxx controller group'
            info['default_creds'] = 'ADMIN / SBTAdmin!1'
            if has_http:
                info['web_url'] = f"https://{ip}"
        elif has_s7:
            info['model'] = 'Siemens Desigo CC / Insight'
            info['device_type'] = 'Management Station'
            info['description'] = 'Desigo CC or Insight management workstation with S7 communication'
            info['default_creds'] = 'Check Desigo CC application login'
            if has_http:
                info['web_url'] = f"https://{ip}"
        elif instance and 9000 < instance < 10000:
            info['model'] = 'Siemens Desigo CC Server'
            info['device_type'] = 'Management Station'
            info['description'] = 'Desigo CC building management server'
            if has_http:
                info['web_url'] = f"https://{ip}"
        elif has_nginx and max_apdu == 1476:
            info['model'] = 'Siemens Desigo PXC Compact/Modular'
            info['device_type'] = 'Field Controller'
            info['description'] = 'Desigo PXC field-level controller with embedded web server'
            info['default_creds'] = 'ADMIN / SBTAdmin!1'
            info['web_url'] = f"https://{ip}"
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

    # --- Johnson Controls ---------------------------------------------
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

    # --- Contemporary Controls ----------------------------------------
    elif vendor_id in (245, 485):
        info['model'] = 'Contemporary Controls BASRT-B'
        info['device_type'] = 'BACnet Router'
        info['description'] = 'BACnet/IP to MS/TP router (Ethernut platform)'
        info['default_creds'] = 'admin / admin'
        if has_http:
            info['web_url'] = f"http://{ip}"

    # --- Cimetrics ----------------------------------------------------
    elif vendor_id in (13, 514):
        info['model'] = 'Cimetrics BACstac Device'
        info['device_type'] = 'Gateway / Analyzer'
        info['description'] = 'Cimetrics BACstac-based protocol gateway or analyzer'

    # --- Service-only devices -----------------------------------------
    elif protocol == 'Service':
        if 'unifi' in title:
            info['model'] = 'Ubiquiti UniFi Gateway'
            info['device_type'] = 'Network Infrastructure'
            info['description'] = 'UniFi network gateway/controller'
            info['web_url'] = f"https://{ip}"
        elif 'basrt' in title:
            info['model'] = 'Contemporary Controls BASRT-B'
            info['device_type'] = 'BACnet Router'
            info['description'] = 'BACnet/IP to MS/TP router'
            info['web_url'] = f"http://{ip}"
        elif 'nucleus' in banner:
            info['model'] = 'Siemens Desigo PXC (via FTP)'
            info['device_type'] = 'Automation Station'
            info['description'] = 'Siemens controller identified by Nucleus RTOS FTP server'

    # --- SNMP devices -------------------------------------------------
    elif protocol == 'SNMP':
        descr = (dev.get('sys_descr') or '').lower()
        if 'siemens' in descr or 'desigo' in descr:
            info['model'] = 'Siemens Desigo Controller'
            info['device_type'] = 'Controller'
        elif 'trane' in descr or 'tracer' in descr:
            info['model'] = 'Trane Controller'
            info['device_type'] = 'Controller'

    # Fallback model from vendor ID
    if not info['model'] and vendor_id is not None:
        info['model'] = BACNET_VENDORS.get(vendor_id, f'Vendor #{vendor_id}') + ' Controller'
        info['device_type'] = 'Controller'

    # Default web URL if we haven't set one
    if not info['web_url'] and has_http:
        if 443 in ip_services:
            info['web_url'] = f"https://{ip}"
        elif 80 in ip_services:
            info['web_url'] = f"http://{ip}"

    return info
