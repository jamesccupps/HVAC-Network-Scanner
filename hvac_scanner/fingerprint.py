"""
Device fingerprinting engine.

Cross-references vendor ID, max-APDU, instance number, MSTP routing, and
service banners to identify specific controller models.

Extracted from v1 into a standalone module so it can be unit-tested and
extended without touching scan logic.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .constants import BACNET_VENDORS, DEFAULT_CREDS

# ASHRAE BACnet vendor IDs this module branches on.
#
# These were hardcoded as bare literals until the v2.1.1 registry regeneration
# (34 entries -> 593) silently desynced two of them: 485 is SCS, not
# Contemporary Controls, and neither 13 (Teletrol Systems) nor 514 (t-mac
# Technologies) is Cimetrics — Cimetrics is 14. An SCS device was being
# labelled a BACnet router and handed Contemporary Controls' default
# credentials. tests/test_fingerprint.py now asserts each of these against
# BACNET_VENDORS so a future registry update cannot desync them again.
VENDOR_TRANE = 2               # The Trane Company
VENDOR_JOHNSON_CONTROLS = 5    # Johnson Controls
VENDOR_CIMETRICS = 14          # Cimetrics Technology
VENDOR_CONTEMPORARY = 245      # Contemporary Control Systems

# Siemens registered several IDs against the same vendor name; a device may
# report any of them. Branching on 7 alone dropped the rest to the generic
# vendor fallback.
VENDORS_SIEMENS = (7, 9, 22, 313)   # Siemens Schweiz / Siemens Industry


# ---------------------------------------------------------------------------
# DEFAULT_CREDS wiring
#
# constants.DEFAULT_CREDS carries 22 vendor entries but nothing ever read it:
# every credential the scanner emitted came from a string literal inside one
# of the vendor branches below, so only Trane, Siemens, JCI and Contemporary
# Controls ever produced a value. Devices from the other 18 vendors got an
# empty Default Credentials column, despite the README advertising coverage
# for them.
#
# Resolution order:
#   1. A branch below set creds explicitly — it knows the exact model, keep it.
#   2. The model text contains a DEFAULT_CREDS key (longest key wins, so
#      'Trane Tracer SC+' is preferred over 'Trane Tracer SC').
#   3. The vendor ID maps to a product family with a known factory default.
#
# Every ID below was checked against BACNET_VENDORS; tests/test_fingerprint.py
# asserts the mapping so a registry regeneration cannot desync it the way it
# desynced the branch IDs in v2.1.1.
# ---------------------------------------------------------------------------

_VENDOR_ID_TO_CREDS_KEY = {
    17:  'Honeywell Tridium Niagara',   # Honeywell
    18:  'Honeywell Tridium Niagara',   # Alerton / Honeywell
    333: 'Honeywell Tridium Niagara',   # Novar / Honeywell
    36:  'Honeywell Tridium Niagara',   # Tridium
    10:  'Schneider EcoStruxure',       # Schneider Electric
    335: 'Schneider EcoStruxure',       # Schneider Electric
    24:  'Automated Logic WebCTRL',     # Automated Logic
    16:  'Carrier i-Vu',                # United Technologies Carrier
    129: 'Carrier i-Vu',                # Carrier Japan
    28:  'KMC Controls',                # KMC Controls
    332: 'Distech Controls',            # Distech Controls SAS
    364: 'Distech Controls',            # Distech Controls
    35:  'Reliable Controls',           # Reliable Controls
    8:   'Delta Controls',              # Delta Controls
    402: 'Delta Controls',              # Delta Controls Integration Products
    77:  'Carel pCO',                   # Carel Industries
    284: 'Belimo',                      # BELIMO Automation
    423: 'Belimo',                      # BELIMO Automation
    502: 'EasyIO',                      # EasyIO
    3:   'Daikin',                      # Daikin Applied Americas
    53:  'Daikin',                      # DAIKIN Industries
}

# Longest first so more specific product names win the substring match.
_CREDS_KEYS_BY_LENGTH = sorted(DEFAULT_CREDS, key=len, reverse=True)


def _lookup_default_creds(model_text: str, vendor_id) -> str:
    """Resolve factory-default credentials for a device we could not pin to
    an exact model in the branches above. Returns '' when we have nothing —
    an empty column is honest, a guessed credential is not."""
    text = (model_text or '').lower()
    if text:
        for key in _CREDS_KEYS_BY_LENGTH:
            if key.lower() in text:
                return DEFAULT_CREDS[key]
    key = _VENDOR_ID_TO_CREDS_KEY.get(vendor_id)
    return DEFAULT_CREDS.get(key, '') if key else ''


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
    # The device's own Device-object properties, populated by engine._deep_read
    # before _refingerprint runs. modelName is ground truth: the controller
    # literally tells us what it is. The heuristics below only ever existed to
    # cover the case where it does not answer.
    props = dev.get('properties') or {}
    reported_model = str(props.get('model_name') or '').strip()
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
    if vendor_id == VENDOR_TRANE:
        # 'tracer sc' covers SC and SC+; the device reports which.
        #
        # This used to key off `instance in (33333, 22222)`, which are simply
        # the device instances configured at the site this was developed
        # against — an arbitrary local convention, not a protocol fact. An SC+
        # numbered 1 elsewhere fell through to the UC800/UC600 branch and was
        # reported as a unitary controller.
        if 'tracer sc' in reported_model.lower():
            info['model'] = reported_model
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
    elif vendor_id in VENDORS_SIEMENS:
        inst_prefix = instance // 1000 if instance else 0

        # NB: `instance % 1000 == 0` below is a site addressing convention, not
        # a Siemens property. It is kept as a weak hint for panels that do not
        # answer ReadProperty, but a reported modelName overrides it at the end
        # of this function.
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
    elif vendor_id == VENDOR_JOHNSON_CONTROLS:
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
    elif vendor_id == VENDOR_CONTEMPORARY:
        info['model'] = 'Contemporary Controls BASRT-B'
        info['device_type'] = 'BACnet Router'
        info['description'] = 'BACnet/IP to MS/TP router (Ethernut platform)'
        info['default_creds'] = 'admin / admin'
        if has_http:
            info['web_url'] = f"http://{ip}"

    # --- Cimetrics ----------------------------------------------------
    elif vendor_id == VENDOR_CIMETRICS:
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

    # The device's own modelName beats anything we inferred. Applied before
    # credential resolution so the DEFAULT_CREDS match runs against the real
    # product name rather than a guess. This also aligns the JSON/GUI
    # 'identified_model' with the CSV export, which already preferred
    # properties.model_name — the two used to disagree on the same device.
    if reported_model:
        info['model'] = reported_model
        if not info['device_type']:
            info['device_type'] = 'Controller'

    # Fill default credentials from the shared table when no branch above
    # produced a model-specific value.
    if not info['default_creds']:
        info['default_creds'] = _lookup_default_creds(info['model'], vendor_id)

    # Default web URL if we haven't set one
    if not info['web_url'] and has_http:
        if 443 in ip_services:
            info['web_url'] = f"https://{ip}"
        elif 80 in ip_services:
            info['web_url'] = f"http://{ip}"

    return info
