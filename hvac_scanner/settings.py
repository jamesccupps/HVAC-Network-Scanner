"""Remembered GUI settings.

The GUI used to start from the same hard-coded defaults every time, so the
target network, protocol choices and every advanced field had to be typed
again on each launch. They now persist in a small JSON file:

    Windows:  %APPDATA%\\HVACNetworkScanner\\settings.json
    elsewhere: $XDG_CONFIG_HOME/hvac-scanner/settings.json (~/.config/...)

Nothing here is required: a missing, unreadable or corrupt file simply means
defaults, and a failed save is logged and ignored.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def default_path() -> Path:
    if sys.platform.startswith('win'):
        base = os.environ.get('APPDATA') or str(Path.home() / 'AppData' / 'Roaming')
        return Path(base) / 'HVACNetworkScanner' / 'settings.json'
    base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    return Path(base) / 'hvac-scanner' / 'settings.json'


def load(path: "Path | None") -> dict[str, Any]:
    if path is None:
        return {}
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log.warning("ignoring unreadable settings file %s: %s", path, e)
        return {}


def save(path: "Path | None", data: dict[str, Any]) -> None:
    _save(path, data)


# ---------------------------------------------------------------------------
# Site profiles
#
# A named target list with its own options, saved from the GUI for a building
# that gets audited regularly. Stored in the same file, under 'profiles', in
# the GUI's own shape: the target text, the depth, the on/off options and the
# advanced fields as typed. The CLI runs one with --profile.
# ---------------------------------------------------------------------------

# On/off options a profile carries, by their ScanOptions names.
TOGGLE_OPTIONS = ('scan_bacnet', 'scan_mstp', 'scan_modbus', 'scan_services',
                  'scan_snmp', 'scan_p2', 'scan_knx', 'deep_scan', 'use_rpm',
                  'read_bbmd_tables', 'read_metadata', 'mstp_mac_probe')


def profiles(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The saved profiles in a loaded settings file, skipping malformed ones."""
    raw = data.get('profiles')
    if not isinstance(raw, dict):
        return {}
    return {name: p for name, p in raw.items() if isinstance(name, str) and isinstance(p, dict)}


def profile_options(profile: dict[str, Any]) -> dict[str, Any]:
    """ScanOptions keyword arguments for a saved profile.

    A field that is missing or does not parse is left out, so the scanner's
    default applies to it rather than the profile failing as a whole.
    """
    import ipaddress

    out: dict[str, Any] = {}
    targets = profile.get('targets')
    if isinstance(targets, str):
        nets = [t.strip() for t in targets.split(',') if t.strip()]
        if nets:
            out['networks'] = nets
    if profile.get('depth') in ('quick', 'normal', 'full'):
        out['scan_depth'] = profile['depth']
    toggles = profile.get('toggles') or {}
    for name in TOGGLE_OPTIONS:
        if isinstance(toggles.get(name), bool):
            out[name] = toggles[name]

    adv = profile.get('advanced') or {}

    def text(key: str) -> str:
        val = adv.get(key)
        return val.strip() if isinstance(val, str) else ''

    for key, option, cast, minimum in (('timeout', 'timeout', float, 0.1),
                                       ('rate_limit', 'rate_limit_ms', int, 0),
                                       ('whois_chunk', 'whois_chunk_size', int, 0),
                                       ('workers', 'bacnet_workers', int, 1),
                                       ('max_objects', 'max_objects_per_device', int, 1)):
        try:
            val = cast(text(key))
        except ValueError:
            continue
        if val >= minimum:
            out[option] = val
    if text('unicast') in ('auto', 'always', 'off'):
        out['unicast_discovery'] = text('unicast')
    for key, option in (('bbmd', 'bbmd'), ('broadcast', 'bacnet_broadcast')):
        try:
            out[option] = str(ipaddress.IPv4Address(text(key)))
        except ValueError:
            pass
    communities = [c.strip() for c in text('communities').split(',') if c.strip()]
    if communities:
        out['snmp_communities'] = communities
    return out


def _save(path: "Path | None", data: dict[str, Any]) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix('.tmp')
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        log.warning("could not save settings to %s: %s", path, e)
