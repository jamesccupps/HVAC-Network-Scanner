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
