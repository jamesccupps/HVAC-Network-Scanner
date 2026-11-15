"""Bounds for the numeric scan options: one table for the command line, the
window's Advanced fields and saved site profiles.

Each used to keep its own minimums and no maximums. `--timeout nan` passed
(nan <= 0 is false) and failed later inside the socket layer; `inf` and
`1e999` the same; and a saved profile could ask for 100,000 parallel devices
where the command line stops at 64.
"""

from __future__ import annotations

import math
from typing import Any, Optional

# ScanOptions name: (type, lowest, highest)
BOUNDS: dict[str, tuple[type, float, float]] = {
    'timeout': (float, 0.1, 300.0),
    'rate_limit_ms': (int, 0, 60_000),
    'whois_chunk_size': (int, 0, 4_194_304),
    'bacnet_workers': (int, 1, 64),
    'device_time_limit': (float, 0.0, 86_400.0),
    'max_objects_per_device': (int, 1, 1_000_000),
}


def _fmt(v: float) -> str:
    return f"{v:,.0f}" if float(v).is_integer() else f"{v:g}"


def check(option: str, value: Any, label: str, shown: Optional[str] = None) -> Any:
    """`value` if it is within the option's bounds; ValueError with a
    sentence for the user otherwise."""
    _kind, low, high = BOUNDS[option]
    shown = str(value) if shown is None else shown
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} {shown!r} is not a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{label} must be a number, not {shown}")
    if not low <= value <= high:
        raise ValueError(f"{label} must be between {_fmt(low)} and {_fmt(high)}, not {shown}")
    return value


def parse(option: str, text: Any, label: str) -> Any:
    """`text` read as the option's type, within its bounds."""
    kind, _low, _high = BOUNDS[option]
    raw = str(text).strip()
    try:
        value = kind(raw)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{label} {raw!r} is not a number") from None
    return check(option, value, label, raw)
