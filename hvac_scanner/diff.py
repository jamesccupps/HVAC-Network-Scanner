"""Compare a scan against an earlier baseline.

The scanner has produced JSON since v2 and the CLI has been schedulable since
then, but nothing consumed the output. A nightly scan that nobody reads is
just disk usage; the useful question is not "what is on the network" but
"what changed since last time".

What counts as a device identity
--------------------------------
IP addresses move. A BACnet device instance does not — it is configured in the
controller and survives a DHCP lease change, so a device that reappears on a
new address is a *changed* device, not one removal plus one addition. BACnet
devices are therefore keyed on their instance number, and everything else
(Modbus units, bare service ports, SNMP hosts) on address and port, which is
the only stable identity those protocols offer.

What counts as a change
-----------------------
Only fields that mean something to whoever reads the report: model, vendor,
firmware and application-software revision, the device's own object name, and
how many objects it exposes. Present values are deliberately excluded — a
temperature reading differs on every scan and would bury the signal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

# Device fields worth reporting a change on, in report order.
# (path, human label) where path is either a top-level key or 'properties.<k>'.
_TRACKED_FIELDS: list[tuple[str, str]] = [
    ('properties.object_name', 'name'),
    ('properties.model_name', 'model'),
    ('vendor_name', 'vendor'),
    ('properties.firmware_revision', 'firmware'),
    ('properties.application_software_version', 'app software'),
    ('ip', 'address'),
    ('object_count', 'object count'),
]


@dataclass
class FieldChange:
    field: str
    before: Any
    after: Any

    def __str__(self) -> str:
        return f"{self.field}: {self.before!r} -> {self.after!r}"


@dataclass
class DeviceDiff:
    key: str
    label: str
    changes: list[FieldChange] = field(default_factory=list)


@dataclass
class ScanDiff:
    baseline_time: str = ''
    current_time: str = ''
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[DeviceDiff] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            'baseline_time': self.baseline_time,
            'current_time': self.current_time,
            'summary': {
                'added': len(self.added),
                'removed': len(self.removed),
                'changed': len(self.changed),
                'unchanged': self.unchanged,
            },
            'added': [_summarize(d) for d in self.added],
            'removed': [_summarize(d) for d in self.removed],
            'changed': [
                {'device': d.label,
                 'changes': [{'field': c.field, 'before': c.before, 'after': c.after}
                             for c in d.changes]}
                for d in self.changed
            ],
        }


# ---------------------------------------------------------------------------
# identity and field access
# ---------------------------------------------------------------------------

def device_key(dev: dict[str, Any]) -> str:
    """Stable identity for a device across scans.

    BACnet devices key on their instance number: it is configured in the
    controller, so a panel that moves to a new IP is still the same panel and
    should be reported as an address change rather than as a disappearance and
    an unrelated arrival. Everything else has no such identifier and keys on
    address, port and unit.
    """
    proto = str(dev.get('protocol', '') or '')
    if proto.startswith('BACnet'):
        instance = dev.get('instance')
        if instance not in (None, ''):
            return f"bacnet:{instance}"
    parts = [proto or '?', str(dev.get('ip', '?'))]
    if dev.get('port') not in (None, ''):
        parts.append(str(dev['port']))
    if dev.get('unit_id') not in (None, ''):
        parts.append(f"unit{dev['unit_id']}")
    return ':'.join(parts)


def _get(dev: dict[str, Any], path: str) -> Any:
    if path == 'object_count':
        objs = dev.get('objects')
        if not isinstance(objs, list) or not objs:
            # Zero means "not enumerated", not "has no objects": every BACnet
            # device holds at least its own Device object, so an empty list is
            # a scan run without --deep, or an enumeration that failed. Diffing
            # it against a real count would report 0 -> 500 on the first deep
            # scan after a shallow one, and 500 -> 0 whenever a device is busy
            # — false alarms that train the reader to ignore the report.
            return None
        return len(objs)
    if path.startswith('properties.'):
        props = dev.get('properties') or {}
        return props.get(path.split('.', 1)[1])
    return dev.get(path)


def _label(dev: dict[str, Any]) -> str:
    name = _get(dev, 'properties.object_name')
    ip = dev.get('ip', '?')
    proto = dev.get('protocol', '?')
    inst = dev.get('instance')
    bits = [str(ip)]
    if inst not in (None, ''):
        bits.append(f"device {inst}")
    if name:
        bits.append(f"{name!r}")
    return f"{proto} {' '.join(bits)}"


def _summarize(dev: dict[str, Any]) -> dict[str, Any]:
    return {
        'label': _label(dev),
        'ip': dev.get('ip'),
        'protocol': dev.get('protocol'),
        'instance': dev.get('instance'),
        'model': _get(dev, 'properties.model_name') or dev.get('identified_model'),
        'vendor': dev.get('vendor_name'),
        'object_count': _get(dev, 'object_count'),
    }


# ---------------------------------------------------------------------------
# the diff
# ---------------------------------------------------------------------------

def diff_scans(baseline: dict[str, Any], current: dict[str, Any]) -> ScanDiff:
    """Compare two scan exports (the dicts written by ScanResult.write_json)."""
    base_devs = {device_key(d): d for d in baseline.get('devices', [])}
    cur_devs = {device_key(d): d for d in current.get('devices', [])}

    out = ScanDiff(
        baseline_time=str(baseline.get('scan_time', '')),
        current_time=str(current.get('scan_time', '')),
    )

    for key in cur_devs.keys() - base_devs.keys():
        out.added.append(cur_devs[key])
    for key in base_devs.keys() - cur_devs.keys():
        out.removed.append(base_devs[key])

    for key in sorted(base_devs.keys() & cur_devs.keys()):
        before, after = base_devs[key], cur_devs[key]
        changes = []
        for path, label in _TRACKED_FIELDS:
            b, a = _get(before, path), _get(after, path)
            # A field absent from one side is not a change — an earlier scan
            # run without --deep has no object count, and reporting that as a
            # drop to zero would cry wolf on every schedule change.
            if b in (None, '') or a in (None, ''):
                continue
            if b != a:
                changes.append(FieldChange(label, b, a))
        if changes:
            out.changed.append(DeviceDiff(key=key, label=_label(after), changes=changes))
        else:
            out.unchanged += 1

    out.added.sort(key=lambda d: str(d.get('ip', '')))
    out.removed.sort(key=lambda d: str(d.get('ip', '')))
    return out


def load_scan(path: str) -> dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if not isinstance(data, dict) or 'devices' not in data:
        raise ValueError(f"{path} does not look like a scan export "
                         f"(no 'devices' key)")
    return data


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def format_text(diff: ScanDiff, show_unchanged: bool = False) -> str:
    """Plain-text report, suitable for a scheduled job to email or log."""
    lines: list[str] = []
    add = lines.append
    add("HVAC Network Scanner — baseline comparison")
    add(f"Baseline: {diff.baseline_time or 'unknown'}")
    add(f"Current:  {diff.current_time or 'unknown'}")
    add("=" * 70)

    if not diff.has_changes:
        add("")
        add(f"No changes. {diff.unchanged} device(s) match the baseline.")
        return "\n".join(lines) + "\n"

    if diff.added:
        add("")
        add(f"NEW ({len(diff.added)})")
        add("-" * 70)
        for dev in diff.added:
            s = _summarize(dev)
            add(f"  + {s['label']}")
            detail = [x for x in (s['vendor'], s['model']) if x]
            if detail:
                add(f"      {' / '.join(str(d) for d in detail)}")
            if s['object_count']:
                add(f"      {s['object_count']} object(s)")

    if diff.removed:
        add("")
        add(f"NOT RESPONDING ({len(diff.removed)})")
        add("-" * 70)
        for dev in diff.removed:
            s = _summarize(dev)
            add(f"  - {s['label']}")
            detail = [x for x in (s['vendor'], s['model']) if x]
            if detail:
                add(f"      {' / '.join(str(d) for d in detail)}")

    if diff.changed:
        add("")
        add(f"CHANGED ({len(diff.changed)})")
        add("-" * 70)
        for d in diff.changed:
            add(f"  ~ {d.label}")
            for c in d.changes:
                add(f"      {c}")

    add("")
    add("=" * 70)
    add(f"{len(diff.added)} new, {len(diff.removed)} not responding, "
        f"{len(diff.changed)} changed, {diff.unchanged} unchanged")
    if show_unchanged:
        add("(unchanged devices omitted from the detail above)")
    return "\n".join(lines) + "\n"


def write_text(diff: ScanDiff, path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(format_text(diff))


def write_json(diff: ScanDiff, path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(diff.to_dict(), f, indent=2, default=str)
