"""HTML survey report.

One self-contained HTML file — no scripts, no external files — that can be
emailed to a building owner or printed: what was scanned, what was found,
and the things worth acting on first.

Built from the scan's JSON form (`ScanResult.to_dict()`), so it can be
produced straight after a scan or later from a saved export:

    hvac-scanner 10.0.0.0/24 --html survey.html
    python -m hvac_scanner.report scan.json -o survey.html

The findings are prompts for a person who knows the site, not verdicts. A
listed default credential means the product ships with one, not that it is
still set; an override may be deliberate. Each finding says which.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from . import __version__

SEVERITIES = ("high", "medium", "low", "info")
_PRIMARY = ('BACnet/IP', 'BACnet/MSTP', 'Modbus TCP', 'SNMP')
_CLEARTEXT = {21: "FTP", 23: "Telnet"}
_HTTPS_PORTS = {443, 8443}
_HTTP_PORTS = {80, 8080, 8000, 8888, 9090}


@dataclass
class Finding:
    severity: str
    title: str
    why: str
    columns: list[str] = field(default_factory=list)
    rows: list[list[str]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _label(dev: dict[str, Any]) -> str:
    props = dev.get('properties') or {}
    name = props.get('object_name') or ''
    model = props.get('model_name') or dev.get('identified_model') or ''
    return " · ".join(x for x in (name, model) if x) or dev.get('protocol', '')


def _concrete_default(creds: str) -> bool:
    """Whether a credentials entry names an actual factory password.

    Entries like "admin / (set at install)" or "Application login
    (site-configured)" describe where the password comes from; there is
    nothing to check them against.
    """
    for alt in creds.split('|'):
        user, sep, password = alt.partition('/')
        if sep and user.strip() and password.strip() and not password.strip().startswith('('):
            return True
    return False


def _days_left(tls: dict[str, Any], now: datetime) -> Optional[int]:
    raw = tls.get('not_after')
    if not raw:
        return tls.get('days_until_expiry')
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return tls.get('days_until_expiry')
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - now).days


def build_findings(scan: dict[str, Any], now: Optional[datetime] = None) -> list[Finding]:
    """Findings, most severe first, from a scan in its JSON form."""
    now = now or datetime.now(timezone.utc)
    devices = scan.get('devices', [])
    services = [d for d in devices if d.get('protocol') == 'Service']
    primary = [d for d in devices if d.get('protocol') in _PRIMARY]
    ports_by_ip: dict[str, set[int]] = {}
    for s in services:
        ports_by_ip.setdefault(s.get('ip'), set()).add(s.get('port'))
    out: list[Finding] = []

    # Default credentials on something with a reachable management interface
    rows = []
    seen = set()
    for d in primary + services:
        creds = d.get('default_creds') or ''
        ip = d.get('ip')
        if not creds or ip in seen or not _concrete_default(creds):
            continue
        mgmt = sorted(p for p in ports_by_ip.get(ip, ()) if p in _HTTP_PORTS | _HTTPS_PORTS
                      | set(_CLEARTEXT) | {22})
        if not (mgmt or d.get('web_url')):
            continue
        seen.add(ip)
        rows.append([ip, _label(d), d.get('web_url') or ", ".join(map(str, mgmt)), creds])
    if rows:
        out.append(Finding(
            "high", "Products with published default credentials and a reachable login",
            "These products ship with the factory credentials shown, and the scan "
            "reached a web or management login on them. Confirm the defaults were "
            "changed — anyone on this network can try them.",
            ["Address", "Device", "Login", "Factory default"], rows))

    # Cleartext management
    rows = []
    for ip, ports in sorted(ports_by_ip.items(), key=lambda kv: _ip_key(kv[0])):
        for port, name in _CLEARTEXT.items():
            if port in ports:
                rows.append([ip, f"{name} (TCP {port})",
                             "credentials and commands cross the network unencrypted"])
        http = sorted(ports & _HTTP_PORTS)
        if http and not (ports & _HTTPS_PORTS):
            rows.append([ip, f"HTTP only (TCP {', '.join(map(str, http))})",
                         "web login without an HTTPS alternative"])
    if rows:
        out.append(Finding(
            "medium", "Management interfaces without encryption",
            "Logins over these protocols can be read by anyone able to capture "
            "traffic on the path. Disable them where the device offers an encrypted "
            "alternative, or keep them on an isolated BAS network.",
            ["Address", "Interface", "Issue"], rows))

    # SNMP with a default community
    rows = [[d.get('ip'), d.get('community', 'public'), (d.get('sys_descr') or '')[:90]]
            for d in devices if d.get('protocol') == 'SNMP'
            and (d.get('community') or 'public') in ('public', 'private')]
    if rows:
        out.append(Finding(
            "medium", "SNMP answering a default community string",
            "Default communities let anyone on the network read the device's "
            "configuration, and 'private' is commonly writable. Change the community "
            "or move to SNMPv3.",
            ["Address", "Community", "sysDescr"], rows))

    # Certificates
    expired, expiring = [], []
    for s in services:
        tls = s.get('tls') or {}
        days = _days_left(tls, now) if tls else None
        if days is None:
            continue
        row = [s.get('ip'), str(s.get('port')), tls.get('subject_cn') or '',
               (tls.get('not_after') or '')[:10],
               f"expired {-days} days ago" if days < 0 else f"{days} days left"]
        if days < 0:
            expired.append(row)
        elif days < 30:
            expiring.append(row)
    if expired:
        out.append(Finding(
            "medium", "Expired TLS certificates",
            "Browsers warn on these, which trains operators to click through "
            "certificate warnings — the habit an attacker relies on.",
            ["Address", "Port", "Subject CN", "Expires", "Status"], expired))
    if expiring:
        out.append(Finding(
            "low", "TLS certificates expiring within 30 days", "Renew before they lapse.",
            ["Address", "Port", "Subject CN", "Expires", "Status"], expiring))

    # Point status
    alarm_rows, override_rows = [], []
    for d in primary:
        for p in d.get('objects') or []:
            status = p.get('status') or ''
            if not status:
                continue
            row = [d.get('ip'), _label(d), f"{p.get('type')} {p.get('instance')}",
                   p.get('name', ''), f"{p.get('present_value', '')} {p.get('units', '')}".strip(),
                   status]
            (alarm_rows if ('alarm' in status or 'fault' in status) else override_rows).append(row)
    cols = ["Address", "Device", "Object", "Name", "Value", "Status"]
    if alarm_rows:
        out.append(Finding(
            "medium", "Points in alarm or fault",
            "The controller itself reports these points as in alarm or faulted.",
            cols, alarm_rows))
    if override_rows:
        out.append(Finding(
            "low", "Points overridden or out of service",
            "Overrides and out-of-service points are often left in place after "
            "commissioning or a service call. Confirm each is intended.",
            cols, override_rows))

    # Modbus has no authentication
    rows = [[d.get('ip'), f"unit {d.get('unit_id')}",
             " ".join(x for x in (d.get('vendor'), d.get('product')) if x and x != 'Unknown')]
            for d in devices if d.get('protocol') == 'Modbus TCP']
    if rows:
        out.append(Finding(
            "low", "Modbus TCP devices",
            "Modbus has no authentication: anything that can reach TCP 502 can read "
            "and, on most devices, write registers. Keep these on a network only the "
            "BAS can reach.",
            ["Address", "Unit", "Identity"], rows))

    # Reachable across subnets
    rows = [[d.get('ip'), str(d.get('instance')), _label(d)]
            for d in devices if d.get('discovered_via') == 'unicast']
    if rows:
        out.append(Finding(
            "info", "BACnet devices reachable from another subnet",
            "These were found by unicast from outside their own subnet, so BACnet "
            "is routed to them. That is expected for a supervisor, and worth "
            "confirming for everything else.",
            ["Address", "Device instance", "Device"], rows))

    out.sort(key=lambda f: SEVERITIES.index(f.severity))
    return out


def _ip_key(ip: Any):
    try:
        return tuple(int(x) for x in str(ip).split('.'))
    except ValueError:
        return (999,)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
:root { --fg:#1f2328; --dim:#59636e; --line:#d1d9e0; --bg:#ffffff; --panel:#f6f8fa;
  --high:#cf222e; --medium:#bc4c00; --low:#9a6700; --info:#0969da; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e6edf3; --dim:#8b949e; --line:#30363d; --bg:#0d1117; --panel:#161b22;
    --high:#f85149; --medium:#db6d28; --low:#d29922; --info:#58a6ff; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
main { max-width: 1180px; margin: 0 auto; padding: 32px 24px 64px; }
h1 { font-size: 26px; margin: 0 0 4px; }
h2 { font-size: 18px; margin: 40px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
h3 { font-size: 15px; margin: 0; }
.meta { color: var(--dim); margin: 0 0 24px; }
.cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
.card b { display: block; font-size: 22px; }
.card span { color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.finding { border: 1px solid var(--line); border-left: 4px solid var(--sev); border-radius: 8px;
  padding: 14px 16px; margin: 0 0 14px; background: var(--panel); }
.finding p { margin: 6px 0 10px; color: var(--dim); }
.sev { display: inline-block; min-width: 64px; text-align: center; font-size: 11px; font-weight: 700;
  text-transform: uppercase; color: #fff; background: var(--sev); border-radius: 10px;
  padding: 1px 8px; margin-right: 8px; vertical-align: 2px; }
.high { --sev: var(--high); } .medium { --sev: var(--medium); }
.low { --sev: var(--low); } .info { --sev: var(--info); }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--dim); font-weight: 600; }
td.mono, .mono { font-family: "Cascadia Mono", Consolas, ui-monospace, monospace; font-size: 12px; }
.none { color: var(--dim); font-style: italic; }
footer { margin-top: 48px; color: var(--dim); font-size: 12px; }
@media print { body { font-size: 11px; } main { padding: 0; } .finding { break-inside: avoid; }
  h2 { break-after: avoid; } }
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _table(columns: list[str], rows: list[list[Any]], mono: tuple[int, ...] = (0,)) -> str:
    if not rows:
        return '<p class="none">None.</p>'
    head = "".join(f"<th>{_e(c)}</th>" for c in columns)
    body = []
    for row in rows:
        cells = "".join(f'<td class="mono">{_e(v)}</td>' if i in mono else f"<td>{_e(v)}</td>"
                        for i, v in enumerate(row))
        body.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"


def render_html(scan: dict[str, Any], now: Optional[datetime] = None) -> str:
    """The report for a scan in its JSON form, as one HTML document."""
    now = now or datetime.now(timezone.utc)
    devices = scan.get('devices', [])
    counts = scan.get('counts', {})
    findings = build_findings(scan, now)
    primary = [d for d in devices if d.get('protocol') in _PRIMARY]
    primary_ips = {d.get('ip') for d in primary}
    service_only = {}
    for d in devices:
        if d.get('protocol') == 'Service' and d.get('ip') not in primary_ips:
            service_only.setdefault(d.get('ip'), d)
    hosts = len({d.get('ip') for d in devices if d.get('ip')})
    flagged = sum(1 for d in primary for p in d.get('objects') or [] if p.get('status'))

    sev_counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    cards = [("Hosts", hosts), ("BACnet/IP", counts.get('bacnet', 0)),
             ("MS/TP", counts.get('mstp', 0)), ("Modbus", counts.get('modbus', 0)),
             ("Service ports", counts.get('services', 0)), ("SNMP", counts.get('snmp', 0)),
             ("Points", f"{counts.get('points', 0):,}"), ("Flagged points", flagged)]
    cards_html = "".join(f'<div class="card"><b>{_e(v)}</b><span>{_e(k)}</span></div>'
                         for k, v in cards)

    parts = []
    if findings:
        for f in findings:
            parts.append(
                f'<div class="finding {f.severity}"><h3><span class="sev">{f.severity}</span>'
                f'{_e(f.title)} <span class="meta">({len(f.rows)})</span></h3>'
                f'<p>{_e(f.why)}</p>{_table(f.columns, f.rows)}</div>')
    else:
        parts.append('<p class="none">Nothing to report.</p>')
    findings_html = "".join(parts)

    inv_rows = []
    for d in sorted(primary, key=lambda d: (_ip_key(d.get('ip')), str(d.get('instance')))):
        props = d.get('properties') or {}
        ident = d.get('instance') if str(d.get('protocol', '')).startswith('BACnet') \
            else (f"unit {d.get('unit_id')}" if d.get('protocol') == 'Modbus TCP' else '')
        if d.get('source_network'):
            ident = f"{ident} (MS/TP {d.get('source_network')}:{d.get('source_address')})"
        flags = d.get('point_flags') or {}
        inv_rows.append([
            d.get('ip'), d.get('protocol'), ident, props.get('object_name', ''),
            props.get('model_name') or d.get('identified_model') or d.get('product') or '',
            d.get('vendor_name') or d.get('vendor') or '',
            props.get('firmware_revision', ''), props.get('location', ''),
            len(d.get('objects') or []) or '',
            ", ".join(f"{n} {k}" for k, n in flags.items()),
        ])
    for ip, d in sorted(service_only.items(), key=lambda kv: _ip_key(kv[0])):
        inv_rows.append([ip, "Services only", '', '', d.get('identified_model') or d.get('title') or '',
                         d.get('vendor', ''), '', '', '', ''])

    svc_rows = [[d.get('ip'), d.get('port'), d.get('service', ''), d.get('vendor', ''),
                 d.get('title') or d.get('product') or '', d.get('tls_summary', '')]
                for d in sorted((d for d in devices if d.get('protocol') == 'Service'),
                                key=lambda d: (_ip_key(d.get('ip')), d.get('port') or 0))]

    targets = ", ".join(scan.get('targets') or []) or "not recorded"
    try:
        scanned = datetime.fromisoformat(scan.get('scan_time', '')).strftime('%Y-%m-%d %H:%M')
    except (TypeError, ValueError):
        scanned = scan.get('scan_time', 'unknown')
    summary = ", ".join(f"{n} {s}" for s, n in sev_counts.items() if n) or "no findings"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BAS network survey — {_e(targets)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>Building automation network survey</h1>
<p class="meta">Targets <span class="mono">{_e(targets)}</span> · scanned {_e(scanned)}
 · {_e(round(scan.get('elapsed_seconds', 0) or 0, 1))} s · findings: {_e(summary)}</p>
<div class="cards">{cards_html}</div>

<h2>Findings</h2>
{findings_html}

<h2>Device inventory</h2>
{_table(["Address", "Protocol", "ID", "Name", "Model", "Vendor", "Firmware", "Location",
         "Points", "Flagged"], inv_rows)}

<h2>Open service ports</h2>
{_table(["Address", "Port", "Service", "Vendor", "Title / product", "TLS certificate"], svc_rows)}

<footer>
Generated {_e(now.astimezone().strftime('%Y-%m-%d %H:%M'))} by HVAC Network Scanner
{_e(__version__)} ({_e(scan.get('scanner', ''))} produced the scan). Discovery is read-only:
nothing was written to any device and no credentials were tried. Default credentials are the
vendors' published factory defaults, listed so the owner can confirm they were changed.
</footer>
</main>
</body>
</html>
"""


def write_html(scan: dict[str, Any], path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(render_html(scan))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m hvac_scanner.report",
        description="Build the HTML survey report from a saved scan (JSON export).")
    p.add_argument("scan", help="scan JSON written by --json or the GUI's export")
    p.add_argument("-o", "--output", help="HTML file to write (default: next to the JSON)")
    args = p.parse_args(argv)
    try:
        with open(args.scan, encoding='utf-8') as f:
            scan = json.load(f)
    except (OSError, ValueError) as e:
        print(f"ERROR: could not read {args.scan}: {e}", file=sys.stderr)
        return 1
    if not isinstance(scan, dict) or 'devices' not in scan:
        print(f"ERROR: {args.scan} is not a scan export", file=sys.stderr)
        return 1
    out = args.output or (args.scan.rsplit('.', 1)[0] + ".html")
    write_html(scan, out)
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
