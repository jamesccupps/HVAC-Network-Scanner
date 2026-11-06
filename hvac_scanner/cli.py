"""
Headless CLI for the HVAC Network Scanner.

Usage:
    python -m hvac_scanner.cli 192.168.1.0/24
    python -m hvac_scanner.cli 10.0.0.0/24 --json out.json --csv out.csv
    python -m hvac_scanner.cli 192.168.5.0/24 --no-services --no-snmp --quiet
    python -m hvac_scanner.cli 192.168.5.0/24 --rate-limit 50

Designed to run under Task Scheduler / cron for scheduled audits.
Exit codes:
    0 - scan completed (may be zero devices)
    1 - invalid arguments
    2 - scan interrupted
    3 - internal error
    4 - scan completed and differed from the baseline (--fail-on-change)
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from datetime import datetime

from . import __version__
from .engine import ScanEngine, ScanOptions


class _Parser(argparse.ArgumentParser):
    """Argument errors exit 1, as documented. argparse's own 2 is this
    tool's "interrupted", so a scheduled job with a mistyped flag was
    reported as a scan that had been stopped."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def _number(kind, low=None, high=None, name="value"):
    """An argparse type: `kind` (int or float) within [low, high]. A typo
    used to fall through to a default such as no rate limit at all."""
    def parse(text: str):
        try:
            value = kind(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
        if (low is not None and value < low) or (high is not None and value > high):
            bounds = (f"at least {low}" if high is None else
                      f"between {low} and {high}" if low is not None else f"at most {high}")
            raise argparse.ArgumentTypeError(f"{name} must be {bounds}, not {text}")
        return value
    return parse


def _ipv4(text: str) -> str:
    import ipaddress
    try:
        return str(ipaddress.IPv4Address(text.strip()))
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an IPv4 address") from None


def _positive_timeout(text: str) -> float:
    value = _number(float, name="timeout")(text)
    if value <= 0:
        raise argparse.ArgumentTypeError(f"timeout must be more than 0, not {text}")
    return value


# Defaults for the options that take a value. The parser's own default for
# each is None, so main() can tell "given on the command line" (which beats a
# site profile) from "not given" (the profile, else these): comparing with
# the default could not tell `--unicast auto` from no flag at all.
_DEFAULTS = {
    'timeout': 5.0, 'rate_limit': 0, 'scan_depth': 'normal', 'bacnet_workers': 4,
    'device_time_limit': 180.0,
    'whois_chunk': 0, 'whois_max_instance': 4_194_303, 'whois_chunk_delay': 50,
    'bbmd_ttl': 60, 'unicast': 'auto', 'max_hosts': 65_536,
}


def _build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="hvac-scanner",
        description="Multi-protocol HVAC / BAS network scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  hvac-scanner 192.168.1.0/24\n"
            "  hvac-scanner 10.0.0.0/24 --json scan.json\n"
            "  hvac-scanner 192.168.5.0/24 --bacnet-only --timeout 8\n"
        ),
    )

    p.add_argument("networks", nargs="*",
                   help="Targets to scan: CIDR (192.168.1.0/24), single host, "
                        "range (10.0.0.2-100), or a mix. Optional with --profile.")
    # Alternate spelling. It shares `dest` with the positional, so argparse
    # applies it second and the positional's value is discarded - passing both
    # used to silently scan only the flag's networks. Collected separately and
    # merged in main() instead.
    p.add_argument("--networks", dest="networks_flag", nargs="+", default=None,
                   help=argparse.SUPPRESS)
    p.add_argument("--broadcast", type=_ipv4, default=None, metavar="IP",
                   help="Override BACnet Who-Is broadcast target (e.g. "
                        "10.0.0.255 or 255.255.255.255). Needed when "
                        "scanning a narrower CIDR than the physical subnet.")
    p.add_argument("--scan-depth", choices=["devices", "quick", "normal", "full"],
                   default=None,
                   help="Scan depth. 'devices' reads only each device's "
                        "identity (name, model, vendor, firmware): the fastest "
                        "inventory, no points. 'quick' samples ~5%% of each device's "
                        "points (fast overview). 'normal' uses vendor-aware "
                        "caps (default). 'full' reads every object (slow on "
                        "supervisory controllers).")
    p.add_argument("--timeout", type=_positive_timeout, default=None,
                   help="Per-operation timeout in seconds (default: 5)")
    p.add_argument("--rate-limit", type=_number(int, 0, name="rate limit"),
                   default=None, metavar="MS",
                   help="Minimum ms between BACnet packets to the same IP (0=off)")
    p.add_argument("--max-objects", type=_number(int, 1, name="max objects"),
                   default=None, metavar="N",
                   help="Hard ceiling on objects enumerated per BACnet device. "
                        "Applied on top of the vendor-aware profile cap and "
                        "only ever lowers it. Omit to use the profile cap "
                        "(the default).")
    p.add_argument("--no-rpm", action="store_true",
                   help="Disable ReadPropertyMultiple (force one read per property)")
    p.add_argument("--device-time-limit", type=_number(float, 0, name="device time limit"),
                   default=None, metavar="SECONDS",
                   help="Most time one device's deep scan may take before the "
                        "scan keeps what it has read and moves on (default: "
                        "180; 0 = no limit). A controller that drops requests "
                        "costs a timeout for each one.")
    p.add_argument("--bacnet-workers", type=_number(int, 1, 64, name="BACnet workers"),
                   default=None, metavar="N",
                   help="BACnet devices deep-scanned at once (default: 4). Each "
                        "worker owns one IP address, so no device sees more "
                        "than one request at a time either way; 1 scans "
                        "strictly one device after another.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")

    s = p.add_argument_group("site profiles (saved from the GUI)")
    s.add_argument("--profile", metavar="NAME",
                   help="Scan a site profile saved in the GUI: its targets and "
                        "options. Targets and flags given here override it.")
    s.add_argument("--list-profiles", action="store_true",
                   help="List the saved site profiles and exit")
    s.add_argument("--settings-file", metavar="PATH", default=None,
                   help="Settings file holding the profiles (default: the GUI's)")

    # Large-network probing
    d = p.add_argument_group("large-network probing")
    d.add_argument("--whois-chunk", type=_number(int, 0, name="Who-Is chunk"),
                   default=None, metavar="SIZE",
                   help="Split Who-Is by instance range in steps of SIZE "
                        "(default: 0 = single broadcast). Gentler on big "
                        "sites that would otherwise I-Am-storm on a global.")
    d.add_argument("--whois-max-instance",
                   type=_number(int, 0, 4_194_303, name="Who-Is max instance"),
                   default=None,
                   metavar="N",
                   help="Upper bound on instance ranges when chunking "
                        "(default: 4194303, the BACnet max). Only used "
                        "with --whois-chunk.")
    d.add_argument("--whois-chunk-delay", type=_number(int, 0, name="Who-Is chunk delay"),
                   default=None, metavar="MS",
                   help="Sleep between chunked Who-Is broadcasts (default: 50ms)")
    d.add_argument("--bbmd", type=_ipv4, metavar="IP",
                   help="Register as a Foreign Device with this BBMD and send "
                        "Who-Is through it. Discovers devices on subnets the "
                        "scanner cannot broadcast to - one host can then scan "
                        "several buildings. Without this, discovery only sees "
                        "the local subnet.")
    d.add_argument("--bbmd-ttl", type=_number(int, 10, 300, name="BBMD TTL"),
                   default=None, metavar="SECONDS",
                   help="Foreign Device registration lease, 10-300 (default: "
                        "60). Registering adds an entry to the BBMD's "
                        "foreign-device table, the one write this tool makes; "
                        "it is renewed during long scans and expires on its "
                        "own after.")
    d.add_argument("--unicast", choices=["auto", "always", "off"], default=None,
                   help="Unicast BACnet discovery for targets a broadcast "
                        "cannot reach. 'auto' (default) probes target "
                        "addresses on other subnets that did not answer the "
                        "broadcast; 'always' probes every silent target; "
                        "'off' relies on broadcast alone.")
    d.add_argument("--snmp-community", action="append", metavar="NAME",
                   help="SNMP community to try (repeatable; default: public). "
                        "Each one is tried only against hosts that did not "
                        "answer the previous. A community is a password of "
                        "sorts: agents may log or trap a wrong one.")
    d.add_argument("--max-hosts", type=_number(int, 1, name="max hosts"),
                   default=None, metavar="N",
                   help="Refuse to scan more than N addresses in total "
                        "(default: 65536). A guard against a mistyped prefix.")
    d.add_argument("--mstp-probe", action="store_true",
                   help="For MS/TP networks behind a router on another subnet, "
                        "ask each MS/TP address in turn, two at a time (a few "
                        "minutes per network). Finds devices whose I-Am "
                        "broadcasts cannot reach this subnet, without a BBMD.")
    d.add_argument("--no-bbmd-tables", action="store_true",
                   help="Do not read BBMDs' broadcast and foreign-device tables")
    d.add_argument("--no-metadata", action="store_true",
                   help="Do not read trend log, schedule, calendar and network "
                        "port metadata")

    # Protocol toggles
    g = p.add_argument_group("protocols (all enabled by default)")
    g.add_argument("--no-bacnet", action="store_true")
    g.add_argument("--no-mstp",   action="store_true")
    g.add_argument("--no-modbus", action="store_true")
    g.add_argument("--no-services", action="store_true")
    g.add_argument("--no-snmp",   action="store_true")
    g.add_argument("--no-p2",     action="store_true",
                   help="Skip Siemens APOGEE P2 detection (TCP 5033)")
    g.add_argument("--no-knx",    action="store_true",
                   help="Skip KNXnet/IP gateway detection (UDP 3671)")
    g.add_argument("--no-deep",   action="store_true",
                   help="Skip deep-scan (object lists, register reads)")
    g.add_argument("--bacnet-only", action="store_true",
                   help="Shortcut for --no-modbus --no-services --no-snmp --no-p2 --no-knx")

    # Output
    o = p.add_argument_group("output")
    o.add_argument("--json", metavar="PATH", help="Write results to JSON file")
    o.add_argument("--csv",  metavar="PATH", help="Write results to CSV file")
    o.add_argument("--html", metavar="PATH",
                   help="Write a self-contained HTML survey report: findings "
                        "(default credentials, cleartext logins, certificates, "
                        "points in alarm or overridden), inventory, open services.")
    o.add_argument("--points-csv", metavar="PATH",
                   help="Write the point list: one row per BACnet point and "
                        "Modbus register.")
    o.add_argument("--export-classification", metavar="PATH",
                   help="Write a classification report (v2.2). Useful for "
                        "submitting device profile contributions.")

    b = p.add_argument_group("baseline comparison")
    b.add_argument("--baseline", metavar="PATH",
                   help="Compare this scan against a previous JSON export and "
                        "report what changed: devices that appeared or stopped "
                        "responding, and changes to model, firmware, address "
                        "or object count.")
    b.add_argument("--save-baseline", metavar="PATH",
                   help="Write this scan's JSON to PATH for a later --baseline "
                        "comparison. Written even when --baseline reports "
                        "changes, so the next run compares against this one.")
    b.add_argument("--diff-output", metavar="PATH",
                   help="Write the comparison report to PATH (.json for JSON, "
                        "anything else for text). Defaults to stdout.")
    b.add_argument("--fail-on-change", action="store_true",
                   help="Exit 4 when the scan differs from the baseline. For "
                        "scheduled runs that should alert only on change.")
    o.add_argument("--print", choices=["summary", "table", "json", "none"],
                   default="summary", help="Stdout format (default: summary)")
    o.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress progress log (output only)")
    o.add_argument("--verbose", "-v", action="store_true",
                   help="Enable DEBUG logging")

    return p


def _configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_summary(result) -> None:
    print()
    print(f"=== Scan Summary ({datetime.now():%Y-%m-%d %H:%M:%S}) ===")
    print(f"Duration:   {result.elapsed:.1f}s")
    for key in ('bacnet', 'mstp', 'modbus', 'services', 'snmp', 'p2', 'knx'):
        print(f"  {key:10s} {result.counts[key]:4d}")
    print(f"  {'points':10s} {result.counts['points']:4d}")
    # Match the engine's / GUI's definition: unique IPs, not summed protocol counts.
    # An IP that answered on BACnet + HTTPS + FTP is one host, not three.
    unique_hosts = len({d.get('ip') for d in result.devices if d.get('ip')})
    print(f"Unique hosts: {unique_hosts}")


def _print_table(result) -> None:
    rows = []
    for dev in result.devices:
        fp = dev.get('_fingerprint', {})
        rows.append((
            str(dev.get('protocol', '?'))[:12],
            str(dev.get('ip', '?'))[:15],
            str(dev.get('port', '?'))[:5],
            str(dev.get('instance', dev.get('unit_id', '')))[:10],
            (fp.get('model') or '')[:34],
            (dev.get('vendor_name') or dev.get('vendor') or '')[:22],
        ))
    if not rows:
        print("  (no devices found)")
        return
    hdr = ("PROTOCOL", "IP", "PORT", "ID", "MODEL", "VENDOR")
    widths = [max(len(str(r[i])) for r in [hdr] + rows) for i in range(len(hdr))]
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*hdr))
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt.format(*r))


def _print_json(result) -> None:
    import json as _json
    print(_json.dumps(result.to_dict(), indent=2, default=str))


_UNREADABLE = object()


def _read_baseline(args):
    """The --baseline scan, None if there is none to compare with, or
    _UNREADABLE (after saying why) if it exists and cannot be used.

    A missing file is the first run of a schedule when --save-baseline
    names the same path: the run creates it. A damaged one is an error
    before anything is scanned; a schedule that kept going past it used to
    fail every night and never write a replacement.
    """
    if not args.baseline:
        return None
    from pathlib import Path
    from . import diff as diffmod
    if not Path(args.baseline).exists():
        if args.save_baseline:
            print(f"No baseline at {args.baseline} yet; this run will be the first "
                  f"one compared against.", file=sys.stderr)
            return None
        print(f"ERROR: baseline {args.baseline} does not exist", file=sys.stderr)
        return _UNREADABLE
    try:
        return diffmod.load_scan(args.baseline)
    except (OSError, ValueError) as e:
        print(f"ERROR: could not read baseline {args.baseline}: {e}. Delete or "
              f"replace it (a scan with --save-baseline writes a new one).",
              file=sys.stderr)
        return _UNREADABLE


def _handle_baseline(args, result, baseline=None) -> bool:
    """Compare against a baseline and/or save one. Returns True if changed.

    Saving happens even when the comparison found changes, so an unattended
    schedule rolls its baseline forward and reports each night's delta rather
    than re-reporting the same drift forever. A partial scan (stopped, or a
    pass skipped or failed) is not saved: rolling forward on it made the next
    night report everything it missed as new.
    """
    from . import diff as diffmod

    if not result.complete:
        gaps = ", ".join(f"{k} {v}" for k, v in result.passes.items()
                         if v not in ('scanned', 'off'))
        print(f"Warning: this scan is partial ({'stopped' if result.stopped else gaps}); "
              f"devices it did not reach may show as gone.", file=sys.stderr)

    changed = False
    if baseline is not None:
        d = diffmod.diff_scans(baseline, result.to_dict())
        changed = d.has_changes
        if args.diff_output:
            if args.diff_output.lower().endswith('.json'):
                diffmod.write_json(d, args.diff_output)
            else:
                diffmod.write_text(d, args.diff_output)
            if not args.quiet:
                print(f"Wrote comparison: {args.diff_output}", file=sys.stderr)
        else:
            print(diffmod.format_text(d))

    if args.save_baseline and not result.complete:
        print(f"Not saving the baseline: the scan was partial, so "
              f"{args.save_baseline} still holds the last complete one.",
              file=sys.stderr)
    elif args.save_baseline:
        result.write_json(args.save_baseline)
        if not args.quiet:
            print(f"Wrote baseline: {args.save_baseline}", file=sys.stderr)

    return changed


def _utf8_streams() -> None:
    """Never let an encoding error kill a scan's output.

    Unit labels (°F, m², Ω) and the log's punctuation are not all in the
    Windows ANSI code page, which is what stdout/stderr use when redirected
    to a file — the normal case under Task Scheduler. Write UTF-8 instead.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass


# ScanOptions field -> the argument that sets it, for letting flags given on
# the command line override a saved profile.
_ARG_FOR_OPTION = {
    'timeout': 'timeout', 'scan_bacnet': 'no_bacnet', 'scan_mstp': 'no_mstp',
    'scan_modbus': 'no_modbus', 'scan_services': 'no_services', 'scan_snmp': 'no_snmp',
    'scan_p2': 'no_p2', 'scan_knx': 'no_knx', 'deep_scan': 'no_deep', 'use_rpm': 'no_rpm',
    'rate_limit_ms': 'rate_limit', 'max_objects_per_device': 'max_objects',
    'whois_chunk_size': 'whois_chunk', 'bacnet_broadcast': 'broadcast', 'bbmd': 'bbmd',
    'scan_depth': 'scan_depth', 'bacnet_workers': 'bacnet_workers',
    'device_time_limit': 'device_time_limit',
    'unicast_discovery': 'unicast', 'snmp_communities': 'snmp_community',
    'read_bbmd_tables': 'no_bbmd_tables', 'read_metadata': 'no_metadata',
    'mstp_mac_probe': 'mstp_probe',
}


def _load_profiles(args) -> dict:
    from . import settings
    from pathlib import Path
    path = Path(args.settings_file) if args.settings_file else settings.default_path()
    return settings.profiles(settings.load(path))


def main(argv: list[str] | None = None) -> int:
    _utf8_streams()
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose, args.quiet)

    if args.list_profiles:
        saved = _load_profiles(args)
        if not saved:
            print("No saved site profiles. Save one from the GUI (Site > Save).")
        for name, prof in sorted(saved.items(), key=lambda kv: kv[0].lower()):
            print(f"{name}\t{prof.get('targets', '')}")
        return 0

    profile_kw: dict = {}
    if args.profile:
        from .settings import profile_options
        saved = _load_profiles(args)
        if args.profile not in saved:
            known = ", ".join(sorted(saved)) or "none saved"
            print(f"ERROR: no site profile named {args.profile!r} ({known})",
                  file=sys.stderr)
            return 1
        profile_kw = profile_options(saved[args.profile])

    # Merge the positional targets with the --networks alternate spelling,
    # preserving order and dropping duplicates, rather than letting one
    # silently replace the other.
    networks = list(args.networks or [])
    for n in (args.networks_flag or []):
        if n not in networks:
            networks.append(n)
    if not networks:
        networks = list(profile_kw.get('networks') or [])
    if not networks:
        parser.error("the following arguments are required: networks "
                     "(or --profile NAME)")

    # A target that will not parse is a bad argument (exit 1), and should be
    # reported before anything is sent rather than as a scan that "completed"
    # with nothing in it.
    from .netrange import parse_targets, InvalidTargetSyntaxError
    total_hosts = 0
    for n in networks:
        try:
            total_hosts += len(parse_targets(n))
        except InvalidTargetSyntaxError as e:
            print(f"ERROR: invalid target {n!r}: {e}", file=sys.stderr)
            return 1
    # The per-entry limit stops one mistyped prefix; this stops several.
    max_hosts = args.max_hosts or _DEFAULTS['max_hosts']
    if total_hosts > max_hosts:
        print(f"ERROR: the targets cover {total_hosts:,} addresses, more than "
              f"--max-hosts ({max_hosts:,}). Check the prefixes, or raise "
              f"--max-hosts if that many is intended.", file=sys.stderr)
        return 1

    # Read the baseline before scanning, so a missing or damaged one is
    # reported before the network is touched rather than after an hour.
    baseline = _read_baseline(args)
    if baseline is _UNREADABLE:
        return 1

    if args.bacnet_only:
        args.no_modbus = args.no_services = args.no_snmp = args.no_p2 = args.no_knx = True
    given = {dest for dest in _DEFAULTS if getattr(args, dest, None) is not None}
    for dest, default in _DEFAULTS.items():
        if getattr(args, dest, None) is None:
            setattr(args, dest, default)

    kw = dict(
        networks=networks,
        timeout=args.timeout,
        scan_bacnet=not args.no_bacnet,
        scan_mstp=not args.no_mstp,
        scan_modbus=not args.no_modbus,
        scan_services=not args.no_services,
        scan_snmp=not args.no_snmp,
        scan_p2=not args.no_p2,
        scan_knx=not args.no_knx,
        deep_scan=not args.no_deep,
        use_rpm=not args.no_rpm,
        rate_limit_ms=args.rate_limit,
        max_objects_per_device=args.max_objects,
        whois_chunk_size=args.whois_chunk,
        whois_max_instance=args.whois_max_instance,
        whois_chunk_delay_ms=args.whois_chunk_delay,
        bacnet_broadcast=args.broadcast,
        bbmd=args.bbmd,
        bbmd_ttl=args.bbmd_ttl,
        scan_depth=args.scan_depth,
        bacnet_workers=args.bacnet_workers,
        device_time_limit=args.device_time_limit,
        unicast_discovery=args.unicast,
        snmp_communities=args.snmp_community or ["public"],
        read_bbmd_tables=not args.no_bbmd_tables,
        read_metadata=not args.no_metadata,
        mstp_mac_probe=args.mstp_probe,
    )
    # The profile fills in whatever was not given on the command line. A
    # value option was given if it is not None (its parser default); an
    # on/off flag if it is set, since a flag can only turn something on.
    for option, value in profile_kw.items():
        dest = _ARG_FOR_OPTION.get(option)
        if dest is None:
            continue
        explicit = dest in given if dest in _DEFAULTS else bool(getattr(args, dest, None))
        if not explicit:
            kw[option] = value
    opts = ScanOptions(**kw)

    # Progress callback - streams log lines to stderr unless quiet
    def cb(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr, flush=True)

    stop_event = threading.Event()

    def _sigint(_signum, _frame):
        print("\n[interrupt - stopping after current step]", file=sys.stderr)
        stop_event.set()

    signal.signal(signal.SIGINT, _sigint)

    engine = ScanEngine(opts, callback=cb, stop_event=stop_event)
    try:
        result = engine.run()
    except Exception as e:
        logging.exception("scan failed")
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    if args.json:
        try:
            result.write_json(args.json)
            if not args.quiet:
                print(f"Wrote JSON: {args.json}", file=sys.stderr)
        except OSError as e:
            print(f"ERROR: could not write {args.json}: {e}", file=sys.stderr)
            return 3

    if args.csv:
        try:
            result.write_csv(args.csv)
            if not args.quiet:
                print(f"Wrote CSV:  {args.csv}", file=sys.stderr)
        except OSError as e:
            print(f"ERROR: could not write {args.csv}: {e}", file=sys.stderr)
            return 3

    for path, writer, label in ((args.html, result.write_html, "HTML report"),
                                (args.points_csv, result.write_points_csv, "point list")):
        if not path:
            continue
        try:
            writer(path)
            if not args.quiet:
                print(f"Wrote {label}: {path}", file=sys.stderr)
        except OSError as e:
            print(f"ERROR: could not write {path}: {e}", file=sys.stderr)
            return 3

    if args.export_classification:
        try:
            result.write_classification_report(args.export_classification)
            if not args.quiet:
                print(f"Wrote classification report: {args.export_classification}",
                      file=sys.stderr)
        except OSError as e:
            print(f"ERROR: could not write {args.export_classification}: {e}",
                  file=sys.stderr)
            return 3

    changed = False
    if args.baseline or args.save_baseline:
        try:
            changed = _handle_baseline(args, result, baseline)
        except (OSError, ValueError) as e:
            print(f"ERROR: baseline comparison failed: {e}", file=sys.stderr)
            return 3

    if args.print == "summary":
        _print_summary(result)
    elif args.print == "table":
        _print_summary(result)
        print()
        _print_table(result)
    elif args.print == "json":
        _print_json(result)
    # "none" prints nothing to stdout

    if stop_event.is_set() or result.stopped:
        return 2
    if changed and args.fail_on_change:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
