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
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from datetime import datetime

from .engine import ScanEngine, ScanOptions


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
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

    p.add_argument("networks", nargs="+",
                   help="CIDR networks to scan (e.g. 192.168.1.0/24)")
    p.add_argument("--networks", dest="networks", nargs="+", default=None,
                   help=argparse.SUPPRESS)  # alternate spelling
    p.add_argument("--broadcast", type=str, default=None, metavar="IP",
                   help="Override BACnet Who-Is broadcast target (e.g. "
                        "10.0.0.255 or 255.255.255.255). Needed when "
                        "scanning a narrower CIDR than the physical subnet.")
    p.add_argument("--scan-depth", choices=["quick", "normal", "full"],
                   default="normal",
                   help="Scan depth. 'quick' samples ~5%% of each device's "
                        "points (fast overview). 'normal' uses vendor-aware "
                        "caps (default). 'full' reads every object (slow on "
                        "supervisory controllers).")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Per-operation timeout in seconds (default: 5)")
    p.add_argument("--rate-limit", type=int, default=0, metavar="MS",
                   help="Minimum ms between BACnet packets to the same IP (0=off)")
    p.add_argument("--max-objects", type=int, default=500,
                   help="Max objects to enumerate per BACnet device (default: 500)")
    p.add_argument("--no-rpm", action="store_true",
                   help="Disable ReadPropertyMultiple (force one read per property)")

    # Large-network probing
    d = p.add_argument_group("large-network probing")
    d.add_argument("--whois-chunk", type=int, default=0, metavar="SIZE",
                   help="Split Who-Is by instance range in steps of SIZE "
                        "(default: 0 = single broadcast). Gentler on big "
                        "sites that would otherwise I-Am-storm on a global.")
    d.add_argument("--whois-max-instance", type=int, default=4_194_303,
                   metavar="N",
                   help="Upper bound on instance ranges when chunking "
                        "(default: 4194303, the BACnet max). Only used "
                        "with --whois-chunk.")
    d.add_argument("--whois-chunk-delay", type=int, default=50, metavar="MS",
                   help="Sleep between chunked Who-Is broadcasts (default: 50ms)")

    # Protocol toggles
    g = p.add_argument_group("protocols (all enabled by default)")
    g.add_argument("--no-bacnet", action="store_true")
    g.add_argument("--no-mstp",   action="store_true")
    g.add_argument("--no-modbus", action="store_true")
    g.add_argument("--no-services", action="store_true")
    g.add_argument("--no-snmp",   action="store_true")
    g.add_argument("--no-deep",   action="store_true",
                   help="Skip deep-scan (object lists, register reads)")
    g.add_argument("--bacnet-only", action="store_true",
                   help="Shortcut for --no-modbus --no-services --no-snmp")

    # Output
    o = p.add_argument_group("output")
    o.add_argument("--json", metavar="PATH", help="Write results to JSON file")
    o.add_argument("--csv",  metavar="PATH", help="Write results to CSV file")
    o.add_argument("--export-classification", metavar="PATH",
                   help="Write a classification report (v2.2). Useful for "
                        "submitting device profile contributions.")
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
    for key in ('bacnet', 'mstp', 'modbus', 'services', 'snmp'):
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


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _configure_logging(args.verbose, args.quiet)

    if args.bacnet_only:
        args.no_modbus = args.no_services = args.no_snmp = True

    opts = ScanOptions(
        networks=list(args.networks),
        timeout=args.timeout,
        scan_bacnet=not args.no_bacnet,
        scan_mstp=not args.no_mstp,
        scan_modbus=not args.no_modbus,
        scan_services=not args.no_services,
        scan_snmp=not args.no_snmp,
        deep_scan=not args.no_deep,
        use_rpm=not args.no_rpm,
        rate_limit_ms=args.rate_limit,
        max_objects_per_device=args.max_objects,
        whois_chunk_size=args.whois_chunk,
        whois_max_instance=args.whois_max_instance,
        whois_chunk_delay_ms=args.whois_chunk_delay,
        bacnet_broadcast=args.broadcast,
        scan_depth=args.scan_depth,
    )

    # Progress callback — streams log lines to stderr unless quiet
    def cb(msg: str) -> None:
        if not args.quiet:
            print(msg, file=sys.stderr, flush=True)

    stop_event = threading.Event()

    def _sigint(_signum, _frame):
        print("\n[interrupt — stopping after current step]", file=sys.stderr)
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

    if args.print == "summary":
        _print_summary(result)
    elif args.print == "table":
        _print_summary(result)
        print()
        _print_table(result)
    elif args.print == "json":
        _print_json(result)
    # "none" prints nothing to stdout

    return 2 if stop_event.is_set() else 0


if __name__ == "__main__":
    sys.exit(main())
