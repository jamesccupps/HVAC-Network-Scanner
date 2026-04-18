"""
Scan orchestrator.

Runs a full multi-protocol scan and produces a result set. This is the
shared engine used by both the Tk GUI and the CLI.

Design:
- No UI dependencies — callers pass a logger callback
- ScanOptions is a simple dataclass, decoupled from argparse/tk.Vars
- ScanResult holds devices, points, services; export helpers live here

Parallelism:
- BACnet IP discovery is serialized (needs a single bound UDP port)
- Deep-scan per-device is serialized (preserves reply correlation)
- Modbus, services, SNMP sweeps use their own thread pools
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from .bacnet import BACnetClient
from .constants import (
    BACNET_VENDORS,
    BACNET_UNITS,
    DEFAULT_POINT_PROPERTIES,
    HTTP_FINGERPRINTS,
)
from .fingerprint import fingerprint_device
from .modbus import ModbusScanner
from .services import HVACServiceScanner
from .snmp import SNMPScanner

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Options and results
# ---------------------------------------------------------------------------

@dataclass
class ScanOptions:
    networks: list[str] = field(default_factory=list)
    timeout: float = 5.0
    scan_bacnet: bool = True
    scan_mstp: bool = True
    scan_modbus: bool = True
    scan_services: bool = True
    scan_snmp: bool = True
    deep_scan: bool = True
    # Performance tuning:
    use_rpm: bool = True                 # ReadPropertyMultiple for deep reads
    rate_limit_ms: int = 0               # per-IP inter-packet delay
    max_objects_per_device: int = 500    # cap on point enumeration
    service_workers: int = 80
    modbus_workers: int = 50
    snmp_workers: int = 50
    # Large-network discovery behavior:
    #   whois_chunk_size=0 → single global broadcast Who-Is (default, fine for /24)
    #   whois_chunk_size>0 → chunked Who-Is by instance range, much gentler on
    #   large sites because each device sees many Who-Is broadcasts but only
    #   I-Ams back for the one chunk its instance falls into (spreads return
    #   traffic over time instead of concentrating it in one storm).
    whois_chunk_size: int = 0
    whois_max_instance: int = 4_194_303  # 2^22 - 1, the BACnet instance max
    whois_chunk_delay_ms: int = 50       # throttle between chunked Who-Is broadcasts


@dataclass
class ScanResult:
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    elapsed: float = 0.0
    devices: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=lambda: {
        'bacnet': 0, 'mstp': 0, 'modbus': 0, 'services': 0, 'snmp': 0, 'points': 0,
    })

    # -- export helpers -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            'scan_time': self.started_at,
            'elapsed_seconds': round(self.elapsed, 2),
            'scanner': 'HVAC Network Scanner v2',
            'counts': self.counts,
            'devices': [_sanitize_for_json(d) for d in self.devices],
        }

    def write_json(self, path: str) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    def write_csv(self, path: str) -> None:
        with open(path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Protocol', 'IP', 'Port', 'Device ID',
                'Identified Model', 'Device Type', 'Vendor',
                'Web UI URL', 'Default Credentials', 'Description',
                'MSTP Network', 'MSTP MAC',
                'Max APDU', 'Segmentation', 'Vendor ID',
                'Banner', 'Page Title',
            ])
            for dev in self.devices:
                fp = dev.get('_fingerprint', {})
                props = dev.get('properties', {}) or {}
                # Device-reported model_name is the ground truth; fall back to
                # our fingerprint heuristic only if the device didn't advertise one.
                model = props.get('model_name') or fp.get('model', '')
                vendor_from_dev = props.get('vendor_name')
                vendor = dev.get('vendor_name') or vendor_from_dev or dev.get('vendor', '')
                desc = props.get('description') or fp.get('description', '')
                writer.writerow([
                    dev.get('protocol', '?'),
                    dev.get('ip', '?'),
                    dev.get('port', '?'),
                    dev.get('instance', dev.get('unit_id', '')),
                    model,
                    fp.get('device_type', ''),
                    vendor,
                    fp.get('web_url', ''),
                    fp.get('default_creds', ''),
                    desc,
                    dev.get('source_network', ''),
                    dev.get('source_address', ''),
                    dev.get('max_apdu', ''),
                    dev.get('segmentation', ''),
                    dev.get('vendor_id', ''),
                    dev.get('banner', ''),
                    dev.get('title', ''),
                ])


# ---------------------------------------------------------------------------
# The orchestrator
# ---------------------------------------------------------------------------

class ScanEngine:
    def __init__(self, options: ScanOptions,
                 callback: Optional[Callable[[str], None]] = None,
                 stop_event: Optional[threading.Event] = None):
        self.opts = options
        self.callback = callback or (lambda msg: None)
        self.stop_event = stop_event or threading.Event()
        self.result = ScanResult()

    def _log(self, msg: str) -> None:
        log.info(msg)
        try:
            self.callback(msg)
        except Exception:
            log.exception("log callback failed")

    def _stopped(self) -> bool:
        return self.stop_event.is_set()

    # -- main entry ------------------------------------------------------

    def run(self) -> ScanResult:
        start = time.time()

        if not self.opts.networks:
            self._log("No networks specified")
            return self.result

        try:
            if self.opts.scan_bacnet and not self._stopped():
                try:
                    self._scan_bacnet()
                except Exception:
                    log.exception("BACnet scan pass failed")
            if self.opts.scan_modbus and not self._stopped():
                try:
                    self._scan_modbus()
                except Exception:
                    log.exception("Modbus scan pass failed")
            if self.opts.scan_services and not self._stopped():
                try:
                    self._scan_services()
                except Exception:
                    log.exception("Services scan pass failed")
            if self.opts.scan_snmp and not self._stopped():
                try:
                    self._scan_snmp()
                except Exception:
                    log.exception("SNMP scan pass failed")
        finally:
            # Always fingerprint whatever we collected. Even on stop_event
            # or scan-pass exceptions, partial results are still useful and
            # deserve model/type/creds annotation in the export.
            try:
                self._refingerprint()
            except Exception:
                log.exception("Fingerprint pass failed")

        return self._finish(start)

    def _finish(self, start: float) -> ScanResult:
        self.result.elapsed = time.time() - start

        # "Total devices" counts unique IPs across protocols. A single IP with
        # BACnet + HTTPS + FTP is one device, not three.
        unique_ips = {d.get('ip') for d in self.result.devices if d.get('ip')}

        self._log("=" * 65)
        self._log(f"Scan complete in {self.result.elapsed:.1f}s")
        self._log(f"  BACnet/IP:   {self.result.counts['bacnet']}")
        self._log(f"  BACnet/MSTP: {self.result.counts['mstp']}")
        self._log(f"  Modbus TCP:  {self.result.counts['modbus']}")
        self._log(f"  Service ports: {self.result.counts['services']}")
        self._log(f"  SNMP:        {self.result.counts['snmp']}")
        self._log(f"  Total:       {len(unique_ips)} unique IP(s), "
                  f"{self.result.counts['points']} points/registers")
        self._log("=" * 65)
        return self.result

    # -- BACnet ---------------------------------------------------------

    def _bcast_for(self, network: str) -> str:
        try:
            net = ipaddress.ip_network(network, strict=False)
            return str(net.broadcast_address)
        except ValueError:
            return network

    def _scan_bacnet(self) -> None:
        self._log("=" * 65)
        self._log("BACNET/IP DISCOVERY")
        self._log("=" * 65)

        client = BACnetClient(
            timeout=self.opts.timeout,
            callback=self.callback,
            rate_limit_ms=self.opts.rate_limit_ms,
        )

        try:
            client.open()

            for network in self.opts.networks:
                if self._stopped():
                    break
                bcast = self._bcast_for(network)
                self._log(f"\nBACnet/IP scan: {network}")
                devices = self._discover_whois_on(client, bcast)

                for dev in devices:
                    if self._stopped():
                        break
                    dev['protocol'] = 'BACnet/IP'
                    if self.opts.deep_scan:
                        self._deep_read(client, dev)
                    self.result.devices.append(dev)
                    self.result.counts['bacnet'] += 1

            if self.opts.scan_mstp and not self._stopped():
                self._scan_mstp(client)

        finally:
            client.close()

    def _discover_whois_on(self, client: BACnetClient, bcast: str) -> list[dict]:
        """Discover devices on a subnet. Chunked by instance range if configured.

        Single-broadcast mode (default): one Who-Is to the subnet, collect all
        I-Ams. Fine for /24s and small sites.

        Chunked mode (`whois_chunk_size > 0`): Who-Is low=N high=N+chunk-1 in a
        loop from 0 to `whois_max_instance`. Intended for large/busy sites where
        a global Who-Is would produce a damaging I-Am storm. Each chunk sleeps
        `whois_chunk_delay_ms` between broadcasts. Stops early after 10
        consecutive empty chunks (avoids scanning the full 4M instance space
        on a small network).
        """
        chunk = self.opts.whois_chunk_size
        if chunk <= 0:
            return client.discover_who_is(target_ip=bcast)

        # Chunked discovery
        self._log(f"  Chunked Who-Is: range 0–{self.opts.whois_max_instance} "
                  f"in steps of {chunk}")
        seen: set[tuple[str, int]] = set()
        out: list[dict] = []
        empty_streak = 0
        low = 0
        while low <= self.opts.whois_max_instance and not self._stopped():
            high = min(low + chunk - 1, self.opts.whois_max_instance)
            batch = client.discover_who_is(target_ip=bcast, low=low, high=high)
            new_in_batch = 0
            for dev in batch:
                key = (dev['ip'], dev.get('instance'))
                if key in seen:
                    continue
                seen.add(key)
                out.append(dev)
                new_in_batch += 1
            if new_in_batch:
                self._log(f"    {low}–{high}: +{new_in_batch} device(s) "
                          f"(total {len(out)})")
                empty_streak = 0
            else:
                empty_streak += 1
                if empty_streak >= 10:
                    self._log(f"    10 empty chunks in a row — stopping "
                              f"early at instance {high}")
                    break
            if self.opts.whois_chunk_delay_ms > 0:
                time.sleep(self.opts.whois_chunk_delay_ms / 1000.0)
            low = high + 1
        return out

    def _scan_mstp(self, client: BACnetClient) -> None:
        self._log("\n" + "=" * 65)
        self._log("BACNET MSTP / REMOTE NETWORK DISCOVERY")
        self._log("=" * 65)

        existing = {(d['ip'], d.get('instance')) for d in self.result.devices
                    if str(d.get('protocol', '')).startswith('BACnet')}

        for network in self.opts.networks:
            if self._stopped():
                break
            bcast = self._bcast_for(network)

            routers, dnets = client.discover_routers(target_ip=bcast)
            self._log(f"  Found {len(routers)} router(s), {len(dnets)} remote network(s)")

            for dnet in dnets:
                if self._stopped():
                    break
                self._log(f"  -> Who-Is to DNET {dnet}...")
                mstp_devs = client.discover_who_is(target_ip=bcast, dnet=dnet, extra_wait=2.0)

                for dev in mstp_devs:
                    if self._stopped():
                        break
                    key = (dev['ip'], dev.get('instance'))
                    if key in existing:
                        continue
                    existing.add(key)
                    dev['protocol'] = 'BACnet/MSTP'
                    if self.opts.deep_scan and dev.get('source_network'):
                        self._deep_read(client, dev)
                    self.result.devices.append(dev)
                    self.result.counts['mstp'] += 1

    def _deep_read(self, client: BACnetClient, dev: dict[str, Any]) -> None:
        """Read device-level properties + object list + per-point properties.

        For MSTP devices (those with a `source_network` from a routed I-Am),
        the ReadProperty packets include DNET/DADR routing info so the router
        forwards requests across the MSTP trunk. Without this, IP-to-IP works
        but every MSTP device returns 'Object not found' because the router
        tries to answer as itself. (Root cause: v2.0.2 `build_read_property`
        hardcoded an unrouted NPDU. Fix: v2.1.0, credit OldAutomator/Reddit.)
        """
        ip = dev['ip']
        instance = dev.get('instance')
        if instance is None:
            return

        # If this device was discovered behind a router, the router's IP is
        # still where we send UDP — but the NPDU must carry the MSTP route.
        dnet = dev.get('source_network')
        dadr = dev.get('source_address')
        route_suffix = (f" (MSTP net={dnet} mac={dadr})"
                        if dnet is not None else "")
        self._log(f"  Deep scan device {instance} at {ip}{route_suffix}...")

        # Device-level properties (uses RPM if supported)
        try:
            props = client.read_device_info(ip, instance,
                                            prefer_multiple=self.opts.use_rpm,
                                            dnet=dnet, dadr=dadr)
        except Exception as e:
            log.debug("read_device_info %s failed: %s", ip, e)
            props = {}

        if props:
            preview = ', '.join(f"{k}={v[:30]}" for k, v in props.items())
            self._log(f"    Device props: {preview}")
        else:
            self._log("    No device properties returned (ReadProperty may be failing)")

        # Object list + per-point props
        try:
            obj_list = client.read_object_list(
                ip, instance,
                max_objects=self.opts.max_objects_per_device,
                dnet=dnet, dadr=dadr,
            )
        except Exception as e:
            log.debug("object list %s failed: %s", ip, e)
            obj_list = []

        objects = []
        # Object types that aren't "points" in the data sense — they're
        # navigational groupings or metadata containers. Enumerating them
        # clutters the Points tab with junk (no presentValue, no units).
        # Per ASHRAE 135:
        #   8=Device, 10=File, 17=Schedule, 6=Calendar, 15=Notification Class,
        #   20=Trend Log, 27=Trend Log Multiple, 25=Event Log, 29=Structured View
        _NON_POINT_TYPES = {
            'Device', 'File', 'Schedule', 'Calendar',
            'Notification Class', 'Trend Log', 'Trend Log Multiple',
            'Event Log', 'Structured View', 'Program',
        }

        for obj_type, obj_inst in obj_list:
            if self._stopped():
                break
            obj_type_str = str(obj_type)
            if obj_type_str in _NON_POINT_TYPES:
                continue
            try:
                raw = client.read_point_properties(
                    ip, obj_type, obj_inst,
                    prefer_multiple=self.opts.use_rpm,
                    dnet=dnet, dadr=dadr,
                )
            except Exception as e:
                log.debug("point props %s %s:%d failed: %s", ip, obj_type, obj_inst, e)
                raw = {}

            point = {'type': obj_type_str, 'instance': int(obj_inst),
                     'name': '', 'present_value': '', 'units': '', 'description': ''}
            for key, val in raw.items():
                if key == 'units':
                    # BACnet units enum → label. Anything weird gets stringified.
                    if isinstance(val, int):
                        point['units'] = BACNET_UNITS.get(val, f"unit-{val}")
                    else:
                        point['units'] = _safe_str(val)
                elif key == 'presentValue':
                    point['present_value'] = _format_present_value(val)
                elif key == 'objectName':
                    point['name'] = _safe_str(val)
                elif key == 'description':
                    point['description'] = _safe_str(val)
                # Any other returned property is intentionally dropped from
                # the point row — we don't want it spilling into labeled slots.
            objects.append(point)
            self.result.counts['points'] += 1

        props['object_list'] = objects
        dev['properties'] = props
        dev['objects'] = objects
        self._log(f"    Read {len(objects)} points from device {instance}")

    # -- Modbus ---------------------------------------------------------

    def _scan_modbus(self) -> None:
        self._log("\n" + "=" * 65)
        self._log("MODBUS TCP DISCOVERY")
        self._log("=" * 65)

        scanner = ModbusScanner(callback=self.callback,
                                timeout=min(self.opts.timeout, 2.0))

        for network in self.opts.networks:
            if self._stopped():
                break
            self._log(f"\nModbus scan: {network}")
            devices = scanner.scan_network(
                network,
                max_workers=self.opts.modbus_workers,
                stop_event=self.stop_event,
            )

            for dev in devices:
                if self._stopped():
                    break
                dev['protocol'] = 'Modbus TCP'
                dev['instance'] = dev.get('unit_id')

                if self.opts.deep_scan:
                    self._log(f"  Reading registers from {dev['ip']} unit={dev['unit_id']}...")
                    try:
                        dev['holding_registers'] = scanner.read_registers(
                            dev['ip'], dev['port'], dev['unit_id'], 0, 50, 3)
                        dev['input_registers'] = scanner.read_registers(
                            dev['ip'], dev['port'], dev['unit_id'], 0, 50, 4)
                        dev['coils'] = scanner.read_coils(
                            dev['ip'], dev['port'], dev['unit_id'], 0, 16)
                        self.result.counts['points'] += (
                            len(dev.get('holding_registers', []))
                            + len(dev.get('input_registers', []))
                            + len(dev.get('coils', []))
                        )
                    except Exception as e:
                        log.debug("modbus deep read failed: %s", e)

                self.result.devices.append(dev)
                self.result.counts['modbus'] += 1

    # -- Services -------------------------------------------------------

    def _scan_services(self) -> None:
        self._log("\n" + "=" * 65)
        self._log("HVAC SERVICE DISCOVERY")
        self._log("=" * 65)

        scanner = HVACServiceScanner(callback=self.callback,
                                     timeout=min(self.opts.timeout, 2.0))

        for network in self.opts.networks:
            if self._stopped():
                break
            self._log(f"\nService scan: {network}")
            services = scanner.scan_network(
                network,
                max_workers=self.opts.service_workers,
                stop_event=self.stop_event,
            )
            for svc in services:
                if self._stopped():
                    break
                self.result.devices.append(svc)
                self.result.counts['services'] += 1

    # -- SNMP -----------------------------------------------------------

    def _scan_snmp(self) -> None:
        self._log("\n" + "=" * 65)
        self._log("SNMP DISCOVERY")
        self._log("=" * 65)

        scanner = SNMPScanner(callback=self.callback,
                              timeout=min(self.opts.timeout, 2.0))

        for network in self.opts.networks:
            if self._stopped():
                break
            self._log(f"\nSNMP scan: {network}")
            snmp_devs = scanner.scan_network(
                network,
                max_workers=self.opts.snmp_workers,
                stop_event=self.stop_event,
            )

            for dev in snmp_devs:
                if self._stopped():
                    break
                dev['protocol'] = 'SNMP'
                dev['vendor'] = ''
                dev['product'] = dev.get('sys_descr', '')[:80]
                descr = (dev.get('sys_descr') or '').lower()
                for pattern, vendor in HTTP_FINGERPRINTS:
                    if re.search(pattern, descr):
                        dev['vendor'] = vendor
                        break
                self.result.devices.append(dev)
                self.result.counts['snmp'] += 1

    # -- final pass -----------------------------------------------------

    def _refingerprint(self) -> None:
        self._log("\nRe-fingerprinting devices with full service data...")
        for dev in self.result.devices:
            dev['_fingerprint'] = fingerprint_device(dev, self.result.devices)
        self._log("  Fingerprinting complete")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_MAX_CELL_LEN = 200  # cap any single cell so one rogue value can't eat the UI


def _safe_str(val: Any) -> str:
    """Stringify a single cell value with a hard length cap.

    Lists/tuples get collapsed so they don't bleed into neighboring columns.
    """
    if val is None:
        return ""
    if isinstance(val, str):
        s = val
    elif isinstance(val, (list, tuple)):
        # Collapse multi-value responses onto one line
        s = " | ".join(_safe_str(v) for v in val)
    elif isinstance(val, bytes):
        s = val.hex()
    else:
        s = str(val)
    # Strip control chars that break TreeView rendering
    s = ''.join(c for c in s if c.isprintable() or c in ' \t')
    if len(s) > _MAX_CELL_LEN:
        s = s[:_MAX_CELL_LEN - 1] + '\u2026'
    return s.strip()


def _format_present_value(val: Any) -> str:
    """Format a presentValue for display. Handles Trane IEEE 754 sentinels."""
    if val is None:
        return ""
    if isinstance(val, float):
        if abs(val) > 1e30:
            return f"{val:.3e} (unconfigured)"
        return f"{val:.3f}".rstrip('0').rstrip('.')
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (list, tuple)):
        # Some devices return an array — show count, not contents
        return f"[{len(val)} values]"
    return _safe_str(val)


def _sanitize_for_json(dev: dict[str, Any]) -> dict[str, Any]:
    """Strip un-serializable private fields and stringify anything weird."""
    out: dict[str, Any] = {}
    for k, v in dev.items():
        if k.startswith('_'):
            continue
        try:
            json.dumps(v)
            out[k] = v
        except (TypeError, ValueError):
            out[k] = str(v)

    fp = dev.get('_fingerprint', {})
    if fp:
        out['identified_model'] = fp.get('model', '')
        out['device_type'] = fp.get('device_type', '')
        out['web_url'] = fp.get('web_url', '')
        out['default_creds'] = fp.get('default_creds', '')
        out['description'] = fp.get('description', '')
    return out
