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
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from typing import Any, Callable, Optional

from .bacnet import BACnetClient
from .constants import (
    BACNET_VENDORS,
    BACNET_UNITS,
    DEFAULT_POINT_PROPERTIES,
    POINT_PROPERTIES_BY_TYPE,
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
    # v2.1.2: scan depth preset. "quick" samples ~5% of objects per device
    # (useful for fast inventory), "normal" honors vendor-aware caps,
    # "full" reads every object regardless of cap.
    scan_depth: str = "normal"
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
    # v2.1.2: BACnet broadcast override.
    #
    # Why this exists: when a user enters a CIDR narrower than their actual
    # physical subnet (e.g. 10.0.0.0/26 on a /24 network), ipaddress
    # broadcast_address returns 10.0.0.63, which is a valid /26 broadcast
    # address mathematically but is NOT a real Ethernet broadcast on the
    # host's /24 subnet. Windows sends the packet as unicast to whoever
    # owns .63, which is nobody, so it gets dropped and zero I-Am responses
    # come back — silent failure.
    #
    # Set this to the actual physical broadcast address (usually 10.0.0.255
    # or 255.255.255.255 for limited broadcast) to override the per-CIDR
    # broadcast calculation. Blank/None = auto-compute (old behavior).
    bacnet_broadcast: Optional[str] = None


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
                'Object Name',
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
                # v2.1.2: expose device's BACnet objectName (e.g. "SC-1 +
                # E22J04614"). It's what users recognize their devices by.
                obj_name = props.get('object_name', '')
                writer.writerow([
                    dev.get('protocol', '?'),
                    dev.get('ip', '?'),
                    dev.get('port', '?'),
                    dev.get('instance', dev.get('unit_id', '')),
                    obj_name,
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

    def write_classification_report(self, path: str) -> None:
        """Write a plain-text classification report (v2.2).

        This report is intended for users to attach when submitting a
        device-profile contribution on GitHub. It contains no point
        values or sensitive data — just the metadata needed to add a
        profile entry: vendor, model, object count, classification
        path hit, cap applied, and whether the scan succeeded.
        """
        with open(path, 'w', encoding='utf-8') as f:
            # Header
            f.write("HVAC Network Scanner — Classification Report\n")
            f.write(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
            f.write(f"Scan started: {self.started_at}\n")
            f.write(f"Elapsed: {self.elapsed:.1f}s\n")
            f.write("=" * 70 + "\n\n")

            # Tally classification paths across devices
            known_count = 0
            substring_count = 0
            rule_count = 0
            heuristic_count = 0
            default_count = 0
            no_class_count = 0  # devices that weren't deep-scanned

            for dev in self.devices:
                if dev.get('protocol', '').startswith('BACnet'):
                    c = dev.get('_classification')
                    if not c:
                        no_class_count += 1
                        continue
                    exp = (c.get('explanation') or '').lower()
                    if 'known device' in exp:
                        known_count += 1
                    elif 'substring' in exp:
                        substring_count += 1
                    elif 'matched rule' in exp:
                        rule_count += 1
                    elif 'heuristic' in exp:
                        heuristic_count += 1
                    else:
                        default_count += 1

            # Per-device detail
            for dev in self.devices:
                if not dev.get('protocol', '').startswith('BACnet'):
                    continue
                ip = dev.get('ip', '?')
                inst = dev.get('instance', '?')
                props = dev.get('properties', {}) or {}
                obj_name = props.get('object_name', '')
                f.write(f"{ip}  device={inst}")
                if obj_name:
                    f.write(f"  name={obj_name!r}")
                f.write("\n")

                c = dev.get('_classification')
                if not c:
                    f.write("  (no deep-scan performed — classification not captured)\n\n")
                    continue
                f.write(f"  vendor: {c.get('vendor_name')!r}\n")
                f.write(f"  model:  {c.get('model_name')!r}\n")
                f.write(f"  object_count: {c.get('object_count')}\n")
                f.write(f"  classification: {c.get('explanation')}\n")
                if c.get('depth_note'):
                    f.write(f"  scan_depth:     {c.get('depth_note')}\n")
                f.write(f"  cap_applied:    {c.get('profile_cap')}\n")
                f.write(f"  class_label:    {c.get('profile_class')}\n")
                if c.get('profile_verified_at'):
                    f.write(f"  verified_at:    {c.get('profile_verified_at')}\n")
                points = len(dev.get('objects', []) or [])
                f.write(f"  points_read:    {points}\n")
                f.write("\n")

            # Summary
            f.write("=" * 70 + "\n")
            f.write("Summary\n")
            f.write("=" * 70 + "\n")
            total = known_count + substring_count + rule_count + heuristic_count + default_count
            f.write(f"Total BACnet devices classified: {total}\n")
            f.write(f"  Known device (exact profile):       {known_count}\n")
            f.write(f"  Vendor-substring match:             {substring_count}\n")
            f.write(f"  Family/prefix rule match:           {rule_count}\n")
            f.write(f"  Heuristic fallback (size-based):    {heuristic_count}\n")
            f.write(f"  Conservative default:               {default_count}\n")
            if no_class_count:
                f.write(f"  Not deep-scanned (no classification): {no_class_count}\n")
            f.write("\n")

            # Call to action for unknown gear
            unknown_any = heuristic_count + default_count
            if unknown_any > 0:
                f.write("-" * 70 + "\n")
                f.write(f"{unknown_any} device(s) fell back to heuristic or default.\n")
                f.write("If the scan worked correctly, please consider submitting a\n")
                f.write("device profile to help other users. Open a GitHub issue at:\n\n")
                f.write("  https://github.com/jamesccupps/HVAC-Network-Scanner/issues\n\n")
                f.write("and select the 'Device profile submission' template.\n")
                f.write("Attach this report; it contains everything needed.\n")


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

        # v2.1.1: MSTP scanning piggybacks on the BACnet client. If the user
        # asked for MSTP without BACnet, they'd get no results and no error.
        # Warn and gracefully enable BACnet discovery to honor their intent.
        if self.opts.scan_mstp and not self.opts.scan_bacnet:
            self._log("  [!] MSTP scanning requires BACnet discovery — "
                      "enabling BACnet for this scan")
            self.opts = replace(self.opts, scan_bacnet=True)

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

    def _allowed_ips_for_targets(self) -> "set[str] | None":
        """Return the union of IPs across all user target specs.

        Used to filter I-Am responses so we don't deep-scan devices the
        user never asked about. Returns None if the target set is unbounded
        (shouldn't happen in normal use) so callers can short-circuit the
        filter gracefully.
        """
        from .netrange import parse_targets, InvalidTargetSyntaxError
        allowed: set[str] = set()
        for network in self.opts.networks:
            try:
                for ip in parse_targets(network):
                    allowed.add(ip)
            except InvalidTargetSyntaxError:
                log.debug("could not parse target for allowlist: %s", network)
                continue
        return allowed or None

    def _bcast_for(self, network: str) -> str:
        """Compute the broadcast target for the BACnet Who-Is.

        v2.1.2: Does the right thing automatically for every supported
        target syntax. The user never has to think about this.

        Rules:
        - Explicit override in ScanOptions (advanced/CLI) wins.
        - CIDR /24 or wider: use its own broadcast_address.
        - Narrower CIDR (/25–/31): use the enclosing /24's broadcast.
          (Because the narrow CIDR's math broadcast is not a real
          Ethernet broadcast on a physical /24 — previously a silent
          failure mode.)
        - /32 single host or range/list: if every IP fits in one /24,
          use that /24's broadcast. Otherwise use limited broadcast
          255.255.255.255 and log that we did.
        """
        if self.opts.bacnet_broadcast:
            return self.opts.bacnet_broadcast
        # Try plain CIDR first.
        try:
            net = ipaddress.ip_network(network, strict=False)
            if net.prefixlen <= 24:
                return str(net.broadcast_address)
            if net.prefixlen == 32:
                # Single host — broadcast to the enclosing /24.
                supernet = net.supernet(new_prefix=24)
                self._log(
                    f"  Single-host target {net.network_address}; "
                    f"Who-Is broadcasting to {supernet.broadcast_address} "
                    f"(the enclosing /24)."
                )
                return str(supernet.broadcast_address)
            # /25–/31: narrower than a physical /24.
            supernet = net.supernet(new_prefix=24)
            self._log(
                f"  CIDR {network} is narrower than /24; "
                f"Who-Is broadcasting to {supernet.broadcast_address} "
                f"(the enclosing /24) instead of {net.broadcast_address}, "
                f"which isn't a real broadcast on your physical subnet."
            )
            return str(supernet.broadcast_address)
        except ValueError:
            pass
        # Not a CIDR — parse it as a range/list and see if all IPs fit in
        # a single /24. If yes, use that /24's broadcast; otherwise fall
        # back to limited broadcast.
        from .netrange import parse_targets, InvalidTargetSyntaxError
        try:
            hosts = parse_targets(network)
        except InvalidTargetSyntaxError:
            self._log(
                f"  [!] Target {network!r} is not a CIDR and not a valid "
                f"range; using limited broadcast 255.255.255.255 for Who-Is."
            )
            return "255.255.255.255"
        if not hosts:
            return "255.255.255.255"
        # All-in-one-/24 check: mask every host to /24 network address.
        try:
            subnets_24 = {
                str(ipaddress.ip_interface(f"{h}/24").network.network_address)
                for h in hosts
            }
        except ValueError:
            subnets_24 = set()
        if len(subnets_24) == 1:
            one_subnet = next(iter(subnets_24))
            bcast_24 = str(ipaddress.ip_network(f"{one_subnet}/24").broadcast_address)
            self._log(
                f"  Target is a range within {one_subnet}/24; "
                f"Who-Is broadcasting to {bcast_24}."
            )
            return bcast_24
        # Range crosses multiple /24s — safest choice is limited broadcast.
        self._log(
            f"  Target {network!r} spans multiple /24s "
            f"({len(subnets_24)} subnets); using limited broadcast "
            f"255.255.255.255 for Who-Is."
        )
        return "255.255.255.255"

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

            # v2.1.2: compute the authoritative set of IPs the user asked
            # for, so we can drop I-Am responses from devices outside their
            # target range. A Who-Is broadcast reaches every device on the
            # subnet (that's how BACnet works); the user typed a specific
            # range and we should respect that intent by filtering, not by
            # deep-scanning everything that answered.
            allowed_ips = self._allowed_ips_for_targets()

            # v2.1.2: consolidate broadcasts by unique destination. When the
            # user provides comma-separated targets on the same subnet
            # (e.g. "10.0.0.245, 10.0.0.201, 10.0.0.230, 10.0.0.176"), all
            # four targets resolve to the same /24 broadcast (10.0.0.255).
            # Previously we broadcast once per target token — four identical
            # broadcasts with four identical I-Am storms in response. Now
            # we compute the unique broadcast set and fire once per bcast.
            # Also dedupe discovered devices across any remaining iterations
            # as a belt-and-suspenders safety net for genuinely multi-subnet
            # target sets.
            bcast_to_networks: dict[str, list[str]] = {}
            for network in self.opts.networks:
                bcast = self._bcast_for(network)
                bcast_to_networks.setdefault(bcast, []).append(network)

            if len(self.opts.networks) > len(bcast_to_networks):
                saved = len(self.opts.networks) - len(bcast_to_networks)
                self._log(f"  Consolidated {len(self.opts.networks)} target(s) "
                          f"into {len(bcast_to_networks)} broadcast(s) "
                          f"(saved {saved} redundant Who-Is broadcasts).")

            seen_devices: set[tuple[str, Any]] = set()

            for bcast, networks_for_bcast in bcast_to_networks.items():
                if self._stopped():
                    break
                # Log which user targets map to this broadcast
                targets_label = ", ".join(networks_for_bcast)
                self._log(f"\nBACnet/IP scan: {targets_label}")
                self._log(f"  Broadcasting Who-Is to {bcast}:47808 "
                          f"(we send Who-Is — we do not send I-Am)")
                devices = self._discover_whois_on(client, bcast)

                # Filter: drop I-Am responses from IPs the user didn't ask for.
                # Also dedupe against devices seen in earlier iterations
                # (in case the user had targets spanning multiple /24s).
                kept = []
                dropped = 0
                duplicates = 0
                for dev in devices:
                    ip = dev.get('ip', '')
                    if allowed_ips is not None and ip not in allowed_ips:
                        dropped += 1
                        continue
                    dedup_key = (ip, dev.get('instance'))
                    if dedup_key in seen_devices:
                        duplicates += 1
                        continue
                    seen_devices.add(dedup_key)
                    kept.append(dev)
                dup_note = f", {duplicates} duplicate(s)" if duplicates else ""
                self._log(f"  Discovered {len(devices)} device(s); "
                          f"kept {len(kept)} in target range "
                          f"(dropped {dropped} out-of-range{dup_note}).")
                # v2.1.2: if the user had a specific target but got zero
                # matches, the device may be offline, not BACnet/IP, or
                # firewalled. Tell them instead of leaving them guessing.
                if (len(kept) == 0
                        and allowed_ips is not None
                        and len(allowed_ips) > 0
                        and len(devices) > 0):
                    missing = sorted(allowed_ips)
                    shown = missing[:5]
                    more = f" (and {len(missing)-5} more)" if len(missing) > 5 else ""
                    self._log(
                        f"  Note: target IP(s) {shown}{more} did not "
                        f"respond to Who-Is on UDP 47808. This means either "
                        f"the device is not running BACnet/IP, or this "
                        f"scanner cannot reach it. Possibilities:"
                    )
                    self._log(
                        f"    - Device does not have a BACnet/IP stack enabled. "
                        f"Some devices that support BACnet ship with it disabled "
                        f"or on non-standard ports, or run a firmware variant "
                        f"that speaks a proprietary protocol instead. For example, "
                        f"Siemens APOGEE PXC panels with firmware revision 2.x "
                        f"speak proprietary P2/Apogee Ethernet. The same "
                        f"hardware with firmware revision 3.x speaks BACnet/IP "
                        f"and is scannable with this tool."
                    )
                    self._log(
                        f"    - Firewall blocks UDP 47808 between this scanner "
                        f"and the target."
                    )
                    self._log(
                        f"    - Device uses a fundamentally different BMS "
                        f"protocol (Modbus, LonTalk, JCI N2, etc.)."
                    )
                    self._log(
                        f"    - Device is offline or unreachable at the IP layer."
                    )
                    self._log(
                        f"  If the device pings but this message appears, check "
                        f"its BACnet/IP configuration in its management interface. "
                        f"Many devices have BACnet disabled by default."
                    )
                for dev in kept:
                    mstp_tag = (f" (MSTP net {dev['source_network']})"
                                if dev.get('source_network') else "")
                    self._log(f"    Device {dev.get('instance','?')} "
                              f"at {dev.get('ip','?')}{mstp_tag}")

                for dev in kept:
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

        # v2.1.2: apply the same target-IP filter to MSTP. An MSTP device
        # discovered behind a router whose IP is outside the user's target
        # range should not be enumerated or deep-scanned. The user typed a
        # range; respect it.
        allowed_ips = self._allowed_ips_for_targets()

        # v2.1.2: consolidate MSTP discovery broadcasts the same way the
        # BACnet/IP scan does — one Who-Is-Router-To-Network per unique
        # broadcast address, not per target token.
        bcast_set: set[str] = set()
        for network in self.opts.networks:
            bcast_set.add(self._bcast_for(network))

        for bcast in bcast_set:
            if self._stopped():
                break

            routers, dnets = client.discover_routers(target_ip=bcast)

            # Filter routers to ones in the user's target range BEFORE we
            # enumerate anything behind them. Otherwise we'd still send
            # Who-Is to each DNET (which could trip out-of-range MSTP
            # devices even though we wouldn't keep the results).
            if allowed_ips is not None:
                in_range_routers = [r for r in routers if r.get('ip') in allowed_ips]
                in_range_router_ips = {r['ip'] for r in in_range_routers}
                in_range_dnets = [dn for dn in dnets
                                   if any(dn in r.get('networks', [])
                                          for r in in_range_routers)]
                if len(routers) != len(in_range_routers):
                    self._log(
                        f"  Found {len(routers)} router(s); "
                        f"{len(in_range_routers)} in target range "
                        f"({sorted(in_range_router_ips) or 'none'}). "
                        f"Skipping MSTP enumeration behind the rest."
                    )
                else:
                    self._log(f"  Found {len(routers)} router(s), "
                              f"{len(in_range_dnets)} remote network(s) in range")
                dnets_to_scan = in_range_dnets
            else:
                self._log(f"  Found {len(routers)} router(s), "
                          f"{len(dnets)} remote network(s)")
                dnets_to_scan = dnets

            for dnet in dnets_to_scan:
                if self._stopped():
                    break
                self._log(f"  -> Who-Is to DNET {dnet}...")
                mstp_devs = client.discover_who_is(target_ip=bcast, dnet=dnet, extra_wait=2.0)

                # Second filter: the routed Who-Is on the wire is a broadcast
                # that hits all routers on the segment; a router not in our
                # target could still proxy an I-Am back. Drop those.
                kept_mstp = []
                dropped_mstp = 0
                for dev in mstp_devs:
                    ip = dev.get('ip', '')
                    if allowed_ips is None or ip in allowed_ips:
                        kept_mstp.append(dev)
                    else:
                        dropped_mstp += 1
                if dropped_mstp:
                    self._log(f"    Dropped {dropped_mstp} MSTP response(s) "
                              f"from routers outside target range. "
                              f"Kept {len(kept_mstp)}.")

                for dev in kept_mstp:
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

    def _interleave_indices(self, client, ip: str, instance: int,
                            total_count: int, cap: int,
                            dnet=None, dadr=None) -> list[int]:
        """When a device has more objects than our cap, read the full
        object-type layout and return a type-interleaved sample of indices.

        This prevents the "all Analog Inputs, no Binaries" failure mode
        on Tracer SC+ and similar devices that enumerate by-type in array
        order. We pay the cost of reading `total_count` objectList entries
        (each is small, just an object identifier), then intelligently
        pick which ones to deep-read for per-point properties.

        Returns the chosen indices (1-based) in roughly evenly-distributed
        round-robin order across object types.
        """
        from collections import defaultdict

        # Fetch the full type/instance map. Each read is small; what's
        # expensive is the per-point property reads later.
        self._log(f"    Probing full object type layout "
                  f"({total_count} entries)...")
        all_indices = list(range(1, total_count + 1))
        full_map = client.read_object_list_entries(
            ip, instance, all_indices, dnet=dnet, dadr=dadr,
            stop_fn=self._stopped,
        )
        if not full_map:
            return []

        # Bucket by type, preserving array-index order within each type.
        by_type: dict[str, list[int]] = defaultdict(list)
        for idx, (obj_type, _inst) in zip(all_indices, full_map):
            by_type[str(obj_type)].append(idx)

        type_counts = {t: len(v) for t, v in by_type.items()}
        self._log(f"    Object types found: "
                  + ", ".join(f"{t}={n}" for t, n in sorted(type_counts.items())))

        # Interleave: round-robin through types. Take from each type in
        # proportion to its share of the total — so if 80% of objects are
        # AIs, 80% of our cap comes from AIs, but every other type still
        # gets at least a few samples.
        chosen: list[int] = []
        per_type_quota: dict[str, int] = {}
        for t, idxs in by_type.items():
            share = len(idxs) / total_count
            quota = max(5, int(cap * share))  # at least 5 per type if available
            per_type_quota[t] = min(quota, len(idxs))

        # Truncate to cap if needed
        total_alloc = sum(per_type_quota.values())
        if total_alloc > cap:
            # Scale down proportionally
            scale = cap / total_alloc
            for t in per_type_quota:
                per_type_quota[t] = max(
                    min(len(by_type[t]), 2),
                    int(per_type_quota[t] * scale),
                )

        # Emit indices by round-robin — takes first N from each type,
        # interleaved so types alternate in enumeration order.
        taken_counts = {t: 0 for t in by_type}
        while len(chosen) < cap:
            progress = False
            for t, idxs in sorted(by_type.items()):
                if taken_counts[t] < per_type_quota[t]:
                    chosen.append(idxs[taken_counts[t]])
                    taken_counts[t] += 1
                    progress = True
                    if len(chosen) >= cap:
                        break
            if not progress:
                break

        self._log(f"    Interleaved sample: {len(chosen)} indices across "
                  f"{len(by_type)} object type(s).")
        return chosen

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

        # v2.1.2: Classify the device based on vendor/model and objectList
        # length, then apply the appropriate cap. Prevents silent truncation
        # on supervisory controllers (Trane SC+ has ~3000 objects, previously
        # capped at 500 and user only got Analog Inputs).
        try:
            total_count = client.read_object_list_count(
                ip, instance, dnet=dnet, dadr=dadr,
            )
        except Exception as e:
            log.debug("object list count %s failed: %s", ip, e)
            total_count = 0

        if total_count == 0:
            self._log("    Object list is empty or unreadable.")
            obj_list: list[tuple[str, int]] = []
        else:
            from .device_profiles import classify_device, apply_scan_depth
            # v2.1.2: some devices return a short vendor_name via ReadProperty
            # that doesn't match the canonical ASHRAE registry string
            # (e.g. a Trane SC+ reports vendor_name="Trane" via Device object,
            # but the I-Am vendor_id=2 maps to "The Trane Company" in the
            # official registry). Prefer the registry lookup as the primary
            # classification key since that's what our DEVICE_PROFILES table
            # is built against; fall back to whatever the device reported.
            canonical_vendor = dev.get('vendor_name') or props.get('vendor_name')
            profile, explanation = classify_device(
                vendor_name=canonical_vendor,
                model_name=props.get('model_name'),
                object_list_count=total_count,
            )
            profile, depth_note = apply_scan_depth(profile, self.opts.scan_depth)
            self._log(f"    Classified: {explanation}"
                      + (f" | {depth_note}" if depth_note else ""))

            # v2.2: stash classification info for --export-classification.
            # Lets users submit this verbatim when reporting unknown gear.
            dev['_classification'] = {
                'vendor_name': canonical_vendor,
                'model_name': props.get('model_name'),
                'object_count': total_count,
                'profile_class': profile.class_label,
                'profile_cap': profile.object_cap,
                'profile_verified_at': profile.verified_at,
                'explanation': explanation,
                'depth_note': depth_note,
            }

            if total_count > profile.object_cap:
                self._log(
                    f"    [!] Device has {total_count} objects; "
                    f"scan cap is {profile.object_cap}. Enumerating a "
                    f"type-interleaved sample."
                )
                indices = self._interleave_indices(
                    client, ip, instance, total_count, profile.object_cap,
                    dnet=dnet, dadr=dadr,
                )
            else:
                indices = list(range(1, total_count + 1))

            try:
                obj_list = client.read_object_list_entries(
                    ip, instance, indices,
                    dnet=dnet, dadr=dadr,
                    stop_fn=self._stopped,
                )
                self._log(f"    Object list has {total_count} entries; "
                          f"read {len(obj_list)}.")
            except Exception as e:
                log.debug("object list entries %s failed: %s", ip, e)
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
                # v2.1.1: choose properties that actually exist for this
                # object type. Previously asked units/presentValue on every
                # object, flooding the log with "unknown property" errors
                # from binary/calendar/etc. and wasting 2-3x the scan time.
                prop_names = POINT_PROPERTIES_BY_TYPE.get(
                    obj_type_str, DEFAULT_POINT_PROPERTIES)
                raw = client.read_point_properties(
                    ip, obj_type, obj_inst,
                    prop_names=prop_names,
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
