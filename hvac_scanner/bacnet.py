"""
BACnet/IP transport layer.

Wraps the pure codec in socket I/O. Key improvements over v1:
- One socket bound per scanner instance, reused across all reads
- ReadPropertyMultiple support (major speedup on deep scans)
- Rate limiting to avoid overwhelming small field controllers
- Proper invoke-id tracking so concurrent-in-flight requests don't confuse replies
- try/finally on every socket — no leaks on exception paths
- Explicit logging at DEBUG level instead of silent except
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any, Callable, Optional

from . import codec
from .codec import IAmDevice, _extract_invoke_id
from .constants import (
    BACNET_PORT,
    BACNET_VENDORS,
    DEFAULT_DEVICE_PROPERTIES,
    DEFAULT_POINT_PROPERTIES,
    PROP_IDS,
)

log = logging.getLogger(__name__)


class BACnetClient:
    """Single long-lived socket for all BACnet traffic from this scanner.

    Thread-safe: _send_and_wait serializes access to the socket.
    """

    def __init__(self, timeout: float = 3.0, callback: Optional[Callable[[str], None]] = None,
                 rate_limit_ms: int = 0):
        self.timeout = timeout
        self.callback = callback or (lambda msg: None)
        self.rate_limit_ms = rate_limit_ms  # min ms between packets to same IP
        self._last_send: dict[str, float] = {}
        self._invoke_id = 0
        self._lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._bound_port: Optional[int] = None

    # -- Lifecycle --------------------------------------------------------

    def open(self) -> int:
        """Bind a UDP socket. Tries 47808 first (some devices hardcode the
        reply target), falls back to ephemeral. Returns the bound port."""
        if self._sock is not None:
            return self._bound_port or 0

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(self.timeout)

        try:
            sock.bind(("", BACNET_PORT))
            self._bound_port = BACNET_PORT
            self._log(f"  Bound to BACnet port {BACNET_PORT}")
        except OSError:
            sock.bind(("", 0))
            self._bound_port = sock.getsockname()[1]
            self._log(f"  Port {BACNET_PORT} in use, bound to ephemeral port {self._bound_port}")

        self._sock = sock
        return self._bound_port

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._bound_port = None

    def __enter__(self) -> "BACnetClient":
        self.open()
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    # -- Helpers ----------------------------------------------------------

    def _log(self, msg: str) -> None:
        log.debug(msg)
        try:
            self.callback(msg)
        except Exception:
            log.exception("log callback failed")

    def _next_invoke_id(self) -> int:
        with self._lock:
            self._invoke_id = (self._invoke_id + 1) % 256
            return self._invoke_id

    def _throttle(self, ip: str) -> None:
        """Enforce rate_limit_ms between packets to the same IP."""
        if self.rate_limit_ms <= 0:
            return
        now = time.monotonic()
        last = self._last_send.get(ip, 0.0)
        delta_ms = (now - last) * 1000.0
        if delta_ms < self.rate_limit_ms:
            time.sleep((self.rate_limit_ms - delta_ms) / 1000.0)
        self._last_send[ip] = time.monotonic()

    # -- Broadcast discovery ---------------------------------------------

    def discover_who_is(self, target_ip: str = "255.255.255.255",
                        low: Optional[int] = None, high: Optional[int] = None,
                        dnet: Optional[int] = None,
                        extra_wait: float = 0.0) -> list[dict[str, Any]]:
        """Send a Who-Is broadcast and collect I-Am responses.

        dnet restricts the broadcast to a single remote BACnet network
        (used for MSTP probing through routers).
        """
        if self._sock is None:
            raise RuntimeError("BACnetClient not opened")

        pkt = codec.build_whois(low=low, high=high, dnet=dnet)
        try:
            self._sock.sendto(pkt, (target_ip, BACNET_PORT))
            if dnet is not None:
                self._log(f"  -> Who-Is to {target_ip} DNET={dnet}")
            else:
                self._log(f"  -> Who-Is broadcast to {target_ip}")
        except OSError as e:
            self._log(f"  Who-Is send error: {e}")
            return []

        return self._collect_iam(deadline=time.time() + self.timeout + extra_wait)

    def discover_routers(self, target_ip: str = "255.255.255.255") -> tuple[list[dict], list[int]]:
        """Send Who-Is-Router-To-Network. Returns (routers, networks)."""
        if self._sock is None:
            raise RuntimeError("BACnetClient not opened")

        pkt = codec.build_whois_router_to_network()
        try:
            self._sock.sendto(pkt, (target_ip, BACNET_PORT))
        except OSError as e:
            self._log(f"  Router discovery send error: {e}")
            return [], []

        routers: list[dict[str, Any]] = []
        networks: set[int] = set()
        deadline = time.time() + self.timeout

        old_timeout = self._sock.gettimeout()
        self._sock.settimeout(self.timeout)
        try:
            while time.time() < deadline:
                try:
                    data, addr = self._sock.recvfrom(4096)
                except socket.timeout:
                    break
                parsed = codec.parse_iam_router(data)
                if parsed:
                    routers.append({'ip': addr[0], 'port': addr[1], 'networks': parsed})
                    networks.update(parsed)
                    self._log(f"  Router at {addr[0]} -> networks: {parsed}")
        finally:
            self._sock.settimeout(old_timeout)

        return routers, sorted(networks)

    def _collect_iam(self, deadline: float) -> list[dict[str, Any]]:
        assert self._sock is not None
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        old_timeout = self._sock.gettimeout()
        try:
            while time.time() < deadline:
                remaining = max(0.1, deadline - time.time())
                self._sock.settimeout(remaining)
                try:
                    data, addr = self._sock.recvfrom(4096)
                except socket.timeout:
                    break
                device = codec.parse_iam(data, addr)
                if device is None:
                    continue
                key = (device.ip, device.instance)
                if key in seen:
                    continue
                seen.add(key)
                out.append(_iam_to_dict(device))
                self._log(
                    f"  Found device {device.instance} at {addr[0]}"
                    + (f" (MSTP net {device.source_network})" if device.source_network else "")
                )
        finally:
            self._sock.settimeout(old_timeout)
        return out

    # -- ReadProperty -----------------------------------------------------

    def read_property(self, ip: str, obj_type: int | str, obj_instance: int,
                      prop_id: int | str, array_index: Optional[int] = None,
                      dnet: Optional[int] = None,
                      dadr: "str | int | bytes | None" = None) -> Any:
        """Issue a ReadProperty request and return the decoded value.

        For MSTP devices behind a router, pass `dnet`=source_network and
        `dadr`=source_address from the IAm response. `ip` is then the
        router's IP (where UDP unicast goes); the NPDU carries the DNET/DADR
        so the router forwards across the MSTP trunk.
        """
        self._throttle(ip)
        invoke_id = self._next_invoke_id()
        pkt = codec.build_read_property(obj_type, obj_instance, prop_id,
                                        array_index=array_index, invoke_id=invoke_id,
                                        dnet=dnet, dadr=dadr)

        with self._lock:  # serialize socket access
            return self._request_response(ip, pkt, invoke_id,
                                          parser=codec.parse_read_property_ack)

    def read_property_multiple(self, ip: str, obj_type: int | str, obj_instance: int,
                               prop_ids: list[int | str],
                               dnet: Optional[int] = None,
                               dadr: "str | int | bytes | None" = None) -> dict[int, Any]:
        """Issue a ReadPropertyMultiple request; returns {prop_id: value}.

        See `read_property` for MSTP routing semantics.
        """
        self._throttle(ip)
        invoke_id = self._next_invoke_id()
        pkt = codec.build_read_property_multiple(obj_type, obj_instance, prop_ids,
                                                 invoke_id=invoke_id,
                                                 dnet=dnet, dadr=dadr)

        with self._lock:
            result = self._request_response(
                ip, pkt, invoke_id,
                parser=lambda d: codec.parse_read_property_multiple_ack(d, prop_ids)
            )
        return result or {}

    def _request_response(self, ip: str, pkt: bytes, expected_invoke_id: int,
                          parser: Callable[[bytes], Any]) -> Any:
        """Send one packet and wait for the matching response.

        Validates invoke_id + source IP on each received packet. Discards
        anything that doesn't match — this is critical because the socket
        is shared and bound to port 47808 where I-Am broadcasts, COV
        notifications, and stale replies from prior requests regularly arrive.
        Without this filtering, responses from different devices got parsed
        under the wrong request's context, producing column-swapped values
        in the Points tab (observed on Trane Tracer against a busy OCC segment).
        """
        assert self._sock is not None
        try:
            self._sock.sendto(pkt, (ip, BACNET_PORT))
        except OSError as e:
            self._log(f"  sendto {ip} failed: {e}")
            return None

        deadline = time.monotonic() + self.timeout
        old_timeout = self._sock.gettimeout()
        discarded = 0
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if discarded:
                        log.debug("timeout after discarding %d unrelated packets from %s",
                                  discarded, ip)
                    return None
                self._sock.settimeout(remaining)
                try:
                    data, addr = self._sock.recvfrom(4096)
                except socket.timeout:
                    return None

                # Source IP must match the target we sent to
                if addr[0] != ip:
                    discarded += 1
                    continue

                # Invoke ID must match what we sent
                got_id = _extract_invoke_id(data)
                if got_id is not None and got_id != expected_invoke_id:
                    discarded += 1
                    continue

                # It's our reply — parse and return
                try:
                    return parser(data)
                except Exception as e:
                    log.debug("parse error from %s: %s", ip, e)
                    return None
        finally:
            self._sock.settimeout(old_timeout)

    # -- High-level deep scan --------------------------------------------

    def read_device_info(self, ip: str, instance: int,
                         prop_names: Optional[list[str]] = None,
                         prefer_multiple: bool = True,
                         dnet: Optional[int] = None,
                         dadr: "str | int | bytes | None" = None) -> dict[str, str]:
        """Read a bundle of device-level properties. Tries RPM first.

        Pass `dnet`/`dadr` for MSTP devices behind a router (see `read_property`).
        """
        prop_names = prop_names or DEFAULT_DEVICE_PROPERTIES
        prop_num_to_key = {}
        for name in prop_names:
            num = PROP_IDS.get(name)
            if num is not None:
                # map to readable key
                key = name.replace('-', '_').replace(' ', '_')
                prop_num_to_key[num] = key

        props: dict[str, str] = {}

        if prefer_multiple:
            try:
                rpm_result = self.read_property_multiple(
                    ip, 'Device', instance, list(prop_num_to_key.keys()),
                    dnet=dnet, dadr=dadr,
                )
                if rpm_result:
                    for num, val in rpm_result.items():
                        if num in prop_num_to_key and val is not None:
                            props[prop_num_to_key[num]] = _stringify(val)
                    if props:
                        return props
            except Exception as e:
                log.debug("RPM device read failed on %s: %s, falling back", ip, e)

        # Fallback: one ReadProperty per property
        for name in prop_names:
            val = self.read_property(ip, 'Device', instance, name,
                                     dnet=dnet, dadr=dadr)
            if val is not None:
                key = name.replace('-', '_').replace(' ', '_')
                props[key] = _stringify(val)

        return props

    def read_object_list(self, ip: str, instance: int,
                         max_objects: int = 500,
                         dnet: Optional[int] = None,
                         dadr: "str | int | bytes | None" = None) -> list[tuple[str, int]]:
        """Read the object list from a device.

        Pass `dnet`/`dadr` for MSTP devices behind a router.
        """
        count = self.read_property(ip, 'Device', instance, 'objectList',
                                   array_index=0, dnet=dnet, dadr=dadr)
        if not isinstance(count, int) or count <= 0:
            return []

        cap = min(count, max_objects)
        self._log(f"    Object list has {count} entries; reading {cap}")

        objects: list[tuple[str, int]] = []
        for i in range(1, cap + 1):
            result = self.read_property(ip, 'Device', instance, 'objectList',
                                        array_index=i, dnet=dnet, dadr=dadr)
            if isinstance(result, tuple) and len(result) == 2:
                objects.append(result)
        return objects

    def read_point_properties(self, ip: str, obj_type: int | str, obj_instance: int,
                              prop_names: Optional[list[str]] = None,
                              prefer_multiple: bool = True,
                              dnet: Optional[int] = None,
                              dadr: "str | int | bytes | None" = None) -> dict[str, Any]:
        """Read per-point properties (presentValue, name, units, description).

        Returns a dict keyed by property NAME (presentValue, objectName, units,
        description). Values are TYPE-VALIDATED at this layer:

        - presentValue: numeric (float or int) or string — never a list, never bytes
        - objectName:   always a string
        - units:        always an int (enum) if present; string if device overrode
        - description:  always a string

        If a device returns something unexpected for a given property (e.g. the
        Trane Tracer quirk where ReadPropertyMultiple responses occasionally
        reorder values at the packet level), we DROP the bad value rather than
        let it leak into the wrong column downstream.

        Pass `dnet`/`dadr` for MSTP devices behind a router.
        """
        prop_names = prop_names or DEFAULT_POINT_PROPERTIES
        num_to_name = {PROP_IDS[name]: name for name in prop_names if name in PROP_IDS}

        raw: dict[int, Any] = {}
        if prefer_multiple:
            try:
                raw = self.read_property_multiple(ip, obj_type, obj_instance,
                                                  list(num_to_name.keys()),
                                                  dnet=dnet, dadr=dadr) or {}
            except Exception as e:
                log.debug("RPM point read failed on %s %s:%d: %s",
                          ip, obj_type, obj_instance, e)

        # Fallback / fill missing props individually
        if not raw:
            for name in prop_names:
                val = self.read_property(ip, obj_type, obj_instance, name,
                                         dnet=dnet, dadr=dadr)
                if val is not None:
                    num = PROP_IDS.get(name)
                    if num is not None:
                        raw[num] = val

        # Type-validate and remap to name keys
        out: dict[str, Any] = {}
        for num, val in raw.items():
            name = num_to_name.get(num)
            if name is None:
                continue
            validated = _validate_point_property(name, val)
            if validated is not None:
                out[name] = validated
        return out


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _iam_to_dict(device: IAmDevice) -> dict[str, Any]:
    return {
        'ip':             device.ip,
        'port':           device.port,
        'instance':       device.instance,
        'max_apdu':       device.max_apdu,
        'segmentation':   device.segmentation,
        'vendor_id':      device.vendor_id,
        'vendor_name':    BACNET_VENDORS.get(device.vendor_id, f"Vendor #{device.vendor_id}")
                          if device.vendor_id is not None else "Unknown",
        'source_network': device.source_network,
        'source_address': device.source_address,
        'objects':        [],
        'properties':     {},
    }


def _stringify(val: Any) -> str:
    """Stringify a property value for display/export."""
    if isinstance(val, float):
        # Trane VAV sentinel IEEE 754 values
        if abs(val) > 1e30:
            return f"{val:.3e} (unconfigured?)"
        return f"{val:.3f}".rstrip('0').rstrip('.')
    if isinstance(val, tuple) and len(val) == 2:
        return f"{val[0]},{val[1]}"
    return str(val)


# Per-property type expectations. Used to filter out values that don't match
# what the spec says the property should hold — protects the UI/CSV from
# column bleed when a non-conforming device emits a weirdly-encoded value.
_POINT_PROPERTY_TYPES = {
    'presentValue': ('numeric_or_str',),   # Real for analog, Enumerated for binary/MS, could be string
    'objectName':   ('string',),
    'units':        ('int_or_str',),       # Enumerated normally; some devices override with text
    'description':  ('string',),
    'vendorName':   ('string',),
    'modelName':    ('string',),
    'firmwareRevision': ('string',),
    'applicationSoftwareVersion': ('string',),
}


def _validate_point_property(name: str, val: Any) -> Any:
    """Return the value if it matches expectations for `name`, else None.

    This stops things like an objectName string ending up in the units column
    when a device's RPM response doesn't match our property ID expectations.
    """
    expected = _POINT_PROPERTY_TYPES.get(name, ('any',))[0]

    if val is None:
        return None

    if expected == 'numeric_or_str':
        if isinstance(val, (int, float, bool)):
            return val
        if isinstance(val, str):
            return val
        # List/tuple of values — happens occasionally; drop to avoid column bleed
        return None

    if expected == 'string':
        if isinstance(val, str):
            return val
        # Numeric values masquerading as string-typed props are almost always
        # a sign of packet misalignment (vendor RPM quirk) — drop them rather
        # than let them leak into the Name/Description column.
        return None

    if expected == 'int_or_str':
        # NB: bool is a subclass of int — exclude it
        if isinstance(val, bool):
            return None
        if isinstance(val, int):
            return val
        if isinstance(val, str):
            return val
        # Float where an int enum was expected — drop
        return None

    # 'any' fallback
    return val
