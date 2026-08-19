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
    BACNET_OBJ_TYPES,
    BACNET_PORT,
    BACNET_VENDORS,
    DEFAULT_DEVICE_PROPERTIES,
    DEFAULT_POINT_PROPERTIES,
    PROP_IDS,
)

log = logging.getLogger(__name__)

# Consecutive failed individual reads of one property on one device before the
# client stops trying to fill that property from RPM gaps. Low on purpose: the
# cost of being wrong is three wasted round trips per device, and the cost of
# not trying at all is a permanently blank column.
_PARTIAL_FILL_GIVE_UP = 3

# Batched objectList enumeration via ReadPropertyMultiple.
#
# BACnetPropertyReference carries an optional propertyArrayIndex, so one RPM
# request can ask for objectList[1..N]. That collapses object enumeration from
# one round trip per index into one per batch. Sizing is bounded at both ends:
# the REQUEST must fit the device's maxAPDULengthAccepted, and the RESPONSE
# must fit the max APDU we advertise back to it.
_RPM_ELEMENT_REQUEST_BYTES = 8    # ctx0 propId + ctx1 arrayIndex, worst case
_RPM_ELEMENT_RESPONSE_BYTES = 13  # ctx2 propId + ctx3 index + tags + objId
_RPM_FRAMING_OVERHEAD = 60        # BVLC + NPDU + APDU header + objId + tags
_RPM_MAX_BATCH = 100              # keeps the blast radius of one bad batch small
_RPM_OUR_MAX_APDU = 1476          # what build_read_property_multiple advertises
_RPM_BATCH_GIVE_UP = 2            # failed batches before falling back entirely

# Batched per-point property reads.
#
# Response size here cannot be computed from the request: object names and
# descriptions are free-form strings, so a batch that fits on one controller
# overflows on the next. The batch size is therefore adaptive — start
# conservative, grow on success, halve on failure — rather than derived from
# maxAPDULengthAccepted. Devices that cannot segment simply Abort an oversized
# response, which shows up as a failed batch and shrinks the window.
_POINT_BATCH_INITIAL = 8
_POINT_BATCH_MAX = 24
_POINT_BATCH_MIN = 1


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
        # (ip, property_name) -> consecutive individual-read failures, used to
        # stop retrying a property a device clearly will not answer. See
        # read_point_properties.
        self._partial_fill_failures: dict[tuple[str, str], int] = {}
        # (ip, device_instance) -> current point-read batch size. Adaptive:
        # see _POINT_BATCH_INITIAL.
        self._point_batch: dict[tuple[str, int], int] = {}

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
                # v2.1.2: Don't log per-I-Am here. The engine applies a
                # target-spec filter to the results and logs the kept
                # devices (and a summary of how many were dropped).
                # Logging every raw I-Am was misleading because users
                # saw out-of-range IPs in the log and assumed they'd
                # be deep-scanned.
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
        in the Points tab (observed on Trane Tracer against a busy site segment).
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

                # Invoke ID must match what we sent. `None` means the packet
                # carries no invoke-id at all — an Unconfirmed-Request such as
                # an I-Am, an unconfirmed COV notification, or an unconfirmed
                # event notification. The device we are polling emits those on
                # its own schedule and we are bound to 47808, so they land here
                # routinely on a live segment. They are never our reply: drop
                # them and keep waiting out the timeout. Returning here (the
                # pre-fix behavior) aborted the read on the first stray packet
                # and silently lost the point.
                got_id = _extract_invoke_id(data)
                if got_id is None or got_id != expected_invoke_id:
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

    def read_object_list_count(self, ip: str, instance: int,
                               dnet: Optional[int] = None,
                               dadr: "str | int | bytes | None" = None) -> int:
        """Read just the `objectList` length. Cheap preliminary read so
        callers can classify the device before committing to a full
        enumeration depth. Returns 0 if the device doesn't respond.
        """
        count = self.read_property(ip, 'Device', instance, 'objectList',
                                   array_index=0, dnet=dnet, dadr=dadr)
        return count if isinstance(count, int) and count > 0 else 0

    def read_object_list_entries(self, ip: str, instance: int,
                                 indices: list[int],
                                 dnet: Optional[int] = None,
                                 dadr: "str | int | bytes | None" = None,
                                 stop_fn=None,
                                 max_apdu: Optional[int] = None,
                                 prefer_multiple: bool = True) -> list[tuple[str, int]]:
        """Read specified array indices from `objectList`. Caller decides
        which indices (enables interleaving by object type, see engine).

        `stop_fn`, if given, is called after each read; returning True
        aborts enumeration (plumbing for the STOP button).

        Entries that time out or fail to parse are skipped, so the returned
        list is NOT positionally aligned with `indices`. Callers that need to
        know which array index each entry came from must use
        `read_object_list_entries_indexed` instead — pairing this list back
        against `indices` by position silently misattributes every entry after
        the first failed read.
        """
        return [entry for _idx, entry in self.read_object_list_entries_indexed(
            ip, instance, indices, dnet=dnet, dadr=dadr, stop_fn=stop_fn,
            max_apdu=max_apdu, prefer_multiple=prefer_multiple)]

    def read_object_list_entries_indexed(
            self, ip: str, instance: int,
            indices: list[int],
            dnet: Optional[int] = None,
            dadr: "str | int | bytes | None" = None,
            stop_fn=None,
            max_apdu: Optional[int] = None,
            prefer_multiple: bool = True) -> list[tuple[int, tuple[str, int]]]:
        """As `read_object_list_entries`, but pairs each entry with the array
        index it was actually read from.

        Reads that time out or return an unparseable value are omitted, so the
        result is shorter than `indices` whenever the device drops a request.
        Returning the index alongside the entry is what lets callers stay
        aligned across those gaps.

        With `prefer_multiple`, indices are batched into ReadPropertyMultiple
        requests carrying propertyArrayIndex — one round trip per ~100 objects
        instead of per object. A device that will not answer batched requests
        falls back to one read per index after `_RPM_BATCH_GIVE_UP` failures,
        so the slow path stays available without being the default.
        """
        if not prefer_multiple or len(indices) < 2:
            return self._object_list_one_by_one(ip, instance, indices,
                                                dnet, dadr, stop_fn)

        out: list[tuple[int, tuple[str, int]]] = []
        batch_size = self._object_list_batch_size(max_apdu)
        failures = 0
        pos = 0
        while pos < len(indices):
            if stop_fn and stop_fn():
                break
            batch = indices[pos:pos + batch_size]
            got = self._object_list_rpm_batch(ip, instance, batch, dnet, dadr)
            if got is None:
                failures += 1
                out.extend(self._object_list_one_by_one(
                    ip, instance, batch, dnet, dadr, stop_fn))
                if failures >= _RPM_BATCH_GIVE_UP:
                    self._log("    %s does not answer batched objectList reads; "
                              "falling back to one read per index" % ip)
                    out.extend(self._object_list_one_by_one(
                        ip, instance, indices[pos + batch_size:],
                        dnet, dadr, stop_fn))
                    break
            else:
                out.extend(got)
            pos += batch_size
        return out

    @staticmethod
    def _object_list_batch_size(device_max_apdu: Optional[int]) -> int:
        """How many array indices fit in one exchange, bounded at both ends."""
        # Unknown device APDU: assume the smallest common size rather than
        # guessing high and having the request rejected outright.
        dev = device_max_apdu if device_max_apdu else 480
        by_request = (dev - _RPM_FRAMING_OVERHEAD) // _RPM_ELEMENT_REQUEST_BYTES
        by_response = ((_RPM_OUR_MAX_APDU - _RPM_FRAMING_OVERHEAD)
                       // _RPM_ELEMENT_RESPONSE_BYTES)
        return max(1, min(by_request, by_response, _RPM_MAX_BATCH))

    def _object_list_rpm_batch(self, ip: str, instance: int, batch: list[int],
                               dnet=None, dadr=None):
        """Read one batch of objectList indices in a single RPM exchange.

        Returns the entries that came back, or None if the device did not
        answer the batched form at all — which the caller treats as a signal to
        fall back, not as an empty object list.
        """
        self._throttle(ip)
        invoke_id = self._next_invoke_id()
        pkt = codec.build_read_property_multiple(
            'Device', instance, [('objectList', i) for i in batch],
            invoke_id=invoke_id, dnet=dnet, dadr=dadr,
        )
        with self._lock:
            entries = self._request_response(
                ip, pkt, invoke_id,
                parser=codec.parse_read_property_multiple_ack_full,
            )
        if not entries:
            return None
        out: list[tuple[int, tuple[str, int]]] = []
        for e in entries:
            if e.array_index is None or e.prop_id != PROP_IDS['objectList']:
                continue
            if isinstance(e.value, tuple) and len(e.value) == 2:
                out.append((e.array_index, e.value))
        # A response that parsed but yielded nothing usable is still a failure
        # of the batched form, not an empty object list.
        return out or None

    def _object_list_one_by_one(self, ip: str, instance: int,
                                indices: list[int],
                                dnet=None, dadr=None, stop_fn=None
                                ) -> list[tuple[int, tuple[str, int]]]:
        out: list[tuple[int, tuple[str, int]]] = []
        for i in indices:
            if stop_fn and stop_fn():
                break
            result = self.read_property(ip, 'Device', instance, 'objectList',
                                        array_index=i, dnet=dnet, dadr=dadr)
            if isinstance(result, tuple) and len(result) == 2:
                out.append((i, result))
        return out

    def read_object_list(self, ip: str, instance: int,
                         max_objects: int = 500,
                         dnet: Optional[int] = None,
                         dadr: "str | int | bytes | None" = None) -> list[tuple[str, int]]:
        """Read the full object list from a device.

        Convenience wrapper that reads count + enumerates in array order,
        capped at max_objects. For classification-aware scans the engine
        uses read_object_list_count + read_object_list_entries directly
        so it can pre-classify and interleave by type.

        Pass `dnet`/`dadr` for MSTP devices behind a router.
        """
        count = self.read_object_list_count(ip, instance, dnet=dnet, dadr=dadr)
        if count == 0:
            return []

        cap = min(count, max_objects)
        self._log(f"    Object list has {count} entries; reading {cap}")
        return self.read_object_list_entries(
            ip, instance, list(range(1, cap + 1)), dnet=dnet, dadr=dadr,
        )

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

        When RPM returns nothing at all, every property is retried as an
        individual ReadProperty.

        When RPM returns a PARTIAL result, the missing properties are retried
        individually too, but adaptively. A partial result has two causes: the
        device genuinely does not have the property, or its RPM implementation
        is incomplete while single-property reads work fine. The second case is
        common enough to be worth recovering — it is the difference between a
        populated Name column and a blank one — but retrying blindly would cost
        a round trip per missing property per object, which on a
        several-thousand-object supervisory controller is thousands of wasted
        exchanges when the answer is always "no such property".

        So the client remembers, per (ip, property), how many consecutive
        individual reads came back empty and stops retrying that property for
        that device after `_PARTIAL_FILL_GIVE_UP`. A device that simply lacks
        `description` costs three extra reads in total rather than three per
        object; a device with a flaky RPM path gets its data filled in. Any
        success resets the counter.

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

        # RPM returned nothing at all: retry every property individually.
        if not raw:
            for name in prop_names:
                val = self.read_property(ip, obj_type, obj_instance, name,
                                         dnet=dnet, dadr=dadr)
                if val is not None:
                    num = PROP_IDS.get(name)
                    if num is not None:
                        raw[num] = val
        else:
            # RPM returned a partial result: fill the gaps individually, but
            # give up on a property once this device has refused it repeatedly.
            # See the docstring for why this is adaptive rather than blind.
            for name in prop_names:
                num = PROP_IDS.get(name)
                if num is None or num in raw:
                    continue
                key = (ip, name)
                if self._partial_fill_failures.get(key, 0) >= _PARTIAL_FILL_GIVE_UP:
                    continue
                val = self.read_property(ip, obj_type, obj_instance, name,
                                         dnet=dnet, dadr=dadr)
                if val is None:
                    self._partial_fill_failures[key] =                         self._partial_fill_failures.get(key, 0) + 1
                    if self._partial_fill_failures[key] == _PARTIAL_FILL_GIVE_UP:
                        log.debug("%s does not answer %s individually either; "
                                  "stopping per-object retries", ip, name)
                else:
                    self._partial_fill_failures.pop(key, None)
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


    # -- batched point reads ----------------------------------------------

    def read_points_batched(self, ip: str, instance: int,
                            objects: "list[tuple[str, int, list[str]]]",
                            prefer_multiple: bool = True,
                            dnet: Optional[int] = None,
                            dadr: "str | int | bytes | None" = None,
                            stop_fn=None
                            ) -> "list[tuple[str, int, dict[str, Any]]]":
        """Read per-point properties for many objects, batching where possible.

        `objects` is ``[(obj_type, obj_instance, property_names)]`` — each
        object carries its own property list so a binary point is not asked
        for units. Returns ``[(obj_type, obj_instance, validated_properties)]``
        in the input order, with the same per-property type validation
        `read_point_properties` applies.

        Falls back to one exchange per object for anything a batch does not
        answer, so a device with a partial or absent RPM implementation still
        produces a complete result — just more slowly.
        """
        results: "dict[tuple[str, int], dict[str, Any]]" = {}
        if not prefer_multiple:
            for otype, oinst, props in objects:
                if stop_fn and stop_fn():
                    break
                results[(str(otype), oinst)] = self.read_point_properties(
                    ip, otype, oinst, prop_names=props,
                    prefer_multiple=False, dnet=dnet, dadr=dadr)
            return [(t, i, results.get((str(t), i), {})) for t, i, _ in objects]

        key = (ip, instance)
        pos = 0
        while pos < len(objects):
            if stop_fn and stop_fn():
                break
            size = self._point_batch.get(key, _POINT_BATCH_INITIAL)
            batch = objects[pos:pos + size]
            got = self._point_batch_once(ip, batch, dnet, dadr)
            if got is None:
                # Shrink and retry the same slice; at the floor, read singly.
                if size > _POINT_BATCH_MIN:
                    self._point_batch[key] = max(_POINT_BATCH_MIN, size // 2)
                    continue
                for otype, oinst, props in batch:
                    if stop_fn and stop_fn():
                        break
                    results[(str(otype), oinst)] = self.read_point_properties(
                        ip, otype, oinst, prop_names=props,
                        prefer_multiple=False, dnet=dnet, dadr=dadr)
            else:
                results.update(got)
                # Grow slowly while the device keeps up.
                if len(batch) == size and size < _POINT_BATCH_MAX:
                    self._point_batch[key] = size + 1
            pos += len(batch)

        return [(t, i, results.get((str(t), i), {})) for t, i, _ in objects]

    def _point_batch_once(self, ip: str,
                          batch: "list[tuple[str, int, list[str]]]",
                          dnet=None, dadr=None
                          ) -> "Optional[dict[tuple[str, int], dict[str, Any]]]":
        """One batched RPM exchange. None means the device did not answer it."""
        if not batch:
            return {}
        specs = [(otype, oinst, [p for p in props if p in PROP_IDS])
                 for otype, oinst, props in batch]
        self._throttle(ip)
        invoke_id = self._next_invoke_id()
        pkt = codec.build_read_property_multiple_objects(
            specs, invoke_id=invoke_id, dnet=dnet, dadr=dadr)
        with self._lock:
            entries = self._request_response(
                ip, pkt, invoke_id,
                parser=codec.parse_read_property_multiple_ack_full,
            )
        if not entries:
            return None

        # Map numbers back to the names the CALLER asked for. PROP_IDS carries
        # hyphenated aliases alongside the camelCase names ('object-name' and
        # 'objectName' both map to 77), so inverting the whole dict returns
        # whichever alias happens to be last — 'object-name', which the engine
        # does not recognise, silently blanking every name and value.
        num_to_name: dict[int, str] = {}
        for _t, _i, props in batch:
            for name in props:
                num = PROP_IDS.get(name)
                if num is not None:
                    num_to_name[num] = name
        raw: "dict[tuple[str, int], dict[int, Any]]" = {}
        for e in entries:
            if e.obj_type is None:
                continue
            type_name = BACNET_OBJ_TYPES.get(e.obj_type, f"type-{e.obj_type}")
            raw.setdefault((type_name, e.obj_instance), {})[e.prop_id] = e.value

        out: "dict[tuple[str, int], dict[str, Any]]" = {}
        for (type_name, oinst), props in raw.items():
            validated: dict[str, Any] = {}
            for num, val in props.items():
                name = num_to_name.get(num)
                if name is None:
                    continue
                v = _validate_point_property(name, val)
                if v is not None:
                    validated[name] = v
            out[(type_name, oinst)] = validated
        return out or None


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
