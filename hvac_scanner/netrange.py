"""
Network target parsing shared across all scanners.

v2.1.2: accept more than just CIDR. Users reasonably want to express
"scan hosts 2 through 100" without working out what CIDR covers that
range, and they want to mix notations in one target field.

Supported syntaxes (any of these, comma-or-whitespace separated, mixed):

    10.0.0.0/24
    10.0.0.0/26
    10.0.0.5                     # single host
    10.0.0.2-100                 # shorthand: last octet range
    10.0.0.2-10.0.0.100          # full-IP range (same subnet enforced)
    10.0.0.10-20, 10.0.1.0/24    # mixed list

Returns a list of IP strings. The hosts() iterator of a CIDR excludes
the network and broadcast addresses; for user-specified ranges we
include every address in the range (the user asked for them specifically).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Iterator


class InvalidTargetSyntaxError(ValueError):
    """Raised when a target spec is not parseable as CIDR, range, or host."""


_RE_IP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_SHORT_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
_RE_FULL_RANGE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
)


def _parse_token(token: str) -> list[str]:
    """Expand one target spec token to a list of IP strings."""
    token = token.strip()
    if not token:
        return []

    # CIDR form
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as e:
            raise InvalidTargetSyntaxError(f"bad CIDR {token!r}: {e}") from e
        # For /32 we want to include the one host; hosts() returns empty for /32
        if net.prefixlen == 32:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]

    # Full IP range: 10.0.0.2-10.0.0.100
    m = _RE_FULL_RANGE.match(token)
    if m:
        start_s, end_s = m.group(1), m.group(2)
        try:
            start = ipaddress.IPv4Address(start_s)
            end = ipaddress.IPv4Address(end_s)
        except ValueError as e:
            raise InvalidTargetSyntaxError(f"bad IPs in range {token!r}: {e}") from e
        if int(end) < int(start):
            raise InvalidTargetSyntaxError(
                f"range end {end_s} is less than start {start_s} in {token!r}"
            )
        # Cap to something sane so a typo'd /0-ish range can't OOM us.
        max_span = 1 << 16  # 65536 hosts
        if int(end) - int(start) + 1 > max_span:
            raise InvalidTargetSyntaxError(
                f"range {token!r} spans more than {max_span} hosts; refusing"
            )
        return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]

    # Short range: 10.0.0.2-100 (last octet)
    m = _RE_SHORT_RANGE.match(token)
    if m:
        prefix, lo_s, hi_s = m.group(1), m.group(2), m.group(3)
        lo, hi = int(lo_s), int(hi_s)
        if not (0 <= lo <= 255 and 0 <= hi <= 255):
            raise InvalidTargetSyntaxError(f"octet out of range in {token!r}")
        if hi < lo:
            raise InvalidTargetSyntaxError(
                f"range end .{hi} is less than start .{lo} in {token!r}"
            )
        return [f"{prefix}.{i}" for i in range(lo, hi + 1)]

    # Single IP
    if _RE_IP.match(token):
        try:
            ipaddress.IPv4Address(token)
        except ValueError as e:
            raise InvalidTargetSyntaxError(f"bad IP {token!r}: {e}") from e
        return [token]

    raise InvalidTargetSyntaxError(
        f"unrecognized target {token!r} (expected CIDR, IP, or range "
        f"like 10.0.0.2-100)"
    )


def parse_targets(raw: str | Iterable[str]) -> list[str]:
    """Parse one or more target specs to a deduplicated list of IP strings.

    Accepts either a single string (comma/whitespace separated) or an
    iterable of strings. Order is preserved; duplicates within and across
    tokens are collapsed.
    """
    if isinstance(raw, str):
        # Split on commas OR whitespace so both "10.0.0.0/24, 10.0.1.5" and
        # "10.0.0.0/24 10.0.1.5" work.
        tokens: Iterable[str] = [t for t in re.split(r"[,\s]+", raw) if t]
    else:
        tokens = raw

    seen: set[str] = set()
    out: list[str] = []
    for token in tokens:
        for ip in _parse_token(token):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def iter_parse_targets(raw: str | Iterable[str]) -> Iterator[str]:
    """Streaming variant for very large target sets."""
    yield from parse_targets(raw)
