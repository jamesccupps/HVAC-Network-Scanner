"""Minimal X.509 parsing for the HTTPS service probe.

The services scan already opens a TLS connection to every 443/8443 it finds and
then throws the certificate away. That certificate is free fingerprinting data
— BAS controllers put the product line, and often the panel name, in the
subject CN — and its expiry date is operational information the owner of the
system wants regardless.

Why hand-rolled: the project is deliberately zero-dependency, and DER is just
BER, the same tag-length-value encoding the BACnet codec and the SNMP probe
already decode. Only four fields are needed, so a full ASN.1 library would be
a large dependency for a small job.

Scope: subject and issuer common names and organisations, the validity window,
and the serial. Anything malformed yields None rather than raising — a scanner
must not fall over because one device presents a broken certificate, and BAS
gear presents plenty of those.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Optional

# ASN.1 universal tags we care about
_INTEGER = 0x02
_BIT_STRING = 0x03
_OCTET_STRING = 0x04
_OID = 0x06
_UTF8_STRING = 0x0C
_SEQUENCE = 0x30
_SET = 0x31
_PRINTABLE_STRING = 0x13
_T61_STRING = 0x14
_IA5_STRING = 0x16
_UTC_TIME = 0x17
_GENERALIZED_TIME = 0x18
_BMP_STRING = 0x1E

_STRING_TAGS = {_UTF8_STRING, _PRINTABLE_STRING, _T61_STRING, _IA5_STRING,
                _BMP_STRING}

# Relative distinguished name attribute OIDs, DER-encoded contents
_OID_CN = bytes([0x55, 0x04, 0x03])   # 2.5.4.3  commonName
_OID_O = bytes([0x55, 0x04, 0x0A])    # 2.5.4.10 organizationName
_OID_OU = bytes([0x55, 0x04, 0x0B])   # 2.5.4.11 organizationalUnitName


class DerError(ValueError):
    """Raised internally when a structure does not parse. Never escapes."""


@dataclass
class Certificate:
    subject_cn: Optional[str] = None
    subject_o: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_o: Optional[str] = None
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    serial: Optional[str] = None

    @property
    def self_signed(self) -> bool:
        """Issuer equals subject. Near-universal on BAS gear, and worth
        surfacing so the reader knows the CN is self-asserted."""
        return bool(self.subject_cn) and self.subject_cn == self.issuer_cn

    def days_until_expiry(self, now: Optional[datetime.datetime] = None) -> Optional[int]:
        if self.not_after is None:
            return None
        now = now or datetime.datetime.now(datetime.timezone.utc)
        if self.not_after.tzinfo is None:
            now = now.replace(tzinfo=None)
        return (self.not_after - now).days

    @property
    def expired(self) -> Optional[bool]:
        days = self.days_until_expiry()
        return None if days is None else days < 0

    def summary(self) -> str:
        """One line for a log or a details pane."""
        bits = []
        if self.subject_cn:
            bits.append(f"CN={self.subject_cn}")
        if self.subject_o:
            bits.append(f"O={self.subject_o}")
        if self.self_signed:
            bits.append("self-signed")
        elif self.issuer_cn:
            bits.append(f"issued by {self.issuer_cn}")
        days = self.days_until_expiry()
        if days is not None:
            bits.append(f"expired {-days}d ago" if days < 0 else f"expires in {days}d")
        return ", ".join(bits)

    def to_dict(self) -> dict:
        return {
            'subject_cn': self.subject_cn,
            'subject_o': self.subject_o,
            'issuer_cn': self.issuer_cn,
            'issuer_o': self.issuer_o,
            'not_before': self.not_before.isoformat() if self.not_before else None,
            'not_after': self.not_after.isoformat() if self.not_after else None,
            'serial': self.serial,
            'self_signed': self.self_signed,
            'days_until_expiry': self.days_until_expiry(),
        }


# ---------------------------------------------------------------------------
# DER primitives
# ---------------------------------------------------------------------------

def _read_tlv(data: bytes, idx: int) -> tuple[int, int, int, int]:
    """Read one DER element. Returns (tag, content_start, content_end, next)."""
    if idx + 2 > len(data):
        raise DerError("truncated tag")
    tag = data[idx]
    idx += 1
    first = data[idx]
    idx += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or idx + n > len(data):
            raise DerError("bad long-form length")
        length = int.from_bytes(data[idx:idx + n], 'big')
        idx += n
    end = idx + length
    if end > len(data):
        raise DerError("element runs past the buffer")
    return tag, idx, end, end


def _children(data: bytes, start: int, end: int):
    """Iterate the elements of a constructed value."""
    idx = start
    while idx < end:
        tag, cstart, cend, nxt = _read_tlv(data, idx)
        yield tag, cstart, cend
        idx = nxt


def _text(data: bytes, tag: int, start: int, end: int) -> str:
    raw = data[start:end]
    if tag == _BMP_STRING:
        return raw.decode('utf-16-be', errors='replace')
    if tag == _UTF8_STRING:
        return raw.decode('utf-8', errors='replace')
    return raw.decode('latin-1', errors='replace')


def _parse_time(data: bytes, tag: int, start: int, end: int) -> Optional[datetime.datetime]:
    """Decode UTCTime or GeneralizedTime.

    UTCTime's two-digit year uses the RFC 5280 rule: 50-99 means 19xx,
    00-49 means 20xx.
    """
    raw = data[start:end].decode('ascii', errors='replace').strip()
    if not raw.endswith('Z'):
        # Offsets are legal but vanishingly rare in certificates; treating an
        # unparseable time as unknown is safer than guessing at the offset.
        return None
    raw = raw[:-1]
    try:
        if tag == _UTC_TIME:
            if len(raw) < 10:
                return None
            yy = int(raw[0:2])
            year = 1900 + yy if yy >= 50 else 2000 + yy
            rest = raw[2:]
        else:
            if len(raw) < 12:
                return None
            year = int(raw[0:4])
            rest = raw[4:]
        month, day, hour, minute = (int(rest[0:2]), int(rest[2:4]),
                                    int(rest[4:6]), int(rest[6:8]))
        second = int(rest[8:10]) if len(rest) >= 10 else 0
        return datetime.datetime(year, month, day, hour, minute, second,
                                 tzinfo=datetime.timezone.utc)
    except (ValueError, IndexError):
        return None


def _parse_name(data: bytes, start: int, end: int) -> tuple[Optional[str], Optional[str]]:
    """Pull commonName and organizationName out of an X.501 Name.

    Returns the LAST occurrence of each, which is the most specific RDN in a
    conventionally-ordered DN.
    """
    cn = org = None
    for _set_tag, set_start, set_end in _children(data, start, end):
        for _sq_tag, sq_start, sq_end in _children(data, set_start, set_end):
            oid_val = None
            text = None
            for tag, cstart, cend in _children(data, sq_start, sq_end):
                if tag == _OID:
                    oid_val = data[cstart:cend]
                elif tag in _STRING_TAGS:
                    text = _text(data, tag, cstart, cend)
            if text is None:
                continue
            if oid_val == _OID_CN:
                cn = text
            elif oid_val == _OID_O:
                org = text
    return cn, org


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def parse_der_certificate(der: bytes) -> Optional[Certificate]:
    """Parse a DER-encoded X.509 certificate. Returns None if it will not parse.

    Never raises: a scanner must not fall over because one device presents a
    malformed certificate, and building-automation gear presents plenty.
    """
    if not der:
        return None
    try:
        tag, cstart, cend, _ = _read_tlv(der, 0)
        if tag != _SEQUENCE:
            return None
        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, sig }
        tbs = next(_children(der, cstart, cend), None)
        if tbs is None or tbs[0] != _SEQUENCE:
            return None
        _t, tstart, tend = tbs

        fields = list(_children(der, tstart, tend))
        i = 0
        # version [0] EXPLICIT, optional
        if fields and fields[0][0] == 0xA0:
            i += 1
        if i >= len(fields):
            return None
        # serialNumber
        serial = None
        if fields[i][0] == _INTEGER:
            raw = der[fields[i][1]:fields[i][2]]
            serial = raw.hex().upper().lstrip('0') or '0'
            i += 1
        # signature AlgorithmIdentifier
        if i < len(fields) and fields[i][0] == _SEQUENCE:
            i += 1
        # issuer Name
        issuer_cn = issuer_o = None
        if i < len(fields) and fields[i][0] == _SEQUENCE:
            issuer_cn, issuer_o = _parse_name(der, fields[i][1], fields[i][2])
            i += 1
        # validity
        not_before = not_after = None
        if i < len(fields) and fields[i][0] == _SEQUENCE:
            times = list(_children(der, fields[i][1], fields[i][2]))
            if len(times) >= 2:
                not_before = _parse_time(der, *times[0])
                not_after = _parse_time(der, *times[1])
            i += 1
        # subject Name
        subject_cn = subject_o = None
        if i < len(fields) and fields[i][0] == _SEQUENCE:
            subject_cn, subject_o = _parse_name(der, fields[i][1], fields[i][2])

        cert = Certificate(
            subject_cn=subject_cn, subject_o=subject_o,
            issuer_cn=issuer_cn, issuer_o=issuer_o,
            not_before=not_before, not_after=not_after, serial=serial,
        )
        # A certificate with nothing identifying in it is not worth reporting.
        if not any((cert.subject_cn, cert.issuer_cn, cert.not_after)):
            return None
        return cert
    except (DerError, ValueError, IndexError, StopIteration):
        return None
