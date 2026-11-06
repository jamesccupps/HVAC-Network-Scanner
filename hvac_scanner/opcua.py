"""
OPC UA server identity, from the server's own GetEndpoints answer.

OPC UA (TCP 4840) is how many building, energy and plant systems publish
data upward. Any OPC UA client finds out what a server is and how to reach it
the same way: Hello, open a secure channel with security policy None,
GetEndpoints, close. The answer is the server's application name and
product URI, as the server itself states them, and every endpoint it offers:
its security mode and policy and the kinds of user login it accepts. No
session is created and nothing is read or written.

What matters for an audit: an endpoint with security mode None carries
everything unsigned and unencrypted, and an Anonymous user token lets anyone
open a session without a login.

Encodings follow OPC UA Part 6 (binary), with type identifiers checked
against the FreeOpcUa asyncua library: OpenSecureChannel request/response
446/449, GetEndpoints 428/431, ServiceFault 397, CloseSecureChannel 452.
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from contextlib import closing
from typing import Any, Optional

log = logging.getLogger(__name__)

OPCUA_PORT = 4840
POLICY_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
_OPN_REQ, _OPN_RESP = 446, 449
_GETEP_REQ, _GETEP_RESP = 428, 431
_SERVICE_FAULT = 397
_CLOSE_REQ = 452
_MAX_MESSAGE = 1 << 20              # what a reply may total, all chunks together
_MAX_ITEMS = 64                     # endpoints, tokens or URLs read from one array
SECURITY_MODES = {1: "None", 2: "Sign", 3: "SignAndEncrypt"}
TOKEN_TYPES = {0: "Anonymous", 1: "UserName", 2: "Certificate", 3: "IssuedToken"}
APP_TYPES = {0: "Server", 1: "Client", 2: "ClientAndServer", 3: "DiscoveryServer"}


class _Malformed(Exception):
    pass


# -- encoding --------------------------------------------------------------------

def _string(s: Optional[str]) -> bytes:
    if s is None:
        return struct.pack('<i', -1)
    b = s.encode('utf-8')
    return struct.pack('<i', len(b)) + b


def _now() -> int:
    """OPC UA DateTime: 100 ns ticks since 1601-01-01."""
    return int((time.time() + 11644473600) * 10_000_000)


def _request_header(handle: int, timeout_ms: int) -> bytes:
    return (b'\x00\x00'                         # AuthenticationToken: null NodeId
            + struct.pack('<qII', _now(), handle, 0)
            + _string(None)                     # AuditEntryId
            + struct.pack('<I', timeout_ms)
            + b'\x00\x00\x00')                  # AdditionalHeader: null ExtensionObject


def _type_id(n: int) -> bytes:
    return struct.pack('<BBH', 0x01, 0, n)      # four-byte NodeId, namespace 0


def _frame(kind: bytes, body: bytes) -> bytes:
    return kind + b'F' + struct.pack('<I', 8 + len(body)) + body


def build_hello(url: str) -> bytes:
    return _frame(b'HEL', struct.pack('<IIIII', 0, 65536, 65536, _MAX_MESSAGE, 0) + _string(url))


def build_open(timeout_ms: int) -> bytes:
    body = (struct.pack('<I', 0) + _string(POLICY_NONE)
            + struct.pack('<ii', -1, -1)         # sender certificate, receiver thumbprint
            + struct.pack('<II', 1, 1)           # sequence number, request id
            + _type_id(_OPN_REQ) + _request_header(1, timeout_ms)
            + struct.pack('<III', 0, 0, 1)       # protocol version, Issue, security None
            + struct.pack('<i', -1)              # client nonce
            + struct.pack('<I', 600_000))        # requested lifetime, ms
    return _frame(b'OPN', body)


def build_get_endpoints(channel: int, token: int, url: str, timeout_ms: int) -> bytes:
    body = (struct.pack('<IIII', channel, token, 2, 2)
            + _type_id(_GETEP_REQ) + _request_header(2, timeout_ms)
            + _string(url) + struct.pack('<ii', -1, -1))     # no locales, no profiles
    return _frame(b'MSG', body)


def build_close(channel: int, token: int, timeout_ms: int) -> bytes:
    body = (struct.pack('<IIII', channel, token, 3, 3)
            + _type_id(_CLOSE_REQ) + _request_header(3, timeout_ms))
    return _frame(b'CLO', body)


# -- decoding --------------------------------------------------------------------

class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise _Malformed("ran off the end")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack('<I', self.take(4))[0]

    def i32(self) -> int:
        return struct.unpack('<i', self.take(4))[0]

    def string(self) -> Optional[str]:
        n = self.i32()
        if n < 0:
            return None
        return self.take(n).decode('utf-8', errors='replace')

    def bytestring(self) -> Optional[bytes]:
        n = self.i32()
        return None if n < 0 else self.take(n)

    def array(self, item) -> list:
        n = self.i32()
        if n < 0:
            return []
        if n > 10_000:
            raise _Malformed("array too long")
        items = [item() for _ in range(n)]
        return items[:_MAX_ITEMS]

    def node_id(self) -> int:
        """The numeric identifier of a NodeId (0 when it is not numeric)."""
        enc = self.u8()
        kind = enc & 0x3F
        if kind == 0:
            ident = self.u8()
        elif kind == 1:
            self.u8()
            ident = struct.unpack('<H', self.take(2))[0]
        elif kind == 2:
            self.take(2)
            ident = self.u32()
        elif kind == 3:
            self.take(2)
            self.string()
            ident = 0
        elif kind == 4:
            self.take(18)
            ident = 0
        elif kind == 5:
            self.take(2)
            self.bytestring()
            ident = 0
        else:
            raise _Malformed(f"NodeId encoding {enc:#x}")
        if enc & 0x80:
            self.string()                        # namespace URI
        if enc & 0x40:
            self.u32()                           # server index
        return ident

    def localized_text(self) -> str:
        mask = self.u8()
        if mask & 0x01:
            self.string()
        return (self.string() or "") if mask & 0x02 else ""

    def diagnostic_info(self, depth: int = 0) -> None:
        if depth > 4:
            raise _Malformed("diagnostics nested too deep")
        mask = self.u8()
        for bit in (0x01, 0x02, 0x04, 0x08):
            if mask & bit:
                self.i32()
        if mask & 0x10:
            self.string()
        if mask & 0x20:
            self.u32()
        if mask & 0x40:
            self.diagnostic_info(depth + 1)

    def extension_object(self) -> None:
        self.node_id()
        enc = self.u8()
        if enc in (1, 2):
            self.bytestring()

    def response_header(self) -> int:
        """Reads a ResponseHeader; returns its ServiceResult."""
        self.take(8)                             # timestamp
        self.u32()                               # request handle
        result = self.u32()
        self.diagnostic_info()
        self.array(self.string)                  # string table
        self.extension_object()
        return result


def _message_body(sock: socket.socket, kind: bytes) -> bytes:
    """The body of the next message of `kind` (OPN, MSG), its chunks joined,
    with the security and sequence headers removed."""
    body = b''
    while True:
        head = _recv_exact(sock, 8)
        msg_type, chunk, size = head[:3], head[3:4], struct.unpack('<I', head[4:8])[0]
        if size < 8 or len(body) + size > _MAX_MESSAGE:
            raise _Malformed("bad message size")
        data = _recv_exact(sock, size - 8)
        if msg_type == b'ERR':
            r = _Reader(data)
            raise _Malformed(f"server error {r.u32():#010x} {r.string() or ''}".strip())
        if msg_type != kind:
            raise _Malformed(f"expected {kind!r}, got {msg_type!r}")
        r = _Reader(data)
        r.u32()                                  # secure channel id
        if kind == b'OPN':
            r.string(); r.bytestring(); r.bytestring()   # policy, certificate, thumbprint
        else:
            r.u32()                              # token id
        r.take(8)                                # sequence number, request id
        body += data[r.pos:]
        if chunk == b'F':
            return body
        if chunk == b'A':
            raise _Malformed("message aborted")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b''
    while len(out) < n:
        part = sock.recv(n - len(out))
        if not part:
            raise _Malformed("connection closed")
        out += part
    return out


def parse_get_endpoints(body: bytes) -> list[dict[str, Any]]:
    """The endpoints in a GetEndpoints response body (from its type id on)."""
    r = _Reader(body)
    type_id = r.node_id()
    if type_id == _SERVICE_FAULT:
        raise _Malformed(f"service fault {r.response_header():#010x}")
    if type_id != _GETEP_RESP:
        raise _Malformed(f"unexpected response type {type_id}")
    result = r.response_header()
    if result & 0x80000000:
        raise _Malformed(f"GetEndpoints failed {result:#010x}")

    def endpoint() -> dict[str, Any]:
        url = r.string()
        app_uri, product_uri = r.string(), r.string()
        app_name = r.localized_text()
        app_type = r.i32()
        r.string(); r.string()                   # gateway server, discovery profile
        r.array(r.string)                        # discovery URLs
        r.bytestring()                           # server certificate
        mode = r.i32()
        policy = r.string() or ""

        def token() -> str:
            r.string()                           # policy id
            kind = r.i32()
            r.string(); r.string(); r.string()   # issued token type, issuer, policy
            return TOKEN_TYPES.get(kind, f"type {kind}")

        tokens = r.array(token)
        r.string()                               # transport profile
        level = r.u8()
        return {'url': url or "", 'application_uri': app_uri or "",
                'product_uri': product_uri or "", 'application_name': app_name,
                'application_type': APP_TYPES.get(app_type, f"type {app_type}"),
                'security_mode': SECURITY_MODES.get(mode, f"mode {mode}"),
                'security_policy': policy.rsplit('#', 1)[-1], 'user_tokens': tokens,
                'security_level': level}

    return r.array(endpoint)


def probe(ip: str, port: int = OPCUA_PORT, timeout: float = 3.0) -> dict[str, Any]:
    """What the server says about itself, as Services fields; {} if it does
    not speak OPC UA or gives no endpoints."""
    url = f"opc.tcp://{ip}:{port}"
    timeout_ms = int(timeout * 1000)
    try:
        with closing(socket.create_connection((ip, port), timeout=timeout)) as sock:
            sock.settimeout(timeout)
            sock.sendall(build_hello(url))
            head = _recv_exact(sock, 8)
            size = struct.unpack('<I', head[4:8])[0]
            if head[:3] not in (b'ACK', b'ERR') or not 8 <= size <= 4096:
                return {}
            rest = _recv_exact(sock, size - 8)
            if head[:3] == b'ERR':
                return {'banner': f"OPC UA error {struct.unpack('<I', rest[:4])[0]:#010x}"}
            sock.sendall(build_open(timeout_ms))
            r = _Reader(_message_body(sock, b'OPN'))
            if r.node_id() != _OPN_RESP or r.response_header() & 0x80000000:
                return {'banner': "OPC UA (secure channel with policy None refused)"}
            r.u32()                              # server protocol version
            channel, token = r.u32(), r.u32()
            sock.sendall(build_get_endpoints(channel, token, url, timeout_ms))
            endpoints = parse_get_endpoints(_message_body(sock, b'MSG'))
            try:
                sock.sendall(build_close(channel, token, timeout_ms))
            except OSError:
                pass
    except (OSError, _Malformed, struct.error, UnicodeError) as e:
        log.debug("OPC UA probe %s:%d: %s", ip, port, e)
        return {}
    if not endpoints:
        return {'banner': "OPC UA (no endpoints offered)"}
    first = endpoints[0]
    return {
        'product': first['application_name'] or 'OPC UA Server',
        'banner': (f"OPC UA {first['application_type']}: {first['product_uri']}"
                   if first['product_uri'] else f"OPC UA {first['application_type']}"),
        'opcua': {
            'application_name': first['application_name'],
            'application_uri': first['application_uri'],
            'product_uri': first['product_uri'],
            'endpoints': [{k: e[k] for k in ('url', 'security_mode', 'security_policy',
                                              'user_tokens')} for e in endpoints],
            'security_none': any(e['security_mode'] == "None" for e in endpoints),
            'anonymous': any("Anonymous" in e['user_tokens'] for e in endpoints),
        },
    }
