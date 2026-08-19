"""Mock BBMD for testing Foreign Device registration.

Implements the slice of Annex J the scanner uses: Register-Foreign-Device with
a BVLC-Result reply, and Distribute-Broadcast-To-Network, which it relays to a
set of downstream mock devices as a Forwarded-NPDU so replies come back the way
they would from a real deployment.

`mode` controls the behaviour under test:
    "accept"   register normally
    "refuse"   answer registration with a Register-Foreign-Device NAK
    "silent"   ignore registration entirely (a firewalled or absent BBMD)
"""

import socket
import struct
import threading

from hvac_scanner import codec


class MockBBMD:
    def __init__(self, mode='accept', host='127.0.0.1'):
        self.mode = mode
        self.registrations = []       # (addr, ttl)
        self.distributed = 0          # Distribute-Broadcast-To-Network received
        self.downstream = []          # MockBACnetDevice instances behind it
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, 0))
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def add_device(self, dev):
        """Register a mock device as reachable through this BBMD.

        The device must have been built with patch_port=False: the scanner
        talks to the BBMD, and the BBMD relays. A downstream device that
        retargeted the scanner at itself would bypass the thing under test.
        """
        if getattr(dev, 'patch_port', False):
            raise AssertionError(
                "device behind a BBMD must be constructed with patch_port=False")
        self.downstream.append(dev)
        return dev

    def __enter__(self):
        import hvac_scanner.bacnet as _b
        self._saved_port = _b.BACNET_PORT
        _b.BACNET_PORT = self.port
        self._thread.start()
        return self

    def __exit__(self, *a):
        import hvac_scanner.bacnet as _b
        _b.BACNET_PORT = self._saved_port
        self._stop = True
        self._sock.close()

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError:
                return
            try:
                self._handle(data, addr)
            except Exception:
                pass

    def _result(self, code, addr):
        self._sock.sendto(
            struct.pack('!BBHH', 0x81, codec.BVLC_RESULT, 6, code), addr)

    def _handle(self, data, addr):
        if len(data) < 4 or data[0] != 0x81:
            return
        fn = data[1]

        if fn == codec.BVLC_REGISTER_FOREIGN_DEVICE:
            if self.mode == 'silent':
                return
            if self.mode == 'refuse':
                self._result(codec.BVLC_RESULT_REGISTER_FOREIGN_DEVICE_NAK, addr)
                return
            ttl = struct.unpack('!H', data[4:6])[0]
            self.registrations.append((addr, ttl))
            self._result(codec.BVLC_RESULT_SUCCESS, addr)
            return

        if fn == codec.BVLC_DISTRIBUTE_BROADCAST_TO_NETWORK:
            self.distributed += 1
            if not any(a == addr for a, _t in self.registrations):
                self._result(codec.BVLC_RESULT_DISTRIBUTE_BROADCAST_NAK, addr)
                return
            # Relay to downstream devices as a Forwarded-NPDU: BVLC function
            # 0x04 with the originating device's 6-byte B/IP address inserted
            # ahead of the NPDU. Replies go straight back to the scanner.
            npdu = data[4:]
            for dev in self.downstream:
                origin = socket.inet_aton('127.0.0.1') + struct.pack('!H', dev.port)
                fwd = struct.pack('!BBH', 0x81, codec.BVLC_FORWARDED_NPDU,
                                  4 + 6 + len(npdu)) + origin + npdu
                dev.handle_forwarded(fwd, addr)
            return

        # Anything else addressed to the BBMD is ignored.
