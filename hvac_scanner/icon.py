"""The application icon, drawn in code.

A rounded blue tile with a radar scope — two range rings, a sweep and the
blips it has found. Legible at 16 px. Drawing it here rather than shipping image files
keeps the package free of binary assets: the GUI renders its window icon at
start-up, and `packaging/make_icon.py` writes the same drawing out as the
.ico the Windows executable embeds.
"""

from __future__ import annotations

import functools
import math
import struct
import zlib

_TOP = (0x38, 0x8B, 0xFD)       # tile gradient, top
_BOTTOM = (0x1F, 0x5F, 0xD6)    # tile gradient, bottom
_INK = (0xFF, 0xFF, 0xFF)


def render(size: int, samples: int = 4) -> list[list[tuple[int, int, int, int]]]:
    """RGBA pixel rows for an icon `size` pixels square (supersampled)."""
    s = float(size)
    radius = 0.22 * s
    cx = cy = 0.5 * s
    rings = ((0.36 * s, 0.065 * s), (0.20 * s, 0.055 * s))   # (radius, stroke)
    hub = 0.07 * s
    sweep_angle = math.radians(40)                           # up and to the right
    sweep_w = 0.06 * s
    blips = ((0.5 + 0.20 * math.cos(math.radians(135)), 0.5 - 0.20 * math.sin(math.radians(135)), 0.065),
             (0.5 + 0.36 * math.cos(math.radians(-50)), 0.5 - 0.36 * math.sin(math.radians(-50)), 0.075))
    blips = tuple((bx * s, by * s, br * s) for bx, by, br in blips)
    step = 1.0 / samples

    def tile(x: float, y: float) -> bool:
        # Rounded square covering the whole canvas.
        qx = max(radius - x, 0.0, x - (s - radius))
        qy = max(radius - y, 0.0, y - (s - radius))
        return qx * qx + qy * qy <= radius * radius

    ux, uy = math.cos(sweep_angle), math.sin(sweep_angle)

    def ink(x: float, y: float) -> bool:
        dx, dy = x - cx, cy - y
        d = math.hypot(dx, dy)
        if d <= hub:
            return True
        if any(abs(d - r) <= w / 2 for r, w in rings):
            return True
        along = dx * ux + dy * uy                 # sweep: a bar from the hub out
        if 0 <= along <= rings[0][0] and abs(dx * uy - dy * ux) <= sweep_w / 2:
            return True
        return any(math.hypot(x - bx, y - by) <= br for bx, by, br in blips)

    rows = []
    for py in range(size):
        t = py / max(1, size - 1)
        base = tuple(round(a + (b - a) * t) for a, b in zip(_TOP, _BOTTOM))
        row = []
        for px in range(size):
            cover = inked = 0
            for sy in range(samples):
                y = py + (sy + 0.5) * step
                for sx in range(samples):
                    x = px + (sx + 0.5) * step
                    if tile(x, y):
                        cover += 1
                        if ink(x, y):
                            inked += 1
            n = samples * samples
            if not cover:
                row.append((0, 0, 0, 0))
                continue
            f = inked / cover
            rgb = tuple(round(b + (i - b) * f) for b, i in zip(base, _INK))
            row.append((*rgb, round(255 * cover / n)))
        rows.append(row)
    return rows


@functools.lru_cache(maxsize=None)
def png_bytes(size: int) -> bytes:
    """The icon at `size` as a PNG file."""
    rows = render(size)
    raw = b''.join(b'\x00' + bytes(c for px in row for c in px) for row in rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack('!I', len(data)) + tag + data
                + struct.pack('!I', zlib.crc32(tag + data) & 0xFFFFFFFF))

    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('!IIBBBBB', size, size, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9))
            + chunk(b'IEND', b''))


def ico_bytes(sizes: tuple[int, ...] = (16, 24, 32, 48, 64, 128, 256)) -> bytes:
    """A Windows .ico holding the icon at each of `sizes` (PNG-compressed)."""
    images = [png_bytes(n) for n in sizes]
    header = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b''
    for n, img in zip(sizes, images):
        dim = 0 if n >= 256 else n
        entries += struct.pack('<BBBBHHII', dim, dim, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    return header + entries + b''.join(images)
