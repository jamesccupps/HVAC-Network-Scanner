"""
Fast TCP connect sweep, shared by the Modbus and service scanners.

Until v2.7 each sweep ran one blocking connect() per thread, 50-80 threads at
a time. On a real subnet most addresses are empty, and an empty address costs
the whole connect timeout, so a /24 service sweep (254 hosts x 25 ports) spent
most of its time waiting — 6,350 attempts / 80 threads x 2 s is over two and
a half minutes of nothing.

Here the attempts are coroutines on one event loop: a few hundred can be
pending at once for the cost of a few hundred sockets, not a few hundred
threads. Targets are taken lazily from an iterator, so a /16 never becomes a
million-entry list in memory.

Order matters for the devices on the other end. Callers pass targets
port-major (every host on port 21, then every host on port 22, ...), so at
any moment a given controller is seeing roughly one connection attempt, not
twenty-five at once. Small field controllers have small TCP stacks.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Iterable, Optional

log = logging.getLogger(__name__)

# Hard ceiling on simultaneous connection attempts. Windows and Linux both
# handle this comfortably; much past it, a home-grade firewall's connection
# table starts to notice.
MAX_CONCURRENCY = 512


def tcp_sweep(targets: Iterable[tuple[str, int]], *,
              timeout: float,
              concurrency: int = 256,
              total: int = 0,
              stop_event=None,
              on_open: Optional[Callable[[str, int], None]] = None,
              progress: Optional[Callable[[int, int], None]] = None
              ) -> list[tuple[str, int]]:
    """Try a TCP connection to each (ip, port); return the ones that accepted.

    `total`, if known, is passed to `progress(done, total)`, which is called
    every few dozen attempts. `on_open(ip, port)` fires as each open port is
    found. A set `stop_event` ends the sweep after the attempts in flight.
    Runs its own event loop, so call it from a plain (non-async) thread.
    """
    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))
    found: list[tuple[str, int]] = []
    done = 0
    it = iter(targets)

    def report() -> None:
        if progress:
            try:
                progress(done, total)
            except Exception:
                log.exception("progress callback failed")

    async def attempt(ip: str, port: int) -> bool:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout)
        except (OSError, asyncio.TimeoutError, ValueError):
            return False
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        except (OSError, asyncio.TimeoutError):
            pass
        return True

    async def worker() -> None:
        nonlocal done
        for ip, port in it:                 # shared iterator: safe on one loop
            if stop_event is not None and stop_event.is_set():
                return
            if await attempt(ip, port):
                found.append((ip, port))
                if on_open:
                    try:
                        on_open(ip, port)
                    except Exception:
                        log.exception("on_open callback failed")
            done += 1
            if done % 32 == 0:
                report()

    async def main() -> None:
        # A device that resets the connection as it is being closed makes the
        # loop log a scary-looking traceback. It is routine on a sweep.
        asyncio.get_running_loop().set_exception_handler(
            lambda _loop, ctx: log.debug("sweep: %s", ctx.get('message')))
        await asyncio.gather(*(worker() for _ in range(concurrency)))

    asyncio.run(main())
    report()
    return found
