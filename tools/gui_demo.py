"""Drive the real GUI through a scan of the simulated site and screenshot it.

    python tools/sim_site.py &          # the simulated site
    python tools/gui_demo.py out.png    # scan it in the GUI, save a screenshot

    tools/gui_demo.py out.png [devices|points|meta|modbus|services]
        [--advanced] [--filter=TEXT] [--select=TEXT] [--targets=SPEC]
        [--site=NAME] [--probe]

Used for the README screenshot and as a smoke test of the packaged GUI path:
it presses the actual Scan button rather than calling the engine. The
screenshot is a capture of the screen region under the window (Windows only,
via PowerShell), so nothing may cover the window while it runs.
"""

from __future__ import annotations

import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hvac_scanner.gui import HVACNetworkScannerGUI  # noqa: E402

_CAPTURE = r"""
Add-Type -AssemblyName System.Drawing
$b = New-Object System.Drawing.Bitmap {w}, {h}
$g = [System.Drawing.Graphics]::FromImage($b)
$g.CopyFromScreen({x}, {y}, 0, 0, $b.Size)
$b.Save('{out}', [System.Drawing.Imaging.ImageFormat]::Png)
"""


def capture(root: tk.Tk, out: Path) -> None:
    root.update()
    x, y = root.winfo_rootx(), root.winfo_rooty()
    w, h = root.winfo_width(), root.winfo_height()
    script = _CAPTURE.format(x=x, y=y, w=w, h=h, out=str(out).replace("'", "''"))
    subprocess.run(["powershell", "-NoProfile", "-Command", script], check=True,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _opt(argv: list[str], name: str) -> "str | None":
    return next((a.split("=", 1)[1] for a in argv if a.startswith(f"--{name}=")), None)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    out = Path(args[0] if args else "gui.png").resolve()
    tab = args[1] if len(args) > 1 else "devices"
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except (AttributeError, OSError, ImportError):
        pass
    root = tk.Tk()
    root.tk.call('tk', 'scaling', root.winfo_fpixels('1i') / 72.0)
    app = HVACNetworkScannerGUI(root, settings_path=None)
    root.geometry("1500x940+40+40")
    app.network_entry.delete(0, tk.END)
    app.network_entry.insert(0, _opt(argv, "targets") or "127.0.0.2-30")
    app.scan_services.set(True)
    app.mstp_mac_probe.set("--probe" in argv)
    if "--advanced" in argv:
        app._toggle_advanced(True)
    if _opt(argv, "site"):
        app._store_profile(_opt(argv, "site"))
    root.attributes('-topmost', True)
    root.update()

    app.scan_btn.invoke()                      # the real button
    deadline = time.time() + 180
    while (app.scan_running or app.result is None) and time.time() < deadline:
        root.update()
        time.sleep(0.05)
    if app.result is None:
        print("scan did not finish", file=sys.stderr)
        return 1

    tabs = {"devices": 0, "points": 1, "meta": 2, "modbus": 3, "services": 4}
    app.notebook.select(tabs.get(tab, 0))
    if _opt(argv, "filter"):
        app.filter_var.set(_opt(argv, "filter"))
        app._apply_filter()
    if tab == "devices":
        rows = app.device_tree.get_children()
        want = _opt(argv, "select")
        pick = next((r for r in rows if want and want in " ".join(
            str(v) for v in app.device_tree.item(r, "values"))), rows[0] if rows else None)
        if pick:
            app.device_tree.selection_set(pick)
            app.device_tree.see(pick)
    for _ in range(20):
        root.update()
        time.sleep(0.05)
    capture(root, out)
    c = app.result.counts
    print(f"{out}  devices={len(app.result.devices)} points={c['points']} "
          f"elapsed={app.result.elapsed:.1f}s status={app.status_var.get()!r}")
    root.destroy()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
