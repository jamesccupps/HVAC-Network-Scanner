"""Drive the real GUI through a scan of the simulated site and screenshot it.

    python tools/sim_site.py &          # the simulated site
    python tools/gui_demo.py out.png    # scan it in the GUI, save a screenshot

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
    app.network_entry.insert(0, "127.0.0.2-30")
    app.scan_services.set(True)
    if "--advanced" in argv:
        app._toggle_advanced(True)
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

    tabs = {"devices": 0, "points": 1, "modbus": 2, "services": 3}
    app.notebook.select(tabs.get(tab, 0))
    if "--filter" in " ".join(argv):
        app.filter_var.set(next(a.split("=", 1)[1] for a in argv if a.startswith("--filter=")))
        app._apply_filter()
    if tab == "devices":
        rows = app.device_tree.get_children()
        if rows:
            app.device_tree.selection_set(rows[0])
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
