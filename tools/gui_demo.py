"""Drive the real GUI through a scan of the simulated site and screenshot it.

    python tools/sim_site.py &          # the simulated site
    python tools/gui_demo.py out.png    # scan it in the GUI, save a screenshot

    tools/gui_demo.py out.png [devices|points|meta|modbus|services]
        [--advanced] [--filter=TEXT] [--select=TEXT] [--targets=SPEC]
        [--site=NAME] [--probe] [--geometry=WxH+X+Y] [--dpi=96]
        [--sort=COLUMN | --sort=-COLUMN]

--dpi lays the window out as on a screen of that DPI (fonts are sized from
it), so screenshots taken on a 150% display match ones taken at 100%.

Used for the README screenshot and as a smoke test of the packaged GUI path:
it presses the actual Scan button rather than calling the engine. The
screenshot is the window drawn by itself (PrintWindow, through PowerShell:
Windows only), so whatever covers it on screen does not show.
"""

from __future__ import annotations

import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hvac_scanner.gui import HVACNetworkScannerGUI  # noqa: E402

# PrintWindow with PW_CLIENTONLY | PW_RENDERFULLCONTENT: the window draws
# itself into the bitmap, so nothing on top of it (another window, a
# screen-sharing bar) ends up in the picture.
_CAPTURE = r"""
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class Pw {{
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
}}
'@
$b = New-Object System.Drawing.Bitmap {w}, {h}
$g = [System.Drawing.Graphics]::FromImage($b)
$dc = $g.GetHdc()
$ok = [Pw]::PrintWindow([IntPtr]{hwnd}, $dc, 3)
$g.ReleaseHdc($dc)
if (-not $ok) {{ exit 1 }}
$b.Save('{out}', [System.Drawing.Imaging.ImageFormat]::Png)
"""


def capture(root: tk.Tk, out: Path) -> None:
    root.update()
    hwnd = int(root.wm_frame(), 16)
    w, h = root.winfo_width(), root.winfo_height()
    script = _CAPTURE.format(hwnd=hwnd, w=w, h=h, out=str(out).replace("'", "''"))
    # The window keeps answering messages while PowerShell captures it: left
    # waiting, Windows may draw it as a blank "not responding" ghost, which
    # is what gets captured.
    import threading
    done: list = []

    def run() -> None:
        done.append(subprocess.run(["powershell", "-NoProfile", "-Command", script],
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)))
    worker = threading.Thread(target=run)
    worker.start()
    while worker.is_alive():
        root.update()
        time.sleep(0.02)
    if done[0].returncode:
        raise RuntimeError("screen capture failed")


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
    dpi = float(_opt(argv, "dpi") or root.winfo_fpixels('1i'))
    root.tk.call('tk', 'scaling', dpi / 72.0)
    app = HVACNetworkScannerGUI(root, settings_path=None)
    # --geometry=WxH+X+Y keeps the capture clear of anything pinned to the
    # screen (a screen-sharing bar, say), since the capture is of the screen.
    root.geometry(_opt(argv, "geometry") or "1500x940+40+40")
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
    sort = _opt(argv, "sort")                  # a column's heading; -Heading descending
    if sort:
        tree = (app.device_tree, app.points_tree, app.meta_tree, app.reg_tree,
                app.svc_tree)[tabs.get(tab, 0)]
        col = next(c for c in tree["columns"]
                   if tree.heading(c, "text").rstrip(" ▲▼").lower() == sort.lstrip("-").lower())
        for _ in range(2 if sort.startswith("-") else 1):
            app._sort_treeview(tree, col)
    if tab == "devices":
        rows = app.device_tree.get_children()
        want = _opt(argv, "select")
        pick = next((r for r in rows if want and want in " ".join(
            str(v) for v in app.device_tree.item(r, "values"))), rows[0] if rows else None)
        if pick:
            app.device_tree.selection_set(pick)
            app.device_tree.see(pick)
    # Long enough for a tab of a thousand rows to be drawn: captured sooner,
    # the window can still be blank.
    for _ in range(50):
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
