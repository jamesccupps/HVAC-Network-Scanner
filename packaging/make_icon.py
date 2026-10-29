"""Write packaging/hvac_scanner.ico from the icon drawn in hvac_scanner/icon.py.

    python packaging/make_icon.py

The .ico is checked in so a build needs nothing but PyInstaller; rerun this
after changing the drawing.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hvac_scanner.icon import ico_bytes  # noqa: E402

out = ROOT / "packaging" / "hvac_scanner.ico"
out.write_bytes(ico_bytes())
print(f"wrote {out} ({out.stat().st_size:,} bytes)")
