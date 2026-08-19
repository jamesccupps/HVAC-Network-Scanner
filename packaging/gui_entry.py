"""PyInstaller entry point for the GUI.

A frozen build needs a real script to start from; `python -m hvac_scanner`
relies on module execution semantics that PyInstaller does not reproduce.
This keeps that detail out of the package itself.
"""

import multiprocessing
import sys


def main() -> int:
    # Harmless on a single-process app, required if anything ever spawns:
    # without it a frozen Windows build re-launches the whole GUI per child.
    multiprocessing.freeze_support()

    from hvac_scanner.gui import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
