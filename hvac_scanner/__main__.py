"""
Entry point for `python -m hvac_scanner`.

Launches the GUI. For the CLI, use `python -m hvac_scanner.cli` or the
installed `hvac-scanner` console script.
"""

from .gui import main

if __name__ == "__main__":
    main()
