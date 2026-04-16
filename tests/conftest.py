"""Shared pytest configuration."""

import sys
from pathlib import Path

# Ensure the package is importable without install
sys.path.insert(0, str(Path(__file__).parent.parent))
