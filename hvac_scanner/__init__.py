"""
HVAC Network Scanner — BACnet/IP, MS/TP and BACnet/SC, Modbus TCP, KNXnet/IP,
APOGEE P2, HVAC services, SNMP.

Zero third-party dependencies (uses only the Python standard library).
"""

__version__ = "2.8.0"
__author__ = "James Cupps"
__license__ = "MIT"

# Public API — anything a downstream script might import
from .bacnet import BACnetClient
from .engine import ScanEngine, ScanOptions, ScanResult
from .fingerprint import fingerprint_device
from .modbus import ModbusScanner
from .services import HVACServiceScanner
from .snmp import SNMPScanner

__all__ = [
    "__version__",
    "BACnetClient",
    "ScanEngine",
    "ScanOptions",
    "ScanResult",
    "fingerprint_device",
    "ModbusScanner",
    "HVACServiceScanner",
    "SNMPScanner",
]
