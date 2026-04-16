"""
Constants, lookup tables, and reference data for the HVAC Network Scanner.

Split out from the monolithic scanner so unit tests can import these without
pulling in tkinter or the socket layer.

Sources:
- ASHRAE Standard 135 (BACnet) engineering unit enumerations
- BACnet vendor ID registry (https://bacnet.org/assigned-vendor-ids/)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# BACnet framing
# ---------------------------------------------------------------------------
BACNET_PORT = 47808
BACNET_BVLC_TYPE = 0x81

# ---------------------------------------------------------------------------
# BACnet object types (ASHRAE 135 Table 21-1 partial)
# ---------------------------------------------------------------------------
BACNET_OBJ_TYPES = {
    0: "Analog Input", 1: "Analog Output", 2: "Analog Value",
    3: "Binary Input", 4: "Binary Output", 5: "Binary Value",
    6: "Calendar", 7: "Command", 8: "Device",
    9: "Event Enrollment", 10: "File", 11: "Group",
    12: "Loop", 13: "Multi-State Input", 14: "Multi-State Output",
    15: "Notification Class", 16: "Program", 17: "Schedule",
    18: "Averaging", 19: "Multi-State Value", 20: "Trend Log",
    21: "Life Safety Point", 22: "Life Safety Zone",
    23: "Accumulator", 24: "Pulse Converter",
    25: "Event Log", 26: "Global Group", 27: "Trend Log Multiple",
    28: "Load Control", 29: "Structured View",
    30: "Access Door", 31: "Timer", 54: "Lighting Output",
    57: "Network Port", 58: "Elevator Group", 59: "Escalator",
}

# ---------------------------------------------------------------------------
# BACnet engineering units (ASHRAE 135 Table C.1 / engineering-units enum)
# Corrected from the original scanner:
#   - 118 is gal/s per the standard, NOT L/min (which is 81)
#   - Added commonly-encountered units missing from v1
# ---------------------------------------------------------------------------
BACNET_UNITS = {
    0: "sqm", 1: "sqft", 2: "mA", 3: "A", 4: "ohm",
    5: "V", 6: "kV", 7: "MV", 8: "VA", 9: "kVA",
    10: "MVA", 11: "VAR", 12: "kVAR", 13: "MVAR",
    14: "degrees-phase", 15: "PF",
    17: "psi", 18: "bar", 19: "kPa", 20: "cmH2O", 21: "inH2O",
    22: "mmHg", 23: "centibar",
    24: "BTU/lb", 25: "cal/g", 26: "kcal/kg", 27: "J/kg", 28: "kJ/kg",
    29: "W", 30: "kW", 31: "MW", 32: "BTU/h",
    33: "hp", 34: "ton", 35: "J/h", 36: "kJ/h",
    40: "lux", 41: "fc",
    62: "C", 63: "K", 64: "F",
    65: "C-day", 66: "F-day",
    67: "J", 68: "kJ", 69: "Wh", 70: "kWh",
    71: "BTU", 72: "therm",
    75: "L", 76: "gal", 77: "ft3", 78: "m3",
    80: "L/s", 81: "L/min", 82: "L/h", 83: "gal/min", 84: "CFM",
    85: "m3/h", 86: "m3/s",
    90: "m/s", 91: "km/h", 92: "mph",
    93: "ft/s", 94: "ft/min",
    95: "Pa",                     # duplicates 19 conceptually but standard lists both
    96: "kPa-alt", 97: "mmHg",    # kept for backwards compat
    98: "%", 99: "%/s", 100: "%RH",
    105: "mm", 106: "cm", 107: "m", 108: "in", 109: "ft",
    110: "hr", 111: "RPM", 112: "Hz",
    116: "ppm", 117: "ppb",
    118: "gal/s",                 # CORRECTED from L/min
    119: "gal/min",
    120: "s", 121: "min", 122: "h",
    145: "inWC",
}

# ---------------------------------------------------------------------------
# HVAC service ports (sorted by port # for readable tables)
# ---------------------------------------------------------------------------
HVAC_SERVICES = [
    (21,    "FTP",                "tcp"),
    (22,    "SSH",                "tcp"),
    (23,    "Telnet",             "tcp"),
    (80,    "HTTP",               "tcp"),
    (102,   "Siemens S7 / ISO-TSAP", "tcp"),
    (161,   "SNMP",               "udp"),
    (443,   "HTTPS",              "tcp"),
    (502,   "Modbus TCP",         "tcp"),
    (1628,  "LonWorks/IP",        "tcp"),
    (1883,  "MQTT",               "tcp"),
    (1911,  "Niagara Fox",        "tcp"),
    (2222,  "EtherNet/IP Config", "tcp"),
    (3671,  "KNXnet/IP",          "udp"),
    (4840,  "OPC UA",             "tcp"),
    (4843,  "OPC UA TLS",         "tcp"),
    (4911,  "Niagara Fox TLS",    "tcp"),
    (8000,  "HTTP-8000",          "tcp"),
    (8080,  "HTTP-Alt",           "tcp"),
    (8443,  "HTTPS-Alt",          "tcp"),
    (8883,  "MQTT TLS",           "tcp"),
    (8888,  "HTTP-8888",          "tcp"),
    (9090,  "WebCTRL",            "tcp"),
    (9100,  "Building Ctrl",      "tcp"),
    (10001, "Metasys/JCI",        "tcp"),
    (11001, "Metasys ADX",        "tcp"),
    (44818, "EtherNet/IP CIP",    "tcp"),
    (47808, "BACnet/IP",          "udp"),
    (47820, "BACnet/SC",          "tcp"),
]

HVAC_TCP_PORTS = sorted({p for p, _, t in HVAC_SERVICES if t == "tcp"})
HVAC_UDP_PORTS = sorted({p for p, _, t in HVAC_SERVICES if t == "udp"})
PORT_TO_SERVICE = {(p, t): n for p, n, t in HVAC_SERVICES}

# ---------------------------------------------------------------------------
# BACnet vendor database (partial, extended)
# Full registry: https://bacnet.org/assigned-vendor-ids/
# ---------------------------------------------------------------------------
BACNET_VENDORS = {
    0: "ASHRAE", 1: "NIST", 2: "The Trane Company", 3: "McQuay International",
    4: "PolarSoft", 5: "Johnson Controls", 6: "American Auto-Matrix",
    7: "Siemens Building Technologies", 8: "Metasys (JCI)",
    9: "Andover Controls", 10: "TAC (Schneider)", 11: "Orion Analysis",
    12: "Teletrol", 13: "Cimetrics", 14: "Honeywell",
    15: "Alerton", 16: "Carrier Corporation",
    24: "Carrier", 25: "Automated Logic (ALC)",
    27: "KMC Controls", 28: "PolarSoft", 29: "Trend Control Systems",
    36: "Reliable Controls", 37: "Tridium", 38: "Sierra Monitor",
    42: "CSI Control Systems Inc.", 45: "Dorsett Technologies",
    47: "Siemens", 48: "Tour Andover Controls",
    49: "Vykon / Tridium",
    58: "Tridium / Niagara", 78: "EasyIO", 86: "Carel",
    95: "Distech Controls", 115: "Schneider Electric",
    142: "Belimo", 150: "Invensys / TAC",
    182: "Delta Controls", 200: "Daikin",
    245: "Contemporary Controls",
    260: "Trane",
    343: "Siemens Desigo",
    389: "Loytec",
    404: "ABB",
    485: "Contemporary Controls",
    514: "Cimetrics",
    570: "Mitsubishi Electric",
    800: "LG Electronics",
}

# ---------------------------------------------------------------------------
# HTTP / banner fingerprints: (regex, vendor label)
# Applied against banner + title + server + product text.
# ---------------------------------------------------------------------------
HTTP_FINGERPRINTS = [
    (r"trane|tracer",                                   "Trane"),
    (r"siemens|desigo",                                 "Siemens"),
    (r"honeywell|webs|spyder|tridium|niagara",          "Honeywell / Tridium"),
    (r"johnson.?controls|metasys|fec|nae",              "Johnson Controls"),
    (r"schneider|ecostruxure|smartx|andover",           "Schneider Electric"),
    (r"carrier|i-?vu|alerton",                          "Carrier / ALC"),
    (r"automated.?logic|webctrl",                       "Automated Logic"),
    (r"daikin",                                         "Daikin"),
    (r"distech",                                        "Distech Controls"),
    (r"delta.?controls",                                "Delta Controls"),
    (r"reliable.?controls",                             "Reliable Controls"),
    (r"kmc|flexstat|bac-?net",                          "KMC Controls"),
    (r"carel|pco",                                      "Carel"),
    (r"belimo",                                         "Belimo"),
    (r"easyio",                                         "EasyIO"),
    (r"loytec",                                         "Loytec"),
    (r"beckhoff",                                       "Beckhoff"),
    (r"wago",                                           "WAGO"),
    (r"emerson|copeland|vertiv",                        "Emerson"),
    (r"danfoss",                                        "Danfoss"),
    (r"mitsubishi.?electric|melco|city.?multi",         "Mitsubishi Electric"),
    (r"lg.?electronics|lgap|multi.?v",                  "LG Electronics"),
    (r"samsung|dvm",                                    "Samsung HVAC"),
    (r"ubiquiti|unifi",                                 "Ubiquiti"),
]

# ---------------------------------------------------------------------------
# Default credentials database. STRICTLY for the legitimate owner/operator
# of their own BAS. Factory defaults that every integrator already knows.
# ---------------------------------------------------------------------------
DEFAULT_CREDS = {
    'Trane Tracer SC':                  'admin / Tracer1$  |  Trane / Tr@n3',
    'Trane Tracer SC+':                 'admin / Tracer1$',
    'Trane Tracer UC':                  '(no default auth on web UI)',
    'Siemens Desigo PXC':               'ADMIN / SBTAdmin!1',
    'Siemens Desigo CC':                'Application login (site-configured)',
    'Siemens Desigo Insight':           'admin / (site-configured)',
    'Johnson Controls Metasys':         'MetasysAgent / MetasysAgent  |  admin / JCI-admin',
    'Johnson Controls FEC':             'admin / admin',
    'Honeywell Tridium Niagara':        'admin / (set at install)',
    'Schneider EcoStruxure':            'USER1 / USER1  |  admin / admin',
    'Automated Logic WebCTRL':          'admin / admin',
    'Contemporary Controls BASRT-B':    'admin / admin',
    'Carrier i-Vu':                     'admin / admin',
    'KMC Controls':                     'admin / admin',
    'Distech Controls':                 'admin / admin',
    'Reliable Controls':                'admin / admin',
    'Delta Controls':                   'admin / admin',
    'Carel pCO':                        'admin / admin  |  user / user',
    'Belimo':                           'admin / belimo',
    'EasyIO':                           'admin / admin',
    'Daikin':                           'admin / admin',
    'Nucleus FTP (Siemens)':            'admin / admin  |  ADMIN / SBTAdmin!1',
}


# ---------------------------------------------------------------------------
# Property identifiers used by the scanner
# ---------------------------------------------------------------------------
PROP_IDS = {
    'objectName':                   77,
    'objectList':                   76,
    'presentValue':                 85,
    'description':                  28,
    'units':                        117,
    'vendorName':                   121,
    'modelName':                    70,
    'firmwareRevision':             44,
    'applicationSoftwareVersion':   12,
    'objectIdentifier':             75,
    'protocolVersion':              98,
    'protocolRevision':             139,
    'systemStatus':                 112,
    'databaseRevision':             155,
    # hyphenated aliases for convenience
    'object-name':                  77,
    'object-list':                  76,
    'present-value':                85,
    'vendor-name':                  121,
    'model-name':                   70,
    'firmware-revision':            44,
    'application-software-version': 12,
    'protocol-version':             98,
    'protocol-revision':            139,
    'system-status':                112,
}

# Default property set read during device discovery (deep scan)
DEFAULT_DEVICE_PROPERTIES = [
    'object-name',
    'vendor-name',
    'model-name',
    'firmware-revision',
    'application-software-version',
    'description',
    'protocol-version',
    'protocol-revision',
]

# Default property set read per point (deep scan)
DEFAULT_POINT_PROPERTIES = [
    'presentValue',
    'objectName',
    'units',
    'description',
]
