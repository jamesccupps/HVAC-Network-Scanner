# HVAC Network Scanner

A zero-dependency BACnet/IP, Modbus TCP, and HVAC service discovery tool with a tkinter GUI. Scans building automation networks to enumerate controllers, read live point values, and identify devices by vendor and model.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **BACnet/IP Discovery** — Raw UDP Who-Is/I-Am with full ReadProperty support (no BAC0 or bacpypes needed)
- **BACnet MSTP** — Discovers routers via Who-Is-Router-To-Network, then probes each remote network
- **BACnet Deep Scan** — Reads objectName, presentValue, units, and description for every point on every device
- **Modbus TCP** — Port 502 sweep with Device ID (FC 0x2B), register reads, and coil status
- **25+ HVAC Service Ports** — Niagara Fox, OPC UA, KNX, LonWorks, EtherNet/IP CIP, Siemens S7, MQTT, HTTP/HTTPS banner grab, SSH, Telnet, FTP
- **SNMP Discovery** — Raw UDP SNMPv1 sysDescr reads
- **Device Fingerprinting** — Identifies Trane, Siemens, Johnson Controls, Honeywell, Schneider, Carrier, and 20+ other vendors from protocol responses and service banners
- **Default Credentials Database** — Known factory-default logins for common BAS controllers
- **5-Tab Interface** — All Devices, BACnet Points, Modbus Registers, Services, Raw JSON
- **Sortable Columns** — IP-aware and numeric-aware sorting on every column
- **Right-Click Context Menu** — Open Web UI, Copy IP, Copy Credentials, Ping, Show Details
- **Export** — CSV (Excel-compatible) and JSON

## Screenshots

*Add your own screenshots here after running a scan*

## Quick Start

### Windows
```
git clone https://github.com/YOUR_USERNAME/hvac-network-scanner.git
cd hvac-network-scanner
run_hvac_scanner.bat
```

### Linux / macOS
```bash
git clone https://github.com/YOUR_USERNAME/hvac-network-scanner.git
cd hvac-network-scanner
pip install pymodbus  # optional, for Modbus deep scan
python3 hvac_scanner.py
```

### Manual
1. Install [Python 3.10+](https://python.org)
2. Download or clone this repo
3. Run `python hvac_scanner.py`
4. Enter your HVAC network CIDR (e.g. `192.168.1.0/24`)
5. Check desired protocols and click **SCAN**

## Requirements

| Requirement | Notes |
|------------|-------|
| Python 3.10 - 3.13 | Standard CPython |
| tkinter | Included with Python on Windows; `sudo apt install python3-tk` on Linux |
| pymodbus | **Optional** — auto-installed by batch file; only needed for Modbus deep scan |

**No BACnet libraries required.** The scanner implements BACnet/IP ReadProperty from scratch using raw UDP sockets. BAC0, bacpypes, and bacpypes3 are not needed.

## How It Works

### BACnet Discovery Flow
1. Broadcasts a Who-Is packet (BVLC → NPDU → Unconfirmed Who-Is) on UDP port 47808
2. Parses I-Am responses to extract device instance, vendor ID, max APDU, segmentation support
3. Sends Who-Is-Router-To-Network to discover BACnet routers and their MSTP/remote networks
4. For each router, sends directed Who-Is to each DNET to find MSTP field controllers
5. **Deep scan**: sends ReadProperty requests for device properties (objectName, vendorName, modelName, firmware, etc.)
6. Reads the objectList via array-indexed ReadProperty (index 0 for count, then 1..N)
7. For each object: reads presentValue, objectName, units, description

### Raw BACnet ReadProperty
The `RawBACnetReader` class constructs complete BACnet packets from scratch:
- BVLC header (Original-Unicast-NPDU)
- NPDU with expecting-reply flag
- Confirmed-Request APDU with ReadProperty service
- Context-tagged Object Identifier and Property Identifier
- Parses Complex-ACK responses with full application tag decoding (Null, Boolean, Unsigned, Signed, Real, Double, CharacterString, Enumerated, ObjectIdentifier)

### Service Scanning
Probes 25+ TCP ports associated with building automation systems, then performs protocol-specific identification:
- HTTP/HTTPS: grabs Server header and page title, matches against 20+ vendor fingerprint patterns
- Niagara Fox: sends Fox hello handshake
- Siemens S7: sends COTP Connection Request
- EtherNet/IP: sends CIP List Identity
- SSH/Telnet/FTP: grabs banner

### Device Fingerprinting
Cross-references multiple data sources to identify exact hardware:
- BACnet vendor ID + device instance numbering patterns
- Max APDU size and segmentation support
- MSTP routing relationships
- TCP service signatures (Nucleus FTP, nginx, Ethernut)
- HTTP title and server headers

## Supported Vendors

The fingerprint engine identifies controllers from:

| Vendor | Models Identified |
|--------|-------------------|
| Trane | Tracer SC+, Tracer SC, UC800/UC600, UC400/MP581 |
| Siemens | Desigo CC, PXC Automation Station, PXC Compact/Modular, TX-I/O |
| Johnson Controls | FEC, FAC, NAE, Metasys |
| Honeywell / Tridium | Niagara AX/N4, Spyder |
| Schneider Electric | EcoStruxure, SmartX |
| Carrier / ALC | i-Vu, WebCTRL |
| Contemporary Controls | BASRT-B router |
| Cimetrics | BACstac gateway/analyzer |
| + 15 more | KMC, Distech, Delta, Reliable, Daikin, Belimo, etc. |

## Network Requirements

- Your scanning machine must be on the same network/VLAN as the HVAC controllers, or have routing to them
- BACnet/IP uses UDP port 47808 — the scanner tries to bind to this port first (some devices hardcode I-Am responses to 47808), then falls back to an ephemeral port
- If another BACnet application is already using port 47808, close it first or accept ephemeral port mode
- Firewall must allow UDP 47808 (BACnet) and TCP 502 (Modbus) at minimum
- Run as Administrator on Windows if you have binding issues

## Configuration

All configuration is done in the GUI. Comma-separate multiple networks:

```
192.168.1.0/24, 192.168.2.0/24, 10.10.0.0/16
```

Single device scan:
```
192.168.1.100/32
```

### Scan Options

| Option | Default | Description |
|--------|---------|-------------|
| BACnet | ✓ | Who-Is broadcast discovery |
| MSTP | ✓ | Router + remote network discovery |
| Modbus | ✓ | TCP port 502 sweep |
| Services | ✓ | 25+ HVAC service ports |
| SNMP | ✓ | SNMPv1 sysDescr probe |
| Deep | ✓ | Read all properties, object lists, registers |
| Timeout | 5s | BACnet timeout; services capped at 2s |

## Architecture

```
hvac_scanner.py (~2300 lines, single file)
├── RawBACnetReader      — Raw UDP ReadProperty (zero dependencies)
├── BACnetScanner        — Who-Is / I-Am / MSTP router discovery
├── ModbusScanner        — Raw TCP Modbus scanner
├── HVACServiceScanner   — TCP/HTTP service probing + banner grab
├── SNMPScanner          — Raw UDP SNMP v1/v2c
├── fingerprint_device() — Multi-source device identification
├── HVACNetworkScanner   — tkinter GUI (5 tabs, sorting, context menu)
├── BACNET_VENDORS       — 30+ vendor ID mappings
├── BACNET_UNITS         — ASHRAE 135 engineering unit enumerations
├── DEFAULT_CREDS        — Known factory-default credentials
└── HTTP_FINGERPRINTS    — 20+ regex patterns for HTTP vendor ID
```

## Export Formats

### CSV
- UTF-8 with BOM for Excel compatibility
- Columns: Protocol, IP, Port, Device/Unit ID, Network, Vendor, Model, Name, Points, Banner, Segmentation, Max APDU

### JSON
- Full device data including all read properties, object lists, and register values
- Suitable for programmatic analysis or import into other tools

## Notes

- Deep scan caps at 200 objects per device to avoid timeouts on large controllers
- Trane Tracer SC/SC+ controllers flatten LonWorks sub-objects into BACnet Analog Inputs. The pipe character in point names (`Discharge Air Temp|dac-1`) indicates the source controller.
- Very large present values like `9.87e35` from Trane VAVs are IEEE 754 sentinel values for unconfigured auto-commissioning points — not real readings
- The scanner is read-only — it never writes to any device

## Contributing

Pull requests welcome. Areas that could use work:
- Additional vendor fingerprints
- BACnet WriteProperty support (for commissioning tools)
- Trend log reading
- Schedule reading/display
- BACnet/SC (Secure Connect) support
- Alarm/event subscription

## License

MIT License — see [LICENSE](LICENSE)
