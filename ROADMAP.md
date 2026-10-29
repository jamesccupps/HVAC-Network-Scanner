# Roadmap

What is planned or under consideration, roughly in priority order within each
section. Nothing here is a promise of a date. If something you need is
missing, open an issue — that is how items get onto this list and how they
move up it.

Shipped work moves to [CHANGELOG.md](CHANGELOG.md) — most recently point
status flags, multi-state text and the HTML survey report (2.7.0).

## Next

### Siemens APOGEE devices

APOGEE panels on firmware revision 2.x (PXC, PME1252, PXME V2.8.x) speak
Siemens' proprietary P2 protocol over Ethernet rather than BACnet/IP. They
have IP addresses, Desigo CC or Insight may be actively managing them, and
yet today the scanner reports nothing more than a "did not respond to Who-Is"
note — an APOGEE-heavy building looks empty.

Planned, in stages:

1. **Detect.** Recognise a P2 panel from the outside: the TCP port it
   listens on and its response to a harmless connection, so it is reported
   as "Siemens APOGEE panel (P2)" with its address instead of disappearing.
   Read-only, and no more traffic than the existing service probes.
2. **Identify.** Pull what the panel will say about itself without
   credentials — panel name, node, firmware revision — so the inventory
   distinguishes a PXC Modular from a PXC Compact and flags the firmware 2.x
   units that are candidates for a 3.x (BACnet/IP) upgrade.
3. **Enumerate points**, if it can be done safely and read-only. The
   protocol work already exists in the
   [P2 scanner and Wireshark dissector](https://github.com/jamesccupps/P2_Wireshark_Dissector_And_P2_Scanner)
   project; the question is how much of it belongs here versus being called
   from here.

Constraints carried over from [CONTRIBUTING.md](CONTRIBUTING.md): clean-room,
pcap-derived protocol knowledge only, never anything derived from decompiled
vendor software, and never a write to a panel.

### BACnet

- **MS/TP behind remote routers without a BBMD.** Unicast discovery (v2.7)
  finds IP devices on other subnets, but the MS/TP devices behind a remote
  router still need a BBMD. Asking each discovered router directly
  (Who-Is-Router-To-Network, then a routed Who-Is per network) would cover it.
- **Trend log and schedule inventory**, as metadata only (what is trended,
  at what interval; which schedules exist), without pulling history.
- **BACnet/SC.** Detect BACnet Secure Connect hubs (TLS/WebSocket on 47820)
  as more sites adopt it.

### Usability

- **Saved site profiles** in the GUI: named target lists with their own
  options, for people who audit the same few buildings regularly.

## Later / under consideration

- JCI N2 and LonWorks/IP detection (detection only, same constraints as
  APOGEE).
- KNXnet/IP search request (UDP 3671) and Modbus RTU-over-TCP gateways that
  only answer specific unit IDs.
- Signed Windows builds, if a code-signing certificate becomes available.
- A packaged Linux build (AppImage) of the GUI.

## Not planned

- Anything that writes to a device, changes a setpoint, or logs in with the
  default credentials it lists. The scanner reports; it does not act.
