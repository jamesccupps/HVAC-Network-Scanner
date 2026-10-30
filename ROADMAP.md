# Roadmap

What is planned or under consideration, roughly in priority order within each
section. Nothing here is a promise of a date. If something you need is
missing, open an issue — that is how items get onto this list and how they
move up it.

Shipped work moves to [CHANGELOG.md](CHANGELOG.md) — most recently MS/TP
behind remote routers without a BBMD, BBMD tables, trend log and schedule
inventory, BACnet/SC detection and saved site profiles (2.8.0).

## Next

### Siemens APOGEE devices

APOGEE panels on firmware revision 2.x (PXC, PME1252, PXME V2.8.x) speak
Siemens' proprietary P2 protocol over Ethernet rather than BACnet/IP. They
have IP addresses, Desigo CC or Insight may be actively managing them, and
until 2.7.0 the scanner reported nothing more than a "did not respond to
Who-Is" note — an APOGEE-heavy building looked empty.

Planned, in stages:

1. **Detect — shipped in 2.7.0.** Each open TCP/5033 gets one P2 identify
   frame with a BLN name no site uses; a field panel resets at its access
   gate and a supervisor closes, both before processing and without a
   node-table entry. Panels and supervisors are reported as such.
2. **Identify.** Pull what the panel will say about itself without
   credentials — panel name, node, firmware revision — so the inventory
   distinguishes a PXC Modular from a PXC Compact and flags the firmware 2.x
   units that are candidates for a 3.x (BACnet/IP) upgrade. The blocker is
   that any session past the access gate needs the site's BLN name, and a
   handshake with a new identity writes a permanent node-table entry on the
   panel. So this stage would be opt-in, take the BLN name from the user,
   and say plainly what it leaves behind.
3. **Enumerate points**, if it can be done safely and read-only. The
   protocol work already exists in the
   [P2 scanner and Wireshark dissector](https://github.com/jamesccupps/P2_Wireshark_Dissector_And_P2_Scanner)
   project; the question is how much of it belongs here versus being called
   from here.

Constraints carried over from [CONTRIBUTING.md](CONTRIBUTING.md): clean-room,
pcap-derived protocol knowledge only, never anything derived from decompiled
vendor software, and never a write to a panel.

### BACnet

- **Alarm routing inventory**: Notification Class objects — which
  recipients get which alarms, at what priorities — as metadata, the way
  2.8 reads trend logs and schedules.
- **Router tables**: the Network Port `routingTable`, so networks behind a
  chain of routers are found without a Who-Is-Router-To-Network answer.
- **BACnet/SC identity**: with a certificate the site provides, read the
  hub's own Device object. Opt-in, since it joins the secure network.

## Later / under consideration

- JCI N2 and LonWorks/IP detection (detection only, same constraints as
  APOGEE).
- Modbus RTU-over-TCP gateways that only answer specific unit IDs.
- Signed Windows builds, if a code-signing certificate becomes available.
- A packaged Linux build (AppImage) of the GUI.

## Not planned

- Anything that writes to a device, changes a setpoint, or logs in with the
  default credentials it lists. The scanner reports; it does not act.
