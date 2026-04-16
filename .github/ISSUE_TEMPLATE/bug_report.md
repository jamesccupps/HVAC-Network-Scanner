---
name: Bug report
about: Report a defect or unexpected behavior
title: "[Bug] "
labels: bug
assignees: ''
---

**Describe the bug**
A clear, concise description of what's wrong.

**To reproduce**
Steps to reproduce:
1. Command/flags used (or GUI settings)
2. Network / subnet scanned (if safe to share)
3. Observed behavior
4. Expected behavior

**Environment**
- Scanner version (`python -c "import hvac_scanner; print(hvac_scanner.__version__)"`):
- Python version (`python --version`):
- Operating system:
- Running under: [ ] GUI [ ] CLI [ ] Task Scheduler / cron

**Device details (if applicable)**
If the bug involves a specific controller or gateway, note:
- Vendor / model:
- BACnet vendor ID and max-APDU:
- Whether the device is direct-connected or behind an MSTP router:

**Log output**
Paste any relevant scan log or stack trace (remove site-identifying info first).

```
(logs here)
```

**Packet capture (optional but extremely helpful)**
A `.pcap` or `.pcapng` of the relevant exchange is the fastest path to a fix.
Wireshark filter for BACnet: `bacnet || (udp.port == 47808)`.

**Additional context**
Anything else we should know.
