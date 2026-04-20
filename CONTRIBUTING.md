# Contributing to HVAC Network Scanner

Thanks for your interest in helping improve this tool. The most valuable
contribution you can make is **device profile data** from hardware you
actually have running on a real network.

This document covers:

1. How the scanner handles unknown vendors (why profiles matter)
2. How to submit a device profile
3. How to submit a bug report
4. How to submit a general pull request


## 1. How the scanner handles unknown vendors

The scanner has two classification paths for figuring out how to scan a
given BACnet device:

- **Known device profiles** — entries in `hvac_scanner/device_profiles.py`
  with a verified vendor/model combination. These have been tested
  against real hardware and have a known-good object enumeration cap
  plus a human-readable class label.

- **Heuristic fallback** — if a device's vendor/model doesn't match any
  profile, the scanner sizes its cap based on the device's own reported
  object count (`objectList` length). This works correctly for
  unknown gear; it just doesn't produce as nice a classification label.

**The heuristic is a correctness-complete path.** You don't need a
device profile for the scanner to work on your gear. Profiles exist to
make the scan *classification* more informative and to protect against
edge cases (e.g. a vendor that misreports its object count).

This means the value of a contributed profile is: "next time someone
scans gear like mine, they see a clean 'Trane supervisory (Tracer SC+)'
label instead of 'heuristic [large, 5517 objects]'."


## 2. How to submit a device profile

The easiest path is the **GitHub issue route**, which doesn't require a
PR or any code changes on your end:

1. Run the scanner against your device with deep-scan on.
2. Export a classification report: in the GUI's Export dialog, select
   "Classification report (v2.2)" and save as `.txt`. Or on the CLI:
   ```
   hvac-scanner 10.0.0.0/24 --export-classification report.txt
   ```
3. Open a new issue at
   <https://github.com/jamesccupps/HVAC-Network-Scanner/issues/new/choose>
   and select "Device profile submission."
4. Paste the relevant section of the report into the issue body.

The report contains only metadata needed to build a profile: vendor
name, model name, observed object count, and which classification path
the scanner took. **It does NOT contain point values, setpoints, names
of rooms or any facility-identifying information** — you can share it
without exposing anything sensitive.

I'll review submissions periodically and, when there's enough evidence
to add a profile with confidence, add it to `device_profiles.py` with
your site credited in the `verified_at` field.

### What qualifies as evidence

A profile is added when we have:

- **Real hardware confirmation.** Someone has actually scanned the
  device and reported the results. No adding profiles from data sheets
  or marketing pages — the scanner must have exchanged real BACnet
  traffic with the device.
- **Vendor and model strings captured as the device reports them.**
  Not what the nameplate says — what the device returns via ReadProperty
  on the `vendorName` and `modelName` properties of its Device object.
  These sometimes differ from the product name.
- **An observed object count.** So the cap can be set appropriately
  with headroom (typically observed_count + 50–100%, rounded to a
  sensible value).
- **A scan that completed without errors.** If the device required
  RPM fallback or had other quirks, that's noted alongside the profile.

### What does NOT qualify

- Speculation or data-sheet readings ("the vendor says this panel
  supports up to X objects").
- Profiles derived from a single failed scan — we need to know the
  device works with the scanner before adding a profile.
- Anonymous submissions with no verifiable site context.

This bar is deliberate: a wrong profile is worse than no profile. A
wrong cap that undersizes a device's objectList truncates scans
silently. The heuristic fallback handles unknown devices correctly;
promoting them to "known" requires evidence.


## 3. How to submit a bug report

Open an issue and include:

- Scanner version (`hvac-scanner --version` or look at the log banner)
- OS and Python version
- What you ran (command line and / or target network expression)
- Scan log output (the scan log pane, or redirected stderr from the CLI)
- Wireshark capture if you can get one (BACnet + the specific target
  IP is enough — no need to capture all network traffic)

If the bug involves a specific device vendor/model, a classification
report is extremely helpful for reproduction context.


## 4. How to submit a pull request

For code or doc changes:

1. Fork, branch, commit with a descriptive message.
2. Run the full test suite: `python -m pytest`. **All tests must pass.**
3. If you're adding new functionality, add tests for it. The test
   suite currently covers codec behavior, per-object-type property
   filtering, MSTP routing, target filtering and deduplication,
   vendor profile lookup, auto-broadcast heuristics, and the netrange
   parser.
4. For device profile PRs specifically: add the profile entry to
   `hvac_scanner/device_profiles.py` and a regression test to
   `tests/test_device_profiles.py` asserting the observed object
   count won't trigger truncation.
5. Open the PR with a clear title and body. Link the issue if there
   is one.

### Coding conventions

- No new runtime dependencies unless absolutely necessary. Zero-dep is
  a design goal.
- Python 3.10+ features are fine. Don't worry about 3.9 compatibility.
- Match the existing code style (descriptive variable names, comments
  explaining *why* not *what*, f-strings over `.format()`).
- Logging goes through `log = logging.getLogger(__name__)` — don't
  sprinkle `print()` calls.


## Things I won't accept

- Proprietary protocol reverse-engineering contributions that derive
  from decompiled vendor software. Pcap-derived clean-room analysis
  is fine. Decompilation-derived code is not — both for legal reasons
  (vendor EULAs) and because it creates liability exposure for
  anyone using the tool.
- Integrations with non-BACnet / non-Modbus protocols that would
  significantly expand the scanner's scope. This is a BACnet and
  Modbus TCP inventory tool. Requests for Siemens APOGEE P2, JCI N2,
  or other proprietary protocols should go to tools specifically
  designed for those protocols (e.g. PurpleSwift BACnetP2 for
  Siemens APOGEE integration).
- Features that require users to disable safety mechanisms (e.g.
  "scan without any rate limiting at all") without a clear,
  documented use case.


## Contact

Open an issue for anything. I generally review within a week.
