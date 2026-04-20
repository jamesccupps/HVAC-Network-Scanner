---
name: Device profile submission
about: Share verified device information so the scanner can classify your hardware by name
title: "[Profile] <vendor> <model>"
labels: device-profile
---

## Device information

Copy/paste these values from your scan log or classification report. The
scanner reads them directly from the device — don't substitute what the
nameplate says.

- **Vendor name (as reported by device):** 
- **Model name (as reported by device):** 
- **Firmware revision (if reported):** 
- **BACnet vendor ID (numeric):** 
- **Observed object count:** 

## Scan result

- **Did the scan complete successfully?** Yes / No
- **Were there any BACnet errors or rejects?** None / Some (describe)
- **Did the device require RPM fallback?** No / Yes (describe)

## Site / context (optional)

Feel free to leave this blank. If you're willing to have the profile
credited to your site in the `verified_at` field, put a short tag here
(e.g. "ACME HQ 2026", "Anonymous commercial office").

- **Site tag:** 
- **Date of scan:** 

## Classification report (attach or paste)

Paste the relevant device section from your `--export-classification`
report below, or attach the full `.txt` file to this issue.

```
<paste classification report excerpt here>
```

## Additional notes

Anything else worth knowing? Quirks observed, unusual object types,
slow response times, etc.
