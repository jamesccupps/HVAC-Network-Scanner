# CLI Usage

The scanner ships with a headless CLI suitable for scheduled audits, CI
pipelines, and unattended operation on servers without a display.

```bash
python -m hvac_scanner.cli [OPTIONS] NETWORKS...
```

If you installed with `pip install -e .`, the console script `hvac-scanner`
is also on your PATH and is equivalent.

## Flag reference

### Required

| Flag | Description |
|------|-------------|
| `NETWORKS` | One or more CIDR networks (e.g. `192.168.1.0/24`). Multiple networks are space-separated. |

### General

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout SECONDS` | `5` | Per-operation timeout. BACnet-heavy devices may benefit from 8–10. |
| `--rate-limit MS` | `0` | Minimum ms between BACnet packets to the same IP. Set to `50` for small field controllers (UC400, FEC, BASRT). |
| `--max-objects N` | unset | Hard ceiling on BACnet objects enumerated per device, applied on top of the vendor-aware profile cap. Only ever lowers it. Omit to use the profile cap. |
| `--scan-depth LEVEL` | `normal` | `quick` samples ~5% of each device's points, `normal` honours the vendor-aware caps, `full` reads every object. |
| `--broadcast IP` | auto | Override the computed Who-Is broadcast target. Rarely needed: the broadcast is derived from the target syntax automatically. |
| `--no-rpm` | off | Disable `ReadPropertyMultiple`. Use if a specific device misbehaves with RPM requests. Costs roughly two orders of magnitude more round trips on a large controller. |

### Large-network probing

| Flag | Default | Description |
|------|---------|-------------|
| `--whois-chunk SIZE` | `0` | Split Who-Is into instance ranges of this size instead of one global broadcast. On a busy multi-building segment a single global Who-Is makes every device answer at once; chunking spreads the replies out. `0` disables. |
| `--whois-max-instance N` | `4194303` | Upper bound when chunking. Only used with `--whois-chunk`. |
| `--whois-chunk-delay MS` | `50` | Pause between chunked broadcasts. |

### Protocol toggles

All protocols are enabled by default. Any flag turns the corresponding protocol off.

| Flag | Effect |
|------|--------|
| `--no-bacnet` | Skip BACnet/IP `Who-Is` discovery. |
| `--no-mstp` | Skip `Who-Is-Router-To-Network` and MSTP enumeration. |
| `--no-modbus` | Skip Modbus TCP sweep. |
| `--no-services` | Skip the HVAC-services TCP port scan. |
| `--no-snmp` | Skip SNMP `sysDescr` probe. |
| `--no-deep` | Skip deep-scan. Discovery only — no object lists, no register reads. |
| `--bacnet-only` | Shortcut for `--no-modbus --no-services --no-snmp`. |

### Output

| Flag | Description |
|------|-------------|
| `--json PATH` | Write structured results to a JSON file. |
| `--csv PATH` | Write results as CSV (UTF-8 BOM, Excel-friendly). |
| `--export-classification PATH` | Write a plain-text report of how each BACnet device was classified: which profile matched, the cap applied, and the observed object count. Contains no point values. Intended for submitting a device profile when you scan hardware the project has not seen. |
| `--print FORMAT` | Stdout: `summary` (default), `table`, `json`, `none`. |
| `--quiet` / `-q` | Suppress progress log on stderr. |
| `--verbose` / `-v` | Enable DEBUG logging. |

### Baseline comparison

| Flag | Description |
|------|-------------|
| `--baseline PATH` | Compare this scan against a previous JSON export. |
| `--save-baseline PATH` | Write this scan for the next comparison. Written even when changes were found, so a schedule rolls forward. |
| `--diff-output PATH` | Write the comparison to a file; `.json` for JSON, anything else for text. Defaults to stdout. |
| `--fail-on-change` | Exit 4 when the scan differs from the baseline. |

BACnet devices are matched on their device instance rather than their address,
so a controller that moves IP is reported as an address change rather than as
one device disappearing and an unrelated one appearing. Present values are not
compared — they differ on every scan and would bury the signal.

### Cross-subnet discovery

| Flag | Description |
|------|-------------|
| `--bbmd IP` | Register as a Foreign Device with this BBMD and send Who-Is through it. Discovers subnets the scanner cannot broadcast to. |
| `--bbmd-ttl SECONDS` | Registration lease, default 60. Renewed automatically during long scans. |

Without `--bbmd`, discovery only sees the scanner's own subnet: a Who-Is is a
broadcast and broadcasts do not cross a router. If registration fails the
BACnet pass is skipped rather than quietly falling back to a local broadcast,
which would report an empty network and look like a clean result.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed (may be zero devices) |
| 1 | Invalid arguments |
| 2 | Interrupted via Ctrl-C / SIGINT |
| 3 | Internal error (see log) |
| 4 | Scan completed but differed from the baseline (`--fail-on-change` only) |

## Examples

### Quick discovery

```bash
python -m hvac_scanner.cli 192.168.1.0/24
```

### Full scan with exports

```bash
python -m hvac_scanner.cli 10.0.0.0/24 \
    --json scan.json \
    --csv  scan.csv
```

### BACnet-only, conservative rate limiting

```bash
python -m hvac_scanner.cli 192.168.5.0/24 \
    --bacnet-only \
    --rate-limit 50 \
    --timeout 8
```

Good default for buildings with small JACEs, UC400s, FECs, or BASRT routers
that will rate-limit or crash under a firehose of RPM requests.

### Silent scheduled run

```bash
python -m hvac_scanner.cli 192.168.5.0/24 \
    --json /var/log/bas-scan-$(date +%Y%m%d).json \
    --quiet
```

### Nightly change monitoring

The case the baseline flags exist for: run unattended, stay silent when
nothing moved, and produce a report when something did.

```bash
python -m hvac_scanner.cli 10.0.0.0/24 \
    --baseline C:\\BAS\\baseline.json \
    --save-baseline C:\\BAS\\baseline.json \
    --diff-output C:\\BAS\\changes.txt \
    --fail-on-change --quiet --print none
```

Exit code 4 means the network differs from last night. In Task Scheduler, set
the action's "Restart on failure" off and use the exit code to drive whatever
alerting you already have; `changes.txt` holds the detail. Because
`--save-baseline` writes the same path it compared against, each run reports
that night's delta rather than repeating the same drift forever.

The first run has no baseline to compare against; create one with a plain
`--save-baseline` and no `--baseline`.

### Scanning several buildings from one host

```bash
python -m hvac_scanner.cli 10.20.0.0/24 --bbmd 10.20.0.1 --rate-limit 50
```

The target list still bounds which devices are deep-scanned; `--bbmd` only
changes how the Who-Is gets there.

### Piping table output

```bash
python -m hvac_scanner.cli 10.0.0.0/24 --print table --quiet
```

## Scheduling

### Windows Task Scheduler

Save the following to `bas-scan-task.xml` and import with
`schtasks /Create /XML bas-scan-task.xml /TN "HVAC-Scan-Daily"`.

Edit the `Arguments` line (network, output path) and the installation path
under `Command` before importing.

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Nightly HVAC/BAS network discovery audit</Description>
    <Author>HVAC-Network-Scanner</Author>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-01-01T02:30:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Python312\python.exe</Command>
      <Arguments>-m hvac_scanner.cli 192.168.5.0/24 --json C:\Audits\bas-scan.json --rate-limit 50 --quiet</Arguments>
      <WorkingDirectory>C:\Users\JamesCupps\src\HVAC-Network-Scanner</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
```

The `ExecutionTimeLimit` of `PT2H` (two hours) is a safety bound — a full
/24 scan with deep reads against BACnet and Modbus finishes in well under
that on a normal BAS network.

### cron (Linux)

```cron
# Daily at 02:30 — discover devices and save to timestamped JSON
30 2 * * * /usr/bin/python3 -m hvac_scanner.cli 192.168.5.0/24 \
    --json /var/log/bas-scan-$(date +\%Y\%m\%d).json \
    --rate-limit 50 --quiet
```

Paths and the cron user running this need write access to the output
directory. `--quiet` keeps cron from emailing on every run.

## Chaining with other tools

JSON output is designed to be consumable by other tools. Example with `jq`:

```bash
# List all Trane controllers on the network
python -m hvac_scanner.cli 192.168.5.0/24 --json - --print none \
    | jq '.devices[] | select(.vendor_id == 2)'

# Get just the IPs of devices with default credentials exposed
python -m hvac_scanner.cli 192.168.5.0/24 --json scan.json --print none \
    && jq -r '.devices[] | select(.default_creds != "") | .ip' scan.json
```

(Writing JSON to `-` is a future enhancement — for now use an actual file path
and read back.)
