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
| `--max-objects N` | `500` | Cap on the number of BACnet objects enumerated per device during deep scan. |
| `--no-rpm` | off | Disable `ReadPropertyMultiple`. Use if a specific device misbehaves with RPM requests. |

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
| `--print FORMAT` | Stdout: `summary` (default), `table`, `json`, `none`. |
| `--quiet` / `-q` | Suppress progress log on stderr. |
| `--verbose` / `-v` | Enable DEBUG logging. |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed (may be zero devices) |
| 1 | Invalid arguments |
| 2 | Interrupted via Ctrl-C / SIGINT |
| 3 | Internal error (see log) |

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
