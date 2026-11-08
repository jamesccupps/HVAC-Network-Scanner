# Update a copy of the scanner to dist\HVACNetworkScanner.exe for real.
#
# The old copy is the newest published release older than this build that has
# an updater (a latest.json asset). Until there is one -- 2.10.0 is the first
# -- the build updates itself: the old copy is dist's own exe, and the release
# claims the next patch version. Either way the old copy is started, then its
# own updater code (its source, from its tag, or this tree) checks a release
# folder holding dist's exe and a latest.json signed with a throwaway key,
# downloads, verifies and applies, and the old copy is ended the way it ends
# itself. The test checks that the exe was replaced, this build started with
# --updated and cleaned up after itself, and the settings file was left alone.
#
# Then the way 2.13 installs by itself: this build's updater, the old copy
# being this build, installs as the window closes (--no-restart). The exe must
# be replaced, nothing started after, and the .old copy gone.
#
# CI runs it after building the exe (ci.yml). On a PC of your own it works in
# a temporary folder with its own settings folder; the scanner's window opens
# twice while it runs, and it never touches a copy running from elsewhere.
#
#   pwsh packaging/test_update.ps1 [-From X.Y.Z|self] [-Python python]
param(
    [string]$From = '',
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'      # Windows PowerShell's progress bar slows downloads
$repo = 'jamesccupps/HVAC-Network-Scanner'
$exeName = 'HVACNetworkScanner.exe'
$root = Split-Path $PSScriptRoot
$helper = Join-Path $PSScriptRoot 'update_test_helper.py'
$built = Join-Path $root "dist\$exeName"
if (-not (Test-Path $built)) { throw "build the exe first: $built is missing" }

# On a runner, also as an annotation: job logs need a signed-in session, annotations don't.
function Write-Result([string]$level, [string]$message) {
    $message
    if ($env:GITHUB_ACTIONS) { "::${level} title=Update test::$($message -replace "`r?`n", '%0A')" }
}

$version = "$(& $Python $helper version)".Trim()
if (-not $From) {
    $From = "$(& $Python $helper previous)".Trim()
    # Nothing printed means no older release has an updater: the build tests
    # updating itself. A failure must not look like that.
    if ($LASTEXITCODE -ne 0) { throw "couldn't ask GitHub which release came before $version" }
}
# Only the question above needs the token; the old copy's code never sees it.
Remove-Item Env:\GITHUB_TOKEN -ErrorAction SilentlyContinue
if (-not $From) { $From = 'self' }
$self = $From -eq 'self'
if ($self) {
    $p = $version.Split('.')
    $offered = "$($p[0]).$($p[1]).$([int]$p[2] + 1)"
    "no published release older than $version has an updater: updating this build to itself, offered as $offered"
} else {
    $offered = $version
    "updating $From to this build, $version"
}

# Not GetTempPath() on a runner: it can be an 8.3 short path, and processes report long ones.
$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$work = Join-Path $temp "hvac-updtest-$PID"
$release = Join-Path $work 'release'
$appDir = Join-Path $work 'app'
$appExe = Join-Path $appDir $exeName
$appData = Join-Path $work 'appdata'
$settingsDir = Join-Path $appData 'HVACNetworkScanner'
$log = Join-Path $settingsDir 'update.log'
$staging = Join-Path ([IO.Path]::GetTempPath()) "HVACNetworkScanner-update-$offered"
$vp = $version.Split('.')
$next = "$($vp[0]).$($vp[1]).$([int]$vp[2] + 1)"
$staging2 = Join-Path ([IO.Path]::GetTempPath()) "HVACNetworkScanner-update-$next"
New-Item -ItemType Directory -Force $release, $appDir, $settingsDir | Out-Null
Copy-Item $built $release
$key = "$(& $Python $helper sign $release $offered)".Trim()
if ($LASTEXITCODE -ne 0 -or -not $key) { throw "couldn't sign the test release" }

# GitHub answers a download with a 5xx now and then. No answer, a 5xx or a 429
# is tried again, further apart each time; any other status (a 404: the file
# isn't there) fails at once.
function Save-Url([string]$url, [string]$out, [int]$tries = 4) {
    for ($try = 1; ; $try++) {
        try {
            Invoke-WebRequest -UseBasicParsing $url -OutFile $out
            return
        } catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            $transient = $code -eq 0 -or $code -ge 500 -or $code -eq 429
            if (-not $transient -or $try -ge $tries) { throw }
            Write-Host "  $url failed ($($_.Exception.Message)); trying again in $(10 * $try) s"
            Start-Sleep -Seconds (10 * $try)
        }
    }
}

if ($self) {
    Copy-Item $built $appExe
    $oldSource = $root
    $oldVersion = $version
} else {
    Save-Url "https://github.com/$repo/releases/download/v$From/$exeName" $appExe
    Save-Url "https://github.com/$repo/archive/refs/tags/v$From.zip" "$work\source.zip"
    Expand-Archive "$work\source.zip" "$work\source"
    $oldSource = (Get-ChildItem "$work\source" -Directory | Select-Object -First 1).FullName
    $oldVersion = $From
}

function Wait-Until([scriptblock]$done, [int]$seconds, [string]$what) {
    $end = (Get-Date).AddSeconds($seconds)
    while (-not (& $done)) {
        if ((Get-Date) -gt $end) { throw "timed out after $seconds s waiting for $what" }
        Start-Sleep -Milliseconds 500
    }
}
function Test-Log([string]$text) {
    (Test-Path $log) -and (Select-String -Path $log -Pattern $text -SimpleMatch -Quiet)
}
# Copies running from this test's folders. The one-file exe is a loader that
# runs the app as its child, so a copy is a process whose parent isn't one.
function Get-Processes {
    @(Get-CimInstance Win32_Process -Filter "Name = '$exeName'" | Where-Object {
        $_.ExecutablePath -and (
            $_.ExecutablePath.StartsWith($work, [StringComparison]::OrdinalIgnoreCase) -or
            $_.ExecutablePath.StartsWith($staging, [StringComparison]::OrdinalIgnoreCase) -or
            $_.ExecutablePath.StartsWith($staging2, [StringComparison]::OrdinalIgnoreCase)) })
}
function Get-Copies([string]$exe) {
    $all = Get-Processes
    $ids = @($all | ForEach-Object { $_.ProcessId })
    @($all | Where-Object { $_.ExecutablePath -eq $exe -and $ids -notcontains $_.ParentProcessId })
}
function Stop-Copies {
    Get-Processes | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 1
}
function Show-Log {
    if (Test-Path $log) { "--- update.log"; Get-Content $log -Tail 20 }
}

# The old copy's settings, as a user would have them, with no update check of
# its own (it would ask GitHub, not the test release). Each copy finds them
# through APPDATA, which this script points at its own folder.
$settings = Join-Path $settingsDir 'settings.json'
[IO.File]::WriteAllText($settings, '{"check_updates": false}', (New-Object Text.UTF8Encoding $false))
$hash = (Get-FileHash $settings).Hash
# When the old copy is the build itself the bytes can't tell the two apart,
# and NTFS hands a replaced file's creation time on to its successor; the
# modified time can: the swap copies the download's, so date the old one back.
(Get-Item $appExe).LastWriteTimeUtc = [datetime]'2000-01-01'
$started = (Get-Date).ToUniversalTime().AddSeconds(-2)
$savedAppData = $env:APPDATA
$env:APPDATA = $appData

try {
    $old = Start-Process $appExe -WorkingDirectory $appDir -PassThru
    Start-Sleep -Seconds 8                    # the one-file exe unpacks itself, then opens its window
    if ($old.HasExited) { throw "the old copy exited with $($old.ExitCode)" }
    & $Python $helper drive $oldSource $release $appExe $old.Id $key
    if ($LASTEXITCODE -ne 0) { throw "the $oldVersion updater failed" }

    Wait-Until { Test-Log 'update: done' } 120 'the swap'
    Wait-Until { Test-Log "update: $version started" } 120 "$version to start after the update"
    if (Test-Log 'update: failed') { throw "the update failed and the old version was put back" }
    $item = Get-Item $appExe
    if ($item.VersionInfo.ProductVersion -ne $version) {
        throw "the exe is $($item.VersionInfo.ProductVersion) after the update, not $version"
    }
    if ($item.LastWriteTimeUtc -lt $started) { throw "the exe wasn't replaced" }
    if ((Get-FileHash $appExe).Hash -ne (Get-FileHash $built).Hash) { throw "the exe isn't the build" }
    # @(): a function's one-item array comes back as the item, and a CIM
    # object's .Count isn't 1 in Windows PowerShell.
    Wait-Until { @(Get-Copies $appExe).Count -eq 1 } 30 'one copy running'
    Wait-Until { -not (Test-Path "$appExe.old") } 30 'the old exe to be removed'
    if ((Get-FileHash $settings).Hash -ne $hash) { throw "the settings file changed" }
    Show-Log
    Write-Result notice "ok: $oldVersion updated itself to $version"
} catch {
    Show-Log
    Write-Result error "$oldVersion to ${version}: $($_.Exception.Message)"
    throw
} finally {
    Stop-Copies
    $env:APPDATA = $savedAppData
}

# Installing as the window closes.
$release2 = Join-Path $work 'release-close'
$app2Dir = Join-Path $work 'app-close'
$app2Exe = Join-Path $app2Dir $exeName
New-Item -ItemType Directory -Force $release2, $app2Dir | Out-Null
Copy-Item $built $release2
Copy-Item $built $app2Exe
$key2 = "$(& $Python $helper sign $release2 $next)".Trim()
if ($LASTEXITCODE -ne 0 -or -not $key2) { throw "couldn't sign the second test release" }
(Get-Item $app2Exe).LastWriteTimeUtc = [datetime]'2000-01-01'
$started2 = (Get-Date).ToUniversalTime().AddSeconds(-2)
$env:APPDATA = $appData
try {
    $old2 = Start-Process $app2Exe -WorkingDirectory $app2Dir -PassThru
    Start-Sleep -Seconds 8
    if ($old2.HasExited) { throw "the copy to close exited with $($old2.ExitCode)" }
    & $Python $helper drive $root $release2 $app2Exe $old2.Id $key2 close
    if ($LASTEXITCODE -ne 0) { throw "the $version updater failed on close" }
    Wait-Until { Test-Log 'it opens next time' } 120 'the swap on close'
    if (Test-Log 'update: failed') { throw "the update on close failed" }
    $item = Get-Item $app2Exe
    if ($item.LastWriteTimeUtc -lt $started2) { throw "the exe wasn't replaced on close" }
    if ((Get-FileHash $app2Exe).Hash -ne (Get-FileHash $built).Hash) { throw "the exe on close isn't the build" }
    Wait-Until { @(Get-Processes).Count -eq 0 } 30 'the swap to end'
    Start-Sleep -Seconds 5
    if (@(Get-Processes).Count -ne 0) { throw "something started after the update on close" }
    if (Test-Path "$app2Exe.old") { throw "the .old exe was left after the update on close" }
    if ((Get-FileHash $settings).Hash -ne $hash) { throw "the settings file changed on close" }
    Show-Log
    Write-Result notice "ok: $version installed an update as its window closed"
} catch {
    Show-Log
    Write-Result error "install on close: $($_.Exception.Message)"
    throw
} finally {
    Stop-Copies
    $env:APPDATA = $savedAppData
}
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $staging2 -ErrorAction SilentlyContinue
"update ok: $oldVersion to $version, and on close"
