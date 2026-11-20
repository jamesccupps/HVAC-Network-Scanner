# Install the ArtifactSigning module that packaging/authenticode.ps1 imports, from the PowerShell
# Gallery, pinned by its package's SHA-256. Install-Module pins a version only, and on 2026-11-16 it
# stopped a release on a corrupt download ("End of Central Directory record could not be found")
# until the job was run again. This tries three times and installs nothing that doesn't match the
# hash. Every .psd1 and .psm1 in 0.1.8 is Authenticode-signed by Microsoft; that is checked too.
#
# CI's authenticode job runs it before signing. To move to a new version, take the hash from a
# download whose module files check out as Microsoft-signed, and change $Version in authenticode.ps1
# with it.
#
#   pwsh packaging/install_artifactsigning.ps1 [-ModulesDir <dir>]
param([string]$ModulesDir = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'PowerShell\Modules'))
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Name = 'ArtifactSigning'
$Version = '0.1.8'
$Sha256 = '3221344b8c627915d3870f23e80816f31a5d8c2bae1d7c0cdd6c9652f6c4e089'

$url = "https://www.powershellgallery.com/api/v2/package/$Name/$Version"
$pkg = Join-Path ([IO.Path]::GetTempPath()) "$Name.$Version.nupkg"
for ($try = 1; ; $try++) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $pkg -UseBasicParsing
        $got = (Get-FileHash -LiteralPath $pkg -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($got -eq $Sha256) { break }
        Write-Warning "try ${try}: $Name $Version came down with SHA-256 $got, not $Sha256"
    } catch {
        Write-Warning "try ${try}: $Name $Version did not download: $_"
    }
    if ($try -ge 3) { throw "$Name ${Version}: no download matching the pinned SHA-256 after $try tries" }
    Start-Sleep -Seconds (10 * $try)
}

$dest = Join-Path $ModulesDir "$Name\$Version"
if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::ExtractToDirectory($pkg, $dest)
Remove-Item -LiteralPath $pkg -Force
# NuGet's own files, which Install-Module leaves out as well.
foreach ($meta in '_rels', 'package', '[Content_Types].xml', "$Name.nuspec", '.signature.p7s') {
    $p = Join-Path $dest $meta
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
}

$code = @(Get-ChildItem -LiteralPath $dest -Recurse -File | Where-Object { $_.Extension -in '.psd1', '.psm1' })
if ($code.Count -eq 0) { throw "$Name ${Version}: no module files in the package" }
$bad = @($code | Where-Object {
    $s = Get-AuthenticodeSignature -LiteralPath $_.FullName
    $s.Status -ne 'Valid' -or -not $s.SignerCertificate -or
        $s.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,'
})
if ($bad.Count) { throw "not validly signed by Microsoft: $($bad.FullName -join ', ')" }
"installed $Name $Version ($($code.Count) Microsoft-signed module files) to $dest"
