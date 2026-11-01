[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DistributionPath,
    [string]$ExpectedBuildId = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw "A WinCur Windows distribution must be verified on Windows."
    }
    $root = [IO.Path]::GetFullPath($DistributionPath)
    $executable = Join-Path $root "WinCur.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "WinCur.exe was not found in $root"
    }
    $scoring = Get-ChildItem -LiteralPath $root -Filter "scoring_config.json" -File -Recurse |
        Where-Object { $_.FullName -match '[\\/]wincur[\\/]scoring_config\.json$' } |
        Select-Object -First 1
    if (-not $scoring) { throw "The bundled scoring configuration is missing." }
    $qwindows = Get-ChildItem -LiteralPath $root -Filter "qwindows.dll" -File -Recurse | Select-Object -First 1
    if (-not $qwindows) { throw "The Qt Windows platform plugin is missing." }
    $portrait = Get-ChildItem -LiteralPath $root -Filter "wincur_portrait.png" -File -Recurse | Select-Object -First 1
    $icon = Get-ChildItem -LiteralPath $root -Filter "wincur.ico" -File -Recurse | Select-Object -First 1
    if (-not $portrait -or -not $icon) { throw "Approved portrait or multi-size icon resource is missing." }

    $details = (Get-Item -LiteralPath $executable).VersionInfo
    if ($details.ProductName -ne "WinCur" -or $details.FileVersion -notlike "1.0.0.0*" -or $details.ProductVersion -notlike "1.0.0*") {
        throw "Windows executable metadata is inconsistent with WinCur 1.0.0 RC4."
    }

    $probeOutput = Join-Path ([IO.Path]::GetTempPath()) "wincur-packaging-probe-$([Guid]::NewGuid().ToString('N')).json"
    try {
        $arguments = "--packaging-probe `"$probeOutput`""
        $probe = Start-Process -FilePath $executable -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
        if ($probe.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probeOutput -PathType Leaf)) {
            throw "The non-security packaging probe failed with exit code $($probe.ExitCode)."
        }
        $result = Get-Content -LiteralPath $probeOutput -Raw | ConvertFrom-Json
        $buildIdProperty = $result.PSObject.Properties["build_id"]
        $reportedBuildId = if ($buildIdProperty) { [string]$buildIdProperty.Value } else { "" }
        if (-not $result.ok -or -not $result.frozen -or $result.application_version -ne "1.0.0" -or $result.scoring_policy -ne "2.1" -or $result.icon_images -lt 9) {
            throw "The non-security packaging probe returned inconsistent data."
        }
        if ($ExpectedBuildId -and $reportedBuildId -ne $ExpectedBuildId) {
            throw "The packaged build identifier '$reportedBuildId' does not match expected candidate '$ExpectedBuildId'."
        }
    } finally {
        if (Test-Path -LiteralPath $probeOutput) { Remove-Item -LiteralPath $probeOutput -Force }
    }

    Write-Host "WinCur 1.0.0 RC4 distribution verification passed." -ForegroundColor Green
    Write-Host "Executable: $executable"
    Write-Host "Scoring configuration: $($scoring.FullName)"
    Write-Host "Qt platform plugin: $($qwindows.FullName)"
    Write-Host "Portrait resource: $($portrait.FullName)"
    Write-Host "Icon resource: $($icon.FullName)"
    if ($reportedBuildId) { Write-Host "Build identifier: $reportedBuildId" }
    Write-Host "No assessment or remediation was run."
    exit 0
} catch {
    Write-Error "WinCur distribution verification failed: $($_.Exception.Message)"
    exit 1
}
