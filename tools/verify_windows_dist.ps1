[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DistributionPath,
    [string]$ExpectedBuildId = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-ThirdPartyNoticePayload {
    param([string]$PayloadRoot)
    $payload = [IO.Path]::GetFullPath($PayloadRoot).TrimEnd('\', '/')
    $manifestPath = Join-Path $payload "NOTICE_MANIFEST.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Third-party notice manifest is missing."
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.qt_version -ne "6.12.0" -or $manifest.pyside_version -ne "6.12.0") {
        throw "Third-party notice manifest version metadata is inconsistent."
    }
    foreach ($entry in $manifest.files) {
        $relative = [string]$entry.path
        if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
            throw "Unsafe third-party notice manifest path: $relative"
        }
        $target = [IO.Path]::GetFullPath((Join-Path $payload $relative))
        if (-not $target.StartsWith($payload + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Third-party notice manifest path escaped its root: $relative"
        }
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
            throw "Required third-party notice file is missing: $relative"
        }
        if ((Get-Item -LiteralPath $target).Length -ne [long]$entry.size -or
            (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne [string]$entry.sha256) {
            throw "Third-party notice file failed integrity validation: $relative"
        }
    }
}

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
    foreach ($excludedQtRuntime in @("Qt6Pdf.dll", "Qt6Qml.dll", "Qt6QmlMeta.dll", "Qt6QmlModels.dll", "Qt6QmlWorkerScript.dll", "Qt6Quick.dll", "Qt6VirtualKeyboard.dll", "qpdf.dll", "qtvirtualkeyboardplugin.dll")) {
        if (Get-ChildItem -LiteralPath $root -Filter $excludedQtRuntime -File -Recurse | Select-Object -First 1) {
            throw "Unused Qt runtime '$excludedQtRuntime' is present in the minimized distribution."
        }
    }
    foreach ($releaseDocument in @("LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md", "README.txt", "validated_toolchain.json", "frozen_dependency_inventory.json", "build_info.json", "licenses\PYTHON-3.14.10-LICENSE.txt", "licenses\third-party\NOTICE_MANIFEST.json", "licenses\third-party\mesa-llvmpipe-11.2.2\NOTICE.txt", "licenses\third-party\microsoft-vc-runtime-2026\NOTICE.txt", "licenses\third-party\pyinstaller-6.22.3\COPYING.txt")) {
        if (-not (Test-Path -LiteralPath (Join-Path $root $releaseDocument) -PathType Leaf)) {
            throw "Required release document '$releaseDocument' is missing."
        }
    }
    Assert-ThirdPartyNoticePayload (Join-Path $root "licenses\third-party")
    $frozenInventory = Get-Content -LiteralPath (Join-Path $root "frozen_dependency_inventory.json") -Raw | ConvertFrom-Json
    $noticeManifest = Join-Path $root "licenses\third-party\NOTICE_MANIFEST.json"
    if ((Get-FileHash -LiteralPath $noticeManifest -Algorithm SHA256).Hash -ne
        [string]$frozenInventory.third_party_notice_payload.manifest_sha256) {
        throw "The third-party notice manifest does not match the frozen dependency inventory."
    }

    $details = (Get-Item -LiteralPath $executable).VersionInfo
    if ($details.ProductName -ne "WinCur" -or $details.FileVersion -notlike "1.0.0.0*" -or $details.ProductVersion -notlike "1.0.0*") {
        throw "Windows executable metadata is inconsistent with WinCur 1.0.0."
    }

    foreach ($removedMode in @("--helper-action", "--helper-rollback", "--helper-preview", "--helper-scan")) {
        $removed = Start-Process -FilePath $executable -ArgumentList $removedMode -WindowStyle Hidden -Wait -PassThru
        if ($removed.ExitCode -eq 0) {
            throw "Removed command-line mode '$removedMode' was accepted by the assessment-only executable."
        }
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

    Write-Host "WinCur 1.0.0 assessment-only distribution verification passed." -ForegroundColor Green
    Write-Host "Executable: $executable"
    Write-Host "Scoring configuration: $($scoring.FullName)"
    Write-Host "Qt platform plugin: $($qwindows.FullName)"
    Write-Host "Portrait resource: $($portrait.FullName)"
    Write-Host "Icon resource: $($icon.FullName)"
    if ($reportedBuildId) { Write-Host "Build identifier: $reportedBuildId" }
    Write-Host "Removed mutation and elevation command-line modes were rejected."
    Write-Host "No assessment or remediation was run."
    exit 0
} catch {
    Write-Error "WinCur distribution verification failed: $($_.Exception.Message)"
    exit 1
}
