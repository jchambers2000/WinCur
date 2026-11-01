[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^WinCur-1\.0\.0-[A-Za-z0-9._-]+$')]
    [string]$CandidateName,
    [Parameter(Mandatory = $true)]
    [switch]$ConfirmValidated
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    if (-not $ConfirmValidated) {
        throw "Promotion requires -ConfirmValidated after disposable-VM acceptance testing."
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw "WinCur Windows candidates must be promoted on Windows."
    }

    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    $windowsRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "artifacts\windows"))
    $candidatesRoot = [IO.Path]::GetFullPath((Join-Path $windowsRoot "candidates"))
    $currentRoot = [IO.Path]::GetFullPath((Join-Path $windowsRoot "current"))
    $archiveRoot = [IO.Path]::GetFullPath((Join-Path $windowsRoot "archive"))
    foreach ($root in @($candidatesRoot, $currentRoot, $archiveRoot)) {
        if (-not $root.StartsWith($windowsRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Artifact target escaped artifacts\windows: $root"
        }
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            New-Item -ItemType Directory -Path $root | Out-Null
        }
    }

    $candidate = [IO.Path]::GetFullPath((Join-Path $candidatesRoot $CandidateName))
    if ((Split-Path -Parent $candidate) -ne $candidatesRoot -or -not (Test-Path -LiteralPath $candidate -PathType Container)) {
        throw "Candidate must be an existing direct child of artifacts\windows\candidates: $CandidateName"
    }
    $candidateCurrent = Join-Path $currentRoot $CandidateName
    $candidateArchive = Join-Path $archiveRoot $CandidateName
    if (Test-Path -LiteralPath $candidateCurrent) { throw "Current already contains $CandidateName; nothing was changed." }
    if (Test-Path -LiteralPath $candidateArchive) { throw "Archive already contains $CandidateName; nothing was changed." }

    $manifestPath = Join-Path $candidate "BUILD_MANIFEST.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "Candidate manifest is missing: $manifestPath" }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.application_version -ne "1.0.0" -or $manifest.scoring_policy -ne "2.1" -or -not $manifest.build_id) {
        throw "Candidate manifest version, scoring policy, or build identifier is invalid."
    }
    if ($CandidateName -ne "WinCur-1.0.0-$($manifest.build_id)") {
        throw "Candidate directory name does not match manifest build identifier '$($manifest.build_id)'."
    }
    if ($manifest.smoke_test -ne "Passed") {
        throw "Candidate packaging smoke test is not recorded as passed."
    }

    $distribution = Join-Path $candidate "dist\WinCur"
    $verifier = Join-Path $PSScriptRoot "verify_windows_dist.ps1"
    & $verifier -DistributionPath $distribution -ExpectedBuildId $manifest.build_id
    if ($LASTEXITCODE -ne 0) { throw "Independent candidate distribution verification failed." }

    $currentPackages = @(Get-ChildItem -LiteralPath $currentRoot -Directory)
    if ($currentPackages.Count -gt 1) { throw "Current contains more than one package; review it before promotion." }
    $previous = if ($currentPackages.Count -eq 1) { $currentPackages[0] } else { $null }
    if ($previous -and (Test-Path -LiteralPath (Join-Path $archiveRoot $previous.Name))) {
        throw "Archive already contains the current package '$($previous.Name)'; promotion will not overwrite it."
    }

    $description = "archive the current package and promote validated candidate $CandidateName"
    if (-not $PSCmdlet.ShouldProcess($windowsRoot, $description)) {
        Write-Host "Promotion was not performed."
        exit 0
    }

    $archivedPrevious = $false
    try {
        if ($previous) {
            Move-Item -LiteralPath $previous.FullName -Destination $archiveRoot
            $archivedPrevious = $true
        }
        Move-Item -LiteralPath $candidate -Destination $currentRoot
    } catch {
        if ($archivedPrevious -and -not (Test-Path -LiteralPath $previous.FullName) -and -not (Test-Path -LiteralPath (Join-Path $currentRoot $previous.Name))) {
            Move-Item -LiteralPath (Join-Path $archiveRoot $previous.Name) -Destination $currentRoot
        }
        throw
    }

    Write-Host "Validated candidate promoted: $CandidateName" -ForegroundColor Green
    if ($previous) { Write-Host "Previous current package archived: $($previous.Name)" }
    Write-Host "No package was overwritten or deleted."
    exit 0
} catch {
    Write-Error "WinCur candidate promotion failed: $($_.Exception.Message)"
    Write-Error "No automatic fallback candidate will be promoted. Review current, candidates, and archive before retrying."
    exit 1
}
