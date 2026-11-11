[CmdletBinding()]
param(
    [string]$Python = "",
    [switch]$SkipSmokeTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param([string]$FilePath, [string[]]$ArgumentList)
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $FilePath $($ArgumentList -join ' ')"
    }
}

function Get-ManifestPath {
    param([string]$BasePath, [string]$TargetPath)
    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/')
    $target = [IO.Path]::GetFullPath($TargetPath)
    if (-not $target.StartsWith($base + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest resource is outside the candidate package: $target"
    }
    return $target.Substring($base.Length + 1).Replace('\', '/')
}

function Assert-ThirdPartyNoticePayload {
    param([string]$PayloadRoot)
    $root = [IO.Path]::GetFullPath($PayloadRoot).TrimEnd('\', '/')
    $manifestPath = Join-Path $root "NOTICE_MANIFEST.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Third-party notice manifest is missing: $manifestPath"
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
        $target = [IO.Path]::GetFullPath((Join-Path $root $relative))
        if (-not $target.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
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
        throw "WinCur Windows distributions must be built on Windows."
    }

    $projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
    $pythonPath = if ($Python) {
        if ([IO.Path]::IsPathRooted($Python)) { [IO.Path]::GetFullPath($Python) }
        else { [IO.Path]::GetFullPath((Join-Path (Get-Location) $Python)) }
    } else {
        Join-Path $projectRoot ".venv\Scripts\python.exe"
    }
    $specPath = Join-Path $projectRoot "WinCur.spec"
    $scoringPath = Join-Path $projectRoot "wincur\scoring_config.json"
    $metadataPath = Join-Path $projectRoot "packaging\windows_version_info.txt"
    $portraitPath = Join-Path $projectRoot "wincur\assets\wincur_portrait.png"
    $iconPath = Join-Path $projectRoot "wincur\assets\wincur.ico"
    $brandHashesPath = Join-Path $projectRoot "wincur\assets\branding_hashes.json"
    $licensePath = Join-Path $projectRoot "LICENSE"
    $noticePath = Join-Path $projectRoot "NOTICE.md"
    $thirdPartyNoticePath = Join-Path $projectRoot "THIRD_PARTY_NOTICES.md"
    $portableReadmePath = Join-Path $projectRoot "packaging\PORTABLE_README.txt"
    $validatedToolchainPath = Join-Path $projectRoot "packaging\validated_toolchain.json"
    $frozenInventoryPath = Join-Path $projectRoot "packaging\frozen_dependency_inventory.json"
    $thirdPartyLicensePayloadPath = Join-Path $projectRoot "packaging\third_party_notices"

    foreach ($required in @($pythonPath, $specPath, $scoringPath, $metadataPath, $portraitPath, $iconPath, $brandHashesPath, $licensePath, $noticePath, $thirdPartyNoticePath, $portableReadmePath, $validatedToolchainPath, $frozenInventoryPath)) {
        if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
            throw "Required build input is missing: $required"
        }
    }
    if (-not (Test-Path -LiteralPath $thirdPartyLicensePayloadPath -PathType Container)) {
        throw "Required third-party notice payload is missing: $thirdPartyLicensePayloadPath"
    }
    Assert-ThirdPartyNoticePayload $thirdPartyLicensePayloadPath
    Push-Location $projectRoot
    try {
        Invoke-Checked $pythonPath @("-c", "import struct,sys; assert sys.version_info >= (3,11); assert struct.calcsize('P') == 8, '64-bit Python is required'")
        Invoke-Checked $pythonPath @("-c", "import PySide6; print('PySide6=' + PySide6.__version__)")
        & $pythonPath -c "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('PyInstaller') else 1)"
        if ($LASTEXITCODE -ne 0) {
            throw "PyInstaller is not installed in the selected environment. Run '$pythonPath -m pip install -r requirements-build.txt' and retry."
        }
        Invoke-Checked $pythonPath @("-c", "import PyInstaller; print('PyInstaller=' + PyInstaller.__version__)")
        $validatedToolchain = Get-Content -LiteralPath $validatedToolchainPath -Raw | ConvertFrom-Json
        $actualPythonVersion = (& $pythonPath -c "import platform; print(platform.python_version())").Trim()
        $actualPySideVersion = (& $pythonPath -c "import PySide6; print(PySide6.__version__)").Trim()
        $actualShibokenVersion = (& $pythonPath -c "import shiboken6; print(shiboken6.__version__)").Trim()
        $actualPyInstallerVersion = (& $pythonPath -c "import PyInstaller; print(PyInstaller.__version__)").Trim()
        if ($actualPythonVersion -ne $validatedToolchain.validated_environment.python -or
            $actualPySideVersion -ne $validatedToolchain.validated_environment.pyside6 -or
            $actualShibokenVersion -ne $validatedToolchain.validated_environment.shiboken6 -or
            $actualPyInstallerVersion -ne $validatedToolchain.validated_environment.pyinstaller) {
            throw "The selected build environment differs from packaging\validated_toolchain.json. Review and revalidate dependency licenses before changing the release toolchain."
        }
        $pythonLicensePath = (& $pythonPath -c "import pathlib,sys; print(pathlib.Path(sys.base_prefix) / 'LICENSE.txt')").Trim()
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonLicensePath -PathType Leaf)) {
            throw "The selected CPython installation does not provide LICENSE.txt; public packaging cannot continue."
        }
        $version = (& $pythonPath -c "from wincur import APP_VERSION; print(APP_VERSION)").Trim()
        if ($LASTEXITCODE -ne 0 -or $version -ne "1.0.0") {
            throw "Expected WinCur application version 1.0.0, received '$version'."
        }
        $approvedHashes = Get-Content -LiteralPath $brandHashesPath -Raw | ConvertFrom-Json
        $portraitHash = (Get-FileHash -LiteralPath $portraitPath -Algorithm SHA256).Hash
        $iconHash = (Get-FileHash -LiteralPath $iconPath -Algorithm SHA256).Hash
        if ($portraitHash -ne $approvedHashes.'wincur_portrait.png' -or $iconHash -ne $approvedHashes.'wincur.ico') {
            throw "Approved branding integrity validation failed. The build will not regenerate or substitute branding assets."
        }

        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $buildId = "$stamp-$PID-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        $builtUtc = [DateTime]::UtcNow.ToString("o")
        $candidatesRoot = Join-Path $projectRoot "artifacts\windows\candidates"
        New-Item -ItemType Directory -Path $candidatesRoot -Force | Out-Null
        $releaseRoot = Join-Path $candidatesRoot "WinCur-$version-$buildId"
        if (Test-Path -LiteralPath $releaseRoot) {
            throw "The unique candidate output already exists and will not be overwritten: $releaseRoot"
        }
        $distRoot = Join-Path $releaseRoot "dist"
        $workRoot = Join-Path $releaseRoot "work"
        New-Item -ItemType Directory -Path $distRoot, $workRoot -Force | Out-Null
        $buildInfoPath = Join-Path $releaseRoot "build_info.json"
        [ordered]@{ build_id = $buildId; built_utc = $builtUtc } |
            ConvertTo-Json | Set-Content -LiteralPath $buildInfoPath -Encoding UTF8

        Write-Host "Building isolated WinCur $version candidate $buildId..."
        $previousBuildInfoPath = [Environment]::GetEnvironmentVariable("WINCUR_BUILD_INFO_PATH", "Process")
        try {
            [Environment]::SetEnvironmentVariable("WINCUR_BUILD_INFO_PATH", $buildInfoPath, "Process")
            Invoke-Checked $pythonPath @(
                "-m", "PyInstaller", "--noconfirm",
                "--distpath", $distRoot,
                "--workpath", $workRoot,
                $specPath
            )
        } finally {
            [Environment]::SetEnvironmentVariable("WINCUR_BUILD_INFO_PATH", $previousBuildInfoPath, "Process")
        }

        $applicationRoot = Join-Path $distRoot "WinCur"
        $executable = Join-Path $applicationRoot "WinCur.exe"
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
            throw "PyInstaller completed without producing the expected executable: $executable"
        }

        $licenseOutput = Join-Path $applicationRoot "licenses"
        New-Item -ItemType Directory -Path $licenseOutput | Out-Null
        Copy-Item -LiteralPath $licensePath -Destination (Join-Path $applicationRoot "LICENSE")
        Copy-Item -LiteralPath $noticePath -Destination (Join-Path $applicationRoot "NOTICE.md")
        Copy-Item -LiteralPath $thirdPartyNoticePath -Destination (Join-Path $applicationRoot "THIRD_PARTY_NOTICES.md")
        Copy-Item -LiteralPath $portableReadmePath -Destination (Join-Path $applicationRoot "README.txt")
        Copy-Item -LiteralPath $validatedToolchainPath -Destination (Join-Path $applicationRoot "validated_toolchain.json")
        Copy-Item -LiteralPath $frozenInventoryPath -Destination (Join-Path $applicationRoot "frozen_dependency_inventory.json")
        Copy-Item -LiteralPath $buildInfoPath -Destination (Join-Path $applicationRoot "build_info.json")
        Copy-Item -LiteralPath $pythonLicensePath -Destination (Join-Path $licenseOutput "PYTHON-3.14.10-LICENSE.txt")
        Copy-Item -LiteralPath $thirdPartyLicensePayloadPath -Destination (Join-Path $licenseOutput "third-party") -Recurse
        Assert-ThirdPartyNoticePayload (Join-Path $licenseOutput "third-party")
        $frozenInventory = Get-Content -LiteralPath $frozenInventoryPath -Raw | ConvertFrom-Json
        $noticeManifestOutput = Join-Path $licenseOutput "third-party\NOTICE_MANIFEST.json"
        if ((Get-FileHash -LiteralPath $noticeManifestOutput -Algorithm SHA256).Hash -ne
            [string]$frozenInventory.third_party_notice_payload.manifest_sha256) {
            throw "The staged third-party notice manifest does not match the frozen dependency inventory."
        }

        $archiveListing = & $pythonPath -m PyInstaller.utils.cliutils.archive_viewer --list --recursive --brief $executable 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "The PyInstaller archive could not be inspected for assessment-only release boundaries."
        }
        $forbiddenModules = @("wincur.helper", "wincur.hardening", "wincur.privileges")
        foreach ($forbiddenModule in $forbiddenModules) {
            if ($archiveListing -match "(?m)^\s*$([Regex]::Escape($forbiddenModule))\s*$") {
                throw "The assessment-only distribution unexpectedly contains forbidden module '$forbiddenModule'."
            }
        }
        $excludedQtRuntime = @(
            "PySide6\Qt6Pdf.dll",
            "PySide6\Qt6Qml.dll",
            "PySide6\Qt6QmlMeta.dll",
            "PySide6\Qt6QmlModels.dll",
            "PySide6\Qt6QmlWorkerScript.dll",
            "PySide6\Qt6Quick.dll",
            "PySide6\Qt6VirtualKeyboard.dll",
            "PySide6\plugins\imageformats\qpdf.dll",
            "PySide6\plugins\platforminputcontexts\qtvirtualkeyboardplugin.dll"
        )
        foreach ($relativeQtPath in $excludedQtRuntime) {
            if (Test-Path -LiteralPath (Join-Path $applicationRoot $relativeQtPath)) {
                throw "The distribution unexpectedly contains unused Qt runtime '$relativeQtPath'."
            }
        }

        $bundledScoring = Get-ChildItem -LiteralPath $applicationRoot -Filter "scoring_config.json" -File -Recurse |
            Where-Object { $_.FullName -match '[\\/]wincur[\\/]scoring_config\.json$' } |
            Select-Object -First 1
        if (-not $bundledScoring) {
            throw "The distribution is incomplete: wincur\scoring_config.json was not bundled."
        }
        $qtPlatform = Get-ChildItem -LiteralPath $applicationRoot -Filter "qwindows.dll" -File -Recurse | Select-Object -First 1
        if (-not $qtPlatform) {
            throw "The distribution is incomplete: the PySide6 Windows platform plugin qwindows.dll is missing."
        }
        $bundledPortrait = Get-ChildItem -LiteralPath $applicationRoot -Filter "wincur_portrait.png" -File -Recurse | Select-Object -First 1
        $bundledIcon = Get-ChildItem -LiteralPath $applicationRoot -Filter "wincur.ico" -File -Recurse | Select-Object -First 1
        $bundledBuildInfo = Get-ChildItem -LiteralPath $applicationRoot -Filter "build_info.json" -File -Recurse | Select-Object -First 1
        if (-not $bundledPortrait -or -not $bundledIcon -or -not $bundledBuildInfo) {
            throw "The distribution is incomplete: approved branding and generated build information are required."
        }
        foreach ($releaseDocument in @("LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md", "README.txt", "validated_toolchain.json", "frozen_dependency_inventory.json", "build_info.json", "licenses\PYTHON-3.14.10-LICENSE.txt", "licenses\third-party\NOTICE_MANIFEST.json", "licenses\third-party\mesa-llvmpipe-11.2.2\NOTICE.txt", "licenses\third-party\microsoft-vc-runtime-2026\NOTICE.txt", "licenses\third-party\pyinstaller-6.22.3\COPYING.txt")) {
            if (-not (Test-Path -LiteralPath (Join-Path $applicationRoot $releaseDocument) -PathType Leaf)) {
                throw "The distribution is incomplete: required release document '$releaseDocument' is missing."
            }
        }

        $versionInfo = (Get-Item -LiteralPath $executable).VersionInfo
        if ($versionInfo.ProductName -ne "WinCur" -or $versionInfo.FileDescription -ne "WinCur Windows Security Assessment" -or $versionInfo.FileVersion -notlike "1.0.0.0*" -or $versionInfo.ProductVersion -notlike "1.0.0*") {
            throw "Executable version metadata is inconsistent. ProductName='$($versionInfo.ProductName)', FileDescription='$($versionInfo.FileDescription)', FileVersion='$($versionInfo.FileVersion)', ProductVersion='$($versionInfo.ProductVersion)'."
        }

        $probeOutput = Join-Path $releaseRoot "packaging-probe.json"
        if (-not $SkipSmokeTest) {
            $probeArguments = "--packaging-probe `"$probeOutput`""
            $probe = Start-Process -FilePath $executable -ArgumentList $probeArguments -WindowStyle Hidden -Wait -PassThru
            if ($probe.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probeOutput -PathType Leaf)) {
                throw "The packaged resource smoke test failed with exit code $($probe.ExitCode)."
            }
            $probeData = Get-Content -LiteralPath $probeOutput -Raw | ConvertFrom-Json
            if (-not $probeData.ok -or -not $probeData.frozen -or $probeData.application_version -ne $version -or $probeData.build_id -ne $buildId -or $probeData.scoring_policy -ne "2.1" -or $probeData.icon_images -lt 9 -or $probeData.portrait_sha256 -ne $portraitHash -or $probeData.icon_sha256 -ne $iconHash) {
                throw "The packaged resource smoke test returned inconsistent metadata."
            }
        }

        $manifest = [ordered]@{
            application_version = $version
            build_id = $buildId
            scoring_policy = "2.1"
            format = "onedir"
            built_utc = $builtUtc
            python = (& $pythonPath --version 2>&1 | Out-String).Trim()
            pyside6 = $actualPySideVersion
            shiboken6 = $actualShibokenVersion
            pyinstaller = $actualPyInstallerVersion
            executable = Get-ManifestPath $releaseRoot $executable
            executable_sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
            scoring_config = Get-ManifestPath $releaseRoot $bundledScoring.FullName
            scoring_config_sha256 = (Get-FileHash -LiteralPath $bundledScoring.FullName -Algorithm SHA256).Hash
            portrait = Get-ManifestPath $releaseRoot $bundledPortrait.FullName
            portrait_sha256 = (Get-FileHash -LiteralPath $bundledPortrait.FullName -Algorithm SHA256).Hash
            icon = Get-ManifestPath $releaseRoot $bundledIcon.FullName
            icon_sha256 = (Get-FileHash -LiteralPath $bundledIcon.FullName -Algorithm SHA256).Hash
            build_info = Get-ManifestPath $releaseRoot $bundledBuildInfo.FullName
            build_info_sha256 = (Get-FileHash -LiteralPath $bundledBuildInfo.FullName -Algorithm SHA256).Hash
            qt_platform_plugin = Get-ManifestPath $releaseRoot $qtPlatform.FullName
            smoke_test = if ($SkipSmokeTest) { "Skipped by explicit option" } else { "Passed" }
            assessment_only_archive_check = "Passed"
            unused_qt_runtime_check = "Passed"
            signed = $false
            release_documents = @(
                "dist/WinCur/LICENSE",
                "dist/WinCur/NOTICE.md",
                "dist/WinCur/THIRD_PARTY_NOTICES.md",
                "dist/WinCur/README.txt",
                "dist/WinCur/validated_toolchain.json",
                "dist/WinCur/frozen_dependency_inventory.json",
                "dist/WinCur/build_info.json",
                "dist/WinCur/licenses/PYTHON-3.14.10-LICENSE.txt"
                "dist/WinCur/licenses/third-party/NOTICE_MANIFEST.json"
                "dist/WinCur/licenses/third-party/mesa-llvmpipe-11.2.2/NOTICE.txt"
                "dist/WinCur/licenses/third-party/microsoft-vc-runtime-2026/NOTICE.txt"
                "dist/WinCur/licenses/third-party/pyinstaller-6.22.3/COPYING.txt"
            )
        }
        $manifestPath = Join-Path $releaseRoot "BUILD_MANIFEST.json"
        $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

        Write-Host ""
        Write-Host "WinCur $version candidate $buildId completed successfully." -ForegroundColor Green
        Write-Host "Distribution: $applicationRoot"
        Write-Host "Manifest:     $manifestPath"
        Write-Host "Candidate only. It was not promoted to artifacts\windows\current."
        Write-Host "Copy the entire WinCur directory; WinCur.exe is not standalone."
    } finally {
        Pop-Location
    }
    exit 0
} catch {
    Write-Error "WinCur build failed: $($_.Exception.Message)"
    Write-Error "Existing artifact directories were not deleted or overwritten. Close any running build manually before rebuilding it."
    exit 1
}
