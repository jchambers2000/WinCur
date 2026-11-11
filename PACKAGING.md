# WinCur 1.0.0 Windows packaging

WinCur uses a maintained PyInstaller one-directory configuration. The build
automatically includes the scoring policy and Windows version metadata; no
manual `--add-data` argument is required.

Packaging does not run an assessment, remediation, rollback, registry write,
firewall command, or service change. A build is not a security integration
test, and the resulting executable is unsigned.

## Supported build environment

- Windows 11, 64-bit
- Validated final-release toolchain: CPython 3.14.10, PySide6 6.12.0,
  shiboken6 6.12.0, and PyInstaller 6.22.3
- PowerShell 5.1 or newer

The complete recorded environment is in
`packaging/validated_toolchain.json`. The dependency files retain supported
development ranges, but the public build script fails closed when the selected
Python, PySide6, shiboken6, or PyInstaller version differs from the validated
release toolchain. A toolchain update requires another frozen dependency and
license review.

Create or refresh the build environment from the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
```

PyInstaller is a build-time dependency and is not needed on destination PCs.
The packaged distribution includes the Python runtime and required PySide6/Qt
libraries.

## Standard build command

Close any WinCur instance from an older build, then run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_windows.ps1
```

The script verifies Windows, 64-bit Python, PySide6, PyInstaller, the maintained
specification, scoring configuration, and version metadata. It builds with
[WinCur.spec](WinCur.spec), checks `WinCur.exe`, `scoring_config.json`, and the
Qt `qwindows.dll` platform plugin, validates Windows version information, and
runs a non-security packaged-resource probe.

Every invocation creates an unpromoted candidate with a unique build identifier:

```text
artifacts\windows\candidates\WinCur-1.0.0-<build-id>\
  BUILD_MANIFEST.json
  build_info.json
  packaging-probe.json
  dist\
    WinCur\
      WinCur.exe
      README.txt
      LICENSE
      NOTICE.md
      THIRD_PARTY_NOTICES.md
      validated_toolchain.json
      frozen_dependency_inventory.json
      build_info.json
      licenses\
        PYTHON-3.14.10-LICENSE.txt
        third-party\
          NOTICE_MANIFEST.json
          mesa-llvmpipe-11.2.2\NOTICE.txt
          microsoft-vc-runtime-2026\NOTICE.txt
          pyinstaller-6.22.3\COPYING.txt
          qt-6.12.0\...
          pyside6-6.12.0\...
      _internal\
        wincur\scoring_config.json
        wincur\build_info.json
        wincur\assets\wincur_portrait.png
        wincur\assets\wincur.ico
        ...PySide6, Qt plugins, Python runtime, and dependencies...
```

Exact internal Qt paths are controlled by the installed PyInstaller/PySide6
versions. The build script locates and verifies the required files rather than
assuming one Qt subdirectory layout.

The build identifier is visible under **Settings > About WinCur**, is returned
by the packaging probe, and is recorded in the manifest. Manifest resource
paths are relative to the candidate root so moving a complete package does not
make them misleading.

The script never terminates a running WinCur process, promotes a candidate, or
removes or overwrites an existing artifact directory. A failed build remains isolated,
so a locked `qwindows.dll` in an older distribution cannot damage a known-good
build. Close the process holding the older DLL manually when that old folder is
no longer needed.

## Maintained resources and entry points

- `main.py` is the GUI and fixed non-security packaging-probe entry point.
- `wincur/scoring_config.json` is declared in `WinCur.spec` and resolves through
  `wincur.resources` in source and frozen modes.
- `wincur/assets/wincur_portrait.png` and `wincur/assets/wincur.ico` are the
  approved immutable branding resources. `wincur/assets/branding_hashes.json`
  records their approved SHA-256 hashes. Normal builds validate these exact
  files and never regenerate or substitute them.
- `packaging/windows_version_info.txt` supplies Product Name `WinCur`, File
  Description `WinCur Windows Security Assessment`, Product Version `1.0.0`,
  and File Version `1.0.0.0`. No publisher or copyright owner is invented.
- PyInstaller's maintained PySide6 hooks collect Qt binaries and plugins. The
  build script independently requires `qwindows.dll` before reporting success.
- The PyInstaller analysis explicitly excludes the legacy hardening, helper,
  and elevation modules. The executable manifest remains `asInvoker` and the
  application does not request UAC elevation.
- All writable state remains below `%LOCALAPPDATA%\WinCur` or a destination
  explicitly selected by the user. The installation directory is read-only at
  runtime.

The build refuses to continue if either approved branding resource is missing
or has changed and never substitutes a placeholder. The ICO is applied to both
Qt and the Windows executable and is verified by the packaging probe.

## Verify a completed or relocated distribution

Copy the complete `dist\WinCur` directory. `WinCur.exe` is not standalone and
must remain with `_internal` and all sibling files.

Run the non-security verifier after copying or relocating the folder:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_windows_dist.ps1 `
  -DistributionPath 'C:\Validation\WinCur'
```

The verifier checks files and metadata, then starts only the fixed
`--packaging-probe` mode. That mode reads the bundled scoring policy and writes
a small result in `%TEMP%`; it does not construct the UI, run checks, request
elevation, or invoke remediation.

It also requires the portable README, WinCur license, project and third-party
notices, validated toolchain record, exact CPython license collected from the
build interpreter, and the complete hashed third-party notice payload. Every
file listed by `licenses\third-party\NOTICE_MANIFEST.json` is checked for its
expected size and SHA-256 value.

## Explicit candidate promotion

Building and smoke-testing a candidate never makes it current. After separate
disposable-VM acceptance testing, promote exactly one named candidate with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\promote_windows_candidate.ps1 `
  -CandidateName 'WinCur-1.0.0-<build-id>' `
  -ConfirmValidated
```

The promotion script independently verifies the frozen distribution and build
identifier, requires the manifest smoke test to have passed, asks for an
explicit PowerShell confirmation, archives the previous `current` package, and
moves the candidate into `current`. It refuses name collisions, multiple
current packages, invalid metadata, or failed verification. It never deletes
or overwrites a package and attempts to restore the former current package if
the second move fails.

Artifact roles are:

```text
artifacts\windows\current\     one explicitly promoted, VM-validated package
artifacts\windows\candidates\  newly built, unpromoted packages
artifacts\windows\archive\     previous current packages and retained builds
```

Windows Explorer verification:

1. Right-click `WinCur.exe` and choose **Properties**.
2. Open **Details**.
3. Confirm Product name `WinCur`, File description `WinCur Windows Security
   Assessment`, Product version `1.0.0`, and File version `1.0.0.0`.
4. Do not expect a Digital Signatures tab for this unsigned release.

## Read-only installation test

In a disposable Windows 11 VM:

1. Copy the complete distribution to a new folder.
2. Grant ordinary users read and execute access while denying writes to that
   copied installation folder.
3. Run `tools\verify_windows_dist.ps1` against the copy.
4. Start WinCur normally and perform only a read-only assessment.
5. Confirm history appears below `%LOCALAPPDATA%\WinCur` and an HTML report can
   be written to the user's Documents directory.
6. Confirm no file inside the copied distribution changes.

Do not make the source repository or the only known-good artifact read-only;
always use a disposable copy.

## Clean-VM release validation

Use a restored disposable Windows 11 snapshot with no development Python on
`PATH`:

1. Copy the entire one-directory distribution.
2. Run the distribution verifier.
3. Start normally as a standard user and complete a read-only assessment.
4. Confirm there is no Administrator Scan, Fix Workspace, Apply, Preview, or
   Rollback control and that normal use produces no UAC prompt.
5. Restart and verify scan history, legacy action history (if present), settings,
   layout, and themes.
6. Export a report and verify its version and policy metadata.
7. Relocate the complete directory and repeat the probe and standard scan.
8. Repeat from a read-only copy at 100%, 125%, and 150% display scaling.
9. Invoke each removed `--helper-*` mode and confirm it exits nonzero without
   opening the GUI or requesting elevation.

The public assessment-only build must not include or exercise remediation,
rollback, or elevation functionality. Never treat a successful build or
packaging probe as proof that a security change works.

## Public ZIP staging

Do not ZIP the candidate root, `work` directory, or repository. After the
candidate passes independent verification and disposable-VM acceptance, stage
only the contents of `dist\WinCur` so `WinCur.exe`, `_internal`, `README.txt`,
notices, licenses, and metadata are at the archive root. Generate the ZIP into
a new, uniquely named staging directory and record both the executable and ZIP
SHA-256 values. Never overwrite or promote a previous artifact automatically.

The public GitHub release must also provide the exact Qt 6.12.0 and Qt for
Python 6.12.0 corresponding-source archives listed in
`THIRD_PARTY_NOTICES.md`, with their SHA-256 hashes independently verified.
Those large upstream source archives are deliberately not committed to this
repository and are not embedded in the portable application ZIP.

## Unsigned executable and future signing

WinCur 1.0.0 is not digitally signed. Windows SmartScreen or antivirus products
may warn about a new unsigned executable, and moving or rebuilding it changes
its hash. Do not suppress those warnings programmatically and do not advise
users to disable Windows security protections.

A future release may add Authenticode signing after a publisher identity,
certificate custody process, timestamp service, release approval process, and
independent verification are established. Signing must occur after the build
and before publication; this repository currently makes no signature or
publisher-trust claim.

## Known limitations

- The build is one-directory only; one-file packaging is not supported.
- PyInstaller output is not guaranteed to be byte-for-byte reproducible because
  Python, Qt, PyInstaller, PE timestamps, and toolchain inputs affect binaries.
  `BUILD_MANIFEST.json` records hashes and versions for traceability.
- Legacy elevated-helper source remains in the repository for research but is
  excluded from the assessment-only distribution.
- Authenticode signing, an installer, automatic updates, CI publishing, and
  long-term artifact retention remain out of scope.
- Public binary publication remains blocked until the exact Qt/PySide source
  archives and Microsoft Visual C++ redistribution entitlement identified in
  `THIRD_PARTY_NOTICES.md` have been reviewed and satisfied.
