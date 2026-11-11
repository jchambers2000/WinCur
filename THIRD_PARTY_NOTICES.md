# WinCur third-party notices

This inventory describes the Windows 11 x64 one-directory build produced from
the validated toolchain in `packaging/validated_toolchain.json`. It is based on
inspection of the most recent frozen candidate and must be regenerated or
reviewed whenever the interpreter, wheels, PyInstaller, or collected files
change.

WinCur is distributed under GPL-3.0-only. The portable build uses the
open-source GPL-compatible licensing options described below. This document is
an attribution and release-engineering record, not legal advice.

## Redistributed runtime components

### CPython 3.14.10

- Runtime files include `python314.dll`, `python3.dll`, `base_library.zip`, and
  CPython extension modules.
- License: Python Software Foundation License Version 2 and the additional
  historical and bundled-component notices in CPython's `LICENSE.txt`.
- The build copies the exact interpreter's `LICENSE.txt` into
  `licenses/PYTHON-3.14.10-LICENSE.txt` in the candidate package.
- That license file also contains notices for bundled components used by the
  frozen runtime, including bzip2 1.0.8, libffi, and Zstandard.

Python and the Python logo are trademarks or registered trademarks of the
Python Software Foundation.

### Qt for Python 6.12.0

- PySide6 bindings collected: QtCore, QtGui, QtNetwork, and QtWidgets.
- shiboken6 runtime collected: `Shiboken.pyd` and `shiboken6.abi3.dll`.
- Installed package metadata offers LGPL-3.0-only, GPL-2.0-only, or
  GPL-3.0-only for PySide6, PySide6 Essentials/Addons, and shiboken6.
- WinCur's public GPL-3.0-only build uses the GPL-3.0-only option so that one
  consistent copyleft license applies to WinCur and the GPL-only Qt module
  described below. WinCur's root `LICENSE` contains the GPLv3 text.

Copyright in Qt for Python remains with The Qt Company Ltd and other
contributors.

### Qt 6.12.0 libraries and plugins

The minimized candidate contains Qt Core, GUI, Widgets, Network, OpenGL, and
SVG libraries, plus Windows platform, image-format, TLS, style,
network-information, and generic touch plugins. The maintained specification
explicitly excludes the unused PDF image plugin and Virtual Keyboard input
plugin together with their Qt PDF, QML, Quick, and Virtual Keyboard dependency
chains. It does **not** contain Qt WebEngine binaries.

The remaining Qt modules are available under open-source GPLv3-compatible
terms. WinCur's public GPL-3.0-only build uses the GPL-3.0 option consistently
for Qt/PySide and makes corresponding source for the exact Qt and Qt for Python
versions available alongside the binary release.

Required source artifacts for the validated build:

| Artifact | Upstream location | SHA-256 |
|---|---|---|
| `qt-everywhere-src-6.12.0.zip` | `https://download.qt.io/official_releases/qt/6.12/6.12.0/single/qt-everywhere-src-6.12.0.zip` | `a72e89c33726d742e67edf494abf7b625eaffc756673221c9823322ecd1a32d1` |
| `pyside-setup-everywhere-src-6.12.0.zip` | `https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.12.0-src/pyside-setup-everywhere-src-6.12.0.zip` | `15b25c9e06f3acb8930c318192f3c20aee162f4b8d01bf4b4c60193c924cd847` |

The Qt source archive contains module-specific copyright and third-party
license material. The release process must retain those files and make the
matching archives available from the same release location as the WinCur ZIP;
an upstream URL alone must not be treated as WinCur's durable source offering.
The Qt 6.12 third-party inventory includes additional permissively licensed
code used by the collected modules and plugins, including image codecs,
OpenGL software rendering, and Virtual Keyboard input methods.

The maintained release payload at `packaging/third_party_notices` contains a
conservative module-level bundle generated from Qt's own 6.12.0 attribution
metadata. It preserves the upstream attribution JSON, every referenced
license/copyright file, and the module `LICENSES` directories for `qtbase`,
`qtsvg`, and `qtimageformats`. It includes optional entries assigned to these
bundled modules when static feature detection cannot prove their absence;
extra attribution is preferred to an unsupported omission. The payload's
`NOTICE_MANIFEST.json` records and hashes every file, and both the build and
independent distribution verifier reject a missing or altered entry.

Qt and the Qt logo are trademarks of The Qt Company Ltd. Their use here does
not imply endorsement.

### Mesa llvmpipe 11.2.2

The inspected Windows candidate also contains Qt's separately supplied
`opengl32sw.dll` software OpenGL renderer. The file is signed by The Qt Company
Oy and has SHA-256
`18aedc7a4b610f53bcc7b7a5c5ed9293c7e86f030e3273ad54ed3bb1ebd36702`.
Qt identifies this component as Mesa llvmpipe and attributes it under the MIT
License and Boost Software License 1.0.

Qt's official prebuilt package is
`opengl32sw-64-mesa_11_2_2-signed_sha256.7z` (SHA-256
`c61f801c1760aa24b02c7a8354323cddf368b86f8f5c34b50b3b224f7d728afd`).
The candidate DLL has a newer Authenticode signature than the DLL in that
package, so their whole-file hashes differ. Their PE section payloads and
certificate-normalized hashes are identical; the normalized SHA-256 is
`d303dd60bbf11418063f4bb72292e481ca1e88d84915fbd049a21666b92c0ee0`.

The `qt-everywhere-src-6.12.0.zip` archive contains Qt's provisioning script
for the Mesa 11.2.2 binary and generic MIT/Boost license texts, but it does not
contain the Mesa 11.2.2 source tree or the complete component-specific
attribution. The maintained notice payload therefore includes Qt's complete
component attribution and the applicable MIT and Boost Software License 1.0
wording in `mesa-llvmpipe-11.2.2/NOTICE.txt`.

### OpenSSL 3.5.9

- Redistributed as `libcrypto-3.dll` and `libssl-3.dll` from the CPython
  installation.
- License: Apache License 2.0 for OpenSSL 3.0 and later.
- The Apache License 2.0 text is included in the CPython `LICENSE.txt` copied
  into the portable package. Copyright remains with the OpenSSL Project and
  its contributors.

### Microsoft Visual C++ runtime

The candidate contains x64 release-runtime `VCRUNTIME140.dll`,
`VCRUNTIME140_1.dll`, `MSVCP140.dll`, `MSVCP140_1.dll`, and `MSVCP140_2.dll`
files required by CPython and Qt. These files are Microsoft Distributable Code
and are proprietary Microsoft components separately aggregated with WinCur.
They are not covered by WinCur's GPL-3.0-only license grant. That separation
does not reduce or add restrictions to the rights granted for WinCur's
GPL-covered code. Microsoft copyrights and trademarks remain with Microsoft
Corporation, and no Microsoft endorsement is implied.

The inspected package contains runtime versions 14.51.36247.0 (copied
byte-for-byte from the installed CPython 3.14.10 runtime) and 14.44.35211.0
(copied byte-for-byte from the installed PySide6/shiboken6 6.12.0 wheels).
Every copy has a valid Authenticode signature. The Qt-distributed 14.44 copies
have executable-section payloads matching the installed Microsoft x64 REDIST
copies; vendor signatures account for whole-file differences. The 14.51 copies
are byte-identical to the Microsoft-signed System32 and CPython installation
copies. No preview, debug, or `debug_nonredist` component is included.

The release owner has recorded a complete, stable Visual Studio Community 2026
installation and personally attested acceptance of its individual license for
WinCur development. The Community license's Distributable Code provisions and
Microsoft's Visual Studio 2026 REDIST list govern these DLLs. Downstream users
and distributors must preserve their separate proprietary status and comply
with the applicable Microsoft terms. The packaged terms are at
`licenses/third-party/microsoft-vc-runtime-2026/NOTICE.txt`.

### PyInstaller 6.22.3 bootloader

`WinCur.exe` embeds the PyInstaller Windows bootloader. PyInstaller is licensed
under GPL-2.0-or-later with a Bootloader Exception granting permission to link
or embed the compiled bootloader and distribute that combination without
restrictions arising solely from those embedded files. Copyright notices in
the installed release identify the PyInstaller Development Team, Giovanni
Bajo, and McMillan Enterprises, Inc.

The release payload copies the exact installed PyInstaller 6.22.3
`COPYING.txt`, including the Bootloader Exception, to
`licenses/third-party/pyinstaller-6.22.3/COPYING.txt`.

## Build-only packages

The validated environment also contains `altgraph 0.17.5`, `packaging 26.3`,
`pefile 2024.8.26`, `pyinstaller-hooks-contrib 2026.9`, and
`pywin32-ctypes 0.2.3`. They are inputs to PyInstaller analysis and are not
present as importable packages in the inspected frozen distribution. Their
licenses are respectively MIT, Apache-2.0 OR BSD-2-Clause, MIT, and
BSD-3-Clause. PyInstaller Community Hooks uses GPL-2.0-or-later for its
build-time standard hooks and Apache-2.0 for runtime-hook files that may be
embedded in a frozen application; the final archive inspection must identify
any such collected runtime hooks.

## Release gate

A public binary release is blocked until all of the following are true:

1. The final candidate is rebuilt and this inventory is compared with its
   actual collected files.
2. The two exact source archives above are downloaded from the official Qt
   release service, their SHA-256 hashes are verified, and they are uploaded
   alongside the WinCur ZIP (or an equivalent compliant source-delivery method
   is reviewed and documented).
3. The final ZIP contains `LICENSE`, `NOTICE.md`, this file, the exact CPython
   license copied by the build, `README.txt`, and build metadata.
4. The Microsoft runtime redistribution entitlement and REDIST-list coverage
   are confirmed for the account/toolchain used to build the public package.
5. The checked notice payload is included in the portable package and its
   integrity manifest passes the independent distribution verifier.
6. The Mesa llvmpipe provenance comparison for the exact `opengl32sw.dll` is
   retained with the release record.
7. The final frozen file inventory is retained with the release records so any
   newly collected Qt plugin or native library triggers another license review.

Until these items are complete, a candidate may be tested privately but must
not be described as license-complete for public binary redistribution.
