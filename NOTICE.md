# WinCur licensing and attribution notice

## Project source

WinCur source code and project documentation are made available under the
GNU General Public License, version 3 only (`GPL-3.0-only`). See
[`LICENSE`](LICENSE) for the complete license text.

Copyright in individual contributions remains with the respective
contributors. This notice does not assign copyright to a named person or
organization and does not claim exclusive ownership of every element in the
repository.

## Portrait and application icon

The portrait in `wincur/assets/wincur_portrait.png` was generated with an AI
system using a headshot supplied by the project maintainer. The maintainer is
the person depicted and has authorized the portrait's inclusion in this public
repository and its distribution and modification as part of WinCur under
`GPL-3.0-only`, to the extent copyright or other permission is required and
held by the maintainer.

The application icon in `wincur/assets/wincur.ico` is a mechanical derivative
of that portrait and is provided on the same basis.

No claim is made that the AI-generated output independently qualifies for
copyright protection, or that WinCur or its contributors hold exclusive rights
in AI-generated material. This notice also does not claim rights belonging to
the provider of the AI system or any other third party.

## Dependencies

Source-development dependencies are installed separately and remain subject to
their upstream licenses. A frozen Windows build redistributes a more specific
set of runtime components, including CPython, Qt, PySide6, shiboken6, OpenSSL,
Microsoft Visual C++ runtime libraries, and the PyInstaller bootloader.

[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) records the exact versions
observed in the validated toolchain, the files collected by PyInstaller, the
applicable notices, and the corresponding-source requirement for the GPLv3 Qt
components. The portable archive must include this notice, WinCur's `LICENSE`,
the CPython license file collected from the exact interpreter used to build,
and `licenses/third-party/NOTICE_MANIFEST.json` with every notice file listed
by that integrity manifest. The generated `BUILD_MANIFEST.json` and
`build_info.json` record the particular build.

No trademark license or endorsement is implied by naming a third-party
component. Third-party copyrights remain with their respective holders.

The Microsoft Visual C++ runtime DLLs in a portable Windows build are separate
proprietary components aggregated with WinCur for runtime interoperability.
They are not licensed under GPL-3.0-only. Their separate terms apply only to
those Microsoft components and do not limit the GPL rights granted for
WinCur's GPL-covered code. See
`licenses/third-party/microsoft-vc-runtime-2026/NOTICE.txt` in the portable
distribution.

