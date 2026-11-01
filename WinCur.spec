# -*- mode: python ; coding: utf-8 -*-
"""Maintained one-directory PyInstaller configuration for WinCur."""

from pathlib import Path
import os


project_root = Path(SPECPATH).resolve()
scoring_config = project_root / "wincur" / "scoring_config.json"
version_resource = project_root / "packaging" / "windows_version_info.txt"
portrait_resource = project_root / "wincur" / "assets" / "wincur_portrait.png"
icon_resource = project_root / "wincur" / "assets" / "wincur.ico"
branding_hashes = project_root / "wincur" / "assets" / "branding_hashes.json"
build_info = Path(os.environ.get("WINCUR_BUILD_INFO_PATH", project_root / "wincur" / "build_info.json"))

if not scoring_config.is_file():
    raise SystemExit(f"Required scoring configuration is missing: {scoring_config}")
if not version_resource.is_file():
    raise SystemExit(f"Windows version metadata is missing: {version_resource}")
if not portrait_resource.is_file():
    raise SystemExit(f"Approved portrait artwork is missing: {portrait_resource}")
if not icon_resource.is_file():
    raise SystemExit(f"Approved Windows icon is missing: {icon_resource}")
if not branding_hashes.is_file():
    raise SystemExit(f"Branding integrity manifest is missing: {branding_hashes}")
if not build_info.is_file():
    raise SystemExit(f"Generated build information is missing: {build_info}")

a = Analysis(
    [str(project_root / "main.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(scoring_config), "wincur"),
        (str(portrait_resource), "wincur/assets"),
        (str(icon_resource), "wincur/assets"),
        (str(branding_hashes), "wincur/assets"),
        (str(build_info), "wincur"),
    ],
    hiddenimports=[
        "wincur.helper",
        "wincur.hardening",
        "wincur.packaging_probe",
        "wincur.ui",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="WinCur",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    version=str(version_resource),
    icon=str(icon_resource),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="WinCur",
)
