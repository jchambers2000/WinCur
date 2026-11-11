"""Prepare the checked release-notice payload from verified upstream archives.

This tool is release engineering only. It never imports or changes WinCur.
It intentionally includes all Qt attribution records assigned to a bundled Qt
module, even when an optional platform feature may not be active in the
Windows binaries. Extra attribution is preferable to an unsupported omission.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path, PurePosixPath


QT_SHA256 = "a72e89c33726d742e67edf494abf7b625eaffc756673221c9823322ecd1a32d1"
PYSIDE_SHA256 = "15b25c9e06f3acb8930c318192f3c20aee162f4b8d01bf4b4c60193c924cd847"
QT_MODULES = ("qtbase", "qtsvg", "qtimageformats")
QDOC_MODULES = {
    "qtcore",
    "qtgui",
    "qtnetwork",
    "qtopengl",
    "qtsvg",
    "qtwidgets",
    "qtimageformats",
}


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_member(member: str) -> PurePosixPath:
    value = PurePosixPath(member)
    if value.is_absolute() or ".." in value.parts:
        raise ValueError(f"Unsafe archive member: {member}")
    return value


def write_member(archive: zipfile.ZipFile, member: str, target: Path) -> None:
    safe_member(member)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(archive.read(member))


def resolve_member(base: PurePosixPath, reference: str) -> PurePosixPath:
    parts: list[str] = list(base.parts)
    for part in PurePosixPath(reference).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise ValueError(f"License reference escapes archive root: {reference}")
            parts.pop()
        else:
            parts.append(part)
    return PurePosixPath(*parts)


def prepare_qt(qt_archive: Path, output: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with zipfile.ZipFile(qt_archive) as archive:
        names = set(archive.namelist())
        prefix = PurePosixPath("qt-everywhere-src-6.12.0")

        for module in QT_MODULES:
            licenses_prefix = f"{prefix}/{module}/LICENSES/"
            for member in sorted(name for name in names if name.startswith(licenses_prefix) and not name.endswith("/")):
                relative = PurePosixPath(member).relative_to(prefix)
                write_member(archive, member, output / "qt-6.12.0" / Path(*relative.parts))

        for member in sorted(name for name in names if name.endswith("/qt_attribution.json")):
            path = PurePosixPath(member)
            if not any(path.parts[1] == module for module in QT_MODULES):
                continue
            # Qt's attribution files are JSON-like metadata and a few contain
            # literal line breaks inside strings. The upstream Qt tooling
            # accepts them; strict=False preserves those records without
            # rewriting their source files.
            payload = json.loads(archive.read(member), strict=False)
            entries = payload if isinstance(payload, list) else [payload]
            selected = [entry for entry in entries if entry.get("QDocModule") in QDOC_MODULES]
            if not selected:
                continue

            relative = path.relative_to(prefix)
            attribution_target = output / "qt-6.12.0" / "attributions" / Path(*relative.parts)
            attribution_target.parent.mkdir(parents=True, exist_ok=True)
            attribution_target.write_text(
                json.dumps(selected, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )

            referenced: set[str] = set()
            for entry in selected:
                for key in ("LicenseFile", "CopyrightFile"):
                    value = entry.get(key)
                    if isinstance(value, str):
                        referenced.add(value)
                values = entry.get("LicenseFiles")
                if isinstance(values, list):
                    referenced.update(value for value in values if isinstance(value, str))
                records.append(
                    {
                        "id": entry.get("Id"),
                        "name": entry.get("Name"),
                        "module": entry.get("QDocModule"),
                        "license": entry.get("License"),
                        "license_id": entry.get("LicenseId"),
                        "attribution": str(relative),
                    }
                )

            for reference in sorted(referenced):
                resolved = resolve_member(path.parent, reference)
                resolved_name = str(resolved)
                if resolved_name not in names:
                    raise FileNotFoundError(f"Referenced Qt notice is missing: {resolved_name}")
                target_relative = resolved.relative_to(prefix)
                write_member(
                    archive,
                    resolved_name,
                    output / "qt-6.12.0" / "referenced" / Path(*target_relative.parts),
                )
    return records


def prepare_pyside(pyside_archive: Path, output: Path) -> None:
    with zipfile.ZipFile(pyside_archive) as archive:
        prefix = PurePosixPath("pyside-setup-everywhere-src-6.12.0")
        for member in sorted(archive.namelist()):
            path = PurePosixPath(member)
            if member.endswith("/") or not member.startswith(f"{prefix}/"):
                continue
            relative = path.relative_to(prefix)
            if "LICENSES" not in relative.parts:
                continue
            write_member(archive, member, output / "pyside6-6.12.0" / Path(*relative.parts))


def write_manifest(output: Path, records: list[dict[str, object]]) -> None:
    files = []
    for path in sorted(item for item in output.rglob("*") if item.is_file()):
        relative = path.relative_to(output).as_posix()
        files.append({"path": relative, "size": path.stat().st_size, "sha256": file_hash(path)})
    manifest = {
        "schema_version": 1,
        "qt_version": "6.12.0",
        "pyside_version": "6.12.0",
        "policy": "Conservative module-level notice set for the frozen WinCur inventory",
        "qt_attributions": records,
        "files": files,
    }
    (output / "NOTICE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qt-archive", type=Path, required=True)
    parser.add_argument("--pyside-archive", type=Path, required=True)
    parser.add_argument("--pyinstaller-copying", type=Path, required=True)
    parser.add_argument("--mesa-notice", type=Path, required=True)
    parser.add_argument("--microsoft-runtime-notice", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()

    if file_hash(arguments.qt_archive) != QT_SHA256:
        raise ValueError("Qt source archive SHA-256 does not match the reviewed 6.12.0 release")
    if file_hash(arguments.pyside_archive) != PYSIDE_SHA256:
        raise ValueError("PySide source archive SHA-256 does not match the reviewed 6.12.0 release")
    if arguments.output.exists() and any(arguments.output.iterdir()):
        raise FileExistsError(f"Output directory must be absent or empty: {arguments.output}")
    arguments.output.mkdir(parents=True, exist_ok=True)

    records = prepare_qt(arguments.qt_archive, arguments.output)
    prepare_pyside(arguments.pyside_archive, arguments.output)
    pyinstaller_target = arguments.output / "pyinstaller-6.22.3" / "COPYING.txt"
    pyinstaller_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(arguments.pyinstaller_copying, pyinstaller_target)
    mesa_target = arguments.output / "mesa-llvmpipe-11.2.2" / "NOTICE.txt"
    mesa_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(arguments.mesa_notice, mesa_target)
    microsoft_target = arguments.output / "microsoft-vc-runtime-2026" / "NOTICE.txt"
    microsoft_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(arguments.microsoft_runtime_notice, microsoft_target)
    write_manifest(arguments.output, records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
