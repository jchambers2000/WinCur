"""Generate a multi-size Windows ICO from the approved WinCur portrait."""

from __future__ import annotations

import argparse
import os
import struct
import tempfile
from pathlib import Path

from PySide6.QtCore import QByteArray, QBuffer, QIODevice, QRect, Qt
from PySide6.QtGui import QImage, QPainter


ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def _png_for_size(source: QImage, size: int) -> bytes:
    canvas = QImage(size, size, QImage.Format.Format_RGBA8888); canvas.fill(Qt.GlobalColor.transparent)
    padding = max(1, round(size * 0.0625)); available = size - 2 * padding
    scaled = source.size().scaled(available, available, Qt.AspectRatioMode.KeepAspectRatio)
    target = QRect(0, 0, scaled.width(), scaled.height()); target.moveCenter(canvas.rect().center())
    painter = QPainter(canvas); painter.setRenderHint(QPainter.RenderHint.Antialiasing); painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    painter.drawImage(target, source); painter.end()
    payload = QByteArray(); buffer = QBuffer(payload); buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not canvas.save(buffer, "PNG"): raise OSError(f"Qt could not encode the {size}px icon image.")
    return bytes(payload)


def generate_icon(source_path: Path, output: Path) -> None:
    if not source_path.is_file(): raise FileNotFoundError(f"Approved portrait artwork is missing: {source_path}")
    source = QImage(str(source_path))
    if source.isNull(): raise ValueError("The approved portrait source must be a readable PNG file.")
    if source_path.suffix.casefold() != ".png": raise ValueError("The approved portrait source must use the PNG format.")
    if max(source.width(), source.height()) < 1024: raise ValueError("The approved portrait must be at least 1024 pixels on its longest edge.")
    images = [(size, _png_for_size(source, size)) for size in ICON_SIZES]
    header_size = 6 + 16 * len(images); offset = header_size; entries = []
    for size, payload in images:
        dimension = 0 if size == 256 else size
        entries.append(struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(payload), offset)); offset += len(payload)
    ico = struct.pack("<HHH", 0, 1, len(images)) + b"".join(entries) + b"".join(payload for _, payload in images)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent); temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle: handle.write(ico); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        try: temporary.unlink(missing_ok=True)
        except OSError: pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--source", type=Path, required=True); parser.add_argument("--output", type=Path, required=True); arguments = parser.parse_args()
    try: generate_icon(arguments.source.resolve(), arguments.output.resolve())
    except Exception as exc: parser.exit(1, f"Brand asset generation failed: {exc}\n")
    print(f"Generated multi-size WinCur icon: {arguments.output.resolve()}"); return 0


if __name__ == "__main__": raise SystemExit(main())
