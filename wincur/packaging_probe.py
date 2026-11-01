"""Non-security smoke probe for a source tree or frozen distribution."""

from __future__ import annotations

import sys
import struct
import hashlib
import json
from pathlib import Path

from . import APP_VERSION
from .build_info import load_build_info
from .resources import require_resource
from .scoring import load_scoring_config
from .storage import atomic_write_json


def validate_brand_resources(portrait: Path, icon: Path, hash_manifest: Path | None = None) -> dict[str, object]:
    png = portrait.read_bytes()
    if len(png) < 24 or png[:8] != b"\x89PNG\r\n\x1a\n" or png[12:16] != b"IHDR":
        raise ValueError(f"The bundled portrait is not a readable PNG resource: {portrait}")
    width, height = struct.unpack(">II", png[16:24])
    if max(width, height) < 1024:
        raise ValueError(f"The bundled portrait is too small for approved high-DPI branding: {width}x{height}")
    ico = icon.read_bytes()
    if len(ico) < 6 or ico[:4] != b"\x00\x00\x01\x00":
        raise ValueError(f"The bundled application icon is not a Windows ICO resource: {icon}")
    image_count = struct.unpack("<H", ico[4:6])[0]
    if image_count < 9:
        raise ValueError(f"The bundled application icon contains only {image_count} image sizes; at least 9 are required.")
    portrait_hash = hashlib.sha256(png).hexdigest().upper()
    icon_hash = hashlib.sha256(ico).hexdigest().upper()
    if hash_manifest is not None:
        expected = json.loads(hash_manifest.read_text(encoding="utf-8"))
        if not isinstance(expected, dict):
            raise ValueError(f"The branding integrity manifest has an invalid root object: {hash_manifest}")
        for name, actual in ((portrait.name, portrait_hash), (icon.name, icon_hash)):
            wanted = str(expected.get(name, "")).upper()
            if not wanted or actual != wanted:
                raise ValueError(f"The approved branding resource failed its SHA-256 integrity check: {name}")
    return {"portrait_width": width, "portrait_height": height, "icon_images": image_count,
            "portrait_sha256": portrait_hash, "icon_sha256": icon_hash}


def run_packaging_probe(output: Path, config_path: Path | None = None, portrait: Path | None = None,
                        icon: Path | None = None, hash_manifest: Path | None = None) -> int:
    """Verify version and bundled scoring data without scanning or changing Windows."""
    try:
        resource = config_path or require_resource("scoring_config.json")
        portrait_resource = portrait or require_resource("assets/wincur_portrait.png")
        icon_resource = icon or require_resource("assets/wincur.ico")
        manifest_resource = hash_manifest or require_resource("assets/branding_hashes.json")
        config = load_scoring_config(resource)
        build = load_build_info(required=bool(getattr(sys, "frozen", False)))
        branding = validate_brand_resources(portrait_resource, icon_resource, manifest_resource)
        payload = {
            "ok": True,
            "application_version": APP_VERSION,
            "build_id": build["build_id"],
            "scoring_policy": str(config.get("policy_version", "Unversioned")),
            "frozen": bool(getattr(sys, "frozen", False)),
            "resource": str(resource),
            "portrait_resource": str(portrait_resource),
            "icon_resource": str(icon_resource),
            "branding_manifest": str(manifest_resource),
            **branding,
            "executable": str(Path(sys.executable).resolve()),
        }
    except Exception as exc:
        payload = {
            "ok": False,
            "application_version": APP_VERSION,
            "frozen": bool(getattr(sys, "frozen", False)),
            "error": str(exc),
        }
    atomic_write_json(output, payload, indent=2)
    return 0 if payload["ok"] else 1
