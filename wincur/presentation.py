"""Presentation-only text cleanup that never mutates captured assessment data."""

from __future__ import annotations

import unicodedata


def sanitize_display_text(value: object) -> str:
    """Remove non-printing controls while preserving useful line and tab spacing."""
    text = str(value if value is not None else "")
    return "".join(
        character for character in text
        if character in ("\n", "\t") or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    )
