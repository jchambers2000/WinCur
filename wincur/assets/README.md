# WinCur branding assets

The finalized user-supplied black-and-white pen-doodle portrait is stored at:

```text
wincur/assets/wincur_portrait.png
```

The approved source was converted only to remove its white background and retain
the black line artwork on transparency. It remains the authoritative runtime
portrait source. Requirements for any future approved replacement are:

- The exact approved black-and-white pen-doodle portrait.
- PNG with transparency where appropriate.
- Original aspect ratio preserved.
- At least 1024 pixels on its longest edge so high-DPI rendering remains sharp.
- No added text, border, shield, or invented brand treatment.

The Windows build script uses `tools/generate_brand_assets.py` to reproducibly
create:

```text
wincur/assets/wincur.ico
```

The ICO contains square transparent canvases at 16, 20, 24, 32, 40, 48, 64,
128, and 256 pixels while preserving the portrait's aspect ratio. Do not check
in or distribute an ICO generated from unapproved artwork.

## Publication permission

The portrait was generated with an AI system using a headshot supplied by the
project maintainer, who is the person depicted. The maintainer has authorized
the portrait and its derived icon for inclusion in the public WinCur repository
and for distribution and modification as part of WinCur under `GPL-3.0-only`,
to the extent copyright or other permission is required and held by the
maintainer.

No claim is made that the AI-generated output independently qualifies for
copyright protection or that the project holds exclusive rights in it. See the
repository's `NOTICE.md` for the complete attribution and rights statement.
