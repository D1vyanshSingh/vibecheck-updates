"""VibeCheck brand assets for generated reports.

The report is a standalone HTML document: it must look the same on a machine
with no network and print faithfully to PDF. Brand fonts are embedded from
``assets/fonts`` as data URIs, and the mark is inline SVG, so nothing here
depends on a CDN or on fonts being installed locally.

If the font files are missing the report still renders; the CSS falls back to
the system stack declared in ``report._CSS``.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

BRAND = {
    "name": "VibeCheck",
    "tagline": "Secure what you build",
    "site": "vibecheck.dev",
    "void": "#08080D",
    "surface": "#11101A",
    "elevated": "#171323",
    "violet": "#702BFF",
    "violet_bright": "#974FFF",
    "lavender": "#C9B5FF",
    "fog": "#F5F3FF",
    "muted": "#A5A0B5",
}

_FONT_DIR = Path(__file__).with_name("assets") / "fonts"

# (family, file, weight range). The files are the latin subsets Google Fonts
# serves for the marketing site's next/font setup (SIL Open Font License).
_FONTS = (
    ("Space Grotesk", "space-grotesk-latin.woff2", "300 700"),
    ("Inter", "inter-latin.woff2", "100 900"),
    ("JetBrains Mono", "jetbrains-mono-latin.woff2", "400 700"),
)


@lru_cache(maxsize=1)
def font_css() -> str:
    """``@font-face`` rules with the brand fonts embedded as data URIs."""
    rules: list[str] = []
    for family, filename, weights in _FONTS:
        path = _FONT_DIR / filename
        try:
            payload = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError:
            continue
        rules.append(
            "@font-face{"
            f"font-family:'{family}';"
            "font-style:normal;"
            f"font-weight:{weights};"
            "font-display:swap;"
            f"src:url(data:font/woff2;base64,{payload}) format('woff2');"
            "}"
        )
    return "".join(rules)


def logo_svg(size: int = 40, tone: str = "dark", class_name: str = "") -> str:
    """The VibeCheck mark: two converging strokes, an orbital ellipse and a star.

    ``tone="dark"`` is for the near-black cover; ``tone="light"`` swaps the
    star to violet so the mark reads on white paper.
    """
    star = BRAND["fog"] if tone == "dark" else BRAND["violet"]
    extra = f' class="{class_name}"' if class_name else ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" '
        f'width="{size}" height="{size}" fill="none" aria-hidden="true"{extra}>'
        "<defs>"
        '<linearGradient id="vcMarkStroke" x1="8" y1="6" x2="40" y2="42" '
        'gradientUnits="userSpaceOnUse">'
        '<stop offset="0" stop-color="#C9B5FF"/>'
        '<stop offset="0.55" stop-color="#974FFF"/>'
        '<stop offset="1" stop-color="#702BFF"/>'
        "</linearGradient>"
        '<linearGradient id="vcMarkOrbit" x1="6" y1="10" x2="42" y2="34" '
        'gradientUnits="userSpaceOnUse">'
        '<stop offset="0" stop-color="#702BFF" stop-opacity="0.3"/>'
        '<stop offset="0.5" stop-color="#C9B5FF" stop-opacity="0.95"/>'
        '<stop offset="1" stop-color="#974FFF" stop-opacity="0.4"/>'
        "</linearGradient>"
        "</defs>"
        '<ellipse cx="24" cy="23.5" rx="20" ry="9.4" transform="rotate(-31 24 23.5)" '
        'stroke="url(#vcMarkOrbit)" stroke-width="1.4"/>'
        '<path d="M13.5 12.5 L23.9 37.4 L34.4 12.5" stroke="url(#vcMarkStroke)" '
        'stroke-width="5" stroke-linecap="square" fill="none"/>'
        '<path d="M37.4 4.6 C37.9 8.1 38.9 9.1 42.4 9.6 C38.9 10.1 37.9 11.1 37.4 '
        '14.6 C36.9 11.1 35.9 10.1 32.4 9.6 C35.9 9.1 36.9 8.1 37.4 4.6 Z" '
        f'fill="{star}"/>'
        "</svg>"
    )


@lru_cache(maxsize=1)
def favicon_data_uri() -> str:
    """The mark on a dark rounded tile, as an inline SVG favicon."""
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
        '<rect width="48" height="48" rx="11" fill="#08080D"/>'
        '<ellipse cx="24" cy="23.5" rx="19" ry="8.8" transform="rotate(-31 24 23.5)" '
        'stroke="#C9B5FF" stroke-opacity="0.75" stroke-width="1.4" fill="none"/>'
        '<path d="M13.5 12.5 L23.9 37.4 L34.4 12.5" stroke="#974FFF" '
        'stroke-width="5" stroke-linecap="square" fill="none"/>'
        '<path d="M37.4 4.6 C37.9 8.1 38.9 9.1 42.4 9.6 C38.9 10.1 37.9 11.1 37.4 '
        '14.6 C36.9 11.1 35.9 10.1 32.4 9.6 C35.9 9.1 36.9 8.1 37.4 4.6 Z" '
        'fill="#F5F3FF"/>'
        "</svg>"
    )
    encoded = (
        svg.replace("%", "%25")
        .replace("#", "%23")
        .replace("<", "%3C")
        .replace(">", "%3E")
        .replace('"', "%22")
    )
    return "data:image/svg+xml," + encoded
