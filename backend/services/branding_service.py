"""
Branding of an instance: product name, accent colour, footer text, link and logos.

Everything lives in the table ``app_settings`` (keys ``brand.*``) and is set by
administrators on the "Einstellungen" page. Nothing is set by default, so an
installation without any entry looks exactly like InterCat Lynx.

What is NOT configurable on purpose (licence, see NOTICE and the footer):
  - the link to the source code (AGPL-3.0 section 13),
  - the note that the software is a fork of OpenThreat,
  - the copyright line for the names and logos "Intercat" / "InterCat Lynx".

Logos are stored as base64 text in the database. Only PNG, JPEG and WebP are
accepted, recognised by their first bytes (not by the file name or the
announced type). SVG is refused because it can carry scripts.
"""

import base64
import re
import secrets
from typing import Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from . import settings_service

NAME_KEY = "brand.name"
ACCENT_KEY = "brand.accent"
FOOTER_KEY = "brand.footer"
URL_KEY = "brand.url"
VERSION_KEY = "brand.version"
LOGO_KEYS = {"light": "brand.logo_light", "dark": "brand.logo_dark"}
TEXT_KEYS = (NAME_KEY, ACCENT_KEY, FOOTER_KEY, URL_KEY)

DEFAULT_NAME = "InterCat Lynx"
MAX_NAME = 40
MAX_FOOTER = 200
MAX_URL = 255
MAX_LOGO_BYTES = 512 * 1024
MIN_CONTRAST = 4.5  # WCAG AA for normal text: white text on a button of the accent colour

_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class BrandingError(ValueError):
    """The value cannot be used. The message is shown to the administrator."""


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------


def _luminance(hex_color: str) -> float:
    channels = []
    for i in (1, 3, 5):
        c = int(hex_color[i : i + 2], 16) / 255
        channels.append(c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4)
    r, g, b = channels
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_with_white(hex_color: str) -> float:
    return 1.05 / (_luminance(hex_color) + 0.05)


def clean_name(value: str) -> str:
    value = _CONTROL.sub("", value).strip()
    if not value:
        raise BrandingError("Der Produktname darf nicht leer sein")
    if len(value) > MAX_NAME:
        raise BrandingError(f"Der Produktname darf höchstens {MAX_NAME} Zeichen lang sein")
    return value


def clean_accent(value: str) -> str:
    value = value.strip()
    if not _HEX.match(value):
        raise BrandingError("Die Farbe muss als #RRGGBB angegeben werden, zum Beispiel #2271b3")
    ratio = contrast_with_white(value)
    if ratio < MIN_CONTRAST:
        raise BrandingError(
            f"Diese Farbe ist zu hell für weiße Schrift auf Schaltflächen "
            f"(Kontrast {ratio:.1f}:1, nötig sind {MIN_CONTRAST}:1)"
        )
    return value.lower()


def clean_footer(value: str) -> str:
    value = _CONTROL.sub(" ", value).strip()
    if len(value) > MAX_FOOTER:
        raise BrandingError(f"Der Fußzeilentext darf höchstens {MAX_FOOTER} Zeichen lang sein")
    return value


def clean_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if (
        len(value) > MAX_URL
        or parsed.scheme not in ("http", "https")
        or not parsed.netloc
        or _CONTROL.search(value)
        or " " in value
    ):
        raise BrandingError("Die Adresse muss mit http:// oder https:// beginnen")
    return value


def sniff_image(data: bytes) -> Optional[str]:
    """MIME type from the first bytes, or None if it is not PNG/JPEG/WebP."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(data) > 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


# --------------------------------------------------------------------------
# read and write
# --------------------------------------------------------------------------


def _touch_version(db: Session) -> str:
    """New version string: part of the logo address, so browsers load a changed logo."""
    version = secrets.token_hex(4)
    settings_service.set_value(db, VERSION_KEY, version)
    return version


def set_text(db: Session, key: str, value: Optional[str]) -> None:
    """Set one text value; an empty value removes it (back to the default)."""
    if value:
        settings_service.set_value(db, key, value)
    else:
        settings_service.delete(db, key)


def set_logo(db: Session, variant: str, data: bytes) -> str:
    if variant not in LOGO_KEYS:
        raise BrandingError("Unbekannte Logo-Variante")
    if not data:
        raise BrandingError("Die Datei ist leer")
    if len(data) > MAX_LOGO_BYTES:
        raise BrandingError(f"Das Logo darf höchstens {MAX_LOGO_BYTES // 1024} KB groß sein")
    mime = sniff_image(data)
    if mime is None:
        raise BrandingError("Erlaubt sind PNG, JPEG und WebP (kein SVG)")
    settings_service.set_value(db, LOGO_KEYS[variant], base64.b64encode(data).decode("ascii"))
    return mime


def delete_logo(db: Session, variant: str) -> None:
    if variant not in LOGO_KEYS:
        raise BrandingError("Unbekannte Logo-Variante")
    settings_service.delete(db, LOGO_KEYS[variant])


def touch(db: Session) -> None:
    _touch_version(db)


def read_logo(db: Session, variant: str) -> Optional[Tuple[bytes, str]]:
    """(bytes, mime type) of the logo, or None. A damaged entry counts as missing."""
    key = LOGO_KEYS.get(variant)
    raw = settings_service.get(db, key) if key else None
    if not raw:
        return None
    try:
        data = base64.b64decode(raw, validate=True)
    except ValueError:
        return None
    mime = sniff_image(data)
    return (data, mime) if mime else None


def get_branding(db: Session) -> dict:
    """The public view: what the pages need to draw themselves."""
    name = settings_service.get(db, NAME_KEY) or DEFAULT_NAME
    version = settings_service.get(db, VERSION_KEY) or "0"
    has = {v: settings_service.is_set(db, k) for v, k in LOGO_KEYS.items()}

    def logo_url(variant: str) -> Optional[str]:
        # One uploaded logo serves both colour schemes
        use = variant if has[variant] else ("dark" if variant == "light" else "light")
        if not has[use]:
            return None
        return f"/api/v1/branding/logo/{use}?v={version}"

    custom = any(settings_service.is_set(db, k) for k in (*TEXT_KEYS, *LOGO_KEYS.values()))
    return {
        "name": name,
        "accent": settings_service.get(db, ACCENT_KEY) or None,
        "footer_text": settings_service.get(db, FOOTER_KEY) or None,
        "url": settings_service.get(db, URL_KEY) or None,
        "logo_light": logo_url("light"),
        "logo_dark": logo_url("dark"),
        "custom": custom,
        "version": version,
    }
