import re
from typing import Optional, Tuple

from django.core.exceptions import ValidationError
from PIL import ImageColor

# Standard user-facing validation error message for Level 2 RGB colour secrets
RGB_VALIDATION_ERROR_MESSAGE = (
    "Enter a valid RGB value, hexadecimal colour, or recognised colour name."
)

# Standard CSS3/X11 colour names from Pillow (148 recognised colours including
# 'red', 'blue', 'green', 'purple', 'black', 'white', etc.).
# Arbitrary text and unrecognised words are not in this set.
SUPPORTED_COLOR_NAMES = frozenset(ImageColor.colormap.keys())

# RGB triplet regex: exactly three integer components separated by commas,
# allowing optional whitespace around each component.
# Component length 1 to 3 digits; range [0, 255] is enforced numerically.
_RE_RGB_TRIPLET = re.compile(r'^\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*$')

# Hexadecimal colour regex: exactly six hexadecimal digits, with optional leading '#'.
# Version without '#' is explicitly accepted and normalised consistently with '#'.
_RE_HEX_COLOR = re.compile(r'^#?([0-9a-fA-F]{6})$')


def validate_rgb_password(value: str) -> Tuple[bool, Optional[str]]:
    """Validate and normalise a Level 2 colour password.

    Accepts three formats:
    1. RGB triplet: '255,0,128', allowing optional whitespace around components.
       Every component must be an integer from 0 through 255.
       Normalised to 'r,g,b' without extra whitespace.
    2. Hexadecimal colour: '#FF0080' or 'FF0080', containing exactly six
       hexadecimal digits. Both with and without '#' are accepted and
       consistently normalised to lowercase with '#' prefix ('#ff0080').
    3. Recognised colour names: standard colour names from PIL.ImageColor.colormap
       (e.g. 'red', 'blue', 'green', 'purple', 'black', 'white').
       Case-insensitive, normalised to lowercase.

    Rejects:
    - Arbitrary text such as 'ABC', 'hello', or 'MySecret123' unless it matches
      a supported format.
    - RGB components outside 0–255.
    - Missing or extra RGB components, decimal components, malformed hex strings,
      empty input, and whitespace-only input.

    Returns:
        (True, normalised_value) if valid.
        (False, None) if invalid.
    """
    if not value or not isinstance(value, str):
        return False, None

    stripped = value.strip()
    if not stripped:
        return False, None

    # 1. RGB Triplet format
    match_rgb = _RE_RGB_TRIPLET.fullmatch(stripped)
    if match_rgb:
        r_str, g_str, b_str = match_rgb.groups()
        r, g, b = int(r_str), int(g_str), int(b_str)
        if 0 <= r <= 255 and 0 <= g <= 255 and 0 <= b <= 255:
            return True, f"{r},{g},{b}"
        return False, None

    # 2. Hexadecimal format (exactly 6 hex digits, optional leading '#')
    match_hex = _RE_HEX_COLOR.fullmatch(stripped)
    if match_hex:
        hex_digits = match_hex.group(1).lower()
        return True, f"#{hex_digits}"

    # 3. Recognised colour name format
    name_lower = stripped.lower()
    if name_lower in SUPPORTED_COLOR_NAMES:
        return True, name_lower

    return False, None


def rgb_color_validator(value: str) -> str:
    """Validate that the given string is a valid Level 2 colour password.

    Raises ValidationError if invalid. Returns normalised value if valid.
    """
    is_valid, normalised = validate_rgb_password(value)
    if not is_valid:
        raise ValidationError(RGB_VALIDATION_ERROR_MESSAGE)
    return normalised
