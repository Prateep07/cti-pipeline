"""Refanging, canonical value normalisation and grounding checks.

Grounding answers: "does this extracted value actually appear in the report?"
Two levels are reported everywhere:
  strict  - the value appears character-for-character in the raw text
  relaxed - the value appears after refanging (hxxp -> http, [.] -> .) and lower-casing
Defanged IOCs are normal in CTI, so `relaxed` is the primary hallucination criterion and
`strict` is reported alongside it.
"""
from __future__ import annotations

import re

_REFANG_RULES = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.I), "@"),
]
_TRAILING_PUNCT = ".,;:)]}'\""

# A value only counts as present if it is not glued to more identifier characters,
# so 1.2.3.4 is NOT found inside 11.2.3.45 or 1.2.3.4.5.
_LEFT = r"(?<![A-Za-z0-9._-])"
_RIGHT = r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9])"


def refang(s: str) -> str:
    for pattern, repl in _REFANG_RULES:
        s = pattern.sub(repl, s)
    return s


def normalize_value(type_: str, value: str) -> str:
    """Canonical form used to compare predicted and gold values."""
    v = refang(value.strip()).rstrip(_TRAILING_PUNCT)
    if type_ in ("md5", "sha1", "sha256", "domain", "email", "ipv4", "ipv6"):
        v = v.lower()
    elif type_ in ("cve", "attack_technique"):
        v = v.upper()
    elif type_ == "url":
        v = re.sub(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*)", lambda m: m.group(1).lower() + m.group(2).lower(), v)
    return v


def _find(needle: str, haystack: str) -> bool:
    if not needle:
        return False
    return re.search(_LEFT + re.escape(needle) + _RIGHT, haystack) is not None


def grounded(type_: str, value: str, text: str) -> tuple[bool, bool]:
    """Return (strict, relaxed) grounding of `value` in `text`."""
    strict = _find(value.strip(), text)
    relaxed = _find(normalize_value(type_, value).lower(), refang(text).lower())
    return strict, relaxed


def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def quote_grounded(quote: str, text: str) -> bool:
    """Is the quoted span present in the report (whitespace/case-insensitive, refang-aware)?"""
    q = _ws(quote)
    if not q:
        return False
    return q in _ws(text) or _ws(refang(quote)) in _ws(refang(text))
