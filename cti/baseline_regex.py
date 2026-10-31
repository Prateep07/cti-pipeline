"""Regex IOC baseline.

Primary backend: ioc-finder (`pip install ioc-finder`). If it is not installed, a small built-in
regex extractor is used so the pipeline can be tested end to end. The fallback is NOT ioc-finder:
its numbers must not be reported as ioc-finder results, so every results file records the backend
that was actually used.
"""
from __future__ import annotations

import ipaddress
import re

from .normalize import normalize_value, refang

# ioc-finder result key -> our type
_IOC_FINDER_KEYS = {
    "ipv4s": "ipv4",
    "ipv6s": "ipv6",
    "domains": "domain",
    "urls": "url",
    "email_addresses": "email",
    "md5s": "md5",
    "sha1s": "sha1",
    "sha256s": "sha256",
    "cves": "cve",
}


def ioc_finder_available() -> bool:
    try:
        import ioc_finder  # noqa: F401

        return True
    except ImportError:
        return False


def ioc_finder_version() -> str | None:
    try:
        from importlib.metadata import version

        return version("ioc-finder")
    except Exception:
        return None


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in items:
        k = (it["type"], normalize_value(it["type"], it["value"]))
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out


def _flatten(x) -> list[str]:
    if isinstance(x, dict):
        return [v for vals in x.values() for v in _flatten(vals)]
    if isinstance(x, (list, tuple, set)):
        return [v for vals in x for v in _flatten(vals)]
    return [str(x)] if x else []


def _extract_ioc_finder(text: str) -> list[dict]:
    # NOTE: written against ioc-finder's documented result keys; not exercised in the sandbox
    # where this was authored (no PyPI access). Run tests/test_regex.py after installing it.
    from ioc_finder import find_iocs

    res = find_iocs(text)
    items = []
    for key, type_ in _IOC_FINDER_KEYS.items():
        for v in _flatten(res.get(key, [])):
            items.append({"type": type_, "value": v, "quote": ""})
    for v in _flatten(res.get("attack_techniques", [])):
        items.append({"type": "attack_technique", "value": v, "quote": ""})
    return _dedupe(items)


# ---------------------------------------------------------------- built-in fallback
_TLDS = {
    "com", "net", "org", "io", "info", "biz", "co", "ru", "cn", "de", "uk", "us", "xyz", "top",
    "site", "online", "club", "cc", "tk", "ml", "ga", "cf", "gq", "in", "fr", "nl", "br", "jp",
    "kr", "eu", "me", "tv", "su", "ir", "ua",
}
_RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"')\]]+", re.I)
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RE_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_RE_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_RE_DOMAIN = re.compile(
    r"(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24})(?![\w-])"
)
_RE_HASH = {
    "sha256": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])"),
    "sha1": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{40}(?![0-9A-Fa-f])"),
    "md5": re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])"),
}
_RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_RE_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _extract_fallback(text: str) -> list[dict]:
    t = refang(text)
    items: list[dict] = []

    def add(type_: str, value: str) -> None:
        items.append({"type": type_, "value": value, "quote": ""})

    for m in _RE_URL.finditer(t):
        add("url", m.group(0).rstrip(".,;:"))
    for m in _RE_EMAIL.finditer(t):
        add("email", m.group(0))
    for m in _RE_IPV4.finditer(t):
        try:
            ipaddress.IPv4Address(m.group(0))
            add("ipv4", m.group(0))
        except ValueError:
            pass
    for m in _RE_IPV6.finditer(t):
        try:
            ipaddress.IPv6Address(m.group(0))
            add("ipv6", m.group(0))
        except ValueError:
            pass
    for m in _RE_DOMAIN.finditer(t):
        if m.group(1).lower() in _TLDS:
            add("domain", m.group(0))
    for type_, rx in _RE_HASH.items():
        for m in rx.finditer(t):
            add(type_, m.group(0))
    for m in _RE_CVE.finditer(t):
        add("cve", m.group(0))
    for m in _RE_TECH.finditer(t):
        add("attack_technique", m.group(0))
    return _dedupe(items)


def extract(text: str, backend: str = "auto") -> tuple[list[dict], str]:
    """Return (items, backend_used). backend: auto | ioc_finder | fallback."""
    if backend == "ioc_finder" or (backend == "auto" and ioc_finder_available()):
        if not ioc_finder_available():
            raise RuntimeError("ioc-finder requested but not installed: pip install ioc-finder")
        return _extract_ioc_finder(text), "ioc_finder"
    return _extract_fallback(text), "fallback"
