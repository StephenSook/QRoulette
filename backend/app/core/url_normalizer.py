"""URL normalization helpers for deterministic URL analysis."""

from __future__ import annotations

from dataclasses import dataclass
import posixpath
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import tldextract

SUSPICIOUS_FILE_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".pif",
    ".app",
    ".dmg",
    ".pkg",
    ".command",
    ".js",
    ".vbs",
    ".wsf",
    ".jar",
    ".py",
    ".sh",
    ".apk",
    ".docm",
    ".xlsm",
    ".pptm",
}

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(slots=True)
class NormalizedUrl:
    """Normalized URL parts consumed by the URL analysis service."""

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    hostname_ascii: str
    path: str
    registrable_domain: str
    subdomain: str
    has_non_ascii_domain: bool
    has_non_ascii_subdomain: bool
    has_punycode_domain: bool
    has_punycode_subdomain: bool
    suspicious_file_extension: str | None


def _ensure_scheme(url: str) -> str:
    """Default missing schemes to HTTPS."""

    candidate = url.strip()
    if "://" not in candidate:
        return f"https://{candidate}"
    return candidate


def _to_ascii_hostname(hostname: str) -> str:
    """Convert a hostname to an ASCII IDNA representation."""

    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def _normalize_path(raw_path: str) -> str:
    """Normalize a URL path without lowercasing case-sensitive segments."""

    decoded_path = unquote(raw_path or "/")
    normalized = posixpath.normpath(decoded_path)
    while normalized.startswith("//"):
        normalized = normalized[1:]
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if decoded_path.endswith("/") and normalized != "/":
        normalized = f"{normalized}/"
    return quote(normalized, safe="/-._~!$&'()*+,;=:@")


def _join_registered_domain(domain: str, suffix: str) -> str:
    """Combine domain and suffix into the registrable domain."""

    if domain and suffix:
        return f"{domain}.{suffix}"
    return domain


def _has_non_ascii(value: str) -> bool:
    """Return whether the string contains any non-ASCII code point."""

    return any(ord(char) > 127 for char in value)


def _contains_punycode_label(value: str) -> bool:
    """Return whether any label uses punycode."""

    return any(label.startswith("xn--") for label in value.split(".") if label)


def normalize_url(url: str) -> NormalizedUrl:
    """Normalize a URL and extract domain-level attributes."""

    candidate = _ensure_scheme(url)
    split = urlsplit(candidate)

    scheme = (split.scheme or "https").lower()
    hostname = (split.hostname or "").rstrip(".").lower()
    hostname_ascii = _to_ascii_hostname(hostname)
    path = _normalize_path(split.path)

    extract_unicode = _extract(hostname)
    extract_ascii = _extract(hostname_ascii)

    registrable_domain = _join_registered_domain(
        extract_unicode.domain,
        extract_unicode.suffix,
    )
    subdomain = extract_unicode.subdomain

    port = f":{split.port}" if split.port else ""
    normalized_url = urlunsplit(
        (
            scheme,
            f"{hostname_ascii}{port}",
            path,
            split.query,
            "",
        )
    )

    suspicious_extension = None
    lower_path = path.lower()
    for extension in SUSPICIOUS_FILE_EXTENSIONS:
        if lower_path.endswith(extension):
            suspicious_extension = extension
            break

    return NormalizedUrl(
        original_url=url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        hostname_ascii=hostname_ascii,
        path=path,
        registrable_domain=registrable_domain,
        subdomain=subdomain,
        has_non_ascii_domain=_has_non_ascii(registrable_domain),
        has_non_ascii_subdomain=_has_non_ascii(subdomain),
        has_punycode_domain=_contains_punycode_label(
            _join_registered_domain(extract_ascii.domain, extract_ascii.suffix)
        ),
        has_punycode_subdomain=_contains_punycode_label(extract_ascii.subdomain),
        suspicious_file_extension=suspicious_extension,
    )
