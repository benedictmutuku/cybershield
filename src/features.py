"""Feature extraction utilities for suspicious URL analysis."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

_SUSPICIOUS_KEYWORDS = (
    "account",
    "bank",
    "confirm",
    "free",
    "gift",
    "invoice",
    "login",
    "password",
    "paypal",
    "phishing",
    "secure",
    "signin",
    "suspended",
    "update",
    "urgent",
    "verify",
    "wallet",
)
_KEYWORD_PATTERN = re.compile(
    r"(?<![a-z0-9])(?:"
    + "|".join(re.escape(keyword) for keyword in _SUSPICIOUS_KEYWORDS)
    + r")(?![a-z0-9])",
    re.IGNORECASE,
)


def _hostname_from_url(url: str) -> tuple[str | None, bool]:
    """Return the normalized hostname and whether the URL uses HTTPS."""
    try:
        parsed = urlsplit(url)
        if not parsed.scheme and not parsed.netloc:
            parsed = urlsplit(f"//{url}")
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValueError(f"Invalid URL: {url!r}") from exc

    return hostname.lower().rstrip(".") if hostname else None, parsed.scheme.lower() == "https"


def _is_ip_address(hostname: str | None) -> bool:
    if hostname is None:
        return False
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def extract_url_features(url: str) -> dict[str, int | float]:
    """Extract numeric, model-friendly characteristics from a URL.

    URLs without a scheme are accepted and parsed as host-based URLs. Counts
    such as dots and digits are calculated over the complete trimmed URL.
    """
    if not isinstance(url, str):
        raise TypeError("url must be a string")

    value = url.strip()
    if not value:
        raise ValueError("url must not be empty")

    hostname, uses_https = _hostname_from_url(value)
    is_ip_address = _is_ip_address(hostname)
    subdomains = 0
    if hostname and not is_ip_address:
        subdomains = max(0, len(hostname.split(".")) - 2)

    return {
        "length": len(value),
        "dots": value.count("."),
        "hyphens": value.count("-"),
        "digits": sum(character.isdigit() for character in value),
        "at_symbol": value.count("@"),
        "is_ip_address": int(is_ip_address),
        "uses_https": int(uses_https),
        "subdomains": subdomains,
        "suspicious_keywords": len(_KEYWORD_PATTERN.findall(value)),
        "entropy": _shannon_entropy(value),
    }
