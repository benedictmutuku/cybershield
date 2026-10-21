import math

import pytest

from src.features import extract_url_features


def test_extracts_url_character_and_security_features() -> None:
    features = extract_url_features(
        "https://secure-login.example.co.uk/account/verify/123"
    )

    assert features["length"] == len(
        "https://secure-login.example.co.uk/account/verify/123"
    )
    assert features["dots"] == 3
    assert features["hyphens"] == 1
    assert features["digits"] == 3
    assert features["at_symbol"] == 0
    assert features["is_ip_address"] == 0
    assert features["uses_https"] == 1
    assert features["subdomains"] == 2
    assert features["suspicious_keywords"] == 4
    assert features["entropy"] > 0


def test_supports_urls_without_scheme_and_detects_ip_host() -> None:
    features = extract_url_features("192.0.2.10/login")

    assert features["is_ip_address"] == 1
    assert features["uses_https"] == 0
    assert features["subdomains"] == 0


def test_entropy_of_repeated_characters_is_zero() -> None:
    features = extract_url_features("aaaa")

    assert features["entropy"] == 0
    assert math.isfinite(features["entropy"])


@pytest.mark.parametrize("url", ["", "   "])
def test_rejects_empty_urls(url: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        extract_url_features(url)


def test_rejects_non_string_input() -> None:
    with pytest.raises(TypeError, match="must be a string"):
        extract_url_features(None)  # type: ignore[arg-type]


def test_rejects_malformed_ipv6_url() -> None:
    with pytest.raises(ValueError, match="Invalid URL"):
        extract_url_features("https://[not-an-ip]/")
