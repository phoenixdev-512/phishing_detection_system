import time
import pytest
from app.services.preprocessing import extract_candidate_domain


def test_basic_https_extraction():
    """Verify basic HTTPS URL yields correct candidate_domain, subdomain, scheme, is_ip."""
    result = extract_candidate_domain("https://login.paypal.com/verify")
    assert result.candidate_domain == "paypal.com"
    assert result.subdomain == "login"
    assert result.scheme == "https"
    assert result.is_ip is False


def test_scheme_injection():
    """Verify schemeless URL is prepended with http:// and parsed correctly."""
    result = extract_candidate_domain("evil.com/path")
    assert result.candidate_domain == "evil.com"
    assert result.scheme == "http"


def test_percent_decoding():
    """Verify percent-encoded netloc/path is decoded before processing."""
    result = extract_candidate_domain("https://evil.com/%61%64%6D%69%6E/login")
    # fqdn is the decoded authority; candidate_domain is the eTLD+1
    assert result.candidate_domain == "evil.com"
    # The raw_url still contains the hex form; fqdn should NOT contain %61
    assert "%61" not in result.fqdn


def test_default_port_stripping_https():
    """Verify :443 is stripped from fqdn on HTTPS URLs."""
    result = extract_candidate_domain("https://example.com:443/page")
    assert ":443" not in result.fqdn


def test_default_port_stripping_http():
    """Verify :80 is stripped from fqdn on HTTP URLs."""
    result = extract_candidate_domain("http://example.com:80/page")
    assert ":80" not in result.fqdn


def test_non_default_port_preserved():
    """Verify non-default port does not interfere with candidate_domain extraction."""
    result = extract_candidate_domain("https://example.com:8443/page")
    assert result.candidate_domain == "example.com"


def test_path_traversal_normalization():
    """Verify path traversal sequences are normalized without raising an exception."""
    result = extract_candidate_domain("https://evil.com/legit/../admin")
    assert result.candidate_domain == "evil.com"


def test_ipv4_detection():
    """Verify IPv4 address sets is_ip=True and candidate_domain to the IP string."""
    result = extract_candidate_domain("http://192.168.1.1/phish")
    assert result.is_ip is True
    assert result.candidate_domain == "192.168.1.1"


def test_ipv6_detection():
    """Verify IPv6 literal enclosed in brackets sets is_ip=True."""
    result = extract_candidate_domain("http://[::1]/phish")
    assert result.is_ip is True


def test_cyrillic_idn_punycode():
    """Verify Cyrillic homograph domain triggers Punycode conversion."""
    # U+0430 is Cyrillic small letter 'a', visually identical to Latin 'a'
    cyrillic_url = "http://p\u0430ypal.com/"
    result = extract_candidate_domain(cyrillic_url)
    assert result.punycode_converted is True
    assert "xn--" in result.candidate_domain


def test_missing_candidate_domain_raises():
    """Verify ValueError is raised when no valid eTLD+1 can be extracted."""
    with pytest.raises(ValueError):
        extract_candidate_domain("http://localhost/")


def test_temporal_anchor_is_set():
    """Verify temporal_anchor is a positive float close to the current time."""
    before = time.time()
    result = extract_candidate_domain("https://example.com/")
    after = time.time()
    assert isinstance(result.temporal_anchor, float)
    assert result.temporal_anchor > 0
    assert abs(result.temporal_anchor - time.time()) < 2.0
