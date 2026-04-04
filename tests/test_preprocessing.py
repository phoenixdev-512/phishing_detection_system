import pytest
from app.services.preprocessing import extract_candidate_domain

def test_extract_idn_conversion():
    # Cyrillic "p" in paypal
    res = extract_candidate_domain("http://рaypal.com")
    assert res.punycode_converted is True
    assert res.candidate_domain == "xn--aypal-uye.com"

def test_extract_percent_decoding():
    res = extract_candidate_domain("http://example.com/%61%64%6D%69%6E")
    # Path is decoded implicitly but CandidateDomain extraction ignores path for $d$
    assert res.candidate_domain == "example.com"
    
def test_extract_ip():
    res = extract_candidate_domain("http://192.168.1.1/login")
    assert res.is_ip is True
    assert res.candidate_domain == "192.168.1.1"

def test_extract_port_stripping():
    res = extract_candidate_domain("https://example.com:443")
    assert res.candidate_domain == "example.com"

def test_extract_path_normalization():
    res = extract_candidate_domain("http://example.com/../admin")
    assert res.candidate_domain == "example.com"
    
def test_extract_subdomain():
    res = extract_candidate_domain("http://secure.login.example.com")
    assert res.candidate_domain == "example.com"
    assert res.subdomain == "secure.login"

def test_raise_error_on_invalid():
    with pytest.raises(ValueError):
        extract_candidate_domain("http://") # No domain
