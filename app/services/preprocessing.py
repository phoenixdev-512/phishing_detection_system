import posixpath
import re
import time
import urllib.parse
from dataclasses import dataclass

import tldextract


@dataclass
class CandidateDomain:
    raw_url: str
    candidate_domain: str   # eTLD+1, e.g. "example.com"
    fqdn: str               # full decoded authority, e.g. "login.evil.com"
    subdomain: str          # subdomain component, e.g. "login"
    scheme: str             # "https" or "http"
    temporal_anchor: float  # time.time() recorded at ingestion
    is_ip: bool             # True if netloc is an IPv4 or IPv6 literal
    punycode_converted: bool  # True if IDN ToASCII was applied


def extract_candidate_domain(raw_url: str) -> CandidateDomain:
    # Step 2a — RFC 3986 decomposition
    url_to_parse = raw_url.strip()
    if not url_to_parse.startswith("http://") and not url_to_parse.startswith("https://"):
        url_to_parse = "http://" + url_to_parse
    parsed = urllib.parse.urlsplit(url_to_parse)

    # Step 2b — Percent-decoding
    netloc = urllib.parse.unquote(parsed.netloc)
    path = urllib.parse.unquote(parsed.path)

    # Step 2c — Canonicalization
    scheme = parsed.scheme.lower()
    netloc = netloc.lower()

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    # Resolve relative path traversals
    if path:
        path = posixpath.normpath(path)
        if path == ".":
            path = ""
    else:
        path = ""

    # Step 2d — IDN Punycode conversion
    punycode_converted = False
    # IPv6 literals are enclosed in brackets — do not attempt port-splitting on them
    if netloc.startswith("["):
        # IPv6 literal: [::1] or [::1]:port
        bracket_end = netloc.find("]")
        host_part = netloc[:bracket_end + 1]   # includes brackets, e.g. "[::1]"
        port_suffix = netloc[bracket_end + 1:]  # e.g. ":8080" or ""
        # No Punycode conversion for IP literals
    elif ":" in netloc:
        host_part, port_part = netloc.rsplit(":", 1)
        port_suffix = ":" + port_part
    else:
        host_part = netloc
        port_suffix = ""

    # Only attempt IDNA conversion on non-IP (non-bracket) hosts
    if not host_part.startswith("["):
        labels = host_part.split(".")
        converted_labels = []
        for label in labels:
            try:
                converted = label.encode("idna").decode("ascii")
                if converted != label:
                    punycode_converted = True
                converted_labels.append(converted)
            except UnicodeError:
                converted_labels.append(label)
        host_part = ".".join(converted_labels)

    netloc = host_part + port_suffix

    # Step 2e — IP literal detection (re used only here)
    # Strip port for IP check
    host_for_ip_check = host_part

    ipv4_pattern = re.compile(
        r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    )
    is_ip = bool(ipv4_pattern.match(host_for_ip_check)) or (
        host_for_ip_check.startswith("[") and host_for_ip_check.endswith("]")
    )

    # Step 2f — Candidate domain extraction
    if is_ip:
        candidate_domain = host_for_ip_check.strip("[]")
        subdomain = ""
        fqdn = host_for_ip_check
    else:
        fqdn = host_part
        extracted = tldextract.extract(host_part, include_psl_private_domains=True)
        candidate_domain = extracted.registered_domain
        if not candidate_domain:
            raise ValueError(f"Cannot extract valid candidate domain from: {raw_url}")
        subdomain = extracted.subdomain

    # Step 2g — Record temporal anchor
    temporal_anchor = time.time()

    # Step 2h — Return populated dataclass
    return CandidateDomain(
        raw_url=raw_url,
        candidate_domain=candidate_domain,
        fqdn=fqdn,
        subdomain=subdomain,
        scheme=scheme,
        temporal_anchor=temporal_anchor,
        is_ip=is_ip,
        punycode_converted=punycode_converted,
    )
