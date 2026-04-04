import posixpath
import time
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, unquote
import tldextract

@dataclass
class CandidateDomain:
    raw_url: str
    candidate_domain: str   # $d$ - the eTLD+1
    fqdn: str               # full decoded authority
    subdomain: str
    scheme: str
    temporal_anchor: float  # $t$ - POSIX timestamp
    is_ip: bool             # True if netloc is an IPv4/IPv6 literal
    punycode_converted: bool  # True if IDN conversion was applied

# Regex for IPv4/IPv6 literal detection
IP_REGEX = re.compile(
    r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|'  # IPv4
    r'^\[?([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}\]?$'  # Basic IPv6
)

# Shared TLD Extractor instance
tld_extractor = tldextract.TLDExtract(include_psl_private_domains=True)

def extract_candidate_domain(raw_url: str) -> CandidateDomain:
    # Pre-step: Add default scheme if totally missing, so urlsplit doesn't treat netloc as path
    if not re.match(r'^[a-zA-Z]+://', raw_url):
        raw_url_for_parsing = 'http://' + raw_url
    else:
        raw_url_for_parsing = raw_url

    # Step 1: Decomposition
    parts = urlsplit(raw_url_for_parsing)
    scheme = parts.scheme
    netloc = parts.netloc
    path = parts.path

    # Step 2: Percent-Decoding
    netloc = unquote(netloc)
    path = unquote(path)

    # Step 3: Canonicalization
    scheme = scheme.lower()
    netloc = netloc.lower()
    
    # Strip default ports
    if scheme == 'http' and netloc.endswith(':80'):
        netloc = netloc[:-3]
    elif scheme == 'https' and netloc.endswith(':443'):
        netloc = netloc[:-4]
    
    # Resolve relative path traversals
    if path:
        path = posixpath.normpath(path)

    # Step 4: IDN Punycode Conversion
    labels = netloc.split('.')
    punycode_converted = False
    ascii_labels = []
    
    for label in labels:
        try:
            ascii_label = label.encode('idna').decode('ascii')
            if ascii_label != label:
                punycode_converted = True
            ascii_labels.append(ascii_label)
        except UnicodeError:
            ascii_labels.append(label)
    
    fqdn = '.'.join(ascii_labels)

    # IPv4/IPv6 fast check
    is_ip = bool(IP_REGEX.match(fqdn))

    # Step 5: Candidate Domain extraction
    extracted = tld_extractor(fqdn)

    
    if is_ip:
        candidate_domain = fqdn
    else:
        candidate_domain = extracted.registered_domain
        
    if not candidate_domain:
        raise ValueError("Cannot extract valid candidate domain from input")

    # Step 6: State Initialization
    temporal_anchor = time.time()

    return CandidateDomain(
        raw_url=raw_url,
        candidate_domain=candidate_domain,
        fqdn=fqdn,
        subdomain=extracted.subdomain,
        scheme=scheme,
        temporal_anchor=temporal_anchor,
        is_ip=is_ip,
        punycode_converted=punycode_converted
    )
