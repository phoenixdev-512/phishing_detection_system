import re
import socket
from urllib.parse import urlparse, urlunparse
import tldextract
from fastapi import HTTPException

class URLPreprocessor:
    def __init__(self):
        # Regex to identify IP addresses (IPv4)
        self.ip_regex = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )

    def normalize(self, raw_url: str) -> dict:
        """
        Main pipeline to clean and extract features from a URL.
        Returns a dictionary of components.
        """
        # 1. Basic Sanitization
        clean_url = raw_url.strip()
        # Remove control characters (e.g., tabs, newlines which can be obfuscation vectors)
        clean_url = "".join(ch for ch in clean_url if ch.isprintable())

        # 2. Protocol Validation & Addition
        # If no scheme is present, default to http:// to allow parsing
        if not re.match(r'^[a-zA-Z]+://', clean_url):
            clean_url = 'http://' + clean_url

        # 3. IDN (Internationalized Domain Name) Conversion
        # This converts characters like 'рaypal.com' (Cyrillic 'a') into 'xn--pypal-4ve.com'
        try:
            parsed_initial = urlparse(clean_url)
            # Encode the hostname to IDNA (Punycode)
            ascii_host = parsed_initial.hostname.encode('idna').decode('ascii')
            # Reconstruct the URL with the ASCII hostname
            # urlparse is immutable, so we replace components in a list logic
            clean_url = urlunparse((
                parsed_initial.scheme,
                ascii_host,
                parsed_initial.path,
                parsed_initial.params,
                parsed_initial.query,
                parsed_initial.fragment
            ))
        except (UnicodeError, AttributeError):
            # If conversion fails, the domain might be malformed or already ASCII
            pass

        # 4. Deep Structural Decomposition
        # Using tldextract for accurate Subdomain/Domain/Suffix separation
        extracted = tldextract.extract(clean_url)
        parsed = urlparse(clean_url)

        # 5. Feature Extraction for later layers
        # We prepare these now so the Heuristic layer doesn't have to re-parse
        features = {
            "full_url": clean_url,
            "protocol": parsed.scheme,
            "subdomain": extracted.subdomain,
            "domain": extracted.domain,
            "suffix": extracted.suffix,  # The TLD (e.g., .com, .co.uk)
            "registered_domain": extracted.registered_domain,  # domain.suffix
            "path": parsed.path,
            "query_params": parsed.query,
            "is_ip_address": self._is_ip_address(extracted.domain),
            "url_length": len(clean_url)
        }

        # 6. Basic Validation
        if not features["registered_domain"] and not features["is_ip_address"]:
            raise HTTPException(status_code=400, detail="Invalid URL: No valid domain or IP found.")

        return features

    def _is_ip_address(self, domain_part: str) -> bool:
        """Helper to check if the domain part is actually an IP."""
        return bool(self.ip_regex.match(domain_part))

# Instantiate a global preprocessor to be imported elsewhere
preprocessor = URLPreprocessor()
