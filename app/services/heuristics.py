import logging
from difflib import SequenceMatcher
from urllib.parse import urlparse
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


class HeuristicEngine:
    def __init__(self):
        # List of brands often targeted by phishing (Report Section 4.6.2)      
        self.TARGET_BRANDS = [
            "google", "facebook", "amazon", "paypal",
            "microsoft", "instagram", "netflix", "linkedin", "apple"
        ]

        # Keywords common in phishing paths (Report Section 4.6.3)
        self.SUSPICIOUS_KEYWORDS = [
            "login", "verify", "update", "secure",
            "account", "banking", "confirm", "signin", "wallet"
        ]

    def analyze(self, url_components: Dict) -> Dict:
        """
        Runs all heuristic checks and returns a risk score + reasons.
        """
        risk_score = 0
        reasons = []

        domain = url_components["domain"]  # e.g., "google"
        suffix = url_components["suffix"]  # e.g., "com"
        full_domain = f"{domain}.{suffix}" if suffix else domain
        subdomain = url_components["subdomain"]
        path = url_components["path"]
        full_url = url_components["full_url"]

        # 1. Typosquatting Detection
        typo_score, typo_reason = self._check_typosquatting(domain)
        risk_score += typo_score
        if typo_reason:
            reasons.append(typo_reason)

        # 2. Keyword Analysis
        keyword_score, keyword_reason = self._check_suspicious_keywords(path)   
        risk_score += keyword_score
        if keyword_reason:
            reasons.append(keyword_reason)

        # 3. Structural Analysis
        struct_score, struct_reasons = self._check_url_structure(
            full_url, subdomain, url_components["is_ip_address"]
        )
        risk_score += struct_score
        reasons.extend(struct_reasons)

        # Cap score at 100
        final_score = min(100, risk_score) / 100.0

        return {
            "risk_score": final_score,
            "reasons": reasons if reasons else ["No heuristic red flags detected."]
        }

    def _check_typosquatting(self, domain: str) -> Tuple[int, str]:
        """
        Check if domain is similar to popular brands.
        Returns (score_penalty, reason)
        """
        for brand in self.TARGET_BRANDS:
            similarity = SequenceMatcher(None, domain.lower(), brand).ratio()   

            # If very similar but not exact (e.g., "paypa1" vs "paypal")        
            if 0.7 < similarity < 1.0:
                logger.warning(f"Possible typosquatting: {domain} similar to {brand} ({similarity:.2%})")
                return (40, f"Domain '{domain}' is suspiciously similar to '{brand}' (typosquatting).")

        return (0, "")

    def _check_suspicious_keywords(self, path: str) -> Tuple[int, str]:
        """
        Check for phishing keywords in the URL path.
        """
        if not path or path == "/":
            return (0, "")

        path_lower = path.lower()
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in path_lower]

        if found_keywords:
            logger.info(f"Suspicious keywords found in path: {found_keywords}") 
            return (20, f"URL path contains suspicious keywords: {', '.join(found_keywords)}.")

        return (0, "")

    def _check_url_structure(self, url: str, subdomain: str, is_ip: bool) -> Tuple[int, List[str]]:
        """
        Analyze URL structure for suspicious patterns.
        Returns (score_penalty, list_of_reasons)
        """
        score = 0
        reasons = []

        # Check 1: IP Address URLs (high risk)
        if is_ip:
            score += 50
            reasons.append("URL uses an IP address instead of a domain name (high risk).")

        # Check 2: Excessive URL Length
        if len(url) > 75:
            score += 15
            reasons.append(f"URL is unusually long ({len(url)} characters).")   

        # Check 3: Excessive Subdomains
        if subdomain:
            # Count subdomain parts by splitting on dots
            subdomain_parts = subdomain.split(".")
            subdomain_count = len(subdomain_parts)
            if subdomain_count >= 3:
                score += 20
                reasons.append(f"URL has {subdomain_count} subdomain parts (suspicious).")

        return (score, reasons)

# Singleton instance
heuristic_engine = HeuristicEngine()
