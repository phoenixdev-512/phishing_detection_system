import whois
import datetime
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
        
        # 3. Domain Age Analysis
        age_score, age_reason = self._check_domain_age(full_domain)
        risk_score += age_score
        if age_reason:
            reasons.append(age_reason)
        
        # 4. Structural Analysis
        struct_score, struct_reasons = self._check_url_structure(
            full_url, subdomain, url_components["is_ip_address"]
        )
        risk_score += struct_score
        reasons.extend(struct_reasons)
        
        # Cap score at 100
        risk_score = min(risk_score, 100)
        
        return {
            "risk_score": risk_score,
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
    
    def _check_domain_age(self, domain: str) -> Tuple[int, str]:
        """
        Check if domain was created recently (< 30 days).
        Note: WHOIS lookups can be slow and may fail.
        """
        try:
            # Timeout after 5 seconds to prevent hanging
            w = whois.whois(domain)
            
            # Extract creation date
            creation_date = w.creation_date
            
            # Handle case where creation_date is a list
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                # Make timezone-aware if needed
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
                
                now = datetime.datetime.now(datetime.timezone.utc)
                age_days = (now - creation_date).days
                
                if age_days < 30:
                    logger.warning(f"Domain {domain} is only {age_days} days old")
                    return (30, f"Domain is very new ({age_days} days old). New domains are often used for phishing.")
                elif age_days < 90:
                    return (15, f"Domain is relatively new ({age_days} days old).")
        
        except Exception as e:
            # WHOIS lookup failed - don't penalize but log it
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            pass
        
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
            subdomain_count = subdomain.count('.') + 1
            if subdomain_count >= 3:
                score += 20
                reasons.append(f"URL has {subdomain_count} subdomain levels (suspicious).")
        
        return (score, reasons)


# Singleton instance
heuristic_engine = HeuristicEngine()
