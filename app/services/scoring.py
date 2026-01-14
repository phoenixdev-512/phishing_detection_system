from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class RiskAggregator:
    def __init__(self):
        # Weights defined in Report Section 4.7
        self.WEIGHTS = {
            "database_match": 100,  # Instant block
            "api_match": 100,       # Instant block
            "typosquatting": 80,    # High probability
            "suspicious_keyword": 20,  # Accumulative
            "new_domain": 40,
            "ip_address": 60,
            "long_url": 15,
            "excessive_subdomains": 20
        }
    
    def calculate_risk(
        self, 
        db_result: Optional[Dict], 
        api_result: Optional[Dict], 
        heuristic_result: Dict,
        url_components: Dict
    ) -> Dict:
        """
        Aggregates signals from all detection layers into a final score and verdict.
        
        Returns:
            Dict with keys: risk_score, status, verdict_source, reasons, details
        """
        score = 0
        final_reasons = []
        source = "Heuristic Analysis"  # Default source
        details = {
            "db_checked": db_result is not None,
            "api_checked": api_result is not None,
            "heuristic_score": heuristic_result.get("risk_score", 0),
            "layers_triggered": []
        }
        
        # 1. Critical Checks (Layers 1 & 2) - Instant blocks
        if db_result:
            score = 100
            source = f"Local Database ({db_result.get('source', 'Unknown')})"
            final_reasons.append("URL found in local blacklist.")
            details["layers_triggered"].append("database")
            logger.info(f"Database match found: {db_result}")
        
        elif api_result and api_result.get("is_malicious"):
            score = 100
            source = f"External Threat Intel ({api_result.get('source', 'Unknown')})"
            final_reasons.extend(api_result.get("reasons", ["Flagged by external API."]))
            details["layers_triggered"].append("api")
            logger.info(f"API match found: {api_result}")
        
        # 2. Heuristic Aggregation (Layer 3)
        else:
            # If no critical block, we aggregate heuristic signals
            score = heuristic_result.get("risk_score", 0)
            final_reasons = heuristic_result.get("reasons", [])
            details["layers_triggered"].append("heuristics")
            
            # Add additional context about what was analyzed
            if not db_result:
                details["layers_triggered"].append("database_clean")
            if not (api_result and api_result.get("is_malicious")):
                details["layers_triggered"].append("api_clean")
        
        # 3. Determine Final Status
        status = self._determine_status(score)
        
        # 4. Add transparency details
        details["final_score"] = score
        details["classification"] = status
        details["url_features"] = {
            "domain": url_components.get("registered_domain", "unknown"),
            "is_ip": url_components.get("is_ip_address", False),
            "url_length": url_components.get("url_length", 0),
            "has_subdomain": bool(url_components.get("subdomain")),
        }
        
        logger.info(f"Risk aggregation complete: score={score}, status={status}, source={source}")
        
        return {
            "risk_score": score,
            "status": status,
            "verdict_source": source,
            "reasons": final_reasons if final_reasons else ["No threats detected."],
            "details": details
        }
    
    def _determine_status(self, score: int) -> str:
        """
        Classify the URL based on the risk score.
        
        Score ranges:
        - 0-39: safe
        - 40-69: suspicious
        - 70-100: malicious (or suspicious for heuristic-only detections)
        """
        if score >= 70:
            return "malicious"
        elif score >= 40:
            return "suspicious"
        else:
            return "safe"
    
    def get_recommendation(self, status: str, score: int) -> str:
        """
        Provide actionable recommendations based on the verdict.
        """
        if status == "malicious":
            return "⛔ DO NOT VISIT - This URL is highly dangerous. It matches known phishing databases or exhibits multiple high-risk characteristics."
        elif status == "suspicious":
            if score >= 60:
                return "⚠️ HIGH CAUTION - This URL shows strong indicators of phishing. Proceed only if you absolutely trust the source."
            else:
                return "⚠️ CAUTION - This URL has some suspicious characteristics. Verify the sender and domain carefully before proceeding."
        else:
            return "✅ SAFE - No immediate threats detected. However, always verify the URL matches your intended destination."


# Singleton instance
risk_aggregator = RiskAggregator()
