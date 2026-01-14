import aiohttp
import asyncio
import time
import logging
from typing import Optional, Dict
from app.core.config import settings

logger = logging.getLogger(__name__)

# A simple in-memory cache: { "url": {"result": ..., "timestamp": ...} }
# In production, use Redis.
api_cache: Dict[str, Dict] = {}
CACHE_TTL = 300  # 5 minutes


class APIManager:
    def __init__(self):
        self.google_api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.phishtank_url = "https://checkurl.phishtank.com/checkurl/"

    async def check_url(self, url: str) -> Optional[Dict]:
        """
        Orchestrates parallel checks to all external providers.
        """
        # 1. Check Cache first
        if url in api_cache:
            entry = api_cache[url]
            if time.time() - entry["timestamp"] < CACHE_TTL:
                logger.info(f"Cache Hit for {url}")
                return entry["result"]

        # 2. Define the tasks (Parallel Execution)
        async with aiohttp.ClientSession() as session:
            tasks = [
                self._check_google_safe_browsing(session, url),
                self._check_phishtank(session, url),
            ]
            
            # Run all checks in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # 3. Process Results
        # If ANY API says "malicious", we flag it
        for result in results:
            if isinstance(result, dict) and result.get("is_malicious"):
                # Cache the result
                api_cache[url] = {
                    "result": result,
                    "timestamp": time.time()
                }
                return result

        # All APIs say safe or failed
        safe_result = {
            "is_malicious": False,
            "source": "External APIs",
            "risk_score": 0
        }
        
        # Cache safe result too
        api_cache[url] = {
            "result": safe_result,
            "timestamp": time.time()
        }
        
        return safe_result

    async def _check_google_safe_browsing(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """
        Check Google Safe Browsing API.
        Note: This is a MOCK implementation. Real implementation requires API key.
        """
        if not self.google_api_key:
            logger.info("Google Safe Browsing API key not configured - skipping check")
            return None

        # REAL IMPLEMENTATION (commented out - uncomment when you have API key):
        # try:
        #     api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_api_key}"
        #     payload = {
        #         "client": {
        #             "clientId": "phishing-detector",
        #             "clientVersion": "1.0.0"
        #         },
        #         "threatInfo": {
        #             "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        #             "platformTypes": ["ANY_PLATFORM"],
        #             "threatEntryTypes": ["URL"],
        #             "threatEntries": [{"url": url}]
        #         }
        #     }
        #     
        #     async with session.post(api_url, json=payload, timeout=5) as response:
        #         if response.status == 200:
        #             data = await response.json()
        #             if data.get("matches"):
        #                 return {
        #                     "is_malicious": True,
        #                     "source": "Google Safe Browsing",
        #                     "risk_score": 95,
        #                     "threat_type": data["matches"][0].get("threatType", "UNKNOWN")
        #                 }
        #         return None
        # except Exception as e:
        #     logger.error(f"Google Safe Browsing API error: {e}")
        #     return None

        # MOCK IMPLEMENTATION (remove when using real API):
        logger.info(f"Mock Google Safe Browsing check for {url}")
        return None  # Mock: Always returns safe

    async def _check_phishtank(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """
        Check PhishTank database.
        Note: PhishTank has rate limits and requires proper user agent.
        """
        try:
            # PhishTank POST API endpoint
            headers = {
                "User-Agent": "phishing-detector/1.0"
            }
            
            data = {
                "url": url,
                "format": "json"
            }
            
            async with session.post(
                self.phishtank_url,
                data=data,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    # PhishTank response structure:
                    # {"meta": {...}, "results": {"in_database": true/false, "phish_id": ..., "verified": ...}}
                    if result.get("results", {}).get("in_database"):
                        if result["results"].get("verified"):
                            return {
                                "is_malicious": True,
                                "source": "PhishTank",
                                "risk_score": 90,
                                "phish_id": result["results"].get("phish_id")
                            }
                    return None
                else:
                    logger.warning(f"PhishTank returned status {response.status}")
                    return None
                    
        except asyncio.TimeoutError:
            logger.warning(f"PhishTank API timeout for {url}")
            return None
        except Exception as e:
            logger.error(f"PhishTank API error: {e}")
            return None


# Singleton instance
api_manager = APIManager()
