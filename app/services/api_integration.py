import aiohttp
import asyncio
import time
import logging
from typing import Optional, Dict
from collections import OrderedDict
from app.core.config import settings

logger = logging.getLogger(__name__)

# A simple in-memory cache with size limit: { "url": {"result": ..., "timestamp": ...} }
# In production, use Redis.
CACHE_TTL = 300  # 5 minutes
MAX_CACHE_SIZE = 1000  # Maximum cache entries


class LRUCache:
    """Thread-safe LRU cache with TTL support"""
    def __init__(self, max_size: int, ttl: int):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Dict]:
        async with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                # Check if expired
                if time.time() - entry["timestamp"] < self.ttl:
                    # Move to end (most recently used)
                    self.cache.move_to_end(key)
                    return entry["result"]
                else:
                    # Expired, remove it
                    del self.cache[key]
            return None
    
    async def set(self, key: str, value: Dict):
        async with self.lock:
            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size and key not in self.cache:
                self.cache.popitem(last=False)
            
            self.cache[key] = {
                "result": value,
                "timestamp": time.time()
            }
            self.cache.move_to_end(key)


api_cache = LRUCache(MAX_CACHE_SIZE, CACHE_TTL)


class APIManager:
    def __init__(self):
        self.google_api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.phishtank_url = "https://checkurl.phishtank.com/checkurl/"

    async def check_url(self, url: str) -> Optional[Dict]:
        """
        Orchestrates parallel checks to all external providers.
        """
        # 1. Check Cache first
        cached_result = await api_cache.get(url)
        if cached_result:
            logger.info(f"Cache Hit for {url}")
            return cached_result

        # 2. Define the tasks (Parallel Execution)
        async with aiohttp.ClientSession() as session:
            tasks = [
                self._check_google_safe_browsing(session, url),
                self._check_phishtank(session, url),
            ]
            
            # Run all checks in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # 3. Process Results
        # Log any exceptions that occurred
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                api_name = ["Google Safe Browsing", "PhishTank"][i]
                logger.warning(f"{api_name} check failed: {result}")
        
        # If ANY API says "malicious", we flag it
        for result in results:
            if isinstance(result, dict) and result.get("is_malicious"):
                # Cache the result
                await api_cache.set(url, result)
                return result

        # All APIs say safe or failed
        safe_result = {
            "is_malicious": False,
            "source": "External APIs",
            "risk_score": 0
        }
        
        # Cache safe result too
        await api_cache.set(url, safe_result)
        
        return safe_result

    async def _check_google_safe_browsing(self, session: aiohttp.ClientSession, url: str) -> Optional[Dict]:
        """
        Check Google Safe Browsing API.
        Note: This is a MOCK implementation. Real implementation requires API key.
        """
        if not self.google_api_key:
            logger.debug("Google Safe Browsing API key not configured - skipping check")
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
        #     async with session.post(api_url, json=payload, timeout=aiohttp.ClientTimeout(total=5)) as response:
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
        logger.debug(f"Mock Google Safe Browsing check for {url}")
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
                    try:
                        result = await response.json()
                    except aiohttp.ContentTypeError as e:
                        logger.error(f"PhishTank returned invalid JSON: {e}")
                        return None
                    
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
