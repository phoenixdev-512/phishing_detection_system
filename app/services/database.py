import sqlite3
import math
import os
import logging

logger = logging.getLogger(__name__)

class PhishingDatabase:
    def __init__(self, db_path="phishing_db.sqlite"):
        self.db_path = db_path
        self.cache = set()
        self._initialize_db()
        self._load_cache()

    def _initialize_db(self):
        """Create the tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table 1: Known Malicious URLs (The "Blacklist")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                source TEXT,
                risk_score INTEGER,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table 2: Scan History (The "Log")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                status TEXT,
                risk_score INTEGER,
                verdict_source TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table 3: Domain Age Cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_age_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                creation_date TEXT,
                fetched_at REAL NOT NULL,
                ttl_seconds INTEGER DEFAULT 86400
            )
        ''')

        # Table 4: Graph Cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS graph_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                graph_json TEXT NOT NULL,
                tis_score REAL,
                scp_score REAL,
                fetched_at REAL NOT NULL,
                ttl_seconds INTEGER DEFAULT 300
            )
        ''')
        
        conn.commit()
        conn.close()

    def _load_cache(self):
        """On startup, load all existing DB URLs into RAM"""
        logger.info("Loading Database into Memory Cache...")
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM malicious_urls")
            count = cursor.fetchone()[0]
            
            if count > 100000:
                logger.warning(f"Database contains {count} URLs. Memory usage might be high.")
            
            cursor.execute("SELECT url FROM malicious_urls")
            rows = cursor.fetchall()
            for row in rows:
                self.cache.add(row[0])
            logger.info(f"Loaded {len(rows)} URLs into Memory Cache.")
            conn.close()
        except Exception as e:
            logger.error(f"Error loading cache: {e}")

    def add_url(self, url, source="manual", score=100):
        """Add a URL to both DB (Blacklist) and Cache"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO malicious_urls (url, source, risk_score) VALUES (?, ?, ?)", 
                           (url, source, score))
            conn.commit()
            conn.close()
            
            self.cache.add(url)
            return True
        except sqlite3.IntegrityError:
            return False  

    def check_url(self, url):
        if url not in self.cache:
            return None  

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url, risk_score, source FROM malicious_urls WHERE url = ?", (url,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                "found": True,
                "url": result[0],
                "risk_score": result[1],
                "source": result[2]
            }
        return None

    def log_scan(self, url, status, risk_score, source):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history (url, status, risk_score, verdict_source) VALUES (?, ?, ?, ?)",
                (url, status, risk_score, source)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")

    def get_recent_scans(self, limit=50):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, status, risk_score, verdict_source, timestamp FROM scan_history ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "url": r[0],
                "status": r[1],
                "risk_score": r[2],
                "verdict_source": r[3],
                "timestamp": r[4]
            }
            for r in rows
        ]

    def get_stats(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        stats["total_scans"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'malicious'")
        stats["malicious_detects"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'suspicious'")
        stats["suspicious_detects"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'safe'")
        stats["safe_detects"] = cursor.fetchone()[0]
        conn.close()
        return stats

    def get_malicious_domains(self):
        """Used for SCP calculator to match siblings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM malicious_urls")
        rows = cursor.fetchall()
        conn.close()
        # Parse logic assumes domains are stored, but they might be full URLs. 
        # This will need proper parsing before utilization.
        return set([r[0] for r in rows])


db_service = PhishingDatabase()
