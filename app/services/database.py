import sqlite3
import mmh3
from bitarray import bitarray
import math
import os
import logging

logger = logging.getLogger(__name__)


class BloomFilter:
    def __init__(self, items_count, fp_prob):
        """
        items_count: expected number of items (n)
        fp_prob: desired false positive probability (p)
        """
        self.fp_prob = fp_prob
        self.size = self.get_size(items_count, fp_prob)
        self.hash_count = self.get_hash_count(self.size, items_count)
        
        # Initialize bit array with all zeros
        self.bit_array = bitarray(self.size)
        self.bit_array.setall(0)

    def add(self, item):
        """Add an item to the filter"""
        for i in range(self.hash_count):
            # Create k distinct hash functions
            digest = mmh3.hash(item, i) % self.size
            self.bit_array[digest] = 1

    def check(self, item):
        """Check for existence of an item"""
        for i in range(self.hash_count):
            digest = mmh3.hash(item, i) % self.size
            if self.bit_array[digest] == 0:
                return False  # Definitely not present
        return True  # Possibly present

    @classmethod
    def get_size(cls, n, p):
        """Return the size of bit array (m) to use"""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    @classmethod
    def get_hash_count(cls, m, n):
        """Return the hash function count (k) to use"""
        k = (m / n) * math.log(2)
        return int(k)


class PhishingDatabase:
    def __init__(self, db_path="phishing_db.sqlite"):
        self.db_path = db_path
        # Initialize Bloom Filter (Assuming capacity for 100k URLs, 5% false positive)
        self.bloom = BloomFilter(100000, 0.05)
        self._initialize_db()
        self._load_bloom_filter()

    def _initialize_db(self):
        """Create the table if it doesn't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                source TEXT,
                risk_score INTEGER,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def _load_bloom_filter(self):
        """On startup, load all existing DB URLs into RAM (Bloom Filter)"""
        logger.info("Loading Database into Bloom Filter...")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM malicious_urls")
        rows = cursor.fetchall()
        for row in rows:
            self.bloom.add(row[0])
        logger.info(f"Loaded {len(rows)} URLs into Bloom Filter.")
        conn.close()

    def add_url(self, url, source="manual", score=100):
        """Add a URL to both DB and Bloom Filter"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO malicious_urls (url, source, risk_score) VALUES (?, ?, ?)", 
                           (url, source, score))
            conn.commit()
            conn.close()
            
            # Update Bloom Filter immediately
            self.bloom.add(url)
            return True
        except sqlite3.IntegrityError:
            return False  # URL already exists

    def check_url(self, url):
        """
        The Fast Lookup Layer:
        1. Check Bloom Filter (Memory) -> Fast fail
        2. Check SQLite (Disk) -> Exact confirmation
        """
        # Step 1: Bloom Filter Check
        if not self.bloom.check(url):
            return None  # Definitely safe (not in our DB)

        # Step 2: Database Confirmation (only if Bloom says "Maybe")
        # This prevents disk I/O for 99% of safe traffic
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


# Singleton instance
db_service = PhishingDatabase()
