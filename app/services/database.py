import json
import logging
import sqlite3
import time

logger = logging.getLogger(__name__)


class PhishingDatabase:
    def get_recent_history(self, limit=20):
        return self.get_recent_scans(limit)

    def __init__(self, db_path="phishing_db.sqlite"):
        self.db_path = db_path
        self.cache = set()
        self._initialize_db()
        self._load_cache()

    def _initialize_db(self):
        """Create tables and apply schema migrations."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Table 1: Known Malicious URLs (blacklist)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS malicious_urls (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                url        TEXT UNIQUE NOT NULL,
                source     TEXT,
                risk_score INTEGER,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table 2: Scan History
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                url            TEXT NOT NULL,
                status         TEXT,
                risk_score     INTEGER,
                verdict_source TEXT,
                timestamp      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration: add tgis_score column if it doesn't exist yet
        try:
            cursor.execute('ALTER TABLE scan_history ADD COLUMN tgis_score REAL')
        except sqlite3.OperationalError:
            pass  # Column already exists on subsequent startups

        # Table 3: Domain Age Cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_age_cache (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                domain        TEXT UNIQUE NOT NULL,
                creation_date TEXT,
                fetched_at    REAL NOT NULL,
                ttl_seconds   INTEGER DEFAULT 86400
            )
        ''')

        # Table 4: Graph Cache
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS graph_cache (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT UNIQUE NOT NULL,
                graph_json  TEXT NOT NULL,
                tis_score   REAL,
                scp_score   REAL,
                fetched_at  REAL NOT NULL,
                ttl_seconds INTEGER DEFAULT 300
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_history_id INTEGER,
                url             TEXT NOT NULL,
                original_status TEXT NOT NULL,
                corrected_status TEXT NOT NULL,
                analyst_note    TEXT,
                submitted_at    REAL NOT NULL,
                FOREIGN KEY (scan_history_id) REFERENCES scan_history(id)
            )
        ''')

        conn.commit()
        conn.close()

    def _load_cache(self):
        """On startup, load all existing blacklist URLs into in-memory set."""
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

    # ------------------------------------------------------------------
    # Blacklist methods
    # ------------------------------------------------------------------

    def add_url(self, url, source="manual", score=100):
        """Add a URL to both DB blacklist and in-memory cache."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO malicious_urls (url, source, risk_score) VALUES (?, ?, ?)",
                (url, source, score)
            )
            conn.commit()
            conn.close()
            self.cache.add(url)
            return True
        except sqlite3.IntegrityError:
            return False

    def check_url(self, url):
        """Return blacklist record for url, or None if not found."""
        if url not in self.cache:
            return None

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, risk_score, source FROM malicious_urls WHERE url = ?",
            (url,)
        )
        result = cursor.fetchone()
        conn.close()

        if result:
            return {"found": True, "url": result[0], "risk_score": result[1], "source": result[2]}
        return None

    def get_malicious_domains(self):
        """Return set of all known-malicious URL strings (used by SCP calculator)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM malicious_urls")
        rows = cursor.fetchall()
        conn.close()
        return set(r[0] for r in rows)

    # ------------------------------------------------------------------
    # Scan history methods
    # ------------------------------------------------------------------

    def log_scan(self, url, status, risk_score, source, tgis_score: float | None = None):
        """Insert a scan result into scan_history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scan_history (url, status, risk_score, verdict_source, tgis_score) VALUES (?, ?, ?, ?, ?)",
                (url, status, risk_score, source, tgis_score)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")

    def get_recent_scans(self, limit=50):
        """Return the most recent scan records."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT url, status, risk_score, verdict_source, timestamp, tgis_score "
            "FROM scan_history ORDER BY id DESC LIMIT ?",
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
                "timestamp": r[4],
                "tgis_score": r[5],
            }
            for r in rows
        ]

    def get_stats(self):
        """Return aggregate scan statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}
        cursor.execute("SELECT COUNT(*) FROM scan_history")
        stats["total_scans"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'malicious'")
        stats["malicious_count"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'suspicious'")
        stats["suspicious_count"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'safe'")
        stats["safe_count"] = cursor.fetchone()[0]

        # Proxy: rows with a tgis_score recorded indicate TGIS pipeline ran (SCP may have been active)
        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE tgis_score IS NOT NULL")
        stats["scp_activations"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM scan_history WHERE verdict_source = 'Blacklist'")
        stats["blacklist_hits"] = cursor.fetchone()[0]

        # Placeholder until a dedicated timing column is added
        stats["avg_pipeline_ms"] = 0.0

        conn.close()
        return stats

    # ------------------------------------------------------------------
    # Domain age cache methods
    # ------------------------------------------------------------------

    def get_domain_age(self, domain: str) -> str | None:
        """Return cached creation_date string, or '__CACHE_MISS__' if expired/absent."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT creation_date FROM domain_age_cache "
                "WHERE domain = ? AND (fetched_at + ttl_seconds) > ?",
                (domain, time.time())
            )
            row = cursor.fetchone()
            conn.close()
            if row is not None:
                return row[0]  # may be None if WHOIS failed when cached
            return "__CACHE_MISS__"
        except Exception as e:
            logger.error(f"get_domain_age error: {e}")
            return "__CACHE_MISS__"

    def set_domain_age(self, domain: str, creation_date: str | None) -> None:
        """Insert or replace a domain age cache entry."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO domain_age_cache (domain, creation_date, fetched_at) VALUES (?, ?, ?)",
                (domain, creation_date, time.time())
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"set_domain_age error: {e}")

    # ------------------------------------------------------------------
    # Graph cache methods
    # ------------------------------------------------------------------

    def get_graph(self, domain: str) -> dict | None:
        """Return deserialized graph dict from cache, or None on miss/expiry."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT graph_json FROM graph_cache "
                "WHERE domain = ? AND (fetched_at + ttl_seconds) > ?",
                (domain, time.time())
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                return json.loads(row[0])
            return None
        except Exception as e:
            logger.error(f"get_graph error: {e}")
            return None

    def set_graph(
        self,
        domain: str,
        graph_json_dict: dict,
        tis_score: float | None,
        scp_score: float | None,
    ) -> None:
        """Insert or replace a serialized graph in the cache."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO graph_cache "
                "(domain, graph_json, tis_score, scp_score, fetched_at) VALUES (?, ?, ?, ?, ?)",
                (domain, json.dumps(graph_json_dict), tis_score, scp_score, time.time())
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"set_graph error: {e}")

    # ------------------------------------------------------------------
    # Feedback methods
    # ------------------------------------------------------------------

    def submit_feedback(self, url: str, original_status: str,
                        corrected_status: str, note: str = "") -> int:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO analyst_feedback 
                   (url, original_status, corrected_status, analyst_note, submitted_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (url, original_status, corrected_status, note, time.time())
            )
            row_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return row_id
        except Exception as e:
            logger.error(f"submit_feedback error: {e}")
            return -1

    def get_feedback(self, limit: int = 50) -> list[dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM analyst_feedback ORDER BY submitted_at DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"get_feedback error: {e}")
            return []


db_service = PhishingDatabase()

DatabaseService = PhishingDatabase
def get_db():
    return db_service
