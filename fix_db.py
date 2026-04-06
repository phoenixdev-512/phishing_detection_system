import sqlite3
with open("app/services/database.py", "a") as f:
    f.write("""
    def get_recent_history(self, limit: int = 20):
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT url, status, risk_score, tgis_score, verdict_source, timestamp FROM scan_history ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error fetching history: {e}")
            return []

    def get_stats(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            total = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'suspicious'")
            suspicious = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'safe'")
            safe = cursor.fetchone()[0] or 0

            conn.close()
            return {
                "total_scans": total,
                "suspicious_detected": suspicious,
                "safe_detected": safe,
            }
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Error fetching stats: {e}")
            return {"total_scans": 0, "suspicious_detected": 0, "safe_detected": 0}

DatabaseService = PhishingDatabase
def get_db():
    return db_service
""")
