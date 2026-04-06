import json
import pickle
import sqlite3
import logging
import numpy as np
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from app.core.config import settings
from app.services.ml_signal import build_feature_vector, MODEL_PATH
from app.services.tis_calculator import TISResult
from app.services.scp_calculator import SCPResult

logger = logging.getLogger(__name__)

class MLTrainer:
    def __init__(self):
        # Determine database path
        db_url = getattr(settings, "DATABASE_URL", "phishing_db.sqlite")
        self.db_path = db_url.replace("sqlite:///", "")

    def fetch_labeled_data(self) -> tuple[list, list]:
        """
        Query scan_history where status IN ('safe','malicious') and tgis_score IS NOT NULL.
        Reconstruct a minimal TISResult and SCPResult from stored fields.
        Returns:
            X_features: list of feature vectors.
            y_labels: list of labels (0 = safe, 1 = malicious).
        """
        X_features = []
        y_labels = []

        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Ensure columns exist to avoid query errors. If they don't, we add them just in case,
            # or simply select what we can. The prompt states "stored tgis_score, scp_score, tis_score fields".
            # We'll try to select them. Some might be missing if schema is older, so we use PRAGMA or just try/except.
            try:
                # Add columns if they don't exist (migration)
                cursor.execute("ALTER TABLE scan_history ADD COLUMN tis_score REAL")
                cursor.execute("ALTER TABLE scan_history ADD COLUMN scp_score REAL")
                cursor.execute("ALTER TABLE scan_history ADD COLUMN residual_heuristic REAL")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # Columns already exist

            query = """
                SELECT 
                    url, status, tgis_score, 
                    tis_score, scp_score, residual_heuristic
                FROM scan_history 
                WHERE status IN ('safe', 'malicious') 
                  AND tgis_score IS NOT NULL
            """
            cursor.execute(query)
            rows = cursor.fetchall()

            for row in rows:
                status = row["status"]
                label = 1 if status == "malicious" else 0

                # Reconstruct minimal results from stored scores
                # Since we don't have full graph metrics stored, we use zero-filled defaults
                # for the non-score attributes that `build_feature_vector` expects.
                tis = TISResult(
                    tis_score=float(row["tis_score"] or 0.0),
                    per_type_isolation={},
                    observed_edges={},
                    expected_edges={},
                    domain_age_days=1.0,  # default placeholder
                    whois_failed=False
                )
                
                scp_activated = row["scp_score"] is not None
                scp = SCPResult(
                    scp_score=float(row["scp_score"] or 0.0),
                    siblings_found=[],
                    sibling_weights={},
                    scp_activated=scp_activated
                )
                
                res_heuristic = float(row["residual_heuristic"] or 0.0)
                
                # Mock node and edge counts
                graph_node_count = 10
                graph_edge_count = 10

                features = build_feature_vector(
                    tis_result=tis,
                    scp_result=scp,
                    residual_heuristic=res_heuristic,
                    graph_node_count=graph_node_count,
                    graph_edge_count=graph_edge_count
                )
                
                X_features.append(features)
                y_labels.append(label)

        except Exception as e:
            logger.error(f"Failed to fetch labeled data: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

        return X_features, y_labels

    def train(self) -> dict:
        """
        Trains a LogisticRegression model using the historical scan data.
        Saves the resulting Pipeline (scaler + model) to MODEL_PATH.
        """
        X, y = self.fetch_labeled_data()
        
        if len(X) < 50:
            logger.warning(f"Insufficient data for training. Found {len(X)} samples, need at least 50.")
            return {"status": "insufficient_data"}

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced"))
        ])
        
        pipeline.fit(X_train, y_train)
        
        y_pred = pipeline.predict(X_test)
        report = classification_report(y_test, y_pred)
        
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(pipeline, f)
            
        logger.info(f"Model trained successfully. Report:\n{report}")
        return {"status": "trained", "report": report, "n_samples": len(X)}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    trainer = MLTrainer()
    result = trainer.train()
    print(result.get("report", result.get("status")))
