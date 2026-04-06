import json
import logging
import sqlite3
from pathlib import Path
import numpy as np
from scipy.optimize import curve_fit
from app.core.config import settings

logger = logging.getLogger(__name__)

DB_PATH = getattr(settings, "DATABASE_URL", "phishing_db.sqlite").replace("sqlite:///", "")
PARAMS_PATH = Path("data/egd_trained_params.json")

def exponential_model(x, alpha, beta, gamma):
    """Piecewise exponential curve: E_k(a) = alpha * (1 - exp(-beta * a)) + gamma"""
    return alpha * (1.0 - np.exp(-beta * x)) + gamma

class EGDTrainer:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.edge_types = ["infrastructure", "certificate", "ownership", "routing"]

    def fetch_training_data(self) -> dict:
        """
        Pulls known-safe subgraph data from scan_history and graph_cache.
        Returns a dict mapping edge_type to a list of (age_days, edge_count) tuples.
        """
        data = {et: ([], []) for et in self.edge_types}
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Subquery to get known-safe domains
            cursor.execute("""
                SELECT s.url, g.domain, g.graph_json, a.creation_date 
                FROM scan_history s
                JOIN graph_cache g ON s.url LIKE '%' || g.domain || '%'
                LEFT JOIN domain_age_cache a ON g.domain = a.domain
                WHERE s.status = 'safe'
            """)
            rows = cursor.fetchall()
            
            for row in rows:
                try:
                    graph_dict = json.loads(row["graph_json"])
                    import networkx as nx
                    from datetime import datetime
                    
                    graph = nx.node_link_graph(graph_dict)
                    domain = row["domain"]
                    creation_date_str = row["creation_date"]
                    
                    if not creation_date_str:
                        continue
                        
                    creation_dt = datetime.fromisoformat(creation_date_str)
                    age_days = max(0.1, (datetime.utcnow() - creation_dt.replace(tzinfo=None)).total_seconds() / 86400)
                    
                    # Count actual edges by type
                    counts = {et: 0 for et in self.edge_types}
                    for _, _, d in graph.edges(data=True):
                        e_type = d.get("edge_type", "")
                        if e_type in counts:
                            counts[e_type] += 1
                            
                    for et in self.edge_types:
                        data[et][0].append(age_days)
                        data[et][1].append(counts[et])
                        
                except Exception as e:
                    logger.debug(f"Skipping row due to error: {e}")
                    
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Database error during training data fetch: {e}")
            
        return data

    def fit_edge_type(self, ages: list, counts: list, default_params: dict) -> dict:
        """Fits the exponential curve to the data safely, falling back to defaults if needed."""
        x_data = np.array(ages)
        y_data = np.array(counts)
        
        if len(x_data) < 10:
            return default_params
            
        try:
            # Bounds: alpha > 0, beta > 0, gamma >= 0
            bounds = ([0.0, 0.0, 0.0], [500.0, 1.0, 100.0])
            p0 = [default_params["alpha"], default_params["beta"], default_params["gamma"]]
            popt, _ = curve_fit(exponential_model, x_data, y_data, p0=p0, bounds=bounds, maxfev=2000)
            return {"alpha": float(popt[0]), "beta": float(popt[1]), "gamma": float(popt[2])}
        except Exception as e:
            logger.warning(f"Failed to fit curve: {e}. Falling back to default.")
            return default_params

    def train(self):
        data = self.fetch_training_data()
        trained_params = {}
        
        default_egd = getattr(settings, "EGD_PARAMS", {})
        
        for et in self.edge_types:
            ages, counts = data[et]
            default_p = default_egd.get(et, {"alpha": 10.0, "beta": 0.05, "gamma": 1.0})
            trained_params[et] = self.fit_edge_type(ages, counts, default_p)
            
        self.save_trained_params(trained_params)
        return trained_params
        
    def save_trained_params(self, params: dict):
        PARAMS_PATH.parent.mkdir(exist_ok=True)
        with open(PARAMS_PATH, "w") as f:
            json.dump(params, f, indent=4)
        logger.info(f"Trained EGD parameters saved to {PARAMS_PATH}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    trainer = EGDTrainer()
    res = trainer.train()
    print("Training complete. Parameters:")
    print(json.dumps(res, indent=2))
