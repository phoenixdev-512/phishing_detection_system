import math
import json
import logging
from pathlib import Path
from app.core.config import settings

logger = logging.getLogger(__name__)

class EGDModel:
    def __init__(self):
        self.params = getattr(settings, "EGD_PARAMS", {}).copy()
        
        # Attempt to load dynamically trained ML params
        trained_params_path = Path("data/egd_trained_params.json")
        if trained_params_path.exists():
            try:
                with open(trained_params_path, "r") as f:
                    trained_data = json.load(f)
                
                # Merge dynamically trained params into config ones
                for key, val in trained_data.items():
                    if key in self.params and isinstance(val, dict):
                        self.params[key].update({
                            k: v for k, v in val.items() if k in ["alpha", "beta", "gamma"]
                        })
                logger.info("Loaded trained EGD parameters from disk.")
            except Exception as e:
                logger.warning(f"Failed to load trained EGD params: {e}. Falling back to config.")
        
        required_keys = ["infrastructure", "certificate", "ownership", "routing"]
        for key in required_keys:
            if key not in self.params:
                raise ValueError(f"Missing required key '{key}' in EGD_PARAMS")

    def expected_edges(self, edge_type: str, domain_age_days: float) -> float:
        if edge_type not in self.params:
            raise KeyError(f"Invalid edge_type: {edge_type}")
        
        a = max(0.0, min(float(domain_age_days), 3650.0))
        params = self.params[edge_type]
        alpha = params["alpha"]
        beta = params["beta"]
        gamma = params["gamma"]
        
        result = alpha * (1 - math.exp(-beta * a)) + gamma
        return result

    def compute_all_baselines(self, domain_age_days: float, whois_failed: bool = False) -> dict:
        if whois_failed:
            age_to_use = 1.0
        else:
            age_to_use = max(0.0, min(float(domain_age_days), 3650.0))

        baselines = {}
        for edge_type in ["infrastructure", "certificate", "ownership", "routing"]:
            baselines[edge_type] = self.expected_edges(edge_type, age_to_use)
        
        baselines["domain_age_days_used"] = age_to_use
        baselines["whois_failed"] = whois_failed
        return baselines

    def serialize(self) -> dict:
        import copy
        return {
            "model_params": copy.deepcopy(self.params),
            "note": "Call compute_all_baselines(age) for age-specific expected counts"
        }

