import math
from app.core.config import settings

class EGDModel:
    def __init__(self):
        self.params = settings.EGD_PARAMS
        self.baselines = {}
        self.clamped_age_days = 1.0
        self.whois_failed = False

    def expected_edges(self, edge_type: str, domain_age_days: float) -> float:
        if edge_type not in self.params:
            return 0.0
        
        # Clamp age
        a = max(0.0, min(float(domain_age_days), 3650.0))
        
        p = self.params[edge_type]
        alpha = p["alpha"]
        beta = p["beta"]
        gamma = p["gamma"]
        
        # Piecewise exponential saturation function
        return alpha * (1 - math.exp(-beta * a)) + gamma

    def compute_all_baselines(self, domain_age_days: float | None) -> dict:
        self.whois_failed = False
        if domain_age_days is None:
            self.clamped_age_days = 1.0
            self.whois_failed = True
        else:
            self.clamped_age_days = max(0.0, min(float(domain_age_days), 3650.0))
            
        self.baselines = {
            edge_type: self.expected_edges(edge_type, self.clamped_age_days)
            for edge_type in self.params.keys()
        }
        
        # Merge whois_failed into the returned baselines dict per spec
        if self.whois_failed:
            self.baselines["whois_failed"] = True
            
        return self.baselines

    def serialize(self) -> dict:
        return {
            "parameters_used": self.params,
            "computed_baselines": self.baselines
        }

