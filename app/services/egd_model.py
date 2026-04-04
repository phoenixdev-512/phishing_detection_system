import math
from app.core.config import settings

class EGDModel:
    def __init__(self, domain_age_days: float | None):
        self.params = settings.EGD_PARAMS
        self.whois_failed = False
        
        if domain_age_days is None:
            self.whois_failed = True
            self.domain_age_days = 1.0
        else:
            self.domain_age_days = max(0.0, min(float(domain_age_days), 3650.0))
            
        self.baselines = {}

    def expected_edges(self, edge_type: str, domain_age_days: float) -> float:
        if edge_type not in self.params:
            return 0.0
        
        p = self.params[edge_type]
        a = domain_age_days
        alpha = p["alpha"]
        beta = p["beta"]
        gamma = p["gamma"]
        
        # Piecewise exponential saturation function
        return alpha * (1 - math.exp(-beta * a)) + gamma

    def compute_all_baselines(self) -> dict[str, float]:
        self.baselines = {
            edge_type: self.expected_edges(edge_type, self.domain_age_days)
            for edge_type in self.params.keys()
        }
        return self.baselines

    def serialize(self) -> dict:
        return {
            "whois_failed": self.whois_failed,
            "clamped_age_days": self.domain_age_days,
            "parameters_used": self.params,
            "computed_baselines": self.baselines
        }
