import dataclasses
from dataclasses import dataclass
import networkx as nx
from app.core.config import settings

@dataclass
class TISResult:
    tis_score: float
    per_type_isolation: dict
    observed_edges: dict
    expected_edges: dict
    domain_age_days: float
    whois_failed: bool

class TISCalculator:
    def __init__(self, graph: nx.DiGraph, egd_baselines: dict):
        self.graph = graph
        self.baselines = egd_baselines
        self.weights = settings.TIS_WEIGHTS
        self.domain_age_days = egd_baselines.get("domain_age_days_used", 1.0)
        self.whois_failed = egd_baselines.get("whois_failed", False)

    def count_observed_edges(self, edge_type: str) -> int:
        return sum(1 for _, _, d in self.graph.edges(data=True) if d.get("edge_type") == edge_type)

    def compute_isolation_component(self, edge_type: str) -> float:
        expected = self.baselines.get(edge_type, 0.0)
        observed = self.count_observed_edges(edge_type)
        if expected <= 0.0:
            return 0.0
        numerator = max(0.0, expected - float(observed))
        result = numerator / expected
        return max(0.0, min(1.0, result))

    def compute_tis(self) -> TISResult:
        tis_score = 0.0
        per_type_isolation = {}
        observed_edges = {}
        expected_edges = {}
        
        edge_types = ["infrastructure", "certificate", "ownership", "routing"]
        
        for k in edge_types:
            i_k = self.compute_isolation_component(k)
            per_type_isolation[k] = i_k
            observed_edges[k] = self.count_observed_edges(k)
            expected_edges[k] = self.baselines.get(k, 0.0)
            tis_score += self.weights.get(k, 0.0) * i_k
            
        tis_score = max(0.0, min(1.0, tis_score))
        
        return TISResult(
            tis_score=tis_score,
            per_type_isolation=per_type_isolation,
            observed_edges=observed_edges,
            expected_edges=expected_edges,
            domain_age_days=self.domain_age_days,
            whois_failed=self.whois_failed
        )

