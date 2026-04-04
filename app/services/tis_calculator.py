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
    def __init__(self, root_node: str, graph: nx.DiGraph, egd_baselines: dict, domain_age_days: float, whois_failed: bool):
        self.root_node = root_node
        self.graph = graph
        self.egd_baselines = egd_baselines
        self.weights = settings.TIS_WEIGHTS
        self.domain_age_days = domain_age_days
        self.whois_failed = whois_failed
        
        # Compute observed edge counts directly from graph
        self.observed_edges = {
            "infrastructure": self.count_observed_edges("infrastructure"),
            "certificate": self.count_observed_edges("certificate"),
            "ownership": self.count_observed_edges("ownership"),
            "routing": self.count_observed_edges("routing")
        }

    def count_observed_edges(self, edge_type: str) -> int:
        count = 0
        if self.root_node in self.graph:
            for u, v, data in self.graph.out_edges(self.root_node, data=True):
                if data.get("edge_type") == edge_type:
                    count += 1
        return count

    def compute_isolation_component(self, edge_type: str) -> float:
        expected = self.egd_baselines.get(edge_type, 0.0)
        observed = self.observed_edges.get(edge_type, 0)
        
        if expected <= 0.0:
            return 0.0
            
        isolation = max(0.0, expected - observed) / expected
        return min(1.0, isolation) # clamp to 1.0

    def compute_tis(self) -> TISResult:
        per_type_isolation = {}
        composite_tis = 0.0
        
        for edge_type, weight in self.weights.items():
            i_k = self.compute_isolation_component(edge_type)
            per_type_isolation[edge_type] = i_k
            composite_tis += weight * i_k
            
        return TISResult(
            tis_score=min(1.0, max(0.0, composite_tis)),
            per_type_isolation=per_type_isolation,
            observed_edges=self.observed_edges,
            expected_edges=self.egd_baselines,
            domain_age_days=self.domain_age_days,
            whois_failed=self.whois_failed
        )
