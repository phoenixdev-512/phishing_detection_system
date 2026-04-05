import dataclasses
from dataclasses import dataclass
import networkx as nx
from app.core.config import settings
from app.services.tis_calculator import TISCalculator, TISResult

@dataclass
class SCPResult:
    scp_score: float
    siblings_found: list
    sibling_weights: dict
    scp_activated: bool

class SCPCalculator:
    def __init__(self, graph: nx.DiGraph, tis_result: TISResult, known_malicious_set: set[str], candidate_domain: str):
        self.graph = graph
        self.tis_result = tis_result
        self.known_malicious_set = known_malicious_set
        self.candidate_domain = candidate_domain
        self.threshold = settings.SCP_AGE_THRESHOLD_DAYS

    def find_siblings(self) -> list[str]:
        n_candidate = set(self.graph.successors(self.candidate_domain)) if self.candidate_domain in self.graph else set()
        siblings = []
        
        for s in self.graph.nodes:
            if s == self.candidate_domain:
                continue
                
            n_s = set(self.graph.successors(s)) | set(self.graph.predecessors(s))
            shared = n_candidate.intersection(n_s)
            
            if not shared:
                continue
                
            edge_types = set()
            for shared_node in shared:
                if self.graph.has_edge(self.candidate_domain, shared_node):
                    edge_data = self.graph.get_edge_data(self.candidate_domain, shared_node)
                    if "edge_type" in edge_data:
                        edge_types.add(edge_data["edge_type"])
                        
                if self.graph.has_edge(s, shared_node):
                    edge_data = self.graph.get_edge_data(s, shared_node)
                    if "edge_type" in edge_data:
                        edge_types.add(edge_data["edge_type"])
                        
            if len(edge_types) >= 2:
                siblings.append(str(s))
                
        return siblings

    def jaccard_similarity(self, node_a: str, node_b: str) -> float:
        if node_a not in self.graph or node_b not in self.graph:
            return 0.0
            
        n_a = (set(self.graph.successors(node_a)) | set(self.graph.predecessors(node_a))) - {node_a}
        n_b = (set(self.graph.successors(node_b)) | set(self.graph.predecessors(node_b))) - {node_b}
        
        intersection = n_a & n_b
        union = n_a | n_b
        
        if not union:
            return 0.0
            
        return len(intersection) / len(union)

    def _compute_sibling_tis(self, sibling: str) -> float:
        try:
            from app.services.egd_model import EGDModel
            
            if sibling not in self.graph:
                return 0.5
                
            neighbors = set(self.graph.successors(sibling)) | set(self.graph.predecessors(sibling))
            subgraph_nodes = neighbors | {sibling}
            sibling_graph = self.graph.subgraph(subgraph_nodes).copy()
            
            egd_model = EGDModel()
            baselines = egd_model.compute_all_baselines(1.0)
            
            tis_calc = TISCalculator(sibling_graph, baselines)
            tis_res = tis_calc.compute_tis()
            
            return tis_res.tis_score
        except Exception:
            return 0.5

    def compute_sibling_weight(self, sibling: str) -> float:
        j = self.jaccard_similarity(self.candidate_domain, sibling)
        m = 1.0 if sibling in self.known_malicious_set else 0.0
        tis_s = self._compute_sibling_tis(sibling)
        
        return j * (m + 0.5 * tis_s)

    def compute_scp(self) -> SCPResult:
        if self.tis_result.domain_age_days >= self.threshold:
            return SCPResult(
                scp_score=0.0,
                siblings_found=[],
                sibling_weights={},
                scp_activated=False
            )
            
        siblings = self.find_siblings()
        
        if not siblings:
            return SCPResult(
                scp_score=0.0,
                siblings_found=[],
                sibling_weights={},
                scp_activated=True
            )
            
        weights = {}
        for s in siblings:
            weights[s] = self.compute_sibling_weight(s)
            
        scp_score = min(1.0, sum(weights.values()) / max(1, len(siblings)))
        
        return SCPResult(
            scp_score=scp_score,
            siblings_found=siblings,
            sibling_weights=weights,
            scp_activated=True
        )

