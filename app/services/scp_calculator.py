from dataclasses import dataclass
import networkx as nx
from app.services.tis_calculator import TISResult, TISCalculator

@dataclass
class SCPResult:
    scp_score: float
    siblings_found: list      
    sibling_weights: dict     
    scp_activated: bool       

class SCPCalculator:
    def __init__(self, root_node: str, graph: nx.DiGraph, tis_result: TISResult, known_malicious_set: set):
        self.root_node = root_node
        self.graph = graph
        self.tis_result = tis_result
        self.known_malicious_set = known_malicious_set

    def find_siblings(self) -> list[str]:
        # Sibling must share >= 2 infrastructure edge types with candidate domain d.
        # Wait, the prompt says ">= 2 distinct edge types".
        siblings = []
        if self.root_node not in self.graph:
            return siblings

        root_neighbors = set(self.graph.successors(self.root_node))
        
        for node in self.graph.nodes():
            if node == self.root_node:
                continue
            
            # Find nodes that act as "siblings" (domains that share the same infrastructure)
            # Typically a sibling is another domain node. Is it a san_sibling? 
            # We look for nodes that have out_edges to the shared infrastructure.
            if not self.graph.out_degree(node):
                 continue

            node_out_neighbors = set(self.graph.successors(node))
            shared_neighbors = root_neighbors.intersection(node_out_neighbors)
            
            # Count distinct edge types among shared edges
            shared_edge_types = set()
            for neighbor in shared_neighbors:
                edge_data = self.graph.get_edge_data(node, neighbor)
                if edge_data and "edge_type" in edge_data:
                    shared_edge_types.add(edge_data["edge_type"])
                    
                root_edge_data = self.graph.get_edge_data(self.root_node, neighbor)
                if root_edge_data and "edge_type" in root_edge_data:
                    shared_edge_types.add(root_edge_data["edge_type"])

            if len(shared_edge_types) >= 2 or self._is_san_sibling(node):
                siblings.append(node)
                
        return siblings

    def _is_san_sibling(self, node: str) -> bool:
        # fallback if they are directly connected by certificate_sibling
        if self.graph.has_edge(self.root_node, node):
            if self.graph.get_edge_data(self.root_node, node).get("edge_type") == "certificate_sibling":
                return True
        return False

    def jaccard_similarity(self, node_a: str, node_b: str) -> float:
        if node_a not in self.graph or node_b not in self.graph:
            return 0.0
            
        set_a = set(self.graph.successors(node_a))
        set_b = set(self.graph.successors(node_b))
        
        union_size = len(set_a.union(set_b))
        if union_size == 0:
            return 0.0
            
        intersection_size = len(set_a.intersection(set_b))
        return intersection_size / union_size

    def compute_sibling_weight(self, sibling: str) -> float:
        j_val = self.jaccard_similarity(self.root_node, sibling)
        
        m_s = 1.0 if sibling in self.known_malicious_set else 0.0
        
        # Lightweight TIS for sibling (assume same expected baseline and age for simplicity)
        sib_tis_calc = TISCalculator(
            root_node=sibling,
            graph=self.graph,
            egd_baselines=self.tis_result.expected_edges,
            domain_age_days=self.tis_result.domain_age_days,
            whois_failed=self.tis_result.whois_failed
        )
        sib_tis = sib_tis_calc.compute_tis().tis_score
        
        return j_val * (m_s + 0.5 * sib_tis)

    def compute_scp(self) -> SCPResult:
        if self.tis_result.domain_age_days >= 1.0:
            return SCPResult(
                scp_score=0.0,
                siblings_found=[],
                sibling_weights={},
                scp_activated=False
            )
            
        siblings = self.find_siblings()
        sibling_weights = {}
        sum_w = 0.0
        
        for sibling in siblings:
            w_s = self.compute_sibling_weight(sibling)
            sibling_weights[sibling] = w_s
            sum_w += w_s
            
        norm_factor = max(1, len(siblings))
        scp_score = min(1.0, sum_w / norm_factor)
        
        return SCPResult(
            scp_score=scp_score,
            siblings_found=siblings,
            sibling_weights=sibling_weights,
            scp_activated=True
        )
