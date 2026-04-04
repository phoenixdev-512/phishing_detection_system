from app.core.config import settings
from app.services.tis_calculator import TISResult
from app.services.scp_calculator import SCPResult
from networkx.readwrite import json_graph
import networkx as nx

class TGISAggregator:
    def __init__(self, 
                 url: str,
                 graph: nx.DiGraph,
                 tis_result: TISResult, 
                 scp_result: SCPResult, 
                 residual_heuristic_score: float, 
                 blacklist_hit: bool):
        self.url = url
        self.graph = graph
        self.tis_result = tis_result
        self.scp_result = scp_result
        self.residual_heuristic_score = residual_heuristic_score
        self.blacklist_hit = blacklist_hit
        
        self.alpha_w = settings.TGIS_ALPHA
        self.beta_w = settings.TGIS_BETA
        self.gamma_w = settings.TGIS_GAMMA

    def aggregate(self) -> dict:
        if self.blacklist_hit:
            tgis_final = 1.0
            status = "malicious"
            reasons = ["Blacklist direct match override."]
            recommendation = "MALICIOUS - Do not proceed."
        else:
            tis = self.tis_result.tis_score
            scp = self.scp_result.scp_score
            r = self.residual_heuristic_score
            
            tgis_final = self.alpha_w * tis + self.beta_w * scp + self.gamma_w * r
            
            reasons = [
                f"TIS component: {tis:.2f}",
                f"Legacy heuristic component: {r:.2f}"
            ]
            if self.scp_result.scp_activated:
                reasons.append(f"SCP activated: {len(self.scp_result.siblings_found)} siblings found contributing {scp:.2f}")

            if tgis_final < 0.30:
                status = "safe"
                recommendation = "SAFE - The domain graph aligns with baseline infrastructure."
            elif tgis_final < 0.60:
                status = "suspicious"
                recommendation = "WARNING - Anomalous infrastructure footprint."
            else:
                status = "malicious"
                recommendation = "MALICIOUS - High likelihood of phishing via Temporal Graph Isolation."

        # Compute graph summary
        graph_summary = {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "edge_counts": self.tis_result.observed_edges,
            "expected_edges": self.tis_result.expected_edges
        }

        # Format siblings list for UI
        siblings_ui = []
        for sib in self.scp_result.siblings_found:
            siblings_ui.append({
                "domain": sib,
                "weight": self.scp_result.sibling_weights.get(sib, 0.0),
                "is_known_malicious": (self.scp_result.sibling_weights.get(sib, 0.0) >= 1.0) # approx
            })

        return {
            "url": self.url,
            "status": status,
            "risk_score": int(tgis_final * 100),
            "verdict_source": "TGIS_Pipeline",
            "reasons": reasons,
            "recommendation": recommendation,
            "details": {},  # For latency timings or debugging metrics
            
            "tgis_score": tgis_final,
            "tis_score": self.tis_result.tis_score,
            "scp_score": self.scp_result.scp_score,
            "residual_heuristic": self.residual_heuristic_score,
            "domain_age_days": self.tis_result.domain_age_days,
            "scp_activated": self.scp_result.scp_activated,
            "siblings": siblings_ui,
            "graph_summary": graph_summary,
            "graph_json": json_graph.node_link_data(self.graph)
        }
