# FILE 3: tests/test_scp_calculator.py
import pytest
import networkx as nx
from app.services.scp_calculator import SCPCalculator, SCPResult
from app.services.tis_calculator import TISResult

def build_tis_result(age: float) -> TISResult:
    return TISResult(
        tis_score=0.5,
        per_type_isolation={"infrastructure": 0.5, "certificate": 0.5, "ownership": 0.5, "routing": 0.5},
        observed_edges={"infrastructure": 0, "certificate": 0, "ownership": 0, "routing": 0},
        expected_edges={"infrastructure": 1.0, "certificate": 1.0, "ownership": 1.0, "routing": 1.0},
        domain_age_days=age,
        whois_failed=False
    )

def test_scp_deactivated_for_old_domain():
    tis_res = build_tis_result(2.0)
    calc = SCPCalculator(nx.DiGraph(), tis_res, set(), "test.com")
    calc.threshold = 1.0
    
    result = calc.compute_scp()
    assert result.scp_activated is False
    assert result.scp_score == 0.0

def test_scp_activated_for_new_domain():
    tis_res = build_tis_result(0.5)
    g = nx.DiGraph()
    g.add_node("test.com")
    g.add_node("sibling.com")
    g.add_node("shared_ip")
    g.add_node("shared_ca")
    
    g.add_edge("test.com", "shared_ip", edge_type="infrastructure")
    g.add_edge("test.com", "shared_ca", edge_type="certificate")
    g.add_edge("sibling.com", "shared_ip", edge_type="infrastructure")
    g.add_edge("sibling.com", "shared_ca", edge_type="certificate")
    
    calc = SCPCalculator(g, tis_res, set(), "test.com")
    calc.threshold = 1.0
    
    result = calc.compute_scp()
    assert result.scp_activated is True
    assert "sibling.com" in result.siblings_found

def test_malicious_sibling_increases_score():
    tis_res = build_tis_result(0.5)
    g = nx.DiGraph()
    g.add_node("test.com")
    g.add_node("evil.com")
    g.add_node("shared_ip")
    g.add_node("shared_ca")
    
    g.add_edge("test.com", "shared_ip", edge_type="infrastructure")
    g.add_edge("test.com", "shared_ca", edge_type="certificate")
    g.add_edge("evil.com", "shared_ip", edge_type="infrastructure")
    g.add_edge("evil.com", "shared_ca", edge_type="certificate")
    
    calc_malicious = SCPCalculator(g, tis_res, {"evil.com"}, "test.com")
    res_malicious = calc_malicious.compute_scp()
    
    calc_benign = SCPCalculator(g, tis_res, set(), "test.com")
    res_benign = calc_benign.compute_scp()
    
    assert res_malicious.scp_score > 0.0
    assert res_malicious.scp_score > res_benign.scp_score

def test_jaccard_full_overlap():
    tis_res = build_tis_result(0.5)
    g = nx.DiGraph()
    g.add_node("a")
    g.add_node("b")
    g.add_node("n1")
    g.add_node("n2")
    
    g.add_edge("a", "n1")
    g.add_edge("a", "n2")
    g.add_edge("b", "n1")
    g.add_edge("b", "n2")
    
    calc = SCPCalculator(g, tis_res, set(), "a")
    similarity = calc.jaccard_similarity("a", "b")
    assert similarity == 1.0

def test_jaccard_no_overlap():
    tis_res = build_tis_result(0.5)
    g = nx.DiGraph()
    g.add_node("a")
    g.add_node("b")
    g.add_node("n1")
    g.add_node("n2")
    
    g.add_edge("a", "n1")
    g.add_edge("b", "n2")
    
    calc = SCPCalculator(g, tis_res, set(), "a")
    similarity = calc.jaccard_similarity("a", "b")
    assert similarity == 0.0

def test_scp_score_clamped_to_one():
    tis_res = build_tis_result(0.5)
    g = nx.DiGraph()
    g.add_node("test.com")
    
    for i in range(5):
        sib = f"evil_{i}.com"
        ip = f"ip_{i}"
        ca = f"ca_{i}"
        g.add_node(sib)
        g.add_node(ip)
        g.add_node(ca)
        
        g.add_edge("test.com", ip, edge_type="infrastructure")
        g.add_edge("test.com", ca, edge_type="certificate")
        
        g.add_edge(sib, ip, edge_type="infrastructure")
        g.add_edge(sib, ca, edge_type="certificate")
        
    malicious_set = {f"evil_{i}.com" for i in range(5)}
    calc = SCPCalculator(g, tis_res, malicious_set, "test.com")
    
    result = calc.compute_scp()
    assert result.scp_score <= 1.0

