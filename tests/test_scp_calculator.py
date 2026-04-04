import pytest
import networkx as nx
from app.services.scp_calculator import SCPCalculator
from app.services.tis_calculator import TISResult

def test_scp_activation():
    # Only activates if domain age < 1.0
    graph = nx.DiGraph()
    graph.add_node("example.com")
    tis_res = TISResult(0.5, {}, {}, {}, 2.0, False) # Age 2.0
    
    calc = SCPCalculator("example.com", graph, tis_res, set())
    res = calc.compute_scp()
    
    assert res.scp_activated is False
    assert res.scp_score == 0.0

def test_scp_computation():
    graph = nx.DiGraph()
    graph.add_node("d.com")
    graph.add_node("s1.com")
    graph.add_node("s2.com")
    graph.add_node("ip1")
    graph.add_node("ip2")
    
    # d.com and s1.com and s2.com all connect to ip1 and ip2
    graph.add_edge("d.com", "ip1", edge_type="infrastructure")
    graph.add_edge("d.com", "ip2", edge_type="infrastructure")
    
    graph.add_edge("s1.com", "ip1", edge_type="infrastructure")
    graph.add_edge("s1.com", "ip2", edge_type="infrastructure")
    
    graph.add_edge("s2.com", "ip1", edge_type="infrastructure")
    graph.add_edge("s2.com", "ip2", edge_type="infrastructure")
    
    tis_res = TISResult(0.5, {}, {}, {}, 0.5, False)
    known_malicious = {"s1.com"} # s1 is malicious
    
    calc = SCPCalculator("d.com", graph, tis_res, known_malicious)
    res = calc.compute_scp()
    
    assert res.scp_activated is True
    assert "s1.com" in res.siblings_found
    assert "s2.com" in res.siblings_found
    
    # Since s1.com is malicious and Jaccard overlap is 1.0 
    assert res.sibling_weights["s1.com"] > res.sibling_weights["s2.com"]
