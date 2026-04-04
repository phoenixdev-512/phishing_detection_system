import pytest
import networkx as nx
from app.services.tis_calculator import TISCalculator

def test_tis_calculation_safe():
    graph = nx.DiGraph()
    graph.add_node("example.com")
    # Add dummy edges to make observed > expected
    for i in range(10):
        graph.add_edge("example.com", f"ip{i}", edge_type="infrastructure")
        
    baselines = {
        "infrastructure": 5.0,
        "certificate": 0.0,
        "ownership": 0.0,
        "routing": 0.0
    }
    
    calc = TISCalculator("example.com", graph, baselines, 100.0, False)
    res = calc.compute_tis()
    
    assert res.tis_score == 0.0 # safe

def test_tis_calculation_malicious():
    graph = nx.DiGraph()
    graph.add_node("example.com")
    # 0 edges, but expect many
    baselines = {
        "infrastructure": 10.0,
        "certificate": 5.0,
        "ownership": 2.0,
        "routing": 1.0
    }
    calc = TISCalculator("example.com", graph, baselines, 100.0, False)
    res = calc.compute_tis()
    
    # Since observed is 0, isolation for each component is expected/expected = 1.0
    # Weights sum to 1.0, so tis_score = 1.0
    assert res.tis_score == 1.0
