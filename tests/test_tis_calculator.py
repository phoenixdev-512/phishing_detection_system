# FILE 2: tests/test_tis_calculator.py
import pytest
import networkx as nx
from app.services.tis_calculator import TISCalculator, TISResult
from app.services.egd_model import EGDModel

def build_test_graph(edge_type_counts: dict) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("test.com", type="candidate")
    for i, (edge_type, count) in enumerate(edge_type_counts.items()):
        for j in range(count):
            node_id = f"node_{i}_{j}"
            g.add_node(node_id)
            g.add_edge("test.com", node_id, edge_type=edge_type)
    return g

def test_tis_zero_when_fully_connected():
    model = EGDModel()
    baselines = model.compute_all_baselines(0.1)
    graph = build_test_graph({
        "infrastructure": 10,
        "certificate": 10,
        "ownership": 10,
        "routing": 10
    })
    calc = TISCalculator(graph, baselines)
    result = calc.compute_tis()
    assert result.tis_score == 0.0

def test_tis_one_when_fully_isolated():
    model = EGDModel()
    baselines = model.compute_all_baselines(30.0)
    graph = build_test_graph({
        "infrastructure": 0,
        "certificate": 0,
        "ownership": 0,
        "routing": 0
    })
    calc = TISCalculator(graph, baselines)
    result = calc.compute_tis()
    assert result.tis_score == pytest.approx(1.0, abs=0.01)

def test_per_type_isolation_in_result():
    model = EGDModel()
    baselines = model.compute_all_baselines(10.0)
    graph = build_test_graph({"infrastructure": 1})
    calc = TISCalculator(graph, baselines)
    result = calc.compute_tis()
    
    for key in ["infrastructure", "certificate", "ownership", "routing"]:
        assert key in result.per_type_isolation
        assert 0.0 <= result.per_type_isolation[key] <= 1.0

def test_weight_normalization():
    model = EGDModel()
    baselines = model.compute_all_baselines(30.0)
    graph = build_test_graph({})
    calc = TISCalculator(graph, baselines)
    result = calc.compute_tis()
    
    expected_sum = sum(calc.weights.values())
    assert result.tis_score == pytest.approx(expected_sum, abs=0.01)

def test_zero_expected_no_division_error():
    model = EGDModel()
    baselines = model.compute_all_baselines(0.0)
    graph = build_test_graph({})
    calc = TISCalculator(graph, baselines)
    result = calc.compute_tis()
    
    assert result.per_type_isolation["certificate"] == 0.0

