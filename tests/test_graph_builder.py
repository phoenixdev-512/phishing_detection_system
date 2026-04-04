import pytest
import asyncio
import networkx as nx
from app.services.graph_builder import EgoGraphBuilder
from app.services.preprocessing import CandidateDomain
import time

@pytest.fixture
def mock_candidate():
    return CandidateDomain(
        raw_url="http://example.com",
        candidate_domain="example.com",
        fqdn="example.com",
        subdomain="",
        scheme="http",
        temporal_anchor=time.time(),
        is_ip=False,
        punycode_converted=False
    )

@pytest.mark.asyncio
async def test_build_graph_timeout(mock_candidate):
    # Enforce aggressive timeout to ensure gracefully handling empty structures without crashing
    builder = EgoGraphBuilder(mock_candidate)
    
    # 0ms timeout should definitely timeout
    g = await builder.build_graph(timeout_ms=0)
    
    # We should just get the candidate node back
    assert len(g.nodes) == 1
    assert "example.com" in g.nodes
    assert builder.edge_counts["infrastructure"] == 0

@pytest.mark.asyncio
async def test_build_graph_live_safe(mock_candidate):
    builder = EgoGraphBuilder(mock_candidate)
    # Using 5000ms just to see if it grabs basically anything without fail, allowing external hits locally
    g = await builder.build_graph(timeout_ms=5000)
    
    # We should have the root node
    assert "example.com" in g.nodes
    
    # Check that error doesn't raise from graph execution
    assert isinstance(g, nx.DiGraph)
