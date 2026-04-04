import asyncio
import networkx as nx
from typing import Protocol
from datetime import datetime, timezone
from app.services.preprocessing import CandidateDomain
import logging

logger = logging.getLogger(__name__)

class DataSource(Protocol):
    async def fetch_pdns(self, domain: str) -> nx.DiGraph: ...
    async def fetch_ct_logs(self, domain: str) -> nx.DiGraph: ...
    async def fetch_whois(self, domain: str) -> nx.DiGraph: ...
    async def fetch_bgp(self, ips: list[str]) -> nx.DiGraph: ...

class MockDataSource:
    """Phase A mock data source returning pre-fabricated graphs."""
    
    async def fetch_pdns(self, domain: str) -> nx.DiGraph:
        g = nx.DiGraph()
        g.add_node(domain, type='candidate')
        if "phish" in domain:
             IPs = ["192.168.1.1"]
        else:
             IPs = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        for ip in IPs:
            g.add_node(ip, type='ip')
            g.add_edge(domain, ip, edge_type='infrastructure')
        return g

    async def fetch_ct_logs(self, domain: str) -> nx.DiGraph:
        g = nx.DiGraph()
        g.add_node(domain, type='candidate')
        if "phish" in domain:
            g.add_node("Let's Encrypt", type='ca')
            g.add_edge(domain, "Let's Encrypt", edge_type='certificate')
            # Add malicious sibling
            g.add_node("example-phish2.com", type='san_sibling')
            g.add_edge(domain, "example-phish2.com", edge_type='certificate_sibling')
        else:
            g.add_node("DigiCert", type='ca')
            g.add_edge(domain, "DigiCert", edge_type='certificate')
        return g

    async def fetch_whois(self, domain: str) -> nx.DiGraph:
        g = nx.DiGraph()
        if "phish" in domain:
            creation_date = datetime.now(timezone.utc).isoformat()
            registrar = "Shady Registrar LLC"
            ns = ["ns1.shady.com"]
        else:
            creation_date = "2000-01-01T00:00:00+00:00"
            registrar = "MarkMonitor Inc."
            ns = ["ns1.google.com", "ns2.google.com"]
            
        g.add_node(domain, type='candidate', domain_creation_date=creation_date)
        g.add_node(registrar, type='registrar')
        g.add_edge(domain, registrar, edge_type='ownership')
        for n in ns:
            g.add_node(n, type='nameserver')
            g.add_edge(domain, n, edge_type='ownership')
        return g

    async def fetch_bgp(self, ips: list[str]) -> nx.DiGraph:
        g = nx.DiGraph()
        for ip in ips:
            asn = "AS15169" if ip.startswith("8.") else "AS12345"
            g.add_node(asn, type='asn')
            g.add_edge(ip, asn, edge_type='routing')
        return g

class EgoGraphBuilder:
    def __init__(self, candidate: CandidateDomain, data_source: DataSource = None):
        self.candidate = candidate
        self.d = candidate.candidate_domain
        self.graph = nx.DiGraph()
        self.graph.add_node(self.d, type='candidate')
        self.data_source = data_source or MockDataSource()
        
        self.edge_counts = {
            "infrastructure": 0,
            "certificate": 0,
            "ownership": 0,
            "routing": 0
        }
        self.domain_age_days = None

    async def _safe_fetch(self, coroutine) -> nx.DiGraph:
        try:
            return await coroutine
        except Exception as e:
            logger.warning(f"Data source fetch failed: {e}")
            return nx.DiGraph()

    async def build_graph(self, timeout_ms: int = 200) -> nx.DiGraph:
        # 1. Fetch PDNS, CT, WHOIS concurrently
        tasks = [
            self._safe_fetch(self.data_source.fetch_pdns(self.d)),
            self._safe_fetch(self.data_source.fetch_ct_logs(self.d)),
            self._safe_fetch(self.data_source.fetch_whois(self.d))
        ]
        
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout_ms / 1000.0)
            pdns_g, ct_g, whois_g = results
        except asyncio.TimeoutError:
            logger.warning(f"Graph construction timed out after {timeout_ms}ms")
            pdns_g, ct_g, whois_g = nx.DiGraph(), nx.DiGraph(), nx.DiGraph()
            
        # 2. Merge initial subgraphs
        for g in [pdns_g, ct_g, whois_g]:
            if len(g.nodes) > 0:
                self.graph = nx.compose(self.graph, g)
                
        # 3. Extract IPs to query BGP
        ips = [n for n, attr in self.graph.nodes(data=True) if attr.get('type') == 'ip']
        if ips:
            try:
                bgp_g = await asyncio.wait_for(
                    self._safe_fetch(self.data_source.fetch_bgp(ips)), 
                    timeout=timeout_ms / 1000.0
                )
                if len(bgp_g.nodes) > 0:
                    self.graph = nx.compose(self.graph, bgp_g)
            except asyncio.TimeoutError:
                logger.warning("BGP fetch timed out")

        # 4. Process domain_creation_date
        root_attrs = self.graph.nodes[self.d]
        if "domain_creation_date" in root_attrs:
            # Calculate age
            try:
                creation_dt = datetime.fromisoformat(root_attrs["domain_creation_date"].replace('Z', '+00:00'))
                age_seconds = self.candidate.temporal_anchor - creation_dt.timestamp()
                self.domain_age_days = max(0.0, age_seconds / 86400.0)
            except Exception as e:
                logger.warning(f"Failed to parse creation date: {e}")
                self.domain_age_days = None
                
        # 5. Calculate Edge counts
        for u, v, data in self.graph.edges(data=True):
            etype = data.get('edge_type')
            if etype in self.edge_counts:
                self.edge_counts[etype] += 1

        return self.graph
