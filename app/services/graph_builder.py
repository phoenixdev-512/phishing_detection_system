import asyncio
import aiohttp
import networkx as nx
from datetime import datetime, timezone
import time
import whois
import logging
from app.services.preprocessing import CandidateDomain

logger = logging.getLogger(__name__)

class EgoGraphBuilder:
    def __init__(self, candidate: CandidateDomain):
        self.candidate = candidate
        self.d = candidate.candidate_domain
        self.graph = nx.DiGraph()
        self.graph.add_node(self.d, type='candidate')
        
        self.edge_counts = {
            "infrastructure": 0,
            "certificate": 0,
            "ownership": 0,
            "routing": 0,
            "certificate_sibling": 0
        }
        self.domain_age_days = None

    async def _fetch_pdns(self, session: aiohttp.ClientSession) -> nx.DiGraph:
        g = nx.DiGraph()
        try:
            url = f"https://pdns.circl.lu/query/{self.d}"
            async with session.get(url, timeout=5) as response:
                if response.status == 404:
                    return g
                response.raise_for_status()
                # CIRCL PDNS can return stream of JSON objects or array
                data = await response.text()
                import json
                
                ips = set()
                # Attempt to parse json lines or array
                records = []
                try:
                    records = json.loads(data)
                    if not isinstance(records, list):
                        records = [records]
                except json.JSONDecodeError:
                    for line in data.strip().split('\n'):
                        if line:
                            records.append(json.loads(line))
                            
                for record in records:
                    if 'rdata' in record and isinstance(record['rdata'], str):
                        # fast simple IP filter check (rudimentary)
                        if record['rdata'].count('.') == 3 or ':' in record['rdata']:
                            ips.add(record['rdata'])
                    if 'rrset' in record and isinstance(record['rrset'], list):
                         for r in record['rrset']:
                             ips.add(r)
                
                # Also handle expected literal prompt format: "For each unique IP in the rrset list"
                if isinstance(records, dict) and 'rrset' in records:
                    for ip in records['rrset']:
                        ips.add(ip)

                for ip in ips:
                    if type(ip) is str and (':' in ip or ip.count('.') == 3):
                        g.add_node(ip, type='ip', first_seen=time.time())
                        g.add_edge(self.d, ip, edge_type='infrastructure', observed_at=time.time())
        except Exception as e:
            logger.warning(f"PDNS fetch failed: {e}")
        return g

    async def _fetch_ct_logs(self, session: aiohttp.ClientSession) -> nx.DiGraph:
        g = nx.DiGraph()
        try:
            url = f"https://crt.sh/?q={self.d}&output=json"
            async with session.get(url, timeout=5) as response:
                response.raise_for_status()
                data = await response.json()
                
                unique_cas = set()
                unique_sans = set()
                
                if isinstance(data, list):
                    for entry in data:
                        issuer = entry.get('issuer_ca_id') or entry.get('issuer_name')
                        if issuer:
                            unique_cas.add(str(issuer))
                            
                        name_value = entry.get('name_value', '')
                        for san in name_value.split('\n'):
                            san = san.strip()
                            if san and san != self.d and '*' not in san:
                                unique_sans.add(san)
                
                for ca in unique_cas:
                    g.add_node(ca, type='ca')
                    g.add_edge(self.d, ca, edge_type='certificate', observed_at=time.time())
                    
                for san in unique_sans:
                    g.add_node(san, type='san_sibling')
                    g.add_edge(self.d, san, edge_type='certificate_sibling', observed_at=time.time())
                    
        except Exception as e:
            logger.warning(f"CT Logs fetch failed: {e}")
        return g

    def _fetch_whois_sync(self) -> nx.DiGraph:
        g = nx.DiGraph()
        try:
            w = whois.whois(self.d)
            
            # Registrar
            registrar = w.get('registrar')
            if isinstance(registrar, list) and registrar:
                registrar = registrar[0]
            if registrar:
                g.add_node(registrar, type='registrar')
                g.add_edge(self.d, registrar, edge_type='ownership', observed_at=time.time())

            # Name Servers
            name_servers = w.get('name_servers')
            if name_servers:
                if isinstance(name_servers, str):
                    name_servers = [name_servers]
                for ns in name_servers:
                    if isinstance(ns, str):
                        ns = ns.lower().strip()
                        g.add_node(ns, type='nameserver')
                        g.add_edge(self.d, ns, edge_type='ownership', observed_at=time.time())

            # Creation date
            creation_date = w.get('creation_date')
            if isinstance(creation_date, list) and creation_date:
                creation_date = creation_date[0]
            
            if creation_date:
                # Store strictly back on the root level (will merge back in)
                g.add_node(self.d, type='candidate')
                g.nodes[self.d]['domain_creation_date'] = creation_date.isoformat()
                
        except Exception as e:
            logger.warning(f"WHOIS fetch failed: {e}")
            
        return g

    async def _fetch_whois(self) -> nx.DiGraph:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_whois_sync)

    async def _fetch_bgp(self, session: aiohttp.ClientSession, ips: list[str]) -> nx.DiGraph:
        g = nx.DiGraph()
        if not ips:
            return g
            
        try:
            # Fallback direct to RDAP limit to 1 IP out of consideration
            ip_target = ips[0]
            url = f"https://rdap.arin.net/registry/ip/{ip_target}"
            
            async with session.get(url, timeout=5) as response:
                response.raise_for_status()
                data = await response.json()
                
                asn = None
                if 'entities' in data:
                    for entity in data['entities']:
                        roles = entity.get('roles', [])
                        if 'registrant' in roles or 'administrative' in roles:
                             handle = entity.get('handle')
                             if handle and handle.startswith('AS'):
                                 asn = handle
                
                if asn is None: 
                     # Arbitrary fallback if entity logic fails but handles IP bounds
                     asn_node = data.get('handle', 'ASN_UNKNOWN')
                     asn = f"AS-{asn_node}"
                     
                g.add_node(asn, type='asn')
                g.add_edge(ip_target, asn, edge_type='routing', observed_at=time.time())
                
        except Exception as e:
            logger.warning(f"BGP/RDAP fetch failed: {e}")
            
        return g

    async def build_graph(self, timeout_ms: int = 200) -> nx.DiGraph:
        async with aiohttp.ClientSession() as session:
            # 1. Fetch PDNS, CT, WHOIS concurrently
            tasks = [
                self._fetch_pdns(session),
                self._fetch_ct_logs(session),
                self._fetch_whois()
            ]
            
            timeout_sec = timeout_ms / 1000.0
            
            try:
                results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout_sec)
            except asyncio.TimeoutError:
                logger.warning(f"Graph construction timed out after {timeout_ms}ms")
                results = [nx.DiGraph(), nx.DiGraph(), nx.DiGraph()]
                
            # Filter exceptions vs active subgraphs
            valid_subgraphs = []
            for res in results:
                if isinstance(res, nx.DiGraph):
                    valid_subgraphs.append(res)
                else:
                    logger.warning(f"A stage thread failed forcefully: {res}")
                    
            for sg in valid_subgraphs:
                if len(sg.nodes) > 0:
                    self.graph = nx.compose(self.graph, sg)
                    
            # 2. Extract IPs to query BGP
            ips = [n for n, attr in self.graph.nodes(data=True) if attr.get('type') == 'ip']
            if ips:
                try:
                    bgp_g = await asyncio.wait_for(
                        self._fetch_bgp(session, ips), 
                        timeout=min(timeout_sec, 2.0)
                    )
                    if len(bgp_g.nodes) > 0:
                        self.graph = nx.compose(self.graph, bgp_g)
                except asyncio.TimeoutError:
                    logger.warning("BGP fetch timed out")
                except Exception as e:
                    logger.warning(f"BGP thread failed forcefully: {e}")

            # 3. Process domain_creation_date
            root_attrs = self.graph.nodes[self.d]
            if "domain_creation_date" in root_attrs:
                try:
                    dt_str = root_attrs["domain_creation_date"].replace('Z', '+00:00')
                    creation_dt = datetime.fromisoformat(dt_str)
                    
                    if creation_dt.tzinfo is None:
                        creation_dt = creation_dt.replace(tzinfo=timezone.utc)
                        
                    age_seconds = self.candidate.temporal_anchor - creation_dt.timestamp()
                    self.domain_age_days = max(0.0, age_seconds / 86400.0)
                except Exception as e:
                    logger.warning(f"Failed to parse creation date: {e}")
                    self.domain_age_days = None
                    
            # 4. Calculate Edge counts
            for u, v, data in self.graph.edges(data=True):
                etype = data.get('edge_type')
                if etype in self.edge_counts:
                    self.edge_counts[etype] += 1

            return self.graph
