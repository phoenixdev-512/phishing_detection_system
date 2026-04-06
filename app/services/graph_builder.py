import asyncio
import time
import json
import logging
from datetime import datetime
import networkx as nx
import aiohttp
import whois
from app.core.config import settings
from app.services.preprocessing import CandidateDomain
from app.services.database import DatabaseService

logger = logging.getLogger(__name__)

class EgoGraphBuilder:
    def __init__(self, candidate: CandidateDomain, db: DatabaseService):
        self.candidate = candidate
        self.db = db
        self.graph = nx.DiGraph()
        self.graph.add_node(candidate.candidate_domain, type="candidate")
        self.domain_age_days: float | None = None
        self.thread_results: dict = {
            "pdns": "pending",
            "ct_logs": "pending",
            "whois": "pending",
            "bgp": "pending"
        }
        self._creation_date_string = None

    async def build_graph(self) -> nx.DiGraph:
        cached = self.db.get_graph(self.candidate.candidate_domain)
        if cached is not None:
            self.graph = nx.node_link_graph(cached)
            age_result = self.db.get_domain_age(self.candidate.candidate_domain)
            if age_result and age_result != "__CACHE_MISS__":
                self._set_domain_age_from_string(age_result)
            return self.graph

        timeout = aiohttp.ClientTimeout(total=settings.TGIS_TIMEOUT_MS / 1000)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            results = await asyncio.gather(
                self._fetch_pdns(session),
                self._fetch_ct_logs(session),
                self._fetch_whois(),
                self._fetch_bgp(session),
                return_exceptions=True
            )

        thread_names = ["pdns", "ct_logs", "whois", "bgp"]
        for thread_name, result in zip(thread_names, results):
            if isinstance(result, Exception):
                if isinstance(result, asyncio.TimeoutError):
                    logger.warning(f"Timeout in {thread_name}")
                    self.thread_results[thread_name] = "timeout"
                else:
                    logger.warning(f"Exception in {thread_name}: {result}")
                    self.thread_results[thread_name] = "error"
            else:
                self.thread_results[thread_name] = "success"

        self.db.set_graph(
            self.candidate.candidate_domain,
            nx.node_link_data(self.graph),
            None,
            None
        )

        if self._creation_date_string:
            self.db.set_domain_age(
                self.candidate.candidate_domain,
                self._creation_date_string
            )

        return self.graph

    async def _fetch_pdns(self, session: aiohttp.ClientSession) -> None:
        url = f"{settings.PDNS_API_URL}/{self.candidate.candidate_domain}"
        async with session.get(url, headers={"Accept": "application/json"}) as response:
            if response.status == 404:
                self.thread_results["pdns"] = "success"
                return
            response.raise_for_status()
            data = await response.json()
            
            for record in data:
                rrtype = record.get("rrtype")
                rdata = record.get("rdata", [])
                if rrtype in ("A", "AAAA"):
                    for ip in rdata:
                        self.graph.add_node(ip, type="ip")
                        self.graph.add_edge(
                            self.candidate.candidate_domain, ip,
                            edge_type="infrastructure",
                            observed_at=time.time()
                        )
            self.thread_results["pdns"] = "success"

    async def _fetch_ct_logs(self, session: aiohttp.ClientSession) -> None:
        url = f"{settings.CT_LOGS_API_URL}/?q={self.candidate.candidate_domain}&output=json"
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                data = await response.json()
        except Exception as e:
            logger.warning(f"ct_logs fetch error: {e}")
            raise

        if not isinstance(data, list):
            logger.warning("ct_logs response is not a valid list")
            raise ValueError("ct_logs response not a list")

        for entry in data:
            ca_id = str(entry.get("issuer_ca_id", ""))
            if ca_id:
                self.graph.add_node(ca_id, type="ca")
                self.graph.add_edge(
                    self.candidate.candidate_domain, ca_id,
                    edge_type="certificate", observed_at=time.time()
                )
            name_value = entry.get("name_value", "")
            for san in name_value.split("\n"):
                san = san.strip().lstrip("*.")
                if san and san != self.candidate.candidate_domain and "." in san:
                    self.graph.add_node(san, type="san_sibling")
                    self.graph.add_edge(
                        self.candidate.candidate_domain, san,
                        edge_type="certificate_sibling", observed_at=time.time()
                    )
        self.thread_results["ct_logs"] = "success"

    async def _fetch_whois(self) -> None:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(
            None, whois.whois, self.candidate.candidate_domain
        )
        registrar = str(w.registrar) if w.registrar else None
        name_servers = w.name_servers
        creation_date = w.creation_date

        if registrar:
            self.graph.add_node(registrar, type="registrar")
            self.graph.add_edge(self.candidate.candidate_domain, registrar,
                                edge_type="ownership", observed_at=time.time())
        
        for ns in (name_servers or []):
            ns_clean = str(ns).lower().rstrip(".")
            self.graph.add_node(ns_clean, type="nameserver")
            self.graph.add_edge(self.candidate.candidate_domain, ns_clean,
                                edge_type="ownership", observed_at=time.time())
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            self._creation_date_string = creation_date.isoformat() if hasattr(creation_date, "isoformat") else str(creation_date)
            self._set_domain_age_from_string(self._creation_date_string)
            
        self.thread_results["whois"] = "success"

    RDAP_REGISTRIES = [
        "https://rdap.arin.net/registry/ip",    # North America
        "https://rdap.db.ripe.net/ip",          # Europe, Middle East, Central Asia
        "https://rdap.apnic.net/ip",            # Asia Pacific
        "https://rdap.lacnic.net/rdap/ip",      # Latin America & Caribbean
        "https://rdap.afrinic.net/rdap/ip",     # Africa
    ]

    async def _fetch_bgp(self, session: aiohttp.ClientSession) -> None:
        # Get the first IP from the graph (added by PDNS thread)
        ip_nodes = [n for n, d in self.graph.nodes(data=True)
                    if d.get("type") == "ip"]
        if not ip_nodes:
            self.thread_results["bgp"] = "skipped_no_ips"
            return

        target_ip = ip_nodes[0]

        # Try all registries in parallel, take the first successful response
        async def query_registry(base_url: str) -> dict | None:
            try:
                url = f"{base_url}/{target_ip}"
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=3.0),
                    headers={"Accept": "application/rdap+json,application/json"}
                ) as resp:
                    if resp.status == 200:
                        return await resp.json(content_type=None)
            except Exception:
                return None
            return None

        results = await asyncio.gather(
            *[query_registry(r) for r in self.RDAP_REGISTRIES],
            return_exceptions=True
        )

        asn = None
        asn_name = None
        for result in results:
            if isinstance(result, Exception) or result is None:
                continue
            # Try to extract ASN from RDAP response
            # Common paths: result["handle"], result["autnums"][0]["handle"]
            if "handle" in result:
                asn = str(result["handle"])
                break
            if "autnums" in result and result["autnums"]:
                asn = str(result["autnums"][0].get("handle", ""))
                asn_name = result["autnums"][0].get("name", "")
                break
            # Some registries put it in "links" or "networks"
            if "networks" in result and result["networks"]:
                asn = f"AS_{target_ip}"  # fallback
                break

        if asn:
            node_attrs = {"type": "asn"}
            if asn_name:
                node_attrs["name"] = asn_name
            self.graph.add_node(asn, **node_attrs)
            self.graph.add_edge(
                self.candidate.candidate_domain, asn,
                edge_type="routing",
                observed_at=time.time()
            )
            self.thread_results["bgp"] = "success"
        else:
            self.thread_results["bgp"] = "no_asn_found"

    def _set_domain_age_from_string(self, date_str: str | None) -> None:
        if not date_str:
            self.domain_age_days = None
            return
        
        try:
            creation_dt = datetime.fromisoformat(date_str)
            age = (datetime.utcnow() - creation_dt.replace(tzinfo=None)).total_seconds() / 86400
            self.domain_age_days = max(0.0, age)
        except Exception:
            self.domain_age_days = None

    @property
    def edge_counts(self) -> dict[str, int]:
        counts = {
            "infrastructure": 0,
            "certificate": 0,
            "certificate_sibling": 0,
            "ownership": 0,
            "routing": 0
        }
        for _, _, data in self.graph.edges(data=True):
            edge_type = data.get("edge_type")
            if edge_type in counts:
                counts[edge_type] += 1
        return counts
