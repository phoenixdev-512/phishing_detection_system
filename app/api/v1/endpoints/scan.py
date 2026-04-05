import time
import json
import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
import networkx as nx

from app.core.config import settings
from app.schemas.url_schema import AnalysisResult, SiblingDomain, GraphSummary, URLRequest
from app.services.preprocessing import extract_candidate_domain
from app.services.database import DatabaseService, get_db
from app.services.graph_builder import EgoGraphBuilder
from app.services.egd_model import EGDModel
from app.services.tis_calculator import TISCalculator, TISResult
from app.services.scp_calculator import SCPCalculator, SCPResult
from app.services.heuristics import heuristic_engine
from app.services.tgis_aggregator import TGISAggregator

logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

analyze_heuristics = heuristic_engine.analyze

@router.post("/scan", response_model=AnalysisResult)
@limiter.limit(f"{getattr(settings, 'RATE_LIMIT_PER_MINUTE', 60)}/minute")
async def scan(request: Request, payload: URLRequest, db: DatabaseService = Depends(get_db)):
    try:
        timing = {}
        t0 = time.time()

        if getattr(settings, "API_KEY", None):
            key = request.headers.get("X-API-Key")
            if key != settings.API_KEY:
                raise HTTPException(status_code=403, detail="Invalid or missing API key")

        try:
            candidate = extract_candidate_domain(str(payload.url))
        except ValueError as e:
            raise HTTPException(422, detail=str(e))
        timing["stage_0_preprocessing_ms"] = round((time.time() - t0) * 1000)

        t1 = time.time()
        blacklist_hit = db.check_url(candidate.candidate_domain)
        timing["blacklist_check_ms"] = round((time.time() - t1) * 1000)

        graph = nx.DiGraph()
        domain_age_days = None
        whois_failed = True
        baselines = {}
        tis_result = TISResult(0.0, {}, {}, {}, 0.0, False)
        scp_result = SCPResult(0.0, [], {}, False)
        residual_r_dict = {"risk_score": 0.0}
        residual_r = 0.0
        known_malicious = set()
        builder = None
        scp_calc = None

        if not blacklist_hit:
            t2 = time.time()
            builder = EgoGraphBuilder(candidate, db)
            try:
                graph = await builder.build_graph()
                domain_age_days = builder.domain_age_days
                whois_failed = domain_age_days is None
            except Exception as e:
                logger.error(f"Graph build failed: {e}", exc_info=True)
                graph = nx.DiGraph()
                domain_age_days = None
                whois_failed = True
                timing["graph_build_error"] = str(e)
            timing["stage_1_graph_build_ms"] = round((time.time() - t2) * 1000)
            timing["graph_build_threads"] = getattr(builder, "thread_results", {})

            t3 = time.time()
            egd = EGDModel()
            baselines = egd.compute_all_baselines(
                domain_age_days or 1.0, whois_failed=whois_failed
            )
            timing["stage_2_egd_ms"] = round((time.time() - t3) * 1000)

            t4 = time.time()
            tis_calc = TISCalculator(graph, baselines)
            tis_result = tis_calc.compute_tis()
            timing["stage_3_tis_ms"] = round((time.time() - t4) * 1000)

            t5 = time.time()
            known_malicious = db.get_malicious_set()
            scp_calc = SCPCalculator(graph, tis_result, known_malicious,
                                     candidate.candidate_domain)
            scp_result = scp_calc.compute_scp()
            timing["stage_4_scp_ms"] = round((time.time() - t5) * 1000)

            t6 = time.time()
            url_features = {
                "domain": getattr(candidate, "candidate_domain", ""),
                "fqdn": getattr(candidate, "fqdn", ""),
                "is_ip": getattr(candidate, "is_ip", False),
                "url_length": len(str(payload.url)),
                "has_subdomain": bool(getattr(candidate, "subdomain", "")),
                "suffix": getattr(candidate, "suffix", ""),
                "subdomain": getattr(candidate, "subdomain", ""),
                "path": getattr(candidate, "path", ""),
                "full_url": str(payload.url),
                "is_ip_address": getattr(candidate, "is_ip", False),
            }
            residual_r_dict = analyze_heuristics(url_features)
            if isinstance(residual_r_dict, dict):
                residual_r = residual_r_dict.get("risk_score", 0.0)
            else:
                residual_r = float(residual_r_dict)
            timing["stage_residual_heuristic_ms"] = round((time.time() - t6) * 1000)

        t7 = time.time()
        aggregator = TGISAggregator(
            tis_result=tis_result,
            scp_result=scp_result,
            residual_heuristic=residual_r,
            blacklist_hit=blacklist_hit,
            candidate_domain=candidate.candidate_domain,
            known_malicious_set=known_malicious
        )
        verdict = aggregator.aggregate()
        timing["stage_5_aggregation_ms"] = round((time.time() - t7) * 1000)
        timing["total_ms"] = round((time.time() - t0) * 1000)

        graph_summary = None
        graph_json_dict = None
        if not blacklist_hit and builder:
            graph_summary = GraphSummary(
                total_nodes=graph.number_of_nodes(),
                total_edges=graph.number_of_edges(),
                edge_counts=builder.edge_counts,
                expected_edges={k: baselines.get(k, 0.0) for k in
                                ["infrastructure", "certificate", "ownership", "routing"]}
            )
            graph_json_dict = nx.node_link_data(graph)

        siblings = []
        if not blacklist_hit and scp_result and scp_calc:
            siblings = [
                SiblingDomain(
                    domain=s,
                    weight=scp_result.sibling_weights.get(s, 0.0),
                    is_known_malicious=(s in known_malicious),
                    jaccard_similarity=scp_calc.jaccard_similarity(
                        candidate.candidate_domain, s)
                )
                for s in scp_result.siblings_found
            ]

        db.log_scan(
            url=str(payload.url),
            status=verdict.status,
            risk_score=verdict.risk_score,
            verdict_source=verdict.verdict_source,
            tgis_score=verdict.tgis_score
        )

        details = {
            "blacklist_hit": blacklist_hit,
            "whois_failed": whois_failed if not blacklist_hit else None,
            "scp_activated": verdict.scp_activated,
            "pipeline_timing": timing,
            "graph_build_threads": getattr(builder, "thread_results", {}) if builder else {},
            "egd_baselines": baselines if not blacklist_hit else {}
        }

        return AnalysisResult(
            url=str(payload.url),
            status=verdict.status,
            risk_score=verdict.risk_score,
            verdict_source=verdict.verdict_source,
            reasons=verdict.reasons,
            recommendation=verdict.recommendation,
            tgis_score=verdict.tgis_score,
            tis_score=tis_result.tis_score if tis_result else None,
            scp_score=scp_result.scp_score if scp_result else None,
            residual_heuristic=residual_r,
            domain_age_days=verdict.domain_age_days,
            scp_activated=verdict.scp_activated,
            siblings=siblings,
            graph_summary=graph_summary,
            graph_json=graph_json_dict,
            details=details
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unhandled exception in scan endpoint: {e}", exc_info=True)
        raise HTTPException(500, detail={
            "error": str(e),
            "stage": "unknown",
            "url": str(payload.url)
        })
