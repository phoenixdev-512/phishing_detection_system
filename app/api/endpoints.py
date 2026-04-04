from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from app.schemas.url_schema import URLRequest, AnalysisResult
from app.services.database import db_service
from app.services.preprocessing import extract_candidate_domain
from app.services.graph_builder import EgoGraphBuilder
from app.services.egd_model import EGDModel
from app.services.tis_calculator import TISCalculator
from app.services.scp_calculator import SCPCalculator
from app.services.tgis_aggregator import TGISAggregator
from app.core.config import settings
from app.core.security import limiter
import time
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/scan", response_model=AnalysisResult)
@limiter.limit("30/minute")
async def scan_url(request: Request, body: URLRequest):
    pipeline_timing = {}
    url = str(body.url)
    
    try:
        # Stage 0: Preprocessing
        t0 = time.time()
        try:
            candidate = extract_candidate_domain(url)
        except Exception as e:
            logger.error(f"Stage 0 Failed: {e}")
            raise Exception(f"Stage 0 (Preprocessing): {e}")
        pipeline_timing["stage_0_preprocessing_ms"] = int((time.time() - t0) * 1000)

        # Legacy URL Heuristic components (mocked for this rewrite since heuristics.py is replaced by TGIS, but we need residual)
        # Real pipeline might reuse heuristic_engine. We'll assign a base generic scale to R
        residual_heuristic_score = 0.15 
        
        # Fast Blacklist hit
        db_match = db_service.check_url(url)
        if db_match:
            aggregator = TGISAggregator(
                url=url, graph=None, tis_result=None, scp_result=None,
                residual_heuristic_score=residual_heuristic_score,
                blacklist_hit=True
            )
            return aggregator.aggregate()

        # Stage 1: Async Ego-Graph Construction
        t1 = time.time()
        try:
            graph_builder = EgoGraphBuilder(candidate=candidate)
            graph = await graph_builder.build_graph(timeout_ms=settings.TGIS_TIMEOUT_MS)
        except Exception as e:
            logger.error(f"Stage 1 Failed: {e}")
            raise Exception(f"Stage 1 (Graph Build): {e}")
        pipeline_timing["stage_1_graph_build_ms"] = int((time.time() - t1) * 1000)

        # Stage 2: Expected Graph Density (EGD)
        t2 = time.time()
        try:
            egd_model = EGDModel(domain_age_days=graph_builder.domain_age_days)
            baselines = egd_model.compute_all_baselines()
        except Exception as e:
            logger.error(f"Stage 2 Failed: {e}")
            raise Exception(f"Stage 2 (EGD Model): {e}")
        pipeline_timing["stage_2_egd_ms"] = int((time.time() - t2) * 1000)

        # Stage 3: Temporal Isolation Score (TIS)
        t3 = time.time()
        try:
            tis_calculator = TISCalculator(
                root_node=candidate.candidate_domain,
                graph=graph,
                egd_baselines=baselines,
                domain_age_days=egd_model.domain_age_days,
                whois_failed=egd_model.whois_failed
            )
            tis_result = tis_calculator.compute_tis()
        except Exception as e:
            logger.error(f"Stage 3 Failed: {e}")
            raise Exception(f"Stage 3 (TIS Calculator): {e}")
        pipeline_timing["stage_3_tis_ms"] = int((time.time() - t3) * 1000)

        # Stage 4: Sibling Contamination Propagation (SCP)
        t4 = time.time()
        try:
            known_malicious = db_service.get_malicious_domains()
            scp_calculator = SCPCalculator(
                root_node=candidate.candidate_domain,
                graph=graph,
                tis_result=tis_result,
                known_malicious_set=known_malicious
            )
            scp_result = scp_calculator.compute_scp()
        except Exception as e:
            logger.error(f"Stage 4 Failed: {e}")
            raise Exception(f"Stage 4 (SCP Calculator): {e}")
        pipeline_timing["stage_4_scp_ms"] = int((time.time() - t4) * 1000)

        # Stage 5: Final Aggregation
        t5 = time.time()
        try:
            aggregator = TGISAggregator(
                url=url,
                graph=graph,
                tis_result=tis_result,
                scp_result=scp_result,
                residual_heuristic_score=residual_heuristic_score,
                blacklist_hit=False
            )
            final_result = aggregator.aggregate()
            final_result["details"]["pipeline_timing"] = pipeline_timing
        except Exception as e:
            logger.error(f"Stage 5 Failed: {e}")
            raise Exception(f"Stage 5 (Aggregator): {e}")
        pipeline_timing["stage_5_aggregator_ms"] = int((time.time() - t5) * 1000)

        # Log scan
        db_service.log_scan(
            url=url,
            status=final_result["status"],
            risk_score=final_result["risk_score"],
            source=final_result["verdict_source"]
        )

        return final_result

    except Exception as e:
        # Find which stage failed
        stage = "unknown"
        if "Stage" in str(e):
            stage = str(e).split(":")[0].strip()
            
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "stage": stage,
                "url": url
            }
        )

@router.get("/history")
async def get_history(limit: int = 20):
    try:
        return db_service.get_recent_scans(limit)
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch history")

@router.get("/stats")
async def get_stats():
    try:
        return db_service.get_stats()
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch stats")
