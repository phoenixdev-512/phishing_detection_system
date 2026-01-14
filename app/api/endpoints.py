from fastapi import APIRouter
from app.schemas.url_schema import URLRequest, AnalysisResult
import logging

# Set up logging
logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/scan", response_model=AnalysisResult)
async def scan_url(request: URLRequest):
    """
    Receives a URL, processes it through the analysis pipeline, 
    and returns a risk assessment.
    """
    input_url = str(request.url)
    
    # --- PLACEHOLDER LOGIC FOR PHASE 1 ---
    # In future phases, we will call:
    # 1. preprocessing.normalize(input_url)
    # 2. database.check_local(normalized_url)
    # 3. api_integration.check_external(normalized_url)
    # 4. heuristics.analyze(normalized_url)
    
    logger.info(f"Received URL for scanning: {input_url}")

    return AnalysisResult(
        url=input_url,
        status="unknown",
        risk_score=0,
        verdict_source="System Initialization",
        reasons=["Phase 1 Skeleton: System is operational but analysis layers are empty."]
    )
