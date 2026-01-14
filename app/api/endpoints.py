from fastapi import APIRouter, HTTPException
from app.schemas.url_schema import URLRequest, AnalysisResult
from app.services.preprocessing import preprocessor  # Import the service
from app.services.database import db_service  # Import the new DB service
from app.services.api_integration import api_manager  # Import the API manager
from app.services.heuristics import heuristic_engine  # Import the heuristic engine
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
    try:
        # Phase 2: Preprocessing
        url_components = preprocessor.normalize(str(request.url))
        clean_url = url_components['full_url']
        
        logger.info(f"Received URL for scanning: {clean_url}")

        # --- PHASE 3 INTEGRATION ---
        # Check Local Database (Speed Layer)
        db_match = db_service.check_url(clean_url)
        
        if db_match:
            # STOP! We found it in the local blacklist.
            # Return immediately without calling external APIs (saving time & money)
            return AnalysisResult(
                url=clean_url,
                status="malicious",
                risk_score=db_match["risk_score"],
                verdict_source=f"Local Database ({db_match['source']})",
                reasons=[f"Exact match found in local blacklist."]
            )

        # --- PHASE 4 INTEGRATION ---
        # Check External APIs (if not in local DB)
        api_result = await api_manager.check_url(clean_url)
        
        if api_result and api_result.get("is_malicious"):
            # External API flagged it as malicious
            return AnalysisResult(
                url=clean_url,
                status="malicious",
                risk_score=api_result.get("risk_score", 85),
                verdict_source=api_result.get("source", "External API"),
                reasons=[f"Flagged by {api_result.get('source', 'external API')}."]
            )
        
        # --- PHASE 5 INTEGRATION ---
        # Run Heuristic Analysis (if not caught by DB or APIs)
        heuristic_result = heuristic_engine.analyze(url_components)
        
        # Determine verdict based on heuristic risk score
        if heuristic_result["risk_score"] >= 70:
            # High risk based on heuristics
            return AnalysisResult(
                url=clean_url,
                status="suspicious",
                risk_score=heuristic_result["risk_score"],
                verdict_source="Heuristic Analysis",
                reasons=heuristic_result["reasons"]
            )
        elif heuristic_result["risk_score"] >= 40:
            # Medium risk - suspicious but not conclusive
            return AnalysisResult(
                url=clean_url,
                status="suspicious",
                risk_score=heuristic_result["risk_score"],
                verdict_source="Heuristic Analysis",
                reasons=heuristic_result["reasons"]
            )
        else:
            # Low risk based on heuristics
            return AnalysisResult(
                url=clean_url,
                status="safe",
                risk_score=heuristic_result["risk_score"],
                verdict_source="Complete Analysis (DB + API + Heuristics)",
                reasons=heuristic_result["reasons"]
            )
        
    except HTTPException as e:
        raise e
    except Exception as e:
        # Fallback for unexpected parsing errors
        logger.error(f"Error processing URL: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error processing URL: {str(e)}")
