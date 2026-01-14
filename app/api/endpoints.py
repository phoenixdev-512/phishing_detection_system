from fastapi import APIRouter, HTTPException
from app.schemas.url_schema import URLRequest, AnalysisResult
from app.services.preprocessing import preprocessor  # Import the service
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
        # --- PHASE 2 INTEGRATION ---
        # Normalize and extract components
        url_components = preprocessor.normalize(str(request.url))
        
        logger.info(f"Received URL for scanning: {url_components['full_url']}")
        
        # For now, we will return the "cleaned" URL in the result
        # In later phases, 'url_components' will be passed to DB and Heuristics
        return AnalysisResult(
            url=url_components['full_url'],  # Return the clean, Punycode version
            status="unknown",
            risk_score=0,
            verdict_source="Phase 2 Preprocessing",
            reasons=[
                "Preprocessing complete.",
                f"Detected Protocol: {url_components['protocol']}",
                f"Registered Domain: {url_components['registered_domain']}",
                f"Is IP Address: {url_components['is_ip_address']}"
            ]
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        # Fallback for unexpected parsing errors
        logger.error(f"Error processing URL: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error processing URL: {str(e)}")
