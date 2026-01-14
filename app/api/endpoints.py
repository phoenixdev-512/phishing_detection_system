from fastapi import APIRouter, HTTPException
from app.schemas.url_schema import URLRequest, AnalysisResult
from app.services.preprocessing import preprocessor  # Import the service
from app.services.database import db_service  # Import the new DB service
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

        # ... If not found, logic proceeds to External APIs (Phase 4) ...
        
        return AnalysisResult(
            url=clean_url,
            status="safe",  # Placeholder until Phase 4/5
            risk_score=0,
            verdict_source="Clean (Local Check)",
            reasons=["No match in local database."]
        )
        
    except HTTPException as e:
        raise e
    except Exception as e:
        # Fallback for unexpected parsing errors
        logger.error(f"Error processing URL: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error processing URL: {str(e)}")
