from fastapi import APIRouter, HTTPException
from app.schemas.url_schema import URLRequest, AnalysisResult
from app.services.preprocessing import preprocessor  # Import the service
from app.services.database import db_service  # Import the new DB service
from app.services.api_integration import api_manager  # Import the API manager
from app.services.heuristics import heuristic_engine  # Import the heuristic engine
from app.services.scoring import risk_aggregator  # Import the risk aggregator
import logging

# Set up logging
logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/scan", response_model=AnalysisResult)
async def scan_url(request: URLRequest):
    """
    Receives a URL, processes it through the complete analysis pipeline,
    and returns a comprehensive risk assessment with actionable recommendations.
    
    Pipeline:
    1. Preprocessing: Sanitization, IDN conversion, feature extraction
    2. Local Database: Bloom filter + SQLite check for known threats
    3. External APIs: Google Safe Browsing, PhishTank (parallel async)
    4. Heuristic Analysis: Typosquatting, keywords, structure, domain age
    5. Risk Aggregation: Weighted scoring and final verdict
    """
    try:
        # Phase 2: Preprocessing
        url_components = preprocessor.normalize(str(request.url))
        clean_url = url_components['full_url']
        
        logger.info(f"Received URL for scanning: {clean_url}")

        # Phase 3: Check Local Database (Speed Layer)
        db_match = db_service.check_url(clean_url)
        
        # Phase 4: Check External APIs (if not in local DB)
        api_result = await api_manager.check_url(clean_url)
        
        # Phase 5: Run Heuristic Analysis
        heuristic_result = heuristic_engine.analyze(url_components)
        
        # Phase 6: Risk Aggregation
        aggregated_result = risk_aggregator.calculate_risk(
            db_result=db_match,
            api_result=api_result,
            heuristic_result=heuristic_result,
            url_components=url_components
        )
        
        # Get actionable recommendation
        recommendation = risk_aggregator.get_recommendation(
            aggregated_result["status"],
            aggregated_result["risk_score"]
        )
        
        return AnalysisResult(
            url=clean_url,
            status=aggregated_result["status"],
            risk_score=aggregated_result["risk_score"],
            verdict_source=aggregated_result["verdict_source"],
            reasons=aggregated_result["reasons"],
            recommendation=recommendation,
            details=aggregated_result["details"]
        )
        
    except HTTPException as e:
        raise e
    except Exception as e:
        # Fallback for unexpected parsing errors
        logger.error(f"Error processing URL: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error processing URL: {str(e)}")
