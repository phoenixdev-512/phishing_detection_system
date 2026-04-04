from pydantic import BaseModel, HttpUrl, Field
from typing import List, Dict, Any, Optional

# Request Model: What the user sends
class URLRequest(BaseModel):
    # HttpUrl automatically validates that the string looks like a URL
    url: HttpUrl = Field(..., description="The target URL to scan")

# Response Model: What the system returns (based on Report logic)
class AnalysisResult(BaseModel):
    url: str
    status: str = Field(..., description="safe, suspicious, or malicious")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0-100")
    verdict_source: str = Field(..., description="Which layer caught it? (DB, API, Heuristic)")
    reasons: List[str] = Field(default=[], description="Explainable reasons for the verdict")
    recommendation: Optional[str] = Field(None, description="Actionable recommendation for the user")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional analysis details for transparency")
    
    # NEW TGIS FIELDS
    tgis_score: Optional[float] = None
    tis_score: Optional[float] = None
    scp_score: Optional[float] = None
    residual_heuristic: Optional[float] = None
    domain_age_days: Optional[float] = None
    scp_activated: Optional[bool] = None
    siblings: Optional[List[Dict[str, Any]]] = None
    graph_summary: Optional[Dict[str, Any]] = None
    graph_json: Optional[Dict[str, Any]] = None
