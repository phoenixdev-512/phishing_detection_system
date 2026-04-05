from pydantic import BaseModel, HttpUrl, Field
from typing import List, Dict, Any, Optional

class URLRequest(BaseModel):
    url: HttpUrl = Field(..., description="The target URL to scan")

class SiblingDomain(BaseModel):
    domain: str
    weight: float
    is_known_malicious: bool
    jaccard_similarity: float

class GraphSummary(BaseModel):
    total_nodes: int
    total_edges: int
    edge_counts: dict[str, int]
    expected_edges: dict[str, float]

class AnalysisResult(BaseModel):
    url: str
    status: str = Field(..., description="safe, suspicious, or malicious")      
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0-100")
    verdict_source: str = Field(..., description="Which layer caught it? (DB, API, Heuristic)")
    reasons: List[str] = Field(default=[], description="Explainable reasons for the verdict")
    recommendation: Optional[str] = Field(None, description="Actionable recommendation for the user")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional analysis details for transparency")

    # NEW TGIS FIELDS
    tgis_score: float | None = None
    tis_score: float | None = None
    scp_score: float | None = None
    residual_heuristic: float | None = None
    domain_age_days: float | None = None
    scp_activated: bool | None = None
    siblings: list[SiblingDomain] = Field(default_factory=list)
    graph_summary: GraphSummary | None = None
    graph_json: dict | None = None

    class Config:
        populate_by_name = True

