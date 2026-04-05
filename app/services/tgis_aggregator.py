import dataclasses
from dataclasses import dataclass
from app.core.config import settings
from app.services.tis_calculator import TISResult
from app.services.scp_calculator import SCPResult

@dataclass
class TGISResult:
    tgis_score: float
    tis_score: float
    scp_score: float
    residual_heuristic: float
    status: str
    risk_score: int
    verdict_source: str
    reasons: list[str]
    recommendation: str
    domain_age_days: float
    scp_activated: bool

class TGISAggregator:
    def __init__(self, tis_result: TISResult, scp_result: SCPResult,
                 residual_heuristic: float, blacklist_hit: bool,
                 candidate_domain: str, known_malicious_set: set[str] = None):
        self.tis_result = tis_result
        self.scp_result = scp_result
        self.residual_heuristic = residual_heuristic
        self.blacklist_hit = blacklist_hit
        self.candidate_domain = candidate_domain
        self.known_malicious_set = known_malicious_set or set()
        
        self.alpha = settings.TGIS_ALPHA
        self.beta = settings.TGIS_BETA
        self.gamma = settings.TGIS_GAMMA

    def aggregate(self) -> TGISResult:
        if self.blacklist_hit:
            return TGISResult(
                tgis_score=1.0,
                tis_score=1.0,
                scp_score=1.0,
                residual_heuristic=1.0,
                status="malicious",
                risk_score=100,
                verdict_source="Blacklist",
                reasons=["Domain found in local malicious URL blacklist."],
                recommendation=self._get_recommendation("malicious"),
                domain_age_days=self.tis_result.domain_age_days,
                scp_activated=False
            )

        tgis = (self.alpha * self.tis_result.tis_score +
                self.beta * self.scp_result.scp_score +
                self.gamma * self.residual_heuristic)
        tgis = max(0.0, min(1.0, tgis))

        if tgis < 0.30:
            status = "safe"
        elif tgis < 0.60:
            status = "suspicious"
        else:
            status = "malicious"

        reasons = []
        for k, i_k in self.tis_result.per_type_isolation.items():
            if i_k > 0.5:
                obs = self.tis_result.observed_edges.get(k, 0)
                exp = self.tis_result.expected_edges.get(k, 0.0)
                reasons.append(f"TIS: {k} isolation {i_k:.2f} (observed {obs}, expected {exp:.1f})")

        if self.scp_result.scp_activated and self.scp_result.scp_score > 0:
            n_malicious = sum(1 for s in self.scp_result.siblings_found if s in self.known_malicious_set)
            reasons.append(
                f"SCP: {len(self.scp_result.siblings_found)} sibling(s) detected "
                f"(contamination score {self.scp_result.scp_score:.2f})"
            )

        if self.scp_result.scp_activated:
            age_hours = round(self.tis_result.domain_age_days * 24, 1)
            reasons.append(f"SCP activated: domain is {age_hours}h old")

        if self.residual_heuristic > 0.3:
            reasons.append(f"Residual heuristics flagged (score {self.residual_heuristic:.2f})")

        if not reasons:
            reasons.append("No significant threat indicators detected.")

        return TGISResult(
            tgis_score=tgis,
            tis_score=self.tis_result.tis_score,
            scp_score=self.scp_result.scp_score,
            residual_heuristic=self.residual_heuristic,
            status=status,
            risk_score=round(tgis * 100),
            verdict_source="TGIS",
            reasons=reasons,
            recommendation=self._get_recommendation(status),
            domain_age_days=self.tis_result.domain_age_days,
            scp_activated=self.scp_result.scp_activated
        )

    def _get_recommendation(self, status: str) -> str:
        if status == "safe":
            return "SAFE — No infrastructure anomalies detected. Always verify the URL matches your intended destination."
        elif status == "suspicious":
            return "SUSPICIOUS — Infrastructure graph shows partial isolation. Proceed with caution and verify the domain independently."
        elif status == "malicious":
            return "MALICIOUS — Do not visit this URL. Infrastructure analysis indicates a high-risk domain. Close this tab immediately."
        return ""

