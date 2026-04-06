import json
import os
import logging
import pickle
from pathlib import Path
import numpy as np
from app.services.tis_calculator import TISResult
from app.services.scp_calculator import SCPResult

logger = logging.getLogger(__name__)

MODEL_PATH = Path("data/ml_model.pkl")
ENABLED = MODEL_PATH.exists()

def build_feature_vector(
    tis_result: TISResult,
    scp_result: SCPResult,
    residual_heuristic: float,
    graph_node_count: int,
    graph_edge_count: int,
) -> list[float]:
    """
    Construct an 18-dimensional feature vector from TGIS pipeline outputs.
    """
    return [
        tis_result.tis_score,
        scp_result.scp_score if scp_result.scp_activated else 0.0,
        residual_heuristic,
        tis_result.domain_age_days or 0.0,
        float(tis_result.whois_failed),
        float(scp_result.scp_activated),
        float(len(scp_result.siblings_found) if scp_result.siblings_found else 0),
        float(tis_result.observed_edges.get("infrastructure", 0)),
        float(tis_result.observed_edges.get("certificate", 0)),
        float(tis_result.observed_edges.get("ownership", 0)),
        float(tis_result.observed_edges.get("routing", 0)),
        float(tis_result.expected_edges.get("infrastructure", 0)),
        float(tis_result.expected_edges.get("certificate", 0)),
        float(tis_result.expected_edges.get("ownership", 0)),
        float(tis_result.expected_edges.get("routing", 0)),
        float(graph_node_count),
        float(graph_edge_count),
        float(max(scp_result.sibling_weights.values()) if scp_result.sibling_weights else 0.0),
    ]

def predict_ml_score(
    tis_result: TISResult,
    scp_result: SCPResult,
    residual_heuristic: float,
    graph_node_count: int,
    graph_edge_count: int,
) -> float | None:
    """
    Load the ML model, build the feature vector, and predict malicious probability.
    """
    if not MODEL_PATH.exists():
        return None

    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        
        features = build_feature_vector(
            tis_result, scp_result, residual_heuristic, graph_node_count, graph_edge_count
        )
        
        # predict_proba returns array of probabilities for classes [0, 1]
        # index 1 corresponds to "malicious" (label 1)
        prob = model.predict_proba([features])[0][1]
        
        # Clamp to [0.0, 1.0] just to be safe
        return max(0.0, min(1.0, prob))
        
    except Exception as e:
        logger.warning(f"Failed to predict ML score: {e}")
        return None
