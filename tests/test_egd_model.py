# FILE 1: tests/test_egd_model.py
import pytest
import math
from app.services.egd_model import EGDModel

def test_baseline_at_zero_age():
    model = EGDModel()
    expected_gammas = {
        "infrastructure": 0.5,
        "certificate": 0.0,
        "ownership": 1.0,
        "routing": 0.2
    }
    for edge_type, expected_gamma in expected_gammas.items():
        actual = model.expected_edges(edge_type, 0.0)
        assert actual == pytest.approx(expected_gamma, abs=0.001)

def test_saturation_at_large_age():
    model = EGDModel()
    actual = model.expected_edges("infrastructure", 3650.0)
    assert actual == pytest.approx(18.5, abs=0.1)

def test_age_clamping_negative():
    model = EGDModel()
    actual_neg = model.expected_edges("infrastructure", -5.0)
    actual_zero = model.expected_edges("infrastructure", 0.0)
    assert actual_neg == actual_zero

def test_age_clamping_over_max():
    model = EGDModel()
    actual_over = model.expected_edges("infrastructure", 9999.0)
    actual_max = model.expected_edges("infrastructure", 3650.0)
    assert actual_over == actual_max

def test_compute_all_baselines_returns_four_keys():
    model = EGDModel()
    baselines = model.compute_all_baselines(30.0)
    for key in ["infrastructure", "certificate", "ownership", "routing"]:
        assert key in baselines

def test_whois_failed_forces_age_to_one():
    model = EGDModel()
    b1 = model.compute_all_baselines(0.0, whois_failed=False)
    b2 = model.compute_all_baselines(0.0, whois_failed=True)
    b3 = model.compute_all_baselines(1.0, whois_failed=False)
    
    assert b1["infrastructure"] != b2["infrastructure"]
    assert b2["infrastructure"] == b3["infrastructure"]
    assert b2["whois_failed"] is True

