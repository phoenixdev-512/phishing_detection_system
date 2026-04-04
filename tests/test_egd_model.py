import pytest
from app.services.egd_model import EGDModel
from app.core.config import settings

def test_egd_properties():
    # Test age clamping
    model1 = EGDModel()
    model1.compute_all_baselines(-5)
    assert model1.clamped_age_days == 0.0
    
    model2 = EGDModel()
    model2.compute_all_baselines(5000)
    assert model2.clamped_age_days == 3650.0
    
    # Test whois failed fallback
    model3 = EGDModel()
    model3.compute_all_baselines(None)
    assert model3.whois_failed is True
    assert model3.clamped_age_days == 1.0

def test_curve_math():
    model = EGDModel()
    model.compute_all_baselines(0.0)
    infra_params = settings.EGD_PARAMS["infrastructure"]
    
    # At a=0, E = gamma
    val_0 = model.expected_edges("infrastructure", 0.0)
    assert val_0 == infra_params["gamma"]
    
    # At large a, E approaches alpha + gamma
    val_large = model.expected_edges("infrastructure", 3650.0)
    assert abs(val_large - (infra_params["alpha"] + infra_params["gamma"])) < 0.1
