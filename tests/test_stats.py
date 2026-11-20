import numpy as np
import pandas as pd
import pytest
from tlslab.analysis.stats import (
    exact_rate_ci, paired_contrasts, distribution_summary, rank_biserial,
    bootstrap_median_ratio
)


def test_exact_rate_and_summary():
    ci = exact_rate_ci(10, 10)
    assert ci["rate"] == 1
    assert ci["ci_low"] < 1 and ci["ci_high"] == 1
    assert distribution_summary([1, 2, 3])["median"] == 2
    assert rank_biserial([1, 2, -3]) > -1


def test_paired_conditions_with_known_block_factor():
    rows = []
    for block in range(1, 10):
        for condition, factor in (("P1", 1), ("P2", 2), ("A4", 0.5)):
            rows.append({"block": block, "condition": condition,
                         "throughput": factor * (100 + block)})
    result = paired_contrasts(pd.DataFrame(rows), metric="throughput", reference="P1")
    assert len(result) == 2
    assert np.isclose(result.set_index("condition").loc["P2", "median_ratio"], 2)
    assert "p_holm" in result
    # Constant within-block ratios make the BCa interval undefined.
    assert result["ci_low"].isna().all()
    assert result["ci_high"].isna().all()


def test_insufficient_blocks_rejected():
    with pytest.raises(ValueError):
        paired_contrasts(pd.DataFrame({"block":[1], "condition":["P1"], "x":[1]}),
                         metric="x", reference="P1")


def test_degenerate_bca_ratio_is_explicitly_unavailable():
    reference = np.arange(101., 110.)
    low, high = bootstrap_median_ratio(2 * reference, reference)
    assert np.isnan(low) and np.isnan(high)


def test_non_degenerate_paired_ratio_has_finite_interval():
    reference = np.arange(101., 113.)
    ratio = np.array([1.1, 1.4, 1.2, 1.5, 1.3, 1.7,
                      1.25, 1.45, 1.35, 1.6, 1.15, 1.55])
    low, high = bootstrap_median_ratio(reference * ratio, reference)
    assert np.isfinite(low) and np.isfinite(high)
    assert low <= high
