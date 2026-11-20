"""Paired-block inference and exact binomial intervals for frozen E1-E7 contrasts."""
from __future__ import annotations

import warnings

import numpy as np
import pandas as pd
from scipy import stats
from statsmodels.stats.multitest import multipletests


def rank_biserial(diff):
    d = np.asarray(diff, dtype=float)
    d = d[np.isfinite(d) & (d != 0)]
    if len(d) == 0:
        return float("nan")
    ranks = stats.rankdata(np.abs(d))
    positive = ranks[d > 0].sum()
    negative = ranks[d < 0].sum()
    return float((positive - negative) / (positive + negative))


def exact_rate_ci(successes: int, trials: int, confidence: float = .95):
    if trials <= 0 or successes < 0 or successes > trials:
        raise ValueError("invalid binomial counts")
    result = stats.binomtest(successes, trials).proportion_ci(confidence_level=confidence,
                                                               method="exact")
    return {"k": successes, "n": trials, "rate": successes / trials,
            "ci_low": result.low, "ci_high": result.high}


def distribution_summary(data):
    values = np.asarray(data, dtype=float)
    values = values[np.isfinite(values)]
    if not values.size:
        raise ValueError("no finite measurements")
    return {"n": int(values.size), "median": float(np.median(values)),
            "mean": float(np.mean(values)), "sd": float(np.std(values, ddof=1)) if len(values)>1 else float("nan"),
            "q1": float(np.percentile(values, 25)), "q3": float(np.percentile(values, 75)),
            "p95": float(np.percentile(values, 95)), "p99": float(np.percentile(values, 99))}


def bootstrap_median_ratio(a, b, *, seed: int = 20261112):
    a, b = np.asarray(a, dtype=float), np.asarray(b, dtype=float)
    if len(a) != len(b) or len(a) < 3 or np.any(b <= 0):
        raise ValueError("paired bootstrap requires >= 3 positive-reference blocks")
    def statistic(x, y, *, axis):
        return np.median(x / y, axis=axis)
    # A constant paired ratio makes BCa acceleration undefined. Do not
    # manufacture a zero-width confidence interval for a synthetic sample.
    ratios = a / b
    if np.all(ratios == ratios[0]):
        return float("nan"), float("nan")
    with np.errstate(all="ignore"), warnings.catch_warnings():
        # SciPy signals an undefined BCa interval with a warning (not a
        # ValueError). Convert only this specific warning into an exception.
        warnings.simplefilter("error", stats.DegenerateDataWarning)
        try:
            ci = stats.bootstrap((a, b), statistic, paired=True, vectorized=True,
                                 method="BCa", n_resamples=10000,
                                 confidence_level=.95, rng=np.random.default_rng(seed))
        except (stats.DegenerateDataWarning, ValueError):
            return float("nan"), float("nan")
    low, high = float(ci.confidence_interval.low), float(ci.confidence_interval.high)
    return (low, high) if np.isfinite(low) and np.isfinite(high) else (float("nan"), float("nan"))


def paired_contrasts(df: pd.DataFrame, *, metric: str, reference: str,
                     condition: str = "condition", block: str = "block") -> pd.DataFrame:
    if len({metric, condition, block} - set(df.columns)):
        raise ValueError("missing required paired-comparison columns")
    wide = df.pivot_table(index=block, columns=condition, values=metric, aggfunc="median")
    # Complete-case block pairing; exclusions must be logged in the experiment manifest.
    wide = wide.dropna(how="any")
    if reference not in wide.columns or len(wide) < 3 or wide.shape[1] < 2:
        raise ValueError("insufficient complete paired blocks or missing reference")
    if wide.shape[1] >= 3:
        fr = stats.friedmanchisquare(*(wide[c].to_numpy() for c in wide.columns))
        friedman_p = float(fr.pvalue)
        kendall_w = float(fr.statistic / (len(wide) * (wide.shape[1]-1)))
    else:
        friedman_p, kendall_w = float("nan"), float("nan")
    ref = wide[reference].to_numpy(dtype=float)
    rows = []
    for name in wide.columns:
        if name == reference:
            continue
        vals = wide[name].to_numpy(dtype=float)
        if (vals <= 0).any() or (ref <= 0).any():
            raise ValueError("throughput/latency ratio requires positive observations")
        diff = vals - ref
        p = 1.0 if np.all(diff == 0) else float(stats.wilcoxon(
            vals, ref, zero_method="wilcox", alternative="two-sided").pvalue)
        low, high = bootstrap_median_ratio(vals, ref)
        rows.append({"condition": name, "reference": reference, "n_blocks": len(wide),
                     "median_ratio": float(np.median(vals / ref)),
                     "ci_low": low, "ci_high": high, "p_raw": p,
                     "rank_biserial": rank_biserial(diff), "friedman_p": friedman_p,
                     "kendall_w": kendall_w})
    adjusted = multipletests([r["p_raw"] for r in rows], method="holm")[1]
    for row, adj in zip(rows, adjusted):
        row["p_holm"] = float(adj)
    return pd.DataFrame(rows)


def summarize_grouped(df: pd.DataFrame, group_cols: list[str], metric: str):
    out = []
    for key, subset in df.groupby(group_cols, dropna=False):
        fields = dict(zip(group_cols, key if isinstance(key, tuple) else (key,)))
        fields.update(distribution_summary(subset[metric]))
        out.append(fields)
    return pd.DataFrame(out)
