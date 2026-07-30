"""
multirun_error_bars.py
=======================
Stability / test-retest reliability analysis across the 5 prompt-preamble
runs (prompts_cvss4_0_a..e — see run_eval.sh). This is a SELF-consistency
study: NO external ground truth is used anywhere in this script (no ClawHub
verdict, no other baseline). The question it answers is exactly the one a
reviewer asking for "stability across repeated runs" wants answered:
regardless of which of the 5 prompt wordings evaluates a skill, does
SkillVetBench arrive at the same verdict?

INPUT LAYOUT (must already exist — this script only reads):
    reports/
      prompts_cvss4_0_a/<model_slug>/<skill>.md.json
      prompts_cvss4_0_b/<model_slug>/<skill>.md.json
      prompts_cvss4_0_c/<model_slug>/<skill>.md.json
      prompts_cvss4_0_d/<model_slug>/<skill>.md.json
      prompts_cvss4_0_e/<model_slug>/<skill>.md.json

Each of the 5 folders is one full evaluation run of the SAME skills / SAME
evaluator model, differing only in the wording of the system-prompt preamble
(the "run-to-run" axis this reliability analysis measures). Three model
folders are expected under each variant (three evaluator models).

FOUR COMPLEMENTARY ANALYSES, per evaluator model
--------------------------------------------------
  1. Fleiss' kappa — categorical agreement across the 5 runs, for:
       (a) the full 5-level `overall_risk` label (NONE/LOW/MEDIUM/HIGH/CRITICAL)
       (b) the binary alarm flag (HIGH/CRITICAL vs. not — same rule used
           everywhere else in this project)
     Interpreted against the standard Landis & Koch (1977) benchmark scale.

  2. ICC(3,1) — intraclass correlation (two-way mixed, consistency, single
     measure; Shrout & Fleiss 1979) for the CONTINUOUS `cvss_base_score` and
     `sars_score` across the 5 runs. This is the standard test-retest
     reliability coefficient for a numeric measurement repeated under
     different conditions (here: different prompt wording).

  3. Unanimous / super-majority agreement rate — % of skills where all 5
     runs agree on the alarm flag, and % where at least 4 of 5 agree.

  4. Catch Rate / Correct Alarm / Miss Rate of an individual run against the
     5-run MAJORITY VOTE of that same model (i.e. "does this one run agree
     with its own 5-run consensus?") — mean +/- SD across the 5 runs, plus a
     95% Clopper-Pearson CI on the pooled counts. This keeps the exact three
     metric names the reviewer asked about, now framed correctly as a
     self-consistency check rather than a detection-accuracy claim.

Usage
-----
    pip install scipy pandas matplotlib statsmodels   # if not already installed
    python source_code/eval/multirun_error_bars.py
    python source_code/eval/multirun_error_bars.py --reports-dir reports --out-dir results/multirun_stability
"""

import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import beta
from statsmodels.stats.inter_rater import aggregate_raters, fleiss_kappa as _fleiss_kappa

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False


DEFAULT_VARIANTS = [
    "prompts_cvss4_0_a",
    "prompts_cvss4_0_b",
    "prompts_cvss4_0_c",
    "prompts_cvss4_0_d",
    "prompts_cvss4_0_e",
]

# Variant "a" was evaluated before top-N was pinned at 20 and has extra
# skills the other 4 variants don't — those are dropped automatically by
# intersecting skill sets per model (see common_skills()).


# ── SkillVetBench's own decision, read from a single report JSON ────────────

def overall_risk_label(record: dict):
    """Raw 5-level severity label, or None if missing/unparsed/record is None."""
    if not record:
        return None
    risk = (record.get("overall_risk") or "").strip().upper()
    return risk if risk in ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL") else None


def skillvetbench_flag(record: dict):
    """True = flagged (HIGH/CRITICAL). Same alarm rule used across the project."""
    risk = overall_risk_label(record)
    return None if risk is None else risk in ("HIGH", "CRITICAL")


# ─────────────────────────────────────────────────────────────────────────────
# Loading
# ─────────────────────────────────────────────────────────────────────────────

_TRAILING_RUN_SUFFIX = re.compile(r"_\d+$")


def canonical_model_name(dirname: str) -> str:
    """
    Strip an accidental trailing run-count suffix (e.g. 'gemma4_latest_1'
    from an early manual re-run) so the same model matches across variants.
    """
    return _TRAILING_RUN_SUFFIX.sub("", dirname)


def load_all(reports_dir: Path, variants: list) -> dict:
    """Returns data[model][variant][skill_filename] = report dict."""
    data: dict = {}
    dir_map: dict = {}  # canonical_model -> {variant: actual_dirname}

    for variant in variants:
        vdir = reports_dir / variant
        if not vdir.is_dir():
            print(f"WARNING: variant dir not found, skipping: {vdir}", file=sys.stderr)
            continue
        for model_dir in sorted(p for p in vdir.iterdir() if p.is_dir()):
            model = canonical_model_name(model_dir.name)
            dir_map.setdefault(model, {})[variant] = model_dir.name
            data.setdefault(model, {}).setdefault(variant, {})
            for jf in model_dir.glob("*.json"):
                if jf.name == "_index.json":
                    continue
                try:
                    record = json.loads(jf.read_text(encoding="utf-8"))
                except Exception as e:
                    print(f"WARNING: could not parse {jf}: {e}", file=sys.stderr)
                    continue
                skill = record.get("filename", jf.stem)
                data[model][variant][skill] = record

    print("\n[Config] Model directory name per variant (canonicalised):")
    for model, per_variant in dir_map.items():
        print(f"  {model}:")
        for v in variants:
            print(f"    {v:<20s} -> {per_variant.get(v, '(missing)')}")

    return data


def common_skills(model_data: dict, variants: list) -> set:
    """Skills with a report present in EVERY variant for this model."""
    sets = [set(model_data.get(v, {}).keys()) for v in variants]
    sets = [s for s in sets if s]
    if not sets:
        return set()
    common = sets[0]
    for s in sets[1:]:
        common &= s
    return common


def get_record(model_data: dict, variant: str, skill: str):
    """
    Fetch (model_data, variant, skill)'s report, or None if missing OR if the
    LLM call failed for that run (evaluator.py's `error` field is non-empty).
    A failed parse still carries a numeric cvss_base_score/sars_score
    fallback (from an all-N default CVSS vector) and overall_risk="ERROR" —
    both must be excluded from every stability metric below, not silently
    counted as a real (e.g. "no risk") data point.
    """
    r = model_data.get(variant, {}).get(skill)
    if not r or r.get("error"):
        return None
    return r


# ─────────────────────────────────────────────────────────────────────────────
# 1. Fleiss' kappa — categorical agreement across the 5 runs
# ─────────────────────────────────────────────────────────────────────────────

def kappa_interpretation(k: float) -> str:
    """Landis & Koch (1977) benchmark scale."""
    if np.isnan(k):
        return "n/a"
    if k < 0:
        return "poor"
    if k < 0.20:
        return "slight"
    if k < 0.40:
        return "fair"
    if k < 0.60:
        return "moderate"
    if k < 0.80:
        return "substantial"
    return "almost perfect"


def fleiss_kappa_for(model_data: dict, skills: list, variants: list, label_fn) -> tuple:
    """
    label_fn(record) -> a hashable category label, or None to exclude that
    skill (only skills with a label in ALL 5 runs are used).
    Returns (kappa, n_skills_used).
    """
    rows = []
    for s in skills:
        labels = []
        for v in variants:
            r = get_record(model_data, v, s)
            lab = label_fn(r) if r else None
            if lab is None:
                break
            labels.append(str(lab))
        if len(labels) == len(variants):
            rows.append(labels)
    if len(rows) < 2:
        return float("nan"), len(rows)
    table, _ = aggregate_raters(np.array(rows))
    return float(_fleiss_kappa(table, method="fleiss")), len(rows)


# ─────────────────────────────────────────────────────────────────────────────
# 2. ICC(3,1) — continuous-score stability across the 5 runs
# ─────────────────────────────────────────────────────────────────────────────

def icc_3_1(data: np.ndarray) -> float:
    """
    Two-way mixed effects, consistency, single measurement (Shrout & Fleiss
    1979). data shape: (n_subjects, k_raters) — here (n_skills, 5_runs).
    """
    n, k = data.shape
    if n < 2 or k < 2:
        return float("nan")
    grand_mean  = data.mean()
    subj_means  = data.mean(axis=1)
    rater_means = data.mean(axis=0)

    ss_total    = ((data - grand_mean) ** 2).sum()
    ss_subjects = k * ((subj_means - grand_mean) ** 2).sum()
    ss_raters   = n * ((rater_means - grand_mean) ** 2).sum()
    ss_error    = ss_total - ss_subjects - ss_raters

    ms_subjects = ss_subjects / (n - 1)
    ms_error    = ss_error / ((n - 1) * (k - 1)) if (n - 1) * (k - 1) > 0 else float("nan")

    denom = ms_subjects + (k - 1) * ms_error
    if denom == 0 or np.isnan(denom):
        return float("nan")
    return float((ms_subjects - ms_error) / denom)


def score_stability(model_data: dict, skills: list, variants: list, score_field: str) -> dict:
    """ICC(3,1) and mean within-skill SD for a continuous score field."""
    rows = []
    for s in skills:
        vals = []
        for v in variants:
            r = get_record(model_data, v, s)
            val = r.get(score_field) if r else None
            if isinstance(val, (int, float)):
                vals.append(float(val))
        if len(vals) == len(variants):
            rows.append(vals)
    if len(rows) < 2:
        return {"icc": float("nan"), "mean_within_skill_sd": float("nan"), "n_skills": len(rows)}
    arr = np.array(rows)
    within_sds = arr.std(axis=1, ddof=1)
    return {
        "icc": icc_3_1(arr),
        "mean_within_skill_sd": float(within_sds.mean()),
        "n_skills": len(rows),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Parse-success rate — a model that can't reliably produce valid JSON at all
# will trivially show 0 usable skills for every reliability metric below;
# report this explicitly so a NaN reads as "unusable output", not "no data".
# ─────────────────────────────────────────────────────────────────────────────

def parse_success_rate(model_data: dict, skills: list, variants: list) -> dict:
    per_run = {}
    for v in variants:
        valid = sum(1 for s in skills if get_record(model_data, v, s) is not None)
        per_run[v] = valid / len(skills) if skills else float("nan")
    overall = float(np.mean(list(per_run.values()))) if per_run else float("nan")
    return {"per_run": per_run, "mean": overall}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Unanimous / super-majority agreement on the alarm flag
# ─────────────────────────────────────────────────────────────────────────────

def agreement_rates(model_data: dict, skills: list, variants: list) -> dict:
    unanimous = supermajority = total = 0
    for s in skills:
        records = [get_record(model_data, v, s) for v in variants]
        flags = [skillvetbench_flag(r) if r else None for r in records]
        flags = [f for f in flags if f is not None]
        if len(flags) != len(variants):
            continue
        total += 1
        pos = sum(flags)
        neg = len(flags) - pos
        if pos == len(flags) or neg == len(flags):
            unanimous += 1
        if max(pos, neg) >= 4:
            supermajority += 1
    return {
        "n_skills": total,
        "unanimous_rate":     (unanimous / total) if total else float("nan"),
        "supermajority_rate": (supermajority / total) if total else float("nan"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 4. Catch Rate / Correct Alarm / Miss Rate vs. the 5-run majority vote
# ─────────────────────────────────────────────────────────────────────────────

def confusion(pred_flags: list, gt_flags: list) -> dict:
    tp = fp = fn = tn = excluded = 0
    for pred, gt in zip(pred_flags, gt_flags):
        if pred is None or gt is None:
            excluded += 1
            continue
        if pred and gt:
            tp += 1
        elif pred and not gt:
            fp += 1
        elif not pred and gt:
            fn += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "excluded": excluded}


def rates_from_confusion(c: dict) -> dict:
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    return {
        "catch_rate":    tp / (tp + fn) if (tp + fn) > 0 else float("nan"),
        "miss_rate":     fn / (tp + fn) if (tp + fn) > 0 else float("nan"),
        "correct_alarm": tp / (tp + fp) if (tp + fp) > 0 else float("nan"),
        "catch_rate_kn":    (tp, tp + fn),
        "correct_alarm_kn": (tp, tp + fp),
    }


def clopper_pearson(k: int, n: int, alpha: float = 0.05):
    if n == 0:
        return (float("nan"), float("nan"))
    lo = 0.0 if k == 0 else beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - alpha / 2, k + 1, n - k)
    return (lo, hi)


def aggregate_runs(per_run_rates: list, alpha: float = 0.05) -> dict:
    out = {}
    for metric, kn_key, flip in (
        ("catch_rate",    "catch_rate_kn",    False),
        ("miss_rate",     "catch_rate_kn",    True),
        ("correct_alarm", "correct_alarm_kn", False),
    ):
        vals = np.array([r[metric] for r in per_run_rates], dtype=float)
        vals = vals[~np.isnan(vals)]
        mean = float(np.mean(vals)) if len(vals) else float("nan")
        std  = float(np.std(vals, ddof=1)) if len(vals) > 1 else float("nan")

        pooled_k = sum(r[kn_key][0] for r in per_run_rates)
        pooled_n = sum(r[kn_key][1] for r in per_run_rates)
        if flip:
            pooled_k = pooled_n - pooled_k
        ci_lo, ci_hi = clopper_pearson(pooled_k, pooled_n, alpha)

        out[metric] = {
            "mean": mean, "std": std, "n_runs": int(len(vals)),
            "pooled_k": int(pooled_k), "pooled_n": int(pooled_n),
            "ci_lo": ci_lo, "ci_hi": ci_hi,
        }
    return out


def run_self_consistency(model_data: dict, skills: list, variants: list) -> list:
    """Majority vote of SkillVetBench's own 5-run flags = reference; score each run against it."""
    majority = {}
    for s in skills:
        flags_per_run = [skillvetbench_flag(get_record(model_data, v, s)) for v in variants]
        votes = [f for f in flags_per_run if f is not None]
        majority[s] = (sum(votes) > len(votes) / 2) if votes else None

    per_run = []
    for v in variants:
        records = [get_record(model_data, v, s) for s in skills]
        preds = [skillvetbench_flag(r) if r else None for r in records]
        gts   = [majority.get(s) for s in skills]
        c = confusion(preds, gts)
        per_run.append({**rates_from_confusion(c), "_confusion": c, "_variant": v})
    return per_run


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def plot_consistency_bars(consistency_summary: pd.DataFrame, out_dir: Path):
    if not HAS_MPL:
        return
    metrics = ["catch_rate", "correct_alarm", "miss_rate"]
    metric_labels = {"catch_rate": "Catch Rate", "correct_alarm": "Correct Alarm", "miss_rate": "Miss Rate"}
    models = sorted(consistency_summary["model"].unique())
    x = np.arange(len(models))

    fig, axes = plt.subplots(1, len(metrics), figsize=(5 * len(metrics), 4.2), sharey=True)
    for ax, metric in zip(axes, metrics):
        sub = consistency_summary[consistency_summary["metric"] == metric].set_index("model").reindex(models)
        means = sub["mean"].to_numpy(dtype=float)
        stds  = sub["std"].to_numpy(dtype=float)
        ax.bar(x, np.nan_to_num(means), yerr=np.nan_to_num(stds), capsize=5, color="#2b6cb0")
        for xi, val in zip(x, means):
            if np.isnan(val):
                ax.text(xi, 0.02, "N/A", rotation=90, fontsize=7, ha="center", va="bottom", color="#2b6cb0")
        ax.set_xticks(x)
        ax.set_xticklabels(models, rotation=20, ha="right")
        ax.set_title(metric_labels[metric])
        ax.set_ylim(0, 1.05)
        ax.grid(axis="y", alpha=0.3)
    axes[0].set_ylabel("Rate vs. 5-run majority vote\n(mean ± SD across 5 prompt variants)")
    fig.suptitle("Self-consistency: does each run agree with its own 5-run consensus?")
    fig.tight_layout()
    path = out_dir / "self_consistency_error_bars.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved figure: {path}")


def plot_kappa_bars(reliability: pd.DataFrame, out_dir: Path):
    if not HAS_MPL:
        return
    models = reliability["model"].tolist()
    x = np.arange(len(models))
    width = 0.35

    kappa_risk = reliability["fleiss_kappa_overall_risk"].to_numpy(dtype=float)
    kappa_flag = reliability["fleiss_kappa_alarm_flag"].to_numpy(dtype=float)

    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(x - width / 2, np.nan_to_num(kappa_risk), width, label="overall_risk (5-level)", color="#2b6cb0")
    ax.bar(x + width / 2, np.nan_to_num(kappa_flag), width, label="alarm flag (binary)", color="#dd6b20")

    # NaN (undefined — model's output too often failed to parse at all) would
    # otherwise render as an invisible zero-height bar, misreadable as kappa=0
    # ("poor agreement") rather than "not computable". Label it explicitly.
    for xi, val in zip(x - width / 2, kappa_risk):
        if np.isnan(val):
            ax.text(xi, 0.02, "N/A", rotation=90, fontsize=7, ha="center", va="bottom", color="#2b6cb0")
    for xi, val in zip(x + width / 2, kappa_flag):
        if np.isnan(val):
            ax.text(xi, 0.02, "N/A", rotation=90, fontsize=7, ha="center", va="bottom", color="#dd6b20")

    for y, txt in ((0.20, "slight"), (0.40, "fair"), (0.60, "moderate"), (0.80, "substantial")):
        ax.axhline(y, color="gray", linestyle=":", linewidth=0.8)
        ax.text(len(models) - 0.4, y + 0.01, txt, fontsize=7, color="gray", ha="right")

    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=20, ha="right")
    ax.set_ylabel("Fleiss' kappa across 5 runs")
    ax.set_ylim(0, 1.05)
    ax.set_title("Inter-run categorical agreement (Landis & Koch bands)")
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = out_dir / "fleiss_kappa.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved figure: {path}")


def plot_score_spread(model_data: dict, skills: list, variants: list, model: str,
                      score_field: str, out_dir: Path):
    if not HAS_MPL:
        return
    skills = sorted(skills)
    rows = []
    for s in skills:
        records = [get_record(model_data, v, s) for v in variants]
        vals = [r.get(score_field) for r in records if r is not None]
        vals = [v for v in vals if isinstance(v, (int, float))]
        if len(vals) == len(variants):
            rows.append((s, vals))
    if not rows:
        return

    fig, ax = plt.subplots(figsize=(max(8, 0.4 * len(rows)), 4.5))
    for i, (s, vals) in enumerate(rows):
        ax.plot([i, i], [min(vals), max(vals)], color="#a0aec0", linewidth=1.5, zorder=1)
        ax.scatter([i] * len(vals), vals, color="#2b6cb0", s=18, zorder=2)
        ax.scatter([i], [np.mean(vals)], color="#c53030", marker="_", s=200, zorder=3)
    ax.set_xticks(range(len(rows)))
    ax.set_xticklabels([s for s, _ in rows], rotation=75, ha="right", fontsize=7)
    ax.set_ylabel(score_field)
    ax.set_title(f"{score_field} across 5 prompt-variant runs — {model}\n"
                f"(gray bar = min-max range, dots = individual runs, red tick = mean)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    path = out_dir / f"score_spread_{score_field}_{model}.png"
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved figure: {path}")


def print_reviewer_sentences(reliability: pd.DataFrame, consistency_summary: pd.DataFrame, n_runs: int):
    print("\n" + "=" * 78)
    print("  Draft reviewer-response sentences (fill in / trim as needed)")
    print("=" * 78)
    for _, row in reliability.iterrows():
        model = row["model"]
        cs = {r.metric: r for r in consistency_summary[consistency_summary["model"] == model].itertuples()}
        print(f"\n[model = {model}]  (n={n_runs} prompt-preamble runs, {int(row['n_skills_kappa'])} skills)")
        print(
            f"  Parse success rate (valid JSON returned) = {row['parse_success_rate_mean']*100:.1f}% "
            f"of {int(row['n_skills_total'])} skills, averaged over the {n_runs} runs"
        )
        if np.isnan(row["fleiss_kappa_overall_risk"]) and row["parse_success_rate_mean"] < 0.9:
            print(
                "  NOTE: reliability metrics below are undefined (NaN) for this model — too few "
                "skills returned a parseable answer in ALL 5 runs simultaneously to compute them. "
                "This itself is a finding: this model's *output-format* reliability, not just its "
                "security judgment, is the limiting factor."
            )
        print(
            f"  Fleiss' kappa (overall_risk, 5-level)  = {row['fleiss_kappa_overall_risk']:.3f} "
            f"({kappa_interpretation(row['fleiss_kappa_overall_risk'])} agreement)"
        )
        print(
            f"  Fleiss' kappa (alarm flag, binary)     = {row['fleiss_kappa_alarm_flag']:.3f} "
            f"({kappa_interpretation(row['fleiss_kappa_alarm_flag'])} agreement)"
        )
        print(
            f"  ICC(3,1) CVSS score                    = {row['icc_cvss_score']:.3f}  "
            f"(mean within-skill SD = {row['mean_sd_cvss_score']:.3f})"
        )
        print(
            f"  ICC(3,1) SARS score                    = {row['icc_sars_score']:.3f}  "
            f"(mean within-skill SD = {row['mean_sd_sars_score']:.3f})"
        )
        print(
            f"  Unanimous agreement (5/5 runs)          = {row['unanimous_rate']*100:.1f}% of skills"
        )
        print(
            f"  Super-majority agreement (>=4/5 runs)   = {row['supermajority_rate']*100:.1f}% of skills"
        )
        if all(m in cs for m in ("catch_rate", "correct_alarm", "miss_rate")):
            cr, ca, mr = cs["catch_rate"], cs["correct_alarm"], cs["miss_rate"]
            print(
                f"  Catch Rate vs. 5-run majority           = {cr.mean:.3f} +/- {cr.std:.3f} (SD), "
                f"95% CP CI [{cr.ci95_lo:.3f}, {cr.ci95_hi:.3f}]"
            )
            print(
                f"  Correct Alarm vs. 5-run majority        = {ca.mean:.3f} +/- {ca.std:.3f} (SD), "
                f"95% CP CI [{ca.ci95_lo:.3f}, {ca.ci95_hi:.3f}]"
            )
            print(
                f"  Miss Rate vs. 5-run majority             = {mr.mean:.3f} +/- {mr.std:.3f} (SD), "
                f"95% CP CI [{mr.ci95_lo:.3f}, {mr.ci95_hi:.3f}]"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Multi-run (5 prompt-variant) stability / test-retest reliability "
                    "analysis: Fleiss' kappa, ICC(3,1), agreement rates, and "
                    "Catch Rate / Correct Alarm / Miss Rate vs. the 5-run majority "
                    "vote. No external ground truth (no ClawHub) is used.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--reports-dir", default="reports", metavar="DIR")
    parser.add_argument(
        "--variants", default=",".join(DEFAULT_VARIANTS), metavar="LIST",
        help="Comma-separated prompt-variant folder names under --reports-dir",
    )
    parser.add_argument("--out-dir", default="results/multirun_stability", metavar="DIR")
    parser.add_argument("--alpha", default=0.05, type=float, help="1 - confidence level for the Clopper-Pearson CI")
    parser.add_argument("--no-plots", action="store_true", help="Skip PNG figure generation")
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir).expanduser().resolve()
    out_dir     = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    variants = [v.strip() for v in args.variants.split(",") if v.strip()]

    print(f"Reports dir : {reports_dir}")
    print(f"Variants    : {variants}")
    print(f"Out dir     : {out_dir}")

    data = load_all(reports_dir, variants)
    if not data:
        print("ERROR: no data loaded — check --reports-dir / --variants.", file=sys.stderr)
        sys.exit(1)

    reliability_rows = []
    consistency_rows = []

    for model, model_data in data.items():
        skills = sorted(common_skills(model_data, variants))
        if not skills:
            print(f"WARNING: no skills common to all variants for model '{model}' — skipping.", file=sys.stderr)
            continue
        print(f"\n[{model}] {len(skills)} skill(s) common to all {len(variants)} variants")

        parse_rate = parse_success_rate(model_data, skills, variants)
        print(f"  Parse success rate per run: " +
              ", ".join(f"{v}={r*100:.0f}%" for v, r in parse_rate["per_run"].items()) +
              f"  (mean={parse_rate['mean']*100:.0f}%)")

        kappa_risk, n_kappa = fleiss_kappa_for(model_data, skills, variants, overall_risk_label)
        kappa_flag, _       = fleiss_kappa_for(model_data, skills, variants, skillvetbench_flag)
        cvss_stab = score_stability(model_data, skills, variants, "cvss_base_score")
        sars_stab = score_stability(model_data, skills, variants, "sars_score")
        agree     = agreement_rates(model_data, skills, variants)

        reliability_rows.append({
            "model": model,
            "n_skills_total": len(skills),
            "parse_success_rate_mean": parse_rate["mean"],
            "n_skills_kappa": n_kappa,
            "fleiss_kappa_overall_risk": kappa_risk,
            "fleiss_kappa_alarm_flag":   kappa_flag,
            "icc_cvss_score":     cvss_stab["icc"],
            "mean_sd_cvss_score": cvss_stab["mean_within_skill_sd"],
            "icc_sars_score":     sars_stab["icc"],
            "mean_sd_sars_score": sars_stab["mean_within_skill_sd"],
            "unanimous_rate":     agree["unanimous_rate"],
            "supermajority_rate": agree["supermajority_rate"],
        })

        per_run = run_self_consistency(model_data, skills, variants)
        agg = aggregate_runs(per_run, alpha=args.alpha)
        for metric in ("catch_rate", "correct_alarm", "miss_rate"):
            a = agg[metric]
            consistency_rows.append({
                "model": model, "metric": metric,
                "mean": a["mean"], "std": a["std"],
                "ci95_lo": a["ci_lo"], "ci95_hi": a["ci_hi"],
                "n_runs": a["n_runs"], "pooled_k": a["pooled_k"], "pooled_n": a["pooled_n"],
            })

        if not args.no_plots:
            plot_score_spread(model_data, skills, variants, model, "cvss_base_score", out_dir)

    reliability = pd.DataFrame(reliability_rows)
    consistency_summary = pd.DataFrame(consistency_rows)

    reliability_path = out_dir / "reliability_summary.csv"
    consistency_path = out_dir / "self_consistency_summary.csv"
    reliability.to_csv(reliability_path, index=False)
    consistency_summary.to_csv(consistency_path, index=False)

    print("\n" + "=" * 78)
    print("  Reliability summary (Fleiss' kappa, ICC(3,1), agreement rates)")
    print("=" * 78)
    with pd.option_context("display.max_rows", None, "display.width", 160):
        print(reliability.round(4).to_string(index=False))

    print("\n" + "=" * 78)
    print("  Self-consistency summary (Catch Rate / Correct Alarm / Miss Rate")
    print("  vs. the 5-run majority vote)")
    print("=" * 78)
    with pd.option_context("display.max_rows", None, "display.width", 160):
        print(consistency_summary.round(4).to_string(index=False))

    print(f"\nSaved: {reliability_path}")
    print(f"Saved: {consistency_path}")

    if not args.no_plots:
        plot_consistency_bars(consistency_summary, out_dir)
        plot_kappa_bars(reliability, out_dir)

    print_reviewer_sentences(reliability, consistency_summary, len(variants))


if __name__ == "__main__":
    main()
