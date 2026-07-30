#!/usr/bin/env python3
"""
multirun_variance_tests.py
==========================
Companion to multirun_error_bars.py for the 5 prompt-preamble runs
(prompts_cvss4_0_a..e). That script answers "how big is the run-to-run
variation" (SD, CIs, kappa, ICC); this one answers the question reviewers
usually ask next: "is the variation STATISTICALLY significant, and what does
it look like?" — using the standard repeated-measures toolbox:

  1. Friedman test (non-parametric repeated-measures ANOVA) per model and
     score field (cvss_base_score, sars_score): H0 = prompt preamble has no
     effect on the score. A non-significant p means run-to-run differences
     are consistent with noise.

  2. Kendall's W (coefficient of concordance) — effect-size companion of the
     Friedman test: how consistently the runs rank the skills. W near 1 =
     the 5 runs essentially agree on the skill ordering regardless of
     preamble wording. Interpreted on the usual scale
     (<0.3 weak, 0.3-0.5 moderate, 0.5-0.7 strong, >0.7 very strong).

  3. Bland-Altman plot — the standard test-retest agreement figure: each
     run's score minus the skill's 5-run mean, plotted against that mean,
     with bias and 95% limits of agreement (+-1.96 SD).

  4. Boxplot + jittered raw points per run — full score distribution of
     each run, not just mean +/- SD.

  5. Skill x run heatmap of cvss_base_score — visual proof that scores
     track the skill (rows) rather than the prompt preamble (columns).

Only skills with a valid (parseable, non-error) report in ALL 5 runs enter
the Friedman / Kendall's W / Bland-Altman computations; boxplots and
heatmaps use every available value (missing cells shown in gray).

Usage
-----
    python source_code/eval/multirun_variance_tests.py
    python source_code/eval/multirun_variance_tests.py --out-dir results/multirun_stability
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Reuse the loading / validity logic from the sibling script so both
# analyses always read the data exactly the same way.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from multirun_error_bars import (  # noqa: E402
    DEFAULT_VARIANTS,
    common_skills,
    get_record,
    load_all,
)

SCORE_FIELDS = ["cvss_base_score", "sars_score"]

DISPLAY_NAMES = {
    "cryptidbleh_gemma4-claude-sonnet-4.6": "gemma4-claude-sonnet-4.6",
    "gemma4_latest": "gemma4:latest",
    "qwen3.5_latest": "qwen3.5:latest",
}


# ─────────────────────────────────────────────────────────────────────────────
# Score matrix: rows = skills, cols = runs; only complete skills are kept
# ─────────────────────────────────────────────────────────────────────────────

def score_matrix(model_data: dict, skills: list, variants: list, field: str):
    """(matrix shape (n_complete_skills, n_runs), skill names) or (None, [])."""
    rows, names = [], []
    for s in skills:
        vals = []
        for v in variants:
            r = get_record(model_data, v, s)
            val = r.get(field) if r else None
            vals.append(float(val) if isinstance(val, (int, float)) else np.nan)
        if not np.isnan(vals).any():
            rows.append(vals)
            names.append(s)
    if not rows:
        return None, []
    return np.array(rows), names


# ─────────────────────────────────────────────────────────────────────────────
# 1+2. Friedman test and Kendall's W
# ─────────────────────────────────────────────────────────────────────────────

def kendalls_w(mat: np.ndarray) -> float:
    """Tie-corrected coefficient of concordance for a (n_subjects, k_raters)
    matrix. With this correction, n*(k-1)*W equals the Friedman chi2 exactly."""
    n, k = mat.shape
    ranks = np.apply_along_axis(stats.rankdata, 1, mat)  # rank raters per subject
    col_sums = ranks.sum(axis=0)
    s = ((col_sums - col_sums.mean()) ** 2).sum()
    # tie correction: scores repeat across runs, which would deflate W
    tie = sum((counts ** 3 - counts).sum()
              for _, counts in (np.unique(row, return_counts=True) for row in mat))
    denom = n ** 2 * (k ** 3 - k) - n * tie
    return float(12 * s / denom) if denom > 0 else float("nan")


def w_interpretation(w: float) -> str:
    if np.isnan(w):
        return "n/a"
    if w < 0.3:
        return "weak"
    if w < 0.5:
        return "moderate"
    if w < 0.7:
        return "strong"
    return "very strong"


def friedman_and_w(model_data, skills, variants, field):
    mat, _ = score_matrix(model_data, skills, variants, field)
    if mat is None or mat.shape[0] < 3:
        return {"n_skills": 0 if mat is None else mat.shape[0],
                "chi2": np.nan, "p_value": np.nan, "kendalls_w": np.nan}
    chi2, p = stats.friedmanchisquare(*[mat[:, i] for i in range(mat.shape[1])])
    return {"n_skills": mat.shape[0], "chi2": float(chi2), "p_value": float(p),
            "kendalls_w": kendalls_w(mat)}


# ─────────────────────────────────────────────────────────────────────────────
# 3. Bland-Altman plot (each run vs. the skill's 5-run mean)
# ─────────────────────────────────────────────────────────────────────────────

def plot_bland_altman(data, variants, out_dir):
    models = [m for m in data]
    fig, axes = plt.subplots(len(models), len(SCORE_FIELDS),
                             figsize=(6.2 * len(SCORE_FIELDS), 4.2 * len(models)),
                             squeeze=False)
    for row, model in enumerate(models):
        skills = sorted(common_skills(data[model], variants))
        for col, field in enumerate(SCORE_FIELDS):
            ax = axes[row][col]
            mat, _ = score_matrix(data[model], skills, variants, field)
            if mat is None:
                ax.text(0.5, 0.5, "insufficient complete data",
                        ha="center", va="center", transform=ax.transAxes)
                ax.set_title(f"{DISPLAY_NAMES.get(model, model)} — {field}")
                continue
            skill_mean = mat.mean(axis=1)
            avg = np.repeat(skill_mean, mat.shape[1])
            diff = (mat - skill_mean[:, None]).ravel()
            bias = diff.mean()
            loa = 1.96 * diff.std(ddof=1)

            ax.scatter(avg, diff, s=22, alpha=0.7, color="#2b6cb0", edgecolor="none")
            ax.axhline(bias, color="#c53030", linewidth=1.4,
                       label=f"bias = {bias:+.3f}")
            ax.axhline(bias + loa, color="#c53030", linewidth=1, linestyle="--",
                       label=f"95% LoA = ±{loa:.3f}")
            ax.axhline(bias - loa, color="#c53030", linewidth=1, linestyle="--")
            ax.axhline(0, color="gray", linewidth=0.7, linestyle=":")
            ax.set_xlabel("skill mean across 5 runs")
            ax.set_ylabel("run score − skill mean")
            ax.set_title(f"{DISPLAY_NAMES.get(model, model)} — {field}")
            ax.legend(fontsize=8, loc="upper right")
            ax.grid(alpha=0.3)
    fig.suptitle("Bland–Altman test–retest agreement across the 5 prompt-preamble runs")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    path = out_dir / "bland_altman_agreement.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Boxplot + jittered raw points per run
# ─────────────────────────────────────────────────────────────────────────────

def plot_run_boxplots(data, variants, out_dir):
    models = list(data)
    fig, axes = plt.subplots(len(models), len(SCORE_FIELDS),
                             figsize=(6.2 * len(SCORE_FIELDS), 4.0 * len(models)),
                             squeeze=False)
    for row, model in enumerate(models):
        skills = sorted(common_skills(data[model], variants))
        for col, field in enumerate(SCORE_FIELDS):
            ax = axes[row][col]
            per_run = []
            for v in variants:
                vals = []
                for s in skills:
                    r = get_record(data[model], v, s)
                    val = r.get(field) if r else None
                    if isinstance(val, (int, float)):
                        vals.append(float(val))
                per_run.append(vals)
            positions = np.arange(len(variants))
            bp = ax.boxplot([p if p else [np.nan] for p in per_run],
                            positions=positions, widths=0.55, patch_artist=True,
                            medianprops=dict(color="#c53030", linewidth=1.5))
            for box in bp["boxes"]:
                box.set(facecolor="#bee3f8", edgecolor="#2b6cb0")
            rng = np.random.default_rng(0)
            for pos, vals in zip(positions, per_run):
                jitter = rng.uniform(-0.12, 0.12, size=len(vals))
                ax.scatter(pos + jitter, vals, s=16, color="#2b6cb0",
                           alpha=0.75, zorder=3, edgecolor="none")
            ax.set_xticks(positions)
            ax.set_xticklabels([v.replace("prompts_cvss4_0_", "run ") for v in variants])
            ax.set_ylabel(field)
            ax.set_title(f"{DISPLAY_NAMES.get(model, model)} — {field}")
            ax.grid(axis="y", alpha=0.3)
    fig.suptitle("Score distribution per prompt-preamble run (box = IQR, red = median, dots = skills)")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    path = out_dir / "score_boxplot_per_run.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Skill x run heatmap of cvss_base_score
# ─────────────────────────────────────────────────────────────────────────────

def plot_heatmaps(data, variants, out_dir, field="cvss_base_score"):
    models = list(data)
    fig, axes = plt.subplots(1, len(models), figsize=(5.4 * len(models), 7),
                             squeeze=False)
    for ax, model in zip(axes[0], models):
        skills = sorted(common_skills(data[model], variants))
        mat = np.full((len(skills), len(variants)), np.nan)
        for i, s in enumerate(skills):
            for j, v in enumerate(variants):
                r = get_record(data[model], v, s)
                val = r.get(field) if r else None
                if isinstance(val, (int, float)):
                    mat[i, j] = float(val)
        masked = np.ma.masked_invalid(mat)
        cmap = plt.cm.RdYlGn_r.copy()
        cmap.set_bad(color="#e2e8f0")
        im = ax.imshow(masked, aspect="auto", cmap=cmap, vmin=0, vmax=10)
        for i in range(mat.shape[0]):
            for j in range(mat.shape[1]):
                if not np.isnan(mat[i, j]):
                    ax.text(j, i, f"{mat[i, j]:.1f}", ha="center", va="center",
                            fontsize=6.5)
        ax.set_xticks(range(len(variants)))
        ax.set_xticklabels([v.replace("prompts_cvss4_0_", "run ") for v in variants],
                           fontsize=8)
        ax.set_yticks(range(len(skills)))
        ax.set_yticklabels([s.replace(".md", "") for s in skills], fontsize=6.5)
        ax.set_title(DISPLAY_NAMES.get(model, model), fontsize=10)
        fig.colorbar(im, ax=ax, shrink=0.6, label=field)
    fig.suptitle(f"{field} per skill (row) and prompt-preamble run (column); gray = failed parse")
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    path = out_dir / f"heatmap_{field}.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Friedman test + Kendall's W + Bland-Altman + per-run "
                    "boxplots + skill-by-run heatmap for the 5 prompt-preamble runs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--reports-dir", default="reports", metavar="DIR")
    parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS), metavar="LIST")
    parser.add_argument("--out-dir", default="results/multirun_stability", metavar="DIR")
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    variants = [v.strip() for v in args.variants.split(",") if v.strip()]

    data = load_all(reports_dir, variants)
    if not data:
        print("ERROR: no data loaded.", file=sys.stderr)
        sys.exit(1)

    rows = []
    for model, model_data in data.items():
        skills = sorted(common_skills(model_data, variants))
        for field in SCORE_FIELDS:
            res = friedman_and_w(model_data, skills, variants, field)
            rows.append({"model": model, "score": field, **res})

    summary = pd.DataFrame(rows)
    summary_path = out_dir / "friedman_kendall_summary.csv"
    summary.to_csv(summary_path, index=False)

    print("\n" + "=" * 78)
    print("  Friedman test (H0: prompt preamble has no effect) + Kendall's W")
    print("=" * 78)
    with pd.option_context("display.width", 160):
        print(summary.round(4).to_string(index=False))
    print(f"\nSaved: {summary_path}")

    print("\nDraft reviewer-response sentences:")
    for _, r in summary.iterrows():
        if np.isnan(r["p_value"]):
            print(f"  [{r['model']} / {r['score']}] not computable "
                  f"(only {int(r['n_skills'])} skills with complete 5-run data)")
            continue
        sig = "significant" if r["p_value"] < 0.05 else "not significant"
        print(
            f"  [{r['model']} / {r['score']}] A Friedman test across the five "
            f"prompt preambles found no statistically significant effect of "
            f"preamble wording (chi2({len(variants) - 1}) = {r['chi2']:.2f}, "
            f"p = {r['p_value']:.3f})"
            if sig == "not significant" else
            f"  [{r['model']} / {r['score']}] Friedman chi2({len(variants) - 1}) "
            f"= {r['chi2']:.2f}, p = {r['p_value']:.3f} ({sig})"
        )
        print(
            f"      Kendall's W = {r['kendalls_w']:.3f} "
            f"({w_interpretation(r['kendalls_w'])} concordance, "
            f"n = {int(r['n_skills'])} skills with complete 5-run data)"
        )

    if not args.no_plots:
        plot_bland_altman(data, variants, out_dir)
        plot_run_boxplots(data, variants, out_dir)
        plot_heatmaps(data, variants, out_dir)


if __name__ == "__main__":
    main()
