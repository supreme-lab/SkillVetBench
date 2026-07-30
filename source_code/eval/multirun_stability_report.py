#!/usr/bin/env python3
"""
multirun_stability_report.py
============================
Consolidated 5-run stability "report card" for the prompt-preamble study
(prompts_cvss4_0_a..e), organised the way reviewers expect it:

  Continuous scores (cvss_base_score, sars_score)
    - ICC(2,1)            two-way random effects, absolute agreement, single
                          measure (Shrout & Fleiss 1979). > 0.75 = excellent.
    - CV                  mean within-skill coefficient of variation (sigma/mu).
                          Skills scored constantly 0 count as CV = 0.
                          < 0.10 = highly stable.
    - SEM                 standard error of measurement, SD * sqrt(1 - ICC).
                          SEM < 0.25 -> a single run's 95% CI is about +-0.5.
    - % within tolerance  % of skills whose 5-run sigma < tolerance (0.25).

  Rankings (skills ranked by score within each run)
    - Kendall's W         tie-corrected concordance across the 5 runs.
    - Spearman rho        mean +/- SD over all 10 run pairs.
    - Top-1 consistency   modal top-ranked (highest-risk) skill, x/5 runs.

  Binary verdicts (alarm flag: overall_risk HIGH/CRITICAL)
    - Fleiss' kappa       chance-corrected agreement across the 5 runs.
    - Unanimous rate      % of skills with 5/5 identical verdicts.
    - Mode + confidence   per-skill table, e.g. "Flagged (4/5 runs)".

Friedman p-values from multirun_variance_tests.py are included in the
continuous-scores table for completeness (H0: preamble has no effect).

Only skills with a valid (parseable, non-error) report in ALL 5 runs enter
the continuous/ranking statistics; the binary-verdict section uses every
skill with at least one valid run and marks missing runs explicitly.

Usage
-----
    python source_code/eval/multirun_stability_report.py
    python source_code/eval/multirun_stability_report.py --tolerance 0.25

Outputs (in --out-dir, default results/multirun_stability/):
    stability_report.md          the three tables, per model, as Markdown
    stability_continuous.csv
    stability_rankings.csv
    binary_verdict_modes.csv
"""

import argparse
import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parent))
from multirun_error_bars import (  # noqa: E402
    DEFAULT_VARIANTS,
    agreement_rates,
    common_skills,
    fleiss_kappa_for,
    get_record,
    load_all,
    skillvetbench_flag,
)
from multirun_variance_tests import (  # noqa: E402
    DISPLAY_NAMES,
    SCORE_FIELDS,
    friedman_and_w,
    kendalls_w,
    score_matrix,
)

ICC_THRESH = 0.75
CV_THRESH = 0.10
SEM_THRESH = 0.25


# ─────────────────────────────────────────────────────────────────────────────
# Continuous-score statistics
# ─────────────────────────────────────────────────────────────────────────────

def icc_2_1(mat: np.ndarray) -> float:
    """ICC(2,1): two-way random effects, absolute agreement, single measure.
    mat shape: (n_subjects, k_raters)."""
    n, k = mat.shape
    if n < 2 or k < 2:
        return float("nan")
    grand = mat.mean()
    ss_total = ((mat - grand) ** 2).sum()
    ss_subjects = k * ((mat.mean(axis=1) - grand) ** 2).sum()
    ss_raters = n * ((mat.mean(axis=0) - grand) ** 2).sum()
    ss_error = ss_total - ss_subjects - ss_raters

    ms_subjects = ss_subjects / (n - 1)
    ms_raters = ss_raters / (k - 1)
    ms_error = ss_error / ((n - 1) * (k - 1)) if (n - 1) * (k - 1) > 0 else float("nan")

    denom = ms_subjects + (k - 1) * ms_error + k * (ms_raters - ms_error) / n
    if denom == 0 or np.isnan(denom):
        return float("nan")
    return float((ms_subjects - ms_error) / denom)


def continuous_stats(mat: np.ndarray, tolerance: float) -> dict:
    """All continuous-score stability stats for one complete score matrix."""
    within_sd = mat.std(axis=1, ddof=1)
    within_mean = mat.mean(axis=1)
    # CV per skill; a skill scored constantly 0 is perfectly stable (CV = 0)
    with np.errstate(divide="ignore", invalid="ignore"):
        cv_per_skill = np.where(within_mean > 0, within_sd / within_mean, 0.0)
    icc = icc_2_1(mat)
    sem = float(mat.std(ddof=1) * np.sqrt(max(0.0, 1.0 - icc))) if not np.isnan(icc) else float("nan")
    return {
        "icc_2_1": icc,
        "cv_mean": float(cv_per_skill.mean()),
        "sem": sem,
        "pct_within_tolerance": float((within_sd < tolerance).mean()),
        "mean_within_skill_sd": float(within_sd.mean()),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Ranking statistics
# ─────────────────────────────────────────────────────────────────────────────

def spearman_pairs(mat: np.ndarray) -> dict:
    """Mean/min Spearman rho over all run pairs (columns of mat)."""
    rhos = []
    for i, j in combinations(range(mat.shape[1]), 2):
        rho, _ = stats.spearmanr(mat[:, i], mat[:, j])
        if not np.isnan(rho):
            rhos.append(rho)
    if not rhos:
        return {"spearman_mean": float("nan"), "spearman_sd": float("nan"),
                "spearman_min": float("nan")}
    return {"spearman_mean": float(np.mean(rhos)),
            "spearman_sd": float(np.std(rhos, ddof=1)) if len(rhos) > 1 else 0.0,
            "spearman_min": float(np.min(rhos))}


def top1_consistency(mat: np.ndarray, skill_names: list) -> str:
    """Modal top-ranked (highest-score) skill across runs, e.g. 'gog (4/5)'."""
    winners = []
    for j in range(mat.shape[1]):
        winners.append(skill_names[int(np.argmax(mat[:, j]))])
    mode_skill, mode_count = max(((w, winners.count(w)) for w in set(winners)),
                                 key=lambda t: t[1])
    return f"{mode_skill.replace('.md', '')} ({mode_count}/{mat.shape[1]})"


# ─────────────────────────────────────────────────────────────────────────────
# Binary-verdict statistics
# ─────────────────────────────────────────────────────────────────────────────

def verdict_modes(model_data, skills, variants):
    """Per-skill modal alarm verdict with confidence, e.g. 'Flagged (4/5)'."""
    rows = []
    for s in skills:
        flags = [skillvetbench_flag(get_record(model_data, v, s)) for v in variants]
        valid = [f for f in flags if f is not None]
        if not valid:
            continue
        n_flagged = sum(valid)
        flagged = n_flagged > len(valid) / 2
        confidence = max(n_flagged, len(valid) - n_flagged)
        rows.append({
            "skill": s.replace(".md", ""),
            "verdict": "Flagged" if flagged else "Not flagged",
            "confidence": f"{confidence}/{len(valid)}",
            "n_valid_runs": len(valid),
            "unanimous": confidence == len(valid) == len(variants),
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Markdown report
# ─────────────────────────────────────────────────────────────────────────────

def md_table(headers: list, rows: list) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(" --- " for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def fmt(val, digits=3):
    return "n/a" if val is None or (isinstance(val, float) and np.isnan(val)) \
        else f"{val:.{digits}f}"


def passfail(val, thresh, higher_is_better=True):
    if val is None or (isinstance(val, float) and np.isnan(val)):
        return "—"
    ok = val > thresh if higher_is_better else val < thresh
    return "PASS" if ok else "FAIL"


def build_report(data, variants, tolerance):
    md_parts, cont_rows, rank_rows, mode_rows = [], [], [], []

    for model, model_data in data.items():
        label = DISPLAY_NAMES.get(model, model)
        skills = sorted(common_skills(model_data, variants))
        md_parts.append(f"\n## Model: `{label}` "
                        f"({len(skills)} skills x {len(variants)} runs)\n")

        # ── Continuous scores ────────────────────────────────────────────
        table_rows = []
        for field in SCORE_FIELDS:
            mat, names = score_matrix(model_data, skills, variants, field)
            if mat is None or mat.shape[0] < 2:
                for metric, why, thresh in (
                    ("ICC(2,1)", "test-retest reliability", "> 0.75 = excellent"),
                    ("CV", "relative stability", "< 0.10 = highly stable"),
                    ("SEM", "absolute precision", "< 0.25 -> 95% CI ~ +-0.5"),
                    ("% within tolerance", "practical usability",
                     f"% of skills with sigma < {tolerance}"),
                ):
                    table_rows.append([field, metric, why, thresh, "n/a", "—"])
                    cont_rows.append({"model": model, "score": field, "metric": metric,
                                      "value": float("nan")})
                continue
            cs = continuous_stats(mat, tolerance)
            fw = friedman_and_w(model_data, skills, variants, field)
            entries = [
                ("ICC(2,1)", "test-retest reliability", "> 0.75 = excellent",
                 cs["icc_2_1"], passfail(cs["icc_2_1"], ICC_THRESH, True), 3),
                ("CV (mean within-skill)", "relative stability", "< 0.10 = highly stable",
                 cs["cv_mean"], passfail(cs["cv_mean"], CV_THRESH, False), 3),
                ("SEM", "absolute precision", "< 0.25 -> 95% CI ~ +-0.5",
                 cs["sem"], passfail(cs["sem"], SEM_THRESH, False), 3),
                ("% within tolerance", "practical usability",
                 f"% of skills with sigma < {tolerance}",
                 cs["pct_within_tolerance"], "", 3),
                ("Friedman p", "preamble effect (H0: none)", "p > 0.05 = no effect",
                 fw["p_value"], passfail(fw["p_value"], 0.05, True), 4),
            ]
            for metric, why, thresh, val, verdict, digits in entries:
                table_rows.append([field, metric, why, thresh, fmt(val, digits), verdict])
                cont_rows.append({"model": model, "score": field, "metric": metric,
                                  "value": val})

        md_parts.append("### Continuous scores (SARS, CVSS)\n")
        md_parts.append(md_table(
            ["Score", "Metric", "Why", "Threshold", "Value", "Check"], table_rows))

        # ── Rankings ─────────────────────────────────────────────────────
        table_rows = []
        for field in SCORE_FIELDS:
            mat, names = score_matrix(model_data, skills, variants, field)
            if mat is None or mat.shape[0] < 2:
                table_rows.append([field, "Kendall's W", "n/a"])
                table_rows.append([field, "Spearman rho (mean over run pairs)", "n/a"])
                table_rows.append([field, "Top-1 consistency", "n/a"])
                continue
            w = kendalls_w(mat)
            sp = spearman_pairs(mat)
            t1 = top1_consistency(mat, names)
            table_rows.append([field, "Kendall's W",
                               f"{fmt(w)} ({'very strong' if w > 0.7 else 'strong' if w > 0.5 else 'moderate' if w > 0.3 else 'weak'})"])
            table_rows.append([field, "Spearman rho (mean ± SD over 10 run pairs)",
                               f"{fmt(sp['spearman_mean'])} ± {fmt(sp['spearman_sd'])} "
                               f"(min {fmt(sp['spearman_min'])})"])
            table_rows.append([field, "Top-1 consistency (modal highest-risk skill)", t1])
            rank_rows.append({"model": model, "score": field, "kendalls_w": w,
                              **sp, "top1": t1})

        md_parts.append("\n### Rankings\n")
        md_parts.append(md_table(["Score", "Metric", "Value"], table_rows))

        # ── Binary verdicts ──────────────────────────────────────────────
        kappa, n_kappa = fleiss_kappa_for(model_data, skills, variants, skillvetbench_flag)
        agree = agreement_rates(model_data, skills, variants)
        modes = verdict_modes(model_data, skills, variants)
        mode_rows += [{"model": model, **m} for m in modes]

        md_parts.append("\n### Binary verdicts (alarm = HIGH/CRITICAL)\n")
        md_parts.append(md_table(
            ["Metric", "Why", "Value"],
            [["Fleiss' kappa", "agreement corrected for chance (5 runs)",
              f"{fmt(kappa)} (n={n_kappa} skills with 5/5 valid runs)"],
             ["Unanimous rate", "% of skills with 5/5 identical verdicts",
              fmt(agree["unanimous_rate"])],
             ["Super-majority (>=4/5)", "% of skills with >=4/5 agreement",
              fmt(agree["supermajority_rate"])]]))

        md_parts.append("\nPer-skill mode + confidence:\n")
        md_parts.append(md_table(
            ["Skill", "Verdict", "Confidence"],
            [[m["skill"], m["verdict"], m["confidence"]] for m in modes]))

    report = ("# Multi-run stability report (5 prompt-preamble runs)\n"
              "\nAlarm flag = overall_risk HIGH/CRITICAL. Continuous/ranking "
              "statistics use skills with valid output in all 5 runs.\n"
              + "\n".join(md_parts))
    return report, pd.DataFrame(cont_rows), pd.DataFrame(rank_rows), pd.DataFrame(mode_rows)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Consolidated stability report card for the 5 prompt-preamble "
                    "runs: ICC(2,1)/CV/SEM/%-within-tolerance, Kendall's W/Spearman/"
                    "Top-1, Fleiss' kappa/unanimous/mode+confidence.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--reports-dir", default="reports", metavar="DIR")
    parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS), metavar="LIST")
    parser.add_argument("--out-dir", default="results/multirun_stability", metavar="DIR")
    parser.add_argument("--tolerance", type=float, default=0.25,
                        help="within-skill sigma tolerance for the %% within tolerance metric")
    args = parser.parse_args()

    reports_dir = Path(args.reports_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    variants = [v.strip() for v in args.variants.split(",") if v.strip()]

    data = load_all(reports_dir, variants)
    if not data:
        print("ERROR: no data loaded.", file=sys.stderr)
        sys.exit(1)

    report, cont, rank, modes = build_report(data, variants, args.tolerance)

    report_path = out_dir / "stability_report.md"
    report_path.write_text(report, encoding="utf-8")
    cont.to_csv(out_dir / "stability_continuous.csv", index=False)
    rank.to_csv(out_dir / "stability_rankings.csv", index=False)
    modes.to_csv(out_dir / "binary_verdict_modes.csv", index=False)

    print(report)
    print(f"\nSaved: {report_path}")
    print(f"Saved: {out_dir / 'stability_continuous.csv'}")
    print(f"Saved: {out_dir / 'stability_rankings.csv'}")
    print(f"Saved: {out_dir / 'binary_verdict_modes.csv'}")


if __name__ == "__main__":
    main()
