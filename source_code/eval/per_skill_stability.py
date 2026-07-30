#!/usr/bin/env python3
"""
per_skill_stability.py
======================
Per-skill stability view of the 5 prompt-preamble runs
(prompts_cvss4_0_a..e), for 20 skills x 3 evaluator models. Complements the
aggregate statistics (multirun_error_bars.py / multirun_stability_report.py)
with per-skill detail for every report field a reviewer might ask about:

  Numeric metrics (mean +/- SD error bars across the 5 runs, per model):
      cvss_base_score, sars_score, vulnerability_count

  Categorical metrics (mode + run-agreement heatmap, skills x models):
      overall_risk, cvss_severity, sars_severity

  Binary flag (flag-rate heatmap, skills x models):
      is_vulnerable  (fraction of valid runs flagging the skill)

  Textual stability of skill_purpose_analysis:
      mean pairwise similarity of the (up to 5) run texts per skill and
      model — word TF-IDF cosine and sentence-embedding cosine
      (all-MiniLM-L6-v2 from the local HF cache; skipped with a note if
      unavailable). High similarity = the narrative justification is as
      stable as the scores.

The skill set is the intersection of skills valid across all variants of
all models (the same 20 skills used everywhere else in this study). Failed
runs (error field) are excluded per cell; annotations show n valid runs.

Usage
-----
    python source_code/eval/per_skill_stability.py
    python source_code/eval/per_skill_stability.py --no-embeddings --no-plots

Outputs (in --out-dir, default results/multirun_stability/):
    perskill_summary.csv                    one long table with everything
    perskill_numeric_<metric>.png           mean +/- SD error bars (3)
    perskill_categorical_<metric>.png       mode + agreement heatmaps (3)
    perskill_is_vulnerable.png              flag-rate heatmap
    perskill_text_purpose_analysis.png      text-similarity heatmaps
"""

import argparse
import sys
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent))
from multirun_error_bars import (  # noqa: E402
    DEFAULT_VARIANTS,
    common_skills,
    get_record,
    load_all,
)
from multirun_variance_tests import DISPLAY_NAMES  # noqa: E402

NUMERIC_METRICS = ["cvss_base_score", "sars_score", "vulnerability_count"]
CATEGORICAL_METRICS = ["overall_risk", "cvss_severity", "sars_severity"]

SEVERITY_ORDER = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_LABELS = ["None", "Low", "Medium", "High", "Critical"]


def severity_rank(value):
    if value is None:
        return None
    return SEVERITY_ORDER.get(str(value).strip().upper())


# ─────────────────────────────────────────────────────────────────────────────
# Per-skill extraction
# ─────────────────────────────────────────────────────────────────────────────

def collect(data, skills, variants):
    """numeric[model][skill][metric] = list of values (valid runs only);
    categorical[model][skill][metric] = list of labels;
    flag[model][skill] = list of bools; texts[model][skill] = list of str."""
    numeric, categorical, flag, texts = {}, {}, {}, {}
    for model, model_data in data.items():
        numeric[model], categorical[model], flag[model], texts[model] = {}, {}, {}, {}
        for s in skills:
            numeric[model][s] = {m: [] for m in NUMERIC_METRICS}
            categorical[model][s] = {m: [] for m in CATEGORICAL_METRICS}
            flag[model][s] = []
            texts[model][s] = []
            for v in variants:
                r = get_record(model_data, v, s)
                if r is None:
                    continue
                for m in NUMERIC_METRICS:
                    val = r.get(m)
                    if isinstance(val, (int, float)):
                        numeric[model][s][m].append(float(val))
                for m in CATEGORICAL_METRICS:
                    if severity_rank(r.get(m)) is not None:
                        categorical[model][s][m].append(str(r[m]).strip().upper())
                if isinstance(r.get("is_vulnerable"), bool):
                    flag[model][s].append(r["is_vulnerable"])
                spa = (r.get("skill_purpose_analysis") or "").strip()
                if spa:
                    texts[model][s].append(spa)
    return numeric, categorical, flag, texts


# ─────────────────────────────────────────────────────────────────────────────
# Plots
# ─────────────────────────────────────────────────────────────────────────────

def short(skill, n=18):
    s = skill.replace(".md", "")
    return s if len(s) <= n else s[: n - 1] + "…"


def plot_numeric(numeric, models, skills, metric, out_dir):
    fig, axes = plt.subplots(len(models), 1, figsize=(11, 3.4 * len(models)),
                             sharex=True, squeeze=False)
    for ax, model in zip(axes[:, 0], models):
        means, sds, ns = [], [], []
        for s in skills:
            vals = numeric[model][s][metric]
            means.append(np.mean(vals) if vals else np.nan)
            sds.append(np.std(vals, ddof=1) if len(vals) > 1 else 0.0)
            ns.append(len(vals))
        x = np.arange(len(skills))
        ax.errorbar(x, means, yerr=sds, fmt="o", color="#2b6cb0",
                    ecolor="#a0aec0", elinewidth=1.4, capsize=3, markersize=5)
        for xi, (m, n) in enumerate(zip(means, ns)):
            if n < 5 and not np.isnan(m):
                ax.annotate(f"n={n}", (xi, m), textcoords="offset points",
                            xytext=(0, 8), fontsize=6.5, ha="center", color="#c53030")
            if np.isnan(m):
                ax.annotate("no valid runs", (xi, 0), rotation=90, fontsize=6.5,
                            ha="center", va="bottom", color="#c53030")
        ax.set_ylabel(metric)
        ax.set_title(f"{DISPLAY_NAMES.get(model, model)} — {metric} "
                     f"(mean ± SD across 5 runs)", fontsize=10)
        ax.grid(axis="y", alpha=0.3)
        ax.set_xticks(x)
        ax.set_xticklabels([short(s) for s in skills], rotation=75, ha="right",
                           fontsize=7)
    fig.tight_layout()
    path = out_dir / f"perskill_numeric_{metric}.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


def plot_categorical(categorical, models, skills, metric, out_dir):
    mat = np.full((len(skills), len(models)), np.nan)
    annot = [[""] * len(models) for _ in skills]
    for j, model in enumerate(models):
        for i, s in enumerate(skills):
            labels = categorical[model][s][metric]
            if not labels:
                annot[i][j] = "n/a"
                continue
            # mode; ties broken toward the more severe label (conservative)
            counts = {lab: labels.count(lab) for lab in set(labels)}
            mode = max(counts, key=lambda lab: (counts[lab], SEVERITY_ORDER[lab]))
            mat[i, j] = SEVERITY_ORDER[mode]
            annot[i][j] = f"{mode.title()}\n{counts[mode]}/{len(labels)}"

    fig, ax = plt.subplots(figsize=(2.6 * len(models) + 2.5, 0.38 * len(skills) + 1.6))
    cmap = plt.cm.RdYlGn_r.copy()
    cmap.set_bad(color="#e2e8f0")
    im = ax.imshow(np.ma.masked_invalid(mat), aspect="auto", cmap=cmap,
                   vmin=0, vmax=4)
    for i in range(len(skills)):
        for j in range(len(models)):
            ax.text(j, i, annot[i][j], ha="center", va="center", fontsize=6.5)
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels([DISPLAY_NAMES.get(m, m) for m in models], fontsize=9)
    ax.set_yticks(range(len(skills)))
    ax.set_yticklabels([short(s, 26) for s in skills], fontsize=7)
    cb = fig.colorbar(im, ax=ax, shrink=0.6, ticks=range(5))
    cb.ax.set_yticklabels(SEVERITY_LABELS, fontsize=8)
    ax.set_title(f"{metric}: modal category across 5 runs (annotation = mode, runs agreeing)",
                 fontsize=10)
    fig.tight_layout()
    path = out_dir / f"perskill_categorical_{metric}.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


def plot_flag_rates(flag, models, skills, out_dir):
    mat = np.full((len(skills), len(models)), np.nan)
    annot = [[""] * len(models) for _ in skills]
    for j, model in enumerate(models):
        for i, s in enumerate(skills):
            vals = flag[model][s]
            if not vals:
                annot[i][j] = "n/a"
                continue
            mat[i, j] = sum(vals) / len(vals)
            annot[i][j] = f"{sum(vals)}/{len(vals)}"

    fig, ax = plt.subplots(figsize=(2.6 * len(models) + 2.5, 0.38 * len(skills) + 1.6))
    cmap = plt.cm.Reds.copy()
    cmap.set_bad(color="#e2e8f0")
    im = ax.imshow(np.ma.masked_invalid(mat), aspect="auto", cmap=cmap,
                   vmin=0, vmax=1)
    for i in range(len(skills)):
        for j in range(len(models)):
            color = "white" if not np.isnan(mat[i, j]) and mat[i, j] > 0.6 else "black"
            ax.text(j, i, annot[i][j], ha="center", va="center", fontsize=7,
                    color=color)
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels([DISPLAY_NAMES.get(m, m) for m in models], fontsize=9)
    ax.set_yticks(range(len(skills)))
    ax.set_yticklabels([short(s, 26) for s in skills], fontsize=7)
    fig.colorbar(im, ax=ax, shrink=0.6, label="flag rate")
    ax.set_title("is_vulnerable: fraction of valid runs flagging the skill", fontsize=10)
    fig.tight_layout()
    path = out_dir / "perskill_is_vulnerable.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


def text_similarity(texts, models, skills, use_embeddings):
    """Mean pairwise word-TFIDF and embedding cosine per (model, skill)."""
    from sklearn.feature_extraction.text import TfidfVectorizer

    def mean_pairwise(vecs):
        n = len(vecs)
        if n < 2:
            return np.nan
        sims = []
        for i, j in combinations(range(n), 2):
            a, b = vecs[i], vecs[j]
            na, nb = np.linalg.norm(a), np.linalg.norm(b)
            if na and nb:
                sims.append(float(a @ b / (na * nb)))
        return float(np.mean(sims)) if sims else np.nan

    tfidf_mat = np.full((len(skills), len(models)), np.nan)
    emb_mat = np.full((len(skills), len(models)), np.nan)

    for j, model in enumerate(models):
        for i, s in enumerate(skills):
            docs = texts[model][s]
            if len(docs) >= 2:
                try:
                    vec = TfidfVectorizer(stop_words="english").fit(docs)
                    tfidf_mat[i, j] = mean_pairwise(vec.transform(docs).toarray())
                except ValueError:
                    pass

    if use_embeddings:
        try:
            from sentence_transformers import SentenceTransformer
            st = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2",
                                     local_files_only=True)
            for j, model in enumerate(models):
                for i, s in enumerate(skills):
                    docs = texts[model][s]
                    if len(docs) >= 2:
                        emb = st.encode(docs, normalize_embeddings=True)
                        emb_mat[i, j] = mean_pairwise(emb)
        except Exception as e:
            print(f"NOTE: embedding similarity skipped ({e.__class__.__name__}: {e})",
                  file=sys.stderr)

    return tfidf_mat, emb_mat


def plot_text_similarity(tfidf_mat, emb_mat, models, skills, out_dir):
    panels = [("word TF-IDF cosine", tfidf_mat)]
    if not np.isnan(emb_mat).all():
        panels.append(("embedding cosine (MiniLM-L6)", emb_mat))
    fig, axes = plt.subplots(1, len(panels),
                             figsize=(3.4 * len(models) * len(panels) / 1.6 + 3,
                                      0.38 * len(skills) + 1.6),
                             squeeze=False)
    cmap = plt.cm.viridis.copy()
    cmap.set_bad(color="#e2e8f0")
    for ax, (title, mat) in zip(axes[0], panels):
        im = ax.imshow(np.ma.masked_invalid(mat), aspect="auto", cmap=cmap,
                       vmin=0, vmax=1)
        for i in range(len(skills)):
            for j in range(len(models)):
                if not np.isnan(mat[i, j]):
                    ax.text(j, i, f"{mat[i, j]:.2f}", ha="center", va="center",
                            fontsize=7,
                            color="white" if mat[i, j] < 0.65 else "black")
                else:
                    ax.text(j, i, "n/a", ha="center", va="center", fontsize=7)
        ax.set_xticks(range(len(models)))
        ax.set_xticklabels([DISPLAY_NAMES.get(m, m) for m in models], fontsize=8)
        ax.set_yticks(range(len(skills)))
        ax.set_yticklabels([short(s, 26) for s in skills], fontsize=7)
        ax.set_title(title, fontsize=10)
        fig.colorbar(im, ax=ax, shrink=0.6)
    fig.suptitle("skill_purpose_analysis: mean pairwise similarity of the 5 run texts "
                 "(higher = more stable narrative)", fontsize=11)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    path = out_dir / "perskill_text_purpose_analysis.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Summary table
# ─────────────────────────────────────────────────────────────────────────────

def build_summary(numeric, categorical, flag, texts, tfidf_mat, emb_mat,
                  models, skills, variants):
    rows = []
    for j, model in enumerate(models):
        for i, s in enumerate(skills):
            row = {"model": model, "skill": s.replace(".md", "")}
            for m in NUMERIC_METRICS:
                vals = numeric[model][s][m]
                row[f"{m}_mean"] = float(np.mean(vals)) if vals else np.nan
                row[f"{m}_sd"] = float(np.std(vals, ddof=1)) if len(vals) > 1 else 0.0
                row[f"{m}_n"] = len(vals)
            for m in CATEGORICAL_METRICS:
                labels = categorical[model][s][m]
                if labels:
                    counts = {lab: labels.count(lab) for lab in set(labels)}
                    mode = max(counts, key=lambda lab: (counts[lab], SEVERITY_ORDER[lab]))
                    row[f"{m}_mode"] = mode.title()
                    row[f"{m}_agreement"] = counts[mode] / len(labels)
                    row[f"{m}_n"] = len(labels)
                else:
                    row[f"{m}_mode"] = None
                    row[f"{m}_agreement"] = np.nan
                    row[f"{m}_n"] = 0
            vals = flag[model][s]
            row["is_vulnerable_flag_rate"] = float(np.mean(vals)) if vals else np.nan
            row["is_vulnerable_n"] = len(vals)
            row["purpose_text_n"] = len(texts[model][s])
            row["purpose_text_tfidf_cosine"] = tfidf_mat[i, j]
            row["purpose_text_embedding_cosine"] = emb_mat[i, j]
            rows.append(row)
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Per-skill stability across the 5 prompt-preamble runs for "
                    "20 skills x 3 models: numeric error bars, categorical mode + "
                    "agreement, is_vulnerable flag rate, skill_purpose_analysis "
                    "text similarity.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--reports-dir", default="reports", metavar="DIR")
    parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS), metavar="LIST")
    parser.add_argument("--out-dir", default="results/multirun_stability", metavar="DIR")
    parser.add_argument("--no-embeddings", action="store_true")
    parser.add_argument("--no-plots", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    variants = [v.strip() for v in args.variants.split(",") if v.strip()]

    data = load_all(Path(args.reports_dir).expanduser().resolve(), variants)
    if not data:
        print("ERROR: no data loaded.", file=sys.stderr)
        sys.exit(1)

    models = list(data)
    # skills common to every variant of every model -> aligned 20-skill panels
    skills = None
    for model_data in data.values():
        cs = common_skills(model_data, variants)
        skills = set(cs) if skills is None else skills & set(cs)
    skills = sorted(skills or [])
    print(f"\n{len(skills)} skills common to all {len(variants)} runs of all "
          f"{len(models)} models")

    numeric, categorical, flag, texts = collect(data, skills, variants)
    tfidf_mat, emb_mat = text_similarity(texts, models, skills,
                                         use_embeddings=not args.no_embeddings)

    summary = build_summary(numeric, categorical, flag, texts, tfidf_mat, emb_mat,
                            models, skills, variants)
    summary_path = out_dir / "perskill_summary.csv"
    summary.to_csv(summary_path, index=False, float_format="%.4f")
    print(f"Saved: {summary_path}")

    # compact console digest
    print("\nPer-model digest (means over the 20 skills):")
    digest = summary.groupby("model").agg(
        cvss_mean=("cvss_base_score_mean", "mean"),
        cvss_sd=("cvss_base_score_sd", "mean"),
        sars_mean=("sars_score_mean", "mean"),
        sars_sd=("sars_score_sd", "mean"),
        vuln_count_mean=("vulnerability_count_mean", "mean"),
        flag_rate=("is_vulnerable_flag_rate", "mean"),
        risk_agreement=("overall_risk_agreement", "mean"),
        text_tfidf=("purpose_text_tfidf_cosine", "mean"),
        text_emb=("purpose_text_embedding_cosine", "mean"),
    ).round(3)
    digest.index = [DISPLAY_NAMES.get(m, m) for m in digest.index]
    print(digest.to_string())

    if not args.no_plots:
        for m in NUMERIC_METRICS:
            plot_numeric(numeric, models, skills, m, out_dir)
        for m in CATEGORICAL_METRICS:
            plot_categorical(categorical, models, skills, m, out_dir)
        plot_flag_rates(flag, models, skills, out_dir)
        plot_text_similarity(tfidf_mat, emb_mat, models, skills, out_dir)


if __name__ == "__main__":
    main()
