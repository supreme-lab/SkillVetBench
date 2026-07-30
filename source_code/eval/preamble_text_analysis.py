#!/usr/bin/env python3
"""
preamble_text_analysis.py
=========================
Textual analysis of the five prompt preambles (prompts_cvss4_0_a..e) used in
the multi-run stability study. Reviewers asking for multi-run error bars will
also ask: "how different were the five preambles, really?" — if they were
near-identical paraphrases, run-to-run stability would be trivial. This
script quantifies preamble diversity and, crucially, tests whether textual
differences between preambles predict outcome differences at all:

  1. Design intent     persona/style declaration extracted from each variant
                       module's docstring (qualitative, by design).

  2. Corpus statistics words, sentences, vocabulary, type-token ratio.

  3. Pairwise similarity between all 10 preamble pairs, four complementary
     metrics:
       - word-level TF-IDF cosine        (shared vocabulary / rubric core)
       - char 3-5-gram TF-IDF cosine     (phrasing-level overlap)
       - Jaccard on content words        (set overlap, stopwords removed)
       - sentence-embedding cosine       (semantic similarity;
                                          all-MiniLM-L6-v2, local HF cache
                                          only — skipped with a note if the
                                          model is not cached)
     Rendered as an annotated 4-panel heatmap.

  4. Distinctive terms  top TF-IDF terms per preamble — what makes each
     variant unique relative to the other four.

  5. Mantel test (the key analysis): does textual DISTANCE between preamble
     pairs predict OUTCOME DISTANCE (mean |delta score| across skills) for
     each model? Exact permutation test over all 5! = 120 run-label
     permutations, Spearman correlation. A non-significant result means:
     measured textual differences between preambles do NOT translate into
     systematic score differences — the strongest form of the stability
     claim this study can make.

Usage
-----
    python source_code/eval/preamble_text_analysis.py
    python source_code/eval/preamble_text_analysis.py --no-embeddings

Outputs (in --out-dir, default results/multirun_stability/):
    preamble_corpus_stats.csv
    preamble_pairwise_similarity.csv
    preamble_distinctive_terms.csv
    preamble_mantel_tests.csv
    preamble_similarity_heatmap.png
"""

import argparse
import importlib.util
import re
import sys
from itertools import combinations, permutations
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.feature_extraction.text import TfidfVectorizer

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
from multirun_variance_tests import DISPLAY_NAMES, SCORE_FIELDS  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROMPT_DIR = PROJECT_ROOT / "source_code" / "utils"

STOPWORDS = set("""
a an the and or of to in for on with without by is are was were be been being
you your yours we our ours it its this that these those as at from into about
all any each no not only must should can could will would do does did have has
had when where which who whom what how if then than so such same per via etc
""".split())

TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.'/-][a-z0-9]+)*")


# ─────────────────────────────────────────────────────────────────────────────
# Loading the preambles
# ─────────────────────────────────────────────────────────────────────────────

def load_preambles(variants: list) -> dict:
    """variant -> {'text': system prompt, 'persona': docstring style note}."""
    out = {}
    for v in variants:
        path = PROMPT_DIR / f"{v}.py"
        if not path.is_file():
            print(f"WARNING: prompt module not found: {path}", file=sys.stderr)
            continue
        spec = importlib.util.spec_from_file_location(v, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        doc = mod.__doc__ or ""
        persona = "baseline (original wording)"
        m = re.search(r"STYLE VARIANT\s+([A-Z])\s*\n?\(([^)]+)\)", doc)
        if m:
            persona = re.sub(r"\s+", " ", f"variant {m.group(1)}: {m.group(2)}").strip()
        out[v] = {"text": mod.SKILL_SECURITY_EVAL_SYSTEM_PROMPT, "persona": persona}
    return out


def tokens(text: str):
    return TOKEN_RE.findall(text.lower())


def content_tokens(text: str):
    return [t for t in tokens(text) if t not in STOPWORDS]


# ─────────────────────────────────────────────────────────────────────────────
# 2. Corpus statistics
# ─────────────────────────────────────────────────────────────────────────────

def corpus_stats(preambles: dict) -> pd.DataFrame:
    rows = []
    for v, d in preambles.items():
        toks = tokens(d["text"])
        sents = [s for s in re.split(r"[.!?]+|\n\s*\n", d["text"]) if s.strip()]
        rows.append({
            "variant": v.replace("prompts_cvss4_0_", "run "),
            "persona": d["persona"],
            "words": len(toks),
            "sentences": len(sents),
            "vocab": len(set(toks)),
            "type_token_ratio": len(set(toks)) / len(toks) if toks else np.nan,
        })
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Pairwise similarity (4 metrics)
# ─────────────────────────────────────────────────────────────────────────────

def pairwise_similarities(preambles: dict, use_embeddings: bool):
    variants = list(preambles)
    texts = [preambles[v]["text"] for v in variants]

    def cosine_matrix(matrix):
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        normed = matrix / norms
        return normed @ normed.T

    word_tfidf = TfidfVectorizer(token_pattern=r"(?u)\b\w[\w.'/-]*\b").fit_transform(texts)
    sim_word = cosine_matrix(word_tfidf.toarray())

    char_tfidf = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5)).fit_transform(texts)
    sim_char = cosine_matrix(char_tfidf.toarray())

    content_sets = [set(content_tokens(t)) for t in texts]
    n = len(texts)
    sim_jacc = np.eye(n)
    for i, j in combinations(range(n), 2):
        union = content_sets[i] | content_sets[j]
        sim = len(content_sets[i] & content_sets[j]) / len(union) if union else 1.0
        sim_jacc[i, j] = sim_jacc[j, i] = sim

    sim_emb = None
    if use_embeddings:
        try:
            from sentence_transformers import SentenceTransformer
            model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2",
                                        local_files_only=True)
            emb = model.encode(texts, normalize_embeddings=True)
            sim_emb = emb @ emb.T
        except Exception as e:
            print(f"NOTE: embedding similarity skipped ({e.__class__.__name__}: {e})",
                  file=sys.stderr)

    mats = {"word_tfidf_cosine": sim_word, "char_ngram_cosine": sim_char,
            "jaccard_content_words": sim_jacc}
    if sim_emb is not None:
        mats["embedding_cosine"] = sim_emb

    rows = []
    for i, j in combinations(range(n), 2):
        row = {"pair": f"{variants[i][-1]}-{variants[j][-1]}"}
        for name, m in mats.items():
            row[name] = float(m[i, j])
        rows.append(row)
    return pd.DataFrame(rows), mats, variants


def plot_similarity_heatmaps(mats: dict, variants: list, out_dir: Path):
    labels = [v.replace("prompts_cvss4_0_", "run ") for v in variants]
    titles = {"word_tfidf_cosine": "word TF-IDF cosine",
              "char_ngram_cosine": "char 3–5-gram TF-IDF cosine",
              "jaccard_content_words": "Jaccard (content words)",
              "embedding_cosine": "embedding cosine (MiniLM-L6)"}
    n_panels = len(mats)
    fig, axes = plt.subplots(1, n_panels, figsize=(4.6 * n_panels, 4.2), squeeze=False)
    for ax, (name, mat) in zip(axes[0], mats.items()):
        im = ax.imshow(mat, cmap="viridis", vmin=0, vmax=1)
        for i in range(mat.shape[0]):
            for j in range(mat.shape[1]):
                ax.text(j, i, f"{mat[i, j]:.2f}", ha="center", va="center",
                        fontsize=8, color="white" if mat[i, j] < 0.7 else "black")
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=8)
        ax.set_title(titles.get(name, name), fontsize=9)
        fig.colorbar(im, ax=ax, shrink=0.7)
    fig.suptitle("Pairwise similarity of the five prompt preambles "
                 "(same task contract, different persona/phrasing)")
    fig.tight_layout(rect=[0, 0, 1, 0.94])
    path = out_dir / "preamble_similarity_heatmap.png"
    fig.savefig(path, dpi=180)
    plt.close(fig)
    print(f"  Saved figure: {path}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Distinctive terms per preamble
# ─────────────────────────────────────────────────────────────────────────────

def distinctive_terms(preambles: dict, top_k: int = 10) -> pd.DataFrame:
    variants = list(preambles)
    texts = [preambles[v]["text"] for v in variants]
    # keep only real words (2+ letters): drop single chars (CVSS vector
    # letters) and pure numbers (category indices) that dominate TF-IDF
    vec = TfidfVectorizer(token_pattern=r"(?u)\b[a-z][a-z][\w.'/-]*\b",
                          stop_words=list(STOPWORDS))
    tfidf = vec.fit_transform(texts).toarray()
    vocab = np.array(vec.get_feature_names_out())
    rows = []
    for i, v in enumerate(variants):
        top = vocab[np.argsort(-tfidf[i])[:top_k]]
        rows.append({"variant": v.replace("prompts_cvss4_0_", "run "),
                     "top_tfidf_terms": ", ".join(top)})
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Mantel test: text distance vs. outcome distance (exact permutations)
# ─────────────────────────────────────────────────────────────────────────────

def outcome_distance_matrix(model_data, skills, variants, field):
    """mean |score_i - score_j| over skills valid in BOTH runs of each pair."""
    n = len(variants)
    mat = np.full((n, n), np.nan)
    for i, j in combinations(range(n), 2):
        diffs = []
        for s in skills:
            ri, rj = get_record(model_data, variants[i], s), get_record(model_data, variants[j], s)
            vi = ri.get(field) if ri else None
            vj = rj.get(field) if rj else None
            if isinstance(vi, (int, float)) and isinstance(vj, (int, float)):
                diffs.append(abs(float(vi) - float(vj)))
        if len(diffs) >= 3:
            mat[i, j] = mat[j, i] = float(np.mean(diffs))
    return mat


def mantel_exact(text_dist: np.ndarray, out_dist: np.ndarray):
    """Exact Mantel test over all k! run-label permutations (Spearman)."""
    k = text_dist.shape[0]
    iu = np.triu_indices(k, 1)
    x = text_dist[iu]
    y_obs = out_dist[iu]
    if np.isnan(y_obs).any():
        return float("nan"), float("nan")
    rho_obs = stats.spearmanr(x, y_obs).statistic
    count = 0
    total = 0
    for perm in permutations(range(k)):
        p = np.array(perm)
        y = out_dist[np.ix_(p, p)][iu]
        rho = stats.spearmanr(x, y).statistic
        total += 1
        if abs(rho) >= abs(rho_obs) - 1e-12:
            count += 1
    return float(rho_obs), count / total


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Textual diversity analysis of the 5 prompt preambles + "
                    "Mantel test of text distance vs. outcome distance.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--reports-dir", default="reports", metavar="DIR")
    parser.add_argument("--variants", default=",".join(DEFAULT_VARIANTS), metavar="LIST")
    parser.add_argument("--out-dir", default="results/multirun_stability", metavar="DIR")
    parser.add_argument("--no-embeddings", action="store_true",
                        help="Skip sentence-embedding similarity")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    variants = [v.strip() for v in args.variants.split(",") if v.strip()]

    preambles = load_preambles(variants)
    if len(preambles) < 2:
        print("ERROR: need at least 2 preambles.", file=sys.stderr)
        sys.exit(1)

    print("Preamble personas (by design):")
    for v, d in preambles.items():
        print(f"  {v.replace('prompts_cvss4_0_', 'run ')}: {d['persona']}")

    # 2. corpus stats
    stats_df = corpus_stats(preambles)
    stats_df.to_csv(out_dir / "preamble_corpus_stats.csv", index=False)
    print("\nCorpus statistics:")
    print(stats_df.round(3).to_string(index=False))

    # 3. pairwise similarity
    pw, mats, variant_order = pairwise_similarities(preambles,
                                                    use_embeddings=not args.no_embeddings)
    pw.to_csv(out_dir / "preamble_pairwise_similarity.csv", index=False)
    print("\nPairwise similarity (10 preamble pairs):")
    print(pw.round(3).to_string(index=False))
    for col in pw.columns[1:]:
        print(f"  {col}: mean off-diagonal = {pw[col].mean():.3f} "
              f"(range {pw[col].min():.3f}–{pw[col].max():.3f})")
    plot_similarity_heatmaps(mats, variant_order, out_dir)

    # 4. distinctive terms
    terms = distinctive_terms(preambles)
    terms.to_csv(out_dir / "preamble_distinctive_terms.csv", index=False)
    print("\nDistinctive terms per preamble (top TF-IDF):")
    print(terms.to_string(index=False))

    # 5. Mantel tests
    text_metrics = {name: 1.0 - m for name, m in mats.items()}
    data = load_all(Path(args.reports_dir).expanduser().resolve(), variants)
    rows = []
    for model, model_data in data.items():
        skills = sorted(common_skills(model_data, variants))
        for field in SCORE_FIELDS:
            out_dist = outcome_distance_matrix(model_data, skills, variants, field)
            for metric, tdist in text_metrics.items():
                rho, p = mantel_exact(tdist, out_dist)
                rows.append({"model": model, "score": field,
                             "text_distance": metric.replace("_cosine", ""),
                             "mantel_rho": rho, "p_value_exact": p})
    mantel = pd.DataFrame(rows)
    mantel.to_csv(out_dir / "preamble_mantel_tests.csv", index=False)

    print("\n" + "=" * 78)
    print("  Mantel tests: does preamble text distance predict outcome distance?")
    print("  (exact permutation test over all 5! = 120 label permutations)")
    print("=" * 78)
    show = mantel.copy()
    show["model"] = show["model"].map(lambda m: DISPLAY_NAMES.get(m, m))
    print(show.round(3).to_string(index=False))

    print("\nDraft reviewer-response sentences:")
    for (model, field), grp in mantel.groupby(["model", "score"]):
        label = DISPLAY_NAMES.get(model, model)
        for _, r in grp.iterrows():
            if np.isnan(r["p_value_exact"]):
                print(f"  [{label} / {field} / {r['text_distance']}] not computable")
                continue
            verdict = ("no association" if r["p_value_exact"] >= 0.05
                       else "a SIGNIFICANT association")
            print(
                f"  [{label} / {field} / text distance = {r['text_distance']}] "
                f"Mantel rho = {r['mantel_rho']:.3f}, exact p = {r['p_value_exact']:.3f} "
                f"-> {verdict} between preamble text distance and score distance"
            )

    print(f"\nSaved outputs in: {out_dir}")


if __name__ == "__main__":
    main()
