"""
evaluation_analysis.py
======================
Baseline comparison analysis across four evaluation frameworks:
  1. CVSS v4.0    — industry-standard vulnerability score (from leaderboard CSV)
  2. SARS         — Skill Agentic Risk Score (from leaderboard CSV)
  3. OpenClaw     — ClawHub's official LLM safety evaluation (from clawhub_enriched.json)
  4. VirusTotal   — static file hash analysis (from clawhub_enriched.json)

Produces:
  Figure 1  — Risk / Verdict Distribution across all four methods
  Figure 2  — CVSS vs SARS Score Scatter (coloured by OpenClaw verdict)
  Figure 3  — SARS Dimension Heatmap (mean score per dimension)
  Figure 4  — OpenClaw 5-Category Pass/Warn/Fail Distribution
  Figure 5  — Method Agreement Matrix (how often each pair agrees)
  Figure 6  — CVSS vs SARS Severity Confusion Matrix
  Figure 7  — VirusTotal vs SARS Risk Level Comparison
  Figure 8  — Top-20 Skills Comparison Table (all four methods)

Usage:
  python evaluation_analysis.py
  python evaluation_analysis.py --csv path/to/leaderboard.csv
  python evaluation_analysis.py --enriched path/to/clawhub_enriched.json
  python evaluation_analysis.py --out results/
  python evaluation_analysis.py --no-show      # save only, do not display
"""

import argparse
import json
import os
import sys
import warnings
from pathlib import Path

import matplotlib
matplotlib.use("Agg")   # non-interactive backend — works without a display
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.colors import LinearSegmentedColormap
import numpy as np

warnings.filterwarnings("ignore")

# ── Try pandas — needed for CSV loading only ──────────────────────────────
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("Note: pandas not installed — CSV loading will use csv module")
    import csv

# ─────────────────────────────────────────────────────────────────────────────
# Style
# ─────────────────────────────────────────────────────────────────────────────

plt.rcParams.update({
    "font.family":       "DejaVu Sans",
    "font.size":         10,
    "axes.titlesize":    12,
    "axes.titleweight":  "bold",
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "figure.dpi":        150,
    "savefig.dpi":       200,
    "savefig.bbox":      "tight",
})

# Severity / verdict colours (consistent across all figures)
RISK_COLORS = {
    "CRITICAL":   "#DC2626",
    "HIGH":       "#EA580C",
    "MEDIUM":     "#D97706",
    "LOW":        "#16A34A",
    "NONE":       "#0D9488",
    "UNKNOWN":    "#94A3B8",
    "Malicious":  "#DC2626",
    "Suspicious": "#D97706",
    "Benign":     "#16A34A",
    "clean":      "#16A34A",
    "suspicious": "#D97706",
    "malicious":  "#DC2626",
}

STATUS_COLORS = {
    "pass": "#16A34A",
    "warn": "#D97706",
    "fail": "#DC2626",
    "":     "#94A3B8",
}

SARS_DIM_LABELS = {
    "sars_ifr": "IFR\n(Instruction\nFidelity)",
    "sars_dg":  "DG\n(Data\nGravity)",
    "sars_ai":  "AI\n(Action\nIrreversibility)",
    "sars_br":  "BR\n(Blast\nRadius)",
    "sars_ca":  "CA\n(Chain\nAmplification)",
}

OC_DIMS = [
    ("purpose_capability",    "Purpose &\nCapability"),
    ("instruction_scope",     "Instruction\nScope"),
    ("install_mechanism",     "Install\nMechanism"),
    ("credentials",           "Credentials"),
    ("persistence_privilege", "Persistence &\nPrivilege"),
]

SEVERITY_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
VERDICT_ORDER  = ["Benign", "Suspicious", "Malicious"]


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_csv(path: str) -> list:
    """
    Load the leaderboard CSV. Returns list of dicts with correct types.

    Type conversions applied:
      float : cvss_base_score, sars_score, sars_ifr/dg/ai/br/ca, vulnerability_count
      int   : rank
      bool  : is_vulnerable
      UPPER : cvss_severity, sars_severity, overall_risk  (normalised to uppercase)
      strip : all other string columns
    """
    if not os.path.exists(path):
        print(f"[WARN] CSV not found: {path}")
        return []

    FLOAT_COLS = (
        "cvss_base_score", "sars_score",
        "sars_ifr", "sars_dg", "sars_ai", "sars_br", "sars_ca",
        "vulnerability_count",
    )
    INT_COLS   = ("rank",)
    BOOL_COLS  = ("is_vulnerable",)
    UPPER_COLS = ("cvss_severity", "sars_severity", "overall_risk")

    VALID_SEVERITY = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _upper_sev(val: str) -> str:
        """Normalise severity to uppercase; return UNKNOWN if unrecognised."""
        s = str(val or "").strip().upper()
        return s if s in VALID_SEVERITY else "UNKNOWN"

    if HAS_PANDAS:
        df = pd.read_csv(path, dtype=str)

        for col in FLOAT_COLS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
            else:
                df[col] = 0.0

        for col in INT_COLS:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
            else:
                df[col] = 0

        for col in BOOL_COLS:
            if col in df.columns:
                df[col] = df[col].str.strip().str.lower().map(
                    {"true": True, "1": True, "false": False, "0": False}
                ).fillna(False)
            else:
                df[col] = False

        for col in UPPER_COLS:
            if col in df.columns:
                df[col] = df[col].fillna("").apply(_upper_sev)
            else:
                df[col] = "UNKNOWN"

        return df.to_dict("records")

    else:
        rows = []
        with open(path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                for col in FLOAT_COLS:
                    try:
                        row[col] = float(row.get(col) or 0)
                    except (ValueError, TypeError):
                        row[col] = 0.0

                for col in INT_COLS:
                    try:
                        row[col] = int(row.get(col) or 0)
                    except (ValueError, TypeError):
                        row[col] = 0

                for col in BOOL_COLS:
                    row[col] = str(row.get(col, "")).strip().lower() in ("true", "1")

                for col in UPPER_COLS:
                    row[col] = _upper_sev(row.get(col, ""))

                rows.append(row)
        return rows


def load_enriched(path: str) -> dict:
    """Load clawhub_enriched.json. Returns slug-keyed dict."""
    if not os.path.exists(path):
        print(f"[WARN] Enriched JSON not found: {path}")
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def merge(rows: list, enriched: dict) -> list:
    """
    Join CSV rows with enriched JSON on skill_slug.

    VT data comes from two separate blocks in clawhub_enriched.json:

      virustotal_clawhub   -- the VT analysis embedded in the ClawHub page
        .verdict           -> vt_verdict   (PRIMARY -- always present)
        .status            -> vt_status
        .analysis          -> vt_analysis  (raw text: Type/Name/Version/description)
        .source            -> vt_source    (e.g. "palm")

      virustotal_report    -- fetched from VT API or parsed from embed
        .detection
          .flagged         -> vt_flagged   (count of flagged engines)
          .total           -> vt_total     (total engines or "~64")
          .ratio_str       -> vt_ratio_str (e.g. "0/64" or "0/~64")
        .community_score   -> vt_community
        .code_insight
          .type            -> vt_ci_type
          .name            -> vt_ci_name
          .version         -> vt_ci_version
          .description     -> vt_ci_description
          .tags            -> vt_tags
          .size_kb         -> vt_size_kb
          .last_analysis   -> vt_last_analysis
    """
    merged = []
    for row in rows:
        slug = row.get("skill_slug", "")
        info = enriched.get(slug, {})

        # ── OpenClaw ──────────────────────────────────────────────────────
        oc   = info.get("openclaw", {})
        dims = oc.get("dimensions", {})

        raw_oc_verdict = oc.get("verdict", "")
        row["openclaw_verdict"] = raw_oc_verdict
        if not raw_oc_verdict or normalise_verdict(raw_oc_verdict) == "Unknown":
            print(f"  [WARN] Unknown OpenClaw verdict for slug='{slug}' "
                  f"raw='{raw_oc_verdict}'")
        row["openclaw_confidence"] = oc.get("confidence", "")
        row["openclaw_model"]      = oc.get("model", "")
        row["openclaw_summary"]    = oc.get("summary", "")

        for dim_key, _ in OC_DIMS:
            row[f"oc_{dim_key}"] = dims.get(dim_key, {}).get("status", "")

        # ── VT verdict -- PRIMARY source: virustotal_clawhub ─────────────
        # virustotal_clawhub is always present (scraped from ClawHub page).
        # virustotal_report may have partial data if no VT_API_KEY was set.
        vt_clawhub = info.get("virustotal_clawhub", {})
        raw_vt_verdict = vt_clawhub.get("verdict", "")
        row["vt_verdict"] = normalise_verdict(raw_vt_verdict)
        if row["vt_verdict"] == "Unknown":
            print(f"  [WARN] Unknown VT verdict for slug='{slug}' "
                  f"raw='{raw_vt_verdict}' "
                  f"source='{vt_clawhub.get('source', '')}'")
        row["vt_status"]     = vt_clawhub.get("status", "")
        row["vt_analysis"]   = vt_clawhub.get("analysis", "")
        row["vt_source"]     = vt_clawhub.get("source", "")

        # Parse Type / Name / Version / description from the embedded
        # analysis text field.
        # Format:
        #   "Type: OpenClaw Skill\nName: xsearch\nVersion: 1.0.0\n\n<desc>"
        meta = {}
        desc_lines = []
        in_desc = False
        for line in vt_clawhub.get("analysis", "").splitlines():
            line = line.strip()
            if not line:
                if meta:
                    in_desc = True
                continue
            if in_desc:
                desc_lines.append(line)
            else:
                for key in ("Type", "Name", "Version"):
                    if line.startswith(key + ":"):
                        meta[key.lower()] = line[len(key)+1:].strip()
                        break

        row["vt_type"]        = meta.get("type", "")
        row["vt_name"]        = meta.get("name", "")
        row["vt_version"]     = meta.get("version", "")
        row["vt_description"] = " ".join(desc_lines)

        # ── Detection stats -- from virustotal_report ─────────────────────
        vt_report = info.get("virustotal_report", {})
        vt_det    = vt_report.get("detection", {})

        flagged = vt_det.get("flagged", None)
        if flagged is None and vt_clawhub.get("status", "") == "clean":
            flagged = 0                     # clean embed -> 0 flagged
        row["vt_flagged"]   = flagged
        row["vt_total"]     = vt_det.get("total", "")
        row["vt_ratio_str"] = vt_det.get("ratio_str", "")

        # community_score is a string "unavailable ..." when no API key used
        community = vt_report.get("community_score", None)
        if isinstance(community, str):
            community = None
        row["vt_community"] = community

        # ── Code insight -- virustotal_report.code_insight (API path) ─────
        # Falls back to the fields parsed from the embedded analysis text.
        ci = vt_report.get("code_insight", {})
        row["vt_ci_type"]        = ci.get("type",        row["vt_type"])
        row["vt_ci_name"]        = ci.get("name",        row["vt_name"])
        row["vt_ci_version"]     = ci.get("version",     row["vt_version"])
        row["vt_ci_description"] = ci.get("description", row["vt_description"])
        row["vt_tags"]           = ci.get("tags",        [])
        row["vt_size_kb"]        = ci.get("size_kb",     0)
        row["vt_last_analysis"]  = ci.get("last_analysis", "")

        # ── Skill stats ───────────────────────────────────────────────────
        stats = info.get("stats", {})
        row["stars"]     = stats.get("stars",     0)
        row["downloads"] = stats.get("downloads", 0)

        merged.append(row)
    return merged



def sev_to_int(s: str) -> int:
    return {"NONE":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get(str(s).upper(), -1)

def verdict_to_int(v: str) -> int:
    return {"Benign":0,"benign":0,"clean":0,
            "Suspicious":1,"suspicious":1,"warn":1,
            "Malicious":2,"malicious":2}.get(str(v), -1)

def normalise_verdict(v: str) -> str:
    v = str(v).strip().lower()
    if v in ("benign","clean","safe"): return "Benign"
    if v in ("suspicious","warn"):     return "Suspicious"
    if v in ("malicious","unsafe"):    return "Malicious"
    return "Unknown"

def normalise_sars_sev(s: str) -> str:
    s = str(s).strip().upper()
    return s if s in SEVERITY_ORDER else "UNKNOWN"

def count(rows, key, val):
    return sum(1 for r in rows if str(r.get(key,"")).strip() == str(val))


def save_fig(fig, out_dir: Path, name: str, show: bool):
    path = out_dir / name
    fig.savefig(path, dpi=200, bbox_inches="tight")
    print(f"  Saved: {path}")
    if show:
        plt.show()
    plt.close(fig)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 1 — Risk / Verdict Distribution
# ─────────────────────────────────────────────────────────────────────────────

def fig_risk_distribution(rows: list, out_dir: Path, show: bool):
    """Grouped bar chart: how each method distributes skills across risk bands."""

    # CVSS severity distribution
    cvss_counts = {s: count(rows, "cvss_severity", s) for s in SEVERITY_ORDER}

    # SARS severity distribution
    sars_counts = {s: count(rows, "sars_severity", s) for s in SEVERITY_ORDER}

    # OpenClaw verdict
    oc_counts = {}
    for v in VERDICT_ORDER:
        oc_counts[v] = sum(1 for r in rows
                           if normalise_verdict(r.get("openclaw_verdict","")) == v)
    oc_unknown = len(rows) - sum(oc_counts.values())
    if oc_unknown: oc_counts["Unknown"] = oc_unknown

    # VT verdict
    vt_counts = {}
    for v in VERDICT_ORDER:
        vt_counts[v] = sum(1 for r in rows
                           if normalise_verdict(r.get("vt_verdict","")) == v)
    vt_unknown = len(rows) - sum(vt_counts.values())
    if vt_unknown: vt_counts["Unknown"] = vt_unknown

    fig, axes = plt.subplots(1, 4, figsize=(15, 5))
    fig.suptitle("Figure 1 — Risk / Verdict Distribution Across All Four Methods",
                 fontsize=13, fontweight="bold", y=1.02)

    def _bar(ax, counts, title, order=None):
        order  = order or list(counts.keys())
        labels = [k for k in order if k in counts]
        vals   = [counts[k] for k in labels]
        colors = [RISK_COLORS.get(k, "#94A3B8") for k in labels]
        bars   = ax.bar(range(len(labels)), vals, color=colors,
                        edgecolor="white", linewidth=0.8, zorder=3)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=30, ha="right", fontsize=8)
        ax.set_title(title, fontsize=10, fontweight="bold")
        ax.set_ylabel("Number of Skills")
        ax.yaxis.grid(True, linestyle="--", alpha=0.5)
        ax.set_axisbelow(True)
        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                        str(val), ha="center", va="bottom", fontsize=8)

    _bar(axes[0], cvss_counts,  "CVSS v4.0 Severity",  SEVERITY_ORDER)
    _bar(axes[1], sars_counts,  "SARS Severity",         SEVERITY_ORDER)
    _bar(axes[2], oc_counts,    "OpenClaw Verdict",       VERDICT_ORDER + ["Unknown"])
    _bar(axes[3], vt_counts,    "VirusTotal Verdict",     VERDICT_ORDER + ["Unknown"])

    plt.tight_layout()
    save_fig(fig, out_dir, "fig1_risk_distribution.png", show)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 2 — CVSS vs SARS Scatter (coloured by OpenClaw verdict)
# ─────────────────────────────────────────────────────────────────────────────

def fig_scatter(rows: list, out_dir: Path, show: bool):
    """Scatter plot: CVSS score (x) vs SARS score (y), colour by OpenClaw verdict."""

    groups = {"Benign": [], "Suspicious": [], "Malicious": [], "Unknown": []}
    for r in rows:
        v = normalise_verdict(r.get("openclaw_verdict", ""))
        if v not in groups:
            v = "Unknown"
        groups[v].append((float(r.get("cvss_base_score", 0)),
                           float(r.get("sars_score", 0))))

    fig, ax = plt.subplots(figsize=(8, 7))

    markers = {"Benign":"o", "Suspicious":"s", "Malicious":"^", "Unknown":"D"}
    for verdict, pts in groups.items():
        if not pts:
            continue
        xs, ys = zip(*pts)
        ax.scatter(xs, ys,
                   c=RISK_COLORS.get(verdict, "#94A3B8"),
                   marker=markers[verdict],
                   alpha=0.7, s=55, edgecolors="white", linewidths=0.4,
                   label=f"OpenClaw: {verdict} (n={len(pts)})", zorder=3)

    # Diagonal: SARS == CVSS
    ax.plot([0, 10], [0, 10], "--", color="#94A3B8", linewidth=1.2,
            label="SARS = CVSS (diagonal)", zorder=2)

    # Quadrant annotations
    ax.text(1.5, 8.5, "SARS\n>> CVSS", fontsize=8, color="#1E3A5F",
            ha="center", va="center",
            bbox=dict(boxstyle="round,pad=0.3", fc="#EFF6FF", ec="#2563EB", alpha=0.8))
    ax.text(8.5, 1.5, "CVSS\n>> SARS", fontsize=8, color="#94A3B8",
            ha="center", va="center",
            bbox=dict(boxstyle="round,pad=0.3", fc="#F8FAFF", ec="#CBD5E1", alpha=0.8))

    # Compute mean delta
    valid = [(float(r.get("cvss_base_score",0)), float(r.get("sars_score",0)))
             for r in rows if r.get("cvss_base_score") and r.get("sars_score")]
    if valid:
        mean_delta = np.mean([y - x for x, y in valid])
        ax.text(0.03, 0.97,
                f"Mean Δ (SARS−CVSS) = {mean_delta:+.2f}",
                transform=ax.transAxes, fontsize=9,
                va="top", ha="left",
                bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#CBD5E1"))

    ax.set_xlim(-0.3, 10.5)
    ax.set_ylim(-0.3, 10.5)
    ax.set_xlabel("CVSS v4.0 Score", fontsize=11)
    ax.set_ylabel("SARS Score",       fontsize=11)
    ax.set_title("Figure 2 — CVSS v4.0 vs SARS Score\n(coloured by OpenClaw verdict)",
                 fontsize=12, fontweight="bold")
    ax.legend(fontsize=8, framealpha=0.9)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)
    ax.xaxis.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)

    plt.tight_layout()
    save_fig(fig, out_dir, "fig2_cvss_vs_sars_scatter.png", show)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 3 — SARS Dimension Heatmap
# ─────────────────────────────────────────────────────────────────────────────

def fig_sars_heatmap(rows: list, out_dir: Path, show: bool):
    """Heatmap: mean SARS dimension score per overall_risk band."""

    dims    = ["sars_ifr", "sars_dg", "sars_ai", "sars_br", "sars_ca"]
    risk_bands = [b for b in SEVERITY_ORDER if any(
        str(r.get("overall_risk","")).upper() == b for r in rows
    )]

    if not risk_bands:
        print("  [SKIP] Figure 3 — no risk band data")
        return

    matrix = []
    for band in risk_bands:
        band_rows = [r for r in rows if str(r.get("overall_risk","")).upper() == band]
        if not band_rows:
            matrix.append([0]*len(dims))
            continue
        matrix.append([
            float(np.mean([float(r.get(d, 0)) for r in band_rows]))
            for d in dims
        ])

    mat = np.array(matrix)   # shape: (n_bands, 5)

    fig, ax = plt.subplots(figsize=(9, 4))
    cmap = LinearSegmentedColormap.from_list(
        "risk", ["#F0FDF4","#FEFCE8","#FFF7ED","#FEF2F2","#7F1D1D"]
    )
    im = ax.imshow(mat, cmap=cmap, aspect="auto", vmin=0, vmax=3)

    ax.set_xticks(range(len(dims)))
    ax.set_xticklabels([SARS_DIM_LABELS[d] for d in dims], fontsize=8)
    ax.set_yticks(range(len(risk_bands)))
    ax.set_yticklabels(risk_bands, fontsize=9, fontweight="bold")

    for i in range(len(risk_bands)):
        for j in range(len(dims)):
            val = mat[i, j]
            ax.text(j, i, f"{val:.2f}", ha="center", va="center",
                    fontsize=9, fontweight="bold",
                    color="white" if val > 1.8 else "#1E293B")

    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("Mean Dimension Score (0–3)", fontsize=9)
    cbar.set_ticks([0, 1, 2, 3])

    ax.set_title("Figure 3 — SARS Dimension Profile by Overall Risk Band\n"
                 "(mean score per dimension, 0 = safest, 3 = most dangerous)",
                 fontsize=11, fontweight="bold")
    ax.set_xlabel("SARS Dimension", fontsize=10)
    ax.set_ylabel("Overall Risk Band", fontsize=10)

    # Add count annotation
    for i, band in enumerate(risk_bands):
        n = sum(1 for r in rows if str(r.get("overall_risk","")).upper() == band)
        ax.text(len(dims)-0.3, i, f"  n={n}", va="center", fontsize=7, color="#64748B")

    plt.tight_layout()
    save_fig(fig, out_dir, "fig3_sars_dimension_heatmap.png", show)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 4 — OpenClaw 5-Category Distribution
# ─────────────────────────────────────────────────────────────────────────────

def fig_openclaw_dimensions(rows: list, out_dir: Path, show: bool):
    """Horizontal stacked bar: pass/warn/fail counts for each of the 5 OC categories."""

    has_oc = any(r.get("openclaw_verdict") for r in rows)
    if not has_oc:
        print("  [SKIP] Figure 4 — no OpenClaw data in merged dataset")
        return

    fig, ax = plt.subplots(figsize=(10, 4.5))

    dim_keys   = [k for k, _ in OC_DIMS]
    dim_labels = [l for _, l in OC_DIMS]
    statuses   = ["pass", "warn", "fail", ""]

    bottoms = np.zeros(len(dim_keys))
    bar_colors = {"pass": "#16A34A", "warn": "#D97706", "fail": "#DC2626", "": "#CBD5E1"}
    bar_labels = {"pass": "Pass ✓", "warn": "Warn ⚠", "fail": "Fail ✗", "": "No data"}

    for status in statuses:
        vals = [
            sum(1 for r in rows if r.get(f"oc_{dk}", "") == status)
            for dk in dim_keys
        ]
        bars = ax.barh(range(len(dim_keys)), vals, left=bottoms,
                       color=bar_colors[status], label=bar_labels[status],
                       edgecolor="white", linewidth=0.6, height=0.55)
        # Label inside bar if wide enough
        for i, (val, bot) in enumerate(zip(vals, bottoms)):
            if val > 1:
                ax.text(bot + val/2, i, str(val), ha="center", va="center",
                        fontsize=8, fontweight="bold", color="white")
        bottoms = bottoms + np.array(vals)

    ax.set_yticks(range(len(dim_keys)))
    ax.set_yticklabels(dim_labels, fontsize=9)
    ax.set_xlabel("Number of Skills", fontsize=10)
    ax.set_title("Figure 4 — OpenClaw 5-Category Safety Evaluation\n"
                 "(Pass / Warn / Fail distribution per category)",
                 fontsize=11, fontweight="bold")
    ax.legend(loc="lower right", fontsize=8)
    ax.xaxis.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)

    plt.tight_layout()
    save_fig(fig, out_dir, "fig4_openclaw_dimensions.png", show)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 5 — Method Agreement Matrix
# ─────────────────────────────────────────────────────────────────────────────

def fig_agreement_matrix(rows: list, out_dir: Path, show: bool):
    """
    Heatmap showing pairwise agreement rate between methods.
    Agreement = both methods assign the same risk band (Low/Medium/High/Critical).
    """

    def risk_group(r):
        """Map a row to Low/Medium/High/Critical for each method."""
        cvss_s  = str(r.get("cvss_severity", "UNKNOWN")).upper()
        sars_s  = str(r.get("sars_severity", "UNKNOWN")).upper()
        oc_v    = normalise_verdict(r.get("openclaw_verdict",""))
        vt_v    = normalise_verdict(r.get("vt_verdict",""))

        # Map to 3-tier for cross-method comparison
        def tier_sev(s):
            return {"CRITICAL":"HIGH","HIGH":"HIGH","MEDIUM":"MEDIUM",
                    "LOW":"LOW","NONE":"LOW"}.get(s,"UNKNOWN")
        def tier_verdict(v):
            return {"Malicious":"HIGH","Suspicious":"MEDIUM","Benign":"LOW"}.get(v,"UNKNOWN")

        return {
            "CVSS":      tier_sev(cvss_s),
            "SARS":      tier_sev(sars_s),
            "OpenClaw":  tier_verdict(oc_v),
            "VirusTotal":tier_verdict(vt_v),
        }

    methods = ["CVSS", "SARS", "OpenClaw", "VirusTotal"]
    n = len(methods)
    matrix = np.zeros((n, n))

    for r in rows:
        groups = risk_group(r)
        for i, m1 in enumerate(methods):
            for j, m2 in enumerate(methods):
                if groups[m1] != "UNKNOWN" and groups[m2] != "UNKNOWN":
                    if groups[m1] == groups[m2]:
                        matrix[i, j] += 1

    # Normalise to percentage
    totals = np.zeros((n, n))
    for r in rows:
        groups = risk_group(r)
        for i, m1 in enumerate(methods):
            for j, m2 in enumerate(methods):
                if groups[m1] != "UNKNOWN" and groups[m2] != "UNKNOWN":
                    totals[i, j] += 1

    with np.errstate(divide="ignore", invalid="ignore"):
        pct = np.where(totals > 0, matrix / totals * 100, 0)

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(pct, cmap="Blues", vmin=0, vmax=100)

    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(methods, fontsize=10, fontweight="bold")
    ax.set_yticklabels(methods, fontsize=10, fontweight="bold")

    for i in range(n):
        for j in range(n):
            color = "white" if pct[i,j] > 60 else "#1E293B"
            ax.text(j, i, f"{pct[i,j]:.0f}%", ha="center", va="center",
                    fontsize=11, fontweight="bold", color=color)

    cbar = plt.colorbar(im, ax=ax, shrink=0.8)
    cbar.set_label("Agreement Rate (%)", fontsize=9)

    ax.set_title("Figure 5 — Pairwise Method Agreement Matrix\n"
                 "(% of skills where both methods assign the same risk tier)",
                 fontsize=11, fontweight="bold")
    ax.set_xlabel("Method B", fontsize=10)
    ax.set_ylabel("Method A", fontsize=10)

    plt.tight_layout()
    save_fig(fig, out_dir, "fig5_agreement_matrix.png", show)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 6 — CVSS vs SARS Severity Confusion Matrix
# ─────────────────────────────────────────────────────────────────────────────

def fig_cvss_sars_confusion(rows: list, out_dir: Path, show: bool):
    """Confusion matrix: CVSS severity (rows) vs SARS severity (cols)."""

    bands = [b for b in SEVERITY_ORDER
             if any(str(r.get("cvss_severity","")).upper() == b or
                    str(r.get("sars_severity","")).upper() == b for r in rows)]
    if not bands:
        print("  [SKIP] Figure 6 — no severity data")
        return

    n = len(bands)
    mat = np.zeros((n, n), dtype=int)
    band_idx = {b: i for i, b in enumerate(bands)}

    for r in rows:
        cs = str(r.get("cvss_severity","")).upper()
        ss = str(r.get("sars_severity","")).upper()
        if cs in band_idx and ss in band_idx:
            mat[band_idx[cs], band_idx[ss]] += 1

    fig, ax = plt.subplots(figsize=(7, 5.5))
    cmap = LinearSegmentedColormap.from_list("cm", ["#F8FAFF","#DBEAFE","#2563EB"])
    im = ax.imshow(mat, cmap=cmap)

    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(bands, fontsize=9, fontweight="bold")
    ax.set_yticklabels(bands, fontsize=9, fontweight="bold")
    ax.set_xlabel("SARS Severity",  fontsize=10)
    ax.set_ylabel("CVSS Severity",  fontsize=10)

    for i in range(n):
        for j in range(n):
            val = mat[i,j]
            color = "white" if val > mat.max()*0.5 else "#1E293B"
            ax.text(j, i, str(val), ha="center", va="center",
                    fontsize=11, fontweight="bold", color=color)

    # Diagonal (agreement) highlight
    for i in range(n):
        ax.add_patch(mpatches.Rectangle((i-0.5, i-0.5), 1, 1,
                     fill=False, edgecolor="#16A34A", linewidth=2.5))

    agree = int(np.trace(mat))
    total = int(mat.sum())
    kappa_note = f"Diagonal agreement: {agree}/{total} ({agree/total*100:.0f}%)" if total else ""

    ax.set_title(f"Figure 6 — CVSS vs SARS Severity Confusion Matrix\n"
                 f"{kappa_note}",
                 fontsize=11, fontweight="bold")

    plt.colorbar(im, ax=ax, shrink=0.8).set_label("Skill Count", fontsize=9)
    plt.tight_layout()
    save_fig(fig, out_dir, "fig6_cvss_sars_confusion.png", show)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 7 — VirusTotal vs SARS Risk Comparison
# ─────────────────────────────────────────────────────────────────────────────

def fig_vt_vs_sars(rows: list, out_dir: Path, show: bool):
    """
    Grouped bar: for VT-clean skills, how does SARS rate them?
    Highlights skills where VT says clean but SARS says HIGH/CRITICAL.
    """
    vt_rows = [r for r in rows if normalise_verdict(r.get("vt_verdict","")) == "Benign"]
    if not vt_rows:
        print("  [SKIP] Figure 7 — no VT-Benign data")
        return

    # SARS distribution for VT-clean skills vs ALL skills
    sars_all   = {s: count(rows,    "sars_severity", s) for s in SEVERITY_ORDER}
    sars_clean = {s: count(vt_rows, "sars_severity", s) for s in SEVERITY_ORDER}

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("Figure 7 — VirusTotal vs SARS: Where Do They Disagree?",
                 fontsize=12, fontweight="bold")

    # Left: SARS for VT-clean vs all
    x  = np.arange(len(SEVERITY_ORDER))
    w  = 0.38
    ax = axes[0]
    bar1 = ax.bar(x - w/2, [sars_all.get(s,0)   for s in SEVERITY_ORDER],
                  width=w, color="#2563EB", alpha=0.8, label="All skills")
    bar2 = ax.bar(x + w/2, [sars_clean.get(s,0) for s in SEVERITY_ORDER],
                  width=w, color="#16A34A", alpha=0.8, label="VT-Benign skills")
    ax.set_xticks(x)
    ax.set_xticklabels(SEVERITY_ORDER, fontsize=9)
    ax.set_ylabel("Number of Skills")
    ax.set_title("SARS Severity Distribution\n(All vs VT-Benign)", fontsize=10, fontweight="bold")
    ax.legend(fontsize=8)
    ax.yaxis.grid(True, linestyle="--", alpha=0.4)
    ax.set_axisbelow(True)

    # Right: Skills where VT=Benign but SARS=HIGH or CRITICAL (the interesting cases)
    divergent = [r for r in vt_rows
                 if str(r.get("sars_severity","")).upper() in ("HIGH","CRITICAL")]
    ax2 = axes[1]
    if divergent:
        divergent.sort(key=lambda r: float(r.get("sars_score",0)), reverse=True)
        top = divergent[:15]
        names  = [str(r.get("skill_name",""))[:22] for r in top]
        scores = [float(r.get("sars_score",0))  for r in top]
        colors = [RISK_COLORS.get(str(r.get("sars_severity","")).upper(),"#94A3B8") for r in top]
        bars   = ax2.barh(range(len(top)), scores, color=colors,
                          edgecolor="white", linewidth=0.5)
        ax2.set_yticks(range(len(top)))
        ax2.set_yticklabels(names, fontsize=7)
        ax2.set_xlim(0, 10.5)
        ax2.set_xlabel("SARS Score", fontsize=9)
        ax2.set_title(f"Skills VT says Benign but SARS says HIGH/CRITICAL\n"
                      f"(n={len(divergent)} total, showing top {len(top)})",
                      fontsize=10, fontweight="bold")
        for bar, val in zip(bars, scores):
            ax2.text(val + 0.1, bar.get_y() + bar.get_height()/2,
                     f"{val:.1f}", va="center", fontsize=7)
        ax2.xaxis.grid(True, linestyle="--", alpha=0.4)
        ax2.set_axisbelow(True)
    else:
        ax2.text(0.5, 0.5, "No divergent cases found\n(VT=Benign, SARS=HIGH/CRITICAL)",
                 ha="center", va="center", transform=ax2.transAxes, fontsize=10)
        ax2.set_title("Divergent Cases", fontsize=10, fontweight="bold")

    plt.tight_layout()
    save_fig(fig, out_dir, "fig7_vt_vs_sars.png", show)


# ─────────────────────────────────────────────────────────────────────────────
# Figure 8 — Top-20 Skills Comparison Table
# ─────────────────────────────────────────────────────────────────────────────

def fig_top20_table(rows: list, out_dir: Path, show: bool):
    """Colour-coded table: top-20 skills by SARS score, all four methods side by side."""

    if not rows:
        print("  [SKIP] Figure 8 — no data")
        return

    sorted_rows = sorted(rows, key=lambda r: float(r.get("sars_score",0)), reverse=True)
    top = sorted_rows[:20]

    col_headers = ["Rank", "Skill", "CVSS\nScore", "CVSS\nSev.", "SARS\nScore",
                   "SARS\nSev.", "OpenClaw\nVerdict", "VT\nVerdict"]
    n_cols = len(col_headers)
    n_rows = len(top)

    fig, ax = plt.subplots(figsize=(16, 0.45 * n_rows + 1.8))
    ax.axis("off")

    col_widths = [0.05, 0.23, 0.07, 0.07, 0.07, 0.07, 0.12, 0.10]

    # Header
    x = 0
    for i, (hdr, w) in enumerate(zip(col_headers, col_widths)):
        ax.text(x + w/2, 1.0, hdr, ha="center", va="center",
                fontsize=7.5, fontweight="bold",
                transform=ax.transAxes,
                bbox=dict(boxstyle="round,pad=0.2", fc="#1E3A5F", ec="none"))
        ax.text(x + w/2, 1.0, hdr, ha="center", va="center",
                fontsize=7.5, fontweight="bold", color="white",
                transform=ax.transAxes)
        x += w

    row_h = 1.0 / (n_rows + 1)

    for ri, r in enumerate(top):
        y = 1.0 - (ri + 1) * row_h
        bg = "#F8FAFF" if ri % 2 == 0 else "white"

        sars_sev = str(r.get("sars_severity","")).upper()
        cvss_sev = str(r.get("cvss_severity","")).upper()
        oc_v     = normalise_verdict(r.get("openclaw_verdict",""))
        vt_v     = normalise_verdict(r.get("vt_verdict",""))

        cells = [
            str(ri+1),
            str(r.get("skill_name",""))[:28],
            f"{float(r.get('cvss_base_score',0)):.1f}",
            cvss_sev[:4],
            f"{float(r.get('sars_score',0)):.1f}",
            sars_sev[:4],
            oc_v,
            vt_v,
        ]
        cell_colors = [
            None, None,
            RISK_COLORS.get(cvss_sev, "#94A3B8"),
            RISK_COLORS.get(cvss_sev, "#94A3B8"),
            RISK_COLORS.get(sars_sev, "#94A3B8"),
            RISK_COLORS.get(sars_sev, "#94A3B8"),
            RISK_COLORS.get(oc_v, "#94A3B8"),
            RISK_COLORS.get(vt_v, "#94A3B8"),
        ]

        x = 0
        for ci, (cell_text, w, cc) in enumerate(zip(cells, col_widths, cell_colors)):
            fc = cc if cc and ci >= 2 else bg
            text_color = "white" if cc and ci >= 2 else "#1E293B"
            ax.add_patch(mpatches.FancyBboxPatch(
                (x, y), w, row_h,
                boxstyle="square,pad=0",
                transform=ax.transAxes,
                fc=fc, ec="white", linewidth=0.8,
            ))
            ax.text(x + w/2, y + row_h/2, cell_text,
                    ha="center", va="center",
                    fontsize=6.8, color=text_color,
                    transform=ax.transAxes,
                    clip_on=True)
            x += w

    ax.set_title("Figure 8 — Top-20 Skills by SARS Score (All Four Methods)",
                 fontsize=12, fontweight="bold", pad=20)

    plt.tight_layout()
    save_fig(fig, out_dir, "fig8_top20_table.png", show)



# ─────────────────────────────────────────────────────────────────────────────
# LaTeX table generation
# ─────────────────────────────────────────────────────────────────────────────

def _bold_max(vals: list, fmt: str = ".2f") -> list:
    """Return formatted strings with the maximum value wrapped in \\textbf{}."""
    numeric = [v for v in vals if v is not None]
    if not numeric:
        return ["—"] * len(vals)
    mx = max(numeric)
    out = []
    for v in vals:
        if v is None:
            out.append("—")
        elif v == mx:
            out.append(f"\\textbf{{{v:{fmt}}}}")
        else:
            out.append(f"{v:{fmt}}")
    return out


def _bold_min(vals: list, fmt: str = ".2f") -> list:
    """Return formatted strings with the minimum value wrapped in \\textbf{}."""
    numeric = [v for v in vals if v is not None]
    if not numeric:
        return ["—"] * len(vals)
    mn = min(numeric)
    out = []
    for v in vals:
        if v is None:
            out.append("—")
        elif v == mn:
            out.append(f"\\textbf{{{v:{fmt}}}}")
        else:
            out.append(f"{v:{fmt}}")
    return out


def _row(cells: list, gray: bool = False, midrule: bool = False) -> str:
    """Format one LaTeX table row, optionally with rowcolor and midrule."""
    prefix = "\\rowcolor{RowGray}\n" if gray else ""
    suffix = "\\\\\n\\midrule\n" if midrule else "\\\\"
    return prefix + " & ".join(str(c) for c in cells) + " " + suffix + "\n"



# ─────────────────────────────────────────────────────────────────────────────
# LaTeX table generation
# ─────────────────────────────────────────────────────────────────────────────

def _bold_max(vals, fmt=".2f"):
    numeric = [v for v in vals if v is not None]
    if not numeric:
        return ["—"] * len(vals)
    mx = max(numeric)
    return [
        ("\\textbf{" + format(v, fmt) + "}") if v == mx else format(v, fmt)
        if v is not None else "—"
        for v in vals
    ]


def generate_latex_tables(rows, out_dir, enriched=None):
    """
    Generate six LaTeX tables from the merged evaluation data and write
    them all to results/evaluation_tables.tex.

    Tables:
      Tab 1 — Risk/verdict distribution (all four methods)
      Tab 2 — SARS dimension means by overall risk band
      Tab 3 — CVSS vs SARS severity confusion matrix
      Tab 4 — OpenClaw 5-category pass/warn/fail distribution
      Tab 5 — Top-10 skills (SARS, CVSS, delta, OpenClaw, VT)
      Tab 6 — Pairwise method agreement rates
    """
    from pathlib import Path as _P
    out_dir = _P(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    LN = "\n"   # newline alias for f-string use
    n  = len(rows)

    # ── helper: produce one tabular row ──────────────────────────────────
    def row(cells, gray=False, bold_idx=None):
        bold_idx = bold_idx or set()
        formatted = []
        for i, c in enumerate(cells):
            formatted.append("\\textbf{" + str(c) + "}" if i in bold_idx else str(c))
        prefix = "\\rowcolor{RowGray}\n" if gray else ""
        return prefix + " & ".join(formatted) + " \\\\"

    def pct_str(x, total):
        return f"{x} ({x/total*100:.0f}\\%)" if total else "0"

    def risk_tier(r, method):
        if method == "CVSS":
            s = str(r.get("cvss_severity","")).upper()
            return {"CRITICAL":"HIGH","HIGH":"HIGH","MEDIUM":"MEDIUM",
                    "LOW":"LOW","NONE":"LOW"}.get(s,"?")
        if method == "SARS":
            s = str(r.get("sars_severity","")).upper()
            return {"CRITICAL":"HIGH","HIGH":"HIGH","MEDIUM":"MEDIUM",
                    "LOW":"LOW","NONE":"LOW"}.get(s,"?")
        v = normalise_verdict(r.get("openclaw_verdict","") if method == "OpenClaw"
                              else r.get("vt_verdict",""))
        return {"Malicious":"HIGH","Suspicious":"MEDIUM","Benign":"LOW"}.get(v,"?")

    out = []

    # ── Preamble ─────────────────────────────────────────────────────────
    out.append("% ============================================================")
    out.append("% Evaluation Results Tables — AgentAIBench")
    out.append("% Generated by evaluation_analysis.py — SUPREME Lab, UTEP")
    out.append("% Requires in preamble: booktabs, tabularx, multirow,")
    out.append("%   array, xcolor, colortbl, amsmath")
    out.append("% Column types L{w} and C{w} defined in define.tex")
    out.append("% ============================================================")
    out.append("")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 1 — Risk Distribution
    # ══════════════════════════════════════════════════════════════════════
    bands = SEVERITY_ORDER
    oc_map = {"NONE":"Benign","MEDIUM":"Suspicious","CRITICAL":"Malicious"}
    cvss_d = {s: count(rows,"cvss_severity",s) for s in bands}
    sars_d = {s: count(rows,"sars_severity",s) for s in bands}
    oc_d   = {
        "NONE":     sum(1 for r in rows if normalise_verdict(r.get("openclaw_verdict","")) == "Benign"),
        "MEDIUM":   sum(1 for r in rows if normalise_verdict(r.get("openclaw_verdict","")) == "Suspicious"),
        "CRITICAL": sum(1 for r in rows if normalise_verdict(r.get("openclaw_verdict","")) == "Malicious"),
    }
    vt_d   = {
        "NONE":     sum(1 for r in rows if normalise_verdict(r.get("vt_verdict","")) == "Benign"),
        "MEDIUM":   sum(1 for r in rows if normalise_verdict(r.get("vt_verdict","")) == "Suspicious"),
        "CRITICAL": sum(1 for r in rows if normalise_verdict(r.get("vt_verdict","")) == "Malicious"),
    }

    out += [
        "% ─── Table 1 ─────────────────────────────────────────────────────",
        "\\begin{table}[htbp]",
        "\\centering",
        f"\\caption{{Risk and verdict distribution of {n} evaluated skills across "
        "all four evaluation frameworks. OpenClaw and VirusTotal use a ternary "
        "verdict scale; CVSS and SARS use a five-level severity scale.}",
        "\\label{tab:risk_distribution}",
        "\\renewcommand{\\arraystretch}{1.3}",
        "\\begin{tabular}{@{} L{3.0cm} C{1.3cm} C{1.3cm} C{1.8cm} C{1.8cm} @{}}",
        "\\toprule",
        "\\textbf{Severity / Verdict} & \\textbf{CVSS} & \\textbf{SARS}"
        " & \\textbf{OpenClaw} & \\textbf{VirusTotal} \\\\",
        "\\midrule",
    ]
    for i, band in enumerate(bands):
        oc_label = oc_map.get(band, "---")
        oc_val = str(oc_d.get(band, "---")) if band in oc_d else "---"
        vt_val = str(vt_d.get(band, "---")) if band in vt_d else "---"
        label  = f"{band} ({oc_label})"
        out.append(row([label, cvss_d[band], sars_d[band], oc_val, vt_val], gray=(i%2==1)))
    out += [
        "\\midrule",
        row([f"\\textit{{Total}}", n, n, n, n]),
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ]

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 2 — SARS Dimension Means by Risk Band
    # ══════════════════════════════════════════════════════════════════════
    dims = ["sars_ifr","sars_dg","sars_ai","sars_br","sars_ca"]
    band_data = []
    for band in bands:
        br = [r for r in rows if str(r.get("overall_risk","")).upper() == band]
        if not br:
            continue
        means = [round(float(np.mean([float(r.get(d,0)) for r in br])),2) for d in dims]
        sars_m = round(float(np.mean([float(r.get("sars_score",0)) for r in br])),1)
        band_data.append((band, means, sars_m, len(br)))

    if band_data:
        col_maxes = [_bold_max([bd[1][j] for bd in band_data]) for j in range(5)]
        sars_maxes = _bold_max([bd[2] for bd in band_data], fmt=".1f")
        all_means  = [round(float(np.mean([float(r.get(d,0)) for r in rows])),2) for d in dims]
        all_sars   = round(float(np.mean([float(r.get("sars_score",0)) for r in rows])),1)

        out += [
            "% ─── Table 2 ─────────────────────────────────────────────────────",
            "\\begin{table}[htbp]",
            "\\centering",
            "\\caption{Mean SARS dimension score (0--3) by overall risk band. "
            "Bold values indicate the highest score in each column. "
            "IFR\\,=\\,Instruction Fidelity Risk, DG\\,=\\,Data Gravity, "
            "AI\\,=\\,Action Irreversibility, BR\\,=\\,Blast Radius, CA\\,=\\,Chain Amplification.}",
            "\\label{tab:sars_by_band}",
            "\\renewcommand{\\arraystretch}{1.3}",
            "\\begin{tabular}{@{} L{2.8cm} C{1.0cm} C{1.0cm} C{1.0cm} C{1.0cm} C{1.0cm} C{1.2cm} @{}}",
            "\\toprule",
            "\\textbf{Risk Band} & \\textbf{IFR} & \\textbf{DG} & \\textbf{AI}"
            " & \\textbf{BR} & \\textbf{CA} & \\textbf{SARS} \\\\",
            "\\midrule",
        ]
        for idx,(band,means,sars_m,cnt) in enumerate(band_data):
            cells = [f"\\textbf{{{band}}} (n\\,=\\,{cnt})"]
            cells += [col_maxes[j][idx] for j in range(5)]
            cells.append(sars_maxes[idx])
            out.append(row(cells, gray=(idx%2==1)))
        out += [
            "\\midrule",
            row(["\\textit{Overall mean}"] + [f"{v:.2f}" for v in all_means] + [f"{all_sars:.1f}"]),
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ]

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 3 — CVSS vs SARS Confusion Matrix
    # ══════════════════════════════════════════════════════════════════════
    pb = [b for b in bands if any(
        str(r.get("cvss_severity","")).upper()==b or
        str(r.get("sars_severity","")).upper()==b for r in rows)]
    if pb:
        bidx = {b:i for i,b in enumerate(pb)}
        nb   = len(pb)
        mat  = [[0]*nb for _ in range(nb)]
        for r in rows:
            cs = str(r.get("cvss_severity","")).upper()
            ss = str(r.get("sars_severity","")).upper()
            if cs in bidx and ss in bidx:
                mat[bidx[cs]][bidx[ss]] += 1
        agree = sum(mat[i][i] for i in range(nb))
        tot   = sum(mat[i][j] for i in range(nb) for j in range(nb))
        agree_pct = f"{agree/tot*100:.0f}\\%" if tot else "---"

        out += [
            "% ─── Table 3 ─────────────────────────────────────────────────────",
            "\\begin{table}[htbp]",
            "\\centering",
            f"\\caption{{Severity-band confusion matrix: CVSS v4.0 (rows) vs.\\ SARS (columns). "
            f"Values are skill counts; bold diagonal entries show agreement. "
            f"Overall agreement: {agree}/{tot} ({agree_pct}).}}",
            "\\label{tab:cvss_sars_confusion}",
            "\\renewcommand{\\arraystretch}{1.3}",
            "\\begin{tabular}{@{} L{2.2cm} " + " ".join(["C{1.4cm}"]*nb) + " @{}}",
            "\\toprule",
            f"& \\multicolumn{{{nb}}}{{c}}{{\\textbf{{SARS Severity}}}} \\\\",
            f"\\cmidrule(lr){{2-{nb+1}}}",
            "\\textbf{CVSS} & " + " & ".join(f"\\textbf{{{b[:4]}}}" for b in pb) + " \\\\",
            "\\midrule",
        ]
        for i, br in enumerate(pb):
            cells = [f"\\textbf{{{br[:4]}}}"]
            for j, val in enumerate(mat[i]):
                cells.append(f"\\textbf{{{val}}}" if i == j else str(val))
            out.append(row(cells, gray=(i%2==1)))
        out += ["\\bottomrule","\\end{tabular}","\\end{table}",""]

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 4 — OpenClaw 5-Category Distribution
    # ══════════════════════════════════════════════════════════════════════
    oc_rows = [r for r in rows if r.get("openclaw_verdict")]
    n_oc    = len(oc_rows)
    if n_oc:
        out += [
            "% ─── Table 4 ─────────────────────────────────────────────────────",
            "\\begin{table}[htbp]",
            "\\centering",
            f"\\caption{{OpenClaw safety evaluation results across the five categories "
            f"for {n_oc} skills. Values show skill count and percentage. "
            "Pass\\,=\\,no concern, Warn\\,=\\,minor concern, Fail\\,=\\,significant issue.}}",
            "\\label{tab:openclaw_dims}",
            "\\renewcommand{\\arraystretch}{1.3}",
            "\\begin{tabularx}{\\linewidth}{@{} L{3.6cm} X X X C{1.4cm} @{}}",
            "\\toprule",
            "\\textbf{Category} & \\textbf{Pass} & \\textbf{Warn} & \\textbf{Fail} & \\textbf{No Data} \\\\",
            "\\midrule",
        ]
        for idx,(dk,dl) in enumerate(OC_DIMS):
            label = dl.replace("\n"," ")
            p  = sum(1 for r in oc_rows if r.get(f"oc_{dk}","")=="pass")
            w  = sum(1 for r in oc_rows if r.get(f"oc_{dk}","")=="warn")
            f_ = sum(1 for r in oc_rows if r.get(f"oc_{dk}","")=="fail")
            nd = n_oc - p - w - f_
            out.append(row(
                [label, pct_str(p,n_oc), pct_str(w,n_oc),
                 pct_str(f_,n_oc), pct_str(nd,n_oc)],
                gray=(idx%2==1)
            ))
        out += ["\\bottomrule","\\end{tabularx}","\\end{table}",""]

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 5 — Top-10 Skills
    # ══════════════════════════════════════════════════════════════════════
    top10 = sorted(rows, key=lambda r: float(r.get("sars_score",0)), reverse=True)[:10]
    if top10:
        m_sars = float(np.mean([float(r.get("sars_score",0)) for r in top10]))
        m_cvss = float(np.mean([float(r.get("cvss_base_score",0)) for r in top10]))
        a_sars = float(np.mean([float(r.get("sars_score",0)) for r in rows]))
        a_cvss = float(np.mean([float(r.get("cvss_base_score",0)) for r in rows]))
        out += [
            "% ─── Table 5 ─────────────────────────────────────────────────────",
            "\\begin{table}[htbp]",
            "\\centering",
            "\\caption{Top-10 highest-risk skills ranked by SARS score. "
            "$\\Delta = \\text{SARS} - \\text{CVSS}$; positive values indicate "
            "risk underreported by CVSS alone. OC\\,=\\,OpenClaw verdict, "
            "VT\\,=\\,VirusTotal verdict.}",
            "\\label{tab:top10}",
            "\\renewcommand{\\arraystretch}{1.25}",
            "\\begin{tabularx}{\\linewidth}{@{} r L{3.0cm} C{1.0cm} C{1.0cm} C{0.8cm} L{2.0cm} L{2.0cm} @{}}",
            "\\toprule",
            "\\textbf{\\#} & \\textbf{Skill} & \\textbf{SARS} & \\textbf{CVSS}"
            " & \\textbf{$\\Delta$} & \\textbf{OC} & \\textbf{VT} \\\\",
            "\\midrule",
        ]
        for i,r in enumerate(top10):
            sname = str(r.get("skill_name",""))[:26].replace("_","\\_")
            sars  = float(r.get("sars_score",0))
            cvss  = float(r.get("cvss_base_score",0))
            delta = sars - cvss
            oc_v  = normalise_verdict(r.get("openclaw_verdict",""))
            vt_v  = normalise_verdict(r.get("vt_verdict",""))
            sign  = "+" if delta >= 0 else ""
            out.append(row(
                [i+1, f"\\texttt{{{sname}}}", f"{sars:.1f}", f"{cvss:.1f}",
                 f"${sign}{delta:.1f}$", oc_v, vt_v],
                gray=(i%2==1)
            ))
        out += [
            "\\midrule",
            row([f"\\multicolumn{{2}}{{@{{}}l}}{{\\textit{{Mean (top-10)}}}}",
                 f"{m_sars:.1f}", f"{m_cvss:.1f}",
                 f"$+{m_sars-m_cvss:.1f}$" if m_sars>=m_cvss else f"${m_sars-m_cvss:.1f}$",
                 "", ""]),
            row([f"\\multicolumn{{2}}{{@{{}}l}}{{\\textit{{Mean (all {n} skills)}}}}",
                 f"{a_sars:.1f}", f"{a_cvss:.1f}",
                 f"$+{a_sars-a_cvss:.1f}$" if a_sars>=a_cvss else f"${a_sars-a_cvss:.1f}$",
                 "", ""]),
            "\\bottomrule",
            "\\end{tabularx}",
            "\\end{table}",
            "",
        ]

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 6 — Pairwise Agreement
    # ══════════════════════════════════════════════════════════════════════
    methods = ["CVSS","SARS","OpenClaw","VirusTotal"]
    nm      = len(methods)
    agree_m  = [[0.0]*nm for _ in range(nm)]
    total_m  = [[0.0]*nm for _ in range(nm)]
    for r in rows:
        tiers = {m: risk_tier(r,m) for m in methods}
        for i,m1 in enumerate(methods):
            for j,m2 in enumerate(methods):
                if tiers[m1] != "?" and tiers[m2] != "?":
                    total_m[i][j] += 1
                    if tiers[m1] == tiers[m2]:
                        agree_m[i][j] += 1

    out += [
        "% ─── Table 6 ─────────────────────────────────────────────────────",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Pairwise agreement rate (\\%) between the four evaluation methods. "
        "Agreement is defined as both methods assigning the same risk tier "
        "(Low / Medium / High) to a skill. Bold diagonal = self-agreement (100\\%).}",
        "\\label{tab:agreement}",
        "\\renewcommand{\\arraystretch}{1.3}",
        "\\begin{tabular}{@{} L{2.2cm} C{1.6cm} C{1.6cm} C{1.8cm} C{1.8cm} @{}}",
        "\\toprule",
        "\\textbf{Method} & " + " & ".join(f"\\textbf{{{m}}}" for m in methods) + " \\\\",
        "\\midrule",
    ]
    for i,m1 in enumerate(methods):
        cells = [f"\\textbf{{{m1}}}"]
        for j in range(nm):
            t = total_m[i][j]
            pv = agree_m[i][j]/t*100 if t > 0 else 0
            val = f"\\textbf{{{pv:.0f}\\%}}" if i==j else f"{pv:.0f}\\%"
            cells.append(val)
        out.append(row(cells, gray=(i%2==1)))
    out += ["\\bottomrule","\\end{tabular}","\\end{table}",""]

    # ── Write file ────────────────────────────────────────────────────────
    out_path = out_dir / "evaluation_tables.tex"
    with open(out_path,"w",encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"  Saved: {out_path}  ({len(out)} lines)")



# ─────────────────────────────────────────────────────────────────────────────
# Radar / Spider plots
# ─────────────────────────────────────────────────────────────────────────────

def _radar_ax(ax, values, labels, color, label, alpha_fill=0.15, lw=2.0):
    """
    Draw one polygon on a radar axis.

    ax      : a polar matplotlib axis
    values  : list of floats, one per spoke (already normalised 0-1)
    labels  : spoke labels (used to set ticks on first call)
    color   : line + fill colour
    label   : legend label
    """
    n = len(values)
    angles = [k * 2 * np.pi / n for k in range(n)] + [0]
    vals   = list(values) + [values[0]]           # close the polygon

    ax.plot(angles, vals, color=color, linewidth=lw, label=label, zorder=3)
    ax.fill(angles, vals, color=color, alpha=alpha_fill, zorder=2)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, fontsize=8, fontweight="bold")
    ax.set_yticklabels([])
    ax.spines["polar"].set_visible(True)
    ax.spines["polar"].set_linewidth(0.5)
    ax.spines["polar"].set_edgecolor("#CBD5E1")
    ax.grid(True, color="#E2E8F0", linewidth=0.7, linestyle="--")


def fig_radar(rows: list, out_dir, show: bool):
    """
    Three-panel radar / spider chart figure.

    Panel A — SARS dimension profile per top_finding_category
      Axes : IFR, DG, AI, BR, CA  (mean score 0-3, displayed as 0-1)
      Lines: one per vulnerability category (top 6 by count)

    Panel B — SARS dimension profile per CVSS severity band
      Axes : same five SARS dimensions
      Lines: one per band (NONE, LOW, MEDIUM, HIGH, CRITICAL)

    Panel C — Overall method comparison
      Axes : CVSS Risk, SARS Risk, OpenClaw Risk, VT Risk, Vuln Density
      Lines: each axis normalised to 0-1 across the dataset
             a single "average skill" polygon showing the benchmark profile
    """
    from pathlib import Path as _P
    out_dir = _P(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    DIMS      = ["sars_ifr", "sars_dg", "sars_ai", "sars_br", "sars_ca"]
    DIM_LABS  = ["IFR\n(Injection)", "DG\n(Data)", "AI\n(Irreversibility)",
                 "BR\n(Blast)", "CA\n(Chain)"]
    DIM_MAX   = 3.0     # SARS dimensions scored 0-3

    # colour palette — distinct, print-friendly
    PALETTE = [
        "#2563EB","#DC2626","#16A34A","#D97706","#7C3AED",
        "#0D9488","#EA580C","#9333EA","#0891B2","#65A30D",
    ]
    BAND_COLORS = {
        "NONE":     "#0D9488",
        "LOW":      "#16A34A",
        "MEDIUM":   "#D97706",
        "HIGH":     "#EA580C",
        "CRITICAL": "#DC2626",
        "UNKNOWN":  "#94A3B8",
    }

    fig = plt.figure(figsize=(18, 6))
    fig.suptitle("Figure 9 — Radar Plots: SARS Dimension Profiles",
                 fontsize=13, fontweight="bold", y=1.02)

    # ── Panel A — by top_finding_category ────────────────────────────────
    ax_a = fig.add_subplot(131, polar=True)
    ax_a.set_title("A.  SARS Profile\nby Vulnerability Category",
                   fontsize=10, fontweight="bold", pad=18)

    # Group rows by top_finding_category; keep top 6 by count
    from collections import Counter
    cat_counts = Counter(
        str(r.get("top_finding_category", "")).strip()
        for r in rows
        if str(r.get("top_finding_category", "")).strip()
    )
    top_cats = [c for c, _ in cat_counts.most_common(6)]

    plotted_a = False
    for ci, cat in enumerate(top_cats):
        cat_rows = [r for r in rows
                    if str(r.get("top_finding_category","")).strip() == cat]
        if len(cat_rows) < 2:
            continue
        means = [
            float(np.mean([float(r.get(d, 0)) for r in cat_rows])) / DIM_MAX
            for d in DIMS
        ]
        short = cat.replace(" / ", "/").replace(" Injection", " Inj.") \
                   .replace("Credential / Secret Exposure", "Credential") \
                   .replace("Indirect / Embedded Injection", "Indirect Inj.") \
                   .replace("Dependency / Supply Chain", "Dep./Supply") \
                   .replace("Scope Creep", "Scope Creep")
        short = short[:22]
        _radar_ax(ax_a, means, DIM_LABS, PALETTE[ci % len(PALETTE)],
                  f"{short} (n={len(cat_rows)})")
        plotted_a = True

    if not plotted_a:
        ax_a.text(0, 0, "No top_finding_category\ndata available",
                  ha="center", va="center", fontsize=9)

    ax_a.set_ylim(0, 1)
    ax_a.set_yticks([0.33, 0.67, 1.0])
    ax_a.set_yticklabels(["1", "2", "3"], fontsize=6, color="#94A3B8")
    leg_a = ax_a.legend(loc="upper right", bbox_to_anchor=(1.55, 1.15),
                        fontsize=7, framealpha=0.9, title="Category")
    leg_a.get_title().set_fontsize(7)

    # ── Panel B — by CVSS severity band ──────────────────────────────────
    ax_b = fig.add_subplot(132, polar=True)
    ax_b.set_title("B.  SARS Profile\nby CVSS Severity Band",
                   fontsize=10, fontweight="bold", pad=18)

    present_bands = [b for b in SEVERITY_ORDER
                     if any(str(r.get("cvss_severity","")) == b for r in rows)]

    for band in present_bands:
        band_rows = [r for r in rows if str(r.get("cvss_severity","")) == band]
        if not band_rows:
            continue
        means = [
            float(np.mean([float(r.get(d, 0)) for r in band_rows])) / DIM_MAX
            for d in DIMS
        ]
        _radar_ax(ax_b, means, DIM_LABS,
                  BAND_COLORS.get(band, "#94A3B8"),
                  f"{band} (n={len(band_rows)})",
                  alpha_fill=0.12)

    ax_b.set_ylim(0, 1)
    ax_b.set_yticks([0.33, 0.67, 1.0])
    ax_b.set_yticklabels(["1", "2", "3"], fontsize=6, color="#94A3B8")
    leg_b = ax_b.legend(loc="upper right", bbox_to_anchor=(1.5, 1.15),
                        fontsize=7, framealpha=0.9, title="CVSS Severity")
    leg_b.get_title().set_fontsize(7)

    # ── Panel C — Overall method comparison radar ─────────────────────────
    # Each axis = one evaluation method, normalised to 0-1 across dataset.
    # We also add Vuln Density (vulnerability_count / max_count) and
    # Stars (popularity proxy) so the radar has ≥5 spokes.
    ax_c = fig.add_subplot(133, polar=True)
    ax_c.set_title("C.  Method Comparison\n(Mean normalised risk per method)",
                   fontsize=10, fontweight="bold", pad=18)

    def _norm_mean(vals, vmin=0, vmax=10):
        v = [float(x) for x in vals if x is not None]
        if not v:
            return 0.0
        return float(np.mean(v)) / vmax

    def _verdict_score(verdict_str):
        """Map OpenClaw/VT verdict to numeric 0-1."""
        return {"Benign": 0.1, "Suspicious": 0.55, "Malicious": 1.0,
                "Unknown": 0.5}.get(verdict_str, 0.5)

    c_axes   = ["CVSS\nScore", "SARS\nScore", "OpenClaw\nRisk",
                "VirusTotal\nRisk", "Vuln\nDensity"]

    # Mean across all skills
    cvss_m  = _norm_mean([r.get("cvss_base_score", 0) for r in rows], 0, 10)
    sars_m  = _norm_mean([r.get("sars_score",      0) for r in rows], 0, 10)
    oc_m    = float(np.mean([_verdict_score(normalise_verdict(r.get("openclaw_verdict","")))
                              for r in rows])) if rows else 0.0
    vt_m    = float(np.mean([_verdict_score(normalise_verdict(r.get("vt_verdict","")))
                              for r in rows])) if rows else 0.0
    max_vuln = max((float(r.get("vulnerability_count", 0)) for r in rows), default=1)
    vuln_m  = float(np.mean([float(r.get("vulnerability_count", 0)) for r in rows])) \
              / max(max_vuln, 1) if rows else 0.0

    overall_profile = [cvss_m, sars_m, oc_m, vt_m, vuln_m]

    # Also draw per-severity profiles for context
    for band in [b for b in SEVERITY_ORDER if b in present_bands]:
        band_rows = [r for r in rows if str(r.get("overall_risk","")) == band]
        if len(band_rows) < 2:
            continue
        bp = [
            _norm_mean([r.get("cvss_base_score",0) for r in band_rows], 0, 10),
            _norm_mean([r.get("sars_score",0)      for r in band_rows], 0, 10),
            float(np.mean([_verdict_score(normalise_verdict(r.get("openclaw_verdict","")))
                           for r in band_rows])),
            float(np.mean([_verdict_score(normalise_verdict(r.get("vt_verdict","")))
                           for r in band_rows])),
            float(np.mean([float(r.get("vulnerability_count",0)) for r in band_rows]))
            / max(max_vuln, 1),
        ]
        _radar_ax(ax_c, bp, c_axes,
                  BAND_COLORS.get(band, "#94A3B8"),
                  f"{band} (n={len(band_rows)})",
                  alpha_fill=0.07, lw=1.2)

    # Overall mean — thicker line on top
    _radar_ax(ax_c, overall_profile, c_axes, "#1E3A5F",
              f"All skills (n={len(rows)})", alpha_fill=0.18, lw=2.5)

    ax_c.set_ylim(0, 1)
    ax_c.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax_c.set_yticklabels(["25%", "50%", "75%", "100%"],
                          fontsize=6, color="#94A3B8")
    leg_c = ax_c.legend(loc="upper right", bbox_to_anchor=(1.55, 1.15),
                        fontsize=7, framealpha=0.9, title="Risk Band")
    leg_c.get_title().set_fontsize(7)

    plt.tight_layout(pad=2.0)
    save_fig(fig, out_dir, "fig9_radar.png", show)




# ─────────────────────────────────────────────────────────────────────────────
# Result tables: top_finding_category breakdowns
# ─────────────────────────────────────────────────────────────────────────────

# Severity → 3-tier verdict mapping (used in Table A)
def _to_verdict(sev_or_verdict: str) -> str:
    """
    Map a severity band OR a method verdict to the common 3-tier scale.
      CRITICAL / HIGH  → Malicious
      MEDIUM           → Suspicious
      LOW / NONE       → Benign
      Malicious/Suspicious/Benign passthrough
    """
    v = str(sev_or_verdict).strip().upper()
    if v in ("CRITICAL", "HIGH", "MALICIOUS"):
        return "Malicious"
    if v in ("MEDIUM", "SUSPICIOUS"):
        return "Suspicious"
    if v in ("LOW", "NONE", "BENIGN", "CLEAN"):
        return "Benign"
    return "Unknown"


def generate_category_tables(rows: list, out_dir) -> None:
    """
    Write two LaTeX tables to results/evaluation_category_tables.tex.

    Table A — top_finding_category × Method Comparison
      Rows    : each vulnerability category (+ Total row)
      Columns : n, CVSS verdict, SARS verdict, OpenClaw verdict, VT verdict
                each shown as Malicious / Suspicious / Benign counts

    Table B — top_finding_category × SARS Dimension Means
      Rows    : each vulnerability category (+ Overall mean)
      Columns : IFR, DG, AI, BR, CA mean (0-3), plus CRITICAL/HIGH/MEDIUM/LOW counts
    """
    from pathlib import Path as _P
    import numpy as np
    out_dir = _P(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    DIMS      = ["sars_ifr", "sars_dg", "sars_ai", "sars_br", "sars_ca"]
    DIM_HDRS  = ["IFR", "DG", "AI", "BR", "CA"]
    VERDICTS  = ["Malicious", "Suspicious", "Benign"]
    SARS_BANDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    # ── Collect all non-empty categories ─────────────────────────────────
    from collections import defaultdict, Counter
    cat_rows = defaultdict(list)
    for r in rows:
        cat = str(r.get("top_finding_category", "")).strip()
        if cat:
            cat_rows[cat].append(r)

    # Sort categories by count descending
    cats = sorted(cat_rows.keys(), key=lambda c: -len(cat_rows[c]))

    if not cats:
        print("  [SKIP] Category tables — no top_finding_category data")
        return

    def pct(x, n):
        return f"{x} ({x/n*100:.0f}\\%)" if n else "0"

    def bold_max(vals, fmt=".2f"):
        if not vals:
            return ["—"] * len(vals)
        mx = max(vals)
        return [("\\textbf{" + format(v, fmt) + "}") if v == mx
                else format(v, fmt) for v in vals]

    out = []
    out.append("% ============================================================")
    out.append("% Category Breakdown Tables — AgentAIBench")
    out.append("% Generated by evaluation_analysis.py — SUPREME Lab, UTEP")
    out.append("% ============================================================")
    out.append("")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE A — Method comparison per category (Malicious/Suspicious/Benign)
    # ══════════════════════════════════════════════════════════════════════
    #
    # Mapping:
    #   CVSS    severity  : CRITICAL/HIGH→Malicious, MEDIUM→Suspicious, LOW/NONE→Benign
    #   SARS    severity  : same
    #   OpenClaw verdict  : passthrough (already Malicious/Suspicious/Benign)
    #   VT verdict        : passthrough

    out += [
        "% ─── Table A: Method Comparison by Vulnerability Category ──────────",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Method verdict comparison by top vulnerability category. "
        "CVSS and SARS severity bands are mapped to a three-tier verdict scale: "
        "Critical/High\\,$\\rightarrow$\\,Malicious, "
        "Medium\\,$\\rightarrow$\\,Suspicious, "
        "Low/None\\,$\\rightarrow$\\,Benign. "
        "Values show number of skills. Bold values highlight the dominant verdict per method and category.}",
        "\\label{tab:cat_method_comparison}",
        "\\renewcommand{\\arraystretch}{1.3}",
        "\\setlength{\\tabcolsep}{4pt}",
        "\\begin{tabularx}{\\linewidth}{@{} L{2.8cm} r "
        "X X X "     # CVSS
        "X X X "     # SARS
        "X X X "     # OpenClaw
        "X X X "     # VT
        "@{}}",
        "\\toprule",
        "& & \\multicolumn{3}{c}{\\textbf{CVSS v4.0}} "
        "& \\multicolumn{3}{c}{\\textbf{SARS}} "
        "& \\multicolumn{3}{c}{\\textbf{OpenClaw}} "
        "& \\multicolumn{3}{c}{\\textbf{VirusTotal}} \\\\",
        "\\cmidrule(lr){3-5}\\cmidrule(lr){6-8}"
        "\\cmidrule(lr){9-11}\\cmidrule(lr){12-14}",
        "\\textbf{Category} & \\textbf{n} "
        "& \\textbf{Mal.} & \\textbf{Sus.} & \\textbf{Ben.} "
        "& \\textbf{Mal.} & \\textbf{Sus.} & \\textbf{Ben.} "
        "& \\textbf{Mal.} & \\textbf{Sus.} & \\textbf{Ben.} "
        "& \\textbf{Mal.} & \\textbf{Sus.} & \\textbf{Ben.} \\\\",
        "\\midrule",
    ]

    def _method_counts(cat_list, sev_key, verdict_fn):
        counts = Counter(_to_verdict(verdict_fn(r)) for r in cat_list)
        return [counts.get(v, 0) for v in VERDICTS]

    total_all = {v: 0 for v in VERDICTS}

    for idx, cat in enumerate(cats):
        cr = cat_rows[cat]
        n  = len(cr)
        gray = (idx % 2 == 1)

        cvss_counts = _method_counts(cr, "cvss_severity",
                                     lambda r: r.get("cvss_severity",""))
        sars_counts = _method_counts(cr, "sars_severity",
                                     lambda r: r.get("sars_severity",""))
        oc_counts   = _method_counts(cr, "openclaw_verdict",
                                     lambda r: normalise_verdict(r.get("openclaw_verdict","")))
        vt_counts   = _method_counts(cr, "vt_verdict",
                                     lambda r: normalise_verdict(r.get("vt_verdict","")))

        short = cat.replace("Credential / Secret Exposure", "Credential Exposure") \
                   .replace("Dependency / Supply Chain", "Dep./Supply Chain") \
                   .replace("Indirect / Embedded Injection", "Indirect Injection") \
                   .replace(" / ", "/")
        short = short[:30]

        def _bold_group(counts):
            """Bold the maximum value in a group of 3 (Mal/Sus/Ben)."""
            mx = max(counts)
            return [("\\textbf{" + str(v) + "}") if v == mx and mx > 0
                    else str(v) for v in counts]

        cells = [short, str(n)]
        cells += _bold_group(cvss_counts)
        cells += _bold_group(sars_counts)
        cells += _bold_group(oc_counts)
        cells += _bold_group(vt_counts)

        prefix = "\\rowcolor{RowGray}\n" if gray else ""
        out.append(prefix + " & ".join(cells) + " \\\\")

    # Total row
    all_cvss = _method_counts(rows, "cvss_severity",
                              lambda r: r.get("cvss_severity",""))
    all_sars = _method_counts(rows, "sars_severity",
                              lambda r: r.get("sars_severity",""))
    all_oc   = _method_counts(rows, "openclaw_verdict",
                              lambda r: normalise_verdict(r.get("openclaw_verdict","")))
    all_vt   = _method_counts(rows, "vt_verdict",
                              lambda r: normalise_verdict(r.get("vt_verdict","")))

    total_cells = [f"\\textit{{Total (all {len(rows)})}}", str(len(rows))]
    total_cells += [str(v) for v in all_cvss]
    total_cells += [str(v) for v in all_sars]
    total_cells += [str(v) for v in all_oc]
    total_cells += [str(v) for v in all_vt]

    out += [
        "\\midrule",
        " & ".join(total_cells) + " \\\\",
        "\\bottomrule",
        "\\end{tabularx}",
        "\\end{table}",
        "",
    ]
    
    # ══════════════════════════════════════════════════════════════════════
    # TABLE B — SARS dimension means per category with band counts + CVSS mean
    # ══════════════════════════════════════════════════════════════════════

    out += [
        "% ─── Table B: SARS Metrics by Vulnerability Category ──────────────",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Mean SARS dimension scores (0--3) and mean CVSS base score "
        "per vulnerability category. "
        "The final four columns show the number of skills rated at each SARS "
        "severity level. Bold values indicate the highest dimension mean in each "
        "column. IFR\\,=\\,Instruction Fidelity Risk, DG\\,=\\,Data Gravity, "
        "AI\\,=\\,Action Irreversibility, BR\\,=\\,Blast Radius, "
        "CA\\,=\\,Chain Amplification.}",
        "\\label{tab:cat_sars_dims}",
        "\\renewcommand{\\arraystretch}{1.25}",
        "\\begin{tabularx}{\\linewidth}{@{} L{3.2cm} r C{0.8cm} "  # Cat | n | CVSS
        "C{0.8cm} C{0.8cm} C{0.8cm} C{0.8cm} C{0.8cm} "           # 5 SARS dims
        "X X X X "                                                   # CRIT HIGH MED LOW
        "@{}}",
        "\\toprule",
        "& & & \\multicolumn{5}{c}{\\textbf{Mean SARS Dimension (0--3)}} "
        "& \\multicolumn{4}{c}{\\textbf{SARS Severity Count}} \\\\",
        "\\cmidrule(lr){4-8}\\cmidrule(lr){9-12}",
        "\\textbf{Category} & \\textbf{n} & \\textbf{CVSS} "
        "& \\textbf{IFR} & \\textbf{DG} & \\textbf{AI} "
        "& \\textbf{BR} & \\textbf{CA} "
        "& \\textbf{CRIT.} & \\textbf{HIGH} & \\textbf{MED.} & \\textbf{LOW} \\\\",
        "\\midrule",
    ]

    # Collect column values for bold-max computation
    col_means = {d: [] for d in DIMS}
    cvss_col_vals = []  # for bold-max on CVSS column

    cat_data = []   # (cat, n, means_dict, cvss_mean, band_counts)
    for cat in cats:
        cr = cat_rows[cat]
        n  = len(cr)
        means = {
            d: round(float(np.mean([float(r.get(d, 0)) for r in cr])), 2)
            for d in DIMS
        }
        cvss_mean = round(
            float(np.mean([float(r.get("cvss_base_score", 0)) for r in cr])), 2
        )
        band_counts = {
            b: sum(1 for r in cr if str(r.get("sars_severity", "")).upper() == b)
            for b in SARS_BANDS
        }
        cat_data.append((cat, n, means, cvss_mean, band_counts))
        for d in DIMS:
            col_means[d].append(means[d])
        cvss_col_vals.append(cvss_mean)

    # Compute bold-max per SARS dimension column
    col_bolds = {}
    for d in DIMS:
        vals = col_means[d]
        mx   = max(vals) if vals else None
        col_bolds[d] = [
            ("\\textbf{" + f"{v:.2f}" + "}") if v == mx else f"{v:.2f}"
            for v in vals
        ]

    # Compute bold-max for CVSS column
    cvss_mx = max(cvss_col_vals) if cvss_col_vals else None
    cvss_bolds = [
        ("\\textbf{" + f"{v:.2f}" + "}") if v == cvss_mx else f"{v:.2f}"
        for v in cvss_col_vals
    ]

    for idx, (cat, n, means, cvss_mean, band_counts) in enumerate(cat_data):
        gray = (idx % 2 == 1)
        short = (
            cat.replace("Credential / Secret Exposure", "Credential Exposure")
               .replace("Dependency / Supply Chain", "Dep./Supply Chain")
               .replace("Indirect / Embedded Injection", "Indirect Injection")
               .replace(" / ", "/")
        )
        short = short[:30]

        cells  = [short, str(n)]
        cells += [cvss_bolds[idx]]                          # CVSS mean
        cells += [col_bolds[d][idx] for d in DIMS]          # SARS dims
        cells += [str(band_counts.get(b, 0)) for b in SARS_BANDS]  # severity counts

        prefix = "\\rowcolor{RowGray}\n" if gray else ""
        out.append(prefix + " & ".join(cells) + " \\\\")

    # Overall mean row
    all_means    = {
        d: round(float(np.mean([float(r.get(d, 0)) for r in rows])), 2)
        for d in DIMS
    }
    all_cvss_mean = round(
        float(np.mean([float(r.get("cvss_base_score", 0)) for r in rows])), 2
    )
    all_band = {
        b: sum(1 for r in rows if str(r.get("sars_severity", "")).upper() == b)
        for b in SARS_BANDS
    }

    total_b  = ["\\textit{Overall mean}", str(len(rows))]
    total_b += [f"{all_cvss_mean:.2f}"]                     # CVSS mean
    total_b += [f"{all_means[d]:.2f}" for d in DIMS]        # SARS dims
    total_b += [str(all_band.get(b, 0)) for b in SARS_BANDS]

    out += [
        "\\midrule",
        " & ".join(total_b) + " \\\\",
        "\\bottomrule",
        "\\end{tabularx}",
        "\\end{table}",
        "",
    ]

    out_path = out_dir / "evaluation_category_tables.tex"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"  Saved: {out_path}  ({len(out)} lines, {len(cats)} categories)")



# ─────────────────────────────────────────────────────────────────────────────
# Summary statistics (printed to console + saved as JSON)
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(rows: list, out_dir: Path):
    """Print and save a summary statistics report."""

    n = len(rows)
    if n == 0:
        print("No data to summarise.")
        return

    cvss_scores = [float(r.get("cvss_base_score",0)) for r in rows]
    sars_scores = [float(r.get("sars_score",0))      for r in rows]
    deltas      = [s - c for c, s in zip(cvss_scores, sars_scores)]

    oc_verdicts = [normalise_verdict(r.get("openclaw_verdict","")) for r in rows]
    vt_verdicts = [normalise_verdict(r.get("vt_verdict",""))       for r in rows]

    # SARS dimension means
    dim_means = {
        d: float(np.mean([float(r.get(d,0)) for r in rows]))
        for d in ("sars_ifr","sars_dg","sars_ai","sars_br","sars_ca")
    }

    # Agreement: SARS HIGH/CRITICAL where VT says Benign
    vt_benign_sars_high = sum(
        1 for r in rows
        if normalise_verdict(r.get("vt_verdict","")) == "Benign"
        and str(r.get("sars_severity","")).upper() in ("HIGH","CRITICAL")
    )

    summary = {
        "total_skills": n,
        "cvss": {
            "mean":   round(float(np.mean(cvss_scores)), 3),
            "median": round(float(np.median(cvss_scores)), 3),
            "std":    round(float(np.std(cvss_scores)), 3),
            "distribution": {s: count(rows,"cvss_severity",s) for s in SEVERITY_ORDER},
        },
        "sars": {
            "mean":   round(float(np.mean(sars_scores)), 3),
            "median": round(float(np.median(sars_scores)), 3),
            "std":    round(float(np.std(sars_scores)), 3),
            "distribution": {s: count(rows,"sars_severity",s) for s in SEVERITY_ORDER},
            "dimension_means": {k: round(v,3) for k,v in dim_means.items()},
        },
        "delta_sars_minus_cvss": {
            "mean":   round(float(np.mean(deltas)), 3),
            "median": round(float(np.median(deltas)), 3),
            "pct_sars_higher": round(sum(1 for d in deltas if d > 0)/n*100, 1),
            "pct_cvss_higher": round(sum(1 for d in deltas if d < 0)/n*100, 1),
            "pct_equal":       round(sum(1 for d in deltas if d == 0)/n*100, 1),
        },
        "openclaw": {
            "distribution": {v: oc_verdicts.count(v) for v in VERDICT_ORDER+["Unknown"]},
            "coverage_pct": round(sum(1 for v in oc_verdicts if v != "Unknown")/n*100, 1),
        },
        "virustotal": {
            "distribution": {v: vt_verdicts.count(v) for v in VERDICT_ORDER+["Unknown"]},
            "coverage_pct": round(sum(1 for v in vt_verdicts if v != "Unknown")/n*100, 1),
        },
        "key_finding": {
            "vt_benign_but_sars_high_critical": vt_benign_sars_high,
            "pct": round(vt_benign_sars_high/n*100, 1) if n else 0,
        },
    }

    print("\n" + "═"*60)
    print("  EVALUATION COMPARISON SUMMARY")
    print("═"*60)
    print(f"  Total skills analysed : {n}")
    print(f"\n  CVSS v4.0")
    print(f"    Mean score  : {summary['cvss']['mean']:.2f}")
    print(f"    Distribution: {summary['cvss']['distribution']}")
    print(f"\n  SARS")
    print(f"    Mean score  : {summary['sars']['mean']:.2f}")
    print(f"    Distribution: {summary['sars']['distribution']}")
    print(f"\n  SARS − CVSS delta")
    print(f"    Mean delta  : {summary['delta_sars_minus_cvss']['mean']:+.2f}")
    print(f"    SARS higher : {summary['delta_sars_minus_cvss']['pct_sars_higher']:.0f}% of skills")
    print(f"    CVSS higher : {summary['delta_sars_minus_cvss']['pct_cvss_higher']:.0f}% of skills")
    print(f"\n  OpenClaw (coverage: {summary['openclaw']['coverage_pct']:.0f}%)")
    print(f"    {summary['openclaw']['distribution']}")
    print(f"\n  VirusTotal (coverage: {summary['virustotal']['coverage_pct']:.0f}%)")
    print(f"    {summary['virustotal']['distribution']}")
    print(f"\n  Key finding")
    print(f"    VT=Benign but SARS=HIGH/CRITICAL: "
          f"{vt_benign_sars_high} skills ({summary['key_finding']['pct']:.0f}%)")
    print("═"*60 + "\n")

    out = out_dir / "evaluation_summary.json"
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"  Summary saved: {out}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# LaTeX table generation
# ─────────────────────────────────────────────────────────────────────────────

def _tex_bold(val: str) -> str:
    return f"\\textbf{{{val}}}"


def _tex_rowcolor(i: int) -> str:
    return "\\rowcolor{RowGray}\n" if i % 2 == 1 else ""


def _fmt(v, decimals=2) -> str:
    try:
        return f"{float(v):.{decimals}f}"
    except (TypeError, ValueError):
        return str(v)


def generate_latex_tables(rows: list, out_dir: Path) -> None:
    """
    Generate all LaTeX comparison tables and write them to
    out_dir/latex_tables.tex (one file, input-able from any paper).

    Tables:
      Tab 1 — Risk distribution across all four methods
      Tab 2 — SARS dimension scores by overall risk band
      Tab 3 — OpenClaw 5-category pass/warn/fail counts
      Tab 4 — Method pairwise agreement matrix
      Tab 5 — CVSS vs SARS severity confusion matrix
      Tab 6 — Top-15 skills comparison (all four methods)
      Tab 7 — VT-Benign but SARS HIGH/CRITICAL (divergent cases)
    """

    lines = []

    def L(s=""):
        lines.append(s)

    def section(title: str):
        L()
        L(f"% {'─'*60}")
        L(f"% {title}")
        L(f"% {'─'*60}")
        L()

    # ── Preamble comment ──────────────────────────────────────────────────
    L("% ============================================================")
    L("% Evaluation Comparison Tables — AgentAIBench")
    L("% Auto-generated by evaluation_analysis.py")
    L("% ============================================================")
    L("%")
    L("% Required in define.tex / preamble:")
    L("%   \\usepackage{booktabs}")
    L("%   \\usepackage{tabularx}")
    L("%   \\usepackage{multirow}")
    L("%   \\usepackage{xcolor}")
    L("%   \\usepackage{colortbl}")
    L("%   \\usepackage{array}")
    L("%   \\newcolumntype{L}[1]{>{\\raggedright\\arraybackslash}p{#1}}")
    L("%   \\newcolumntype{C}[1]{>{\\centering\\arraybackslash}p{#1}}")
    L("%   \\definecolor{RowGray}{HTML}{F1F5F9}")
    L()

    n = len(rows)

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 1 — Risk distribution across all four methods
    # ══════════════════════════════════════════════════════════════════════
    section("Table 1 — Risk Distribution")

    SEVERITY_ORDER_TEX = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    VERDICT_ORDER_TEX  = ["Malicious", "Suspicious", "Benign", "Unknown"]

    cvss_dist = {s: count(rows, "cvss_severity", s) for s in SEVERITY_ORDER_TEX}
    sars_dist = {s: count(rows, "sars_severity", s) for s in SEVERITY_ORDER_TEX}
    oc_dist   = {v: sum(1 for r in rows if normalise_verdict(r.get("openclaw_verdict","")) == v)
                 for v in VERDICT_ORDER_TEX}
    vt_dist   = {v: sum(1 for r in rows if normalise_verdict(r.get("vt_verdict","")) == v)
                 for v in VERDICT_ORDER_TEX}

    L("\\begin{table}[htbp]")
    L("\\centering")
    L("\\caption{Risk and verdict distribution across all four evaluation frameworks.")
    L(f"  Total skills evaluated: $N={n}$. Values show number of skills per band.")
    L("  CVSS and SARS use a five-point severity scale; OpenClaw and VirusTotal")
    L("  use a three-point verdict scale.}")
    L("\\label{tab:risk_distribution}")
    L("\\renewcommand{\\arraystretch}{1.3}")
    L("\\begin{tabular}{@{} L{2.8cm} C{1.1cm} C{1.1cm} C{1.1cm} C{1.1cm} C{1.1cm} @{}}")
    L("\\toprule")
    L("\\textbf{Level / Verdict}")
    L("    & \\textbf{CVSS} & \\textbf{SARS}")
    L("    & \\textbf{Open-\\\\Claw} & \\textbf{Virus-\\\\Total} & \\textbf{\\%} \\\\")
    L("\\midrule")

    all_bands = list(dict.fromkeys(SEVERITY_ORDER_TEX + VERDICT_ORDER_TEX))
    printed = set()
    for i, band in enumerate(all_bands):
        if band in printed:
            continue
        printed.add(band)
        cv  = cvss_dist.get(band, "—")
        sa  = sars_dist.get(band, "—")
        oc  = oc_dist.get(band, "—")
        vt  = vt_dist.get(band, "—")
        # representative % (use SARS if numeric, else OC)
        num = sa if isinstance(sa, int) else oc
        pct = f"{int(num)/n*100:.0f}" if isinstance(num, int) and n else "—"

        row_color = _tex_rowcolor(i)
        cv_str  = str(cv)  if isinstance(cv,  int) else "—"
        sa_str  = str(sa)  if isinstance(sa,  int) else "—"
        oc_str  = str(oc)  if isinstance(oc,  int) else "—"
        vt_str  = str(vt)  if isinstance(vt,  int) else "—"

        L(f"{row_color}{band:<14} & {cv_str:>5} & {sa_str:>5} & {oc_str:>5} & {vt_str:>5} & {pct:>4} \\\\")

    L("\\midrule")
    L(f"\\textit{{Total}} & {n} & {n} & {n} & {n} & 100 \\\\")
    L("\\bottomrule")
    L("\\end{tabular}")
    L("\\end{table}")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 2 — SARS dimension scores by overall risk band
    # ══════════════════════════════════════════════════════════════════════
    section("Table 2 — SARS Dimension Scores by Risk Band")

    dims     = ["sars_ifr", "sars_dg", "sars_ai", "sars_br", "sars_ca"]
    dim_hdr  = ["IFR", "DG", "AI", "BR", "CA"]
    bands_present = [b for b in SEVERITY_ORDER_TEX
                     if any(str(r.get("overall_risk","")).upper() == b for r in rows)]

    # Compute means
    band_means = {}
    for band in bands_present:
        br = [r for r in rows if str(r.get("overall_risk","")).upper() == band]
        band_means[band] = [float(np.mean([float(r.get(d,0)) for r in br])) for d in dims]
        band_means[band].append(float(np.mean([float(r.get("sars_score",0)) for r in br])))

    # Column maximums (for bold)
    all_vals = [band_means[b] for b in bands_present]
    col_max  = [max(row[c] for row in all_vals) for c in range(len(dims)+1)] if all_vals else [0]*(len(dims)+1)
    # Overall means
    overall  = [float(np.mean([float(r.get(d,0)) for r in rows])) for d in dims]
    overall.append(float(np.mean([float(r.get("sars_score",0)) for r in rows])))

    L("\\begin{table}[htbp]")
    L("\\centering")
    L("\\caption{Mean SARS dimension score (0--3) and composite SARS score (0--10)")
    L("  by overall risk band. Bold values indicate the highest score in each column.}")
    L("\\label{tab:sars_dims}")
    L("\\renewcommand{\\arraystretch}{1.3}")
    L("\\begin{tabular}{@{} L{2.8cm} C{1.0cm} C{1.0cm} C{1.0cm} C{1.0cm} C{1.0cm} C{1.2cm} C{1.0cm} @{}}")
    L("\\toprule")
    L("\\textbf{Risk Band}")
    hdr_cols = " & ".join([f"\\textbf{{{h}}}" for h in dim_hdr])
    L(f"    & {hdr_cols} & \\textbf{{SARS}} & $n$ \\\\")
    L("\\midrule")

    for i, band in enumerate(bands_present):
        vals = band_means[band]
        n_band = sum(1 for r in rows if str(r.get("overall_risk","")).upper() == band)
        cells = []
        for ci, v in enumerate(vals):
            s = f"{v:.2f}"
            if abs(v - col_max[ci]) < 0.001:
                s = _tex_bold(s)
            cells.append(s)
        row_color = _tex_rowcolor(i)
        L(f"{row_color}{band:<12} & {' & '.join(cells)} & {n_band} \\\\")

    L("\\midrule")
    ov_cells = []
    for ci, v in enumerate(overall):
        ov_cells.append(f"{v:.2f}")
    L(f"\\textit{{Overall}} & {' & '.join(ov_cells)} & {n} \\\\")
    L("\\bottomrule")
    L("\\end{tabular}")
    L("\\end{table}")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 3 — OpenClaw 5-category pass/warn/fail
    # ══════════════════════════════════════════════════════════════════════
    section("Table 3 — OpenClaw Safety Category Results")

    has_oc = any(r.get("openclaw_verdict") for r in rows)

    L("\\begin{table}[htbp]")
    L("\\centering")
    L("\\caption{OpenClaw safety evaluation results across the five categories.")
    L("  Values show number of skills per status. Pass~(\\checkmark) indicates no concern;")
    L("  Warn~($\\sim$) indicates minor concern; Fail~($\\times$) indicates a significant issue.}")
    L("\\label{tab:openclaw_cats}")
    L("\\renewcommand{\\arraystretch}{1.3}")
    L("\\begin{tabular}{@{} L{3.6cm} C{1.2cm} C{1.2cm} C{1.2cm} C{1.3cm} @{}}")
    L("\\toprule")
    L("\\textbf{Category}")
    L("    & \\textbf{Pass} & \\textbf{Warn} & \\textbf{Fail} & \\textbf{No data} \\\\")
    L("\\midrule")

    oc_dim_labels = [
        ("purpose_capability",    "Purpose \\& Capability"),
        ("instruction_scope",     "Instruction Scope"),
        ("install_mechanism",     "Install Mechanism"),
        ("credentials",           "Credentials"),
        ("persistence_privilege", "Persistence \\& Privilege"),
    ]
    for i, (dk, label) in enumerate(oc_dim_labels):
        key = f"oc_{dk}"
        pass_n = count(rows, key, "pass")
        warn_n = count(rows, key, "warn")
        fail_n = count(rows, key, "fail")
        none_n = n - pass_n - warn_n - fail_n
        row_color = _tex_rowcolor(i)
        # Bold the worst (fail if >0, else warn)
        fail_s = _tex_bold(str(fail_n)) if fail_n > 0 else str(fail_n)
        warn_s = _tex_bold(str(warn_n)) if warn_n > 0 and fail_n == 0 else str(warn_n)
        L(f"{row_color}{label} & {pass_n} & {warn_s} & {fail_s} & {none_n} \\\\")

    L("\\midrule")
    total_pass = sum(count(rows, f"oc_{dk}", "pass") for dk, _ in oc_dim_labels)
    total_warn = sum(count(rows, f"oc_{dk}", "warn") for dk, _ in oc_dim_labels)
    total_fail = sum(count(rows, f"oc_{dk}", "fail") for dk, _ in oc_dim_labels)
    total_none = 5*n - total_pass - total_warn - total_fail
    L(f"\\textit{{Total (all categories)}} & {total_pass} & {total_warn} & {total_fail} & {total_none} \\\\")
    L("\\bottomrule")
    L("\\end{tabular}")
    L("\\end{table}")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 4 — Method agreement matrix
    # ══════════════════════════════════════════════════════════════════════
    section("Table 4 — Method Pairwise Agreement Matrix")

    methods = ["CVSS", "SARS", "OpenClaw", "VirusTotal"]

    def tier(r, method):
        if method == "CVSS":
            s = str(r.get("cvss_severity","")).upper()
            return {"CRITICAL":"H","HIGH":"H","MEDIUM":"M","LOW":"L","NONE":"L"}.get(s,"?")
        if method == "SARS":
            s = str(r.get("sars_severity","")).upper()
            return {"CRITICAL":"H","HIGH":"H","MEDIUM":"M","LOW":"L","NONE":"L"}.get(s,"?")
        if method == "OpenClaw":
            v = normalise_verdict(r.get("openclaw_verdict",""))
            return {"Malicious":"H","Suspicious":"M","Benign":"L"}.get(v,"?")
        if method == "VirusTotal":
            v = normalise_verdict(r.get("vt_verdict",""))
            return {"Malicious":"H","Suspicious":"M","Benign":"L"}.get(v,"?")
        return "?"

    L("\\begin{table}[htbp]")
    L("\\centering")
    L("\\caption{Pairwise method agreement matrix. Each cell shows the percentage of skills")
    L("  where both methods assign the same risk tier (Low~$\\leq$~Medium~$\\leq$~High).")
    L("  Diagonal entries are 100\\% by definition. Bold values indicate strong agreement ($>$70\\%).}")
    L("\\label{tab:agreement}")
    L("\\renewcommand{\\arraystretch}{1.3}")
    L("\\begin{tabular}{@{} L{2.4cm} C{1.5cm} C{1.5cm} C{1.8cm} C{1.8cm} @{}}")
    L("\\toprule")
    L("\\textbf{Method A} & \\textbf{CVSS} & \\textbf{SARS} & \\textbf{OpenClaw} & \\textbf{VirusTotal} \\\\")
    L("\\midrule")

    for i, m1 in enumerate(methods):
        cells = []
        for m2 in methods:
            if m1 == m2:
                cells.append("100.0")
                continue
            agree = total_c = 0
            for r in rows:
                t1, t2 = tier(r, m1), tier(r, m2)
                if t1 != "?" and t2 != "?":
                    total_c += 1
                    if t1 == t2:
                        agree += 1
            pct = agree/total_c*100 if total_c else 0
            s = f"{pct:.1f}"
            if pct >= 70:
                s = _tex_bold(s)
            cells.append(s)
        row_color = _tex_rowcolor(i)
        L(f"{row_color}{m1} & {' & '.join(cells)} \\\\")

    L("\\bottomrule")
    L("\\end{tabular}")
    L("\\end{table}")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 5 — CVSS vs SARS confusion matrix
    # ══════════════════════════════════════════════════════════════════════
    section("Table 5 — CVSS vs SARS Severity Confusion Matrix")

    bands5 = [b for b in SEVERITY_ORDER_TEX
              if any(str(r.get("cvss_severity","")).upper() == b or
                     str(r.get("sars_severity","")).upper() == b for r in rows)]

    mat5 = {b1: {b2: 0 for b2 in bands5} for b1 in bands5}
    for r in rows:
        cs = str(r.get("cvss_severity","")).upper()
        ss = str(r.get("sars_severity","")).upper()
        if cs in mat5 and ss in mat5:
            mat5[cs][ss] += 1

    agree_n  = sum(mat5[b][b] for b in bands5 if b in mat5)
    total5   = sum(mat5[b1][b2] for b1 in bands5 for b2 in bands5)
    agree_pct= agree_n/total5*100 if total5 else 0

    col_spec = "C{1.3cm}" * len(bands5)
    L("\\begin{table}[htbp]")
    L("\\centering")
    L("\\caption{CVSS v4.0 severity (rows) vs SARS severity (columns) confusion matrix.")
    L(f"  Diagonal entries (bold) show agreement; off-diagonal entries show divergence.")
    L(f"  Overall agreement: {agree_n}/{total5} ({agree_pct:.0f}\\%).}}")
    L("\\label{tab:confusion}")
    L("\\renewcommand{\\arraystretch}{1.3}")
    L(f"\\begin{{tabular}}{{@{{}} L{{2.6cm}} {col_spec} C{{1.0cm}} @{{}}}}")
    L("\\toprule")
    hdr5 = " & ".join([f"\\textbf{{{b[:4]}}}" for b in bands5])
    L(f"\\textbf{{CVSS $\\backslash$ SARS}} & {hdr5} & \\textbf{{Total}} \\\\")
    L("\\midrule")

    for i, b1 in enumerate(bands5):
        cells5 = []
        row_total = sum(mat5[b1][b2] for b2 in bands5)
        for b2 in bands5:
            v = mat5[b1][b2]
            s = _tex_bold(str(v)) if b1 == b2 else str(v)
            cells5.append(s)
        row_color = _tex_rowcolor(i)
        L(f"{row_color}{b1} & {' & '.join(cells5)} & {row_total} \\\\")

    L("\\midrule")
    col_tots = [sum(mat5[b1][b2] for b1 in bands5) for b2 in bands5]
    L(f"\\textit{{Total}} & {' & '.join(map(str, col_tots))} & {total5} \\\\")
    L("\\bottomrule")
    L("\\end{tabular}")
    L("\\end{table}")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 6 — Top-15 skills all four methods
    # ══════════════════════════════════════════════════════════════════════
    section("Table 6 — Top-15 Highest-Risk Skills (All Four Methods)")

    sorted_rows = sorted(rows, key=lambda r: float(r.get("sars_score",0)), reverse=True)
    top15 = sorted_rows[:15]

    L("\\begin{table}[htbp]")
    L("\\centering")
    L("\\caption{Top-15 highest-risk skills ranked by SARS score.")
    L("  $\\Delta = \\text{SARS} - \\text{CVSS}$; positive values indicate risk")
    L("  underreported by CVSS alone.}")
    L("\\label{tab:top15}")
    L("\\renewcommand{\\arraystretch}{1.25}")
    L("\\begin{tabularx}{\\linewidth}{@{} r L{3.0cm} C{1.0cm} C{1.0cm} C{0.8cm} L{1.8cm} L{2.2cm} @{}}")
    L("\\toprule")
    L("\\textbf{\\#} & \\textbf{Skill}")
    L("    & \\textbf{SARS} & \\textbf{CVSS} & \\textbf{$\\Delta$}")
    L("    & \\textbf{OpenClaw} & \\textbf{VirusTotal} \\\\")
    L("\\midrule")

    for i, r in enumerate(top15):
        sars_s = float(r.get("sars_score",0))
        cvss_s = float(r.get("cvss_base_score",0))
        delta  = sars_s - cvss_s
        name   = str(r.get("skill_name",""))[:28]
        oc_v   = normalise_verdict(r.get("openclaw_verdict",""))
        vt_v   = normalise_verdict(r.get("vt_verdict",""))
        sars_bold = _tex_bold(f"{sars_s:.1f}") if i == 0 else f"{sars_s:.1f}"
        delta_s = f"{delta:+.1f}"
        row_color = _tex_rowcolor(i)
        L(f"{row_color}{i+1} & {name} & {sars_bold} & {cvss_s:.1f} & {delta_s} & {oc_v} & {vt_v} \\\\")

    L("\\midrule")
    mean_sars = float(np.mean([float(r.get("sars_score",0)) for r in top15]))
    mean_cvss = float(np.mean([float(r.get("cvss_base_score",0)) for r in top15]))
    mean_d    = mean_sars - mean_cvss
    L(f"\\multicolumn{{2}}{{@{{}}l}}{{\\textit{{Mean (top-15)}}}} & {mean_sars:.1f} & {mean_cvss:.1f} & {mean_d:+.1f} & & \\\\")
    all_sars = float(np.mean([float(r.get("sars_score",0)) for r in rows]))
    all_cvss = float(np.mean([float(r.get("cvss_base_score",0)) for r in rows]))
    L(f"\\multicolumn{{2}}{{@{{}}l}}{{\\textit{{Mean (all {n} skills)}}}} & {all_sars:.1f} & {all_cvss:.1f} & {all_sars-all_cvss:+.1f} & & \\\\")
    L("\\bottomrule")
    L("\\end{tabularx}")
    L("\\end{table}")

    # ══════════════════════════════════════════════════════════════════════
    # TABLE 7 — Divergent cases: VT=Benign but SARS=HIGH/CRITICAL
    # ══════════════════════════════════════════════════════════════════════
    section("Table 7 — Divergent Cases: VirusTotal Benign but SARS HIGH/CRITICAL")

    divergent = [
        r for r in rows
        if normalise_verdict(r.get("vt_verdict","")) == "Benign"
        and str(r.get("sars_severity","")).upper() in ("HIGH","CRITICAL")
    ]
    divergent.sort(key=lambda r: float(r.get("sars_score",0)), reverse=True)
    show_div  = divergent[:12]

    L("\\begin{table}[htbp]")
    L("\\centering")
    L("\\caption{Skills where VirusTotal reports \\textit{Benign} but SARS assigns")
    L("  \\textit{High} or \\textit{Critical} severity. These represent agentic-specific")
    L(f"  risks invisible to static file scanning. Total: {len(divergent)} skills.}}")
    L("\\label{tab:divergent}")
    L("\\renewcommand{\\arraystretch}{1.25}")
    L("\\begin{tabularx}{\\linewidth}{@{} r L{3.2cm} C{1.0cm} C{1.5cm} L{2.0cm} X @{}}")
    L("\\toprule")
    L("\\textbf{\\#} & \\textbf{Skill} & \\textbf{SARS} & \\textbf{SARS Sev.}")
    L("    & \\textbf{CVSS Sev.} & \\textbf{Top Vulnerability} \\\\")
    L("\\midrule")

    if show_div:
        for i, r in enumerate(show_div):
            name   = str(r.get("skill_name",""))[:30]
            sars_s = float(r.get("sars_score",0))
            sars_v = str(r.get("sars_severity","")).upper()
            cvss_v = str(r.get("cvss_severity","")).upper()
            top_cat= str(r.get("top_finding_category","—"))[:35]
            row_color = _tex_rowcolor(i)
            L(f"{row_color}{i+1} & {name} & {sars_s:.1f} & {sars_v} & {cvss_v} & {top_cat} \\\\")
    else:
        L("\\multicolumn{6}{c}{\\textit{No divergent cases identified.}} \\\\")

    L("\\bottomrule")
    L("\\end{tabularx}")
    L("\\end{table}")

    # ── Write all tables to file ──────────────────────────────────────────
    out_path = out_dir / "latex_tables.tex"
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  Saved: {out_path}  ({len(lines)} lines, 7 tables)")



def main():
    parser = argparse.ArgumentParser(
        description="Evaluation baseline comparison — CVSS, SARS, OpenClaw, VirusTotal"
    )
    parser.add_argument("--csv",      default="data/leaderboard.csv",
                        help="Path to the leaderboard CSV (default: data/leaderboard.csv)")
    parser.add_argument("--enriched", default="data/clawhub_enriched.json",
                        help="Path to clawhub_enriched.json (default: data/clawhub_enriched.json)")
    parser.add_argument("--out",      default="results",
                        help="Output directory for plots (default: results/)")
    parser.add_argument("--no-show",  action="store_true",
                        help="Save figures but do not display them")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    show = not args.no_show

    print(f"\nLoading data ...")
    print(f"  CSV      : {args.csv}")
    print(f"  Enriched : {args.enriched}")

    rows     = load_csv(args.csv)
    enriched = load_enriched(args.enriched)
    merged   = merge(rows, enriched)

    print(f"  Loaded   : {len(merged)} skill evaluations\n")

    if not merged:
        print("ERROR: No data loaded. Check --csv and --enriched paths.")
        sys.exit(1)

    print_summary(merged, out_dir)
    print("Generating LaTeX tables ...")
    generate_latex_tables(merged, out_dir)
    print("Generating category tables ...")
    generate_category_tables(merged, out_dir)

    print("Generating figures ...")
    fig_risk_distribution(merged, out_dir, show)
    fig_scatter(merged, out_dir, show)
    fig_sars_heatmap(merged, out_dir, show)
    fig_openclaw_dimensions(merged, out_dir, show)
    fig_agreement_matrix(merged, out_dir, show)
    fig_cvss_sars_confusion(merged, out_dir, show)
    fig_vt_vs_sars(merged, out_dir, show)
    fig_top20_table(merged, out_dir, show)
    fig_radar(merged, out_dir, show)

    print(f"\nAll outputs saved to: {out_dir.resolve()}")


if __name__ == "__main__":
    main()