"""
AgentSkillBench — Results Figure Generator
===========================================
Generates all tables and figures for the §Results section of the paper.

Usage
-----
  # Single model directory (all *.json files inside)
  python generate_results.py --input /reports/Qwen_Qwen2.5-32B-Instruct/

  # Multiple model directories combined
  python generate_results.py --input /path/to/reports/ModelA/ /path/to/reports/ModelB/

  # Specific files
  python generate_results.py --input /path/to/reports/Qwen_Qwen2.5-32B-Instruct/*.json

  # Custom output directory
  python generate_results.py --input /path/to/reports/Qwen_Qwen2.5-32B-Instruct/ --output ./figures/

Requirements
------------
  pip install matplotlib seaborn numpy
"""

import argparse
import glob
import json
import os
import sys
import warnings
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.gridspec as gridspec
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

warnings.filterwarnings('ignore')

# ── Colour palette ────────────────────────────────────────────────────────────
PALETTE = {
    'LOW':        '#2ecc71',
    'MEDIUM':     '#f39c12',
    'HIGH':       '#e74c3c',
    'Safe':       '#2ecc71',
    'Suspicious': '#f39c12',
    'Malicious':  '#e74c3c',
    'accent':     '#2c3e50',
    'bg':         '#fafafa',
}

# ── Canonical attack category mapping ────────────────────────────────────────
# ALL keys must be UPPERCASE — values are the 7 paper-canonical labels.
# Matching is case-insensitive at runtime, so mixed-case JSON values work fine.
CATEGORY_MAP = {

    # ── Command Injection ─────────────────────────────────────────────────────
    "COMMAND INJECTION":                          "Command Injection",
    "COMMAND INJECTION / RCE":                    "Command Injection",
    "COMMAND/SHELL INJECTION":                    "Command Injection",
    "COMMAND / SHELL INJECTION":                  "Command Injection",
    "SHELL INJECTION":                            "Command Injection",
    "REMOTE CODE EXECUTION":                      "Command Injection",
    "REMOTE CODE EXECUTION / DYNAMIC CODE":       "Command Injection",
    "RCE":                                        "Command Injection",
    "CODE INJECTION":                             "Command Injection",
    "LOG / OUTPUT INJECTION":                     "Command Injection",
    "LOG/OUTPUT INJECTION":                       "Command Injection",
    "AGENTIC STATE MANIPULATION":                 "Command Injection",
    "MULTI-AGENT ATTACKS":                        "Command Injection",
    "MULTI-AGENT / SUBAGENT ATTACKS":             "Command Injection",
    "DENIAL OF SERVICE":                          "Command Injection",
    "DOS":                                        "Command Injection",

    # ── Prompt Injection ──────────────────────────────────────────────────────
    "PROMPT INJECTION":                           "Prompt Injection",
    "INDIRECT INJECTION":                         "Prompt Injection",
    "INDIRECT / EMBEDDED INJECTION":              "Prompt Injection",
    "INDIRECT/EMBEDDED INJECTION":                "Prompt Injection",
    "EMBEDDED INJECTION":                         "Prompt Injection",
    "PROMPT LEAKING":                             "Prompt Injection",
    "JAILBREAK":                                  "Prompt Injection",

    # ── Unsafe File Ops ───────────────────────────────────────────────────────
    "UNSAFE FILE OPERATIONS":                     "Unsafe File Ops",
    "UNSAFE FILE OPS":                            "Unsafe File Ops",
    "UNSAFE FILE ACCESS":                         "Unsafe File Ops",
    "ARBITRARY FILE ACCESS":                      "Unsafe File Ops",
    "FILE SYSTEM ABUSE":                          "Unsafe File Ops",
    "TOOL MISUSE / FUNCTION ABUSE":               "Unsafe File Ops",
    "TOOL MISUSE":                                "Unsafe File Ops",
    "FUNCTION ABUSE":                             "Unsafe File Ops",

    # ── Memory Poisoning ──────────────────────────────────────────────────────
    "MEMORY POISONING":                           "Memory Poisoning",
    "MEMORY POISONING & PERSISTENCE ATTACKS":     "Memory Poisoning",
    "MEMORY POISONING AND PERSISTENCE ATTACKS":   "Memory Poisoning",
    "PERSISTENCE ATTACK":                         "Memory Poisoning",
    "UNVALIDATED MEMORY WRITES":                  "Memory Poisoning",
    "UNVALIDATED CONTENT STORED IN MEMORY":       "Memory Poisoning",
    "STATE MANIPULATION":                         "Memory Poisoning",

    # ── Data Exposure ─────────────────────────────────────────────────────────
    "DATA EXPOSURE":                              "Data Exposure",
    "SENSITIVE DATA EXPOSURE":                    "Data Exposure",
    "DATA EXFILTRATION":                          "Data Exposure",
    "CREDENTIAL HARVESTING":                      "Data Exposure",
    "CREDENTIAL / SECRET EXPOSURE":               "Data Exposure",
    "CREDENTIAL/SECRET EXPOSURE":                 "Data Exposure",
    "SECRET EXPOSURE":                            "Data Exposure",
    "PII LEAKAGE":                                "Data Exposure",
    "INFORMATION DISCLOSURE":                     "Data Exposure",

    # ── Supply Chain ──────────────────────────────────────────────────────────
    "SUPPLY CHAIN":                               "Supply Chain",
    "SUPPLY CHAIN ATTACK":                        "Supply Chain",
    "INSECURE DESERIALIZATION":                   "Supply Chain",
    "DESERIALIZATION":                            "Supply Chain",
    "DEPENDENCY CONFUSION":                       "Supply Chain",
    "TYPOSQUATTING":                              "Supply Chain",

    # ── Privilege Abuse ───────────────────────────────────────────────────────
    "PRIVILEGE ABUSE":                            "Privilege Abuse",
    "PRIVILEGE ESCALATION":                       "Privilege Abuse",
    "SCOPE CREEP / OVER-PRIVILEGED TOOL USE":     "Privilege Abuse",
    "SCOPE CREEP":                                "Privilege Abuse",
    "OVER-PRIVILEGED TOOL USE":                   "Privilege Abuse",
    "OVER PRIVILEGED TOOL USE":                   "Privilege Abuse",
    "EXCESSIVE PERMISSIONS":                      "Privilege Abuse",
    "AUTHORIZATION BYPASS":                       "Privilege Abuse",
}

# Ordered list of canonical categories — controls axis order in Fig 2 & Fig 3
CANONICAL_CATEGORIES = [
    "Command Injection",
    "Prompt Injection",
    "Unsafe File Ops",
    "Memory Poisoning",
    "Data Exposure",
    "Supply Chain",
    "Privilege Abuse",
]

# Pre-build uppercase lookup once at import time
_CATEGORY_MAP_CI = {k.upper().strip(): v for k, v in CATEGORY_MAP.items()}


def normalize_category(raw: str) -> str:
    """
    Map any raw JSON category string → one of the 7 canonical paper labels.
    1. Exact match (case-insensitive, stripped).
    2. Substring match (raw contains a known key, or vice versa).
    3. Keyword-based fallback using discriminating tokens.
    4. Warn and return title-cased raw if nothing matches.
    """
    key = raw.strip().upper()

    # 1. Exact match
    if key in _CATEGORY_MAP_CI:
        return _CATEGORY_MAP_CI[key]

    # 2. Substring match
    for map_key, map_val in _CATEGORY_MAP_CI.items():
        if map_key in key or key in map_key:
            return map_val

    # 3. Keyword token fallback
    keyword_rules = [
        (["MEMORY", "POISON", "PERSIST", "UNVALIDATED"],          "Memory Poisoning"),
        (["PROMPT", "INDIRECT", "EMBEDDED", "JAILBREAK"],         "Prompt Injection"),
        (["COMMAND", "SHELL", "RCE", "CODE EXEC", "DYNAMIC"],     "Command Injection"),
        (["FILE", "PATH TRAV", "DIRECTORY"],                       "Unsafe File Ops"),
        (["CREDENTIAL", "SECRET", "PII", "EXFIL", "SENSITIVE"],   "Data Exposure"),
        (["SUPPLY", "DESERIAL", "DEPEND", "TYPO"],                 "Supply Chain"),
        (["PRIVILEGE", "SCOPE CREEP", "OVER-PRIV", "ESCALAT"],    "Privilege Abuse"),
    ]
    for keywords, canonical in keyword_rules:
        if any(kw in key for kw in keywords):
            return canonical

    # 4. No match — warn once and pass through title-cased
    canonical = raw.strip().title()
    print(f"[warn] Unmapped category '{raw}' → kept as '{canonical}'. "
          "Add it to CATEGORY_MAP to suppress this.")
    return canonical


# ── Global matplotlib style ───────────────────────────────────────────────────
plt.rcParams.update({
    'font.family':       'DejaVu Sans',
    'axes.spines.top':   False,
    'axes.spines.right': False,
    'axes.grid':         True,
    'grid.alpha':        0.25,
    'grid.linestyle':    '--',
    'figure.dpi':        180,
    'savefig.bbox':      'tight',
    'savefig.pad_inches': 0.15,
})


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_data(input_paths: list[str]) -> list[dict]:
    """
    Resolve all input paths (files, directories, globs) and load every
    valid JSON record. Returns a flat list of dicts.
    """
    json_files = []
    for p in input_paths:
        path = Path(p)
        if path.is_dir():
            json_files.extend(sorted(path.glob('*.json')))
        elif path.is_file():
            json_files.append(path)
        else:
            # treat as a glob pattern
            matched = sorted(glob.glob(p))
            if not matched:
                print(f"[warn] No files matched: {p}")
            json_files.extend(Path(m) for m in matched)

    if not json_files:
        sys.exit("[error] No JSON files found. Check your --input path.")

    data = []
    for f in json_files:
        try:
            with open(f) as fh:
                record = json.load(fh)
            # Accept both a single dict and a list of dicts per file
            if isinstance(record, list):
                data.extend(record)
            else:
                data.append(record)
        except Exception as e:
            print(f"[warn] Skipping {f.name}: {e}")

    if not data:
        sys.exit("[error] All files failed to parse.")

    print(f"[info] Loaded {len(data)} records from {len(json_files)} file(s).")
    return data


# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────

def save(fig, out_dir: Path, filename: str, label: str):
    path = out_dir / filename
    fig.savefig(path, dpi=180, facecolor=PALETTE['bg'])
    plt.close(fig)
    print(f"[✓] {label} → {path}")


# ─────────────────────────────────────────────────────────────────────────────
# TABLE 1 — Summary Statistics
# ─────────────────────────────────────────────────────────────────────────────

def make_table1(data: list[dict], out_dir: Path):
    cvss   = [d.get('cvss_base_score', 0) for d in data]
    sars   = [d.get('sars_score', 0)       for d in data]
    vcnt   = [d.get('vulnerability_count', 0) for d in data]
    vuln   = sum(1 for d in data if d.get('is_vulnerable', False))
    n      = len(data)

    risk_c = Counter(d.get('overall_risk', 'UNKNOWN') for d in data)

    rows = [
        ["Skills Evaluated",          str(n)],
        ["Vulnerable Skills (%)",     f"{vuln} ({vuln/n*100:.1f}%)"],
        ["Mean CVSS Score",           f"{np.mean(cvss):.2f} ± {np.std(cvss):.2f}"],
        ["Median CVSS Score",         f"{np.median(cvss):.2f}"],
        ["Mean SARS Score",           f"{np.mean(sars):.2f} ± {np.std(sars):.2f}"],
        ["Median SARS Score",         f"{np.median(sars):.2f}"],
        ["Mean Vuln. per Skill",      f"{np.mean(vcnt):.2f} ± {np.std(vcnt):.2f}"],
        ["Max Vulnerabilities",       str(max(vcnt))],
        ["High-Risk Skills (%)",      f"{risk_c.get('HIGH',0)} ({risk_c.get('HIGH',0)/n*100:.1f}%)"],
        ["Medium-Risk Skills (%)",    f"{risk_c.get('MEDIUM',0)} ({risk_c.get('MEDIUM',0)/n*100:.1f}%)"],
        ["Low-Risk Skills (%)",       f"{risk_c.get('LOW',0)} ({risk_c.get('LOW',0)/n*100:.1f}%)"],
        ["Unique Vuln. Categories",   str(len({v['category'] for d in data for v in d.get('vulnerabilities',[])}))],
        ["Unique Dangerous Patterns", str(len({p for d in data for p in d.get('dangerous_patterns',[])}))],
        ["Malicious Verdict (%)",
         f"{sum(1 for d in data if d.get('clawhub_verdict')=='Malicious')} "
         f"({sum(1 for d in data if d.get('clawhub_verdict')=='Malicious')/n*100:.1f}%)"],
    ]

    fig, ax = plt.subplots(figsize=(7.5, 4.8), facecolor=PALETTE['bg'])
    ax.axis('off')
    tbl = ax.table(cellText=rows, colLabels=["Metric", "Value"],
                   loc='center', cellLoc='left')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(9.5)
    tbl.scale(1, 1.55)
    for (r, c), cell in tbl.get_celld().items():
        cell.set_edgecolor('#cccccc')
        if r == 0:
            cell.set_facecolor('#2c3e50')
            cell.set_text_props(color='white', fontweight='bold')
        elif r % 2 == 0:
            cell.set_facecolor('#eaf0fb')
        else:
            cell.set_facecolor('white')
        if c == 0:
            cell.set_text_props(fontweight='semibold')
    ax.set_title('Table 1: Dataset Overview — Summary Statistics',
                 fontsize=11, fontweight='bold', pad=14, color=PALETTE['accent'])
    plt.tight_layout()
    save(fig, out_dir, 'table1_summary_stats.png', 'Table 1')


# ─────────────────────────────────────────────────────────────────────────────
# FIG 1 — Risk Distribution + CVSS Histogram
# ─────────────────────────────────────────────────────────────────────────────

def make_fig1(data: list[dict], out_dir: Path):
    risk_counts = Counter(d.get('overall_risk', 'UNKNOWN') for d in data)
    risk_order  = ['LOW', 'MEDIUM', 'HIGH']
    risk_vals   = [risk_counts.get(r, 0) for r in risk_order]
    risk_colors = [PALETTE.get(r, '#888') for r in risk_order]

    cvss_by_tier = {
        tier: [d['cvss_base_score'] for d in data
               if d.get('overall_risk') == tier and 'cvss_base_score' in d]
        for tier in risk_order
    }
    all_cvss = [d.get('cvss_base_score', 0) for d in data]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4.2), facecolor=PALETTE['bg'])

    # (a) Bar
    bars = ax1.bar(risk_order, risk_vals, color=risk_colors,
                   edgecolor='white', linewidth=1.2, width=0.55, zorder=3)
    for bar, val in zip(bars, risk_vals):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.4,
                 str(val), ha='center', va='bottom', fontsize=11,
                 fontweight='bold', color=PALETTE['accent'])
    ax1.set_xlabel('Risk Level', fontsize=10, labelpad=6)
    ax1.set_ylabel('Number of Skills', fontsize=10)
    ax1.set_title('(a) Risk Level Distribution', fontsize=10.5, fontweight='bold', pad=8)
    ax1.set_ylim(0, max(risk_vals) + 8)
    ax1.tick_params(labelsize=9)

    # (b) CVSS histogram stacked by tier
    bins = np.linspace(0, 10, 21)
    for tier, color in zip(risk_order, risk_colors):
        scores = cvss_by_tier.get(tier, [])
        if scores:
            ax2.hist(scores, bins=bins, color=color, alpha=0.75,
                     label=tier.capitalize(), edgecolor='white')
    if all_cvss:
        ax2.axvline(np.mean(all_cvss), color='#2c3e50', linestyle='--',
                    linewidth=1.5, label=f'Mean={np.mean(all_cvss):.2f}')
    ax2.set_xlabel('CVSS Base Score', fontsize=10, labelpad=6)
    ax2.set_ylabel('Frequency', fontsize=10)
    ax2.set_title('(b) CVSS Score Distribution by Risk Tier',
                  fontsize=10.5, fontweight='bold', pad=8)
    ax2.legend(fontsize=8.5, framealpha=0.6)
    ax2.tick_params(labelsize=9)

    fig.suptitle('Figure 1: Threat Landscape — Risk & CVSS Distribution',
                 fontsize=12, fontweight='bold', y=1.02, color=PALETTE['accent'])
    plt.tight_layout()
    save(fig, out_dir, 'fig1_risk_distribution.png', 'Figure 1')


# ─────────────────────────────────────────────────────────────────────────────
# FIG 2 — Vulnerability Category Frequency
# ─────────────────────────────────────────────────────────────────────────────

def make_fig2(data: list[dict], out_dir: Path):
    # ── Normalize every raw category to canonical label ──────────────────────
    all_cats = [
        normalize_category(v['category'])
        for d in data
        for v in d.get('vulnerabilities', [])
    ]
    if not all_cats:
        print("[warn] No vulnerability categories found — skipping Figure 2.")
        return

    cat_counts = Counter(all_cats)

    # ── Force the 7-canonical order; append unknowns at the end by count ─────
    labels, values = [], []
    for cat in CANONICAL_CATEGORIES:
        if cat in cat_counts:
            labels.append(cat)
            values.append(cat_counts[cat])
    # Any leftover unmapped categories
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        if cat not in CANONICAL_CATEGORIES:
            labels.append(cat)
            values.append(cnt)

    if not values:
        print("[warn] No counts after normalization — skipping Figure 2.")
        return

    # ── Colour each bar by count (high = red, low = green) ───────────────────
    cmap      = plt.cm.RdYlGn_r
    vmin, vmax = min(values), max(values)
    norm_vals  = [(v - vmin) / (vmax - vmin) if vmax > vmin else 0.5 for v in values]
    colors     = [cmap(n * 0.8 + 0.1) for n in norm_vals]

    fig, ax = plt.subplots(
        figsize=(10, max(4, len(labels) * 0.68 + 1.2)),
        facecolor=PALETTE['bg']
    )
    bars = ax.barh(labels[::-1], values[::-1], color=colors[::-1],
                   edgecolor='white', linewidth=0.8, height=0.60, zorder=3)
    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + 0.3,
                bar.get_y() + bar.get_height() / 2,
                str(val), va='center', ha='left',
                fontsize=10, fontweight='bold', color=PALETTE['accent'])
    ax.set_xlabel('Occurrence Count', fontsize=10.5, labelpad=6)
    ax.set_xlim(0, max(values) + max(values) * 0.15)
    ax.set_title('Figure 2: Attack Category Frequency (Canonical Taxonomy)',
                 fontsize=11.5, fontweight='bold', pad=10, color=PALETTE['accent'])
    ax.tick_params(axis='y', labelsize=10)
    ax.tick_params(axis='x', labelsize=9)
    plt.tight_layout()
    save(fig, out_dir, 'fig2_category_frequency.png', 'Figure 2')


# ─────────────────────────────────────────────────────────────────────────────
# FIG 3 — Dangerous Pattern × Vulnerability Category Co-occurrence Heatmap
# ─────────────────────────────────────────────────────────────────────────────

def make_fig3(data: list[dict], out_dir: Path, top_n: int = 20):
    # ── All unique dangerous patterns ─────────────────────────────────────────
    all_dp = sorted({p for d in data for p in d.get('dangerous_patterns', [])})
    if not all_dp:
        print("[warn] No dangerous patterns found — skipping Figure 3.")
        return

    # ── Columns = canonical categories present in the data, in paper order ────
    present_canonical = {
        normalize_category(v['category'])
        for d in data
        for v in d.get('vulnerabilities', [])
    }
    col_cats = [c for c in CANONICAL_CATEGORIES if c in present_canonical]
    # Append any unmapped extras at the end
    extras = sorted(present_canonical - set(CANONICAL_CATEGORIES))
    col_cats += extras

    if not col_cats:
        print("[warn] No canonical categories resolved — skipping Figure 3.")
        return

    # ── Build co-occurrence matrix (rows=patterns, cols=canonical cats) ───────
    matrix = np.zeros((len(all_dp), len(col_cats)), dtype=int)
    for d in data:
        dp_set  = set(d.get('dangerous_patterns', []))
        cat_set = {normalize_category(v['category']) for v in d.get('vulnerabilities', [])}
        for i, dp in enumerate(all_dp):
            for j, cc in enumerate(col_cats):
                if dp in dp_set and cc in cat_set:
                    matrix[i][j] += 1

    # ── Select top-N rows by total co-occurrence count ────────────────────────
    row_totals  = matrix.sum(axis=1)
    top_idx     = np.argsort(row_totals)[::-1][:top_n]
    top_idx     = sorted(top_idx, key=lambda i: row_totals[i], reverse=True)

    top_dp     = [all_dp[i]  for i in top_idx]
    top_matrix = matrix[top_idx, :]
    actual_n   = len(top_dp)

    print(f"[info] Fig 3 — top {actual_n} patterns × {len(col_cats)} canonical categories.")

    # ── Y-axis: pattern text + total count prefix ─────────────────────────────
    row_sums = top_matrix.sum(axis=1)
    y_labels = [
        f"({row_sums[i]:>3d})  {dp[:44]}{'…' if len(dp) > 44 else ''}"
        for i, dp in enumerate(top_dp)
    ]
    # X-axis: canonical short names (already concise, no wrapping needed)
    x_labels = col_cats

    # ── Plot ──────────────────────────────────────────────────────────────────
    fig_h = max(7, actual_n * 0.52 + 3.0)
    fig_w = max(9,  len(col_cats) * 1.55 + 3.5)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h), facecolor=PALETTE['bg'])

    sns.heatmap(
        top_matrix, ax=ax,
        xticklabels=x_labels,
        yticklabels=y_labels,
        cmap='YlOrRd',
        annot=True, fmt='d',
        linewidths=0.45, linecolor='#e8e8e8',
        cbar_kws={'label': 'Co-occurrence Count', 'shrink': 0.60},
        annot_kws={'size': 9, 'fontweight': 'bold'},
    )
    ax.set_xlabel('Attack Category (canonical)', fontsize=11, labelpad=10)
    ax.set_ylabel('Dangerous Pattern  (total count in parentheses)',
                  fontsize=10.5, labelpad=10)
    ax.set_title(
        f'Figure 3: Top {actual_n} Dangerous Patterns x Attack Category Co-occurrence\n'
        '(patterns ranked by total count; columns = paper-canonical taxonomy)',
        fontsize=11.5, fontweight='bold', pad=14, color=PALETTE['accent'],
    )
    ax.tick_params(axis='x', labelsize=10, rotation=25)
    ax.tick_params(axis='y', labelsize=8.5, rotation=0)

    plt.tight_layout()
    save(fig, out_dir, 'fig3_cooccurrence_heatmap.png', 'Figure 3')


# ─────────────────────────────────────────────────────────────────────────────
# FIG 4 — CVSS vs SARS Scatter
# ─────────────────────────────────────────────────────────────────────────────

def make_fig4(data: list[dict], out_dir: Path):
    records = [d for d in data if 'cvss_base_score' in d and 'sars_score' in d]
    if not records:
        print("[warn] No CVSS/SARS scores found — skipping Figure 4.")
        return

    verdict_style = {
        'Safe':       (PALETTE['Safe'],       'o'),
        'Suspicious': (PALETTE['Suspicious'], 's'),
        'Malicious':  (PALETTE['Malicious'],  '^'),
    }

    fig, ax = plt.subplots(figsize=(7.5, 5.5), facecolor=PALETTE['bg'])

    for verdict, (color, marker) in verdict_style.items():
        subset = [d for d in records if d.get('clawhub_verdict') == verdict]
        if subset:
            ax.scatter([d['cvss_base_score'] for d in subset],
                       [d['sars_score']       for d in subset],
                       c=color, marker=marker, s=60, alpha=0.82,
                       edgecolors='white', linewidths=0.5,
                       label=verdict, zorder=3)

    all_x = np.array([d['cvss_base_score'] for d in records])
    all_y = np.array([d['sars_score']       for d in records])

    if len(all_x) > 1:
        m, b   = np.polyfit(all_x, all_y, 1)
        xline  = np.linspace(all_x.min(), all_x.max(), 200)
        corr   = np.corrcoef(all_x, all_y)[0, 1]
        ax.plot(xline, m * xline + b, '--', color='#2c3e50', linewidth=1.4,
                label=f'Trend (r={corr:.2f})', zorder=2)
        ax.annotate(f'Pearson r = {corr:.3f}',
                    xy=(0.97, 0.05), xycoords='axes fraction', ha='right',
                    fontsize=9, color='#555',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.7))

    ax.plot([0, 10], [0, 10], ':', color='grey', linewidth=0.8,
            alpha=0.5, label='CVSS = SARS')
    ax.set_xlabel('CVSS Base Score', fontsize=10.5, labelpad=6)
    ax.set_ylabel('SARS Score', fontsize=10.5, labelpad=6)
    ax.set_title('Figure 4: CVSS vs. SARS Score Comparison\nColored by ClawHub Verdict',
                 fontsize=11, fontweight='bold', pad=10, color=PALETTE['accent'])
    ax.legend(fontsize=9, framealpha=0.7, loc='upper left')
    ax.set_xlim(0, 10.5); ax.set_ylim(0, 10.5)
    ax.tick_params(labelsize=9)
    plt.tight_layout()
    save(fig, out_dir, 'fig4_cvss_vs_sars.png', 'Figure 4')


# ─────────────────────────────────────────────────────────────────────────────
# FIG 5 — SARS Radar by Risk Tier
# ─────────────────────────────────────────────────────────────────────────────

def make_fig5(data: list[dict], out_dir: Path):
    dims     = ['IFR', 'DG', 'AI', 'BR', 'CA']
    dim_keys = ['sars_ifr', 'sars_dg', 'sars_ai', 'sars_br', 'sars_ca']

    def avg(tier):
        subset = [d for d in data if d.get('overall_risk') == tier]
        if not subset:
            return [0] * len(dims)
        return [np.mean([d.get(k, 0) for d in subset]) for k in dim_keys]

    tiers = [('LOW', 'Low Risk', PALETTE['LOW']),
             ('MEDIUM', 'Medium Risk', PALETTE['MEDIUM']),
             ('HIGH', 'High Risk', PALETTE['HIGH'])]

    N      = len(dims)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]

    def close(lst):
        return lst + lst[:1]

    fig, ax = plt.subplots(figsize=(6.5, 5.8),
                           subplot_kw=dict(polar=True),
                           facecolor=PALETTE['bg'])
    for tier, label, color in tiers:
        vals = avg(tier)
        ax.plot(angles, close(vals), 'o-', linewidth=2, color=color, label=label)
        ax.fill(angles, close(vals), alpha=0.12, color=color)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(dims, fontsize=11, fontweight='bold', color=PALETTE['accent'])
    ax.set_yticks([1, 2, 3, 4])
    ax.set_yticklabels(['1', '2', '3', '4'], fontsize=7.5, color='grey')
    ax.set_ylim(0, 4.5)
    ax.tick_params(pad=6)
    ax.spines['polar'].set_visible(False)
    ax.grid(color='grey', linestyle='--', linewidth=0.5, alpha=0.4)
    ax.set_title(
        'Figure 5: SARS Dimension Profile by Risk Tier\n'
        '(IFR=Instruction-Following Rate, DG=Data Governance,\n'
        'AI=Agent Interaction, BR=Blast Radius, CA=Cascading Action)',
        fontsize=9.5, fontweight='bold', pad=18, color=PALETTE['accent'])
    ax.legend(loc='upper right', bbox_to_anchor=(1.35, 1.12), fontsize=9.5)
    plt.tight_layout()
    save(fig, out_dir, 'fig5_sars_radar.png', 'Figure 5')


# ─────────────────────────────────────────────────────────────────────────────
# FIG 6 — ClawHub Verdict Breakdown
# ─────────────────────────────────────────────────────────────────────────────

def make_fig6(data: list[dict], out_dir: Path):
    verdict_counts = Counter(d.get('clawhub_verdict', 'Unknown') for d in data)

    check_fields = [
        'clawhub_purpose_capability',
        'clawhub_instruction_scope',
        'clawhub_install_mechanism',
        'clawhub_credentials',
        'clawhub_persistence_privilege',
    ]
    check_labels = [
        'Purpose\nCapability',
        'Instruction\nScope',
        'Install\nMechanism',
        'Credentials',
        'Persistence\nPrivilege',
    ]
    check_results = {f: Counter(d.get(f, 'unknown') for d in data) for f in check_fields}

    fig = plt.figure(figsize=(12, 5.2), facecolor=PALETTE['bg'])
    gs  = gridspec.GridSpec(1, 2, width_ratios=[1, 1.7], wspace=0.35)

    # (a) Donut
    ax_donut = fig.add_subplot(gs[0])
    sizes    = [verdict_counts.get(v, 0) for v in ['Safe', 'Suspicious', 'Malicious']]
    colors   = [PALETTE['Safe'], PALETTE['Suspicious'], PALETTE['Malicious']]
    if sum(sizes) > 0:
        wedges, texts, autotexts = ax_donut.pie(
            sizes, labels=['Safe', 'Suspicious', 'Malicious'],
            colors=colors, explode=(0.03, 0.03, 0.05),
            autopct='%1.1f%%', startangle=140,
            wedgeprops=dict(width=0.55, edgecolor='white', linewidth=2),
            textprops={'fontsize': 9.5}
        )
        for at in autotexts:
            at.set_fontsize(9)
            at.set_fontweight('bold')
            at.set_color('white')
    ax_donut.set_title('(a) ClawHub Verdict\nDistribution',
                       fontsize=10.5, fontweight='bold',
                       color=PALETTE['accent'], pad=10)

    # (b) Stacked bar — check results
    ax_bar = fig.add_subplot(gs[1])
    x      = np.arange(len(check_labels))
    w      = 0.55
    pass_v = [check_results[f].get('pass', 0) for f in check_fields]
    warn_v = [check_results[f].get('warn', 0) for f in check_fields]
    fail_v = [check_results[f].get('fail', 0) for f in check_fields]
    bottom_warn = pass_v
    bottom_fail = [p + w2 for p, w2 in zip(pass_v, warn_v)]

    ax_bar.bar(x, pass_v, w, label='Pass', color=PALETTE['Safe'],
               edgecolor='white', linewidth=0.8)
    ax_bar.bar(x, warn_v, w, label='Warn', color=PALETTE['MEDIUM'],
               edgecolor='white', linewidth=0.8, bottom=bottom_warn)
    ax_bar.bar(x, fail_v, w, label='Fail', color=PALETTE['HIGH'],
               edgecolor='white', linewidth=0.8, bottom=bottom_fail)

    ax_bar.set_xticks(x)
    ax_bar.set_xticklabels(check_labels, fontsize=8.5)
    ax_bar.set_ylabel('Count', fontsize=10)
    ax_bar.set_ylim(0, len(data) + 10)
    ax_bar.set_title('(b) ClawHub Security Check Results\nby Category',
                     fontsize=10.5, fontweight='bold',
                     color=PALETTE['accent'], pad=10)
    ax_bar.legend(fontsize=9, loc='upper right', framealpha=0.7)
    ax_bar.tick_params(labelsize=8.5)

    fig.suptitle('Figure 6: Ecosystem Verdict & ClawHub Security Check Breakdown',
                 fontsize=11.5, fontweight='bold', y=1.02, color=PALETTE['accent'])
    plt.tight_layout()
    save(fig, out_dir, 'fig6_clawhub_verdict.png', 'Figure 6')


# ─────────────────────────────────────────────────────────────────────────────
# APPENDIX TABLE — Dangerous Patterns × Attack Categories
# Rows = all dangerous patterns (ranked by total count)
# Columns = 7 canonical attack categories
# ─────────────────────────────────────────────────────────────────────────────

def make_appendix_table(data: list[dict], out_dir: Path):
    """
    LaTeX longtable with:
      - Column 1 : Dangerous Pattern
      - Column 2 : Total (sum across all categories)
      - Columns 3–9 : one per canonical attack category (co-occurrence count)

    Patterns are sorted by total count descending.
    Each cell shows the raw co-occurrence count; 0 is shown as '—'.
    """
    from collections import defaultdict, Counter

    def esc(s: str) -> str:
        return (str(s)
                .replace('&',  r'\&')
                .replace('%',  r'\%')
                .replace('_',  r'\_')
                .replace('#',  r'\#')
                .replace('$',  r'\$')
                .replace('{',  r'\{')
                .replace('}',  r'\}')
                .replace('~',  r'\textasciitilde{}')
                .replace('^',  r'\textasciicircum{}'))

    # ── Build pattern × category co-occurrence matrix ─────────────────────────
    # pattern → {canonical_category: count}
    pattern_cat: dict[str, Counter] = defaultdict(Counter)

    for d in data:
        dp_set  = set(d.get('dangerous_patterns', []))
        cat_set = {normalize_category(v['category'])
                   for v in d.get('vulnerabilities', [])}
        for dp in dp_set:
            for cat in cat_set:
                pattern_cat[dp][cat] += 1

    if not pattern_cat:
        print("[warn] No pattern/category data — skipping appendix table.")
        return

    # ── Only keep canonical categories that actually appear ───────────────────
    present_cats = {c for counts in pattern_cat.values() for c in counts}
    col_cats     = [c for c in CANONICAL_CATEGORIES if c in present_cats]

    # ── Sort patterns by total co-occurrence count descending ─────────────────
    all_patterns = sorted(
        pattern_cat.keys(),
        key=lambda p: (-sum(pattern_cat[p].values()), p)
    )

    # ── Column spec: pattern + Total + one col per category ──────────────────
    n_cat_cols = len(col_cats)
    # pattern column ~wide, Total narrow, category cols narrow
    col_spec = r"p{5.2cm} r " + " ".join(["r"] * n_cat_cols)

    # Short category labels for column headers (space is tight)
    short_labels = {
        "Command Injection":  r"\rotatebox{60}{\textbf{Cmd Injection}}",
        "Prompt Injection":   r"\rotatebox{60}{\textbf{Prompt Injection}}",
        "Unsafe File Ops":    r"\rotatebox{60}{\textbf{Unsafe File Ops}}",
        "Memory Poisoning":   r"\rotatebox{60}{\textbf{Memory Poisoning}}",
        "Data Exposure":      r"\rotatebox{60}{\textbf{Data Exposure}}",
        "Supply Chain":       r"\rotatebox{60}{\textbf{Supply Chain}}",
        "Privilege Abuse":    r"\rotatebox{60}{\textbf{Privilege Abuse}}",
    }

    def col_header(cat):
        return short_labels.get(cat, r"\rotatebox{60}{\textbf{" + esc(cat) + r"}}")

    # ── Header row ────────────────────────────────────────────────────────────
    header_cells = (
        [r"\textbf{Dangerous Pattern}", r"\textbf{Total}"]
        + [col_header(c) for c in col_cats]
    )
    header_line = "  " + " & ".join(header_cells) + r" \\"

    # ── Repeated header for longtable continuation pages ──────────────────────
    repeated_header = (
        r"  \multicolumn{" + str(n_cat_cols + 2) + r"}{c}{"
        r"\tablename\ \thetable{} (continued)} \\[4pt]"
        + "\n  " + r"\toprule" + "\n"
        + header_line + "\n"
        + r"  \midrule"
    )

    # ── Build lines ───────────────────────────────────────────────────────────
    lines = [
        r"% ─────────────────────────────────────────────────────────────────",
        r"% Appendix Table: Dangerous Patterns × Attack Categories",
        r"% Auto-generated by generate_results.py",
        r"% Required packages: booktabs, longtable, xcolor, colortbl, rotating",
        r"% ─────────────────────────────────────────────────────────────────",
        r"",
        r"\begin{center}",
        r"\small",
        r"\setlength{\tabcolsep}{5pt}",
        r"\renewcommand{\arraystretch}{1.18}",
        r"\definecolor{RowShade}{HTML}{EAF0FB}",
        r"\definecolor{TotalCol}{HTML}{D5E8D4}",
        r"",
        rf"\begin{{longtable}}{{{col_spec}}}",
        r"  \caption{Dangerous Pattern co-occurrence across canonical attack "
        r"categories. Rows = all dangerous patterns identified across the "
        r"evaluated skill set, ranked by total co-occurrence count. "
        r"Columns = the seven canonical attack categories. "
        r"Each cell reports the number of skills that exhibit both the pattern "
        r"and the corresponding category. `---' denotes zero co-occurrence.}",
        r"  \label{tab:appendix_patterns} \\",
        r"",
        r"  \toprule",
        header_line,
        r"  \midrule",
        r"  \endfirsthead",
        r"",
        repeated_header,
        r"  \endhead",
        r"",
        r"  \midrule",
        rf"  \multicolumn{{{n_cat_cols + 2}}}{{r}}{{\footnotesize Continued on next page}} \\",
        r"  \endfoot",
        r"",
        r"  \bottomrule",
        r"  \endlastfoot",
        r"",
    ]

    # ── Data rows ─────────────────────────────────────────────────────────────
    for row_idx, pattern in enumerate(all_patterns):
        counts  = pattern_cat[pattern]
        total   = sum(counts.values())
        cat_vals = [counts.get(c, 0) for c in col_cats]

        # Alternate row shading
        if row_idx % 2 == 0:
            lines.append(r"  \rowcolor{RowShade}")

        # Pattern name + Total (bold, green-tinted) + per-category counts
        cells = [esc(pattern), f"\\textbf{{{total}}}"] + \
                ["---" if v == 0 else str(v) for v in cat_vals]

        lines.append("  " + " & ".join(cells) + r" \\")

    lines += [
        r"",
        r"\end{longtable}",
        r"\end{center}",
        r"",
    ]

    # ── Write ─────────────────────────────────────────────────────────────────
    tex_path = out_dir / 'appendix_category_patterns.tex'
    tex_path.write_text("\n".join(lines), encoding='utf-8')
    print(f"[✓] Appendix Table → {tex_path}")
    print(f"     {len(all_patterns)} patterns × {n_cat_cols} categories")
    print(f"     Include with: \\input{{appendix_category_patterns}}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='Generate paper figures from AgentSkillBench JSON reports.')
    p.add_argument(
        '--input', '-i', nargs='+', required=True,
        help='Path(s) to JSON file(s), directory/ies, or glob pattern(s).')
    p.add_argument(
        '--output', '-o', default='./paper_figures',
        help='Output directory for figures (default: ./paper_figures).')
    return p.parse_args()


def main():
    args    = parse_args()
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[info] Output directory: {out_dir.resolve()}")

    data = load_data(args.input)

    make_table1(data, out_dir)
    make_fig1(data, out_dir)
    make_fig2(data, out_dir)
    make_fig3(data, out_dir)
    make_fig4(data, out_dir)
    make_fig5(data, out_dir)
    make_fig6(data, out_dir)
    make_appendix_table(data, out_dir)

    print(f"\n[done] All outputs saved to: {out_dir.resolve()}/")


if __name__ == '__main__':
    main()