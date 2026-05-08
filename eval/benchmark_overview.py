"""
AgentSkillBench - Model-wise Dataset Overview LaTeX Table Generator
Option B: Last column = average of per-model values (not pooled rows).
 
Usage:
  python generate_latex_table.py --input results.csv
  python generate_latex_table.py --input results.csv --output table.tex
 
Required LaTeX packages: booktabs, xcolor, colortbl
"""
 
import argparse
import sys
from pathlib import Path
import pandas as pd
import numpy as np
 
# ── Model short-name aliases ──────────────────────────────────────────────────
MODEL_ALIASES = {
    "Qwen/Qwen2.5-32B-Instruct":            "Qwen2.5-32B",
    "Qwen/Qwen2.5-72B-Instruct":            "Qwen2.5-72B",
    "meta-llama/Llama-3-70B-Instruct":      "Llama-3-70B",
    "meta-llama/Llama-3.1-8B-Instruct":     "Llama-3.1-8B",
    "meta-llama/Llama-3.3-70B-Instruct":    "Llama-3.3-70B",
    "mistralai/Mixtral-8x7B-Instruct-v0.1": "Mixtral-8x7B",
    "mistralai/Mistral-7B-Instruct-v0.3":   "Mistral-7B",
    "google/gemma-2-27b-it":                "Gemma-2-27B",
    "google/gemma-2-9b-it":                 "Gemma-2-9B",
    "microsoft/phi-4":                      "Phi-4",
}
 
def shorten_model(name):
    return MODEL_ALIASES.get(name, name.split("/")[-1][:16])
 
# ── Stat helpers ──────────────────────────────────────────────────────────────
 
def num(s):
    return pd.to_numeric(s, errors="coerce").dropna()
 
def fmt_pct(count, total):
    if total == 0: return "0 (0.0\\%)"
    return f"{int(count)} ({count / total * 100:.1f}\\%)"
 
def fmt_ms(series):
    s = num(series)
    if s.empty: return "---"
    return f"{s.mean():.2f} $\\pm$ {s.std():.2f}"
 
def fmt_med(series):
    s = num(series)
    return f"{s.median():.2f}" if not s.empty else "---"
 
def vuln_count(series):
    return int(series.apply(
        lambda x: str(x).strip().lower() in ("true","1","yes")).sum())
 
 
# ── Per-model metric computation ──────────────────────────────────────────────
# Each function returns a (raw_value, display_string) tuple.
# raw_value is used for computing the cross-model average column.
 
def m_skills(df):
    v = len(df)
    return v, str(v)
 
def m_vuln(df):
    v = vuln_count(df["is_vulnerable"]) / len(df) * 100
    return v, fmt_pct(vuln_count(df["is_vulnerable"]), len(df))
 
def m_cvss_mean(df):
    s = num(df["cvss_base_score"])
    v = s.mean() if not s.empty else np.nan
    return v, fmt_ms(df["cvss_base_score"])
 
def m_cvss_med(df):
    s = num(df["cvss_base_score"])
    v = s.median() if not s.empty else np.nan
    return v, fmt_med(df["cvss_base_score"])
 
def m_sars_mean(df):
    s = num(df["sars_score"])
    v = s.mean() if not s.empty else np.nan
    return v, fmt_ms(df["sars_score"])
 
def m_sars_med(df):
    s = num(df["sars_score"])
    v = s.median() if not s.empty else np.nan
    return v, fmt_med(df["sars_score"])
 
def m_vuln_per_skill_mean(df):
    s = num(df["vulnerability_count"])
    v = s.mean() if not s.empty else np.nan
    return v, fmt_ms(df["vulnerability_count"])
 
def m_max_vuln(df):
    s = num(df["vulnerability_count"])
    v = s.max() if not s.empty else np.nan
    return v, str(int(v)) if not np.isnan(v) else "---"
 
def m_high(df):
    v = (df["overall_risk"].str.upper() == "HIGH").sum() / len(df) * 100
    return v, fmt_pct((df["overall_risk"].str.upper() == "HIGH").sum(), len(df))
 
def m_medium(df):
    v = (df["overall_risk"].str.upper() == "MEDIUM").sum() / len(df) * 100
    return v, fmt_pct((df["overall_risk"].str.upper() == "MEDIUM").sum(), len(df))
 
def m_low(df):
    v = (df["overall_risk"].str.upper() == "LOW").sum() / len(df) * 100
    return v, fmt_pct((df["overall_risk"].str.upper() == "LOW").sum(), len(df))
 
def m_unique_cats(df):
    if "top_finding_category" not in df.columns:
        return np.nan, "---"
    v = df["top_finding_category"].dropna().nunique()
    return float(v), str(int(v))
 
def m_sars_dim(col):
    def fn(df):
        s = num(df[col]) if col in df.columns else pd.Series(dtype=float)
        v = s.mean() if not s.empty else np.nan
        return v, fmt_ms(df[col]) if col in df.columns else "---"
    return fn
 
 
# ── Average column formatter ──────────────────────────────────────────────────
# How to format the cross-model average depends on the metric type.
 
def avg_fmt_pct(raw_vals):
    """Average of percentage values → 'XX.X%' """
    vals = [v for v in raw_vals if not np.isnan(v)]
    if not vals: return "---"
    return f"{np.mean(vals):.1f}\\%"
 
def avg_fmt_float(raw_vals):
    """Average of float values → 'X.XX' """
    vals = [v for v in raw_vals if not np.isnan(v)]
    if not vals: return "---"
    return f"{np.mean(vals):.2f}"
 
def avg_fmt_int(raw_vals):
    """Average of integer values → 'XX.X' """
    vals = [v for v in raw_vals if not np.isnan(v)]
    if not vals: return "---"
    return f"{np.mean(vals):.1f}"
 
 
# ── Metric table definition ───────────────────────────────────────────────────
# Each entry: (display_label, metric_fn, avg_formatter, group_id)
 
def make_metric_rows(df):
    rows = [
        # group 0 — volume
        ("Skills Evaluated",          m_skills,            avg_fmt_int,   0),
        ("Vulnerable Skills (\\%)",   m_vuln,              avg_fmt_pct,   0),
        # group 1 — scores
        ("Mean CVSS Score",           m_cvss_mean,         avg_fmt_float, 1),
        ("Median CVSS Score",         m_cvss_med,          avg_fmt_float, 1),
        ("Mean SARS Score",           m_sars_mean,         avg_fmt_float, 1),
        ("Median SARS Score",         m_sars_med,          avg_fmt_float, 1),
        # group 2 — vuln counts
        ("Mean Vuln. per Skill",      m_vuln_per_skill_mean, avg_fmt_float, 2),
        ("Max Vulnerabilities",       m_max_vuln,          avg_fmt_float, 2),
        # group 3 — risk breakdown
        ("High-Risk Skills (\\%)",    m_high,              avg_fmt_pct,   3),
        ("Medium-Risk Skills (\\%)",  m_medium,            avg_fmt_pct,   3),
        ("Low-Risk Skills (\\%)",     m_low,               avg_fmt_pct,   3),
        # group 4 — categories
        ("Unique Vuln. Categories",   m_unique_cats,       avg_fmt_float, 4),
    ]
    # SARS dimensions — only if columns present
    for col, label in [
        ("sars_ifr", "SARS-IFR (mean $\\pm$ std)"),
        ("sars_dg",  "SARS-DG (mean $\\pm$ std)"),
        ("sars_ai",  "SARS-AI (mean $\\pm$ std)"),
        ("sars_br",  "SARS-BR (mean $\\pm$ std)"),
        ("sars_ca",  "SARS-CA (mean $\\pm$ std)"),
    ]:
        if col in df.columns:
            rows.append((label, m_sars_dim(col), avg_fmt_float, 5))
    return rows
 
 
# ── LaTeX builder ─────────────────────────────────────────────────────────────
 
def build_latex(model_names, model_labels, df, metric_rows, caption, label):
    n_data   = len(model_names)+1          # models + Avg. across Models
    col_spec = "l" + "r" * n_data
 
    def esc(v): return str(v).replace("&", r"\&")
 
    L = []
    L += [
        "% Auto-generated by generate_latex_table.py",
        "% Packages: booktabs, xcolor, colortbl",
        "",
        r"\begin{table*}[t]",
        r"  \centering",
        r"  \setlength{\tabcolsep}{5pt}",
        r"  \renewcommand{\arraystretch}{1.20}",
        r"  \definecolor{RowShade}{HTML}{EAF0FB}",
        f"  \\caption{{{caption}}}",
        f"  \\label{{{label}}}",
        f"  \\begin{{tabular}}{{{col_spec}}}",
        r"    \toprule",
    ]
 
    # Header
    hdr = ["\\textbf{Metric}"] + \
          [f"\\textbf{{{lbl}}}" for lbl in model_labels]
    L.append("    " + " & ".join(hdr) + r" \\")
    L.append(r"    \midrule")
 
    prev_grp = metric_rows[0][3]
    shade    = False
 
    for label_text, fn, avg_fn, grp in metric_rows:
        # Group separator
        if grp != prev_grp:
            L.append(r"    \midrule")
            shade = False
        prev_grp = grp
 
        # Alternating row shade
        if shade:
            L.append(r"    \rowcolor{RowShade}")
        shade = not shade
 
        # Compute per-model values
        raw_vals, disp_vals = [], []
        for m in model_names:
            raw, disp = fn(df[df["model_name"] == m])
            raw_vals.append(raw)
            disp_vals.append(esc(disp))
 
        # Compute cross-model average
        avg_disp = esc(avg_fn(raw_vals))
 
        cells = [f"\\textbf{{{esc(label_text)}}}"] + disp_vals
        L.append("    " + " & ".join(cells) + r" \\")
 
    L += [
        r"    \bottomrule",
        f"  \\end{{tabular}}",
        r"  \begin{minipage}{\linewidth}",
        r"    \vspace{3pt}\footnotesize",
        (r"    \textit{Note:} The same 100 skills were evaluated by each model independently. "
         r"``Avg.\ across Models'' is the mean of per-model values, not a pooled statistic. "
         r"Vuln.\ = skills with $\geq$\,1 vulnerability. CVSS and SARS on a 0--10 scale. "
         r"IFR\,=\,Instruction-Following Risk; DG\,=\,Data Governance; "
         r"AI\,=\,Agent Interaction; BR\,=\,Blast Radius; CA\,=\,Cascading Action."),
        r"  \end{minipage}",
        r"\end{table*}",
        "",
    ]
    return "\n".join(L)
 
 
# ── Main ──────────────────────────────────────────────────────────────────────
 
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input",   "-i", default="/home/ihossain/ISMAIL/SUPREMELAB/AgentSkillBench/data/agentskillbench_full_leaderboard.csv")
    p.add_argument("--output",  "-o", default="/home/ihossain/ISMAIL/SUPREMELAB/AgentSkillBench/results/dataset_overview_table.tex")
    p.add_argument("--caption", default="Model-wise Dataset Overview across LLM Evaluators on AgentSkillBench.")
    p.add_argument("--label",   default="tab:dataset_overview")
    return p.parse_args()

def main():
    args = parse_args()
    path = Path(args.input)
    if not path.exists():
        sys.exit(f"[error] Not found: {path}")
 
    df = pd.read_csv(path)
    print(f"[info] Loaded {len(df)} rows from '{path.name}'")
 
    required = ["model_name","overall_risk","is_vulnerable",
                "vulnerability_count","cvss_base_score","sars_score"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        sys.exit(f"[error] Missing columns: {missing}")
 
    model_names  = sorted(df["model_name"].dropna().unique().tolist())
    model_labels = [shorten_model(m) for m in model_names]
    n_skills     = df.groupby("model_name")["skill_name"].nunique().to_dict() \
                   if "skill_name" in df.columns else {}
    print(f"[info] Models ({len(model_names)}): {model_labels}")
    for m, lbl in zip(model_names, model_labels):
        n = n_skills.get(m, len(df[df["model_name"]==m]))
        print(f"         {lbl}: {n} skills")
 
    metric_rows = make_metric_rows(df)
    latex = build_latex(model_names, model_labels, df, metric_rows,
                        args.caption, args.label)
 
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(latex, encoding="utf-8")
        print(f"[v] Written to: {out}")
    else:
        print("\n" + "-"*72)
        print(latex)
        print("-"*72)
 
if __name__ == "__main__":
    main()