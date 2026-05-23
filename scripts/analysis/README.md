# Analysis Scripts

These scripts perform statistical analysis, comparison, and visualization of evaluation results.

## Overview

```
scripts/analysis/
├── README.md                       ← You are here
├── benchmark_overview.py           ← Generate overview statistics
├── evaluation_analysis.py           ← Statistical analysis of results
├── generate_results.py              ← Visualization & report generation
└── tool_multiplier_analysis.py      ← Skill chain risk analysis
```

---

## Scripts

### 1. benchmark_overview.py
**Purpose**: Generate LaTeX-formatted tables comparing models and skills

**Usage**:
```bash
# Generate LaTeX table
python scripts/analysis/benchmark_overview.py --input reports.csv

# Specify output file
python scripts/analysis/benchmark_overview.py --input reports.csv --output table.tex

# Display in terminal
python scripts/analysis/benchmark_overview.py --input reports.csv --display
```

**Output**:
- LaTeX table with model-wise statistics
- Per-model SARS/CVSS comparisons
- Average scores and rankings

**Requirements**: pandas, numpy

---

### 2. evaluation_analysis.py
**Purpose**: Statistical analysis of evaluation results

**Usage**:
```bash
# Analyze all reports
python scripts/analysis/evaluation_analysis.py

# Analyze specific directory
python scripts/analysis/evaluation_analysis.py --reports-dir reports/

# Generate statistical summary
python scripts/analysis/evaluation_analysis.py --summary

# Compare models
python scripts/analysis/evaluation_analysis.py --compare-models
```

**Output**:
- Mean/median/std dev for SARS and CVSS
- Distribution analysis by risk level
- Vulnerability category breakdown
- Model comparison statistics

**Requirements**: pandas, numpy, scipy, matplotlib

---

### 3. generate_results.py
**Purpose**: Generate visualizations and formatted reports

**Usage**:
```bash
# Generate all visualizations
python scripts/analysis/generate_results.py

# Generate specific visualization
python scripts/analysis/generate_results.py --plot histogram

# Export to specific format
python scripts/analysis/generate_results.py --format pdf

# Custom output directory
python scripts/analysis/generate_results.py --output evaluation_outputs/charts/
```

**Outputs**:
- Histogram of SARS/CVSS scores
- Risk level distribution pie chart
- Vulnerability category bar chart
- Model comparison scatter plots
- Summary PDF reports

**Requirements**: matplotlib, seaborn, reportlab

---

### 4. tool_multiplier_analysis.py
**Purpose**: Analyze chain amplification and skill composition risks

**Usage**:
```bash
# Analyze skill chains
python scripts/analysis/tool_multiplier_analysis.py

# Analyze specific skill combinations
python scripts/analysis/tool_multiplier_analysis.py --skills SKILL1.md SKILL2.md

# Generate chain risk matrix
python scripts/analysis/tool_multiplier_analysis.py --generate-matrix

# Output chain recommendations
python scripts/analysis/tool_multiplier_analysis.py --recommendations
```

**Output**:
- Dangerous skill chain identification
- Chain amplification scores (CA dimension analysis)
- Risk matrix showing which skills should not be combined
- Remediation recommendations for skill chains

**Requirements**: pandas, networkx

---

## Running Analysis Pipeline

### Complete Analysis Workflow

```bash
# 1. Evaluate all skills
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 2. Wait for evaluations to complete

# 3. Generate overview table
python scripts/analysis/benchmark_overview.py --input reports.csv --output results_table.tex

# 4. Statistical analysis
python scripts/analysis/evaluation_analysis.py --summary

# 5. Generate visualizations
python scripts/analysis/generate_results.py --format pdf

# 6. Analyze skill chains
python scripts/analysis/tool_multiplier_analysis.py --generate-matrix

# Results in: evaluation_outputs/
```

### Quick Analysis (5 minutes)

```bash
# Analyze existing reports
python scripts/analysis/evaluation_analysis.py --summary
```

### Comparison Study (30 minutes)

```bash
# Evaluate with multiple models
for model in claude-sonnet-4-6 gpt-4o mistral/Mistral-7B; do
  python server.py --api auto --model $model --eval-all
done

# Generate comparison tables
python scripts/analysis/benchmark_overview.py --input reports.csv --compare-models

# Statistical comparison
python scripts/analysis/evaluation_analysis.py --compare-models
```

---

## Output Files

Results are saved to `evaluation_outputs/`:

```
evaluation_outputs/
├── tables/
│   ├── model_comparison.tex
│   └── skill_statistics.csv
├── charts/
│   ├── sars_distribution.png
│   ├── vulnerability_breakdown.png
│   └── model_comparison.png
├── reports/
│   └── summary_report.pdf
└── data/
    ├── analysis_statistics.json
    └── chain_risk_matrix.json
```

---

## Python API (For Custom Analysis)

### Load Results

```python
from pathlib import Path
from storage import ReportStorage

storage = ReportStorage("reports/")
reports = storage.load_all_reports()
```

### Statistical Analysis

```python
import statistics as stats

sars_scores = [r.sars.score for r in reports]
mean = stats.mean(sars_scores)
median = stats.median(sars_scores)
stdev = stats.stdev(sars_scores)

print(f"SARS Mean: {mean:.2f}, Median: {median:.2f}, StdDev: {stdev:.2f}")
```

### Model Comparison

```python
from collections import defaultdict

by_model = defaultdict(list)
for report in reports:
    by_model[report.model].append(report)

for model, reports_for_model in by_model.items():
    avg_sars = sum(r.sars.score for r in reports_for_model) / len(reports_for_model)
    print(f"{model}: {avg_sars:.2f}")
```

### Vulnerability Analysis

```python
category_counts = defaultdict(int)
for report in reports:
    for vuln in report.vulnerabilities:
        category_counts[vuln['category']] += 1

for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
    print(f"{cat}: {count}")
```

---

## Customizing Analysis

To create custom analysis:

```python
# custom_analysis.py
from storage import ReportStorage

storage = ReportStorage("reports/")
reports = storage.load_all_reports()

# Your custom analysis here
high_risk = [r for r in reports if r.sars.score >= 7.0]
print(f"High-risk skills: {len(high_risk)}")

# Export results
import json
with open("evaluation_outputs/custom_analysis.json", "w") as f:
    json.dump({
        "total_skills": len(reports),
        "high_risk_count": len(high_risk),
        "average_sars": sum(r.sars.score for r in reports) / len(reports)
    }, f, indent=2)
```

Run with:
```bash
python custom_analysis.py
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: matplotlib` | `pip install matplotlib seaborn` |
| `No reports found` | Run `python server.py --eval-all` first |
| `Permission denied` | Check `evaluation_outputs/` directory permissions |
| Out of memory on large datasets | Process in batches or use smaller models |

---

## Next Steps

- Explore `evaluation_outputs/` for generated results
- Read SARS_GUIDE.md to understand methodology
- Check RESEARCH_GUIDE.md for custom metrics
- See ../integration/ for data collection scripts
