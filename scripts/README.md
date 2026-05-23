# Scripts Guide

Complete guide to all scripts in SkillVetBench. Choose based on what you want to do.

## 🎯 Quick Navigation

### I want to... → Run this script

| Goal | Script | Time | Command |
|------|--------|------|---------|
| **Evaluate skills** | server.py | ongoing | `python server.py` |
| **Check GPU availability** | check_gpu.py | 10s | `python scripts/utilities/check_gpu.py` |
| **Download ClawHub skills** | clawhub_scrapper.py | 5m | `python scripts/integration/clawhub_scrapper.py` |
| **Analyze evaluation results** | evaluation_analysis.py | 2m | `python scripts/analysis/evaluation_analysis.py` |
| **Generate visualizations** | generate_results.py | 5m | `python scripts/analysis/generate_results.py` |
| **Generate comparison tables** | benchmark_overview.py | 2m | `python scripts/analysis/benchmark_overview.py` |
| **Analyze skill chains** | tool_multiplier_analysis.py | 3m | `python scripts/analysis/tool_multiplier_analysis.py` |
| **Scan for malware patterns** | clawhavoc_scanner.py | 1m | `python scripts/integration/clawhavoc_scanner.py` |
| **Normalize skill names** | slug_match.py | 10s | `python scripts/utilities/slug_match.py` |

---

## 📁 Script Organization

```
skillvetbench_github/
├── server.py                              ← MAIN: Web interface & evaluation server
├── evaluator.py                           ← MAIN: Evaluation engine
├──
├── scripts/                               ← ALL SCRIPTS
│   ├── README.md                          ← This file
│   │
│   ├── analysis/                          ← ANALYSIS & REPORTING
│   │   ├── README.md                      ← Analysis guide
│   │   ├── benchmark_overview.py          ← Generate LaTeX tables
│   │   ├── evaluation_analysis.py         ← Statistical analysis
│   │   ├── generate_results.py            ← Visualizations & charts
│   │   └── tool_multiplier_analysis.py    ← Skill chain risk analysis
│   │
│   ├── integration/                       ← DATA INTEGRATION
│   │   ├── README.md                      ← Integration guide
│   │   ├── clawhub_scrapper.py            ← Fetch ClawHub skills
│   │   ├── clawhub_fetch.py               ← ClawHub API client
│   │   └── clawhavoc_scanner.py           ← Malware pattern detection
│   │
│   └── utilities/                         ← HELPER UTILITIES
│       ├── README.md                      ← Utilities guide
│       ├── check_gpu.py                   ← GPU availability
│       └── slug_match.py                  ← Skill ID normalization
│
└── eval/                                  ← LEGACY (use scripts/analysis/ instead)
    └── (scripts moved to scripts/analysis/)
```

---

## 🚀 Common Workflows

### Workflow 1: Quick Evaluation (30 minutes)

```bash
# 1. Check GPU
python scripts/utilities/check_gpu.py

# 2. Start server
python server.py --api anthropic --model claude-sonnet-4-6

# 3. Go to http://localhost:8000
# 4. Evaluate skills via web UI
```

---

### Workflow 2: Full Analysis Pipeline (2 hours)

```bash
# 1. Check GPU
python scripts/utilities/check_gpu.py

# 2. Evaluate all skills
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 3. Statistical analysis
python scripts/analysis/evaluation_analysis.py --summary

# 4. Generate visualizations
python scripts/analysis/generate_results.py

# 5. Generate comparison table
python scripts/analysis/benchmark_overview.py --input reports.csv

# 6. Analyze skill chains
python scripts/analysis/tool_multiplier_analysis.py --generate-matrix

# Results in: evaluation_outputs/
```

---

### Workflow 3: ClawHub Integration (1 hour)

```bash
# 1. Download ClawHub skills
python scripts/integration/clawhub_scrapper.py

# 2. Scan for patterns
python scripts/integration/clawhavoc_scanner.py --clawhub

# 3. Move skills to eval directory
cp data/clawhub_skills/* skills/

# 4. Evaluate
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 5. Compare with ClawHub verdicts
python scripts/analysis/evaluation_analysis.py --compare-with-clawhub
```

---

### Workflow 4: Multi-Model Comparison (3 hours)

```bash
# 1. Evaluate with Anthropic
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 2. Evaluate with OpenAI
python server.py --api openai --model gpt-4o --eval-all

# 3. Evaluate with HuggingFace
python server.py --api hf_api --model Qwen/Qwen2.5-14B-Instruct --eval-all

# 4. Generate comparison
python scripts/analysis/benchmark_overview.py --input reports.csv --compare-models
python scripts/analysis/evaluation_analysis.py --compare-models

# Results: evaluation_outputs/
```

---

## 📋 Script Details

### Core Scripts (in root directory)

#### server.py
**Web interface & evaluation engine**
```bash
python server.py                                    # Default: localhost:8000
python server.py --port 9000                       # Custom port
python server.py --api anthropic --model claude-sonnet-4-6  # Specify model
python server.py --skills-dir my_skills/           # Custom directory
python server.py --eval-all                        # Evaluate all skills
```

#### evaluator.py
**Programmatic evaluation (Python API)**
```python
from evaluator import SkillEvaluator
from llm_client import LLMClient

llm = LLMClient(api="anthropic")
evaluator = SkillEvaluator(llm)
report = evaluator.evaluate_skill("skills/SKILL1.md")
```

---

### Analysis Scripts

See [scripts/analysis/README.md](analysis/README.md) for full details.

| Script | Purpose | Time | Command |
|--------|---------|------|---------|
| **benchmark_overview.py** | LaTeX tables | 2m | `python scripts/analysis/benchmark_overview.py` |
| **evaluation_analysis.py** | Statistics | 2m | `python scripts/analysis/evaluation_analysis.py --summary` |
| **generate_results.py** | Visualizations | 5m | `python scripts/analysis/generate_results.py` |
| **tool_multiplier_analysis.py** | Chain risk | 3m | `python scripts/analysis/tool_multiplier_analysis.py` |

---

### Integration Scripts

See [scripts/integration/README.md](integration/README.md) for full details.

| Script | Purpose | Time | Command |
|--------|---------|------|---------|
| **clawhub_scrapper.py** | Download skills | 10m | `python scripts/integration/clawhub_scrapper.py` |
| **clawhub_fetch.py** | API client | varies | `python scripts/integration/clawhub_fetch.py` |
| **clawhavoc_scanner.py** | Malware detection | 1m | `python scripts/integration/clawhavoc_scanner.py` |

---

### Utility Scripts

See [scripts/utilities/README.md](utilities/README.md) for full details.

| Script | Purpose | Time | Command |
|--------|---------|------|---------|
| **check_gpu.py** | GPU check | 10s | `python scripts/utilities/check_gpu.py` |
| **slug_match.py** | ID normalization | 10s | `python scripts/utilities/slug_match.py` |

---

## 🔧 Script Arguments Reference

### Common Arguments

```bash
--help              Show usage information
--verbose           Verbose logging
--output DIR        Specify output directory
--api {anthropic|openai|hf_api|hf_local|ollama}  LLM backend
--model MODEL       Model name (e.g., claude-sonnet-4-6)
--device {cpu|cuda}  Device for local inference
```

### Analysis Scripts

```bash
--input FILE        Input CSV/JSON file
--summary           Generate summary statistics
--compare-models    Compare multiple models
--format {pdf|png|csv}  Output format
--reports-dir DIR   Directory with evaluation results
```

### Integration Scripts

```bash
--fetch-only        Fetch without enrichment
--enrich-only       Enrich existing data
--local DIR         Scan local directory
--clawhub           Scan ClawHub
--report FILE       Save report to file
```

---

## 📊 Output Locations

Results are saved to different locations based on script:

```
skillvetbench_github/
├── reports/                          ← Evaluation results (.json)
├── evaluation_outputs/               ← Analysis results
│   ├── tables/                       ← CSV/LaTeX tables
│   ├── charts/                       ← Visualizations (.png, .pdf)
│   ├── reports/                      ← Summary reports
│   └── data/                         ← Raw analysis data (.json)
└── data/                             ← Integration data
    ├── clawhub_skills.json
    ├── clawhub_enriched.json
    └── [other external data]
```

---

## 🐛 Troubleshooting

### Script Not Found
```bash
# Make sure you're in the right directory
cd /path/to/skillvetbench_github

# Verify script exists
ls scripts/analysis/evaluation_analysis.py

# Run with full path
python scripts/analysis/evaluation_analysis.py
```

### Dependencies Missing
```bash
# Install all requirements
pip install -r requirements.txt

# Or specific package
pip install pandas matplotlib seaborn
```

### Permission Denied
```bash
# Fix permissions
chmod +x scripts/analysis/*.py

# Or run with Python
python scripts/analysis/evaluation_analysis.py
```

### Module Not Found
```bash
# Make sure you're in project root
pwd  # should end with /skillvetbench_github

# Update PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Then run script
python scripts/analysis/evaluation_analysis.py
```

---

## 📖 Documentation

For each script category, see the detailed guide:
- **[Analysis Scripts](analysis/README.md)** — Statistical analysis & visualization
- **[Integration Scripts](integration/README.md)** — Data collection & enrichment
- **[Utility Scripts](utilities/README.md)** — Helpers & maintenance tools

For general documentation:
- **[Main README](../README.md)** — Project overview
- **[SARS Guide](../docs/SARS_GUIDE.md)** — Methodology
- **[Usage Guide](../docs/USAGE.md)** — Web UI & API
- **[Research Guide](../docs/RESEARCH_GUIDE.md)** — Custom extensions

---

## ✅ Pre-Flight Checklist

Before running scripts:

- [ ] Project installed: `pip install -r requirements.txt`
- [ ] API keys set: `export ANTHROPIC_API_KEY=sk-ant-...`
- [ ] Working directory correct: `pwd` ends with `skillvetbench_github`
- [ ] Skills directory exists: `ls skills/`
- [ ] Have sample skills: `ls skills/SKILL*.md`

---

## Next Steps

1. **First time?** → [Quick Reference](../docs/QUICK_REFERENCE.md)
2. **Want to evaluate?** → Run `python server.py`
3. **Want to analyze?** → See [Analysis Scripts](analysis/README.md)
4. **Want to integrate?** → See [Integration Scripts](integration/README.md)
5. **Need help?** → Check relevant README or `--help` flag

---

**Happy analyzing! 🚀**
