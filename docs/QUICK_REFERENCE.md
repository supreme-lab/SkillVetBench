# Quick Reference Card

## For Researchers Using SkillVetBench

### 🚀 Quick Start (5 Minutes)

```bash
# Clone
git clone https://github.com/yourusername/skillvetbench_github.git && cd skillvetbench_github

# Install
pip install -r requirements.txt && export ANTHROPIC_API_KEY=sk-ant-...

# Run
python server.py

# Open http://localhost:8000
```

---

## Command Cheat Sheet

### Start Web Server

```bash
python server.py                                    # Default: localhost:8000
python server.py --port 9000                       # Custom port
python server.py --api anthropic --model claude-sonnet-4-6  # Specify model
python server.py --skills-dir my_skills/ --reports-dir my_reports/  # Custom dirs
```

### Supported Backends

```bash
--api anthropic      # ⭐ Recommended
--api openai
--api hf_api
--api hf_local
--api ollama
```

### Required Environment Variables

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # Claude
export OPENAI_API_KEY=sk-...            # GPT
export HF_TOKEN=hf_...                  # HuggingFace
```

---

## Python API

### Basic Evaluation

```python
from evaluator import SkillEvaluator
from llm_client import LLMClient

llm = LLMClient(api="anthropic", model="claude-sonnet-4-6")
evaluator = SkillEvaluator(llm)
report = evaluator.evaluate_skill("skills/SKILL1.md")

print(f"SARS: {report.sars.score:.1f}")
print(f"CVSS: {report.cvss.score:.1f}")
```

### Batch Evaluation

```python
from pathlib import Path
from storage import ReportStorage

storage = ReportStorage("reports/")
for skill in Path("skills/").glob("*.md"):
    report = evaluator.evaluate_skill(skill)
    storage.save_report(report)
```

### Load Results

```python
reports = storage.load_all_reports()
high_risk = [r for r in reports if r.sars.score >= 7.0]
print(f"High-risk skills: {len(high_risk)}")
```

---

## SARS Scoring Quick Reference

| Dimension | Weight | Scale | What It Measures |
|-----------|--------|-------|------------------|
| **IFR** | 2.0 | 0-3 | Prompt injection surface |
| **DG** | 1.5 | 0-3 | Data sensitivity |
| **AI** | 1.5 | 0-3 | Action reversibility (GET vs DELETE) |
| **BR** | 2.0 | 0-3 | Users/systems affected |
| **CA** | 2.0 | 0-3 | Force multiplier when chained |

### Severity Bands

```
9.0-10.0  🔴 CRITICAL
7.0-8.9   🟠 HIGH
4.0-6.9   🟡 MEDIUM
0.1-3.9   🟢 LOW
```

### Calculate Manually

```python
ifr, dg, ai, br, ca = 3, 1, 3, 2, 2
sars = (2.0*ifr + 1.5*dg + 1.5*ai + 2.0*br + 2.0*ca) / 2.7
print(f"SARS: {sars:.1f}")  # Output: 7.4 HIGH
```

---

## Common Analysis Patterns

### Find Skills by Risk

```python
high_risk = [r for r in reports if r.sars.score >= 7.0]
medium_risk = [r for r in reports if 4.0 <= r.sars.score < 7.0]
low_risk = [r for r in reports if r.sars.score < 4.0]
```

### Find by Vulnerability Type

```python
prompt_injection = [r for r in reports if "prompt_injection" in r.vulnerability_categories]
rce = [r for r in reports if "remote_code_execution" in r.vulnerability_categories]
exfiltration = [r for r in reports if "data_exfiltration" in r.vulnerability_categories]
```

### Find by SARS Dimension

```python
high_ifr = [r for r in reports if r.sars.dimensions.ifr == 3]
high_chain_risk = [r for r in reports if r.sars.dimensions.ca == 3]
```

### Statistics

```python
import statistics as stats

sars_scores = [r.sars.score for r in reports]
cvss_scores = [r.cvss.score for r in reports]

print(f"SARS Mean: {stats.mean(sars_scores):.1f}")
print(f"SARS Median: {stats.median(sars_scores):.1f}")
print(f"CVSS Std Dev: {stats.stdev(cvss_scores):.2f}")
```

### Export to CSV

```python
import csv

with open("results.csv", "w") as f:
    writer = csv.writer(f)
    writer.writerow(["Skill", "SARS", "CVSS", "IFR", "BR", "CA"])
    for r in reports:
        writer.writerow([
            r.skill_name, r.sars.score, r.cvss.score,
            r.sars.dimensions.ifr, r.sars.dimensions.br, r.sars.dimensions.ca
        ])
```

---

## Output File Locations

```
skillvetbench_github/
├── reports/                    # Evaluation results
│   └── SKILL1_claude-sonnet-4-6.json
├── skills/                     # Input skills
│   └── SKILL1.md
└── evaluation_outputs/         # Analysis results
```

### Report JSON Structure

```json
{
  "skill_name": "SKILL1",
  "model": "claude-sonnet-4-6",
  "sars": {
    "score": 7.4,
    "severity": "HIGH",
    "dimensions": {
      "ifr": 3,
      "dg": 1,
      "ai": 3,
      "br": 2,
      "ca": 2
    }
  },
  "cvss": {
    "score": 7.8,
    "severity": "HIGH",
    "metrics": {...}
  },
  "vulnerabilities": [
    {
      "category": "prompt_injection",
      "severity": "HIGH",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| `API key error` | Check `export ANTHROPIC_API_KEY=sk-ant-...` |
| Server won't start | Try `python server.py --port 9000` |
| GPU memory error | Use smaller model: `--model claude-opus-4-7` |
| Slow evaluation | Use faster backend: `--api anthropic` |
| Reports not saving | Check directory permissions: `ls -la reports/` |

---

## Documentation Links

- 📖 **[SARS Guide](SARS_GUIDE.md)** — Deep dive into scoring methodology
- 🔧 **[Research Guide](RESEARCH_GUIDE.md)** — Extend and customize framework
- 🚀 **[Usage Guide](USAGE.md)** — Complete command/API reference
- ⚙️ **[Installation](INSTALLATION.md)** — Setup on different platforms
- 🤝 **[Contributing](CONTRIBUTING.md)** — How to contribute

---

## Dataset Info

**Example Skills**: 10 sample skills in `skills/` directory
- SKILL1-10.md cover various risk profiles
- Good for testing and demos
- See comments in each file for expected risk levels

**Sample Results**: `metrics.json` contains CVSS v4.0 metric definitions

---

## Key Research Papers & References

- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
- Agentic AI Security: (See `references.txt`)
- ClawHub: https://clawhub.ai / https://openclaw.ai

---

## Citation

```bibtex
@software{skillvetbench2024,
  title={SkillVetBench: Dual-Metric Security Evaluation Framework},
  author={Your Name},
  year={2024},
  url={https://github.com/yourusername/skillvetbench_github}
}
```

---

**Need help?** Check docs/ folder or open an issue on GitHub.
