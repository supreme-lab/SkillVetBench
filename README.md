# 🔐 SkillVetBench — Dual-Metric Security Evaluation Framework for Agentic AI Skills

> A comprehensive security evaluation leaderboard and benchmark framework for assessing the safety and security of agentic AI tool-use skills.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
![Status: Active](https://img.shields.io/badge/status-active-green.svg)

---

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/yourusername/skillvetbench_github.git
cd skillvetbench_github

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set API key (example: Anthropic)
export ANTHROPIC_API_KEY=sk-ant-...

# 4. Start web server (http://localhost:8000)
python server.py

# 5. Or evaluate directly in Python
python -c "from evaluator import SkillEvaluator; from llm_client import LLMClient; 
llm = LLMClient(); report = SkillEvaluator(llm).evaluate_skill('skills/SKILL1.md');
print(f'SARS: {report.sars.score}, CVSS: {report.cvss.score}')"
```

**[→ Detailed Installation Guide](docs/INSTALLATION.md)**

---

## What Is This?

Agentic AI systems use **skills** — Markdown files that instruct Large Language Models (LLMs) to call external APIs, execute shell commands, read/write files, or interact with services. Unlike traditional software vulnerabilities, skill-based attacks don't require a bug—they exploit the LLM's interpretation of its own instructions.

**SkillVetBench** automatically audits skill files using a **two-metric approach**:

1. **SARS** — Skill Agentic Risk Score (purpose-built for agentic skills)
2. **CVSS v4.0** — Common Vulnerability Scoring System (industry-standard for comparison)

Every skill is evaluated by an LLM that produces a structured JSON report with vulnerability cards, attack scenarios, remediation guidance, and full metric breakdowns.

---

## Key Features

### 📊 Dual-Metric Scoring
- **SARS** (0–10): Captures agentic-specific risks (prompt injection, data gravity, irreversibility, blast radius, chain amplification)
- **CVSS v4.0** (0–10): Industry-standard vulnerability scoring for cross-reference
- Both metrics run simultaneously on every skill

### 🧠 Multi-LLM Support
- **Anthropic Claude** (recommended)
- **OpenAI GPT-4o** and variants
- **HuggingFace API** (serverless)
- **HuggingFace Local** (GPU inference)
- **Ollama** (local inference)

### 🎯 Interactive Leaderboard
- Sort by SARS, CVSS, risk level, attack category
- Compare models and skills side-by-side
- Click metrics for detailed definitions and explanations
- Background job evaluation with status polling

### 🔍 Detailed Vulnerability Reports
- 12 vulnerability categories (injection, RCE, exfiltration, etc.)
- Per-finding vulnerability cards
- Attack scenarios and exploitation paths
- Prioritized remediation steps

### 📈 Batch Evaluation
- Evaluate single skills or entire directories
- Asynchronous job queuing
- Export results as JSON/CSV
- Compare evaluation results across models

---

## Directory Structure

```
skillvetbench_github/
├── README.md                    ← You are here
├── requirements.txt              ← Python dependencies
├── LICENSE                       ← MIT License
│
├── docs/                         ← 📖 DOCUMENTATION (START HERE)
│   ├── README.md                 ← Documentation index
│   ├── QUICK_REFERENCE.md        ← 5-min cheat sheet
│   ├── INSTALLATION.md           ← Setup instructions
│   ├── USAGE.md                  ← Web UI & API guide
│   ├── SARS_GUIDE.md             ← Methodology deep-dive
│   ├── RESEARCH_GUIDE.md         ← Extending the framework
│   └── CONTRIBUTING.md           ← How to contribute
│
├── scripts/                      ← 🛠️ UTILITY SCRIPTS (NEW)
│   ├── README.md                 ← Scripts guide & workflows
│   ├── analysis/                 ← Analysis & visualization
│   │   ├── README.md
│   │   ├── benchmark_overview.py
│   │   ├── evaluation_analysis.py
│   │   ├── generate_results.py
│   │   └── tool_multiplier_analysis.py
│   ├── integration/              ← Data integration tools
│   │   ├── README.md
│   │   ├── clawhub_scrapper.py
│   │   ├── clawhub_fetch.py
│   │   └── clawhavoc_scanner.py
│   └── utilities/                ← Helper utilities
│       ├── README.md
│       ├── check_gpu.py
│       └── slug_match.py
│
├── config/                       ← Configuration examples
│   └── README.md
│
├── Core Evaluation Engine        ← 🔧 Main application
│   ├── server.py                 ← FastAPI web server
│   ├── evaluator.py              ← Skill evaluation pipeline
│   ├── llm_client.py             ← Multi-backend LLM interface
│   ├── storage.py                ← Results persistence
│   └── templates.html            ← Web UI (HTML/CSS/JS)
│
├── Scoring Metrics               ← Risk scoring modules
│   ├── sars.py                   ← SARS (5 dimensions)
│   ├── cvss4_0.py                ← CVSS v4.0 MacroVector
│   ├── cvss3_5.py                ← CVSS v3.5 (legacy)
│   └── metrics.json              ← CVSS metric definitions
│
├── Prompt Engineering            ← LLM evaluation prompts
│   ├── prompts_cvss4_0.py        ← CVSS evaluation prompt
│   ├── prompts_clawhub.py        ← ClawHub integration
│   └── references.txt            ← Metric references
│
├── Data & Skills                 ← Example data
│   ├── skills/                   ← Example skills (SKILL1-10.md)
│   ├── data/                     ← Sample datasets
│   └── evaluation_outputs/       ← Analysis results (generated)
│
├── Resources                     ← Media & assets
│   ├── images/                   ← Architecture diagrams
│   └── leaderboard.gif           ← UI preview
│
└── Dockerfile                    ← Container configuration
```

---

## System Architecture

![System Architecture Diagram](resources/System-Architecture.png)

The evaluation pipeline works as follows:

1. **Skill Ingestion** — Load skill Markdown files from `skills/` directory
2. **LLM Evaluation** — Send skill to selected LLM backend with structured prompt
3. **Dual Scoring** — LLM simultaneously scores SARS (5 dimensions) and CVSS v4.0 (9 metrics)
4. **Vulnerability Analysis** — LLM identifies 12+ vulnerability categories with attack scenarios
5. **Storage** — Results persisted as JSON with full metadata
6. **Visualization** — Web UI renders leaderboard, details, and interactive metric popups

---

## Usage Guide

### Web Interface (Recommended)

```bash
# Start server on port 8000 (default)
python server.py

# Or specify model and backend
python server.py --api anthropic --model claude-sonnet-4-6

# Custom ports and directories
python server.py --port 9000 --skills-dir my_skills/ --reports-dir my_reports/
```

Then open **http://localhost:8000** in your browser.

**Features**:
- Browse all evaluated skills
- Sort by SARS, CVSS, risk level, attack category
- Click metric cells for detailed explanations
- View vulnerability cards with remediation steps
- Submit new evaluations asynchronously

### Command-Line API

```python
from evaluator import SkillEvaluator
from llm_client import LLMClient

# Initialize
llm = LLMClient(api="anthropic", model="claude-sonnet-4-6")
evaluator = SkillEvaluator(llm)

# Evaluate single skill
report = evaluator.evaluate_skill("skills/SKILL1.md")
print(f"SARS: {report.sars.score}")
print(f"CVSS: {report.cvss.score}")
print(f"Dimensions: IFR={report.sars.dimensions.ifr}, BR={report.sars.dimensions.br}")
```

### Batch Evaluation

```python
from pathlib import Path
from storage import ReportStorage

storage = ReportStorage("reports/")

for skill_file in Path("skills/").glob("*.md"):
    report = evaluator.evaluate_skill(skill_file)
    storage.save_report(report)

# Load all reports
all_reports = storage.load_all_reports()
high_risk = [r for r in all_reports if r.sars.score >= 7.0]
```

**[→ Full Usage Guide](docs/USAGE.md)**

---

## SARS Methodology

### Overview

SARS is a 0–10 composite score purpose-built for evaluating agentic AI skill files. It measures **five dimensions** that traditional CVSS cannot model:

| Dimension | Weight | Description |
|-----------|--------|-------------|
| **IFR** — Instruction Fidelity Risk | 2.0 | How easily can prompt injection manipulate the skill? |
| **DG** — Data Gravity | 1.5 | How sensitive is the data the skill can access? |
| **AI** — Action Irreversibility | 1.5 | Can the skill's actions be undone? (GET vs. DELETE) |
| **BR** — Blast Radius | 2.0 | How many users/systems are affected by one exploitation? |
| **CA** — Chain Amplification | 2.0 | Does combining this skill with others multiply danger? |

### Formula

```
SARS = (2.0 × IFR + 1.5 × DG + 1.5 × AI + 2.0 × BR + 2.0 × CA) / 2.7
```

### Worked Example

**Slack Messaging Skill** (sends user-controlled text to shared channel):
- IFR=3 (message flows directly into API)
- DG=1 (internal but not secrets)
- AI=3 (sent messages can't be unsent)
- BR=2 (all channel members affected)
- CA=2 (chainable with file-reader for exfiltration)

```
SARS = (6.0 + 1.5 + 4.5 + 4.0 + 4.0) / 2.7 = 7.4 → HIGH
```

**[→ Complete SARS Guide](docs/SARS_GUIDE.md)**

---

## CVSS v4.0 Metrics

CVSS v4.0 is scored alongside SARS for industry-standard comparison. The following metrics are evaluated:

**Exploitability**:
- **AT** — Attack Requirements (0–1)
- **PR** — Privileges Required (0–1–2)
- **UI** — User Interaction (0–1)

**Vulnerable System Impact**:
- **VC/VI/VA** — Confidentiality/Integrity/Availability (0–1–2–3)

**Downstream System Impact**:
- **SC/SI/SA** — Downstream Confidentiality/Integrity/Availability (0–1–2–3)

**Threat**:
- **E** — Exploit Maturity (X–A–P–F–U)

**Excluded**: AV (Attack Vector) and AC (Attack Complexity) — skills are universally network-exposed.

---

## Supported LLM Backends

| Backend | Command | Requirements | Notes |
|---------|---------|--------------|-------|
| **Anthropic Claude** | `--api anthropic` | `ANTHROPIC_API_KEY` | ⭐ Recommended; best JSON output |
| **OpenAI GPT** | `--api openai` | `OPENAI_API_KEY` | GPT-4o, GPT-4o-mini |
| **HuggingFace API** | `--api hf_api` | `HF_TOKEN` | Serverless inference |
| **HuggingFace Local** | `--api hf_local` | GPU, models via transformers | Local GPU inference |
| **Ollama** | `--api ollama` | Ollama server running | Open-source models |

```bash
# Anthropic Claude (recommended)
python server.py --api anthropic --model claude-sonnet-4-6

# OpenAI GPT-4o
python server.py --api openai --model gpt-4o

# HuggingFace Qwen
python server.py --api hf_api --model Qwen/Qwen2.5-14B-Instruct

# Local Mistral
python server.py --api hf_local --model mistral/Mistral-7B-Instruct-v0.1 --device cuda
```

---

## Vulnerability Categories

The evaluator detects 12 vulnerability types:

1. **Command/Shell Injection** — `os.system()`, `subprocess`, shell operators
2. **Unsafe File Operations** — Path traversal, write to system dirs
3. **Remote Code Execution** — `eval()`, `pickle.loads()`, unsafe deserialization
4. **Data Exfiltration** — HTTP to external URLs, email sending
5. **Dependency/Supply Chain** — `pip install`, non-standard registries
6. **Prompt Injection** — External content processed as instructions
7. **Privilege Escalation** — `sudo`, admin instructions
8. **Credential Exposure** — Hardcoded keys, logging secrets
9. **Indirect/Embedded Injection** — Processing emails/documents as instructions
10. **Scope Creep** — Over-privileged tool use, "access all" patterns
11. **Insecure Deserialization** — `pickle`, `yaml.load` without entity protection
12. **Log/Output Injection** — User input written to logs unsanitized

---

## For Researchers

SkillVetBench is designed for research on agentic AI security. Key areas:

### 1. **SARS Validation**
- How well does SARS predict real-world exploits?
- Does SARS transfer across skill domains?
- Optimal weight tuning for different use cases?

### 2. **Model Comparison**
- How do different LLMs score the same skill?
- Inter-rater agreement on SARS dimensions?
- Prompt sensitivity analysis

### 3. **Compositional Risk**
- What skill chains are most dangerous?
- Can CA scores predict emergent attacks?
- Dependency graph analysis

### 4. **Evaluation Calibration**
- Expert vs. automated scoring comparison
- Few-shot vs. zero-shot evaluation performance
- Prompt template optimization

### 5. **Custom Extensions**
- Add new dimensions or metrics
- Create domain-specific vulnerabilities
- Integrate external threat intelligence

**[→ Research Extension Guide](docs/RESEARCH_GUIDE.md)**

---

## Examples

### Example 1: Evaluate All Skills

```bash
# Batch evaluate all skills in directory
python server.py --api anthropic --model claude-sonnet-4-6

# Visit http://localhost:8000 → leaderboard shows all results
```

### Example 2: Compare Models

```bash
# Evaluate same skill with multiple models
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all
python server.py --api openai --model gpt-4o --eval-all

# Results stored separately; compare via web UI
```

### Example 3: Analyze Results

```python
from storage import ReportStorage
from pathlib import Path

storage = ReportStorage("reports/")
reports = storage.load_all_reports()

# Find high-risk skills
high_risk = [r for r in reports if r.sars.score >= 7.0]
print(f"High-risk skills: {len(high_risk)}")

# Breakdown by attack category
by_category = {}
for report in reports:
    for cat in report.vulnerability_categories:
        by_category[cat] = by_category.get(cat, 0) + 1

for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
    print(f"{cat}: {count}")
```

### Example 4: Custom Scoring

```python
# Add custom metrics to evaluation
from evaluator import SkillEvaluator
from llm_client import LLMClient

class CustomEvaluator(SkillEvaluator):
    def evaluate_skill(self, skill_path):
        report = super().evaluate_skill(skill_path)
        
        # Add custom analysis
        report.custom_metrics = {
            "file_operations": self.count_file_ops(skill_path),
            "network_calls": self.count_network_calls(skill_path)
        }
        
        return report
```

---

## 🛠️ Scripts & Tools

SkillVetBench includes utility scripts for analysis, integration, and data management. See the complete guide at **[scripts/README.md](scripts/README.md)**.

### Quick Script Reference

| Goal | Script | Command | Time |
|------|--------|---------|------|
| Check GPU availability | `check_gpu.py` | `python scripts/utilities/check_gpu.py` | 10s |
| Generate statistics | `evaluation_analysis.py` | `python scripts/analysis/evaluation_analysis.py` | 2m |
| Create visualizations | `generate_results.py` | `python scripts/analysis/generate_results.py` | 5m |
| Export comparison table | `benchmark_overview.py` | `python scripts/analysis/benchmark_overview.py` | 2m |
| Analyze skill chains | `tool_multiplier_analysis.py` | `python scripts/analysis/tool_multiplier_analysis.py` | 3m |
| Download ClawHub skills | `clawhub_scrapper.py` | `python scripts/integration/clawhub_scrapper.py` | 10m |
| Scan for malware patterns | `clawhavoc_scanner.py` | `python scripts/integration/clawhavoc_scanner.py` | 1m |

### Common Analysis Workflows

#### Workflow 1: Full Analysis Pipeline (2 hours)

```bash
# 1. Check GPU
python scripts/utilities/check_gpu.py

# 2. Evaluate all skills
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 3. Generate statistics
python scripts/analysis/evaluation_analysis.py --summary

# 4. Create visualizations
python scripts/analysis/generate_results.py

# 5. Export comparison table
python scripts/analysis/benchmark_overview.py --input reports.csv

# 6. Analyze skill chains
python scripts/analysis/tool_multiplier_analysis.py --generate-matrix

# Results saved to: evaluation_outputs/
```

#### Workflow 2: ClawHub Integration (1 hour)

```bash
# 1. Download ClawHub skills
python scripts/integration/clawhub_scrapper.py

# 2. Scan for patterns
python scripts/integration/clawhavoc_scanner.py --clawhub

# 3. Move to evaluation directory
cp data/clawhub_skills/* skills/

# 4. Evaluate with SkillVetBench
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 5. Compare with ClawHub verdicts
python scripts/analysis/evaluation_analysis.py --compare-with-clawhub
```

#### Workflow 3: Multi-Model Comparison (3 hours)

```bash
# 1. Evaluate with Anthropic
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 2. Evaluate with OpenAI
python server.py --api openai --model gpt-4o --eval-all

# 3. Evaluate with HuggingFace
python server.py --api hf_api --model Qwen/Qwen2.5-14B-Instruct --eval-all

# 4. Generate comparison tables
python scripts/analysis/benchmark_overview.py --input reports.csv --compare-models

# 5. Statistical comparison
python scripts/analysis/evaluation_analysis.py --compare-models
```

### Script Organization

```
scripts/
├── README.md                        ← Complete scripts guide
├── analysis/                        ← Statistical analysis & visualization
│   ├── README.md
│   ├── benchmark_overview.py        ← Generate LaTeX comparison tables
│   ├── evaluation_analysis.py       ← Statistical analysis & summaries
│   ├── generate_results.py          ← Create charts & visualizations
│   └── tool_multiplier_analysis.py  ← Analyze skill chain risks
├── integration/                     ← Data integration tools
│   ├── README.md
│   ├── clawhub_scrapper.py          ← Fetch & enrich ClawHub skills
│   ├── clawhub_fetch.py             ← ClawHub API client
│   └── clawhavoc_scanner.py         ← Malware pattern detection
└── utilities/                       ← Helper utilities
    ├── README.md
    ├── check_gpu.py                 ← Check GPU availability
    └── slug_match.py                ← Normalize skill identifiers
```

**Full guide:** [scripts/README.md](scripts/README.md)  
**Analysis details:** [scripts/analysis/README.md](scripts/analysis/README.md)  
**Integration guide:** [scripts/integration/README.md](scripts/integration/README.md)  
**Utilities:** [scripts/utilities/README.md](scripts/utilities/README.md)

---

## Performance Notes

- **Single skill evaluation**: 30–60 seconds (varies by LLM)
- **Batch evaluation**: ~1 minute per 5 skills (parallel processing supported)
- **GPU memory** (HuggingFace local): 8GB+ for 7B models, 16GB+ for 13B+
- **API costs**: Varies by backend ($0.02–$0.10 per skill evaluation)

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| API key error | Verify `export ANTHROPIC_API_KEY=sk-ant-...` |
| GPU out of memory | Use smaller model or enable 4-bit quantization |
| Slow evaluations | Switch to faster LLM or reduce batch size |
| Reports not saving | Check permissions on `reports/` directory |

**[→ Full Installation Guide](docs/INSTALLATION.md)**

---

## Citation

If you use SkillVetBench in your research, please cite:

```bibtex
@software{skillvetbench2024,
  title={SkillVetBench: Dual-Metric Security Evaluation Framework for Agentic AI Skills},
  author={Your Name},
  year={2024},
  url={https://github.com/yourusername/skillvetbench_github}
}
```

---

## Contributing

Contributions welcome! Areas we'd love help with:

- [ ] Additional LLM backend integrations
- [ ] New vulnerability categories
- [ ] Custom SARS dimension research
- [ ] ClawHub skill expansion
- [ ] Performance optimizations
- [ ] Documentation & tutorials

See [RESEARCH_GUIDE.md](docs/RESEARCH_GUIDE.md) for extension patterns.

---

## License

[MIT License](LICENSE) — See LICENSE file for details.

CVSS v4.0 is implemented per the [FIRST specification](https://www.first.org/cvss/v4.0/specification-document).  
CVSS is a registered trademark of FIRST.Org, Inc. and used by permission.

---

## Resources

- 📖 **[SARS Methodology Guide](docs/SARS_GUIDE.md)** — Deep dive into scoring dimensions
- 🔧 **[Research Extension Guide](docs/RESEARCH_GUIDE.md)** — Customize and extend the framework
- 🚀 **[Usage Guide](docs/USAGE.md)** — Web UI and API usage
- ⚙️ **[Installation Guide](docs/INSTALLATION.md)** — Setup on any platform

---

## Questions?

- **Bug reports**: Open an issue on GitHub
- **Feature requests**: Discussions tab
- **Usage questions**: Check documentation first
- **Research collaboration**: Open an issue to discuss

---

**Made with 🔐 for agentic AI security research.**
