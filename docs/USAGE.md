# Usage Guide

## Web Interface (Recommended for Researchers)

### Starting the Server

```bash
# Default — http://localhost:8000
python source_code/Backend/server.py

# Specify backend and model
python source_code/Backend/server.py --api anthropic --model claude-sonnet-4-6

# Custom port
python source_code/Backend/server.py --port 9000

# Custom skill and output directories
python source_code/Backend/server.py --skills-dir my_skills/ --reports-dir my_reports/
```

### Features Available in Web Interface

1. **Leaderboard View**
   - Sort by SARS score, CVSS score, risk level
   - Filter by attack category
   - Compare multiple models
   - View vulnerability counts

2. **Skill Details**
   - SARS metric breakdown (IFR, DG, AI, BR, CA)
   - CVSS v4.0 detailed scoring
   - Vulnerability cards with remediation steps
   - Attack scenarios and recommendations

3. **Background Evaluation**
   - Submit evaluations asynchronously
   - Monitor job status in real-time
   - Export results as JSON

## Command-Line Usage

### Single Skill Evaluation

```python
import sys
sys.path.insert(0, "source_code/utils")
sys.path.insert(0, "clawhub")
from evaluator import SkillEvaluator
from llm_client import LLMClient

# Initialize evaluator
llm = LLMClient(api="anthropic", model="claude-sonnet-4-6")
evaluator = SkillEvaluator(llm)

# Evaluate a skill
skill_path = "skills/SKILL1.md"
report = evaluator.evaluate_skill(skill_path)

# Access results
print(f"SARS Score: {report.sars.score}")
print(f"CVSS Score: {report.cvss.score}")
```

### Batch Evaluation

```python
import sys
sys.path.insert(0, "source_code/utils")
sys.path.insert(0, "clawhub")
from pathlib import Path
from evaluator import SkillEvaluator
from llm_client import LLMClient
from storage import ReportStorage

llm = LLMClient(api="anthropic", model="claude-sonnet-4-6")
evaluator = SkillEvaluator(llm)
storage = ReportStorage("reports/")

# Evaluate all skills
skills_dir = Path("skills/")
for skill_file in skills_dir.glob("*.md"):
    report = evaluator.evaluate_skill(skill_file)
    storage.save_report(report)
```

## Analysis Tools

### Evaluation Analysis

```bash
python eval/evaluation_analysis.py
```

### Generate Results & Visualizations

```bash
python eval/generate_results.py
```

### Benchmark Overview

```bash
python eval/benchmark_overveiw.py
```

## Supported LLM Backends

| Backend | Command | Requirements |
|---------|---------|--------------|
| Anthropic Claude | `--api anthropic` | `ANTHROPIC_API_KEY` |
| OpenAI GPT-4 | `--api openai` | `OPENAI_API_KEY` |
| HuggingFace API | `--api hf_api` | `HF_TOKEN` |
| HuggingFace Local | `--api hf_local` | GPU, Models via transformers |
| Ollama | `--api ollama` | Ollama server running |

### Example: Using Different Models

```bash
# GPT-4o
python source_code/Backend/server.py --api openai --model gpt-4o

# HuggingFace Qwen
python source_code/Backend/server.py --api hf_api --model Qwen/Qwen2.5-14B-Instruct

# Local inference with GPU
python source_code/Backend/server.py --api hf_local --model mistral/Mistral-7B-Instruct-v0.1 --device cuda
```

## Output Structure

Evaluation results are stored in JSON format:

```json
{
  "skill_name": "example_skill",
  "evaluated_at": "2024-05-23T10:30:00Z",
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
    "metrics": { ... }
  },
  "vulnerabilities": [ ... ]
}
```

## For Researchers

### Extending the Framework

1. **Add Custom Scoring Metrics**: Extend `source_code/utils/sars.py` or create a new file under `source_code/utils/`
2. **Add New Vulnerability Categories**: Modify `source_code/utils/prompts_cvss4_0.py`
3. **Create New LLM Clients**: Extend `source_code/utils/llm_client.py` with new backends
4. **Custom Evaluation Workflows**: Use `source_code/utils/evaluator.py` as a base class
