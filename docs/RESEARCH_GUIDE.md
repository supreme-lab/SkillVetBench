# Researcher's Extension Guide

## Customizing the Evaluation Framework

SkillVetBench is designed to be extensible. Here's how researchers can modify and extend it for custom evaluations.

## 1. Adding Custom Scoring Metrics

### Create a New Metric Module

```python
# custom_metrics.py
from dataclasses import dataclass
from typing import Dict

@dataclass
class CustomMetric:
    """Your custom metric definition"""
    name: str
    description: str
    weight: float
    
    def calculate(self, skill_content: str, llm_response: Dict) -> float:
        """Calculate metric score from 0-10"""
        pass

def evaluate_custom_metric(skill_content: str) -> float:
    """Main evaluation function"""
    # Implementation
    pass
```

### Integrate into Evaluator

Modify `evaluator.py` to use your custom metric:

```python
from custom_metrics import evaluate_custom_metric

class SkillEvaluator:
    def evaluate_skill(self, skill_path):
        # ... existing code ...
        
        # Add custom metric
        custom_score = evaluate_custom_metric(skill_content)
        report.custom_metrics = {"my_metric": custom_score}
        
        return report
```

---

## 2. Adding New Vulnerability Categories

### Extend Vulnerability Detection

1. **Edit `prompts_cvss4_0.py`** — Add new categories to the LLM prompt:

```python
VULNERABILITY_CATEGORIES = [
    # ... existing categories ...
    {
        "id": "custom_001",
        "name": "Your Custom Vulnerability",
        "description": "Detection pattern description",
        "patterns": ["pattern1", "pattern2"]
    }
]
```

2. **Update Vulnerability Card Display** — Modify `templates.html` to show new category badges

```javascript
const categoryMap = {
    // ... existing ...
    "custom_001": { color: "purple", icon: "⚠️", label: "Custom Risk" }
};
```

---

## 3. Creating Custom LLM Clients

### Add Support for New LLM Providers

```python
# llm_client.py
class CustomLLMClient(BaseLLMClient):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        
    def evaluate_skill(self, prompt: str) -> Dict:
        """Call your custom API"""
        response = your_api_call(
            prompt=prompt,
            model=self.model,
            api_key=self.api_key
        )
        return response.json()

# Register in llm_client.py factory
LLM_PROVIDERS["custom"] = CustomLLMClient
```

---

## 4. Modifying Evaluation Workflows

### Create Custom Evaluation Pipeline

```python
# custom_evaluator.py
from evaluator import SkillEvaluator
from storage import ReportStorage

class ResearchEvaluator(SkillEvaluator):
    def __init__(self, llm, enable_parallel=True):
        super().__init__(llm)
        self.enable_parallel = enable_parallel
        
    def evaluate_batch(self, skill_files):
        """Parallel skill evaluation"""
        if self.enable_parallel:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = executor.map(self.evaluate_skill, skill_files)
                return list(results)
        else:
            return [self.evaluate_skill(f) for f in skill_files]
    
    def analyze_results(self, reports):
        """Custom analysis on evaluation results"""
        # Your analysis logic
        pass
```

### Usage

```python
llm = LLMClient(api="anthropic", model="claude-sonnet-4-6")
evaluator = ResearchEvaluator(llm, enable_parallel=True)
reports = evaluator.evaluate_batch(skill_files)
analysis = evaluator.analyze_results(reports)
```

---

## 5. Querying & Analyzing Results

### Using the Storage API

```python
from storage import ReportStorage

storage = ReportStorage("reports/")

# Load all reports
all_reports = storage.load_all_reports()

# Filter by criteria
high_risk = [r for r in all_reports if r.sars.score >= 7.0]
with_injection = [r for r in all_reports 
                  if "prompt_injection" in r.vulnerability_categories]

# Generate statistics
avg_sars = sum(r.sars.score for r in all_reports) / len(all_reports)
avg_cvss = sum(r.cvss.score for r in all_reports) / len(all_reports)

print(f"Average SARS: {avg_sars:.2f}")
print(f"Average CVSS: {avg_cvss:.2f}")
```

---

## 6. Comparative Analysis

### Comparing Multiple Models

```python
from llm_client import LLMClient
from evaluator import SkillEvaluator
from storage import ReportStorage

models = ["claude-sonnet-4-6", "gpt-4o", "mistral/Mistral-7B-Instruct"]

for model_name in models:
    if "gpt-4" in model_name:
        llm = LLMClient(api="openai", model=model_name)
    elif "mistral" in model_name:
        llm = LLMClient(api="hf_api", model=model_name)
    else:
        llm = LLMClient(api="anthropic", model=model_name)
    
    evaluator = SkillEvaluator(llm)
    
    for skill_file in skill_files:
        report = evaluator.evaluate_skill(skill_file)
        storage.save_report(report, model_name)
```

Then analyze differences:

```python
# Compare SARS/CVSS across models
comparisons = {}
for model_name in models:
    reports = storage.load_reports_by_model(model_name)
    comparisons[model_name] = {
        "avg_sars": sum(r.sars.score for r in reports) / len(reports),
        "avg_cvss": sum(r.cvss.score for r in reports) / len(reports)
    }

for model, stats in comparisons.items():
    print(f"{model}: SARS={stats['avg_sars']:.2f}, CVSS={stats['avg_cvss']:.2f}")
```

---

## 7. Integrating External Data

### Adding Skill Metadata

Create `skill_metadata.json`:

```json
{
  "SKILL1.md": {
    "source": "clawhub",
    "author": "example_user",
    "category": "file_operations",
    "deployment_date": "2024-01-15",
    "prior_incidents": 0
  }
}
```

Use in analysis:

```python
import json

with open("skill_metadata.json") as f:
    metadata = json.load(f)

for report in all_reports:
    skill_name = report.skill_name
    if skill_name in metadata:
        report.metadata = metadata[skill_name]
```

---

## 8. Export & Visualization

### Export Results to CSV

```python
import csv

with open("results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Skill", "SARS", "CVSS", "Model", "IFR", "DG", "AI", "BR", "CA"])
    
    for report in all_reports:
        writer.writerow([
            report.skill_name,
            report.sars.score,
            report.cvss.score,
            report.model,
            report.sars.dimensions.ifr,
            report.sars.dimensions.dg,
            report.sars.dimensions.ai,
            report.sars.dimensions.br,
            report.sars.dimensions.ca
        ])
```

### Statistical Analysis

```python
import numpy as np
from scipy import stats

# SARS/CVSS correlation
sars_scores = [r.sars.score for r in all_reports]
cvss_scores = [r.cvss.score for r in all_reports]

correlation, p_value = stats.pearsonr(sars_scores, cvss_scores)
print(f"SARS-CVSS Correlation: {correlation:.3f} (p={p_value:.4f})")
```

---

## Research Use Cases

### 1. Benchmark Reproducibility
```bash
# Re-evaluate all skills with same model
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all
```

### 2. Model Comparison Study
```bash
# Run evaluation across multiple models
for model in claude-sonnet-4-6 gpt-4o mistral/Mistral-7B; do
  python server.py --model $model --eval-all
done
```

### 3. Prompt Engineering Experiments
Modify prompts in `prompts_cvss4_0.py` and re-evaluate to measure impact.

### 4. Custom Metrics Research
Add new dimensions to `sars.py`, re-evaluate, and analyze correlation with real-world incidents.

---

## Contributing Back

Found improvements? Consider:
1. Creating a new branch for your extension
2. Testing on multiple skills
3. Submitting a PR with documentation
4. Sharing your results in research publications
