# Integration Scripts

These scripts integrate with external data sources and skill repositories like ClawHub.

## Overview

```
scripts/integration/
├── README.md                       ← You are here
├── clawhub_scrapper.py             ← Fetch & enrich ClawHub skills
├── clawhub_fetch.py                ← API client for ClawHub
└── clawhavoc_scanner.py            ← Malicious skill detection
```

---

## Scripts

### 1. clawhub_scrapper.py
**Purpose**: Fetch skills from ClawHub and enrich with threat intelligence

**Usage**:
```bash
# Full workflow (fetch + enrich)
python scripts/integration/clawhub_scrapper.py

# Fetch only
python scripts/integration/clawhub_scrapper.py --fetch-only

# Enrich only (use existing fetched data)
python scripts/integration/clawhub_scrapper.py --enrich-only

# Custom output directory
python scripts/integration/clawhub_scrapper.py --output data/
```

**What it does**:
1. Fetches all skills from ClawHub via paginated API
2. Extracts OpenClaw LLM security evaluations (verdict, confidence, dimensions)
3. Fetches VirusTotal hashes and detection counts
4. Merges security data into enriched dataset

**Output Files**:
```
data/
├── clawhub_skills.json              # All skills (flat list)
├── clawhub_skills_meta.json         # Metadata by slug
└── clawhub_enriched.json            # Full enriched data
```

**Requirements**: httpx, beautifulsoup4 (for HTML parsing)

**API Keys**: None required (public ClawHub API)

---

### 2. clawhub_fetch.py
**Purpose**: Low-level API client for ClawHub integration

**Usage** (as module):
```python
from scripts.integration.clawhub_fetch import ClawHubClient

client = ClawHubClient()

# Fetch all skills
skills = client.fetch_all_skills()

# Fetch specific skill by slug
skill = client.fetch_skill("my_skill_slug")

# Search skills
results = client.search_skills("file operations")
```

**Usage** (command-line):
```bash
# Fetch single skill
python scripts/integration/clawhub_fetch.py --slug my_skill_slug

# Search
python scripts/integration/clawhub_fetch.py --search "data exfiltration"

# List all skills
python scripts/integration/clawhub_fetch.py --list-all
```

**Methods**:
- `fetch_all_skills()` — Get all available skills
- `fetch_skill(slug)` — Get specific skill
- `search_skills(query)` — Search by keyword
- `get_metadata(slug)` — Get skill metadata

---

### 3. clawhavoc_scanner.py
**Purpose**: Detect potentially malicious skills using pattern matching

**Usage**:
```bash
# Scan local skills
python scripts/integration/clawhavoc_scanner.py --local skills/

# Scan ClawHub
python scripts/integration/clawhavoc_scanner.py --clawhub

# Scan specific skill
python scripts/integration/clawhavoc_scanner.py --file skills/SKILL1.md

# Generate report
python scripts/integration/clawhavoc_scanner.py --local skills/ --report malware_report.json
```

**Output**:
```json
{
  "skill_name": "SKILL1",
  "risk_level": "HIGH",
  "detected_patterns": [
    "shell_injection_pattern",
    "privilege_escalation_attempt",
    "data_exfiltration_indicator"
  ],
  "confidence": 0.95,
  "recommendations": ["Do not deploy", "Requires human review"]
}
```

**Detection Patterns**:
- Shell command injection
- Privilege escalation attempts
- Data exfiltration indicators
- Credential exposure patterns
- Unsafe deserialization
- Command execution vulnerabilities

---

## Common Workflows

### Download and Evaluate ClawHub Skills

```bash
# 1. Fetch from ClawHub
python scripts/integration/clawhub_scrapper.py

# 2. Move skills to evaluation directory
cp data/clawhub_skills/* skills/

# 3. Evaluate with SkillVetBench
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 4. Compare with ClawHub verdicts
python scripts/integration/compare_with_clawhub.py
```

### Security Scanning Workflow

```bash
# 1. Scan local skills for patterns
python scripts/integration/clawhavoc_scanner.py --local skills/ --report local_scan.json

# 2. Scan ClawHub
python scripts/integration/clawhavoc_scanner.py --clawhub --report clawhub_scan.json

# 3. Cross-reference with SkillVetBench results
python scripts/analysis/evaluation_analysis.py --compare-with-malware-scan local_scan.json
```

### Build Research Dataset

```bash
# 1. Fetch all ClawHub skills with enrichment
python scripts/integration/clawhub_scrapper.py

# 2. Evaluate locally
python server.py --api anthropic --model claude-sonnet-4-6 --eval-all

# 3. Generate analysis
python scripts/analysis/evaluation_analysis.py --summary

# 4. Export dataset
python -c "
from storage import ReportStorage
import json

storage = ReportStorage('reports/')
reports = storage.load_all_reports()

dataset = {
    'total_skills': len(reports),
    'high_risk': len([r for r in reports if r.sars.score >= 7.0]),
    'vulnerability_breakdown': {...}
}

with open('evaluation_outputs/dataset.json', 'w') as f:
    json.dump(dataset, f, indent=2)
"
```

---

## Python API (For Custom Integration)

### ClawHub Integration

```python
from scripts.integration.clawhub_fetch import ClawHubClient
from evaluator import SkillEvaluator
from llm_client import LLMClient

# Fetch skills
client = ClawHubClient()
clawhub_skills = client.fetch_all_skills()

# Evaluate each
llm = LLMClient(api="anthropic", model="claude-sonnet-4-6")
evaluator = SkillEvaluator(llm)

results = {}
for skill_data in clawhub_skills:
    # Write temporary skill file
    skill_path = f"temp_{skill_data['slug']}.md"
    with open(skill_path, 'w') as f:
        f.write(skill_data['content'])
    
    # Evaluate
    report = evaluator.evaluate_skill(skill_path)
    
    # Compare with ClawHub verdict
    results[skill_data['slug']] = {
        'skillvetbench_sars': report.sars.score,
        'clawhub_verdict': skill_data.get('verdict'),
        'agreement': report.sars.score >= 7.0 == (skill_data.get('verdict') == 'malicious')
    }
```

### Malware Scanning

```python
from scripts.integration.clawhavoc_scanner import MalwareScanner

scanner = MalwareScanner()

# Scan skill
result = scanner.scan_file("skills/SKILL1.md")

print(f"Risk Level: {result['risk_level']}")
print(f"Detected Patterns: {', '.join(result['detected_patterns'])}")
print(f"Confidence: {result['confidence']:.2%}")
```

---

## Configuration

### ClawHub API Settings

By default, uses public ClawHub API. To customize:

```bash
# Custom ClawHub endpoint
export CLAWHUB_API_URL=https://custom-api.example.com

# ClawHub API key (if required)
export CLAWHUB_API_KEY=your-key-here

# Then run:
python scripts/integration/clawhub_scrapper.py
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Connection refused` | Verify internet connection and ClawHub is online |
| `SSL certificate error` | Update certifi: `pip install --upgrade certifi` |
| `Rate limited` | Add delay: `--delay 2` for 2-second waits between requests |
| `Large download slow` | Use `--batch-size 50` to fetch in smaller chunks |
| `Disk space` | Output is ~100MB; ensure sufficient space in `data/` |

---

## Data Formats

### Enriched Skill JSON

```json
{
  "slug": "my_skill",
  "name": "My Skill",
  "description": "...",
  "content": "# Skill markdown...",
  "open_claw_verdict": "benign|suspicious|malicious",
  "open_claw_confidence": 0.95,
  "open_claw_dimensions": {
    "ifr": 1,
    "dg": 0,
    "ai": 0,
    "br": 0,
    "ca": 1
  },
  "virustotal": {
    "sha256": "...",
    "detection_ratio": "0/64",
    "community_score": 0,
    "last_analysis_date": "2024-05-23"
  }
}
```

---

## Next Steps

- Run clawhub_scrapper.py to build your evaluation dataset
- See `../analysis/` for analyzing results
- Check `docs/RESEARCH_GUIDE.md` for custom integration patterns
- Read `docs/USAGE.md` for web server and evaluation API
