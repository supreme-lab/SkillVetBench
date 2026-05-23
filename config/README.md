# Configuration Examples

This folder contains example configurations for different use cases.

## Configuration Files

### Default Configuration (config.yml)

```yaml
# SkillVetBench Default Configuration

# Web Server
server:
  host: "localhost"
  port: 8000
  debug: false

# LLM Backend
llm:
  api: "anthropic"
  model: "claude-sonnet-4-6"
  temperature: 0.0
  max_tokens: 4096

# Directories
paths:
  skills_dir: "skills/"
  reports_dir: "reports/"
  evaluation_outputs_dir: "evaluation_outputs/"

# Evaluation Settings
evaluation:
  timeout_seconds: 300
  max_retries: 3
  parallel_workers: 4

# Metrics
metrics:
  sars_enabled: true
  cvss_enabled: true
  custom_metrics: false
```

### Research Configuration (research.yml)

```yaml
# Configuration for research studies

server:
  host: "0.0.0.0"
  port: 8000
  debug: true

llm:
  api: "anthropic"
  model: "claude-sonnet-4-6"
  temperature: 0.0
  max_tokens: 4096

paths:
  skills_dir: "skills/"
  reports_dir: "reports/"
  evaluation_outputs_dir: "evaluation_outputs/"
  research_data: "research_data/"

evaluation:
  timeout_seconds: 600
  max_retries: 5
  parallel_workers: 8
  save_raw_responses: true  # For analysis

metrics:
  sars_enabled: true
  cvss_enabled: true
  custom_metrics: true
  detailed_logging: true
```

### Multi-Model Comparison Configuration (comparison.yml)

```yaml
# For comparing multiple LLM models

models:
  - name: "claude-sonnet-4-6"
    api: "anthropic"
    config:
      temperature: 0.0
      max_tokens: 4096
      
  - name: "gpt-4o"
    api: "openai"
    config:
      temperature: 0.0
      max_tokens: 4096
      
  - name: "Qwen2.5-14B"
    api: "hf_api"
    config:
      temperature: 0.0
      max_tokens: 4096
      
  - name: "Mistral-7B"
    api: "hf_local"
    config:
      temperature: 0.0
      device: "cuda"

evaluation:
  run_all_models: true
  parallel_workers: 4
  save_comparisons: true
```

### GPU Optimization Configuration (gpu.yml)

```yaml
# For GPU-accelerated local inference

llm:
  api: "hf_local"
  model: "meta-llama/Llama-2-7b-chat-hf"
  device: "cuda"
  dtype: "float16"  # Options: float32, float16, bfloat16
  quantization: "4bit"  # Options: none, 4bit, 8bit

evaluation:
  batch_size: 2
  max_new_tokens: 4096
  gpu_memory_fraction: 0.9
```

---

## Usage

### Load Custom Configuration

```python
import yaml
from evaluator import SkillEvaluator
from llm_client import LLMClient

# Load config
with open("config/research.yml") as f:
    config = yaml.safe_load(f)

# Use config
llm = LLMClient(
    api=config["llm"]["api"],
    model=config["llm"]["model"],
    temperature=config["llm"]["temperature"]
)

evaluator = SkillEvaluator(llm)
```

### Command Line with Config

```bash
# Apply research configuration
SKILLVETBENCH_CONFIG=config/research.yml python server.py

# Override specific settings
python server.py --api openai --model gpt-4o --port 9000
```

---

## Environment-Specific Setups

### Development

```bash
# .env.development
ANTHROPIC_API_KEY=sk-ant-...
DEBUG=true
LOG_LEVEL=DEBUG
```

### Production

```bash
# .env.production
ANTHROPIC_API_KEY=sk-ant-...
DEBUG=false
LOG_LEVEL=INFO
WORKERS=4
```

---

## Configuration Best Practices

1. **Use configuration files** for reproducible research
2. **Keep secrets in environment variables** (not in config files)
3. **Version your configs** alongside experiment results
4. **Document non-obvious settings** with comments
5. **Use different configs** for different use cases (dev/research/production)
