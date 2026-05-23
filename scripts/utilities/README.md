# Utility Scripts

These are small utility scripts for common maintenance and debugging tasks.

## Overview

```
scripts/utilities/
├── README.md                       ← You are here
├── check_gpu.py                    ← GPU availability checker
└── slug_match.py                   ← Skill identifier matcher
```

---

## Scripts

### 1. check_gpu.py
**Purpose**: Check GPU availability and compatibility for local inference

**Usage**:
```bash
# Check GPU availability
python scripts/utilities/check_gpu.py

# Verbose output
python scripts/utilities/check_gpu.py --verbose

# Check specific CUDA version
python scripts/utilities/check_gpu.py --cuda-version
```

**Output Example**:
```
GPU Status:
  Device: NVIDIA RTX 4090
  CUDA Available: True
  CUDA Version: 12.1
  Memory: 24GB / 24GB
  GPU Utilization: 0%

Recommendation:
  ✓ GPU available for local inference
  ✓ Sufficient VRAM for 7B models
  ⚠ 13B+ models may require quantization
```

**Requirements**: torch, pynvml (for NVIDIA GPUs)

**When to use**:
- Before running HuggingFace local inference
- Troubleshooting model loading issues
- Checking available VRAM
- Determining if quantization is needed

---

### 2. slug_match.py
**Purpose**: Match and normalize skill identifiers across different sources

**Usage**:
```bash
# Match skill identifiers
python scripts/utilities/slug_match.py SKILL1.md

# Batch match
python scripts/utilities/slug_match.py skills/*.md

# Generate slug mapping
python scripts/utilities/slug_match.py --generate-map

# Find duplicates
python scripts/utilities/slug_match.py --find-duplicates
```

**Output**:
```
Slug Mapping:
  SKILL1.md          → skill_1
  My Skill.md        → my_skill
  Complex Skill-v2   → complex_skill_v2
```

**Requirements**: None (pure Python)

**When to use**:
- Normalizing skill filenames
- Creating cross-reference maps
- Finding duplicate skills
- Standardizing skill naming conventions

---

## Quick Reference

### Check GPU Before Running Local Models

```bash
# 1. Check GPU
python scripts/utilities/check_gpu.py

# 2. If available, run local inference
if [ $? -eq 0 ]; then
  python server.py --api hf_local --model mistral/Mistral-7B-Instruct-v0.1 --device cuda
fi
```

### Generate Skill Identifier Map

```bash
# Create normalized mapping
python scripts/utilities/slug_match.py --generate-map > skill_mapping.json

# Use in analysis
python -c "
import json
with open('skill_mapping.json') as f:
    mapping = json.load(f)
print(mapping)
"
```

---

## Python API

### Check GPU Status

```python
from scripts.utilities.check_gpu import GPUChecker

checker = GPUChecker()

if checker.is_available():
    print(f"GPU: {checker.get_name()}")
    print(f"Memory: {checker.get_memory_gb()}GB")
    
    if checker.is_sufficient_for_7b():
        print("✓ Can run 7B models")
    
    if checker.is_sufficient_for_13b():
        print("✓ Can run 13B models")
    else:
        print("⚠ Use 4-bit quantization for 13B models")
else:
    print("GPU not available; use CPU or cloud inference")
```

### Normalize Skill Identifiers

```python
from scripts.utilities.slug_match import SlugMatcher
from pathlib import Path

matcher = SlugMatcher()

# Get normalized slug for a file
skill_files = list(Path("skills/").glob("*.md"))
mapping = {f.name: matcher.normalize(f.name) for f in skill_files}

print(mapping)
# Output: {'SKILL1.md': 'skill_1', 'My Skill.md': 'my_skill', ...}
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `No GPU found` | Verify NVIDIA drivers: `nvidia-smi` |
| `CUDA not found` | Install CUDA: https://developer.nvidia.com/cuda-downloads |
| `Out of memory` | Use smaller model or 4-bit quantization |
| `Slug matching errors` | Use `--verbose` flag for debugging |

---

## Environment Setup

### GPU Environment

For local inference with GPU:

```bash
# Install GPU dependencies
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

# Check installation
python scripts/utilities/check_gpu.py
```

### CPU-Only Environment

If GPU not available:

```bash
# Use Anthropic API or OpenAI instead
python server.py --api anthropic --model claude-sonnet-4-6

# Or use Ollama for local inference (CPU)
ollama serve &
python server.py --api ollama --model llama2
```

---

## Integration with Main Pipeline

These utilities are used internally by the framework:

```python
# In server.py or evaluator.py
from scripts.utilities.check_gpu import GPUChecker

checker = GPUChecker()
if checker.is_available():
    device = "cuda"
else:
    device = "cpu"
```

---

## Creating Custom Utilities

Add new utilities to `scripts/utilities/`:

```python
# my_utility.py
"""
Description of what this utility does.

Usage:
  python scripts/utilities/my_utility.py [options]
"""

def main():
    # Your utility code here
    pass

if __name__ == "__main__":
    main()
```

Then update this README with usage instructions.

---

## Next Steps

- Check GPU before running local models: `python scripts/utilities/check_gpu.py`
- See `../analysis/` for analysis scripts
- See `../integration/` for data integration
- Check `docs/INSTALLATION.md` for full setup instructions
