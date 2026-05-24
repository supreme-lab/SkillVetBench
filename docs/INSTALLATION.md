# Installation Guide

## Prerequisites

- Python 3.9+
- pip or conda for package management
- (Optional) Docker for containerized deployment

## Quick Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/skillvetbench_github.git
cd skillvetbench_github
```

### 2. Install Dependencies

**Basic Installation (Anthropic Claude):**
```bash
pip install -r requirements.txt
```

**For OpenAI Support:**
```bash
pip install -r requirements.txt openai>=1.0.0
```

**For HuggingFace Local Inference:**
```bash
pip install -r requirements.txt transformers torch accelerate huggingface_hub
# Optional: GPU quantization support
pip install bitsandbytes  # CUDA only
```

**For Ollama Support:**
Ollama doesn't require a pip package. Just run:
```bash
ollama serve
ollama pull llama3.1:8b
```

### 3. Set Environment Variables

```bash
# For Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-...

# For OpenAI
export OPENAI_API_KEY=sk-...

# For HuggingFace API
export HF_TOKEN=hf_...
```

## Docker Installation

```bash
docker build -t skillvetbench .
docker run -p 8000:8000 \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  skillvetbench
```

## Verification

Test the installation:
```bash
python -c "import sys; sys.path.insert(0, 'source_code/utils'); from evaluator import SkillEvaluator; print('✓ Installation successful')"
```

## Troubleshooting

- **GPU Memory Issues**: Reduce model size or use quantization (4-bit/8-bit)
- **API Key Errors**: Verify environment variables are set correctly
- **Import Errors**: Ensure you're in a clean Python environment: `pip install --upgrade pip`
