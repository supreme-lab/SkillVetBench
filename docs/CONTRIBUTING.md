# Contributing to SkillVetBench

Thank you for considering contributing to SkillVetBench! We welcome researchers, security practitioners, and developers to help improve this framework.

## Areas for Contribution

### 🔬 Research & Analysis
- **SARS validation studies** — Compare SARS scores with real-world exploits
- **Model comparison research** — Analyze how different LLMs score skills
- **Skill composition analysis** — Study dangerous skill chains and patterns
- **Prompt engineering** — Optimize evaluation prompts for better accuracy

### 🛠️ Engineering Contributions
- **New LLM backends** — Add support for new AI providers
- **Performance optimizations** — Faster batch evaluation, parallel processing
- **Custom metrics** — Implement domain-specific scoring dimensions
- **Vulnerability detectors** — Add new vulnerability categories
- **Data visualization** — Interactive dashboards and plots

### 📚 Documentation
- **Tutorials** — How-to guides for specific use cases
- **Examples** — Worked examples and code snippets
- **API documentation** — Docstring improvements
- **Research reproduction** — Detailed methods for published studies

### 🐛 Bug Fixes & Improvements
- **Bug reports** — Issues with evaluation, web UI, or storage
- **Error handling** — Better error messages and recovery
- **Testing** — Unit tests, integration tests, regression tests

---

## Getting Started

### 1. Fork & Clone

```bash
git clone https://github.com/yourusername/skillvetbench_github.git
cd skillvetbench_github
git checkout -b feature/your-feature-name
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Set up API keys for testing
export ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Test Your Changes

```bash
# Test basic functionality
python -m pytest tests/  # if tests exist

# Manual test
python server.py --api anthropic --model claude-sonnet-4-6

# Visit http://localhost:8000
```

---

## Development Workflow

### Adding a New LLM Backend

1. **Create client class** in `llm_client.py`:

```python
class NewLLMClient(BaseLLMClient):
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        
    def evaluate_skill(self, prompt: str) -> Dict:
        # Implement API call
        pass

# Register in factory
LLM_PROVIDERS["newllm"] = NewLLMClient
```

2. **Add to CLI** in `server.py`:

```python
parser.add_argument("--api", choices=["anthropic", "openai", "newllm", ...])
```

3. **Test thoroughly**:

```bash
python server.py --api newllm --model your-model-name
```

4. **Document** in `docs/USAGE.md` and `docs/INSTALLATION.md`

### Adding a New Vulnerability Category

1. **Update prompt** in `prompts_cvss4_0.py`:

```python
VULNERABILITY_CATEGORIES = [
    # ... existing ...
    {
        "id": "new_category_001",
        "name": "Your New Vulnerability",
        "description": "Clear description of what this detects",
        "patterns": ["pattern1", "pattern2"]
    }
]
```

2. **Add to web UI** in `templates.html`:

```javascript
const categoryMap = {
    // ... existing ...
    "new_category_001": { 
        color: "purple", 
        icon: "⚠️", 
        label: "New Vulnerability" 
    }
};
```

3. **Test** with sample skills

4. **Document** what the category detects and why it matters

### Creating Custom SARS Dimensions

1. **Define new dimension** in `sars.py`:

```python
class CustomDimension:
    name = "CD"  # Custom Dimension
    weight = 1.5
    description = "Your dimension description"
    
    def evaluate(self, skill_content: str, llm_response: Dict) -> int:
        # Return 0-3 score
        pass
```

2. **Integrate into formula**:

```python
SARS = (2.0 × IFR + 1.5 × DG + 1.5 × AI + 2.0 × BR + 2.0 × CA + 1.5 × CD) / (2.7 + 1.5)
```

3. **Test on skill samples**

4. **Document** why this dimension matters

---

## Code Style

- **Python**: Follow PEP 8
- **Functions**: Clear docstrings with examples
- **Comments**: Explain *why*, not *what*
- **Error handling**: Use specific exceptions
- **Type hints**: Use Python type annotations

Example:

```python
def evaluate_skill(self, skill_path: str) -> SkillReport:
    """
    Evaluate a single skill file.
    
    Args:
        skill_path: Path to .md skill file
        
    Returns:
        SkillReport with SARS, CVSS, vulnerabilities
        
    Raises:
        FileNotFoundError: If skill_path doesn't exist
        ValueError: If skill format is invalid
    """
    # Implementation
    pass
```

---

## Testing

Before submitting a PR:

1. **Test single skill evaluation**:
```bash
python -c "from evaluator import SkillEvaluator; from llm_client import LLMClient
llm = LLMClient(); report = SkillEvaluator(llm).evaluate_skill('skills/SKILL1.md')
assert report.sars.score is not None"
```

2. **Test batch evaluation**:
```bash
python server.py --api anthropic --model claude-sonnet-4-6
# Submit evaluation via web UI, verify it completes
```

3. **Test with multiple LLMs** (if applicable):
```bash
python server.py --api openai --model gpt-4o
python server.py --api ollama --model mistral
```

4. **Test error handling**:
```bash
python -c "from evaluator import SkillEvaluator
SkillEvaluator(None).evaluate_skill('nonexistent.md')"  # Should raise FileNotFoundError
```

---

## Submitting a Pull Request

### Before You Submit

- [ ] Tests pass
- [ ] Code follows style guide
- [ ] Docstrings are complete
- [ ] No breaking changes (or documented)
- [ ] New dependencies justified

### PR Title Format

```
[Category] Short description

Categories: feat (feature), fix (bug), docs, refactor, perf, test, ci
```

Examples:
- `[feat] Add Groq LLM backend support`
- `[fix] Correct SARS CA dimension calculation`
- `[docs] Add researcher's guide for custom metrics`

### PR Description Template

```markdown
## Description
Brief overview of changes

## Motivation
Why this change? What problem does it solve?

## Testing
How was this tested?

## Research Impact (if applicable)
How does this affect research use cases?

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] No breaking changes
```

---

## Research Contributions

### Publishing Results

If your research uses SkillVetBench, consider:

1. **Creating a research branch** for reproducibility
2. **Documenting your methodology** in `docs/research/`
3. **Publishing results** with code availability
4. **Citing SkillVetBench** in your paper
5. **Sharing findings** with the community

### Reproducibility Standards

- [ ] Fixed random seeds
- [ ] Documented LLM versions and temperatures
- [ ] Hardware specifications noted
- [ ] Dataset and results available
- [ ] Scripts for reproduction included

---

## Community Guidelines

- **Be respectful** — Different backgrounds and perspectives are welcome
- **Be constructive** — Provide actionable feedback
- **Be collaborative** — Work together toward solutions
- **Be inclusive** — Ensure contributions are accessible to all skill levels

---

## Questions?

- **General**: Open an issue on GitHub
- **Research collaboration**: Start a Discussion
- **Code review**: Tag maintainers on your PR
- **Feature ideas**: Use GitHub Issues

Thank you for contributing to agentic AI security research! 🔐
