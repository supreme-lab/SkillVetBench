# Skill Security Evaluator

A security evaluation pipeline for AI agent skill files (`.md`) used by platforms such as **OpenClaw**, LangChain, AutoGen, and similar agentic frameworks. It analyses each skill definition for security vulnerabilities, scores them using the industry-standard **CVSS v3.1** metric, and produces a full written explanation of every finding.

---

## What problem does it solve?

AI agent platforms use "skill" files — Markdown documents that tell an agent *how* to perform a task: which tools to call, what commands to run, which files to read, which APIs to contact. A poorly written skill can silently introduce severe security vulnerabilities — arbitrary code execution, data exfiltration, supply chain attacks, and indirect prompt injection — into any agent that loads it.

This tool lets you **audit a skill file before deploying it**, using an LLM to reason about the security implications of every instruction in the file and report back in a structured, actionable format.

---
```
title: AgentAIBench Skill Security Evaluator
emoji: 🔐
colorFrom: blue
colorTo: teal
sdk: docker
app_port: 7860
pinned: false
```

## 3. Check your `requirements.txt`

Make sure it has at least these — add any missing ones:
```
fastapi>=0.110.0
uvicorn[standard]>=0.29.0
anthropic>=0.28.0
openai>=1.30.0
python-multipart>=0.0.9
```

---

## Project structure

```
skill_security_evaluator/
├── main.py               ← CLI entry point
├── prompts.py            ← Security evaluation system prompt (12 vulnerability categories)
├── llm_client.py         ← Unified LLM client (HuggingFace, Anthropic, OpenAI, Ollama)
├── evaluator.py          ← Core pipeline: .md file → LLM → SkillReport
├── cvss.py               ← CVSS v3.1 base score calculator
├── reporter.py           ← Console output (Rich) and JSON report writer
├── check_gpu.py          ← GPU diagnostic tool for local HuggingFace models
├── requirements.txt      ← Python dependencies
└── sample_skills/
    └── file_processor.md ← Example vulnerable skill for testing
```

---

## Script reference

### `main.py` — Command-line interface

The single entry point for all evaluations. Accepts a path to one `.md` file or an entire directory of skill files, builds the chosen LLM backend, runs the evaluation pipeline, prints results to the terminal, and optionally saves a JSON report.

**Key flags:**

| Flag | Purpose |
|---|---|
| `path` | `.md` file or directory to evaluate |
| `--api` | LLM backend: `hf_local`, `hf_api`, `anthropic`, `openai`, `ollama` |
| `--model` | Model name or HuggingFace ID |
| `--key` | API key or HuggingFace token |
| `--base-url` | Custom endpoint (Groq, Together AI, dedicated HF endpoint, etc.) |
| `--quantize` | `4bit` or `8bit` to reduce GPU memory usage |
| `--device` | Force `cuda`, `mps`, or `cpu` |
| `--output` | Directory to save JSON report |
| `--list-models` | Print all recommended models per backend and exit |

**Exit codes:** `0` = clean, `2` = one or more CRITICAL/HIGH findings.

**Examples:**

```bash
# Anthropic Claude (default)
python main.py sample_skills/

# HuggingFace local — auto-detects GPU
python main.py sample_skills/ --api hf_local --model Qwen/Qwen2.5-14B-Instruct

# 4-bit quantization for GPUs with limited VRAM
python main.py sample_skills/ --api hf_local --quantize 4bit \
  --model meta-llama/Meta-Llama-3.1-8B-Instruct

# HuggingFace hosted API
python main.py sample_skills/ --api hf_api --key hf_... \
  --model meta-llama/Meta-Llama-3.1-70B-Instruct

# Groq (fast, OpenAI-compatible)
python main.py sample_skills/ --api openai --key gsk_... \
  --base-url https://api.groq.com/openai/v1 \
  --model llama-3.1-70b-versatile

# Save JSON report
python main.py sample_skills/ --output reports/
```

---

### `llm_client.py` — Unified LLM client

Provides a single `LLMClient` class with a consistent `complete(system_prompt, user_message) → str` interface across five different backends. Switching models is a one-flag change; the rest of the pipeline is unaffected.

**Supported backends:**

| `api_type` | Description | Requires |
|---|---|---|
| `hf_local` | Downloads and runs HuggingFace model weights locally | `transformers`, `torch`, `accelerate` |
| `hf_api` | HuggingFace Inference API — serverless or dedicated endpoint | `huggingface_hub`, `HF_TOKEN` |
| `anthropic` | Anthropic Claude API | `anthropic`, `ANTHROPIC_API_KEY` |
| `openai` | OpenAI or any OpenAI-compatible endpoint (Groq, Together AI, etc.) | `openai`, `OPENAI_API_KEY` |
| `ollama` | Local Ollama server | Ollama running locally |

**Notable features:**

- **GPU auto-detection** (`hf_local`): automatically selects CUDA → MPS → CPU in order of preference, logs GPU name and available VRAM, warns if the chosen model likely won't fit without quantization.
- **Multi-GPU support**: uses `device_map="auto"` from the `accelerate` library to spread large models across all available GPUs.
- **4-bit / 8-bit quantization** (`--quantize`): integrates `bitsandbytes` NF4 quantization to run large models on consumer GPUs (e.g. Llama 3.1 8B in ~5 GB VRAM instead of ~16 GB).
- **Model ID validation**: catches missing HuggingFace namespaces (e.g. `Qwen2.5-14B-Instruct` instead of `Qwen/Qwen2.5-14B-Instruct`) before any download is attempted and auto-corrects 20+ known model IDs with a clear warning.
- **Recommended model catalogue**: `list_recommended_models()` and `--list-models` print curated model options with memory requirements for each backend.

---

### `prompts.py` — Security evaluation system prompt

Contains the `SKILL_SECURITY_EVAL_SYSTEM_PROMPT` string — a detailed, structured prompt that instructs the LLM to act as a senior cybersecurity researcher and evaluate a skill file against 12 vulnerability categories. Also provides `build_evaluation_prompt()` which wraps the raw skill file content in the user message.

**The 12 vulnerability categories checked:**

1. **Command / Shell Injection** — `os.system`, `subprocess` with `shell=True`, backtick execution
2. **Unsafe File Operations** — arbitrary path reads/writes, path traversal (`../../`), writes to system directories
3. **Remote Code Execution** — `eval()`, `exec()`, `pickle.loads()`, unsafe deserialization
4. **Data Exfiltration** — HTTP requests to external URLs, email forwarding, encoding and transmitting sensitive data
5. **Dependency / Supply Chain Attacks** — `pip install` from untrusted registries, `curl | bash` patterns
6. **Prompt Injection Susceptibility** — skills that instruct the agent to follow instructions found in external documents
7. **Privilege Escalation** — `sudo`, admin access requests, disabling security controls
8. **Credential / Secret Exposure** — hardcoded API keys, passwords, AWS credentials, logging of secrets
9. **Indirect / Embedded Injection** — processing content from emails, web pages, or databases as executable instructions
10. **Scope Creep / Over-privileged Tools** — unrestricted file system or network access beyond the skill's stated purpose
11. **Insecure Deserialization** — `pickle`, `yaml.load()` without `SafeLoader`, XML without entity protection
12. **Log / Output Injection** — writing unsanitised user input to logs, SQL, or HTML

The LLM is instructed to return a structured JSON object containing CVSS v3.1 metric values, a list of individual vulnerability findings (each with affected content, explanation, attack scenario, and remediation), an executive summary, and a remediation priority statement.

---

### `cvss.py` — CVSS v3.1 calculator

A pure-Python implementation of the [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) with no external dependencies. Takes the eight base metric abbreviations from the LLM's JSON output and computes all derived scores.

**Inputs (8 metrics):**

| Metric | Abbreviation | Values |
|---|---|---|
| Attack Vector | `AV` | `N` Network, `A` Adjacent, `L` Local, `P` Physical |
| Attack Complexity | `AC` | `L` Low, `H` High |
| Privileges Required | `PR` | `N` None, `L` Low, `H` High |
| User Interaction | `UI` | `N` None, `R` Required |
| Scope | `S` | `U` Unchanged, `C` Changed |
| Confidentiality Impact | `C` | `N` None, `L` Low, `H` High |
| Integrity Impact | `I` | `N` None, `L` Low, `H` High |
| Availability Impact | `A` | `N` None, `L` Low, `H` High |

**Outputs:**

- **CVSS Base Score** (0.0 – 10.0, rounded up to nearest 0.1 per spec)
- **Severity label** — None / Low / Medium / High / Critical
- **Impact Score**
- **Exploitability Score**
- **Vector string** — e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Full human-readable labels for each metric (e.g. `Attack Vector: Network`)

The `cvss_from_dict()` helper parses the LLM's JSON output tolerantly, accepting both abbreviations (`"N"`) and full words (`"Network"`).

---

### `evaluator.py` — Core evaluation pipeline

Orchestrates the full evaluation: reads the skill file, calls the LLM, parses the JSON response, computes CVSS scores, and assembles a `SkillReport` dataclass. Also handles batch evaluation of entire directories.

**Key classes:**

- `SkillEvaluator` — main class; exposes `evaluate_file(path)` and `evaluate_directory(path)`
- `SkillReport` — dataclass holding all results: CVSS scores, vulnerability list, summaries, and metadata
- `Vulnerability` — dataclass for a single finding: ID, category, severity, affected content, explanation, attack scenario, remediation

The parser is fault-tolerant — it strips markdown fences from LLM output, attempts JSON extraction from surrounding text, and falls back to safe defaults for unparseable CVSS metrics rather than crashing.

---

### `reporter.py` — Output and reporting

Renders evaluation results to the terminal and writes JSON reports to disk.

**Terminal output** uses the `rich` library for colour-coded panels if available, falling back to plain text automatically. Each skill's output includes:
- A header panel showing skill name and overall risk level
- The full CVSS v3.1 metric table with score bars
- The executive summary and skill purpose analysis
- Individual panels for each vulnerability finding, showing: category, severity, the exact affected content quoted from the skill file, a plain-English explanation of why it is dangerous, a concrete step-by-step attack scenario, and a specific remediation recommendation
- Dangerous patterns found and safe practices noted
- A prioritised remediation plan

**JSON output** (`--output reports/`) writes a timestamped file containing all of the above in a machine-readable format, suitable for CI/CD pipelines, dashboards, or further processing. The exit code is `2` if any CRITICAL or HIGH findings were found, enabling automated gates.

---

### `check_gpu.py` — GPU diagnostic tool

A standalone diagnostic script to run on your machine *before* attempting local model inference. Produces a complete hardware readiness report without requiring a skill file.

**Checks performed:**
1. PyTorch installation and version
2. NVIDIA CUDA availability — GPU name(s), VRAM per GPU, total VRAM, CUDA toolkit version
3. Apple Silicon MPS availability
4. AMD ROCm availability
5. All required Python packages and their installed versions
6. A model sizing table showing which models fit in your available VRAM in FP16 and 4-bit quantized form
7. A recommended command tailored to your exact hardware
8. The precise `pip install` command for your CUDA version

```bash
python check_gpu.py
```

---

### `sample_skills/file_processor.md` — Example vulnerable skill

A deliberately insecure skill file included for testing and demonstration. It contains representative examples of multiple vulnerability categories: `subprocess` with `shell=True`, `eval()` on user-supplied batch instructions, `yaml.load()` without `SafeLoader`, hardcoded AWS credentials and API keys, `pip install` from an untrusted registry with `curl | bash`, and an agent instruction that explicitly tells the agent to follow commands embedded in processed files. Use it to verify the pipeline produces correct output before evaluating your own skill files.

---

## Installation

```bash
# Minimal (Anthropic Claude backend)
pip install anthropic rich

# HuggingFace local GPU inference
pip install transformers torch accelerate huggingface_hub
pip install bitsandbytes          # for --quantize 4bit / 8bit (CUDA only)

# OpenAI / Groq / Together AI backend
pip install openai

# Check which PyTorch build matches your CUDA version
python check_gpu.py
```

---

## Quick start

```bash
# 1. Check your GPU
python check_gpu.py

# 2. See all supported models
python main.py --list-models

# 3. Evaluate the sample skill
python main.py sample_skills/file_processor.md --api anthropic

# 4. Evaluate your own skills
python main.py /path/to/your/skills/ --api hf_local \
  --model Qwen/Qwen2.5-14B-Instruct --device cuda --quantize 4bit \
  --output reports/
```

---

## Evaluation output format

Each evaluated skill produces a report containing the following sections:

```
┌─ SKILL NAME  [CRITICAL] ──────────────────────────────────────────────────┐
│ Executive Summary                                                           │
├─ CVSS v3.1 Metrics ────────────────────────────────────────────────────────┤
│ Base Score: 9.8 Critical   Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H │
│ Impact Score: 5.9          Exploitability Score: 3.9                       │
│ Attack Vector: Network     Privileges Required: None  ...                  │
├─ SKV-001 — Finding Title  [CRITICAL] ──────────────────────────────────────┤
│ Category:          Command/Shell Injection                                  │
│ Affected Content:  subprocess.run(command, shell=True, ...)                │
│ Why it is dangerous: ...                                                   │
│ Attack Scenario:   1. Attacker sends malicious command ...                 │
│ Remediation:       Replace shell=True with argument list ...               │
├─ Dangerous Patterns Found ─────────────────────────────────────────────────┤
│ • subprocess.run(command, shell=True)                                       │
│ • eval(instruction)                                                         │
├─ Remediation Priority ─────────────────────────────────────────────────────┤
│ Remove eval() immediately ...                                               │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## Supported CVSS severity thresholds

| Score | Severity |
|---|---|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

---

## Research context

This tool is part of the **AgentAIBench** research project at UTEP SUPREME Lab, which develops evaluation frameworks for security and privacy in agentic AI systems. The skill evaluator specifically addresses the threat surface introduced by third-party skill registries — analogous to package registries (PyPI, npm) but for AI agent behaviour, where a malicious or misconfigured skill can compromise the entire agent pipeline without any code-level vulnerability in the agent itself.

Related work: *AgentDojo* (Debenedetti et al. 2024), *InjecAgent* (Zhan et al. 2024), OWASP LLM Top 10.