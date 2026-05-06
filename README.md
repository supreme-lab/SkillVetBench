---
title: AgentAIBench Skill Security Evaluator
emoji: 🔐
colorFrom: indigo
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# 🔐 AgentAIBench — Skill Security Evaluator

A dual-metric security evaluation leaderboard for agentic AI skills, developed by the **SUPREME Lab** at the **University of Texas at El Paso (UTEP)**.

Part of the **AgentAIBench** benchmark framework for evaluating the safety and security of agentic AI tool-use skills sourced from [ClawHub](https://clawhub.ai) / [OpenClaw](https://openclaw.ai).

---

## What This Is

Agentic AI systems use *skills* — Markdown files that instruct LLMs to call external APIs, execute shell commands, read and write files, or interact with third-party services. Unlike traditional software vulnerabilities, skill-based attacks do not require a bug in the code — they exploit the LLM's interpretation of its own instructions.

This evaluator automatically audits skill files using a two-metric approach:

1. **SARS** — Skill Agentic Risk Score (purpose-built for agentic skills)
2. **CVSS v4.0** — Common Vulnerability Scoring System (industry-standard for comparison)

Every skill is evaluated by an LLM that scores both metrics simultaneously, producing a structured JSON report with vulnerability cards, attack scenarios, remediation guidance, and full metric breakdowns.

---

## Features

- **Dual scoring** — SARS (agentic-native) + CVSS v4.0 (industry-standard) for every skill
- **Multi-model support** — Anthropic Claude, OpenAI GPT, HuggingFace (API + local), Ollama
- **Sortable leaderboard** — Compare models and skills by CVSS score, SARS score, risk level, attack category, and vulnerability count
- **Two-tab detail reports** — SARS report first, CVSS report second; each with interactive metric popups
- **Interactive metric popups** — Click any metric cell to see its full definition, current value explanation, and all possible values
- **Vulnerability cards** — Per-finding breakdowns with affected content, attack scenarios, and remediation steps
- **Attack category tagging** — Prompt injection, data exfiltration, RCE, privilege escalation, and more
- **Background evaluation jobs** — Submit evaluations via the UI; jobs run asynchronously with live status polling

---

## Why Two Metrics?

| | CVSS v4.0 | SARS |
|---|---|---|
| **Designed for** | Software vulnerabilities | Agentic AI skill files |
| **Attack model** | Exploit a software bug | Manipulate LLM interpretation |
| **Scores** | Exploitability + System Impact | Agentic-specific risk dimensions |
| **Standard** | FIRST.Org international standard | SUPREME Lab research metric |
| **Best for** | Comparison with CVE databases | Understanding agentic-native risk |

CVSS was designed to score bugs in software systems. It works well for measuring the impact of a discovered vulnerability, but it does not capture several properties that are unique to agentic skill files: how susceptible the skill is to prompt injection, whether its actions can be undone, or how much more dangerous it becomes when combined with other skills in an agent pipeline. SARS fills that gap.

---

## SARS — Skill Agentic Risk Score

### Overview

SARS is a 0–10 composite score purpose-built for evaluating agentic AI skill files. It measures five dimensions that CVSS cannot model, derived from the skill's API schema, instruction design, data access patterns, and compositional properties.

**Severity bands** (intentionally aligned with CVSS for easy comparison):

| Score | Severity |
|---|---|
| 9.0 – 10.0 | **CRITICAL** |
| 7.0 – 8.9 | **HIGH** |
| 4.0 – 6.9 | **MEDIUM** |
| 0.1 – 3.9 | **LOW** |
| 0.0 | **NONE** |

---

### Why SARS is Necessary

CVSS has no concept of:

- **Prompt injection surface** — A skill that passes user-controlled text directly into tool parameters is trivially exploitable in a way that no CVSS metric captures.
- **Action irreversibility** — A skill that deletes files or sends emails is categorically more dangerous than one that reads files, even if both have the same CVSS impact scores.
- **Compositional danger** — A skill that reads files is low-risk alone, but becomes a critical exfiltration vector when chained with a skill that posts to an external API.
- **Blast radius at the skill level** — Whether an exploitation affects only the requesting user or every user of a shared platform is a property of the skill's integration design, not its underlying software vulnerability.

SARS makes these properties explicit, measurable, and comparable across skill files.

---

### The Five SARS Dimensions

Each dimension is scored as an integer from **0 to 3** by the evaluating LLM. The score reflects which of the four levels best describes the skill.

---

#### IFR — Instruction Fidelity Risk (Weight: 2.0)

*How easily can the skill be manipulated into acting outside its stated purpose through prompt injection or instruction override?*

This is the most important dimension for agentic security. A skill that injects user-supplied text directly into tool calls is trivially exploitable — any adversarial content embedded in a retrieved document, email, or user message can hijack the agent's actions.

| Score | Level | Description |
|---|---|---|
| 0 | Rigid | No user-controlled text flows into tool parameters at all |
| 1 | Low | User text passes through but is scoped to a fixed, constrained operation |
| 2 | Medium | User-controlled text influences which API parameters are called or which tool is selected |
| 3 | High | User text is injected directly into tool calls or commands without sanitization |

**Why weight 2.0?** Prompt injection is the defining attack surface of agentic systems. No traditional vulnerability metric captures it. A skill scoring IFR=3 is exploitable by any content the agent reads, with no technical barrier.

---

#### DG — Data Gravity (Weight: 1.5)

*How sensitive is the data the skill can read or write, based on what its API schema and parameters reveal?*

Unlike CVSS confidentiality impact (which scores the impact after a successful attack), DG measures the inherent sensitivity of what the skill touches — a property of the skill's design, not the outcome of an attack.

| Score | Level | Description |
|---|---|---|
| 0 | Public | Only reads or writes publicly available or non-sensitive data |
| 1 | Internal | Company-internal data that is not sensitive (project metadata, task lists) |
| 2 | Confidential | PII, credentials, session tokens, financial records |
| 3 | Restricted | Health records, private keys, payment instruments, authentication secrets |

**Why weight 1.5?** Data sensitivity is important but partially captured by CVSS's VC/VI/VA metrics. The lower weight reflects this overlap, while DG adds value by measuring the structural risk of the skill's integration rather than the outcome of exploitation.

---

#### AI — Action Irreversibility (Weight: 1.5)

*Can the skill's actions be undone after execution? Derived from HTTP methods (GET vs DELETE), action verbs, and platform rollback capabilities.*

This dimension captures a fundamental asymmetry: reading a file is reversible in consequence; deleting it or sending an email is not. An agent that is deceived into performing an irreversible action causes permanent harm regardless of how quickly the deception is discovered.

| Score | Level | Description |
|---|---|---|
| 0 | Read-only | GET requests only; no state change possible |
| 1 | Reversible | POST/PUT operations where a clear undo path exists (e.g. archive instead of delete) |
| 2 | Difficult | Modifies shared state; partial rollback possible with significant effort |
| 3 | Irreversible | DELETE operations, sent messages, financial transactions, published posts |

**Why weight 1.5?** Irreversibility amplifies the harm of every other risk dimension. However, it does not create a vulnerability on its own — an irreversible skill that requires legitimate authentication is not exploitable by itself. The moderate weight reflects this dependency.

---

#### BR — Blast Radius (Weight: 2.0)

*How many users or downstream systems are affected by a single successful exploitation?*

A skill that posts to a private note affects only one user. A skill that posts to a shared Slack channel affects all members. A skill that modifies a shared codebase or sends external emails creates cross-system impact. BR measures the scope of harm from a single exploitation event.

| Score | Level | Description |
|---|---|---|
| 0 | Self | Affects only the requesting user's own private resources |
| 1 | Team | Affects a bounded group (workspace, project, org unit) |
| 2 | Platform | Affects all users of the integrated service |
| 3 | Cross-platform | Affects external systems, third parties, or the attack is wormable |

**Why weight 2.0?** Blast radius determines whether a compromised agent causes isolated harm or systemic harm. A skill that can affect every user of a platform — or propagate to external systems — is categorically more dangerous and requires higher architectural scrutiny.

---

#### CA — Chain Amplification (Weight: 2.0)

*Does combining this skill with other skills in an agent pipeline multiply its danger significantly?*

Agentic systems compose skills into chains. A file-reading skill combined with a Slack-posting skill enables data exfiltration. A web-search skill combined with a code-execution skill enables supply chain attacks. CA scores the degree to which this skill acts as a force multiplier in a multi-skill pipeline.

| Score | Level | Description |
|---|---|---|
| 0 | None | Self-contained; no meaningful amplification when chained with other skills |
| 1 | Low | Chaining adds marginal additional capability |
| 2 | Medium | Chaining with a retrieval or execution skill creates a meaningful attack path |
| 3 | High | Force multiplier: enables data exfiltration, lateral movement, or persistence when chained |

**Why weight 2.0?** Chain amplification is unique to agentic systems and has no CVSS equivalent. A skill that is low-risk in isolation but becomes critical when chained represents a class of risk that only emerges in agentic contexts. High weight reflects how often this pattern appears in real skill libraries.

---

### Scoring Formula

```
SARS = (2.0 × IFR + 1.5 × DG + 1.5 × AI + 2.0 × BR + 2.0 × CA) / 2.7
```

**Derivation:** The maximum possible raw score is `(2.0×3) + (1.5×3) + (1.5×3) + (2.0×3) + (2.0×3) = 27.0`. Dividing by 2.7 normalizes the result to [0, 10], matching the CVSS scale for easy comparison.

**Weight rationale summary:**

| Dimension | Weight | Rationale |
|---|---|---|
| IFR | 2.0 | Core agentic attack surface; no CVSS equivalent |
| DG | 1.5 | Important but partially overlaps with CVSS VC/VI/VA |
| AI | 1.5 | Amplifies harm but does not create exploitability alone |
| BR | 2.0 | Determines systemic vs isolated harm |
| CA | 2.0 | Unique to agentic pipelines; enables emergent attack paths |

---

### Worked Examples

**Example 1 — Slack messaging skill**

A skill that sends Slack messages with user-controlled content to a shared channel:

| Dimension | Score | Reasoning |
|---|---|---|
| IFR | 3 | Message content flows directly from user input into the Slack API call |
| DG | 1 | Slack messages are internal but not credentials or health records |
| AI | 3 | Sent messages cannot be unsent; no undo path |
| BR | 2 | All channel members see the message |
| CA | 2 | Chained with a file-reader skill, enables content exfiltration via Slack |

```
SARS = (2.0×3 + 1.5×1 + 1.5×3 + 2.0×2 + 2.0×2) / 2.7
     = (6.0 + 1.5 + 4.5 + 4.0 + 4.0) / 2.7
     = 20.0 / 2.7
     = 7.4  →  HIGH
```

---

**Example 2 — Read-only documentation search**

A skill that searches a public documentation index and returns results:

| Dimension | Score | Reasoning |
|---|---|---|
| IFR | 1 | Query is passed through but scoped to a search operation |
| DG | 0 | Only accesses public documentation |
| AI | 0 | Read-only; no state change |
| BR | 0 | Results visible only to the requesting user |
| CA | 1 | Marginal amplification if results are acted upon |

```
SARS = (2.0×1 + 1.5×0 + 1.5×0 + 2.0×0 + 2.0×1) / 2.7
     = (2.0 + 0.0 + 0.0 + 0.0 + 2.0) / 2.7
     = 4.0 / 2.7
     = 1.5  →  LOW
```

---

**Example 3 — File deletion skill with admin access**

A skill that deletes files based on a user-supplied filename, with elevated system permissions:

| Dimension | Score | Reasoning |
|---|---|---|
| IFR | 2 | Filename comes from user input, influencing which file is operated on |
| DG | 2 | Can access any file on the system, including confidential ones |
| AI | 3 | File deletion is irreversible |
| BR | 1 | Affects the team's shared filesystem |
| CA | 3 | Combined with a listing skill, enables targeted destruction; combined with an exfil skill, enables data theft before deletion |

```
SARS = (2.0×2 + 1.5×2 + 1.5×3 + 2.0×1 + 2.0×3) / 2.7
     = (4.0 + 3.0 + 4.5 + 2.0 + 6.0) / 2.7
     = 19.5 / 2.7
     = 7.2  →  HIGH
```

---

## CVSS v4.0 Metrics Used

CVSS v4.0 is scored alongside SARS for industry-standard comparison. The following metrics are evaluated. **AV (Attack Vector) and AC (Attack Complexity) are excluded** — agentic skills are almost universally network-exposed (AV:N) and reliably exploitable (AC:L), so these metrics carry no discriminating value across skill files.

| Group | Metric | Description |
|---|---|---|
| Exploitability | AT — Attack Requirements | Whether specific deployment conditions are needed |
| Exploitability | PR — Privileges Required | Attacker authentication level before exploitation |
| Exploitability | UI — User Interaction | Whether a human must participate in the attack |
| Vulnerable System | VC — Confidentiality | Confidentiality impact on the directly attacked system |
| Vulnerable System | VI — Integrity | Integrity impact on the directly attacked system |
| Vulnerable System | VA — Availability | Availability impact on the directly attacked system |
| Subsequent System | SC — Confidentiality | Confidentiality impact on downstream systems |
| Subsequent System | SI — Integrity | Integrity impact on downstream systems |
| Subsequent System | SA — Availability | Availability impact on downstream systems |
| Threat | E — Exploit Maturity | Known exploitation activity in the wild |

Environmental (CR/IR/AR) and Supplemental (S, AU, R, V, RE, U) metrics are excluded — Environmental metrics are organization-specific and cannot be generalized across skill files; Supplemental metrics are informational only and do not affect the CVSS score.

---

## Vulnerability Categories

The LLM evaluates each skill against 12 vulnerability categories:

1. **Command / Shell Injection** — `os.system()`, `subprocess`, `exec()`, shell operators
2. **Unsafe File Operations** — path traversal, write to system directories, `shutil.rmtree`
3. **Remote Code Execution** — `eval()`, `exec()`, `pickle.loads()`, unsafe deserialization
4. **Data Exfiltration** — HTTP to external URLs, email sending, base64 encoding of sensitive data
5. **Dependency / Supply Chain** — `pip install`, `wget` of scripts, non-standard registries
6. **Prompt Injection** — processing external content as instructions, indirect injection vectors
7. **Privilege Escalation** — `sudo`, admin instructions, disabling security controls
8. **Credential Exposure** — hardcoded keys, logging secrets, transmitting credentials in plaintext
9. **Indirect / Embedded Injection** — skills that process emails or documents as new instructions
10. **Scope Creep** — over-privileged tool use, "access all", "read any" patterns
11. **Insecure Deserialization** — `pickle`, `yaml.load`, XML without entity protection
12. **Log / Output Injection** — writing user input to logs, SQL/HTML without sanitization

---

## Supported LLM Backends

| Backend | Flag | Notes |
|---|---|---|
| Anthropic Claude | `--api anthropic` | Recommended; best structured JSON output |
| OpenAI GPT | `--api openai` | GPT-4o and GPT-4o-mini supported |
| HuggingFace API | `--api hf_api` | Serverless inference; requires `HF_TOKEN` |
| HuggingFace Local | `--api hf_local` | Runs on your machine; requires GPU for large models |
| Ollama | `--api ollama` | Local inference via Ollama server |

---

## Project Files

```
AgentSkillBench/
├── server.py              Web server — FastAPI routes + HTML template loading
├── templates.html         All frontend HTML/CSS/JS (leaderboard + detail pages)
├── storage.py             Report persistence and leaderboard index management
├── evaluator.py           LLM evaluation pipeline → SkillReport dataclass
├── sars.py                SARS scoring logic, dimension definitions, formula
├── cvss4_0.py             CVSS v4.0 MacroVector + interpolation scorer
├── cvss3_5.py             CVSS v3.5 scorer (legacy, kept for reference)
├── prompts_cvss4_0.py     System prompt + JSON format specification for LLM
├── llm_client.py          Unified LLM client (Anthropic, OpenAI, HF, Ollama)
├── metrics.json           CVSS v4.0 metric definitions for UI popups
├── reports/               Evaluation results (JSON, one file per skill × model)
└── skills/                Skill .md files to evaluate
```

---

## Running the Evaluator

```bash
# Default — http://localhost:8000
python server.py

# Specify backend and model
python server.py --api anthropic --model claude-sonnet-4-6

# HuggingFace API
python server.py --api hf_api --model Qwen/Qwen2.5-14B-Instruct

# HuggingFace local with GPU
python server.py --api hf_local --model Qwen/Qwen2.5-14B-Instruct --device cuda

# Custom ports and directories
python server.py --port 9000 --skills-dir my_skills/ --reports-dir my_reports/
```

**Environment variables for API keys:**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
export HF_TOKEN=hf_...
export OPENAI_API_KEY=sk-...
```

---

## Research

This tool is part of ongoing research on agentic AI security at the **SUPREME Lab** (Security and Privacy-Enhanced Machine Learning), University of Texas at El Paso.

**Related papers:**
- *AgentFence: Benchmarking Prompt Injection Defenses in Agentic Systems* — [arXiv:2602.07652](https://arxiv.org/abs/2602.07652)
- *ChainFuzzer: Fuzzing LLM Tool-Call Chains* — [arXiv:2603.12614](https://arxiv.org/abs/2603.12614)
- *FW-SSR: Fine-Tuning Vulnerabilities in Agentic Guards*

**Lab:** [SUPREME Lab, UTEP](https://cs.utep.edu)

---

## Citation

If you use AgentAIBench, the SARS metric, or this evaluator in your research, please cite:

```bibtex
@misc{agentaibench2025,
  title   = {AgentAIBench: Benchmarking Security of Agentic AI Skills},
  author  = {Hossain, Ismail and others},
  year    = {2025},
  note    = {SUPREME Lab, University of Texas at El Paso},
  url     = {https://huggingface.co/spaces/ismail-h/AgentSkillBench}
}
```

---

## License

MIT License — see `LICENSE` for details.

CVSS v4.0 scoring is implemented per the [FIRST specification](https://www.first.org/cvss/v4.0/specification-document).
CVSS is a registered trademark of FIRST.Org, Inc. and is used by permission.

SARS (Skill Agentic Risk Score) is an original metric developed by the SUPREME Lab at UTEP.