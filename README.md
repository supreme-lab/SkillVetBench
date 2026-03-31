---
title: AgentAIBench Skill Security Evaluator
emoji: 🔐
colorFrom: blue
colorTo: teal
sdk: docker
app_port: 7860
pinned: false
---

# 🔐 AgentAIBench — Skill Security Evaluator

A security evaluation leaderboard for agentic AI skills, developed by the **SUPREME Lab** at the **University of Texas at El Paso (UTEP)**.

Part of the **AgentAIBench** benchmark framework for evaluating the safety and security of agentic AI tool-use skills sourced from [ClawHub](https://clawhub.ai).

---

## What This Is

Agentic AI systems use *skills* — tool definitions that instruct LLMs to call external APIs, execute code, or access sensitive resources. This evaluator automatically audits those skill files for security vulnerabilities using a structured LLM-based pipeline scored with **CVSS v4.0**.

---

## Features

- **CVSS v4.0 scoring** — MacroVector + interpolation algorithm (official FIRST specification)
- **20 CVSS metrics** — Full Base, Threat, Environmental, and Supplemental metric coverage
- **Multi-model support** — Anthropic, OpenAI, HuggingFace (local + API), Ollama
- **Sortable leaderboard** — Compare models across skills by risk, score, attack vector, and more
- **Detailed per-skill reports** — Vulnerability cards with attack scenarios, affected content, and remediation steps
- **Interactive metric popups** — Click any CVSS metric cell to learn what it means (spec definitions inline)
- **Attack category tagging** — Prompt injection, tool poisoning, data exfiltration, RCE, and more

---

## CVSS v4.0 Metric Groups

| Group | Metrics | Purpose |
|---|---|---|
| Exploitability | AV, AC, AT, PR, UI | How the attack is launched |
| Vulnerable System | VC, VI, VA | Impact on the directly attacked system |
| Subsequent System | SC, SI, SA | Impact on downstream systems |
| Threat | E | Exploit maturity / in-the-wild activity |
| Environmental | CR, IR, AR | Organizational requirements |
| Supplemental | S, AU, R, V, RE, U | Informational context (does not affect score) |

---

## Research

This tool is part of ongoing research on agentic AI security at the SUPREME Lab (Security and Privacy-Enhanced Machine Learning), UTEP.

**Related papers:**
- *AgentFence: Benchmarking Prompt Injection Defenses in Agentic Systems* — arXiv:2602.07652
- *FW-SSR: Fine-Tuning Vulnerabilities in Agentic Guards*
- *ChainFuzzer: Fuzzing LLM Tool-Call Chains*

**Lab:** [SUPREME Lab, UTEP](https://cs.utep.edu)

---

## Citation

If you use this tool or the AgentAIBench benchmark in your research, please cite:

```bibtex
@misc{agentaibench2025,
  title  = {AgentAIBench: Benchmarking Security of Agentic AI Skills},
  author = {Hossain, Ismail and others},
  year   = {2025},
  note   = {SUPREME Lab, University of Texas at El Paso}
}
```

---

## License

MIT License — see `LICENSE` for details.

CVSS v4.0 scoring is implemented per the FIRST specification.
CVSS is owned by [FIRST.Org, Inc.](https://www.first.org/cvss/) and used by permission.