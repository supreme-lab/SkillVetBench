# SARS Methodology Guide

## Overview

SARS (Skill Agentic Risk Score) is a purpose-built security scoring framework for evaluating agentic AI skills. Unlike CVSS, which is designed for traditional software vulnerabilities, SARS specifically captures risks that emerge from LLM instruction interpretation and skill composition.

## Why SARS?

CVSS cannot model:
- **Prompt injection surface** — User-controlled text flowing into tool parameters
- **Action irreversibility** — Deletion and modification operations vs. read operations
- **Compositional danger** — Skills that are low-risk in isolation but dangerous when chained
- **Blast radius** — Skill-level scope of impact (self vs. team vs. platform vs. cross-platform)

## The Five Dimensions

### 1. IFR — Instruction Fidelity Risk (Weight: 2.0)

**Question**: How easily can the skill be manipulated into acting outside its stated purpose?

**Scoring Levels**:
- **0 (Rigid)**: No user-controlled text flows into tool parameters
- **1 (Low)**: User text passes through but is scoped to a fixed operation
- **2 (Medium)**: User input influences which parameters or tools are called
- **3 (High)**: User text is injected directly into tool calls without sanitization

**Why it matters**: Prompt injection is the defining attack vector for agentic systems. A skill scoring IFR=3 is exploitable by any adversarial content the agent reads.

**Research Questions**:
- How do instruction design patterns affect injection surface?
- Does prompt templating reduce IFR scores compared to concatenation?
- How do different LLMs interpret the same skill differently?

---

### 2. DG — Data Gravity (Weight: 1.5)

**Question**: How sensitive is the data the skill can read or write?

**Scoring Levels**:
- **0 (Public)**: Only public or non-sensitive data
- **1 (Internal)**: Company-internal but non-sensitive (task lists, project metadata)
- **2 (Confidential)**: PII, credentials, session tokens, financial records
- **3 (Restricted)**: Health records, private keys, payment instruments

**Why it matters**: Unlike CVSS VC (Confidentiality Impact), DG measures the *inherent sensitivity* of what the skill touches, not the outcome of an attack.

**Research Questions**:
- How do data classification schemes affect DG scores?
- What's the correlation between DG and actual exploitation impact?
- How do researchers classify ambiguous data types (e.g., internal user emails)?

---

### 3. AI — Action Irreversibility (Weight: 1.5)

**Question**: Can the skill's actions be undone after execution?

**Scoring Levels**:
- **0 (Read-only)**: GET requests only; no state change
- **1 (Reversible)**: POST/PUT operations with clear undo path (e.g., archive instead of delete)
- **2 (Difficult)**: Modifies shared state; partial rollback possible with effort
- **3 (Irreversible)**: DELETE operations, sent messages, financial transactions

**Why it matters**: Reading a file is reversible in consequence; deleting it is not. Irreversibility amplifies the harm of every other risk dimension.

**Research Questions**:
- How do different platforms' rollback capabilities affect AI scores?
- Is there a correlation between AI score and actual recovery time in incidents?
- How do backup/recovery systems reduce AI scores?

---

### 4. BR — Blast Radius (Weight: 2.0)

**Question**: How many users or downstream systems are affected by one exploitation?

**Scoring Levels**:
- **0 (Self)**: Affects only the requesting user's private resources
- **1 (Team)**: Affects a bounded group (workspace, project, org unit)
- **2 (Platform)**: Affects all users of the integrated service
- **3 (Cross-platform)**: Affects external systems or is wormable

**Why it matters**: Blast radius determines whether harm is isolated or systemic. A compromised agent that affects every platform user is categorically more dangerous.

**Research Questions**:
- How do multi-tenant architectures affect BR scores?
- What's the relationship between BR and incident response complexity?
- Can BR be reduced through API access controls and sandboxing?

---

### 5. CA — Chain Amplification (Weight: 2.0)

**Question**: Does combining this skill with others multiply its danger significantly?

**Scoring Levels**:
- **0 (None)**: Self-contained; no meaningful amplification when chained
- **1 (Low)**: Chaining adds marginal capability
- **2 (Medium)**: Chaining with retrieval/execution skills creates meaningful attack paths
- **3 (High)**: Force multiplier — enables exfiltration, lateral movement, or persistence

**Why it matters**: Agentic systems compose skills into chains. A file-reader + Slack-poster enables data exfiltration. This is unique to agentic systems.

**Research Questions**:
- What skill combinations are most dangerous?
- Can CA be predicted from individual skill properties alone?
- How do skill dependency graphs affect overall pipeline risk?

---

## Scoring Formula

```
SARS = (2.0 × IFR + 1.5 × DG + 1.5 × AI + 2.0 × BR + 2.0 × CA) / 2.7
```

**Normalization**: Maximum possible raw score = 27.0 → dividing by 2.7 produces [0–10] scale matching CVSS.

**Weight Rationale**:

| Dimension | Weight | Justification |
|-----------|--------|---------------|
| IFR | 2.0 | Core agentic attack surface; no CVSS equivalent |
| DG | 1.5 | Important but partially overlaps with CVSS VC/VI/VA |
| AI | 1.5 | Amplifies harm but doesn't create exploitability alone |
| BR | 2.0 | Determines systemic vs. isolated harm |
| CA | 2.0 | Unique to agentic pipelines; enables emergent attacks |

---

## Examples

### Example 1: Slack Messaging Skill

A skill that sends Slack messages with user-controlled content to a shared channel.

| Dimension | Score | Reasoning |
|-----------|-------|-----------|
| IFR | 3 | Message content flows directly from user input into API call |
| DG | 1 | Slack messages are internal but not credentials |
| AI | 3 | Sent messages cannot be unsent |
| BR | 2 | All channel members see the message |
| CA | 2 | Chained with file-reader: enables exfiltration |

```
SARS = (2.0×3 + 1.5×1 + 1.5×3 + 2.0×2 + 2.0×2) / 2.7 = 7.4 → HIGH
```

### Example 2: Read-Only Documentation Search

A skill that searches public documentation and returns results.

| Dimension | Score | Reasoning |
|-----------|-------|-----------|
| IFR | 1 | Query is scoped to search operation |
| DG | 0 | Only accesses public documentation |
| AI | 0 | Read-only; no state change |
| BR | 0 | Results visible only to requesting user |
| CA | 1 | Marginal amplification if results are acted upon |

```
SARS = (2.0×1 + 1.5×0 + 1.5×0 + 2.0×0 + 2.0×1) / 2.7 = 1.5 → LOW
```

---

## For Researchers: Questions & Hypotheses

1. **Validation**: How well does SARS correlate with real-world exploit reports?
2. **Weight Optimization**: Are the current weights optimal for predicting harm?
3. **Generalization**: Does SARS transfer across different skill domains?
4. **Calibration**: How do non-expert evaluators' SARS scores differ from expert scores?
5. **Automated Scoring**: Can SARS dimensions be inferred from static analysis alone?
