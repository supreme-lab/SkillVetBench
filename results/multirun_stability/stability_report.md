# Multi-run stability report (5 prompt-preamble runs)

Alarm flag = overall_risk HIGH/CRITICAL. Continuous/ranking statistics use skills with valid output in all 5 runs.

## Model: `gemma4-claude-sonnet-4.6` (20 skills x 5 runs)

### Continuous scores (SARS, CVSS)

| Score | Metric | Why | Threshold | Value | Check |
| --- | --- | --- | --- | --- | --- |
| cvss_base_score | ICC(2,1) | test-retest reliability | > 0.75 = excellent | 0.261 | FAIL |
| cvss_base_score | CV (mean within-skill) | relative stability | < 0.10 = highly stable | 0.582 | FAIL |
| cvss_base_score | SEM | absolute precision | < 0.25 -> 95% CI ~ +-0.5 | 2.814 | FAIL |
| cvss_base_score | % within tolerance | practical usability | % of skills with sigma < 0.25 | 0.071 |  |
| cvss_base_score | Friedman p | preamble effect (H0: none) | p > 0.05 = no effect | 0.0620 | PASS |
| sars_score | ICC(2,1) | test-retest reliability | > 0.75 = excellent | 0.517 | FAIL |
| sars_score | CV (mean within-skill) | relative stability | < 0.10 = highly stable | 0.375 | FAIL |
| sars_score | SEM | absolute precision | < 0.25 -> 95% CI ~ +-0.5 | 1.735 | FAIL |
| sars_score | % within tolerance | practical usability | % of skills with sigma < 0.25 | 0.000 |  |
| sars_score | Friedman p | preamble effect (H0: none) | p > 0.05 = no effect | 0.5197 | PASS |

### Rankings

| Score | Metric | Value |
| --- | --- | --- |
| cvss_base_score | Kendall's W | 0.160 (weak) |
| cvss_base_score | Spearman rho (mean ± SD over 10 run pairs) | 0.183 ± 0.286 (min -0.284) |
| cvss_base_score | Top-1 consistency (modal highest-risk skill) | agent-browser-clawdbot (2/5) |
| sars_score | Kendall's W | 0.058 (weak) |
| sars_score | Spearman rho (mean ± SD over 10 run pairs) | 0.522 ± 0.250 (min 0.137) |
| sars_score | Top-1 consistency (modal highest-risk skill) | ontology (2/5) |

### Binary verdicts (alarm = HIGH/CRITICAL)

| Metric | Why | Value |
| --- | --- | --- |
| Fleiss' kappa | agreement corrected for chance (5 runs) | 0.440 (n=14 skills with 5/5 valid runs) |
| Unanimous rate | % of skills with 5/5 identical verdicts | 0.429 |
| Super-majority (>=4/5) | % of skills with >=4/5 agreement | 1.000 |

Per-skill mode + confidence:

| Skill | Verdict | Confidence |
| --- | --- | --- |
| agent-browser-clawdbot | Flagged | 4/5 |
| api-gateway | Flagged | 4/4 |
| auto-updater | Flagged | 3/3 |
| clawddocs | Not flagged | 2/4 |
| desktop-control | Flagged | 4/5 |
| free-ride | Flagged | 4/5 |
| github | Not flagged | 4/5 |
| gog | Flagged | 2/3 |
| humanizer | Not flagged | 5/5 |
| multi-search-engine | Not flagged | 5/5 |
| nano-banana-pro | Flagged | 3/4 |
| obsidian | Not flagged | 5/5 |
| ontology | Flagged | 4/5 |
| openai-whisper | Not flagged | 5/5 |
| proactive-agent | Not flagged | 5/5 |
| self-improving-agent | Not flagged | 4/5 |
| self-improving | Not flagged | 3/4 |
| skill-vetter | Not flagged | 4/5 |
| weather | Not flagged | 5/5 |
| youtube-watcher | Not flagged | 4/5 |

## Model: `gemma4:latest` (20 skills x 5 runs)

### Continuous scores (SARS, CVSS)

| Score | Metric | Why | Threshold | Value | Check |
| --- | --- | --- | --- | --- | --- |
| cvss_base_score | ICC(2,1) | test-retest reliability | > 0.75 = excellent | 0.484 | FAIL |
| cvss_base_score | CV (mean within-skill) | relative stability | < 0.10 = highly stable | 0.373 | FAIL |
| cvss_base_score | SEM | absolute precision | < 0.25 -> 95% CI ~ +-0.5 | 2.130 | FAIL |
| cvss_base_score | % within tolerance | practical usability | % of skills with sigma < 0.25 | 0.250 |  |
| cvss_base_score | Friedman p | preamble effect (H0: none) | p > 0.05 = no effect | 0.2879 | PASS |
| sars_score | ICC(2,1) | test-retest reliability | > 0.75 = excellent | 0.753 | PASS |
| sars_score | CV (mean within-skill) | relative stability | < 0.10 = highly stable | 0.222 | FAIL |
| sars_score | SEM | absolute precision | < 0.25 -> 95% CI ~ +-0.5 | 1.318 | FAIL |
| sars_score | % within tolerance | practical usability | % of skills with sigma < 0.25 | 0.250 |  |
| sars_score | Friedman p | preamble effect (H0: none) | p > 0.05 = no effect | 0.4284 | PASS |

### Rankings

| Score | Metric | Value |
| --- | --- | --- |
| cvss_base_score | Kendall's W | 0.104 (weak) |
| cvss_base_score | Spearman rho (mean ± SD over 10 run pairs) | 0.364 ± 0.218 (min -0.034) |
| cvss_base_score | Top-1 consistency (modal highest-risk skill) | api-gateway (2/5) |
| sars_score | Kendall's W | 0.080 (weak) |
| sars_score | Spearman rho (mean ± SD over 10 run pairs) | 0.744 ± 0.140 (min 0.464) |
| sars_score | Top-1 consistency (modal highest-risk skill) | api-gateway (5/5) |

### Binary verdicts (alarm = HIGH/CRITICAL)

| Metric | Why | Value |
| --- | --- | --- |
| Fleiss' kappa | agreement corrected for chance (5 runs) | 0.340 (n=12 skills with 5/5 valid runs) |
| Unanimous rate | % of skills with 5/5 identical verdicts | 0.583 |
| Super-majority (>=4/5) | % of skills with >=4/5 agreement | 0.917 |

Per-skill mode + confidence:

| Skill | Verdict | Confidence |
| --- | --- | --- |
| agent-browser-clawdbot | Flagged | 3/3 |
| api-gateway | Flagged | 5/5 |
| auto-updater | Flagged | 4/4 |
| clawddocs | Flagged | 4/5 |
| desktop-control | Flagged | 5/5 |
| free-ride | Flagged | 5/5 |
| github | Flagged | 2/3 |
| gog | Flagged | 3/3 |
| humanizer | Flagged | 4/4 |
| multi-search-engine | Not flagged | 3/5 |
| nano-banana-pro | Flagged | 4/5 |
| obsidian | Flagged | 3/3 |
| ontology | Flagged | 3/3 |
| openai-whisper | Flagged | 5/5 |
| proactive-agent | Flagged | 5/5 |
| self-improving-agent | Flagged | 2/2 |
| self-improving | Flagged | 5/5 |
| skill-vetter | Flagged | 4/5 |
| weather | Not flagged | 4/5 |
| youtube-watcher | Flagged | 5/5 |

## Model: `qwen3.5:latest` (20 skills x 5 runs)

### Continuous scores (SARS, CVSS)

| Score | Metric | Why | Threshold | Value | Check |
| --- | --- | --- | --- | --- | --- |
| cvss_base_score | ICC(2,1) | test-retest reliability | > 0.75 = excellent | n/a | — |
| cvss_base_score | CV | relative stability | < 0.10 = highly stable | n/a | — |
| cvss_base_score | SEM | absolute precision | < 0.25 -> 95% CI ~ +-0.5 | n/a | — |
| cvss_base_score | % within tolerance | practical usability | % of skills with sigma < 0.25 | n/a | — |
| sars_score | ICC(2,1) | test-retest reliability | > 0.75 = excellent | n/a | — |
| sars_score | CV | relative stability | < 0.10 = highly stable | n/a | — |
| sars_score | SEM | absolute precision | < 0.25 -> 95% CI ~ +-0.5 | n/a | — |
| sars_score | % within tolerance | practical usability | % of skills with sigma < 0.25 | n/a | — |

### Rankings

| Score | Metric | Value |
| --- | --- | --- |
| cvss_base_score | Kendall's W | n/a |
| cvss_base_score | Spearman rho (mean over run pairs) | n/a |
| cvss_base_score | Top-1 consistency | n/a |
| sars_score | Kendall's W | n/a |
| sars_score | Spearman rho (mean over run pairs) | n/a |
| sars_score | Top-1 consistency | n/a |

### Binary verdicts (alarm = HIGH/CRITICAL)

| Metric | Why | Value |
| --- | --- | --- |
| Fleiss' kappa | agreement corrected for chance (5 runs) | n/a (n=0 skills with 5/5 valid runs) |
| Unanimous rate | % of skills with 5/5 identical verdicts | n/a |
| Super-majority (>=4/5) | % of skills with >=4/5 agreement | n/a |

Per-skill mode + confidence:

| Skill | Verdict | Confidence |
| --- | --- | --- |
| auto-updater | Flagged | 2/2 |
| clawddocs | Not flagged | 1/1 |
| desktop-control | Flagged | 1/1 |
| github | Flagged | 1/1 |
| humanizer | Not flagged | 2/2 |
| nano-banana-pro | Not flagged | 1/1 |
| proactive-agent | Flagged | 1/1 |
| self-improving-agent | Flagged | 1/1 |
| skill-vetter | Not flagged | 1/2 |
| youtube-watcher | Not flagged | 2/2 |