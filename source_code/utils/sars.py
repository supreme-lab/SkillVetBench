"""
sars.py
=======
Skill Agentic Risk Score (SARS) — an evaluation metric designed specifically
for agentic AI skill files sourced from ClawHub / OpenClaw.

Unlike CVSS, which models software vulnerabilities, SARS models the five
properties that make agentic skills uniquely dangerous:

  IFR  Instruction Fidelity Risk   — prompt injection surface area
  DG   Data Gravity                — sensitivity of data the skill touches
  AI   Action Irreversibility      — whether skill actions can be undone
  BR   Blast Radius                — how many users/systems are affected
  CA   Chain Amplification         — danger multiplier when chained with other skills

Score formula (normalized 0–10):
  SARS = (2.0×IFR + 1.5×DG + 1.5×AI + 2.0×BR + 2.0×CA) / 2.7

Severity bands (same thresholds as CVSS for consistency):
  CRITICAL  9.0 – 10.0
  HIGH      7.0 – 8.9
  MEDIUM    4.0 – 6.9
  LOW       0.1 – 3.9
  NONE      0.0
"""

from dataclasses import dataclass


# ── Dimension definitions ────────────────────────────────────────────────────

SARS_DIMENSIONS = {
    "IFR": {
        "name": "Instruction Fidelity Risk",
        "short": "IFR",
        "description": (
            "How easily can the skill be manipulated into acting outside its "
            "stated purpose through prompt injection or instruction override? "
            "Measures the extent to which user-controlled text flows "
            "unfiltered into the skill's tool-call parameters."
        ),
        "weight": 2.0,
        "levels": {
            0: "Rigid — no free-text input flows into tool behaviour",
            1: "Low — user text passes through but is clearly scoped to a fixed operation",
            2: "Medium — user-controlled text influences API parameters or tool selection",
            3: "High — skill instructions incorporate user text directly with no sanitization",
        },
    },
    "DG": {
        "name": "Data Gravity",
        "short": "DG",
        "description": (
            "How sensitive is the data the skill can read or write? "
            "Derived from the skill's API schema, parameter names, and the "
            "description of what data is accessed or returned."
        ),
        "weight": 1.5,
        "levels": {
            0: "Public — only reads/writes publicly available or non-sensitive data",
            1: "Internal — company-internal data, non-sensitive",
            2: "Confidential — PII, credentials, session tokens, financial records",
            3: "Restricted — health records, private keys, payment instruments, auth secrets",
        },
    },
    "AI": {
        "name": "Action Irreversibility",
        "short": "AI",
        "description": (
            "Can the skill's actions be undone after execution? "
            "Based on HTTP methods (GET vs DELETE), action verbs in the skill "
            "description, and whether the platform provides rollback mechanisms."
        ),
        "weight": 1.5,
        "levels": {
            0: "Read-only — GET only, no state change possible",
            1: "Reversible — POST/PUT with a clear undo path (e.g., archive instead of delete)",
            2: "Difficult — modifies shared state, partial rollback possible with effort",
            3: "Irreversible — DELETE, sent messages, financial transactions, published posts",
        },
    },
    "BR": {
        "name": "Blast Radius",
        "short": "BR",
        "description": (
            "How many users or downstream systems are affected by a single "
            "successful exploitation of this skill? A skill that posts to a "
            "shared channel affects more people than one that edits a private note."
        ),
        "weight": 2.0,
        "levels": {
            0: "Self — only the requesting user or their private resources are affected",
            1: "Team — a bounded group such as a workspace, project, or org unit",
            2: "Platform — all users of the integrated service could be affected",
            3: "Cross-platform — affects external systems, third parties, or attack is wormable",
        },
    },
    "CA": {
        "name": "Chain Amplification",
        "short": "CA",
        "description": (
            "Does combining this skill with other skills multiply its danger "
            "significantly? Skills that enable read-then-exfiltrate, "
            "execute-then-persist, or reconnaissance-then-attack chains "
            "score higher than self-contained tools."
        ),
        "weight": 2.0,
        "levels": {
            0: "None — self-contained, no meaningful amplification when chained",
            1: "Low — chaining adds marginal capability",
            2: "Medium — chaining with a retrieval or execution skill creates a meaningful attack path",
            3: "High — force multiplier: enables exfiltration, lateral movement, or persistence when chained",
        },
    },
}

# ── Scoring constants ────────────────────────────────────────────────────────

_WEIGHTS  = {k: v["weight"] for k, v in SARS_DIMENSIONS.items()}
_MAX_RAW  = sum(w * 3 for w in _WEIGHTS.values())   # 27.0
_DIVISOR  = _MAX_RAW / 10.0                          # 2.7  → normalizes to 0–10


# ── Severity mapping ─────────────────────────────────────────────────────────

def sars_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"


# ── Main dataclass ───────────────────────────────────────────────────────────

@dataclass
class SARSScore:
    """
    Holds the five SARS dimension values and derives the composite score.

    All dimensions are integers in the range [0, 3].
    """
    ifr: int   # Instruction Fidelity Risk
    dg:  int   # Data Gravity
    ai:  int   # Action Irreversibility
    br:  int   # Blast Radius
    ca:  int   # Chain Amplification

    @property
    def score(self) -> float:
        raw = (
            _WEIGHTS["IFR"] * self.ifr +
            _WEIGHTS["DG"]  * self.dg  +
            _WEIGHTS["AI"]  * self.ai  +
            _WEIGHTS["BR"]  * self.br  +
            _WEIGHTS["CA"]  * self.ca
        )
        return round(raw / _DIVISOR, 1)

    @property
    def severity(self) -> str:
        return sars_severity(self.score)

    @property
    def ifr_label(self) -> str:
        return SARS_DIMENSIONS["IFR"]["levels"].get(self.ifr, "Unknown")

    @property
    def dg_label(self) -> str:
        return SARS_DIMENSIONS["DG"]["levels"].get(self.dg, "Unknown")

    @property
    def ai_label(self) -> str:
        return SARS_DIMENSIONS["AI"]["levels"].get(self.ai, "Unknown")

    @property
    def br_label(self) -> str:
        return SARS_DIMENSIONS["BR"]["levels"].get(self.br, "Unknown")

    @property
    def ca_label(self) -> str:
        return SARS_DIMENSIONS["CA"]["levels"].get(self.ca, "Unknown")

    def as_dict(self) -> dict:
        return {
            "sars_score":    self.score,
            "sars_severity": self.severity,
            "sars_ifr":      self.ifr,
            "sars_ifr_label": self.ifr_label,
            "sars_dg":       self.dg,
            "sars_dg_label": self.dg_label,
            "sars_ai":       self.ai,
            "sars_ai_label": self.ai_label,
            "sars_br":       self.br,
            "sars_br_label": self.br_label,
            "sars_ca":       self.ca,
            "sars_ca_label": self.ca_label,
        }


# ── Parser ───────────────────────────────────────────────────────────────────

def sars_from_dict(data: dict) -> SARSScore:
    """
    Parse SARS dimension scores from the LLM JSON output.
    Expects a 'sars_metrics' key with sub-keys IFR, DG, AI, BR, CA.
    All values are clamped to [0, 3].
    """
    sars = data.get("sars_metrics", {})

    def clamp(val, default: int = 0) -> int:
        try:
            return max(0, min(3, int(val)))
        except (TypeError, ValueError):
            return default

    return SARSScore(
        ifr = clamp(sars.get("IFR", 0)),
        dg  = clamp(sars.get("DG",  0)),
        ai  = clamp(sars.get("AI",  0)),
        br  = clamp(sars.get("BR",  0)),
        ca  = clamp(sars.get("CA",  0)),
    )


# ── Prompt block (insert into prompts_cvss4_0.py) ───────────────────────────

SARS_PROMPT_BLOCK = """
  "sars_metrics": {
    "IFR": <0-3>,   // Instruction Fidelity Risk
                    // 0 = no user text flows into tool params
                    // 1 = user text scoped to a fixed operation
                    // 2 = user text influences API params or tool selection
                    // 3 = user text injected directly, no sanitization
    "DG":  <0-3>,   // Data Gravity (sensitivity of data accessed)
                    // 0 = public data only
                    // 1 = internal / non-sensitive
                    // 2 = PII, credentials, financial records
                    // 3 = health records, private keys, payment instruments
    "AI":  <0-3>,   // Action Irreversibility
                    // 0 = read-only, no state change
                    // 1 = reversible writes (undo path exists)
                    // 2 = difficult to reverse (shared state modified)
                    // 3 = irreversible (DELETE, sent messages, transactions)
    "BR":  <0-3>,   // Blast Radius
                    // 0 = affects requesting user only
                    // 1 = affects a bounded team/workspace
                    // 2 = affects all platform users
                    // 3 = cross-platform / wormable
    "CA":  <0-3>    // Chain Amplification
                    // 0 = self-contained, no amplification when chained
                    // 1 = marginal amplification
                    // 2 = meaningful attack path when chained
                    // 3 = force multiplier (exfil, lateral movement, persistence)
  },
"""