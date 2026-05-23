"""
cvss.py
=======
CVSS v3.0 / v3.1 Base Score calculator.

All formulas follow the official FIRST specification:
  https://www.first.org/cvss/v3.1/specification-document

Given the 8 base metric values (AV, AC, PR, UI, S, C, I, A),
computes:
  - Base Score  (0.0 – 10.0)
  - Impact Score
  - Exploitability Score
  - Severity label  (None / Low / Medium / High / Critical)
  - Vector string   e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
"""

from dataclasses import dataclass
from typing import Literal
import math


# ─── Metric abbreviations ────────────────────────────────────────────

AV = Literal["N", "A", "L", "P"]   # Network / Adjacent / Local / Physical
AC = Literal["L", "H"]              # Low / High
PR = Literal["N", "L", "H"]        # None / Low / High
UI = Literal["N", "R"]              # None / Required
S  = Literal["U", "C"]             # Unchanged / Changed
C_ = Literal["N", "L", "H"]        # None / Low / High  (Confidentiality)
I_ = Literal["N", "L", "H"]        # None / Low / High  (Integrity)
A_ = Literal["N", "L", "H"]        # None / Low / High  (Availability)

# ─── Numeric weights ─────────────────────────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}

# PR weights differ depending on Scope
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed

_UI   = {"N": 0.85, "R": 0.62}
_CIA  = {"N": 0.00, "L": 0.22, "H": 0.56}

# ─── Severity label thresholds ───────────────────────────────────────

def severity_label(score: float) -> str:
    if score == 0.0:   return "None"
    if score <= 3.9:   return "Low"
    if score <= 6.9:   return "Medium"
    if score <= 8.9:   return "High"
    return "Critical"


# ─── Main dataclass ──────────────────────────────────────────────────

@dataclass
class CVSSv3:
    AV: str   # N A L P
    AC: str   # L H
    PR: str   # N L H
    UI: str   # N R
    S:  str   # U C
    C:  str   # N L H
    I:  str   # N L H
    A:  str   # N L H

    def _iss(self) -> float:
        """ISS = 1 - [(1-C) * (1-I) * (1-A)]"""
        return 1 - (1 - _CIA[self.C]) * (1 - _CIA[self.I]) * (1 - _CIA[self.A])

    def impact_score(self) -> float:
        iss = self._iss()
        if self.S == "U":
            return round(6.42 * iss, 1)
        else:
            raw = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
            return round(raw, 1)

    def exploitability_score(self) -> float:
        pr_w = _PR_C[self.PR] if self.S == "C" else _PR_U[self.PR]
        raw  = 8.22 * _AV[self.AV] * _AC[self.AC] * pr_w * _UI[self.UI]
        return round(raw, 1)

    def base_score(self) -> float:
        iss = self._iss()
        if iss == 0:
            return 0.0
        impact  = self.impact_score()
        pr_w    = _PR_C[self.PR] if self.S == "C" else _PR_U[self.PR]
        exploit = 8.22 * _AV[self.AV] * _AC[self.AC] * pr_w * _UI[self.UI]
        if self.S == "U":
            raw = min(impact + exploit, 10)
        else:
            raw = min(1.08 * (impact + exploit), 10)
        # Round up to nearest 0.1
        return math.ceil(raw * 10) / 10

    def severity(self) -> str:
        return severity_label(self.base_score())

    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}"
            f"/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"
        )

    def full_report(self) -> dict:
        bs  = self.base_score()
        imp = self.impact_score()
        exp = self.exploitability_score()
        return {
            "cvss_base_score":         bs,
            "cvss_severity":           self.severity(),
            "cvss_vector":             self.vector(),
            "impact_score":            imp,
            "exploitability_score":    exp,
            "attack_vector":           {"N":"Network","A":"Adjacent","L":"Local","P":"Physical"}[self.AV],
            "attack_complexity":       {"L":"Low","H":"High"}[self.AC],
            "privileges_required":     {"N":"None","L":"Low","H":"High"}[self.PR],
            "user_interaction":        {"N":"None","R":"Required"}[self.UI],
            "scope":                   {"U":"Unchanged","C":"Changed"}[self.S],
            "confidentiality_impact":  {"N":"None","L":"Low","H":"High"}[self.C],
            "integrity_impact":        {"N":"None","L":"Low","H":"High"}[self.I],
            "availability_impact":     {"N":"None","L":"Low","H":"High"}[self.A],
        }


# ─── Parse metrics from LLM JSON ─────────────────────────────────────

VALID = {
    "AV": {"N","A","L","P"},
    "AC": {"L","H"},
    "PR": {"N","L","H"},
    "UI": {"N","R"},
    "S":  {"U","C"},
    "C":  {"N","L","H"},
    "I":  {"N","L","H"},
    "A":  {"N","L","H"},
}

_FULL_TO_ABBR = {
    # AV
    "network": "N", "adjacent": "A", "local": "L", "physical": "P",
    # AC
    "low": "L", "high": "H",
    # PR / UI
    "none": "N", "required": "R",
    # S
    "unchanged": "U", "changed": "C",
}

def _norm(val: str, key: str) -> str:
    """Normalise a metric value string to the single-char abbreviation."""
    v = val.strip().upper()
    if v in VALID[key]:
        return v
    # Try first char
    if v[:1] in VALID[key]:
        return v[:1]
    # Try full-word mapping
    mapped = _FULL_TO_ABBR.get(val.strip().lower())
    if mapped and mapped in VALID[key]:
        return mapped
    raise ValueError(f"Invalid CVSS metric {key}={val!r}")


def cvss_from_dict(d: dict) -> CVSSv3:
    """
    Build a CVSSv3 from a dict produced by the LLM.
    Keys accepted (case-insensitive): AV, AC, PR, UI, S, C, I, A
    Plus aliases: attack_vector, attack_complexity, etc.
    """
    alias = {
        "attack_vector": "AV", "attack_complexity": "AC",
        "privileges_required": "PR", "user_interaction": "UI",
        "scope": "S",
        "confidentiality": "C", "confidentiality_impact": "C",
        "integrity": "I",       "integrity_impact": "I",
        "availability": "A",    "availability_impact": "A",
    }
    clean = {}
    for k, v in d.items():
        key = alias.get(k.lower(), k.upper())
        if key in VALID:
            clean[key] = v

    return CVSSv3(
        AV = _norm(clean.get("AV", "N"), "AV"),
        AC = _norm(clean.get("AC", "L"), "AC"),
        PR = _norm(clean.get("PR", "N"), "PR"),
        UI = _norm(clean.get("UI", "N"), "UI"),
        S  = _norm(clean.get("S",  "U"), "S"),
        C  = _norm(clean.get("C",  "N"), "C"),
        I  = _norm(clean.get("I",  "N"), "I"),
        A  = _norm(clean.get("A",  "N"), "A"),
    )
