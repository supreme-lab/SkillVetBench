"""
cvss.py  —  CVSS v4.0 Calculator
=================================
Implements the CVSS version 4.0 scoring specification as defined by FIRST:
  https://www.first.org/cvss/v4.0/specification-document  (Document version 1.2)

Algorithm summary
-----------------
CVSS v4.0 does NOT use a closed-form formula like v3.1.
It uses a three-step MacroVector + interpolation algorithm (Section 8.2):

  Step 1  Resolve effective metric values
            - Modified Base metrics (MAV, MAC, …) override base values
            - E=X defaults to A (worst-case Exploit Maturity)
            - CR/IR/AR=X default to H (worst-case requirements)

  Step 2  Compute a 6-digit MacroVector string (EQ1–EQ6) by applying
          boolean classification rules to the resolved metrics, then look
          up its pre-computed base score in the 270-entry official table.

  Step 3  Interpolate downward within the MacroVector using the severity
          distance of the actual vector from the MacroVector's
          highest-severity vector, weighted by the available score range
          to the next-lower MacroVector.

  Final score = max(0.0, min(10.0, table_score − mean_correction))

Metric groups
-------------
  Base (11 mandatory)    — AV AC AT PR UI / VC VI VA / SC SI SA
  Threat (1 optional)    — E
  Environmental (14)     — CR IR AR / MAV MAC MAT MPR MUI / MVC MVI MVA MSC MSI MSA
  Supplemental (6)       — S AU U R V RE
                           These are informational only — they do NOT affect the score.

Reference implementations
--------------------------
Official FIRST/Red Hat JavaScript:
  https://github.com/RedHatProductSecurity/cvss-v4-calculator
Official Red Hat Python library (cvss package):
  https://github.com/RedHatProductSecurity/cvss

The 270-entry lookup table and MAX_SEVERITY / MAX_COMPOSED constants are
reproduced from the official Red Hat Python implementation (Apache 2.0 /
FIRST open licence).

CVSS is owned by FIRST.Org, Inc. and used by permission.
Full licence: https://www.first.org/cvss/

Usage
-----
  from cvss import CVSSv4, cvss4_from_dict, severity_label

  # From a CVSS v4.0 vector string (supplemental metrics parsed automatically)
  v = CVSSv4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/S:P/AU:Y/U:Red/R:U/V:C/RE:H")
  print(v.score())          # 10.0
  print(v.severity())       # Critical
  print(v.nomenclature())   # CVSS-B
  print(v.vector())         # CVSS:4.0/AV:N/…/S:P/AU:Y/…

  # From keyword arguments
  v = CVSSv4(AV="N", AC="L", AT="N", PR="N", UI="N",
             VC="H", VI="H", VA="H", SC="H", SI="H", SA="H",
             S="P", AU="Y", U="Red", R="U", V="C", RE="H")

  # Full structured report (includes supplemental fields)
  r = v.full_report()
  d = v.as_dict()
"""

import math
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Metric definitions — valid values per metric
# Source: CVSS v4.0 Specification Document, Sections 2–5
# ─────────────────────────────────────────────────────────────────────────────

VALID: dict[str, list[str]] = {
    # ── Base: Exploitability ─────────────────────────────────────────────────
    "AV":  ["N", "A", "L", "P"],        # Attack Vector
    "AC":  ["L", "H"],                   # Attack Complexity
    "AT":  ["N", "P"],                   # Attack Requirements  ← new in v4.0
    "PR":  ["N", "L", "H"],             # Privileges Required
    "UI":  ["N", "P", "A"],             # User Interaction (3 values, was 2 in v3.1)
    # ── Base: Vulnerable System Impact ──────────────────────────────────────
    "VC":  ["H", "L", "N"],             # Confidentiality
    "VI":  ["H", "L", "N"],             # Integrity
    "VA":  ["H", "L", "N"],             # Availability
    # ── Base: Subsequent System Impact  (replaces Scope from v3.1) ──────────
    "SC":  ["H", "L", "N"],             # Confidentiality
    "SI":  ["H", "L", "N"],             # Integrity  (Safety "S" only via MSI)
    "SA":  ["H", "L", "N"],             # Availability  (Safety "S" only via MSA)
    # ── Threat (replaces Temporal from v3.1) ─────────────────────────────────
    "E":   ["A", "P", "U", "X"],        # Exploit Maturity
    # ── Environmental: CIA Requirements ─────────────────────────────────────
    "CR":  ["H", "M", "L", "X"],
    "IR":  ["H", "M", "L", "X"],
    "AR":  ["H", "M", "L", "X"],
    # ── Environmental: Modified Base (overrides for consumer's environment) ──
    "MAV": ["N", "A", "L", "P", "X"],
    "MAC": ["L", "H", "X"],
    "MAT": ["N", "P", "X"],
    "MPR": ["N", "L", "H", "X"],
    "MUI": ["N", "P", "A", "X"],
    "MVC": ["H", "L", "N", "X"],
    "MVI": ["H", "L", "N", "X"],
    "MVA": ["H", "L", "N", "X"],
    "MSC": ["H", "L", "N", "X"],
    "MSI": ["S", "H", "L", "N", "X"],  # Safety (S) valid for MSI
    "MSA": ["S", "H", "L", "N", "X"],  # Safety (S) valid for MSA
    # ── Supplemental (informational only — do NOT affect the score) ──────────
    # Source: CVSS v4.0 Specification Document, Section 4
    "S":   ["X", "N", "P"],             # Safety
    "AU":  ["X", "N", "Y"],             # Automatable
    "U":   ["X", "Clear", "Green", "Amber", "Red"],  # Provider Urgency
    "R":   ["X", "A", "U", "I"],        # Recovery  (A=Automatic U=User I=Irrecoverable)
    "V":   ["X", "D", "C"],             # Value Density  (D=Diffuse C=Concentrated)
    "RE":  ["X", "L", "M", "H"],        # Vulnerability Response Effort
}

MANDATORY: set[str] = {
    "AV", "AC", "AT", "PR", "UI",
    "VC", "VI", "VA",
    "SC", "SI", "SA",
}

# Supplemental metrics — stored and reported but NEVER used in score()
SUPPLEMENTAL: set[str] = {"S", "AU", "U", "R", "V", "RE"}

# Default value for every optional metric when not specified
OPTIONAL_DEFAULTS: dict[str, str] = {
    "E":   "X",
    "CR":  "X", "IR":  "X", "AR":  "X",
    "MAV": "X", "MAC": "X", "MAT": "X", "MPR": "X", "MUI": "X",
    "MVC": "X", "MVI": "X", "MVA": "X",
    "MSC": "X", "MSI": "X", "MSA": "X",
    # Supplemental defaults
    "S":   "X", "AU":  "X", "U":   "X", "R":   "X", "V":   "X", "RE":  "X",
}

# Canonical vector string ordering (Section 7 of the spec)
# Supplemental metrics appear at the end, after Environmental
METRIC_ORDER: list[str] = [
    # Base
    "AV", "AC", "AT", "PR", "UI",
    "VC", "VI", "VA", "SC", "SI", "SA",
    # Threat
    "E",
    # Environmental
    "CR", "IR", "AR",
    "MAV", "MAC", "MAT", "MPR", "MUI",
    "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
    # Supplemental
    "S", "AU", "U", "R", "V", "RE",
]

# Human-readable labels for report output
VALUE_LABELS: dict[str, dict[str, str]] = {
    "AV":  {"N": "Network",    "A": "Adjacent",  "L": "Local",    "P": "Physical"},
    "AC":  {"L": "Low",        "H": "High"},
    "AT":  {"N": "None",       "P": "Present"},
    "PR":  {"N": "None",       "L": "Low",       "H": "High"},
    "UI":  {"N": "None",       "P": "Passive",   "A": "Active"},
    "VC":  {"H": "High",       "L": "Low",       "N": "None"},
    "VI":  {"H": "High",       "L": "Low",       "N": "None"},
    "VA":  {"H": "High",       "L": "Low",       "N": "None"},
    "SC":  {"H": "High",       "L": "Low",       "N": "None"},
    "SI":  {"H": "High",       "L": "Low",       "N": "None"},
    "SA":  {"H": "High",       "L": "Low",       "N": "None"},
    "MSI": {"S": "Safety",     "H": "High",      "L": "Low",   "N": "Negligible", "X": "Not Defined"},
    "MSA": {"S": "Safety",     "H": "High",      "L": "Low",   "N": "Negligible", "X": "Not Defined"},
    "E":   {"A": "Attacked",   "P": "Proof-of-Concept", "U": "Unreported", "X": "Not Defined"},
    "CR":  {"H": "High",       "M": "Medium",    "L": "Low",   "X": "Not Defined"},
    "IR":  {"H": "High",       "M": "Medium",    "L": "Low",   "X": "Not Defined"},
    "AR":  {"H": "High",       "M": "Medium",    "L": "Low",   "X": "Not Defined"},
    # Supplemental
    "S":   {"X": "Not Defined", "N": "Negligible", "P": "Present"},
    "AU":  {"X": "Not Defined", "N": "No",          "Y": "Yes"},
    "U":   {"X": "Not Defined", "Clear": "Clear",   "Green": "Green",
                                 "Amber": "Amber",   "Red": "Red"},
    "R":   {"X": "Not Defined", "A": "Automatic",   "U": "User",   "I": "Irrecoverable"},
    "V":   {"X": "Not Defined", "D": "Diffuse",     "C": "Concentrated"},
    "RE":  {"X": "Not Defined", "L": "Low",         "M": "Medium", "H": "High"},
}
# ─────────────────────────────────────────────────────────────────────────────
# Severity ordering used for severity-distance computation (Section 8.2)
# Supplemental metrics are NOT included here — they play no role in scoring.
# ─────────────────────────────────────────────────────────────────────────────

METRIC_LEVELS: dict[str, dict[str, float]] = {
    "AV":  {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR":  {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI":  {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC":  {"L": 0.0, "H": 0.1},
    "AT":  {"N": 0.0, "P": 0.1},
    "VC":  {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI":  {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA":  {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC":  {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI":  {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA":  {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR":  {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR":  {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR":  {"H": 0.0, "M": 0.1, "L": 0.2},
}

# ─────────────────────────────────────────────────────────────────────────────
# Official 270-entry MacroVector score lookup table
# ─────────────────────────────────────────────────────────────────────────────

CVSS_LOOKUP: dict[str, float] = {
    "000000": 10.0, "000001": 9.9,  "000010": 9.8,  "000011": 9.5,
    "000020": 9.5,  "000021": 9.2,  "000100": 10.0, "000101": 9.6,
    "000110": 9.3,  "000111": 8.7,  "000120": 9.1,  "000121": 8.1,
    "000200": 9.3,  "000201": 9.0,  "000210": 8.9,  "000211": 8.0,
    "000220": 8.1,  "000221": 6.8,  "001000": 9.8,  "001001": 9.5,
    "001010": 9.5,  "001011": 9.2,  "001020": 9.0,  "001021": 8.4,
    "001100": 9.3,  "001101": 9.2,  "001110": 8.9,  "001111": 8.1,
    "001120": 8.1,  "001121": 6.5,  "001200": 8.8,  "001201": 8.0,
    "001210": 7.8,  "001211": 7.0,  "001220": 6.9,  "001221": 4.8,
    "002001": 9.2,  "002011": 8.2,  "002021": 7.2,  "002101": 7.9,
    "002111": 6.9,  "002121": 5.0,  "002201": 6.9,  "002211": 5.5,
    "002221": 2.7,  "010000": 9.9,  "010001": 9.7,  "010010": 9.5,
    "010011": 9.2,  "010020": 9.2,  "010021": 8.5,  "010100": 9.5,
    "010101": 9.1,  "010110": 9.0,  "010111": 8.3,  "010120": 8.4,
    "010121": 7.1,  "010200": 9.2,  "010201": 8.1,  "010210": 8.2,
    "010211": 7.1,  "010220": 7.2,  "010221": 5.3,  "011000": 9.5,
    "011001": 9.3,  "011010": 9.2,  "011011": 8.5,  "011020": 8.5,
    "011021": 7.3,  "011100": 9.2,  "011101": 8.2,  "011110": 8.0,
    "011111": 7.2,  "011120": 7.0,  "011121": 5.9,  "011200": 8.4,
    "011201": 7.0,  "011210": 7.1,  "011211": 5.2,  "011220": 5.0,
    "011221": 3.0,  "012001": 8.6,  "012011": 7.5,  "012021": 5.2,
    "012101": 7.1,  "012111": 5.2,  "012121": 2.9,  "012201": 6.3,
    "012211": 2.9,  "012221": 1.7,  "100000": 9.8,  "100001": 9.5,
    "100010": 9.4,  "100011": 8.7,  "100020": 9.1,  "100021": 8.1,
    "100100": 9.4,  "100101": 8.9,  "100110": 8.6,  "100111": 7.4,
    "100120": 7.7,  "100121": 6.4,  "100200": 8.7,  "100201": 7.5,
    "100210": 7.4,  "100211": 6.3,  "100220": 6.3,  "100221": 4.9,
    "101000": 9.4,  "101001": 8.9,  "101010": 8.8,  "101011": 7.7,
    "101020": 7.6,  "101021": 6.7,  "101100": 8.6,  "101101": 7.6,
    "101110": 7.4,  "101111": 5.8,  "101120": 5.9,  "101121": 5.0,
    "101200": 7.2,  "101201": 5.7,  "101210": 5.7,  "101211": 5.2,
    "101220": 5.2,  "101221": 2.5,  "102001": 8.3,  "102011": 7.0,
    "102021": 5.4,  "102101": 6.5,  "102111": 5.8,  "102121": 2.6,
    "102201": 5.3,  "102211": 2.1,  "102221": 1.3,  "110000": 9.5,
    "110001": 9.0,  "110010": 8.8,  "110011": 7.6,  "110020": 7.6,
    "110021": 7.0,  "110100": 9.0,  "110101": 7.7,  "110110": 7.5,
    "110111": 6.2,  "110120": 6.1,  "110121": 5.3,  "110200": 7.7,
    "110201": 6.6,  "110210": 6.8,  "110211": 5.9,  "110220": 5.2,
    "110221": 3.0,  "111000": 8.9,  "111001": 7.8,  "111010": 7.6,
    "111011": 6.7,  "111020": 6.2,  "111021": 5.8,  "111100": 7.4,
    "111101": 5.9,  "111110": 5.7,  "111111": 5.7,  "111120": 4.7,
    "111121": 2.3,  "111200": 6.1,  "111201": 5.2,  "111210": 5.7,
    "111211": 2.9,  "111220": 2.4,  "111221": 1.6,  "112001": 7.1,
    "112011": 5.9,  "112021": 3.0,  "112101": 5.8,  "112111": 2.6,
    "112121": 1.5,  "112201": 2.3,  "112211": 1.3,  "112221": 0.6,
    "200000": 9.3,  "200001": 8.7,  "200010": 8.6,  "200011": 7.2,
    "200020": 7.5,  "200021": 5.8,  "200100": 8.6,  "200101": 7.4,
    "200110": 7.4,  "200111": 6.1,  "200120": 5.6,  "200121": 3.4,
    "200200": 7.0,  "200201": 5.4,  "200210": 5.2,  "200211": 4.0,
    "200220": 4.0,  "200221": 2.2,  "201000": 8.5,  "201001": 7.5,
    "201010": 7.4,  "201011": 5.5,  "201020": 6.2,  "201021": 5.1,
    "201100": 7.2,  "201101": 5.7,  "201110": 5.5,  "201111": 4.1,
    "201120": 4.6,  "201121": 1.9,  "201200": 5.3,  "201201": 3.6,
    "201210": 3.4,  "201211": 1.9,  "201220": 1.9,  "201221": 0.8,
    "202001": 6.4,  "202011": 5.1,  "202021": 2.0,  "202101": 4.7,
    "202111": 2.1,  "202121": 1.1,  "202201": 2.4,  "202211": 0.9,
    "202221": 0.4,  "210000": 8.8,  "210001": 7.5,  "210010": 7.3,
    "210011": 5.3,  "210020": 6.0,  "210021": 5.0,  "210100": 7.3,
    "210101": 5.5,  "210110": 5.9,  "210111": 4.0,  "210120": 4.1,
    "210121": 2.0,  "210200": 5.4,  "210201": 4.3,  "210210": 4.5,
    "210211": 2.2,  "210220": 2.0,  "210221": 1.1,  "211000": 7.5,
    "211001": 5.5,  "211010": 5.8,  "211011": 4.5,  "211020": 4.0,
    "211021": 2.1,  "211100": 6.1,  "211101": 5.1,  "211110": 4.8,
    "211111": 1.8,  "211120": 2.0,  "211121": 0.9,  "211200": 4.6,
    "211201": 1.8,  "211210": 1.7,  "211211": 0.7,  "211220": 0.8,
    "211221": 0.2,  "212001": 5.3,  "212011": 2.4,  "212021": 1.4,
    "212101": 2.4,  "212111": 1.2,  "212121": 0.5,  "212201": 1.0,
    "212211": 0.3,  "212221": 0.1,
}

assert len(CVSS_LOOKUP) == 270, f"Lookup table must have 270 entries, has {len(CVSS_LOOKUP)}"

# ─────────────────────────────────────────────────────────────────────────────
# Highest-severity vectors and severity depths (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────

EQ1_HIGHEST: dict[str, list[str]] = {
    "0": ["AV:N/PR:N/UI:N"],
    "1": ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"],
    "2": ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"],
}

EQ2_HIGHEST: dict[str, list[str]] = {
    "0": ["AC:L/AT:N"],
    "1": ["AC:H/AT:N", "AC:L/AT:P"],
}

EQ3_EQ6_HIGHEST: dict[str, dict[str, list[str]]] = {
    "0": {
        "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"],
        "1": [
            "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H",
            "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M",
        ],
    },
    "1": {
        "0": [
            "VC:L/VI:H/VA:H/CR:H/IR:H/AR:H",
            "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H",
        ],
        "1": [
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M",
        ],
    },
    "2": {
        "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"],
    },
}

EQ4_HIGHEST: dict[str, list[str]] = {
    "0": ["SC:H/SI:S/SA:S"],
    "1": ["SC:H/SI:H/SA:H"],
    "2": ["SC:L/SI:L/SA:L"],
}

EQ5_HIGHEST: dict[str, list[str]] = {
    "0": ["E:A"],
    "1": ["E:P"],
    "2": ["E:U"],
}

MAX_SEVERITY: dict = {
    "eq1":    {0: 1,  1: 4,  2: 5},
    "eq2":    {0: 1,  1: 2},
    "eq3eq6": {
        0: {0: 7,  1: 6},
        1: {0: 8,  1: 8},
        2: {       1: 10},
    },
    "eq4":    {0: 6,  1: 5,  2: 4},
    "eq5":    {0: 1,  1: 1,  2: 1},
}

# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CVSSv4Report:
    """
    Structured result from CVSSv4.full_report().

    score / severity_label / nomenclature / vector_string are the primary
    outputs.  Supplemental fields (safety, automatable, …) are informational
    only and have no effect on the numeric score.
    """
    score:               float
    severity_label:      str
    nomenclature:        str
    vector_string:       str
    macro_vector:        str
    macro_vector_score:  float
    # Exploitability
    attack_vector:       str
    attack_complexity:   str
    attack_requirements: str
    privileges_required: str
    user_interaction:    str
    # Vulnerable System CIA
    vc: str
    vi: str
    va: str
    # Subsequent System CIA
    sc: str
    si: str
    sa: str
    # Threat
    exploit_maturity:    str
    # Environmental requirements
    cr: str
    ir: str
    ar: str
    # ── Supplemental (informational only) ────────────────────────────────────
    safety:                        str   # S  — physical/cyber safety impact
    automatable:                   str   # AU — can the attack be automated?
    provider_urgency:              str   # U  — vendor-assigned urgency label
    recovery:                      str   # R  — system recovery after exploit
    value_density:                 str   # V  — resources available to attacker
    vulnerability_response_effort: str   # RE — effort to respond/patch


# ─────────────────────────────────────────────────────────────────────────────
# Main scorer class
# ─────────────────────────────────────────────────────────────────────────────

class CVSSv4:
    """
    CVSS v4.0 scorer.

    Accepts a CVSS:4.0/… vector string, or individual metric keyword arguments,
    or a plain dict via class methods.  All 11 mandatory base metrics must be
    supplied.  Optional metrics (including all 6 supplemental) default to "X".

    Supplemental metrics (S, AU, U, R, V, RE) are stored and included in the
    vector string and report but DO NOT influence the numeric score.
    """

    def __init__(self, vector_string: str = "", **kwargs):
        self._raw: dict[str, str] = {}
        if vector_string:
            self._parse_vector(vector_string)
        elif kwargs:
            self._raw = {k.upper(): v for k, v in kwargs.items()}
            # Provider Urgency values are mixed-case (Clear/Green/Amber/Red)
            # — preserve their case; upper() everything else
            for k, v in list(self._raw.items()):
                if k != "U":
                    self._raw[k] = v.upper()
        else:
            raise ValueError(
                "Provide either a CVSS v4.0 vector string or metric keyword arguments."
            )
        self._validate()
        for metric, default in OPTIONAL_DEFAULTS.items():
            self._raw.setdefault(metric, default)

    # ── Alternate constructors ────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, d: dict) -> "CVSSv4":
        """Build from a plain dict with metric abbreviation keys."""
        return cls(**{k.upper(): str(v) for k, v in d.items()})

    @classmethod
    def from_llm_json(cls, d: dict) -> "CVSSv4":
        """
        Build from LLM-generated JSON that may use full English names or values.
        Handles both abbreviated (AV, AC) and full-word keys (attack_vector).
        """
        KEY_MAP = {
            "attack_vector":               "AV",
            "attack_complexity":           "AC",
            "attack_requirements":         "AT",
            "privileges_required":         "PR",
            "user_interaction":            "UI",
            "vc": "VC", "vi": "VI", "va": "VA",
            "sc": "SC", "si": "SI", "sa": "SA",
            "exploit_maturity":            "E",
            "e":                           "E",
            "cr": "CR", "ir": "IR", "ar": "AR",
            "confidentiality_requirement": "CR",
            "integrity_requirement":       "IR",
            "availability_requirement":    "AR",
            # Supplemental
            "safety":                         "S",
            "automatable":                    "AU",
            "au":                             "AU",
            "provider_urgency":               "U",
            "urgency":                        "U",
            "recovery":                       "R",
            "r":                              "R",
            "value_density":                  "V",
            "v":                              "V",
            "vulnerability_response_effort":  "RE",
            "response_effort":                "RE",
            "re":                             "RE",
        }
        VAL_MAP = {
            # Base / Threat / Environmental values
            "network": "N",  "adjacent": "A",  "local": "L",   "physical": "P",
            "low": "L",      "high": "H",      "none": "N",    "present": "P",
            "passive": "P",  "active": "A",    "medium": "M",  "safety": "S",
            "attacked": "A", "proof-of-concept": "P", "poc": "P",
            "unreported": "U",
            "not defined": "X", "not_defined": "X", "x": "X",
            # Supplemental — Automatable
            "yes": "Y", "no": "N",
            # Supplemental — Recovery
            "automatic": "A", "user": "U", "irrecoverable": "I",
            # Supplemental — Value Density
            "diffuse": "D", "concentrated": "C",
            # Supplemental — Response Effort
            # low/medium/high already covered above
            # Supplemental — Provider Urgency (preserve mixed case)
            "clear": "Clear", "green": "Green", "amber": "Amber", "red": "Red",
        }
        clean: dict[str, str] = {}
        for raw_key, raw_val in d.items():
            key = KEY_MAP.get(raw_key.lower(), raw_key.upper())
            if key in VALID:
                raw_str = str(raw_val)
                # Preserve Provider Urgency mixed case
                if key == "U" and raw_str in ("Clear", "Green", "Amber", "Red"):
                    val = raw_str
                else:
                    val = VAL_MAP.get(raw_str.lower(), raw_str.upper())
                clean[key] = val
        return cls(**clean)

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_vector(self, s: str):
        s = s.strip()
        if not s.startswith("CVSS:4.0/"):
            raise ValueError(
                f"Invalid CVSS v4.0 vector string — must begin with 'CVSS:4.0/'.\n"
                f"Got: {s[:50]!r}"
            )
        for part in s[len("CVSS:4.0/"):].split("/"):
            if not part:
                continue
            if ":" not in part:
                raise ValueError(f"Malformed CVSS metric field (no colon): {part!r}")
            metric, value = part.split(":", 1)
            metric = metric.upper()
            # Provider Urgency values are mixed-case — don't upper() them
            if metric != "U":
                value = value.upper()
            self._raw[metric] = value

    def _validate(self):
        missing = MANDATORY - set(self._raw)
        if missing:
            raise ValueError(
                f"Missing mandatory CVSS v4.0 metrics: {sorted(missing)}\n"
                f"All 11 base metrics are required: "
                f"AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA"
            )
        for metric, value in self._raw.items():
            if metric not in VALID:
                raise ValueError(f"Unknown CVSS v4.0 metric: {metric!r}")
            if value not in VALID[metric]:
                raise ValueError(
                    f"Invalid value {value!r} for metric {metric!r}.\n"
                    f"Allowed values: {VALID[metric]}"
                )

    # ── Metric resolution ─────────────────────────────────────────────────────

    def _m(self, metric: str) -> str:
        """
        Return the effective resolved value for a metric.
        Supplemental metrics are never passed to this method during scoring.
        """
        val = self._raw.get(metric, "X")

        if metric == "E" and val == "X":
            return "A"
        if metric in ("CR", "IR", "AR") and val == "X":
            return "H"

        mod_key = "M" + metric
        if mod_key in self._raw:
            mod_val = self._raw[mod_key]
            if mod_val != "X":
                return mod_val

        return val

    def _supp(self, metric: str) -> str:
        """Return the raw value of a supplemental metric (X if not set)."""
        return self._raw.get(metric, "X")

    # ── MacroVector computation ───────────────────────────────────────────────

    def _macro_vector(self) -> str:
        av  = self._m("AV");  pr  = self._m("PR");  ui  = self._m("UI")
        ac  = self._m("AC");  at  = self._m("AT")
        vc  = self._m("VC");  vi  = self._m("VI");  va  = self._m("VA")
        sc  = self._m("SC");  si  = self._m("SI");  sa  = self._m("SA")
        e   = self._m("E")
        cr  = self._m("CR");  ir  = self._m("IR");  ar  = self._m("AR")

        if av == "N" and pr == "N" and ui == "N":
            eq1 = 0
        elif (
            (av == "N" or pr == "N" or ui == "N")
            and not (av == "N" and pr == "N" and ui == "N")
            and av != "P"
        ):
            eq1 = 1
        else:
            eq1 = 2

        eq2 = 0 if (ac == "L" and at == "N") else 1

        if vc == "H" and vi == "H":
            eq3 = 0
        elif (vc == "H" or vi == "H" or va == "H") and not (vc == "H" and vi == "H"):
            eq3 = 1
        else:
            eq3 = 2

        if si == "S" or sa == "S":
            eq4 = 0
        elif sc == "H" or si == "H" or sa == "H":
            eq4 = 1
        else:
            eq4 = 2

        eq5 = {"A": 0, "P": 1}.get(e, 2)

        eq6 = 0 if (
            (cr == "H" and vc == "H")
            or (ir == "H" and vi == "H")
            or (ar == "H" and va == "H")
        ) else 1

        return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

    # ── Highest-severity vector lookup ────────────────────────────────────────

    def _find_highest_vector(self, mv: str) -> str:
        e1v = mv[0]; e2v = mv[1]; e3v = mv[2]
        e4v = mv[3]; e5v = mv[4]; e6v = mv[5]

        candidates_eq1   = EQ1_HIGHEST.get(e1v, [])
        candidates_eq2   = EQ2_HIGHEST.get(e2v, [])
        candidates_eq3e6 = EQ3_EQ6_HIGHEST.get(e3v, {}).get(e6v, [])
        candidates_eq4   = EQ4_HIGHEST.get(e4v, [])
        candidates_eq5   = EQ5_HIGHEST.get(e5v, [])

        for c1 in candidates_eq1:
            for c2 in candidates_eq2:
                for c3e6 in candidates_eq3e6:
                    for c4 in candidates_eq4:
                        for c5 in candidates_eq5:
                            combined = "/".join([c1, c2, c3e6, c4, c5])
                            parts = {
                                seg.split(":")[0]: seg.split(":")[1]
                                for seg in combined.split("/")
                                if ":" in seg
                            }
                            all_non_negative = True
                            for metric, h_val in parts.items():
                                if metric not in METRIC_LEVELS:
                                    continue
                                my_val = self._m(metric)
                                if my_val not in METRIC_LEVELS[metric]:
                                    continue
                                dist = (
                                    METRIC_LEVELS[metric][my_val]
                                    - METRIC_LEVELS[metric][h_val]
                                )
                                if dist < -1e-9:
                                    all_non_negative = False
                                    break
                            if all_non_negative:
                                return combined

        if candidates_eq1 and candidates_eq2 and candidates_eq3e6 \
                and candidates_eq4 and candidates_eq5:
            return "/".join([
                candidates_eq1[0], candidates_eq2[0],
                candidates_eq3e6[0], candidates_eq4[0], candidates_eq5[0]
            ])
        return ""

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self) -> float:
        """
        Compute and return the CVSS v4.0 score (0.0 – 10.0, 1 decimal place).
        Supplemental metrics are completely ignored in this calculation.
        """
        if all(self._m(m) == "N" for m in ("VC", "VI", "VA", "SC", "SI", "SA")):
            return 0.0

        mv = self._macro_vector()
        table_score = CVSS_LOOKUP.get(mv)
        if table_score is None:
            raise ValueError(
                f"MacroVector {mv!r} not found in the lookup table. "
                "This usually means a metric value is invalid."
            )

        e1v = int(mv[0]); e2v = int(mv[1]); e3v = int(mv[2])
        e4v = int(mv[3]); e5v = int(mv[4]); e6v = int(mv[5])

        def _mv_score(digits: list[int]) -> float:
            return CVSS_LOOKUP.get("".join(str(d) for d in digits), float("nan"))

        score_lower_eq1 = _mv_score([e1v+1, e2v, e3v, e4v, e5v, e6v])
        score_lower_eq2 = _mv_score([e1v, e2v+1, e3v, e4v, e5v, e6v])
        score_lower_eq4 = _mv_score([e1v, e2v, e3v, e4v+1, e5v, e6v])
        score_lower_eq5 = _mv_score([e1v, e2v, e3v, e4v, e5v+1, e6v])

        if e3v == 1 and e6v == 1:
            score_lower_eq3eq6 = _mv_score([e1v, e2v, e3v+1, e4v, e5v, e6v])
        elif e3v == 0 and e6v == 1:
            score_lower_eq3eq6 = _mv_score([e1v, e2v, e3v+1, e4v, e5v, e6v])
        elif e3v == 1 and e6v == 0:
            score_lower_eq3eq6 = _mv_score([e1v, e2v, e3v, e4v, e5v, e6v+1])
        elif e3v == 0 and e6v == 0:
            left  = _mv_score([e1v, e2v, e3v, e4v, e5v, e6v+1])
            right = _mv_score([e1v, e2v, e3v+1, e4v, e5v, e6v])
            valid = [x for x in (left, right) if not math.isnan(x)]
            score_lower_eq3eq6 = max(valid) if valid else float("nan")
        else:
            score_lower_eq3eq6 = _mv_score([e1v, e2v, e3v+1, e4v, e5v, e6v+1])

        highest_vec = self._find_highest_vector(mv)
        if not highest_vec:
            return _round_half_up(max(0.0, min(10.0, table_score)))

        h_parts: dict[str, str] = {
            seg.split(":")[0]: seg.split(":")[1]
            for seg in highest_vec.split("/")
            if ":" in seg
        }

        def _dist(metric: str) -> float:
            if metric not in h_parts or metric not in METRIC_LEVELS:
                return 0.0
            my_val = self._m(metric)
            h_val  = h_parts[metric]
            if my_val not in METRIC_LEVELS[metric] or h_val not in METRIC_LEVELS[metric]:
                return 0.0
            return METRIC_LEVELS[metric][my_val] - METRIC_LEVELS[metric][h_val]

        step = 0.1
        dist_eq1    = _dist("AV") + _dist("PR") + _dist("UI")
        dist_eq2    = _dist("AC") + _dist("AT")
        dist_eq3eq6 = (
            _dist("VC") + _dist("VI") + _dist("VA")
            + _dist("CR") + _dist("IR") + _dist("AR")
        )
        dist_eq4 = _dist("SC") + _dist("SI") + _dist("SA")

        max_eq1    = MAX_SEVERITY["eq1"].get(e1v, 1) * step
        max_eq2    = MAX_SEVERITY["eq2"].get(e2v, 1) * step
        max_eq3eq6 = MAX_SEVERITY["eq3eq6"].get(e3v, {}).get(e6v, 1) * step
        max_eq4    = MAX_SEVERITY["eq4"].get(e4v, 1) * step

        n_lower = 0
        norm_eq1 = norm_eq2 = norm_eq3eq6 = norm_eq4 = norm_eq5 = 0.0

        def _normalise(avail: float, dist: float, max_depth: float) -> tuple[bool, float]:
            if not (isinstance(avail, float) and not math.isnan(avail) and avail >= 0):
                return False, 0.0
            pct = (dist / max_depth) if max_depth > 0 else 0.0
            return True, avail * pct

        avail_eq1    = table_score - score_lower_eq1
        avail_eq2    = table_score - score_lower_eq2
        avail_eq3eq6 = table_score - score_lower_eq3eq6
        avail_eq4    = table_score - score_lower_eq4
        avail_eq5    = table_score - score_lower_eq5

        ok, norm_eq1    = _normalise(avail_eq1,    dist_eq1,    max_eq1)
        if ok: n_lower += 1
        ok, norm_eq2    = _normalise(avail_eq2,    dist_eq2,    max_eq2)
        if ok: n_lower += 1
        ok, norm_eq3eq6 = _normalise(avail_eq3eq6, dist_eq3eq6, max_eq3eq6)
        if ok: n_lower += 1
        ok, norm_eq4    = _normalise(avail_eq4,    dist_eq4,    max_eq4)
        if ok: n_lower += 1
        if (isinstance(avail_eq5, float) and not math.isnan(avail_eq5) and avail_eq5 >= 0):
            n_lower += 1
            norm_eq5 = avail_eq5 * 0.0

        if n_lower > 0:
            mean_correction = (
                norm_eq1 + norm_eq2 + norm_eq3eq6 + norm_eq4 + norm_eq5
            ) / n_lower
            table_score -= mean_correction

        return _round_half_up(max(0.0, min(10.0, table_score)))

    # ── Convenience accessors ─────────────────────────────────────────────────

    def severity(self) -> str:
        return severity_label(self.score())

    def vector(self) -> str:
        """
        Return the canonical CVSS v4.0 vector string.
        Supplemental metrics are included when set (not "X").
        Optional metrics set to "X" are omitted.
        """
        parts = []
        for metric in METRIC_ORDER:
            val = self._raw.get(metric, "X")
            if metric in MANDATORY or val != "X":
                parts.append(f"{metric}:{val}")
        return "CVSS:4.0/" + "/".join(parts)

    def nomenclature(self) -> str:
        has_threat = self._raw.get("E", "X") != "X"
        env_metrics = (
            "CR", "IR", "AR",
            "MAV", "MAC", "MAT", "MPR", "MUI",
            "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
        )
        has_env = any(self._raw.get(m, "X") != "X" for m in env_metrics)
        if has_threat and has_env: return "CVSS-BTE"
        if has_threat:             return "CVSS-BT"
        if has_env:                return "CVSS-BE"
        return "CVSS-B"

    def has_supplemental(self) -> bool:
        """Return True if any supplemental metric is set (not X)."""
        return any(self._raw.get(m, "X") != "X" for m in SUPPLEMENTAL)

    def full_report(self) -> CVSSv4Report:
        """Return all scoring details, resolved metric values, and supplemental fields."""
        s  = self.score()
        mv = self._macro_vector()

        def lbl(metric: str) -> str:
            val = self._m(metric)
            return VALUE_LABELS.get(metric, {}).get(val, val)

        def slbl(metric: str) -> str:
            """Label for a supplemental metric."""
            val = self._supp(metric)
            return VALUE_LABELS.get(metric, {}).get(val, val)

        return CVSSv4Report(
            score               = s,
            severity_label      = self.severity(),
            nomenclature        = self.nomenclature(),
            vector_string       = self.vector(),
            macro_vector        = mv,
            macro_vector_score  = CVSS_LOOKUP.get(mv, float("nan")),
            attack_vector       = lbl("AV"),
            attack_complexity   = lbl("AC"),
            attack_requirements = lbl("AT"),
            privileges_required = lbl("PR"),
            user_interaction    = lbl("UI"),
            vc                  = lbl("VC"),
            vi                  = lbl("VI"),
            va                  = lbl("VA"),
            sc                  = lbl("SC"),
            si                  = lbl("SI"),
            sa                  = lbl("SA"),
            exploit_maturity    = lbl("E"),
            cr                  = lbl("CR"),
            ir                  = lbl("IR"),
            ar                  = lbl("AR"),
            # Supplemental
            safety                        = slbl("S"),
            automatable                   = slbl("AU"),
            provider_urgency              = slbl("U"),
            recovery                      = slbl("R"),
            value_density                 = slbl("V"),
            vulnerability_response_effort = slbl("RE"),
        )

    def as_dict(self) -> dict:
        """Serialise the full report to a plain dict for JSON output."""
        r = self.full_report()
        return {
            "cvss_score":                    r.score,
            "cvss_severity":                 r.severity_label,
            "cvss_nomenclature":             r.nomenclature,
            "cvss_vector":                   r.vector_string,
            "macro_vector":                  r.macro_vector,
            "macro_vector_score":            r.macro_vector_score,
            # Base
            "attack_vector":                 r.attack_vector,
            "attack_complexity":             r.attack_complexity,
            "attack_requirements":           r.attack_requirements,
            "privileges_required":           r.privileges_required,
            "user_interaction":              r.user_interaction,
            "confidentiality_vs":            r.vc,
            "integrity_vs":                  r.vi,
            "availability_vs":               r.va,
            "confidentiality_ss":            r.sc,
            "integrity_ss":                  r.si,
            "availability_ss":               r.sa,
            # Threat
            "exploit_maturity":              r.exploit_maturity,
            # Environmental
            "cr":                            r.cr,
            "ir":                            r.ir,
            "ar":                            r.ar,
            # Supplemental (informational only — not used in scoring)
            "safety":                        r.safety,
            "automatable":                   r.automatable,
            "provider_urgency":              r.provider_urgency,
            "recovery":                      r.recovery,
            "value_density":                 r.value_density,
            "vulnerability_response_effort": r.vulnerability_response_effort,
        }

    def __repr__(self) -> str:
        return (
            f"CVSSv4(score={self.score()}, severity={self.severity()!r}, "
            f"nom={self.nomenclature()!r}, mv={self._macro_vector()!r})"
        )

# ─────────────────────────────────────────────────────────────────────────────
# Module-level helpers
# ─────────────────────────────────────────────────────────────────────────────
def severity_label(score: float) -> str:
    """Map a numeric CVSS v4.0 score to its qualitative severity label."""
    if score == 0.0:  return "None"
    if score <= 3.9:  return "Low"
    if score <= 6.9:  return "Medium"
    if score <= 8.9:  return "High"
    return "Critical"

def cvss4_from_dict(d: dict) -> "CVSSv4":
    """
    Convenience function — build a CVSSv4 object from a plain dict.
    Handles LLM-generated JSON with full English key/value names.
    """
    return CVSSv4.from_llm_json(d)

def _round_half_up(x: float) -> float:
    """Round to 1 decimal place using 'round half away from zero' (CVSS spec)."""
    EPSILON = 1e-10
    return round(float(int((x + EPSILON) * 10 + 0.5)) / 10, 1)