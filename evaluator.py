"""
evaluator.py
============
Core pipeline: load skill .md → LLM evaluation → CVSS scoring → SkillReport.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from cvss3_5 import CVSSv3, cvss_from_dict
from cvss4_0 import CVSSv4, cvss4_from_dict, severity_label
# from prompts_cvss3_5 import SKILL_SECURITY_EVAL_SYSTEM_PROMPT, build_evaluation_prompt
from prompts_cvss4_0 import SKILL_SECURITY_EVAL_SYSTEM_PROMPT, build_evaluation_prompt
from llm_client import LLMClient

logger = logging.getLogger("SkillEval")


# ─── Result dataclasses ──────────────────────────────────────────────

@dataclass
class Vulnerability:
    id:               str
    category:         str
    title:            str
    severity:         str
    affected_content: str
    explanation:      str
    attack_scenario:  str
    remediation:      str


@dataclass
class SkillReport:
    filename:               str
    skill_name:             str
    overall_risk:           str
    is_vulnerable:          bool
    vulnerability_count:    int

    # CVSS
    cvss:                   Optional[CVSSv3]
    cvss_base_score:        float
    cvss_severity:          str
    cvss_vector:            str
    impact_score:           float
    exploitability_score:   float
    attack_vector:          str
    attack_complexity:      str
    privileges_required:    str
    user_interaction:       str
    # scope:                  str # for CVSS v3.5

    # Add:
    attack_requirements:    str   # new in v4.0 (replaces Scope)
    exploit_maturity:       str   # from Threat metrics
    nomenclature:           str   # CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE

    confidentiality_impact: str
    integrity_impact:       str
    availability_impact:    str

    # Findings
    vulnerabilities:        list[Vulnerability]
    executive_summary:      str
    skill_purpose_analysis: str
    dangerous_patterns:     list[str]
    safe_patterns:          list[str]
    remediation_priority:   str

    # Meta
    error:                  str = ""


# ─── Evaluator ───────────────────────────────────────────────────────

class SkillEvaluator:

    def __init__(self, llm: LLMClient):
        self.llm = llm

    # ── Evaluate a single file ───────────────────────────────────────

    def evaluate_file(self, path: Path) -> SkillReport:
        logger.info(f"  Evaluating: {path.name}")
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return self._error_report(path.name, f"Could not read file: {e}")

        return self.evaluate_content(content, path.name)

    def evaluate_content(self, content: str, filename: str) -> SkillReport:
        """Evaluate raw skill markdown content."""
        try:
            raw = self.llm.complete(
                system_prompt = SKILL_SECURITY_EVAL_SYSTEM_PROMPT,
                user_message  = build_evaluation_prompt(content, filename),
            )
            return self._parse(raw, filename)
        except Exception as e:
            return self._error_report(filename, f"LLM call failed: {e}")

    # ── Batch evaluation ─────────────────────────────────────────────

    def evaluate_directory(
        self,
        directory: Path,
        glob: str = "**/*.md",
        recursive: bool = True,
    ) -> list[SkillReport]:
        """Evaluate all .md files in a directory."""
        files = sorted(directory.glob(glob))
        if not files:
            logger.warning(f"No .md files found in {directory}")
            return []

        logger.info(f"\nFound {len(files)} skill file(s) in {directory}")
        reports = []
        for i, f in enumerate(files, 1):
            logger.info(f"[{i}/{len(files)}] {f.name}")
            reports.append(self.evaluate_file(f))
        return reports

    # ── JSON parsing ─────────────────────────────────────────────────

    def _parse(self, raw: str, filename: str) -> SkillReport:
        # Strip markdown fences if present
        clean = re.sub(r"```(?:json)?\s*", "", raw).strip().strip("`").strip()

        # Extract JSON object
        try:
            data = json.loads(clean)
        except json.JSONDecodeError:
            s, e = raw.find("{"), raw.rfind("}") + 1
            if s >= 0 and e > s:
                try:
                    data = json.loads(raw[s:e])
                except json.JSONDecodeError as exc:
                    return self._error_report(filename, f"JSON parse failed: {exc}\nRaw: {raw[:300]}")
            else:
                return self._error_report(filename, f"No JSON in LLM response. Raw: {raw[:300]}")

        # Build CVSS v3.5
        # try:
        #     cvss_obj = cvss_from_dict(data.get("cvss_metrics", {}))
        #     cvss_data = cvss_obj.full_report()
        # except Exception as e:
        #     logger.warning(f"  CVSS parse error ({e}), using safe defaults")
        #     cvss_obj  = CVSSv3("L","H","H","R","U","N","N","N")
        #     cvss_data = cvss_obj.full_report()

        # Build CVSS v4.0
        try:
            cvss_obj  = cvss4_from_dict(data.get("cvss_metrics", {}))
            cvss_data = cvss_obj.as_dict()
        except Exception as e:
            logger.warning(f"  CVSS parse error ({e}), using safe defaults")
            cvss_obj  = CVSSv4(AV="N", AC="L", AT="N", PR="N", UI="N",
                            VC="N", VI="N", VA="N", SC="N", SI="N", SA="N")
            cvss_data = cvss_obj.as_dict()

        # Parse vulnerabilities
        vulns = []
        for i, v in enumerate(data.get("vulnerabilities", []), 1):
            vulns.append(Vulnerability(
                id               = v.get("id", f"SKV-{i:03d}"),
                category         = v.get("category", "Unknown"),
                title            = v.get("title", "Untitled"),
                severity         = v.get("severity", "UNKNOWN").upper(),
                affected_content = v.get("affected_content", ""),
                explanation      = v.get("explanation", ""),
                attack_scenario  = v.get("attack_scenario", ""),
                remediation      = v.get("remediation", ""),
            ))

        return SkillReport(
            filename               = filename,
            skill_name             = data.get("skill_name", Path(filename).stem),
            overall_risk           = data.get("overall_risk", "UNKNOWN").upper(),
            is_vulnerable          = bool(data.get("is_vulnerable", len(vulns) > 0)),
            vulnerability_count    = int(data.get("vulnerability_count", len(vulns))),

            cvss                   = cvss_obj,
            # For CVSS v3.5
            # cvss_base_score        = cvss_data["cvss_base_score"],
            # cvss_severity          = cvss_data["cvss_severity"],
            # cvss_vector            = cvss_data["cvss_vector"],
            # impact_score           = cvss_data["impact_score"],
            # exploitability_score   = cvss_data["exploitability_score"],
            # attack_vector          = cvss_data["attack_vector"],
            # attack_complexity      = cvss_data["attack_complexity"],
            # privileges_required    = cvss_data["privileges_required"],
            # user_interaction       = cvss_data["user_interaction"],
            # scope                  = cvss_data["scope"],
            # confidentiality_impact = cvss_data["confidentiality_impact"],
            # integrity_impact       = cvss_data["integrity_impact"],
            # availability_impact    = cvss_data["availability_impact"],

            # For CVSS v4.0
            cvss_base_score        = cvss_data["cvss_score"],
            cvss_severity          = cvss_data["cvss_severity"],
            cvss_vector            = cvss_data["cvss_vector"],
            impact_score           = 0.0,   # v4.0 doesn't expose impact_score separately
            exploitability_score   = 0.0,   # same — no separate exploitability in v4.0
            attack_vector          = cvss_data["attack_vector"],
            attack_complexity      = cvss_data["attack_complexity"],
            attack_requirements    = cvss_data["attack_requirements"],   # new
            privileges_required    = cvss_data["privileges_required"],
            user_interaction       = cvss_data["user_interaction"],
            # scope removed
            confidentiality_impact = cvss_data["confidentiality_vs"],   # key name changed
            integrity_impact       = cvss_data["integrity_vs"],
            availability_impact    = cvss_data["availability_vs"],
            exploit_maturity       = cvss_data["exploit_maturity"],      # new
            nomenclature           = cvss_data["cvss_nomenclature"],     # new

            vulnerabilities        = vulns,
            executive_summary      = data.get("executive_summary", ""),
            skill_purpose_analysis = data.get("skill_purpose_analysis", ""),
            dangerous_patterns     = data.get("dangerous_patterns_found", []),
            safe_patterns          = data.get("safe_patterns_noted", []),
            remediation_priority   = data.get("remediation_priority", ""),
        )
    # For CVSS v3.5
    # def _error_report(self, filename: str, error: str) -> SkillReport:
    #     cvss_obj  = CVSSv3("L","H","H","R","U","N","N","N")
    #     cvss_data = cvss_obj.full_report()
    #     return SkillReport(
    #         filename=filename, skill_name=Path(filename).stem,
    #         overall_risk="ERROR", is_vulnerable=False, vulnerability_count=0,
    #         cvss=cvss_obj, **{k: cvss_data[k] for k in cvss_data},
    #         vulnerabilities=[], executive_summary="",
    #         skill_purpose_analysis="", dangerous_patterns=[],
    #         safe_patterns=[], remediation_priority="",
    #         error=error,
    #     )

    def _error_report(self, filename: str, error: str) -> SkillReport:
        cvss_obj  = CVSSv4(AV="N", AC="L", AT="N", PR="N", UI="N",
                        VC="N", VI="N", VA="N", SC="N", SI="N", SA="N")
        cvss_data = cvss_obj.as_dict()
        return SkillReport(
            filename=filename, skill_name=Path(filename).stem,
            overall_risk="ERROR", is_vulnerable=False, vulnerability_count=0,
            cvss=cvss_obj,
            cvss_base_score=cvss_data["cvss_score"],
            cvss_severity=cvss_data["cvss_severity"],
            cvss_vector=cvss_data["cvss_vector"],
            impact_score=0.0,
            exploitability_score=0.0,
            attack_vector=cvss_data["attack_vector"],
            attack_complexity=cvss_data["attack_complexity"],
            attack_requirements=cvss_data["attack_requirements"],
            privileges_required=cvss_data["privileges_required"],
            user_interaction=cvss_data["user_interaction"],
            confidentiality_impact=cvss_data["confidentiality_vs"],
            integrity_impact=cvss_data["integrity_vs"],
            availability_impact=cvss_data["availability_vs"],
            exploit_maturity=cvss_data["exploit_maturity"],
            nomenclature=cvss_data["cvss_nomenclature"],
            vulnerabilities=[], executive_summary="",
            skill_purpose_analysis="", dangerous_patterns=[],
            safe_patterns=[], remediation_priority="",
            error=error,
        )
