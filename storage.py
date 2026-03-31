"""
storage.py
==========
Manages on-disk storage of skill evaluation results.

Directory layout
────────────────
  <reports_dir>/
    <model_slug>/
      <skill_slug>.json     ← full SkillReport as JSON
    _index.json             ← leaderboard index (fast reads, updated on every write)

The index contains one entry per (skill, model) evaluation with all fields
needed to render the leaderboard without reading individual report files.
"""

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


def _slug(name: str) -> str:
    """Turn any string into a safe filename slug."""
    return re.sub(r"[^\w\-.]", "_", name).strip("_")


def _report_to_dict(report) -> dict:
    """Convert a SkillReport dataclass instance to a plain dict."""
    vulns = []
    for v in (report.vulnerabilities or []):
        vulns.append({
            "id":               getattr(v, "id",               ""),
            "category":         getattr(v, "category",         ""),
            "title":            getattr(v, "title",            ""),
            "severity":         getattr(v, "severity",         ""),
            "affected_content": getattr(v, "affected_content", ""),
            "explanation":      getattr(v, "explanation",      ""),
            "attack_scenario":  getattr(v, "attack_scenario",  ""),
            "remediation":      getattr(v, "remediation",      ""),
        })
    return {
        "filename":               getattr(report, "filename",               ""),
        "skill_name":             getattr(report, "skill_name",             ""),
        "overall_risk":           getattr(report, "overall_risk",           "UNKNOWN"),
        "is_vulnerable":          getattr(report, "is_vulnerable",          False),
        "vulnerability_count":    getattr(report, "vulnerability_count",    0),
        "cvss_base_score":        getattr(report, "cvss_base_score",        0.0),
        "cvss_severity":          getattr(report, "cvss_severity",          ""),
        "cvss_vector":            getattr(report, "cvss_vector",            ""),
        "impact_score":           getattr(report, "impact_score",           0.0),
        "exploitability_score":   getattr(report, "exploitability_score",   0.0),
        "attack_vector":          getattr(report, "attack_vector",          ""),
        "attack_complexity":      getattr(report, "attack_complexity",      ""),
        "privileges_required":    getattr(report, "privileges_required",    ""),
        "user_interaction":       getattr(report, "user_interaction",       ""),
        "scope":                  getattr(report, "scope",                  ""),
        "confidentiality_impact": getattr(report, "confidentiality_impact", ""),
        "integrity_impact":       getattr(report, "integrity_impact",       ""),
        "availability_impact":    getattr(report, "availability_impact",    ""),
        "executive_summary":      getattr(report, "executive_summary",      ""),
        "skill_purpose_analysis": getattr(report, "skill_purpose_analysis", ""),
        "dangerous_patterns":     getattr(report, "dangerous_patterns",     []),
        "safe_patterns":          getattr(report, "safe_patterns",          []),
        "remediation_priority":   getattr(report, "remediation_priority",   ""),
        "vulnerabilities":        vulns,
        "error":                  getattr(report, "error",                  ""),
    }


class ReportStorage:
    """Read/write skill evaluation reports and maintain the leaderboard index."""

    INDEX_FILE = "_index.json"

    def __init__(self, reports_dir: str = "reports"):
        self.root = Path(reports_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self._index_path = self.root / self.INDEX_FILE
        if not self._index_path.exists():
            self._write_index({})

    # ── Write ─────────────────────────────────────────────────────────

    def save(self, report, model_name: str) -> Path:
        """Persist a SkillReport and update the leaderboard index."""
        model_dir = self.root / _slug(model_name)
        model_dir.mkdir(parents=True, exist_ok=True)

        skill_slug = _slug(getattr(report, "filename",
                                   getattr(report, "skill_name", "unknown")))
        out_path   = model_dir / f"{skill_slug}.json"

        data = _report_to_dict(report)
        data["model_name"]    = model_name
        data["evaluated_at"]  = datetime.now().isoformat()

        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

        # Update leaderboard index
        index = self._read_index()
        key   = f"{skill_slug}::{_slug(model_name)}"
        top_cat = ""
        if data["vulnerabilities"]:
            sevs = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
            worst = max(data["vulnerabilities"], key=lambda v: sevs.get(v.get("severity",""),0))
            top_cat = worst.get("category","")

        index[key] = {
            "key":                key,
            "model_name":         model_name,
            "model_slug":         _slug(model_name),
            "skill_name":         data["skill_name"],
            "filename":           data["filename"],
            "skill_slug":         skill_slug,
            "overall_risk":       data["overall_risk"],
            "is_vulnerable":      data["is_vulnerable"],
            "vulnerability_count":data["vulnerability_count"],
            "cvss_base_score":    data["cvss_base_score"],
            "cvss_severity":      data["cvss_severity"],
            "cvss_vector":        data["cvss_vector"],
            "impact_score":       data["impact_score"],
            "exploitability_score": data["exploitability_score"],
            "attack_vector":      data["attack_vector"],
            "attack_complexity":  data["attack_complexity"],
            "privileges_required":data["privileges_required"],
            "user_interaction":   data["user_interaction"],
            "scope":              data["scope"],
            "confidentiality_impact": data["confidentiality_impact"],
            "integrity_impact":   data["integrity_impact"],
            "availability_impact":data["availability_impact"],
            "top_finding_category": top_cat,
            "evaluated_at":       data["evaluated_at"],
            "report_path":        str(out_path),
        }
        self._write_index(index)
        return out_path

    # ── Read ──────────────────────────────────────────────────────────

    def get_leaderboard(self) -> list:
        """Return all index entries sorted by CVSS score descending."""
        index = self._read_index()
        entries = list(index.values())
        entries.sort(key=lambda e: -e.get("cvss_base_score", 0))
        for i, e in enumerate(entries, 1):
            e["rank"] = i
        return entries

    def get_report(self, skill_slug: str, model_slug: str) -> Optional[dict]:
        """Load and return a full report dict, or None if not found."""
        path = self.root / model_slug / f"{skill_slug}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def list_models(self) -> list:
        """Return list of model names that have at least one evaluation."""
        index = self._read_index()
        return sorted({e["model_name"] for e in index.values()})

    def list_skills(self) -> list:
        """Return unique skill names across all models."""
        index = self._read_index()
        return sorted({e["skill_name"] for e in index.values()})

    def already_evaluated(self, filename: str, model_name: str) -> bool:
        """Check if a (skill, model) pair has already been evaluated."""
        key = f"{_slug(filename)}::{_slug(model_name)}"
        return key in self._read_index()

    # ── Index helpers ─────────────────────────────────────────────────

    def _read_index(self) -> dict:
        try:
            return json.loads(self._index_path.read_text())
        except Exception:
            return {}

    def delete(self, skill_slug: str, model_slug: str) -> bool:
        """Delete a report file and remove it from the index. Returns True if found."""
        path = self.root / model_slug / f"{skill_slug}.json"
        index = self._read_index()
        key = f"{skill_slug}::{model_slug}"
        if key not in index and not path.exists():
            return False
        # Remove from index
        index.pop(key, None)
        self._write_index(index)
        # Remove file
        if path.exists():
            path.unlink()
        return True

    def _write_index(self, index: dict):
        self._index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False))