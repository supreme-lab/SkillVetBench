"""
reporter.py
===========
Console (Rich or plain text) + JSON report generation.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List

from evaluator import SkillReport, Vulnerability

logger = logging.getLogger("SkillEval")

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich         import box
    console   = Console()
    _has_rich = True
except ImportError:
    console   = None
    _has_rich = False


SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
    "NONE":     "green",
    "ERROR":    "magenta",
}

RISK_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "NONE":     "✅",
    "ERROR":    "❌",
    "UNKNOWN":  "⚪",
}


# ─── Public interface ────────────────────────────────────────────────

def print_report(report: SkillReport):
    if _has_rich:
        _rich_report(report)
    else:
        _plain_report(report)


def print_summary(reports: List[SkillReport]):
    if _has_rich:
        _rich_summary(reports)
    else:
        _plain_summary(reports)


def save_json_reports(reports: List[SkillReport], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"skill_security_report_{ts}.json"

    data = {
        "generated_at":  datetime.now().isoformat(),
        "total_skills":  len(reports),
        "vulnerable":    sum(1 for r in reports if r.is_vulnerable),
        "critical":      sum(1 for r in reports if r.overall_risk == "CRITICAL"),
        "high":          sum(1 for r in reports if r.overall_risk == "HIGH"),
        "skills":        [_report_to_dict(r) for r in reports],
    }
    path.write_text(json.dumps(data, indent=2))
    logger.info(f"JSON report saved → {path}")
    return path


# ─── Rich output ─────────────────────────────────────────────────────

def _rich_report(r: SkillReport):
    icon  = RISK_ICON.get(r.overall_risk, "⚪")
    color = SEV_COLOR.get(r.overall_risk, "white")

    if r.error:
        console.print(Panel(
            f"[red]{r.error}[/red]",
            title=f"❌ ERROR — {r.filename}",
            border_style="red",
        ))
        return

    # ── Header ───────────────────────────────────────────────────────
    console.print()
    console.print(Panel.fit(
        f"{icon} [bold]{r.skill_name}[/bold]  [{color}]{r.overall_risk}[/{color}]\n"
        f"[dim]{r.filename}[/dim]",
        border_style=color,
    ))

    # ── Executive summary ─────────────────────────────────────────────
    if r.executive_summary:
        console.print(Panel(
            r.executive_summary,
            title="📋 Executive Summary",
            border_style="blue",
            padding=(0, 2),
        ))

    # ── CVSS table ────────────────────────────────────────────────────
    def score_bar(score: float, width: int = 10) -> str:
        filled = int(round(score))
        return f"{'█' * filled}{'░' * (width - filled)}  {score:.1f}/10"

    cvss_lines = [
        f"[bold]CVSS v3.1 Base Score :[/bold]  [{color}]{r.cvss_base_score:.1f} {r.cvss_severity}[/{color}]",
        f"[bold]Vector               :[/bold]  [dim]{r.cvss_vector}[/dim]",
        f"[bold]Impact Score         :[/bold]  {score_bar(r.impact_score)}",
        f"[bold]Exploitability Score :[/bold]  {score_bar(r.exploitability_score)}",
        "",
        f"[bold]Attack Vector        :[/bold]  {r.attack_vector}",
        f"[bold]Attack Complexity    :[/bold]  {r.attack_complexity}",
        f"[bold]Privileges Required  :[/bold]  {r.privileges_required}",
        f"[bold]User Interaction     :[/bold]  {r.user_interaction}",
        f"[bold]Scope                :[/bold]  {r.scope}",
        f"[bold]Confidentiality      :[/bold]  {r.confidentiality_impact}",
        f"[bold]Integrity            :[/bold]  {r.integrity_impact}",
        f"[bold]Availability         :[/bold]  {r.availability_impact}",
    ]
    console.print(Panel(
        "\n".join(cvss_lines),
        title="📊 CVSS v3.1 Metrics",
        border_style=color,
        padding=(0, 2),
    ))

    # ── Skill purpose ─────────────────────────────────────────────────
    if r.skill_purpose_analysis:
        console.print(Panel(
            r.skill_purpose_analysis,
            title="🎯 Skill Purpose Analysis",
            border_style="dim",
            padding=(0, 2),
        ))

    # ── Vulnerability panels ──────────────────────────────────────────
    if r.vulnerabilities:
        console.print(f"\n[bold]🚨 {r.vulnerability_count} Vulnerability(ies) Found[/bold]\n")
        for v in r.vulnerabilities:
            vc = SEV_COLOR.get(v.severity, "white")
            body = [
                f"[bold]Category         :[/bold]  {v.category}",
                f"[bold]Severity         :[/bold]  [{vc}]{v.severity}[/{vc}]",
                "",
                f"[bold]Affected Content :[/bold]",
                f"[dim italic]  {v.affected_content[:300]}[/dim italic]",
                "",
                f"[bold yellow]⚠  Why it is vulnerable:[/bold yellow]",
                f"   {v.explanation}",
                "",
                f"[bold red]🎯 Attack Scenario:[/bold red]",
                f"   {v.attack_scenario}",
                "",
                f"[bold green]🛡  Remediation:[/bold green]",
                f"   {v.remediation}",
            ]
            console.print(Panel(
                "\n".join(body),
                title=f"[bold]{v.id}[/bold] — {v.title}",
                border_style=vc,
                padding=(0, 2),
            ))
    else:
        console.print(Panel(
            "[green]No vulnerabilities detected in this skill file.[/green]",
            title="✅ Clean Skill",
            border_style="green",
        ))

    # ── Patterns found ────────────────────────────────────────────────
    if r.dangerous_patterns:
        console.print(Panel(
            "\n".join(f"  [red]•[/red] {p}" for p in r.dangerous_patterns),
            title="🚩 Dangerous Patterns Found",
            border_style="red",
        ))
    if r.safe_patterns:
        console.print(Panel(
            "\n".join(f"  [green]•[/green] {p}" for p in r.safe_patterns),
            title="✅ Safe Practices Observed",
            border_style="green",
        ))

    # ── Remediation priority ──────────────────────────────────────────
    if r.remediation_priority:
        console.print(Panel(
            r.remediation_priority,
            title="🔧 Remediation Priority",
            border_style="yellow",
        ))


def _rich_summary(reports: List[SkillReport]):
    total     = len(reports)
    vuln      = sum(1 for r in reports if r.is_vulnerable)
    by_risk   = {k: sum(1 for r in reports if r.overall_risk == k)
                 for k in ("CRITICAL","HIGH","MEDIUM","LOW","NONE","ERROR")}

    console.print()
    console.print(Panel.fit(
        "[bold cyan]🔐 SKILL SECURITY EVALUATION — BATCH SUMMARY[/bold cyan]",
        border_style="cyan",
    ))

    tbl = Table(box=box.ROUNDED, header_style="bold magenta")
    tbl.add_column("Skill File",   min_width=30)
    tbl.add_column("Risk",         justify="center", width=10)
    tbl.add_column("CVSS Score",   justify="center", width=12)
    tbl.add_column("Vulns",        justify="center", width=6)
    tbl.add_column("Top Finding",  min_width=35)

    for r in sorted(reports, key=lambda x: -x.cvss_base_score):
        rc   = SEV_COLOR.get(r.overall_risk, "white")
        icon = RISK_ICON.get(r.overall_risk, "⚪")
        top  = r.vulnerabilities[0].title if r.vulnerabilities else "—"
        tbl.add_row(
            r.filename,
            f"{icon} [{rc}]{r.overall_risk}[/{rc}]",
            f"[{rc}]{r.cvss_base_score:.1f}[/{rc}]",
            str(r.vulnerability_count),
            top,
        )

    console.print(tbl)
    console.print(
        f"\n  Total: {total}  |  Vulnerable: [red]{vuln}[/red]  |  "
        + "  ".join(f"[{SEV_COLOR.get(k,'white')}]{k}: {by_risk[k]}[/]"
                    for k in ("CRITICAL","HIGH","MEDIUM","LOW","NONE") if by_risk[k])
    )


# ─── Plain text fallback ─────────────────────────────────────────────

def _plain_report(r: SkillReport):
    w = "="*65
    print(f"\n{w}")
    print(f"  SKILL: {r.skill_name}  |  RISK: {r.overall_risk}")
    print(f"  File : {r.filename}")
    print(w)

    print(f"\nCVSS Base Score      : {r.cvss_base_score:.1f}  ({r.cvss_severity})")
    print(f"Vector               : {r.cvss_vector}")
    print(f"Impact Score         : {r.impact_score:.1f}")
    print(f"Exploitability Score : {r.exploitability_score:.1f}")
    print(f"Attack Vector        : {r.attack_vector}")
    print(f"Attack Complexity    : {r.attack_complexity}")
    print(f"Privileges Required  : {r.privileges_required}")
    print(f"User Interaction     : {r.user_interaction}")
    print(f"Scope                : {r.scope}")
    print(f"Confidentiality      : {r.confidentiality_impact}")
    print(f"Integrity            : {r.integrity_impact}")
    print(f"Availability         : {r.availability_impact}")

    if r.executive_summary:
        print(f"\nSUMMARY\n{r.executive_summary}")

    for v in r.vulnerabilities:
        print(f"\n  [{v.id}] {v.title}  [{v.severity}]")
        print(f"  Category  : {v.category}")
        print(f"  Content   : {v.affected_content[:200]}")
        print(f"  Why Vuln  : {v.explanation}")
        print(f"  Attack    : {v.attack_scenario}")
        print(f"  Fix       : {v.remediation}")

    if r.dangerous_patterns:
        print("\nDangerous patterns: " + ", ".join(r.dangerous_patterns))


def _plain_summary(reports: List[SkillReport]):
    print(f"\n{'='*65}\n  BATCH SUMMARY — {len(reports)} skills evaluated\n{'='*65}")
    for r in sorted(reports, key=lambda x: -x.cvss_base_score):
        icon = RISK_ICON.get(r.overall_risk, "?")
        print(f"  {icon} {r.overall_risk:8s}  {r.cvss_base_score:.1f}  {r.filename}")


# ─── Serialisation ───────────────────────────────────────────────────

def _report_to_dict(r: SkillReport) -> dict:
    return {
        "filename":               r.filename,
        "skill_name":             r.skill_name,
        "overall_risk":           r.overall_risk,
        "is_vulnerable":          r.is_vulnerable,
        "vulnerability_count":    r.vulnerability_count,
        "cvss": {
            "base_score":         r.cvss_base_score,
            "severity":           r.cvss_severity,
            "vector":             r.cvss_vector,
            "impact_score":       r.impact_score,
            "exploitability_score": r.exploitability_score,
            "attack_vector":      r.attack_vector,
            "attack_complexity":  r.attack_complexity,
            "privileges_required":r.privileges_required,
            "user_interaction":   r.user_interaction,
            "scope":              r.scope,
            "confidentiality_impact": r.confidentiality_impact,
            "integrity_impact":   r.integrity_impact,
            "availability_impact":r.availability_impact,
        },
        "executive_summary":      r.executive_summary,
        "skill_purpose_analysis": r.skill_purpose_analysis,
        "dangerous_patterns":     r.dangerous_patterns,
        "safe_patterns":          r.safe_patterns,
        "remediation_priority":   r.remediation_priority,
        "vulnerabilities": [
            {
                "id":               v.id,
                "category":         v.category,
                "title":            v.title,
                "severity":         v.severity,
                "affected_content": v.affected_content,
                "explanation":      v.explanation,
                "attack_scenario":  v.attack_scenario,
                "remediation":      v.remediation,
            }
            for v in r.vulnerabilities
        ],
        "error": r.error,
    }
