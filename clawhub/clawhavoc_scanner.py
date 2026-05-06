"""
clawhavoc_scanner.py
====================
Reads clawhub_enriched.json, filters skills where VirusTotal OR OpenClaw
verdict is Suspicious or Malicious, then for each such skill:

  1. Downloads the skill ZIP from the ClawHub registry (in memory — no file
     written to disk).
  2. Extracts SKILL.md from the ZIP in memory.
  3. Scans SKILL.md for all attack patterns documented in the ClawHavoc
     campaign (Koi Security, February 2026).
  4. Saves a full report to data/clawhavoc_scan_results.txt and a
     structured summary to data/clawhavoc_scan_summary.json.

ClawHavoc attack patterns checked:
  P01  Prerequisites section with fictional utility
  P02  macOS delivery via anonymous glot.io snippet
  P03  Non-official GitHub release (password-protected ZIP)
  P04  Known C2 server IP addresses
  P05  Base64-obfuscated shell command
  P06  Archive password for AV evasion
  P07  Credential exfiltration via webhook.site
  P08  Hidden backdoor in operational code
  P09  Social engineering urgency/authority language
  P10  Reverse shell command
  P11  Dual Windows + macOS delivery in the same skill

Source: https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting

Usage:
  python clawhavoc_scanner.py
  python clawhavoc_scanner.py --enriched data/clawhub_enriched.json
  python clawhavoc_scanner.py --enriched data/clawhub_enriched.json --delay 1.5
  python clawhavoc_scanner.py --dry-run   # filter only, no downloads
"""

import argparse
import io
import json
import logging
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_DIR      = Path("data")
ENRICHED_FILE = DATA_DIR / "clawhub_enriched.json"
RESULTS_FILE  = DATA_DIR / "clawhavoc_scan_results.txt"
SUMMARY_FILE  = DATA_DIR / "clawhavoc_scan_summary.json"

# ── ClawHub download URL ───────────────────────────────────────────────────────
# Correct endpoint: https://wry-manatee-359.convex.site/api/v1/download?slug={slug}
# Returns the skill ZIP directly — no auth, no owner, no version needed.
DOWNLOAD_BASE = "https://wry-manatee-359.convex.site/api/v1/download"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
}

logging.basicConfig(
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("ClawHavocScanner")


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK PATTERN DEFINITIONS (from ClawHavoc blog, Koi Security, Feb 2026)
# ══════════════════════════════════════════════════════════════════════════════

PATTERNS = [
    {
        "id":   "P01",
        "name": "Fictional prerequisite utility",
        "desc": (
            "Prerequisites section presenting a fictional/unofficial utility "
            "(openclawcli, openclaw-agent, AuthTool) as a hard requirement. "
            "This is the social engineering pretext used in all 335 ClawHavoc skills."
        ),
        "keywords": [
            "openclawcli", "openclaw-agent", "authtool",
            "required to function", "required for functionality",
            "requires the", "utility to function",
            "without it, automatic", "without openclawcli",
            "without openclaw-agent", "without authtool",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P02",
        "name": "macOS delivery via glot.io (anonymous snippet execution)",
        "desc": (
            "Directs macOS users to an anonymous glot.io code snippet "
            "and instructs them to execute the command — hides the "
            "obfuscated payload behind a short URL."
        ),
        "keywords": [
            "glot.io/snippets",
            "glot.io",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P03",
        "name": "Non-official GitHub release (password-protected ZIP)",
        "desc": (
            "Provides a download link to a GitHub release from an unofficial "
            "account (Ddoy233, hedefbari, etc.). The ZIP is password-protected "
            "to prevent antivirus scanning of the payload."
        ),
        "keywords": [
            "github.com/ddoy233",
            "github.com/hedefbari",
            "releases/download/latest",
            "openclawcli.zip",
            "openclaw-agent.zip",
            "openclawcli/releases",
            "openclaw-agent/releases",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P04",
        "name": "Known C2 server IP address",
        "desc": (
            "References one of the known ClawHavoc C2 server IP addresses "
            "that deliver the AMOS stealer or reverse shell payloads."
        ),
        "keywords": [
            "91.92.242.30",
            "95.92.242.30",
            "96.92.242.30",
            "202.161.50.59",
            "54.91.154.110",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P05",
        "name": "Base64-obfuscated shell command",
        "desc": (
            "Contains a base64-encoded shell command piped to bash/sh — "
            "the obfuscation technique used by the glot.io macOS delivery chain."
        ),
        "keywords": [
            "base64 -d",
            "base64 -D",
            "| bash",
            "| sh",
            "L2Jpbi9iYXNo",          # b64 prefix of '/bin/bash -c'
            "base64 --decode",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P06",
        "name": "Archive password for AV evasion",
        "desc": (
            "Provides a password to extract a ZIP archive. "
            "Password-protected archives bypass automated antivirus scanning "
            "because the scanner cannot see inside the archive."
        ),
        "keywords": [
            "extract using",
            "extract using pass",
            "password: openclaw",
            "pass: openclaw",
            "password:",
            "pass:",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P07",
        "name": "Credential exfiltration via webhook.site",
        "desc": (
            "References webhook.site — used by the 'rankaj' outlier skill "
            "to POST stolen .env / credential file contents to an attacker-controlled endpoint."
        ),
        "keywords": [
            "webhook.site",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P08",
        "name": "Hidden backdoor in operational code",
        "desc": (
            "Contains an os.system() call or inline curl/shell command hidden "
            "inside functional code — the technique used by better-polymarket "
            "and polymarket-all-in-one to hide a reverse shell inside working code."
        ),
        "keywords": [
            'os.system("curl',
            'os.system(\'curl',
            "curl -s http://",
            "curl -s https://",
            "|sh",
            "| sh",
            "54.91.154.110",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P09",
        "name": "Social engineering authority/urgency language",
        "desc": (
            "Uses IMPORTANT/WARNING authority language combined with functional "
            "dependency claims to coerce users into installing the malicious prerequisite."
        ),
        "keywords": [
            "**important**",
            "important:",
            "will not function",
            "will not work",
            "required before",
            "must be installed",
            "required to use",
            "required to run",
            "ensure openclawcli",
            "ensure openclaw",
            "verify the installation",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P10",
        "name": "Reverse shell command",
        "desc": (
            "Contains a reverse shell command that opens an interactive bash "
            "session to the attacker's server — used by the outlier skills "
            "better-polymarket and polymarket-all-in-one."
        ),
        "keywords": [
            "/dev/tcp/",
            "bash -i",
            "nohup /bin/bash",
            "0>&1",
            "bash -c 'bash -i",
        ],
        "requires_any": 1,
    },
    {
        "id":   "P11",
        "name": "Dual-platform Windows + macOS malware delivery",
        "desc": (
            "Contains both a Windows download URL and a macOS snippet URL "
            "within the same skill — the signature dual-platform delivery "
            "used across all 335 ClawHavoc skills."
        ),
        "check_fn": "dual_platform",   # special check — see _check_dual_platform()
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# Verdict normalisation
# ══════════════════════════════════════════════════════════════════════════════

def _normalise(verdict: str) -> str:
    v = str(verdict or "").strip().lower()
    if v in ("malicious", "unsafe", "mal"):
        return "Malicious"
    if v in ("suspicious", "warn", "sus"):
        return "Suspicious"
    if v in ("benign", "clean", "safe", "ben"):
        return "Benign"
    return ""


def get_verdicts(info: dict) -> dict:
    """Extract and normalise OpenClaw and VirusTotal verdicts from an enriched entry."""
    oc_raw  = info.get("openclaw", {}).get("verdict", "")
    vt_raw  = info.get("virustotal_clawhub", {}).get("verdict", "")
    vt2_raw = info.get("virustotal_report", {}).get("detection", {}).get("verdict", "")

    return {
        "openclaw":   _normalise(oc_raw),
        "virustotal": _normalise(vt_raw) or _normalise(vt2_raw),
    }


def is_suspicious_or_malicious(info: dict) -> bool:
    """Return True if either OpenClaw or VirusTotal verdict is Suspicious or Malicious."""
    vd = get_verdicts(info)
    return any(v in ("Suspicious", "Malicious") for v in vd.values() if v)


# ══════════════════════════════════════════════════════════════════════════════
# ZIP download and SKILL.md extraction (entirely in memory)
# ══════════════════════════════════════════════════════════════════════════════

def download_skill_md(slug: str, timeout: int = 20) -> Optional[str]:
    """
    Download the skill ZIP from ClawHub's Convex endpoint into memory,
    extract SKILL.md (case-insensitive), and return its content as a string.

    URL format: https://wry-manatee-359.convex.site/api/v1/download?slug={slug}

    The ZIP is NEVER written to disk -- it is held entirely in memory via
    io.BytesIO and discarded after SKILL.md is extracted.
    """
    url = f"{DOWNLOAD_BASE}?slug={slug}"
    log.info(f"  Downloading: {url}")

    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        if not resp.ok:
            log.warning(f"  HTTP {resp.status_code} for slug='{slug}'")
            return None
        raw = resp.content
        if len(raw) < 50:
            log.warning(f"  Response too small ({len(raw)} bytes) -- likely not a ZIP")
            return None
        log.debug(f"  Received {len(raw):,} bytes")
    except requests.exceptions.Timeout:
        log.warning(f"  Request timed out for slug='{slug}'")
        return None
    except Exception as e:
        log.warning(f"  Request error for slug='{slug}': {e}")
        return None

    # Extract SKILL.md from the in-memory ZIP -- no disk I/O
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            skill_md_path = next(
                (n for n in names if n.lower().endswith("skill.md")),
                None,
            )
            if not skill_md_path:
                log.warning(f"  SKILL.md not found in ZIP. Contents: {names[:10]}")
                return None
            content = zf.read(skill_md_path).decode("utf-8", errors="replace")
            log.info(f"  Extracted '{skill_md_path}': {len(content):,} chars")
            return content
    except zipfile.BadZipFile:
        log.warning(f"  Response is not a valid ZIP (slug='{slug}')")
    except Exception as e:
        log.warning(f"  ZIP extraction error for slug='{slug}': {e}")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# Attack pattern scanning
# ══════════════════════════════════════════════════════════════════════════════

def _check_dual_platform(content: str) -> tuple[bool, list]:
    """
    P11: Check for dual-platform delivery by looking for BOTH
    (Windows + github release) AND (macOS + glot.io/snippet) in the same file.
    """
    lower = content.lower()
    has_windows  = ("windows" in lower and
                    ("github.com" in lower or "releases/download" in lower or
                     "openclawcli" in lower or "openclaw-agent" in lower))
    has_macos    = ("macos" in lower and "glot.io" in lower)
    if has_windows and has_macos:
        return True, ["windows+github_release", "macos+glot.io"]
    return False, []


def scan_content(content: str) -> dict:
    """
    Scan skill content against all ClawHavoc attack patterns.
    Returns a dict with 'matched_patterns' and 'all_hits'.
    """
    lower    = content.lower()
    matched  = []

    for pat in PATTERNS:
        if "check_fn" in pat and pat["check_fn"] == "dual_platform":
            found, hits = _check_dual_platform(content)
            if found:
                matched.append({
                    "id":    pat["id"],
                    "name":  pat["name"],
                    "desc":  pat["desc"],
                    "hits":  hits,
                })
            continue

        # Keyword search
        keywords = pat.get("keywords", [])
        required = pat.get("requires_any", 1)
        found_kws = [kw for kw in keywords if kw.lower() in lower]
        if len(found_kws) >= required:
            # Find representative line for each matched keyword
            lines_found = []
            for kw in found_kws[:5]:
                for i, line in enumerate(content.splitlines(), 1):
                    if kw.lower() in line.lower():
                        lines_found.append(f"L{i}: {line.strip()[:100]}")
                        break
            matched.append({
                "id":    pat["id"],
                "name":  pat["name"],
                "desc":  pat["desc"],
                "hits":  found_kws,
                "lines": lines_found,
            })

    return {
        "pattern_count": len(matched),
        "patterns":      matched,
        "verdict": (
            "CONFIRMED_MALICIOUS" if any(
                m["id"] in ("P02","P03","P04","P05","P10") for m in matched
            )
            else "HIGH_RISK" if any(
                m["id"] in ("P01","P06","P07","P08","P09","P11") for m in matched
            )
            else "CLEAN"
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Report writers
# ══════════════════════════════════════════════════════════════════════════════

SEP  = "═" * 80
SEP2 = "─" * 80

def write_report(results: list, out_path: Path) -> None:
    """Write the full human-readable text report."""
    now = datetime.now(timezone.utc).isoformat()
    confirmed = [r for r in results if r["scan"]["verdict"] == "CONFIRMED_MALICIOUS"]
    high_risk = [r for r in results if r["scan"]["verdict"] == "HIGH_RISK"]
    clean     = [r for r in results if r["scan"]["verdict"] == "CLEAN"]
    no_dl     = [r for r in results if not r.get("skill_md_available")]

    lines = []
    lines += [
        SEP,
        "  ClawHavoc Attack Pattern Scanner — Results",
        f"  Generated : {now}",
        f"  Skills scanned : {len(results)}",
        f"  CONFIRMED_MALICIOUS : {len(confirmed)}",
        f"  HIGH_RISK           : {len(high_risk)}",
        f"  CLEAN               : {len(clean)}",
        f"  Download failed     : {len(no_dl)}",
        SEP,
        "",
        "Pattern Legend:",
        "  P01  Fictional prerequisite utility (openclawcli / openclaw-agent)",
        "  P02  macOS delivery via anonymous glot.io snippet",
        "  P03  Non-official GitHub release (password-protected ZIP)",
        "  P04  Known ClawHavoc C2 server IP",
        "  P05  Base64-obfuscated shell command",
        "  P06  Archive password for AV evasion",
        "  P07  Credential exfiltration via webhook.site",
        "  P08  Hidden backdoor in operational code",
        "  P09  Social engineering authority/urgency language",
        "  P10  Reverse shell command",
        "  P11  Dual-platform Windows + macOS delivery",
        "",
        "Source: https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-"
        "found-by-the-bot-they-were-targeting",
        "",
    ]

    # ── Section 1: Confirmed Malicious ─────────────────────────────────────
    lines += [SEP, f"  SECTION 1 — CONFIRMED MALICIOUS  ({len(confirmed)} skills)", SEP, ""]
    for r in confirmed:
        _append_skill_block(lines, r)

    # ── Section 2: High Risk ────────────────────────────────────────────────
    lines += [SEP, f"  SECTION 2 — HIGH RISK  ({len(high_risk)} skills)", SEP, ""]
    for r in high_risk:
        _append_skill_block(lines, r)

    # ── Section 3: Clean ───────────────────────────────────────────────────
    lines += [SEP, f"  SECTION 3 — CLEAN (no patterns matched)  ({len(clean)} skills)", SEP, ""]
    for r in clean:
        lines += [
            f"  {r['slug']:<30} OC={r['oc_verdict']:<12} VT={r['vt_verdict']:<12}"
            + (f" [download failed]" if not r.get("skill_md_available") else ""),
        ]

    # ── Section 4: Download failures ───────────────────────────────────────
    if no_dl:
        lines += ["", SEP, f"  SECTION 4 — DOWNLOAD FAILURES  ({len(no_dl)} skills)", SEP, ""]
        for r in no_dl:
            lines.append(f"  {r['slug']:<30} {r.get('download_error','unknown error')}")

    # ── Quick-reference list ────────────────────────────────────────────────
    lines += [
        "", SEP,
        "  QUICK REFERENCE — ALL SUSPICIOUS/MALICIOUS SKILLS",
        SEP, "",
        f"  {'Slug':<35} {'OC Verdict':<14} {'VT Verdict':<14} {'Scan Result':<22} Patterns",
        "  " + "-"*100,
    ]
    for r in sorted(results, key=lambda x: (x["scan"]["verdict"]!="CONFIRMED_MALICIOUS",
                                             x["scan"]["verdict"]!="HIGH_RISK",
                                             x["slug"])):
        pids = ",".join(p["id"] for p in r["scan"]["patterns"]) or "---"
        lines.append(
            f"  {r['slug']:<35} {r['oc_verdict']:<14} {r['vt_verdict']:<14}"
            f" {r['scan']['verdict']:<22} {pids}"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Report saved: {out_path.resolve()}")


def _append_skill_block(lines: list, r: dict) -> None:
    lines += [
        SEP2,
        f"  Slug       : {r['slug']}",
        f"  Owner      : {r.get('owner_handle','')}",
        f"  Version    : {r.get('version','')}",
        f"  ClawHub    : {r.get('clawhub_url','')}",
        f"  OC Verdict : {r['oc_verdict']}   VT Verdict: {r['vt_verdict']}",
        f"  Scan Result: {r['scan']['verdict']}   Patterns matched: {r['scan']['pattern_count']}",
        "",
    ]
    for pat in r["scan"]["patterns"]:
        lines.append(f"  [{pat['id']}] {pat['name']}")
        lines.append(f"       {pat['desc'][:90]}")
        if "hits" in pat:
            lines.append(f"       Keywords matched: {', '.join(pat['hits'][:6])}")
        if "lines" in pat:
            for ln in pat["lines"][:3]:
                lines.append(f"         > {ln}")
        lines.append("")
    lines.append("")


# ══════════════════════════════════════════════════════════════════════════════
# Main pipeline
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Scan suspicious/malicious ClawHub skills for ClawHavoc attack patterns"
    )
    parser.add_argument("--enriched", default=str(ENRICHED_FILE),
                        help="Path to clawhub_enriched.json")
    parser.add_argument("--out",     default=str(RESULTS_FILE),
                        help="Path for the text report")
    parser.add_argument("--summary", default=str(SUMMARY_FILE),
                        help="Path for the JSON summary")
    parser.add_argument("--delay",   default=1.0, type=float,
                        help="Seconds between downloads (default: 1.0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Filter and list targets only; skip downloads")
    parser.add_argument("--slug",    default=None,
                        help="Scan a single slug only (for testing)")
    args = parser.parse_args()

    # ── Load enriched data ─────────────────────────────────────────────────
    enriched_path = Path(args.enriched)
    if not enriched_path.exists():
        log.error(f"Enriched file not found: {enriched_path}")
        return

    log.info(f"Loading: {enriched_path}")
    with open(enriched_path, encoding="utf-8") as f:
        enriched = json.load(f)
    log.info(f"Total skills in enriched file: {len(enriched)}")

    # ── Filter: Suspicious or Malicious ───────────────────────────────────
    if args.slug:
        targets = {args.slug: enriched[args.slug]} if args.slug in enriched else {}
    else:
        targets = {
            slug: info
            for slug, info in enriched.items()
            if is_suspicious_or_malicious(info)
        }

    log.info(f"Skills with Suspicious/Malicious verdict: {len(targets)}")

    if not targets:
        log.warning("No suspicious/malicious skills found. Check verdict fields in enriched JSON.")
        return

    # ── Print filter results ───────────────────────────────────────────────
    log.info("\n  Targeted skills:")
    log.info(f"  {'Slug':<35} {'OpenClaw':<14} {'VirusTotal'}")
    log.info("  " + "-"*65)
    for slug, info in sorted(targets.items()):
        vd = get_verdicts(info)
        log.info(f"  {slug:<35} {vd['openclaw']:<14} {vd['virustotal']}")

    if args.dry_run:
        log.info("\n--dry-run: stopping before downloads")
        return

    # ── Scan each skill ────────────────────────────────────────────────────
    results = []
    total   = len(targets)

    for i, (slug, info) in enumerate(sorted(targets.items()), 1):
        log.info(f"\n[{i}/{total}] {slug}")

        vd      = get_verdicts(info)
        owner   = info.get("owner_handle", "")
        version = info.get("version", "")

        result = {
            "slug":              slug,
            "owner_handle":      owner,
            "version":           version,
            "clawhub_url":       info.get("clawhub_url", f"https://clawhub.ai/{owner}/{slug}"),
            "oc_verdict":        vd["openclaw"],
            "vt_verdict":        vd["virustotal"],
            "skill_md_available":False,
            "skill_md_chars":    0,
            "download_error":    None,
            "scan":              {"pattern_count":0,"patterns":[],"verdict":"CLEAN"},
            "scanned_at":        datetime.now(timezone.utc).isoformat(),
        }

        if not owner:
            log.warning(f"  No owner_handle — skipping download")
            result["download_error"] = "no owner_handle in enriched data"
            results.append(result)
            continue

        # Download + extract SKILL.md in memory
        log.info(f"  URL: {DOWNLOAD_BASE}?slug={slug}")
        skill_md = download_skill_md(slug)

        if skill_md is None:
            log.warning(f"  Download/extraction failed")
            result["download_error"] = "download or zip extraction failed"
            results.append(result)
            time.sleep(args.delay)
            continue

        result["skill_md_available"] = True
        result["skill_md_chars"]     = len(skill_md)
        log.info(f"  SKILL.md: {len(skill_md):,} chars — scanning patterns ...")

        # Scan for attack patterns
        scan = scan_content(skill_md)
        result["scan"] = scan

        verdict_str = scan["verdict"]
        n_patterns  = scan["pattern_count"]
        pids        = ", ".join(p["id"] for p in scan["patterns"])
        log.info(f"  Result: {verdict_str}  |  {n_patterns} patterns matched: {pids or 'none'}")

        results.append(result)
        time.sleep(args.delay)

    # ── Write outputs ──────────────────────────────────────────────────────
    out_path     = Path(args.out)
    summary_path = Path(args.summary)

    write_report(results, out_path)

    # JSON summary
    summary = {
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "enriched_file":      str(enriched_path),
        "total_in_enriched":  len(enriched),
        "total_targeted":     len(targets),
        "confirmed_malicious":sum(1 for r in results if r["scan"]["verdict"] == "CONFIRMED_MALICIOUS"),
        "high_risk":          sum(1 for r in results if r["scan"]["verdict"] == "HIGH_RISK"),
        "clean":              sum(1 for r in results if r["scan"]["verdict"] == "CLEAN"),
        "download_failed":    sum(1 for r in results if not r["skill_md_available"]),
        "pattern_breakdown":  {
            pat["id"]: sum(
                1 for r in results
                if any(p["id"] == pat["id"] for p in r["scan"]["patterns"])
            )
            for pat in PATTERNS
        },
        "results": results,
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    log.info(f"Summary saved: {summary_path.resolve()}")

    # ── Final console summary ──────────────────────────────────────────────
    print("\n" + "═"*60)
    print("  SCAN COMPLETE")
    print("═"*60)
    print(f"  Total suspicious/malicious skills : {len(targets)}")
    print(f"  CONFIRMED_MALICIOUS               : {summary['confirmed_malicious']}")
    print(f"  HIGH_RISK                         : {summary['high_risk']}")
    print(f"  CLEAN (no patterns matched)       : {summary['clean']}")
    print(f"  Download failed                   : {summary['download_failed']}")
    print(f"  Report  → {out_path.resolve()}")
    print(f"  Summary → {summary_path.resolve()}")
    print("═"*60)


if __name__ == "__main__":
    main()