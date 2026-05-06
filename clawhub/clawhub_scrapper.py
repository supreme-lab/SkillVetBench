"""
clawhub_scrapper.py
===================
Two responsibilities:

  1. fetch_all_skills()
     Paginate the ClawHub Convex API and write two files:
       data/clawhub_skills.json       — flat list of every skill
       data/clawhub_skills_meta.json  — slug-keyed metadata dict

  2. enrich_top_skills()
     For each slug in data/slugs.txt (top-100 by stars):
       a. Fetch the ClawHub skill page → extract the full OpenClaw LLM
          evaluation (verdict, confidence, 5 dimensions, guidance, summary,
          model) + VirusTotal sha256 hash + staticScan result.
       b. Fetch the VirusTotal report for that hash → extract detection
          count (x/64), community score, code insights (type, name, version,
          tags, description, file size, last analysis date).
       c. Merge everything into data/clawhub_enriched.json  (slug-keyed).

Run:
  python clawhub_scrapper.py            # fetch + enrich
  python clawhub_scrapper.py --fetch    # fetch only (no enrichment)
  python clawhub_scrapper.py --enrich   # enrich only (reads existing meta)
"""

import argparse
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ── Paths ─────────────────────────────────────────────────────────────────
DATA_DIR      = Path("data")
SKILLS_FILE   = DATA_DIR / "clawhub_skills.json""""
clawhub_scrapper.py
===================
Two responsibilities:

  1. fetch_all_skills()
     Paginate the ClawHub Convex API and write two files:
       data/clawhub_skills.json       — flat list of every skill
       data/clawhub_skills_meta.json  — slug-keyed metadata dict

  2. enrich_top_skills()
     For each slug in data/slugs.txt (top-100 by stars):
       a. Fetch the ClawHub skill page → extract the full OpenClaw LLM
          evaluation (verdict, confidence, 5 dimensions, guidance, summary,
          model) + VirusTotal sha256 hash + staticScan result.
       b. Fetch the VirusTotal report for that hash → extract detection
          count (x/64), community score, code insights (type, name, version,
          tags, description, file size, last analysis date).
       c. Merge everything into data/clawhub_enriched.json  (slug-keyed).

Run:
  python clawhub_scrapper.py            # fetch + enrich
  python clawhub_scrapper.py --fetch    # fetch only (no enrichment)
  python clawhub_scrapper.py --enrich   # enrich only (reads existing meta)
"""

import argparse
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ── Paths ─────────────────────────────────────────────────────────────────
DATA_DIR      = Path("data")
SKILLS_FILE   = DATA_DIR / "clawhub_skills.json"
META_FILE     = DATA_DIR / "clawhub_skills_meta.json"
SLUGS_FILE    = DATA_DIR / "slugs.txt"
ENRICHED_FILE = DATA_DIR / "clawhub_enriched.json"

# ── APIs ───────────────────────────────────────────────────────────────────
CONVEX_API  = "https://wry-manatee-359.convex.cloud/api/query"
CLAWHUB_WEB = "https://clawhub.ai"
VT_UI_API   = "https://www.virustotal.com/ui/files"   # no auth, JSON response

HEADERS_WEB = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
HEADERS_JSON = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
    "Referer": "https://www.virustotal.com/",
}
CONVEX_HEADERS = {"Content-Type": "application/json"}

logging.basicConfig(
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("ClawHubScraper")


# ═══════════════════════════════════════════════════════════════════════════
# PART 1 — Convex API fetch (original functionality, unchanged)
# ═══════════════════════════════════════════════════════════════════════════

def fetch_page(cursor=None) -> dict:
    args = {
        "dir": "desc",
        "highlightedOnly": False,
        "nonSuspiciousOnly": False,
        "numItems": 25,
        "sort": "downloads",
    }
    if cursor is not None:
        args["cursor"] = cursor

    payload = {
        "path": "skills:listPublicPageV4",
        "format": "convex_encoded_json",
        "args": [args],
    }
    response = requests.post(
        CONVEX_API, headers=CONVEX_HEADERS, json=payload, timeout=30
    )
    response.raise_for_status()
    return response.json()


def extract_skill(item: dict) -> dict:
    skill          = item.get("skill", {})
    owner          = item.get("owner", {})
    latest_version = item.get("latestVersion", {})

    created_ts   = skill.get("createdAt")
    created_date = (
        datetime.utcfromtimestamp(created_ts / 1000).strftime("%Y-%m-%d %H:%M:%S UTC")
        if created_ts else None
    )
    return {
        "slug":               skill.get("slug"),
        "display_name":       skill.get("displayName"),
        "summary":            skill.get("summary"),
        "owner_handle":       item.get("ownerHandle"),
        "owner_display_name": owner.get("displayName"),
        "created_date":       created_date,
        "version":            latest_version.get("version"),
        "stats":              skill.get("stats", {}),
        "tags":               list(skill.get("tags", {}).keys()),
        "skill_id":           skill.get("_id"),
    }


def append_to_list_file(f, skills: list, is_first_batch: bool) -> None:
    for i, skill in enumerate(skills):
        prefix = "" if (is_first_batch and i == 0) else ","
        f.write(prefix + "\n" + json.dumps(skill, ensure_ascii=False))
    f.flush()


def update_meta_file(meta_path: Path, new_skills: list) -> None:
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        meta = {}

    for skill in new_skills:
        slug = skill.get("slug")
        if slug:
            meta[slug] = {k: v for k, v in skill.items() if k != "slug"}

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def fetch_all_skills() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    total, cursor, page = 0, None, 1

    with open(SKILLS_FILE, "w", encoding="utf-8") as list_f:
        list_f.write("[")
        is_first_batch = True

        while True:
            log.info(f"Fetching page {page} (cursor: {cursor}) ...")
            try:
                data = fetch_page(cursor)
            except requests.RequestException as e:
                log.error(f"Request failed on page {page}: {e}")
                break

            value = data.get("value", {})
            items = value.get("page", [])

            if not items:
                log.info("Empty page — stopping.")
                break

            skills = [extract_skill(item) for item in items]
            append_to_list_file(list_f, skills, is_first_batch)
            is_first_batch = False
            update_meta_file(META_FILE, skills)

            total   += len(skills)
            has_more = value.get("hasMore", False)
            cursor   = value.get("nextCursor")

            log.info(f"  → {len(skills)} skills saved (total: {total})")

            if not has_more or not cursor:
                log.info("No more pages.")
                break

            page += 1
            time.sleep(0.3)

        list_f.write("\n]\n")

    log.info(f"Done. {total} skills written to:")
    log.info(f"  {SKILLS_FILE}  (flat list)")
    log.info(f"  {META_FILE}    (slug-keyed)")


# ═══════════════════════════════════════════════════════════════════════════
# PART 2 — ClawHub page scraper
# ═══════════════════════════════════════════════════════════════════════════

def _strip_rvar(s: str) -> str:
    """Remove $R[N] = references from ClawHub's TSR serialization format."""
    return re.sub(r"\$R\[\d+\]\s*=\s*", "", s)


def _get_str(window: str, key: str) -> str:
    """Extract first string value for key in a JavaScript-like object."""
    pat = re.compile(
        r'["\']?' + re.escape(key) + r'["\']?' + r'\s*:\s*"((?:[^"\\]|\\.)*)"',
        re.DOTALL,
    )
    m = pat.search(window)
    return m.group(1) if m else ""


def fetch_clawhub_page(owner: str, slug: str, timeout: int = 15) -> Optional[dict]:
    """
    Fetch https://clawhub.ai/{owner}/{slug} and extract:
      - OpenClaw LLM evaluation (verdict, confidence, 5 dimensions, guidance, summary, model)
      - VirusTotal sha256 hash
      - Static scan result
      - Skill stats (stars, downloads, installs)
      - File list with sizes
    Returns None on failure.
    """
    url = f"{CLAWHUB_WEB}/{owner}/{slug}"
    log.info(f"  ClawHub page: {url}")
    try:
        resp = requests.get(url, headers=HEADERS_WEB, timeout=timeout)
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        log.warning(f"  ClawHub fetch error: {e}")
        return None

    # ── Find llmAnalysis block ────────────────────────────────────────────
    la_pos = html.find("llmAnalysis")
    if la_pos < 0:
        log.warning(f"  llmAnalysis not found for {slug}")
        openclaw = {}
    else:
        window = _strip_rvar(html[la_pos: la_pos + 6000])

        # Extract scalar fields
        verdict    = _get_str(window, "verdict").lower()
        confidence = _get_str(window, "confidence").upper()
        summary    = _get_str(window, "summary")
        guidance   = _get_str(window, "guidance")
        model      = _get_str(window, "model")

        # Normalise verdict to Title case
        VERDICT_MAP = {
            "benign": "Benign", "clean": "Benign", "safe": "Benign",
            "suspicious": "Suspicious", "warn": "Suspicious",
            "malicious": "Malicious", "unsafe": "Malicious",
        }
        verdict_str = VERDICT_MAP.get(verdict, "Unknown")
        if confidence not in ("HIGH", "MEDIUM", "LOW"):
            confidence = "UNKNOWN"

        # Extract dimensions [{detail, label, name, rating}]
        dim_re = re.compile(
            r"\{[^{}]{0,2000}?"
            r'detail\s*:\s*"((?:[^"\\]|\\.)*)"'
            r".{0,600}?"
            r'label\s*:\s*"((?:[^"\\]|\\.)*)"'
            r".{0,200}?"
            r'name\s*:\s*"((?:[^"\\]|\\.)*)"'
            r".{0,200}?"
            r'rating\s*:\s*"((?:[^"\\]|\\.)*)"'
            r"[^{}]{0,200}?\}",
            re.DOTALL,
        )
        NAME_MAP = {
            "purpose_capability":          "purpose_capability",
            "instruction_scope":           "instruction_scope",
            "install_mechanism":           "install_mechanism",
            "environment_proportionality": "credentials",
            "credentials":                 "credentials",
            "persistence_privilege":       "persistence_privilege",
        }
        RATING_NORM = {"ok": "pass", "pass": "pass", "warn": "warn", "fail": "fail"}
        dimensions = {}
        for detail, label, name, rating in dim_re.findall(window):
            key = NAME_MAP.get(name.lower())
            if key:
                dimensions[key] = {
                    "label":       label,
                    "status":      RATING_NORM.get(rating.lower(), rating),
                    "description": detail,
                }

        openclaw = {
            "verdict":    verdict_str,
            "confidence": confidence,
            "summary":    summary,
            "assessment": guidance,
            "model":      model,
            "dimensions": dimensions,
        }

    # ── Find vtAnalysis block ─────────────────────────────────────────────
    vt_pos = html.find("vtAnalysis")
    vt_data = {}
    if vt_pos >= 0:
        vt_win = _strip_rvar(html[vt_pos: vt_pos + 1000])
        vt_verdict  = _get_str(vt_win, "verdict").lower()
        vt_status   = _get_str(vt_win, "status").lower()
        vt_analysis = _get_str(vt_win, "analysis")
        vt_source   = _get_str(vt_win, "source")
        vt_data = {
            "verdict":  {"benign":"Benign","clean":"Benign"}.get(vt_verdict, vt_verdict.title()),
            "status":   vt_status,
            "analysis": vt_analysis,
            "source":   vt_source,
        }

    # ── Extract sha256hash (used to build the VT report URL) ──────────────
    sha_match = re.search(r'"sha256hash"\s*:\s*"([a-f0-9]{64})"', html)
    sha256    = sha_match.group(1) if sha_match else ""

    # ── VT report link as shown on the page ───────────────────────────────
    vt_link_match = re.search(
        r'virustotal\.com/gui/file/([a-f0-9]{64})', html
    )
    vt_url = (
        f"https://www.virustotal.com/gui/file/{vt_link_match.group(1)}"
        if vt_link_match else
        (f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else "")
    )
    sha256 = sha256 or (vt_link_match.group(1) if vt_link_match else "")

    # ── staticScan block ──────────────────────────────────────────────────
    ss_pos = html.find("staticScan")
    static_scan = {}
    if ss_pos >= 0:
        ss_win = _strip_rvar(html[ss_pos: ss_pos + 800])
        static_scan = {
            "status":  _get_str(ss_win, "status"),
            "summary": _get_str(ss_win, "summary"),
            "engine":  _get_str(ss_win, "engineVersion"),
        }

    # ── Skill stats from TSR ──────────────────────────────────────────────
    stats_match = re.search(
        r'stats\s*:\s*\{([^}]{10,400})\}', _strip_rvar(html)
    )
    stats = {}
    if stats_match:
        raw_stats = "{" + stats_match.group(1) + "}"
        for k in ("stars", "downloads", "installsAllTime", "installsCurrent",
                  "comments", "versions"):
            m = re.search(rf'"{k}"\s*:\s*(\d+)', raw_stats)
            if m:
                stats[k] = int(m.group(1))

    # ── File list (path + size) ────────────────────────────────────────────
    file_matches = re.findall(
        r'"path"\s*:\s*"([^"]+)"[^}]{0,100}"size"\s*:\s*(\d+)', html
    )
    files = [{"path": p, "size_bytes": int(s)} for p, s in file_matches]

    # ── Skill version info ────────────────────────────────────────────────
    version_match = re.search(r'"version"\s*:\s*"([^"]+)"', html)
    version = version_match.group(1) if version_match else ""

    return {
        "openclaw":    openclaw,
        "virustotal":  {"sha256": sha256, "url": vt_url, **vt_data},
        "static_scan": static_scan,
        "stats":       stats,
        "files":       files,
        "version":     version,
        "scraped_at":  datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════
# PART 3 — VirusTotal enrichment
# ═══════════════════════════════════════════════════════════════════════════

# ── VirusTotal cache: hash → result (avoids re-hitting VT for same hash) ──
_VT_CACHE: dict = {}

# VT public API key (optional).
# Get a free key at https://www.virustotal.com/gui/join-us  (500 lookups/day)
# Set with:  export VT_API_KEY=your_key_here
_VT_API_KEY: str = os.getenv("VT_API_KEY", "")


def _parse_vt_analysis_text(text: str) -> dict:
    """
    Parse the vtAnalysis.analysis text field that ClawHub embeds in its TSR block.
    This IS the "Code insights" content shown in the VT screenshot.

    Example input:
        "Type: OpenClaw Skill
         Name: xsearch
         Version: 1.0.0

         The x-search skill is a well-implemented tool for searching X (Twitter)
         via the official xAI Grok API..."

    Returns a dict with type, name, version, description.
    """
    if not text:
        return {}

    lines       = text.strip().splitlines()
    parsed      = {}
    desc_lines  = []
    in_desc     = False

    for line in lines:
        line = line.strip()
        if not line:
            if parsed:          # blank line after header → start of description
                in_desc = True
            continue
        if in_desc:
            desc_lines.append(line)
            continue
        for key in ("Type", "Name", "Version"):
            if line.startswith(f"{key}:"):
                parsed[key.lower()] = line[len(key)+1:].strip()
                break

    if desc_lines:
        parsed["description"] = " ".join(desc_lines)

    return parsed


def _parse_vt_attrs(attrs: dict, sha256: str) -> dict:
    """Parse a VirusTotal attributes dict into our standard schema."""
    stats           = attrs.get("last_analysis_stats", {})
    flagged         = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total           = sum(stats.get(k, 0) for k in
                          ("malicious", "suspicious", "undetected", "harmless", "timeout"))
    ratio_str       = f"{flagged}/{total}" if total else "—"

    votes           = attrs.get("total_votes", {})
    harmless_votes  = votes.get("harmless", 0)
    malicious_votes = votes.get("malicious", 0)

    type_tags       = attrs.get("type_tags", []) or attrs.get("tags", [])
    meaningful_name = attrs.get("meaningful_name", "")

    ai_results = attrs.get("crowdsourced_ai_results", [])
    ai_insight = {}
    if ai_results:
        best = ai_results[0]
        ai_insight = {
            "vendor":      best.get("vendor", ""),
            "description": best.get("description", ""),
            "confidence":  best.get("confidence", ""),
            "severity":    best.get("severity", ""),
            "category":    best.get("category", ""),
        }

    size_bytes    = attrs.get("size", 0)
    last_ts       = attrs.get("last_analysis_date", 0)
    last_analysis = (
        datetime.utcfromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        if last_ts else ""
    )
    sigma_hits = []
    for rule in attrs.get("sigma_analysis_results", [])[:5]:
        sigma_hits.append({
            "rule":        rule.get("rule_title", ""),
            "severity":    rule.get("rule_level", ""),
            "description": rule.get("description", ""),
        })

    return {
        "sha256":     sha256,
        "report_url": f"https://www.virustotal.com/gui/file/{sha256}",
        "source":     "virustotal_api",
        "detection": {
            "flagged":  flagged,
            "total":    total,
            "ratio_str": ratio_str,
            "stats":    stats,
        },
        "community_score": harmless_votes - malicious_votes,
        "votes": {
            "harmless":  harmless_votes,
            "malicious": malicious_votes,
        },
        "code_insight": {
            "file_type":       attrs.get("type_description", attrs.get("type_tag", "")),
            "magic":           attrs.get("magic", ""),
            "size_bytes":      size_bytes,
            "size_kb":         round(size_bytes / 1024, 2),
            "meaningful_name": meaningful_name,
            "names":           attrs.get("names", [meaningful_name])[:5],
            "tags":            type_tags,
            "last_analysis":   last_analysis,
            "ai_analysis":     ai_insight,
            "sigma_hits":      sigma_hits,
        },
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def fetch_virustotal(
    sha256: str,
    vt_embed: Optional[dict] = None,
    static_scan: Optional[dict] = None,
    timeout: int = 20,
) -> dict:
    """
    Build a VirusTotal report for a file hash.

    Strategy (tried in order):
      1. VT_API_KEY env var set → call /api/v3/files/{hash} with key (reliable)
      2. No API key → extract everything from data already embedded in the
         ClawHub page (vtAnalysis + staticScan blocks, already fetched, free)

    The ClawHub page embeds:
      - vtAnalysis.analysis   → "Code insights" text (Type/Name/Version/description)
      - vtAnalysis.verdict    → "Benign" / "Suspicious" / "Malicious"
      - vtAnalysis.status     → "clean" / "suspicious"
      - staticScan.findings   → list of detections (empty = 0 flagged)
      - staticScan.status     → "clean"

    Set VT_API_KEY for community score + exact detection count:
      export VT_API_KEY=your_free_key   # from virustotal.com/gui/join-us
    """
    if not sha256:
        return {}

    # ── In-memory cache ───────────────────────────────────────────────────
    if sha256 in _VT_CACHE:
        log.debug(f"  VT cache hit: {sha256[:16]}...")
        return _VT_CACHE[sha256]

    report_url = f"https://www.virustotal.com/gui/file/{sha256}"

    # ══════════════════════════════════════════════════════════════════════
    # PATH A: VT API key available → direct API call (reliable, 500/day free)
    # ══════════════════════════════════════════════════════════════════════
    if _VT_API_KEY:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        log.info(f"  VirusTotal API (key): {sha256[:16]}...")
        try:
            resp = requests.get(
                url,
                headers={**HEADERS_JSON, "x-apikey": _VT_API_KEY},
                timeout=timeout,
            )
            if resp.status_code == 404:
                log.info("  VT: hash not yet in database")
                result = {
                    "sha256": sha256, "report_url": report_url,
                    "source": "virustotal_api",
                    "error":  "not_found",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }
            elif resp.ok:
                attrs  = resp.json().get("data", {}).get("attributes", {})
                result = _parse_vt_attrs(attrs, sha256)
                log.info(
                    f"  VT OK — {result['detection']['ratio_str']} flagged  "
                    f"community: {result['community_score']}"
                )
            else:
                log.warning(f"  VT API error {resp.status_code}: {resp.text[:120]}")
                result = {
                    "sha256": sha256, "report_url": report_url,
                    "source": "virustotal_api",
                    "error":  f"http_{resp.status_code}",
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                }
        except Exception as e:
            log.warning(f"  VT API exception: {e}")
            result = {
                "sha256": sha256, "report_url": report_url,
                "source": "virustotal_api",
                "error":  str(e),
                "fetched_at": datetime.now(timezone.utc).isoformat(),
            }

        _VT_CACHE[sha256] = result
        return result

    # ══════════════════════════════════════════════════════════════════════
    # PATH B: No API key → extract from ClawHub-embedded data (always works)
    # ══════════════════════════════════════════════════════════════════════
    log.info(
        f"  VT: no API key — extracting from ClawHub-embedded vtAnalysis "
        f"(set VT_API_KEY env var for full VT data)"
    )

    vt_embed    = vt_embed    or {}
    static_scan = static_scan or {}

    # ── Code insight: parse the vtAnalysis.analysis text ─────────────────
    analysis_text = vt_embed.get("analysis", "")
    code_insight  = _parse_vt_analysis_text(analysis_text)

    # ── Detection: from staticScan.findings ──────────────────────────────
    findings    = static_scan.get("findings", [])
    flagged     = len([f for f in findings if f.get("type") == "malicious"]) if findings else 0
    # VT typically checks ~64 engines; exact total only available with API key
    total_note  = "~64 (exact count requires VT_API_KEY)"
    ratio_str   = f"{flagged}/~64" if flagged == 0 else f"{flagged}/? (set VT_API_KEY)"

    # ── Verdict from vtAnalysis block ─────────────────────────────────────
    vt_verdict  = vt_embed.get("verdict", "")
    vt_status   = vt_embed.get("status", "")

    result = {
        "sha256":          sha256,
        "report_url":      report_url,
        "source":          "clawhub_embedded",
        "detection": {
            "flagged":     flagged,
            "total":       total_note,
            "ratio_str":   ratio_str,
            "verdict":     vt_verdict,
            "status":      vt_status,
            "findings":    findings,
        },
        "community_score": "unavailable (set VT_API_KEY env var for community score)",
        "code_insight": {
            "type":        code_insight.get("type", ""),
            "name":        code_insight.get("name", ""),
            "version":     code_insight.get("version", ""),
            "description": code_insight.get("description", ""),
            "raw_analysis":analysis_text,
        },
        "note": (
            "Partial data — extracted from ClawHub's embedded vtAnalysis block. "
            "For full detection count, community score, and behavioral tags, "
            "set VT_API_KEY=your_free_key (register free at virustotal.com/gui/join-us)"
        ),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }

    _VT_CACHE[sha256] = result
    return result



# ═══════════════════════════════════════════════════════════════════════════
# PART 4 — Enrichment pipeline: slugs.txt → clawhub_enriched.json
# ═══════════════════════════════════════════════════════════════════════════

def load_meta() -> dict:
    """Load clawhub_skills_meta.json (slug → metadata)."""
    try:
        with open(META_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.error(f"Could not load {META_FILE}: {e}")
        return {}


def load_slugs() -> list:
    """Read slug names from data/slugs.txt (one per line)."""
    try:
        lines = SLUGS_FILE.read_text(encoding="utf-8").splitlines()
        return [l.strip() for l in lines if l.strip()]
    except FileNotFoundError:
        log.error(f"{SLUGS_FILE} not found — run with --fetch first or generate slugs.txt")
        return []


def load_enriched() -> dict:
    """Load existing enriched data so we can skip already-done slugs."""
    try:
        with open(ENRICHED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_enriched(enriched: dict) -> None:
    """Write the enriched dict to disk (pretty-printed, slug-keyed)."""
    ENRICHED_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ENRICHED_FILE, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)


def enrich_top_skills(
    force: bool = False,
    clawhub_delay: float = 1.2,
    vt_delay: float = 3.0,
) -> None:
    """
    For each slug in data/slugs.txt:
      1. Look up owner_handle in clawhub_skills_meta.json
      2. Scrape clawhub.ai/{owner}/{slug} → OpenClaw evaluation + VT hash
      3. Call VirusTotal UI API → detection count, community score, code insights
      4. Save result to data/clawhub_enriched.json

    Args:
      force:          Re-fetch slugs already present in enriched.json
      clawhub_delay:  Seconds to wait between ClawHub requests (be polite)
      vt_delay:       Seconds to wait between VT requests
    """
    slugs    = load_slugs()
    meta     = load_meta()
    enriched = load_enriched()

    if not slugs:
        log.error("No slugs to enrich — aborting.")
        return

    log.info(f"Enriching {len(slugs)} slugs (force={force}) ...")
    done = skipped = errors = 0

    for i, slug in enumerate(slugs, 1):
        log.info(f"[{i}/{len(slugs)}] {slug}")

        # ── Skip if already enriched ──────────────────────────────────────
        if not force and slug in enriched:
            log.info(f"  Already enriched — skipping")
            skipped += 1
            continue

        # ── Get owner handle from meta ────────────────────────────────────
        info  = meta.get(slug, {})
        owner = info.get("owner_handle", "")
        if not owner:
            log.warning(f"  No owner_handle in meta for '{slug}' — skipping")
            errors += 1
            continue

        # ── Enrich entry: start with meta fields ──────────────────────────
        entry = {
            "slug":         slug,
            "owner_handle": owner,
            "display_name": info.get("display_name", slug),
            "summary":      info.get("summary", ""),
            "version":      info.get("version", ""),
            "created_date": info.get("created_date", ""),
            "stats":        info.get("stats", {}),
            "tags":         info.get("tags", []),
            "skill_id":     info.get("skill_id", ""),
            "clawhub_url":  f"{CLAWHUB_WEB}/{owner}/{slug}",
        }

        # ── Fetch ClawHub page ────────────────────────────────────────────
        page_data = fetch_clawhub_page(owner, slug)
        if page_data:
            entry["openclaw"]    = page_data.get("openclaw", {})
            entry["static_scan"] = page_data.get("static_scan", {})
            entry["files"]       = page_data.get("files", [])
            # Merge stats from page (may be more up-to-date)
            if page_data.get("stats"):
                entry["stats"].update(page_data["stats"])

            sha256  = page_data.get("virustotal", {}).get("sha256", "")
            vt_url  = page_data.get("virustotal", {}).get("url", "")
            entry["virustotal_url"]    = vt_url
            entry["virustotal_sha256"] = sha256

            # VT data already embedded in the ClawHub page (vtAnalysis block)
            vt_embed = page_data.get("virustotal", {})
            entry["virustotal_clawhub"] = {
                "verdict":  vt_embed.get("verdict", ""),
                "status":   vt_embed.get("status", ""),
                "analysis": vt_embed.get("analysis", ""),
                "source":   vt_embed.get("source", ""),
            }
        else:
            sha256 = ""
            log.warning(f"  ClawHub page fetch failed for {slug}")

        time.sleep(clawhub_delay)

        # ── Fetch VirusTotal report ──────────────────────────────────────
        # Pass the embedded vtAnalysis + staticScan blocks from the ClawHub
        # page so fetch_virustotal can extract data without hitting VT's API
        # when no VT_API_KEY is set.
        vt_embed_data   = entry.get("virustotal_clawhub", {})
        static_scan_data= entry.get("static_scan", {})
        if sha256:
            vt_data = fetch_virustotal(
                sha256,
                vt_embed    = vt_embed_data,
                static_scan = static_scan_data,
            )
            entry["virustotal_report"] = vt_data or {}
        else:
            log.info(f"  No sha256 — skipping VT lookup")
            entry["virustotal_report"] = {}

        # Only sleep between requests when using VT API directly
        if _VT_API_KEY and sha256:
            time.sleep(vt_delay)

        # ── Save incrementally after each skill ───────────────────────────
        enriched[slug] = entry
        save_enriched(enriched)

        done += 1
        log.info(
            f"  ✅ Done — OpenClaw: {entry.get('openclaw', {}).get('verdict', '?')} | "
            f"VT: {entry.get('virustotal_report', {}).get('detection', {}).get('ratio_str', '?')} | "
            f"Community: {entry.get('virustotal_report', {}).get('community_score', '?')}"
        )

    log.info(
        f"\nEnrichment complete — done: {done}, skipped: {skipped}, errors: {errors}"
    )
    log.info(f"Output: {ENRICHED_FILE.resolve()}")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="ClawHub scraper + VirusTotal enrichment"
    )
    parser.add_argument(
        "--fetch",   action="store_true",
        help="Fetch all skills from the Convex API (writes clawhub_skills.json + clawhub_skills_meta.json)"
    )
    parser.add_argument(
        "--enrich",  action="store_true",
        help="Enrich top-100 slugs with OpenClaw + VirusTotal data (writes clawhub_enriched.json)"
    )
    parser.add_argument(
        "--force",   action="store_true",
        help="Re-fetch slugs already present in clawhub_enriched.json"
    )
    parser.add_argument(
        "--clawhub-delay", type=float, default=1.0, metavar="SEC",
        help="Seconds between ClawHub page requests (default: 1.0)"
    )
    parser.add_argument(
        "--vt-delay", type=float, default=8.0, metavar="SEC",
        help="Seconds between VirusTotal requests (default: 8.0). "
    )
    args = parser.parse_args()

    # Default: run both if neither flag given
    run_fetch  = args.fetch  or (not args.fetch and not args.enrich)
    run_enrich = args.enrich or (not args.fetch and not args.enrich)

    if run_fetch:
        log.info("═" * 60)
        log.info("  STEP 1: Fetching all skills from ClawHub Convex API")
        log.info("═" * 60)
        fetch_all_skills()

    if run_enrich:
        log.info("═" * 60)
        log.info("  STEP 2: Enriching top-100 slugs with OpenClaw + VirusTotal")
        log.info("═" * 60)
        enrich_top_skills(
            force          = args.force,
            clawhub_delay  = args.clawhub_delay,
            vt_delay       = args.vt_delay,
        )


if __name__ == "__main__":
    main()
META_FILE     = DATA_DIR / "clawhub_skills_meta.json"
SLUGS_FILE    = DATA_DIR / "slugs.txt"
ENRICHED_FILE = DATA_DIR / "clawhub_enriched.json"

# ── APIs ───────────────────────────────────────────────────────────────────
CONVEX_API  = "https://wry-manatee-359.convex.cloud/api/query"
CLAWHUB_WEB = "https://clawhub.ai"
VT_UI_API   = "https://www.virustotal.com/ui/files"   # no auth, JSON response

HEADERS_WEB = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
HEADERS_JSON = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
    "Referer": "https://www.virustotal.com/",
}
CONVEX_HEADERS = {"Content-Type": "application/json"}

logging.basicConfig(
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
)
log = logging.getLogger("ClawHubScraper")


# ═══════════════════════════════════════════════════════════════════════════
# PART 1 — Convex API fetch (original functionality, unchanged)
# ═══════════════════════════════════════════════════════════════════════════

def fetch_page(cursor=None) -> dict:
    args = {
        "dir": "desc",
        "highlightedOnly": False,
        "nonSuspiciousOnly": False,
        "numItems": 25,
        "sort": "downloads",
    }
    if cursor is not None:
        args["cursor"] = cursor

    payload = {
        "path": "skills:listPublicPageV4",
        "format": "convex_encoded_json",
        "args": [args],
    }
    response = requests.post(
        CONVEX_API, headers=CONVEX_HEADERS, json=payload, timeout=30
    )
    response.raise_for_status()
    return response.json()


def extract_skill(item: dict) -> dict:
    skill          = item.get("skill", {})
    owner          = item.get("owner", {})
    latest_version = item.get("latestVersion", {})

    created_ts   = skill.get("createdAt")
    created_date = (
        datetime.utcfromtimestamp(created_ts / 1000).strftime("%Y-%m-%d %H:%M:%S UTC")
        if created_ts else None
    )
    return {
        "slug":               skill.get("slug"),
        "display_name":       skill.get("displayName"),
        "summary":            skill.get("summary"),
        "owner_handle":       item.get("ownerHandle"),
        "owner_display_name": owner.get("displayName"),
        "created_date":       created_date,
        "version":            latest_version.get("version"),
        "stats":              skill.get("stats", {}),
        "tags":               list(skill.get("tags", {}).keys()),
        "skill_id":           skill.get("_id"),
    }


def append_to_list_file(f, skills: list, is_first_batch: bool) -> None:
    for i, skill in enumerate(skills):
        prefix = "" if (is_first_batch and i == 0) else ","
        f.write(prefix + "\n" + json.dumps(skill, ensure_ascii=False))
    f.flush()


def update_meta_file(meta_path: Path, new_skills: list) -> None:
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        meta = {}

    for skill in new_skills:
        slug = skill.get("slug")
        if slug:
            meta[slug] = {k: v for k, v in skill.items() if k != "slug"}

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def fetch_all_skills() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    total, cursor, page = 0, None, 1

    with open(SKILLS_FILE, "w", encoding="utf-8") as list_f:
        list_f.write("[")
        is_first_batch = True

        while True:
            log.info(f"Fetching page {page} (cursor: {cursor}) ...")
            try:
                data = fetch_page(cursor)
            except requests.RequestException as e:
                log.error(f"Request failed on page {page}: {e}")
                break

            value = data.get("value", {})
            items = value.get("page", [])

            if not items:
                log.info("Empty page — stopping.")
                break

            skills = [extract_skill(item) for item in items]
            append_to_list_file(list_f, skills, is_first_batch)
            is_first_batch = False
            update_meta_file(META_FILE, skills)

            total   += len(skills)
            has_more = value.get("hasMore", False)
            cursor   = value.get("nextCursor")

            log.info(f"  → {len(skills)} skills saved (total: {total})")

            if not has_more or not cursor:
                log.info("No more pages.")
                break

            page += 1
            time.sleep(0.3)

        list_f.write("\n]\n")

    log.info(f"Done. {total} skills written to:")
    log.info(f"  {SKILLS_FILE}  (flat list)")
    log.info(f"  {META_FILE}    (slug-keyed)")


# ═══════════════════════════════════════════════════════════════════════════
# PART 2 — ClawHub page scraper
# ═══════════════════════════════════════════════════════════════════════════

def _strip_rvar(s: str) -> str:
    """Remove $R[N] = references from ClawHub's TSR serialization format."""
    return re.sub(r"\$R\[\d+\]\s*=\s*", "", s)


def _get_str(window: str, key: str) -> str:
    """Extract first string value for key in a JavaScript-like object."""
    pat = re.compile(
        r'["\']?' + re.escape(key) + r'["\']?' + r'\s*:\s*"((?:[^"\\]|\\.)*)"',
        re.DOTALL,
    )
    m = pat.search(window)
    return m.group(1) if m else ""


def fetch_clawhub_page(owner: str, slug: str, timeout: int = 15) -> Optional[dict]:
    """
    Fetch https://clawhub.ai/{owner}/{slug} and extract:
      - OpenClaw LLM evaluation (verdict, confidence, 5 dimensions, guidance, summary, model)
      - VirusTotal sha256 hash
      - Static scan result
      - Skill stats (stars, downloads, installs)
      - File list with sizes
    Returns None on failure.
    """
    url = f"{CLAWHUB_WEB}/{owner}/{slug}"
    log.info(f"  ClawHub page: {url}")
    try:
        resp = requests.get(url, headers=HEADERS_WEB, timeout=timeout)
        resp.raise_for_status()
        html = resp.text
    except Exception as e:
        log.warning(f"  ClawHub fetch error: {e}")
        return None

    # ── Find llmAnalysis block ────────────────────────────────────────────
    la_pos = html.find("llmAnalysis")
    if la_pos < 0:
        log.warning(f"  llmAnalysis not found for {slug}")
        openclaw = {}
    else:
        window = _strip_rvar(html[la_pos: la_pos + 6000])

        # Extract scalar fields
        verdict    = _get_str(window, "verdict").lower()
        confidence = _get_str(window, "confidence").upper()
        summary    = _get_str(window, "summary")
        guidance   = _get_str(window, "guidance")
        model      = _get_str(window, "model")

        # Normalise verdict to Title case
        VERDICT_MAP = {
            "benign": "Benign", "clean": "Benign", "safe": "Benign",
            "suspicious": "Suspicious", "warn": "Suspicious",
            "malicious": "Malicious", "unsafe": "Malicious",
        }
        verdict_str = VERDICT_MAP.get(verdict, "Unknown")
        if confidence not in ("HIGH", "MEDIUM", "LOW"):
            confidence = "UNKNOWN"

        # Extract dimensions [{detail, label, name, rating}]
        dim_re = re.compile(
            r"\{[^{}]{0,2000}?"
            r'detail\s*:\s*"((?:[^"\\]|\\.)*)"'
            r".{0,600}?"
            r'label\s*:\s*"((?:[^"\\]|\\.)*)"'
            r".{0,200}?"
            r'name\s*:\s*"((?:[^"\\]|\\.)*)"'
            r".{0,200}?"
            r'rating\s*:\s*"((?:[^"\\]|\\.)*)"'
            r"[^{}]{0,200}?\}",
            re.DOTALL,
        )
        NAME_MAP = {
            "purpose_capability":          "purpose_capability",
            "instruction_scope":           "instruction_scope",
            "install_mechanism":           "install_mechanism",
            "environment_proportionality": "credentials",
            "credentials":                 "credentials",
            "persistence_privilege":       "persistence_privilege",
        }
        RATING_NORM = {"ok": "pass", "pass": "pass", "warn": "warn", "fail": "fail"}
        dimensions = {}
        for detail, label, name, rating in dim_re.findall(window):
            key = NAME_MAP.get(name.lower())
            if key:
                dimensions[key] = {
                    "label":       label,
                    "status":      RATING_NORM.get(rating.lower(), rating),
                    "description": detail,
                }

        openclaw = {
            "verdict":    verdict_str,
            "confidence": confidence,
            "summary":    summary,
            "assessment": guidance,
            "model":      model,
            "dimensions": dimensions,
        }

    # ── Find vtAnalysis block ─────────────────────────────────────────────
    vt_pos = html.find("vtAnalysis")
    vt_data = {}
    if vt_pos >= 0:
        vt_win = _strip_rvar(html[vt_pos: vt_pos + 1000])
        vt_verdict  = _get_str(vt_win, "verdict").lower()
        vt_status   = _get_str(vt_win, "status").lower()
        vt_analysis = _get_str(vt_win, "analysis")
        vt_source   = _get_str(vt_win, "source")
        vt_data = {
            "verdict":  {"benign":"Benign","clean":"Benign"}.get(vt_verdict, vt_verdict.title()),
            "status":   vt_status,
            "analysis": vt_analysis,
            "source":   vt_source,
        }

    # ── Extract sha256hash (used to build the VT report URL) ──────────────
    sha_match = re.search(r'"sha256hash"\s*:\s*"([a-f0-9]{64})"', html)
    sha256    = sha_match.group(1) if sha_match else ""

    # ── VT report link as shown on the page ───────────────────────────────
    vt_link_match = re.search(
        r'virustotal\.com/gui/file/([a-f0-9]{64})', html
    )
    vt_url = (
        f"https://www.virustotal.com/gui/file/{vt_link_match.group(1)}"
        if vt_link_match else
        (f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else "")
    )
    sha256 = sha256 or (vt_link_match.group(1) if vt_link_match else "")

    # ── staticScan block ──────────────────────────────────────────────────
    ss_pos = html.find("staticScan")
    static_scan = {}
    if ss_pos >= 0:
        ss_win = _strip_rvar(html[ss_pos: ss_pos + 800])
        static_scan = {
            "status":  _get_str(ss_win, "status"),
            "summary": _get_str(ss_win, "summary"),
            "engine":  _get_str(ss_win, "engineVersion"),
        }

    # ── Skill stats from TSR ──────────────────────────────────────────────
    stats_match = re.search(
        r'stats\s*:\s*\{([^}]{10,400})\}', _strip_rvar(html)
    )
    stats = {}
    if stats_match:
        raw_stats = "{" + stats_match.group(1) + "}"
        for k in ("stars", "downloads", "installsAllTime", "installsCurrent",
                  "comments", "versions"):
            m = re.search(rf'"{k}"\s*:\s*(\d+)', raw_stats)
            if m:
                stats[k] = int(m.group(1))

    # ── File list (path + size) ────────────────────────────────────────────
    file_matches = re.findall(
        r'"path"\s*:\s*"([^"]+)"[^}]{0,100}"size"\s*:\s*(\d+)', html
    )
    files = [{"path": p, "size_bytes": int(s)} for p, s in file_matches]

    # ── Skill version info ────────────────────────────────────────────────
    version_match = re.search(r'"version"\s*:\s*"([^"]+)"', html)
    version = version_match.group(1) if version_match else ""

    return {
        "openclaw":    openclaw,
        "virustotal":  {"sha256": sha256, "url": vt_url, **vt_data},
        "static_scan": static_scan,
        "stats":       stats,
        "files":       files,
        "version":     version,
        "scraped_at":  datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════
# PART 3 — VirusTotal enrichment
# ═══════════════════════════════════════════════════════════════════════════

# ── VirusTotal cache: hash → result (avoids re-hitting VT for same file) ──
_VT_CACHE: dict = {}


def _parse_vt_attrs(attrs: dict, sha256: str) -> dict:
    """Parse a VirusTotal attributes dict into our standard schema."""
    stats          = attrs.get("last_analysis_stats", {})
    flagged        = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total          = sum(stats.get(k, 0) for k in
                         ("malicious", "suspicious", "undetected", "harmless", "timeout"))
    ratio_str      = f"{flagged}/{total}" if total else "—"

    votes          = attrs.get("total_votes", {})
    harmless_votes = votes.get("harmless", 0)
    malicious_votes= votes.get("malicious", 0)

    type_tags      = attrs.get("type_tags", []) or attrs.get("tags", [])
    meaningful_name= attrs.get("meaningful_name", "")

    ai_results = attrs.get("crowdsourced_ai_results", [])
    ai_insight = {}
    if ai_results:
        best = ai_results[0]
        ai_insight = {
            "vendor":      best.get("vendor", ""),
            "description": best.get("description", ""),
            "confidence":  best.get("confidence", ""),
            "severity":    best.get("severity", ""),
            "category":    best.get("category", ""),
        }

    size_bytes    = attrs.get("size", 0)
    last_ts       = attrs.get("last_analysis_date", 0)
    last_analysis = (
        datetime.utcfromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
        if last_ts else ""
    )

    sigma_hits = []
    for rule in attrs.get("sigma_analysis_results", [])[:5]:
        sigma_hits.append({
            "rule":        rule.get("rule_title", ""),
            "severity":    rule.get("rule_level", ""),
            "description": rule.get("description", ""),
        })

    return {
        "sha256":          sha256,
        "report_url":      f"https://www.virustotal.com/gui/file/{sha256}",
        "detection": {
            "flagged":     flagged,
            "total":       total,
            "ratio_str":   ratio_str,
            "stats":       stats,
        },
        "community_score": harmless_votes - malicious_votes,
        "votes": {
            "harmless":    harmless_votes,
            "malicious":   malicious_votes,
        },
        "code_insight": {
            "file_type":       attrs.get("type_description", attrs.get("type_tag", "")),
            "magic":           attrs.get("magic", ""),
            "size_bytes":      size_bytes,
            "size_kb":         round(size_bytes / 1024, 2),
            "meaningful_name": meaningful_name,
            "names":           attrs.get("names", [meaningful_name])[:5],
            "tags":            type_tags,
            "last_analysis":   last_analysis,
            "ai_analysis":     ai_insight,
            "sigma_hits":      sigma_hits,
        },
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


def fetch_virustotal(
    sha256: str,
    timeout: int = 20,
    max_retries: int = 4,
    initial_wait: float = 5.0,
) -> Optional[dict]:
    """
    Fetch VirusTotal data for a file hash.

    Uses the public VT UI JSON endpoint (no API key required for
    already-analysed files). Handles 429 Too Many Requests with
    exponential backoff + Retry-After header.

    Falls back to the alternative /api/v3 endpoint if the UI endpoint
    fails after all retries.

    Returns a structured dict with detection count, community score,
    and code insights. Returns None only on unrecoverable failure.
    """
    if not sha256:
        return None

    # ── In-memory cache: never re-hit VT for the same hash ───────────────
    if sha256 in _VT_CACHE:
        log.debug(f"  VT cache hit: {sha256[:16]}...")
        return _VT_CACHE[sha256]

    endpoints = [
        f"https://www.virustotal.com/ui/files/{sha256}",
        f"https://www.virustotal.com/api/v3/files/{sha256}",
    ]

    for endpoint_url in endpoints:
        log.info(f"  VirusTotal: {endpoint_url}")
        wait = initial_wait

        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.get(
                    endpoint_url,
                    headers=HEADERS_JSON,
                    timeout=timeout,
                )

                # ── 404: hash not in VT database ─────────────────────────
                if resp.status_code == 404:
                    log.info(f"  VT: hash not found (not yet submitted to VT)")
                    return {
                        "sha256":     sha256,
                        "report_url": f"https://www.virustotal.com/gui/file/{sha256}",
                        "error":      "not_found",
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                    }

                # ── 429: rate limited ─────────────────────────────────────
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", wait))
                    actual_wait = max(retry_after, wait)
                    log.warning(
                        f"  VT 429 rate limit (attempt {attempt}/{max_retries}). "
                        f"Waiting {actual_wait:.0f}s ..."
                    )
                    time.sleep(actual_wait)
                    wait = min(wait * 2, 120)   # exponential back-off, cap 2 min
                    continue

                # ── Other HTTP error ──────────────────────────────────────
                if not resp.ok:
                    log.warning(
                        f"  VT HTTP {resp.status_code} on attempt {attempt}/{max_retries}"
                    )
                    if attempt < max_retries:
                        time.sleep(wait)
                        wait *= 2
                    continue

                # ── Success ───────────────────────────────────────────────
                data  = resp.json()
                # Both endpoints return data.attributes, but structure differs slightly
                attrs = (
                    data.get("data", {}).get("attributes", {})
                    or data.get("attributes", {})
                )
                result = _parse_vt_attrs(attrs, sha256)
                _VT_CACHE[sha256] = result
                log.info(
                    f"  VT OK — {result['detection']['ratio_str']} flagged, "
                    f"community score: {result['community_score']}"
                )
                return result

            except requests.exceptions.Timeout:
                log.warning(f"  VT timeout (attempt {attempt}/{max_retries})")
                time.sleep(wait)
                wait *= 2
            except requests.exceptions.RequestException as e:
                log.warning(f"  VT request error: {e} (attempt {attempt}/{max_retries})")
                time.sleep(wait)
                wait *= 2

        log.warning(f"  VT endpoint exhausted after {max_retries} attempts: {endpoint_url}")

    # ── All endpoints and retries exhausted ───────────────────────────────
    log.warning(
        f"  VT unavailable for {sha256[:16]}... — storing sha256 + URL only. "
        f"Run again later or increase --vt-delay."
    )
    return {
        "sha256":     sha256,
        "report_url": f"https://www.virustotal.com/gui/file/{sha256}",
        "error":      "rate_limited_all_retries_exhausted",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════════════════════════════════
# PART 4 — Enrichment pipeline: slugs.txt → clawhub_enriched.json
# ═══════════════════════════════════════════════════════════════════════════

def load_meta() -> dict:
    """Load clawhub_skills_meta.json (slug → metadata)."""
    try:
        with open(META_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.error(f"Could not load {META_FILE}: {e}")
        return {}


def load_slugs() -> list:
    """Read slug names from data/slugs.txt (one per line)."""
    try:
        lines = SLUGS_FILE.read_text(encoding="utf-8").splitlines()
        return [l.strip() for l in lines if l.strip()]
    except FileNotFoundError:
        log.error(f"{SLUGS_FILE} not found — run with --fetch first or generate slugs.txt")
        return []


def load_enriched() -> dict:
    """Load existing enriched data so we can skip already-done slugs."""
    try:
        with open(ENRICHED_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_enriched(enriched: dict) -> None:
    """Write the enriched dict to disk (pretty-printed, slug-keyed)."""
    ENRICHED_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ENRICHED_FILE, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2, ensure_ascii=False)


def enrich_top_skills(
    force: bool = False,
    clawhub_delay: float = 1.2,
    vt_delay: float = 8.0,
) -> None:
    """
    For each slug in data/slugs.txt:
      1. Look up owner_handle in clawhub_skills_meta.json
      2. Scrape clawhub.ai/{owner}/{slug} → OpenClaw evaluation + VT hash
      3. Call VirusTotal UI API → detection count, community score, code insights
      4. Save result to data/clawhub_enriched.json

    Args:
      force:          Re-fetch slugs already present in enriched.json
      clawhub_delay:  Seconds to wait between ClawHub requests (be polite)
      vt_delay:       Seconds to wait between VT requests
    """
    slugs    = load_slugs()
    meta     = load_meta()
    enriched = load_enriched()

    if not slugs:
        log.error("No slugs to enrich — aborting.")
        return

    log.info(f"Enriching {len(slugs)} slugs (force={force}) ...")
    done = skipped = errors = 0

    for i, slug in enumerate(slugs, 1):
        log.info(f"[{i}/{len(slugs)}] {slug}")

        # ── Skip if already enriched ──────────────────────────────────────
        if not force and slug in enriched:
            log.info(f"  Already enriched — skipping")
            skipped += 1
            continue

        # ── Get owner handle from meta ────────────────────────────────────
        info  = meta.get(slug, {})
        owner = info.get("owner_handle", "")
        if not owner:
            log.warning(f"  No owner_handle in meta for '{slug}' — skipping")
            errors += 1
            continue

        # ── Enrich entry: start with meta fields ──────────────────────────
        entry = {
            "slug":         slug,
            "owner_handle": owner,
            "display_name": info.get("display_name", slug),
            "summary":      info.get("summary", ""),
            "version":      info.get("version", ""),
            "created_date": info.get("created_date", ""),
            "stats":        info.get("stats", {}),
            "tags":         info.get("tags", []),
            "skill_id":     info.get("skill_id", ""),
            "clawhub_url":  f"{CLAWHUB_WEB}/{owner}/{slug}",
        }

        # ── Fetch ClawHub page ────────────────────────────────────────────
        page_data = fetch_clawhub_page(owner, slug)
        if page_data:
            entry["openclaw"]    = page_data.get("openclaw", {})
            entry["static_scan"] = page_data.get("static_scan", {})
            entry["files"]       = page_data.get("files", [])
            # Merge stats from page (may be more up-to-date)
            if page_data.get("stats"):
                entry["stats"].update(page_data["stats"])

            sha256  = page_data.get("virustotal", {}).get("sha256", "")
            vt_url  = page_data.get("virustotal", {}).get("url", "")
            entry["virustotal_url"]    = vt_url
            entry["virustotal_sha256"] = sha256

            # VT data already embedded in the ClawHub page (vtAnalysis block)
            vt_embed = page_data.get("virustotal", {})
            entry["virustotal_clawhub"] = {
                "verdict":  vt_embed.get("verdict", ""),
                "status":   vt_embed.get("status", ""),
                "analysis": vt_embed.get("analysis", ""),
                "source":   vt_embed.get("source", ""),
            }
        else:
            sha256 = ""
            log.warning(f"  ClawHub page fetch failed for {slug}")

        time.sleep(clawhub_delay)

        # ── Fetch VirusTotal report ───────────────────────────────────────
        if sha256:
            vt_data = fetch_virustotal(sha256)
            entry["virustotal_report"] = vt_data or {}
        else:
            log.info(f"  No sha256 — skipping VT lookup")
            entry["virustotal_report"] = {}

        time.sleep(vt_delay)

        # ── Save incrementally after each skill ───────────────────────────
        enriched[slug] = entry
        save_enriched(enriched)

        done += 1
        log.info(
            f"  ✅ Done — OpenClaw: {entry.get('openclaw', {}).get('verdict', '?')} | "
            f"VT: {entry.get('virustotal_report', {}).get('detection', {}).get('ratio_str', '?')} | "
            f"Community: {entry.get('virustotal_report', {}).get('community_score', '?')}"
        )

    log.info(
        f"\nEnrichment complete — done: {done}, skipped: {skipped}, errors: {errors}"
    )
    log.info(f"Output: {ENRICHED_FILE.resolve()}")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="ClawHub scraper + VirusTotal enrichment"
    )
    parser.add_argument(
        "--fetch",   action="store_true",
        help="Fetch all skills from the Convex API (writes clawhub_skills.json + clawhub_skills_meta.json)"
    )
    parser.add_argument(
        "--enrich",  action="store_true",
        help="Enrich top-100 slugs with OpenClaw + VirusTotal data (writes clawhub_enriched.json)"
    )
    parser.add_argument(
        "--force",   action="store_true",
        help="Re-fetch slugs already present in clawhub_enriched.json"
    )
    parser.add_argument(
        "--clawhub-delay", type=float, default=1.0, metavar="SEC",
        help="Seconds between ClawHub page requests (default: 1.0)"
    )
    parser.add_argument(
        "--vt-delay", type=float, default=8.0, metavar="SEC",
        help="Seconds between VirusTotal requests (default: 8.0). "
    )
    args = parser.parse_args()

    # Default: run both if neither flag given
    run_fetch  = args.fetch  or (not args.fetch and not args.enrich)
    run_enrich = args.enrich or (not args.fetch and not args.enrich)

    if run_fetch:
        log.info("═" * 60)
        log.info("  STEP 1: Fetching all skills from ClawHub Convex API")
        log.info("═" * 60)
        fetch_all_skills()

    if run_enrich:
        log.info("═" * 60)
        log.info("  STEP 2: Enriching top-100 slugs with OpenClaw + VirusTotal")
        log.info("═" * 60)
        enrich_top_skills(
            force          = args.force,
            clawhub_delay  = args.clawhub_delay,
            vt_delay       = args.vt_delay,
        )


if __name__ == "__main__":
    main()