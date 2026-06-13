"""
clawhub_fetch.py
================
ClawHub skill fetching and official evaluation report retrieval.

Two main responsibilities:
  1. Fetch SKILL.md files from ClawHub (original functionality)
  2. Fetch the official ClawHub safety evaluation report for a skill
     — used by the AgentSkillBench detail page ClawHub tab

Official evaluation lookup flow:
  Given a skill filename or slug (e.g. "self-improving-agent"):
    a. Look up in clawhub_skills_meta.json → get skill_id + owner_handle
    b. Try GET /api/v1/skills/{skill_id}   → look for safety/evaluation fields
    c. Try GET /api/v1/skills/{slug}       → same search by slug
    d. Scrape https://clawhub.ai/{owner}/{slug} → parse the rendered HTML
    e. Return a normalized dict matching the ClawHub report schema

ClawHub report schema (mirrors the OpenClaw UI):
  {
    "verdict":    "Benign" | "Suspicious" | "Malicious",
    "confidence": "HIGH"   | "MEDIUM"     | "LOW",
    "summary":    str,
    "assessment": str,
    "categories": {
      "purpose_capability":      {"status": "pass"|"warn"|"fail", "description": str},
      "instruction_scope":       {"status": ..., "description": str},
      "install_mechanism":       {"status": ..., "description": str},
      "credentials":             {"status": ..., "description": str},
      "persistence_privilege":   {"status": ..., "description": str},
    }
  }
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("ClawHubFetch")

BASE_URL    = "https://clawhub.ai/api/v1"
GITHUB_BASE = "https://raw.githubusercontent.com/openclaw/skills/main/skills"
GITHUB_API  = "https://api.github.com/repos/openclaw/skills/contents/skills"
CLAWHUB_WEB = "https://clawhub.ai"

TARGET_OWNER = "byungkyu"   # ← change for batch fetching


# ─────────────────────────────────────────────────────────────────────────────
# Skills metadata (clawhub_skills_meta.json)
# ─────────────────────────────────────────────────────────────────────────────

_META_CACHE: Optional[dict] = None


def load_skills_meta(meta_path: Optional[str] = None) -> dict:
    """
    Load clawhub_skills_meta.json.
    Structure: { slug: { skill_id, owner_handle, display_name, stats, ... } }

    Searches for the file in:
      1. meta_path (if provided)
      2. Same directory as this script
      3. Current working directory
    """
    global _META_CACHE
    if _META_CACHE is not None:
        return _META_CACHE

    candidates = []
    if meta_path:
        candidates.append(Path(meta_path))
    _here = Path(__file__).resolve().parent          # source_code/clawhub
    candidates.append(_here / "data/clawhub_skills_meta.json")
    candidates.append(_here.parent.parent / "data/clawhub_skills_meta.json")  # skillvetbench_github/data/
    candidates.append(Path("data/clawhub_skills_meta.json"))

    for p in candidates:
        if p.exists():
            try:
                _META_CACHE = json.loads(p.read_text(encoding="utf-8"))
                logger.debug(f"Loaded skills meta from {p} ({len(_META_CACHE)} skills)")
                return _META_CACHE
            except Exception as e:
                logger.warning(f"Could not parse {p}: {e}")

    logger.warning("data/clawhub_skills_meta.json not found — skill_id lookup unavailable")
    _META_CACHE = {}
    return _META_CACHE


def lookup_skill(slug_or_filename: str) -> Optional[dict]:
    """
    Look up a skill in the metadata by slug or filename.

    Accepts:
      - "self-improving-agent"
      - "self-improving-agent.md"
      - "self-improving-agent_SKILL.md"
      - "/path/to/self-improving-agent.md"

    Returns the metadata dict or None if not found.
    """
    # Normalise to slug
    slug = Path(slug_or_filename).stem  # remove extension
    slug = slug.replace("_SKILL", "")   # strip _SKILL suffix
    slug = slug.strip("/").split("/")[-1]  # take last path component

    meta = load_skills_meta()

    # Exact match first
    if slug in meta:
        entry = dict(meta[slug])
        entry["slug"] = slug
        return entry

    # Case-insensitive fallback
    slug_lower = slug.lower()
    for key, val in meta.items():
        if key.lower() == slug_lower:
            entry = dict(val)
            entry["slug"] = key
            return entry

    logger.debug(f"Slug '{slug}' not found in clawhub_skills_meta.json")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Official ClawHub evaluation report
# ─────────────────────────────────────────────────────────────────────────────

def fetch_official_evaluation(
    slug_or_filename: str,
    timeout: int = 12,
) -> Optional[dict]:
    """
    Fetch the official ClawHub safety evaluation for a skill.

    Returns a normalized evaluation dict or None if unavailable.

    Strategy (tries each in order until one succeeds):
      1. GET /api/v1/skills/{skill_id}             (by skill_id from meta.json)
      2. GET /api/v1/skills/{slug}                 (by slug)
      3. GET /api/v1/skills/{skill_id}/evaluation  (dedicated evaluation endpoint)
      4. Scrape https://clawhub.ai/{owner}/{slug}  (HTML fallback)
    """
    info = lookup_skill(slug_or_filename)
    slug = info["slug"] if info else _to_slug(slug_or_filename)
    skill_id = info.get("skill_id") if info else None
    owner = info.get("owner_handle") if info else None

    logger.info(f"Fetching official ClawHub evaluation: slug={slug} skill_id={skill_id}")

    # ── Strategy 3: HTML scraping ─────────────────────────────────────────
    if owner:
        result = _scrape_clawhub_page(owner, slug, timeout)
        if result:
            logger.info(f"  ✅ Got evaluation via web scraping clawhub.ai/{owner}/{slug}")
            return result

    # ── Strategy 1: by skill_id via API ──────────────────────────────────
    if skill_id:
        result = _try_api_endpoint(f"{BASE_URL}/skills/{skill_id}", timeout)
        if result:
            logger.info(f"  ✅ Got evaluation via /api/v1/skills/{skill_id}")
            return result

        result = _try_api_endpoint(f"{BASE_URL}/skills/{skill_id}/evaluation", timeout)
        if result:
            logger.info(f"  ✅ Got evaluation via /api/v1/skills/{skill_id}/evaluation")
            return result

        result = _try_api_endpoint(f"{BASE_URL}/skills/{skill_id}/safety", timeout)
        if result:
            logger.info(f"  ✅ Got evaluation via /api/v1/skills/{skill_id}/safety")
            return result

    # ── Strategy 2: by slug via API ───────────────────────────────────────
    result = _try_api_endpoint(f"{BASE_URL}/skills/{slug}", timeout)
    if result:
        logger.info(f"  ✅ Got evaluation via /api/v1/skills/{slug}")
        return result


    logger.info(f"  ℹ️  No official evaluation found for '{slug}'")
    return None


def _to_slug(slug_or_filename: str) -> str:
    """Convert filename or path to a clean slug."""
    slug = Path(slug_or_filename).stem
    slug = slug.replace("_SKILL", "").strip("/").split("/")[-1]
    return slug


def _try_api_endpoint(url: str, timeout: int) -> Optional[dict]:
    """
    Try a single API endpoint. Returns normalised evaluation dict or None.
    """
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code != 200:
            return None
        data = resp.json()
    except Exception as e:
        logger.debug(f"  API {url} → {e}")
        return None

    # Try to extract evaluation from various response shapes
    return _normalise_api_response(data)


def _normalise_api_response(data: dict) -> Optional[dict]:
    """
    ClawHub API may return evaluation data under different keys.
    Try to extract and normalise into our standard schema.
    """
    if not isinstance(data, dict):
        return None

    # Direct evaluation fields at top level
    verdict = (
        data.get("verdict")
        or data.get("safetyVerdict")
        or data.get("classification")
        or data.get("safety_verdict")
        or (
            "Benign" if data.get("is_safe") is True else
            "Malicious" if data.get("is_safe") is False else
            None
        )
    )

    # Nested evaluation object
    eval_obj = (
        data.get("evaluation")
        or data.get("safety")
        or data.get("safetyReport")
        or data.get("analysis")
        or data.get("review")
        or {}
    )

    if not verdict and eval_obj:
        verdict = (
            eval_obj.get("verdict")
            or eval_obj.get("safetyVerdict")
            or eval_obj.get("classification")
        )

    if not verdict:
        return None  # This response has no evaluation data

    # Build normalised categories
    raw_cats = (
        data.get("categories")
        or data.get("checks")
        or eval_obj.get("categories")
        or eval_obj.get("checks")
        or {}
    )

    # Map flexible key names to our standard names
    KEY_MAP = {
        "purpose_capability":  ["purpose_capability","purposeCapability","purpose","capability"],
        "instruction_scope":   ["instruction_scope","instructionScope","scope","instructions"],
        "install_mechanism":   ["install_mechanism","installMechanism","install","installation"],
        "credentials":         ["credentials","credential","secrets","auth"],
        "persistence_privilege":["persistence_privilege","persistencePrivilege","persistence","privilege"],
    }

    normalised_cats = {}
    for std_key, aliases in KEY_MAP.items():
        for alias in aliases:
            if alias in raw_cats:
                cat = raw_cats[alias]
                if isinstance(cat, dict):
                    normalised_cats[std_key] = {
                        "status":      cat.get("status","").lower() or cat.get("result","").lower() or "pass",
                        "description": cat.get("description") or cat.get("details") or cat.get("message") or "",
                    }
                elif isinstance(cat, str):
                    normalised_cats[std_key] = {"status": cat.lower(), "description": ""}
                break

    return {
        "verdict":    str(verdict).capitalize(),
        "confidence": str(data.get("confidence") or eval_obj.get("confidence") or "MEDIUM").upper(),
        "summary":    data.get("summary") or eval_obj.get("summary") or data.get("description") or "",
        "assessment": data.get("assessment") or eval_obj.get("assessment") or eval_obj.get("recommendation") or "",
        "categories": normalised_cats,
        "source":     "official_api",
        "raw":        data,
    }


def _scrape_clawhub_page(owner: str, slug: str, timeout: int) -> Optional[dict]:
    """
    Fetch the ClawHub skill page and extract the official LLM safety evaluation.

    ClawHub is a React SPA. The full skill data is embedded in an inline
    <script class="$tsr"> tag using a custom $R[N] = serialization:

        $_TSR.router = ($R => $R[0] = {
            ...
            llmAnalysis: $R[21] = {
                verdict: "benign",
                confidence: "high",
                summary: "...",
                guidance: "...",
                dimensions: $R[22] = [
                    $R[23] = { name: "purpose_capability",
                               label: "Purpose & Capability",
                               rating: "ok", detail: "..." },
                    ...
                ]
            }
        })($R["tsr"]);

    We strip the $R[N] = references and extract llmAnalysis fields with regex.
    """
    url = f"{CLAWHUB_WEB}/{owner}/{slug}"
    logger.info(f"  Fetching: {url}")
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
            allow_redirects=True,
        )
        resp.raise_for_status()
        html = resp.text
        logger.info(f"  HTTP {resp.status_code}, {len(html):,} chars")
    except Exception as e:
        logger.error(f"  Fetch error: {e}")
        return None

    return _parse_clawhub_html(html, owner, slug)


def _parse_clawhub_html(html: str, owner: str = "", slug: str = "") -> Optional[dict]:
    """
    Parse the ClawHub skill page HTML and extract the llmAnalysis evaluation.

    Key facts about the actual ClawHub HTML:
    - Data is in an inline script tag (NOT __NEXT_DATA__)
    - Uses $R[N] = value references throughout the JavaScript
    - llmAnalysis.verdict is lowercase: "benign" / "suspicious" / "malicious"
    - llmAnalysis.dimensions[i].rating is "ok" / "warn" / "fail"
    - "environment_proportionality" dimension name = Credentials category
    - "guidance" field = the assessment text shown to users

    Returns a normalised dict or None.
    """

    # ── Step 1: Find the llmAnalysis block ───────────────────────────────
    # Try both quoted and unquoted key forms
    la_pos = -1
    for needle in ('"llmAnalysis"', 'llmAnalysis:'):
        la_pos = html.find(needle)
        if la_pos >= 0:
            break

    if la_pos < 0:
        logger.debug("  llmAnalysis not found in HTML — falling back")
        return _parse_clawhub_html_fallback(html)

    # Extract enough HTML to cover all 5 dimensions (each ~400 chars)
    window = html[la_pos: la_pos + 6000]

    # Strip $R[N] = references so the text becomes easier to regex
    window_clean = re.sub(r'\$R\[\d+\]\s*=\s*', '', window)

    # ── Step 2: Extract simple string fields ─────────────────────────────
    def get_str(key):
        """Extract first "value" for key: "value" in the window."""
        pat = re.compile(
            r'["\']?' + re.escape(key) + r'["\']?' + r'\s*:\s*"((?:[^"\\]|\\.)*)"',
            re.DOTALL
        )
        m = pat.search(window)
        return m.group(1) if m else ""

    verdict    = get_str("verdict").lower()
    confidence = get_str("confidence").upper()
    summary    = get_str("summary")
    guidance   = get_str("guidance")

    if not verdict:
        # Fallback: check vtAnalysis verdict
        vt_pos = html.find("vtAnalysis")
        if vt_pos >= 0:
            m = re.search(r'verdict\s*:\s*"([^"]+)"', html[vt_pos:vt_pos+300])
            if m:
                verdict = m.group(1).lower()

    if not verdict:
        logger.debug("  No verdict in llmAnalysis — falling back")
        return _parse_clawhub_html_fallback(html)

    # Normalise verdict
    VERDICT_MAP = {
        "benign": "Benign", "clean": "Benign", "safe": "Benign",
        "suspicious": "Suspicious", "warn": "Suspicious",
        "malicious": "Malicious", "unsafe": "Malicious",
    }
    verdict_str = VERDICT_MAP.get(verdict, "Suspicious")

    if confidence not in ("HIGH", "MEDIUM", "LOW"):
        confidence = "MEDIUM"

    # ── Step 3: Extract dimensions ────────────────────────────────────────
    # Each dimension in the actual HTML:
    #   $R[23] = { detail: "...", label: "...", name: "...", rating: "ok" }
    # After stripping $R[N]= we get plain objects.
    #
    # Use a pattern that handles any field order.
    dim_re = re.compile(
        r'\{[^{}]{0,2000}?'
        r'detail\s*:\s*"((?:[^"\\]|\\.)*)"'
        r'.{0,600}?'
        r'label\s*:\s*"((?:[^"\\]|\\.)*)"'
        r'.{0,200}?'
        r'name\s*:\s*"((?:[^"\\]|\\.)*)"'
        r'.{0,200}?'
        r'rating\s*:\s*"((?:[^"\\]|\\.)*)"'
        r'[^{}]{0,200}?\}',
        re.DOTALL,
    )
    dims_found = dim_re.findall(window_clean)

    # Dimension name/label → our standard key
    # "environment_proportionality" is ClawHub's internal name for Credentials
    NAME_KEY = {
        "purpose_capability":          "purpose_capability",
        "instruction_scope":           "instruction_scope",
        "install_mechanism":           "install_mechanism",
        "environment_proportionality": "credentials",
        "credentials":                 "credentials",
        "persistence_privilege":       "persistence_privilege",
    }
    LABEL_KEY = {
        "purpose & capability":    "purpose_capability",
        "purpose and capability":  "purpose_capability",
        "instruction scope":       "instruction_scope",
        "install mechanism":       "install_mechanism",
        "credentials":             "credentials",
        "persistence & privilege": "persistence_privilege",
        "persistence and privilege":"persistence_privilege",
    }
    # ClawHub uses "ok" where we use "pass"
    RATING_NORM = {"ok": "pass", "pass": "pass", "warn": "warn", "fail": "fail"}

    categories = {}
    for detail, label, name, rating in dims_found:
        std_key = NAME_KEY.get(name.lower()) or LABEL_KEY.get(label.lower())
        if std_key:
            categories[std_key] = {
                "status":      RATING_NORM.get(rating.lower(), "pass"),
                "description": detail,
            }

    logger.info(
        f"  Parsed: verdict={verdict_str} confidence={confidence} "
        f"dims={len(categories)}/5"
    )

    return {
        "verdict":    verdict_str,
        "confidence": confidence,
        "summary":    summary,
        "assessment": guidance,
        "categories": categories,
        "source":     "scraped_tsr",
    }


def _parse_clawhub_html_fallback(html: str) -> Optional[dict]:
    """
    Last-resort parser when llmAnalysis block is missing.
    Reads plain-text verdict/confidence from the rendered HTML.
    """
    # Strip tags for plain text search
    text = re.sub(r'<[^>]+>', ' ', html)
    text = re.sub(r'&amp;', '&', text)
    text = re.sub(r'&lt;', '<', text)
    text = re.sub(r'&gt;', '>', text)
    text = re.sub(r'\s+', ' ', text).strip()

    # Verdict
    verdict = None
    for word in ("Malicious", "Suspicious", "Benign"):
        if word in text:
            verdict = word
            break
    if not verdict:
        m = re.search(r'verdict["\']?\s*:\s*"(\w+)"', html, re.IGNORECASE)
        if m:
            v = m.group(1).lower()
            verdict = {"benign":"Benign","clean":"Benign",
                       "suspicious":"Suspicious",
                       "malicious":"Malicious","unsafe":"Malicious"}.get(v)
    if not verdict:
        return None

    # Confidence
    confidence = "MEDIUM"
    m = re.search(r'(high|medium|low)\s+confidence', html, re.IGNORECASE)
    if m:
        confidence = m.group(1).upper()

    # Category statuses from check-mark classes in rendered HTML
    LABEL_KEY = {
        "purpose & capability":    "purpose_capability",
        "purpose and capability":  "purpose_capability",
        "instruction scope":       "instruction_scope",
        "install mechanism":       "install_mechanism",
        "credentials":             "credentials",
        "persistence & privilege": "persistence_privilege",
        "persistence and privilege":"persistence_privilege",
    }
    categories = {}
    text_upper = text.upper()
    for label, key in LABEL_KEY.items():
        pos = text_upper.find(label.upper())
        if pos >= 0:
            nearby = text[max(0, pos - 100):pos + 400]
            status = "pass"
            if re.search(r'\bfail\b', nearby, re.IGNORECASE):
                status = "fail"
            elif re.search(r'\bwarn\b', nearby, re.IGNORECASE):
                status = "warn"
            desc = re.sub(r'\s+', ' ', nearby.replace(label, '', 1)).strip()[:250]
            categories[key] = {"status": status, "description": desc}

    # Summary from analysis-summary-text span
    summary = ""
    m = re.search(r'analysis-summary-text[^>]*>([^<]{20,400})', html)
    if m:
        summary = re.sub(r'\s+', ' ', m.group(1)).strip()

    # Assessment from analysis-guidance div
    assessment = ""
    m = re.search(
        r'class="analysis-guidance[^"]*"[^>]*>.*?<div[^>]*>([^<]{20,600})',
        html, re.DOTALL
    )
    if m:
        assessment = re.sub(r'\s+', ' ', m.group(1)).strip()

    return {
        "verdict":    verdict,
        "confidence": confidence,
        "summary":    summary,
        "assessment": assessment,
        "categories": categories,
        "source":     "scraped_html_fallback",
    }



def get_skill_url(slug_or_filename: str) -> Optional[str]:
    """Return the ClawHub web URL for a skill, e.g. https://clawhub.ai/pskoett/self-improving-agent"""
    info = lookup_skill(slug_or_filename)
    if not info:
        return None
    slug  = info.get("slug", _to_slug(slug_or_filename))
    owner = info.get("owner_handle", "")
    if not owner:
        return None
    return f"{CLAWHUB_WEB}/{owner}/{slug}"


def get_skill_stats(slug_or_filename: str) -> Optional[dict]:
    """Return skill stats from metadata (stars, downloads, installs, etc.)"""
    info = lookup_skill(slug_or_filename)
    if not info:
        return None
    return {
        "slug":              info.get("slug"),
        "display_name":      info.get("display_name"),
        "owner_handle":      info.get("owner_handle"),
        "owner_display_name":info.get("owner_display_name"),
        "version":           info.get("version"),
        "created_date":      info.get("created_date"),
        "tags":              info.get("tags", []),
        "stats":             info.get("stats", {}),
        "skill_id":          info.get("skill_id"),
        "url":               get_skill_url(slug_or_filename),
        "summary":           info.get("summary"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Download API — fetch skill zip and extract SKILL.md in memory
# ─────────────────────────────────────────────────────────────────────────────

DOWNLOAD_API = "https://wry-manatee-359.convex.site/api/v1/download"
SLUGS_TXT    = "data/slugs.txt"   # one slug name per line, top-N sorted by stars


def _slugs_txt_path() -> Path:
    return Path(__file__).resolve().parent / SLUGS_TXT


def _write_slugs_txt(meta: dict, top_n: int = 100) -> None:
    """
    Write the top-N slug names (sorted by stars descending) to data/slugs.txt.
    One slug per line.  This file is the source of truth for the dropdown.
    """
    path = _slugs_txt_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    ranked = sorted(
        meta.items(),
        key=lambda kv: float((kv[1].get("stats") or {}).get("stars", 0) or 0),
        reverse=True,
    )[:top_n]

    lines = [slug for slug, _ in ranked]
    path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Wrote top-{len(lines)} slugs (by stars) to {path}")


def _read_slugs_txt() -> Optional[list]:
    """
    Read slug names from data/slugs.txt.
    Returns a sorted list of slug name strings, or None if the file does not exist.
    """
    path = _slugs_txt_path()
    if not path.exists():
        return None
    slugs = [s.strip() for s in path.read_text(encoding="utf-8").splitlines() if s.strip()]
    logger.debug(f"Read {len(slugs)} slugs from {path}")
    return slugs


def list_slugs_from_meta(top_n: int = 100) -> list:
    """
    Return the top-N skills for the leaderboard dropdown.

    Args:
        top_n: Maximum number of skills to return, ranked by stars (default 100).

    Flow:
      1. If data/slugs.txt exists → read slug names from it (stars-sorted list),
         enrich each name with metadata (owner, stats, version) from the JSON,
         then return the first top_n entries.
      2. If data/slugs.txt does not exist → parse clawhub_skills_meta.json,
         rank by stars, write slugs.txt (full list), return top_n enriched entries.

    The dropdown order always mirrors the order in slugs.txt (stars desc).
    """
    meta = load_skills_meta()
    if not meta:
        return []

    # ── Ensure slugs.txt exists and contains the top-100 ranked list ─────
    slug_names = _read_slugs_txt()
    if slug_names is None:
        try:
            _write_slugs_txt(meta, top_n)    # writes top-N sorted by stars
            slug_names = _read_slugs_txt()   # re-read to get the ranked order
        except Exception as e:
            logger.warning(f"Could not write slugs.txt: {e}")
            slug_names = None

    # ── Build entries in slugs.txt order (stars desc) ────────────────────
    if slug_names:
        result = []
        for slug in slug_names[:top_n]:        # honour top_n; order preserved from slugs.txt
            info  = meta.get(slug, {})
            owner = info.get("owner_handle", "")
            stats = info.get("stats") or {}
            result.append({
                "slug":         slug,
                "filename":     f"{slug}.md",
                "display_name": info.get("display_name", slug),
                "owner_handle": owner,
                "version":      info.get("version", ""),
                "summary":      (info.get("summary") or "")[:120],
                "stats":        stats,
                "tags":         info.get("tags", []),
                "url":          f"{CLAWHUB_WEB}/{owner}/{slug}" if owner else "",
                "size_kb":      0,
                "models_done":  [],
                "source":       "clawhub_meta",
            })
        return result

    # ── Fallback: slugs.txt unavailable, build from meta directly ────────
    result = []
    for slug, info in meta.items():
        owner = info.get("owner_handle", "")
        stats = info.get("stats") or {}
        result.append({
            "slug":         slug,
            "filename":     f"{slug}.md",
            "display_name": info.get("display_name", slug),
            "owner_handle": owner,
            "version":      info.get("version", ""),
            "summary":      (info.get("summary") or "")[:120],
            "stats":        stats,
            "tags":         info.get("tags", []),
            "url":          f"{CLAWHUB_WEB}/{owner}/{slug}" if owner else "",
            "size_kb":      0,
            "models_done":  [],
            "source":       "clawhub_meta",
        })
    result.sort(key=lambda x: float(x["stats"].get("stars", 0) or 0), reverse=True)
    return result[:top_n]


def fetch_skill_from_zip(slug: str, timeout: int = 30) -> Optional[str]:
    """
    Download the skill zip from the ClawHub download API and extract
    SKILL.md entirely in memory — nothing is written to disk.

    API: GET https://wry-manatee-359.convex.site/api/v1/download?slug={slug}

    Returns the SKILL.md content as a string, or None on failure.
    """
    import io
    import zipfile

    url = f"{DOWNLOAD_API}?slug={slug}"
    logger.info(f"Downloading skill zip: {url}")

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"Accept": "application/zip, application/octet-stream, */*"},
            stream=True,
        )
        resp.raise_for_status()
    except requests.HTTPError as e:
        logger.error(f"  Download failed HTTP {resp.status_code}: {e}")
        return None
    except requests.RequestException as e:
        logger.error(f"  Download request error: {e}")
        return None

    content = resp.content
    logger.info(f"  Downloaded {len(content):,} bytes")

    # ── Try to open as zip ────────────────────────────────────────────────
    try:
        z = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile:
        # Not a zip — accept plain-text markdown directly
        try:
            text = content.decode("utf-8", errors="replace")
            if text.strip().startswith("#") or "---" in text[:200]:
                logger.info("  Response is plain-text SKILL.md (not zipped)")
                return text
        except Exception:
            pass
        logger.error("  Response is neither a valid zip nor plain-text markdown")
        return None

    names = z.namelist()
    logger.info(f"  Zip contents: {names}")

    # ── Locate SKILL.md (case-insensitive, any directory depth) ───────────
    candidates = [n for n in names if n.split("/")[-1].upper() == "SKILL.MD"]
    if not candidates:
        candidates = [n for n in names if n.lower().endswith(".md")]
    if not candidates:
        logger.error(f"  No SKILL.md found in zip. Contents: {names}")
        return None

    # Prefer root-level file; among ties take shortest path
    candidates.sort(key=lambda n: (n.count("/"), n.upper() != "SKILL.MD", n))
    target = candidates[0]

    try:
        skill_md = z.read(target).decode("utf-8", errors="replace")
        logger.info(f"  Extracted '{target}': {len(skill_md):,} chars")
        return skill_md
    except Exception as e:
        logger.error(f"  Could not read '{target}' from zip: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Original batch-fetch functionality (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def get_slugs_via_api(owner: str) -> list:
    slugs, cursor, page = [], None, 1
    print(f"\n[API] Searching for owner='{owner}' ...")
    while True:
        params = {"limit": 50}
        if cursor:
            params["cursor"] = cursor
        try:
            resp = requests.get(f"{BASE_URL}/skills", params=params, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"  API error on page {page}: {e}")
            break
        data  = resp.json()
        items = data.get("items", [])
        if not items:
            break
        for skill in items:
            handle = (
                skill.get("ownerHandle")
                or skill.get("owner", {}).get("handle")
                or skill.get("owner") or ""
            )
            if handle.lower() == owner.lower():
                slugs.append(skill["slug"])
                print(f"  ✓ {skill['slug']}")
        cursor = data.get("nextCursor")
        if not cursor:
            break
        page += 1
    print(f"  API found {len(slugs)} slug(s)")
    return slugs


def get_slugs_via_github(owner: str) -> list:
    url = f"{GITHUB_API}/{owner}"
    print(f"\n[GitHub] Listing skills/{owner}/")
    try:
        resp = requests.get(url, headers={"Accept": "application/vnd.github+json"}, timeout=15)
        resp.raise_for_status()
    except requests.HTTPError as e:
        if resp.status_code == 404:
            print(f"  Owner '{owner}' not found in GitHub archive.")
        else:
            print(f"  GitHub error: {e}")
        return []
    entries = resp.json()
    slugs   = [e["name"] for e in entries if e.get("type") == "dir"]
    print(f"  GitHub found {len(slugs)} slug(s):")
    for s in slugs:
        print(f"    → {s}")
    return slugs


def fetch_skill_md(owner: str, slug: str) -> Optional[str]:
    try:
        url  = f"{BASE_URL}/skills/{slug}/file"
        resp = requests.get(url, params={"path": "SKILL.md"}, timeout=10)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException:
        pass
    try:
        url  = f"{GITHUB_BASE}/{owner}/{slug}/SKILL.md"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"    ✗ Could not fetch SKILL.md for '{slug}': {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Main (batch fetch, original behaviour)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print(f"  ClawHub — All Skills for owner: '{TARGET_OWNER}'")
    print("=" * 60)

    slugs = get_slugs_via_github(TARGET_OWNER)
    if not slugs:
        print("\n  GitHub returned nothing — trying API ...")
        slugs = get_slugs_via_api(TARGET_OWNER)
    if not slugs:
        print(f"\n  ✗ No skills found for owner '{TARGET_OWNER}'.")
        exit(1)

    print(f"\n  Found {len(slugs)} skill(s): {slugs}")
    os.makedirs(TARGET_OWNER, exist_ok=True)
    results = {}

    print(f"\n{'─' * 60}")
    print(f"  Fetching SKILL.md for each slug ...")
    print(f"{'─' * 60}")

    for slug in slugs:
        print(f"\n  [{slug}]")
        content = fetch_skill_md(TARGET_OWNER, slug)
        if content:
            out_path = os.path.join(TARGET_OWNER, f"{slug}_SKILL.md")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"    ✓ {len(content):,} chars → {out_path}")

            # Bonus: show ClawHub URL for this skill
            url = get_skill_url(slug)
            if url:
                print(f"    🔗 {url}")

            results[slug] = content
        else:
            print(f"    ✗ Skipped")

    print(f"\n{'=' * 60}")
    print(f"  Done. {len(results)}/{len(slugs)} files fetched.")
    print(f"  Files saved in: ./{TARGET_OWNER}/")
    print(f"{'=' * 60}")
    