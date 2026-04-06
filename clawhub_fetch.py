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
    candidates.append(Path(__file__).resolve().parent / "data/clawhub_skills_meta.json")
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

    # ── Strategy 3: HTML scraping ─────────────────────────────────────────
    if owner:
        result = _scrape_clawhub_page(owner, slug, timeout)
        if result:
            logger.info(f"  ✅ Got evaluation via web scraping clawhub.ai/{owner}/{slug}")
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
    Scrape https://clawhub.ai/{owner}/{slug} and parse the safety evaluation
    from the rendered HTML.

    The page renders a React app, so the evaluation data is typically
    embedded as a __NEXT_DATA__ JSON script tag or similar.
    """
    url = f"{CLAWHUB_WEB}/{owner}/{slug}"
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; AgentSkillBench/1.0)"},
        )
        if resp.status_code != 200:
            logger.debug(f"  Scrape {url} → HTTP {resp.status_code}")
            return None
        html = resp.text
    except Exception as e:
        logger.debug(f"  Scrape {url} → {e}")
        return None

    # ── Try __NEXT_DATA__ JSON (Next.js apps embed full page data here) ───
    m = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', html, re.DOTALL)
    if m:
        try:
            next_data = json.loads(m.group(1))
            # Walk the Next.js data structure for evaluation fields
            # Common paths: props.pageProps.skill.evaluation / .safety / .review
            skill_data = (
                next_data.get("props", {}).get("pageProps", {}).get("skill")
                or next_data.get("props", {}).get("pageProps", {}).get("data")
                or {}
            )
            result = _normalise_api_response(skill_data)
            if result:
                result["source"] = "scraped_nextjs"
                return result
        except Exception as e:
            logger.debug(f"  __NEXT_DATA__ parse error: {e}")

    # ── Try inline JSON patterns ──────────────────────────────────────────
    for pattern in [
        r'"verdict"\s*:\s*"(Benign|Suspicious|Malicious)"',
        r'"safetyVerdict"\s*:\s*"([^"]+)"',
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            # Found a verdict — try to extract the surrounding JSON object
            verdict_pos = m.start()
            # Find the enclosing { ... }
            start = html.rfind('{', 0, verdict_pos)
            if start >= 0:
                depth = 0
                for i, ch in enumerate(html[start:start+5000], start):
                    if ch == '{': depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            try:
                                obj = json.loads(html[start:i+1])
                                result = _normalise_api_response(obj)
                                if result:
                                    result["source"] = "scraped_html"
                                    return result
                            except Exception:
                                pass
                            break

    # ── Parse structured HTML directly ───────────────────────────────────
    return _parse_clawhub_html(html, owner, slug)


def _parse_clawhub_html(html: str, owner: str, slug: str) -> Optional[dict]:
    """
    Last-resort HTML parser for the ClawHub skill page.
    Extracts verdict, categories, and assessment from the rendered DOM.
    """
    # Verdict
    verdict = None
    for word in ["Benign", "Suspicious", "Malicious"]:
        if word in html:
            verdict = word
            break

    if not verdict:
        return None

    # Confidence
    confidence = "MEDIUM"
    for level in ["HIGH CONFIDENCE", "MEDIUM CONFIDENCE", "LOW CONFIDENCE"]:
        if level in html.upper():
            confidence = level.split()[0]
            break

    # Categories — look for known titles
    CATEGORY_TITLES = {
        "purpose_capability":   ["PURPOSE & CAPABILITY", "PURPOSE AND CAPABILITY"],
        "instruction_scope":    ["INSTRUCTION SCOPE"],
        "install_mechanism":    ["INSTALL MECHANISM"],
        "credentials":          ["CREDENTIALS"],
        "persistence_privilege":["PERSISTENCE & PRIVILEGE", "PERSISTENCE AND PRIVILEGE"],
    }

    categories = {}
    html_upper = html.upper()
    for key, titles in CATEGORY_TITLES.items():
        for title in titles:
            pos = html_upper.find(title)
            if pos >= 0:
                # Look for pass/warn/fail signal near the title
                nearby = html[max(0, pos-200):pos+500]
                status = "pass"
                nearby_lower = nearby.lower()
                if "fail" in nearby_lower or "✕" in nearby or "×" in nearby:
                    status = "fail"
                elif "warn" in nearby_lower or "⚠" in nearby:
                    status = "warn"

                # Extract description text (strip HTML tags)
                desc = re.sub(r'<[^>]+>', ' ', nearby)
                desc = re.sub(r'\s+', ' ', desc).strip()
                desc = desc.replace(title, "").strip()[:300]

                categories[key] = {"status": status, "description": desc}
                break

    # Summary / assessment — paragraphs near the verdict
    verdict_pos = html.find(verdict)
    nearby_text = re.sub(r'<[^>]+>', ' ', html[verdict_pos:verdict_pos+2000])
    nearby_text = re.sub(r'\s+', ' ', nearby_text).strip()
    summary = nearby_text[:300] if nearby_text else ""

    return {
        "verdict":    verdict,
        "confidence": confidence,
        "summary":    summary,
        "assessment": "",
        "categories": categories,
        "source":     "scraped_html_parsed",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Helper: get ClawHub web URL for a skill
# ─────────────────────────────────────────────────────────────────────────────

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