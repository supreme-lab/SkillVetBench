"""
ClawHub — Search by Owner → Get All Slugs → Fetch All SKILL.md
==============================================================
Given an owner handle, this script:
  1. Finds all slugs belonging to that owner
     - Method A: paginate /api/v1/skills and filter by owner   (API)
     - Method B: browse github.com/openclaw/skills/<owner>/     (GitHub)
  2. For each slug found, fetches its SKILL.md
  3. Saves each SKILL.md to  <owner>/<slug>_SKILL.md

Usage:
    pip install requests
    python clawhub_fetch.py

Change TARGET_OWNER below to any ClawHub publisher handle.
"""

import os
import requests

BASE_URL     = "https://clawhub.ai/api/v1"
GITHUB_BASE  = "https://raw.githubusercontent.com/openclaw/skills/main/skills"
GITHUB_API   = "https://api.github.com/repos/openclaw/skills/contents/skills"

TARGET_OWNER = "byungkyu"   # ← Change to any owner handle you want


# ─────────────────────────────────────────────────────────────────
# METHOD A — ClawHub API: paginate all skills, filter by owner
# ─────────────────────────────────────────────────────────────────

def get_slugs_via_api(owner: str) -> list[str]:
    """
    Walk /api/v1/skills pages and collect slugs where ownerHandle == owner.

    The API has no server-side owner filter, so we filter client-side.
    We stop early once we've seen results and then stop seeing the owner
    (skills are sorted by updatedAt so they're clustered if prolific).
    """
    slugs  : list[str] = []
    cursor : str | None = None
    page                = 1

    print(f"\n[API] Searching for owner='{owner}' across all pages ...")

    while True:
        params: dict = {"limit": 50}
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
                or skill.get("owner")
                or ""
            )
            if handle.lower() == owner.lower():
                slugs.append(skill["slug"])
                print(f"  ✓ Found: {skill['slug']}")

        cursor = data.get("nextCursor")
        if not cursor:
            break
        page += 1

    print(f"  API found {len(slugs)} slug(s) for owner '{owner}'")
    return slugs


# ─────────────────────────────────────────────────────────────────
# METHOD B — GitHub archive: list the owner's folder directly
# ─────────────────────────────────────────────────────────────────

def get_slugs_via_github(owner: str) -> list[str]:
    """
    List the owner's folder in the openclaw/skills GitHub archive.

    URL:  https://api.github.com/repos/openclaw/skills/contents/skills/<owner>

    Each subfolder = one slug. This is the most reliable method because
    the archive is organized exactly as  skills/<owner>/<slug>/SKILL.md
    """
    url = f"{GITHUB_API}/{owner}"
    print(f"\n[GitHub] Listing folder: skills/{owner}/")
    print(f"  URL: {url}")

    try:
        resp = requests.get(
            url,
            headers={"Accept": "application/vnd.github+json"},
            timeout=15
        )
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


# ─────────────────────────────────────────────────────────────────
# Fetch SKILL.md — try API first, fall back to GitHub raw
# ─────────────────────────────────────────────────────────────────

def fetch_skill_md(owner: str, slug: str) -> str | None:
    """
    Fetch SKILL.md for a slug.
    Tries the ClawHub file endpoint first, then the GitHub raw URL.
    """
    # --- Try ClawHub API endpoint ---
    try:
        url  = f"{BASE_URL}/skills/{slug}/file"
        resp = requests.get(url, params={"path": "SKILL.md"}, timeout=10)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException:
        pass  # fall through to GitHub

    # --- Fall back to GitHub raw ---
    try:
        url  = f"{GITHUB_BASE}/{owner}/{slug}/SKILL.md"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        print(f"    ✗ Could not fetch SKILL.md for '{slug}': {e}")
        return None


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 60)
    print(f"  ClawHub — All Skills for owner: '{TARGET_OWNER}'")
    print("=" * 60)

    # ── Step 1: Discover all slugs for this owner ──
    # Try GitHub first (more reliable for owner-based lookup)
    slugs = get_slugs_via_github(TARGET_OWNER)

    # If GitHub returned nothing, fall back to API pagination
    if not slugs:
        print("\n  GitHub returned nothing — trying API pagination ...")
        slugs = get_slugs_via_api(TARGET_OWNER)

    if not slugs:
        print(f"\n  ✗ No skills found for owner '{TARGET_OWNER}'. "
              "Check the handle spelling.")
        exit(1)

    print(f"\n  Found {len(slugs)} skill(s): {slugs}")

    # ── Step 2: Fetch SKILL.md for every slug ──
    os.makedirs(TARGET_OWNER, exist_ok=True)   # save all files under owner/
    results: dict[str, str] = {}

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
            print(f"    ✓ {len(content):,} chars → saved to {out_path}")
            results[slug] = content
        else:
            print(f"    ✗ Skipped (fetch failed)")

    # ── Summary ──
    print(f"\n{'=' * 60}")
    print(f"  Done.  {len(results)}/{len(slugs)} SKILL.md files fetched.")
    print(f"  Files saved in: ./{TARGET_OWNER}/")
    print(f"{'=' * 60}")