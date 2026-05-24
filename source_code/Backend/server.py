"""
server.py
=========
Full-stack web server for the Skill Security Evaluator.

  python server.py                          # default: http://localhost:8000
  python server.py --port 9000
  python server.py --skills-dir my_skills/
  python server.py --reports-dir my_reports/
  python server.py --api anthropic          # LLM backend for new evaluations
  python server.py --model Qwen/Qwen2.5-14B-Instruct --api hf_local --device cuda

Pages
─────
  GET /                → Leaderboard (sortable table, filter by model/risk)
  GET /skill/{skill_slug}/{model_slug}  → Full detail page for one evaluation

API
───
  GET  /api/leaderboard              → JSON list of all evaluations
  GET  /api/report/{skill}/{model}   → JSON full report
  DELETE /api/report/{skill}/{model} → Delete a report
  GET  /api/models                   → list of evaluated models
  GET  /api/skill-files              → list of .md files in skills_dir
  POST /api/evaluate                 → queue a skill file for evaluation
  GET  /api/jobs                     → list of pending/running/done jobs
  GET  /api/jobs/{job_id}            → single job status
"""

import argparse
import asyncio
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from fastapi import FastAPI, BackgroundTasks, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
except ImportError:
    print("Install: pip install fastapi uvicorn python-multipart")
    sys.exit(1)

PROJECT_DIR = Path(__file__).resolve().parent          # source_code/Backend
REPO_ROOT   = PROJECT_DIR.parent.parent                # skillvetbench_github
sys.path.insert(0, str(REPO_ROOT.parent))              # repo parent — for skillvetbench_github.* imports
sys.path.insert(0, str(PROJECT_DIR.parent / "clawhub")) # source_code/clawhub — for clawhub_fetch imports

from skillvetbench_github.source_code.utils.storage import ReportStorage, _slug

logger = logging.getLogger("SkillEvalServer")


def _setup_logging(log_file: str = "logs/server.log") -> None:
    """Write logs to both terminal (INFO+) and a rotating file (DEBUG+)."""
    from logging.handlers import RotatingFileHandler
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    fmt = "%(asctime)s  %(levelname)-7s  %(name)s — %(message)s"
    formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)

    fh = RotatingFileHandler(log_path, maxBytes=10*1024*1024,
                             backupCount=5, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    root.addHandler(console)
    root.addHandler(fh)

    for name in ("httpx", "anthropic", "openai", "huggingface_hub",
                 "uvicorn.access", "transformers"):
        logging.getLogger(name).setLevel(logging.WARNING)

    logger.info(f"Logging to file: {log_path.resolve()}")

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    # ── Startup ──────────────────────────────────────────────────────
    global _hf_local_sem, _api_sem
    _hf_local_sem = asyncio.Semaphore(1)   # hf_local: strictly one job at a time
    _api_sem      = asyncio.Semaphore(3)   # API backends: up to 3 concurrent jobs
    logger.info("━" * 60)
    logger.info("  AgentSkillBench Skill Security Evaluator — READY")
    logger.info("━" * 60)
    logger.info(f"  Templates  : {_TEMPLATES_FILE}")
    logger.info(f"  Reports    : {storage.root if storage else '(not initialised)'}")
    logger.info(f"  Skills dir : {skills_dir}")
    logger.info(f"  LLM backend: {llm_config.get('api_type','?')}  model={llm_config.get('model') or '(default)'}")
    logger.info(f"  Leaderboard: {len(_LEADERBOARD_HTML):,} chars")
    logger.info(f"  Detail page: {len(_DETAIL_HTML):,} chars")
    logger.info("━" * 60)
    logger.info("  Open in browser: http://localhost:8000")
    logger.info("━" * 60)
    yield
    # ── Shutdown ─────────────────────────────────────────────────────
    logger.info("Server stopped.")

app          = FastAPI(title="Skill Security Evaluator", version="2.0", lifespan=lifespan)
storage: ReportStorage = None    # type: ignore
skills_dir:  Path      = None    # type: ignore
llm_config:  dict      = {}
jobs:        dict      = {}

# ── LLM instance cache (keyed by api_type + model) ───────────────────────
# For hf_local the transformers pipeline is expensive to load (~minutes).
# We cache the LLMClient after first creation so the model is loaded only
# once and reused across all subsequent evaluate-all jobs.
_llm_cache:  dict      = {}

# ── Concurrency control ───────────────────────────────────────────────────
# hf_local: the transformers pipeline is NOT thread-safe under concurrent use.
# Two jobs running simultaneously would share the same pipeline object → race
# condition, corrupted outputs, or GPU OOM crash.
# Semaphore(1) forces jobs to run one-at-a-time for hf_local.
#
# API backends (Anthropic, OpenAI, hf_api): safe to run in parallel.
# Semaphore(3) allows 3 concurrent jobs — enough to keep the network busy
# without hammering rate limits.
_hf_local_sem: asyncio.Semaphore = None   # type: ignore  (set in lifespan)
_api_sem:      asyncio.Semaphore = None   # type: ignore  (set in lifespan)


def _get_semaphore(api_type: str) -> asyncio.Semaphore:
    """Return the correct semaphore for the given backend."""
    if api_type == "hf_local":
        return _hf_local_sem
    return _api_sem


def _get_or_create_llm(api_type: str, model: str, api_key: str) -> "LLMClient":
    """
    Return a cached LLMClient if one already exists for this (api_type, model).
    Creates and caches a new one on first call.

    For hf_local this means the model weights are loaded into GPU memory exactly
    once — not once per skill evaluation job.
    """
    from skillvetbench_github.source_code.utils.llm_client import LLMClient
    cache_key = f"{api_type}::{model or 'default'}"
    if cache_key not in _llm_cache:
        logger.info(f"Creating new LLMClient for {cache_key} ...")
        _llm_cache[cache_key] = LLMClient(
            api_type = api_type or "anthropic",
            api_key  = api_key,
            model    = model or None,
            **{k: v for k, v in llm_config.items()
               if k in ("base_url", "load_in_4bit", "load_in_8bit",
                        "device", "hf_cache_dir", "max_tokens")},
        )
        logger.info(f"LLMClient ready: {cache_key}")
    else:
        logger.debug(f"Reusing cached LLMClient: {cache_key}")
    return _llm_cache[cache_key]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Request logging middleware
# ─────────────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request, call_next):
    import time
    start = time.monotonic()
    try:
        response = await call_next(request)
        ms = (time.monotonic() - start) * 1000
        level = logging.WARNING if response.status_code >= 400 else logging.DEBUG
        logger.log(level, f"{request.method} {request.url.path}  →  {response.status_code}  ({ms:.0f}ms)")
        return response
    except Exception as exc:
        ms = (time.monotonic() - start) * 1000
        logger.error(f"{request.method} {request.url.path}  →  EXCEPTION ({ms:.0f}ms): {exc}", exc_info=True)
        raise


# ─────────────────────────────────────────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/ping")
def ping():
    """Quick health check — open http://localhost:8000/ping in browser to test."""
    logger.info("PING received — server is alive")
    return {"status": "ok", "message": "AgentSkillBench server is running"}


@app.get("/api/leaderboard")
def api_leaderboard(model: str = "", risk: str = "", sort: str = "cvss_base_score"):
    logger.debug("api_leaderboard called")
    rows = storage.get_leaderboard()
    if model:
        rows = [r for r in rows if model.lower() in r["model_name"].lower()]
    if risk:
        rows = [r for r in rows if r["overall_risk"] == risk.upper()]
    for i, r in enumerate(rows, 1):
        r["rank"] = i
    return rows


@app.get("/api/report/{skill_slug}/{model_slug}")
def api_report(skill_slug: str, model_slug: str):
    report = storage.get_report(skill_slug, model_slug)
    if not report:
        raise HTTPException(404, f"Report not found: {skill_slug} / {model_slug}")
    return report


@app.delete("/api/report/{skill_slug}/{model_slug}")
def api_delete_report(skill_slug: str, model_slug: str):
    deleted = storage.delete(skill_slug, model_slug)
    if not deleted:
        raise HTTPException(404, f"Report not found: {skill_slug} / {model_slug}")
    return {"deleted": True, "skill_slug": skill_slug, "model_slug": model_slug}


@app.get("/api/models")
def api_models():
    return storage.list_models()


@app.get("/api/leaderboard/csv")
def api_leaderboard_csv():
    """Download the full leaderboard as a CSV file."""
    import csv, io
    rows = storage.get_leaderboard()

    # Use the exact keys present in the index entry (from storage.save)
    columns = [
        "rank", "skill_name", "filename", "skill_slug",
        "model_name", "model_slug",
        "overall_risk", "is_vulnerable", "vulnerability_count",
        "cvss_base_score", "cvss_severity", "cvss_vector",
        "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
        "sars_score", "sars_severity", "sars_ifr", "sars_dg", "sars_ai", "sars_br", "sars_ca",
        "top_finding_category", "evaluated_at", "error",
    ]

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for i, row in enumerate(rows, 1):
        row["rank"] = i
        writer.writerow(row)

    from fastapi.responses import Response
    csv_bytes = buf.getvalue().encode("utf-8")
    logger.info(f"CSV download: {len(rows)} rows, {len(csv_bytes):,} bytes")
    return Response(
        content    = csv_bytes,
        media_type = "text/csv",
        headers    = {"Content-Disposition":
                      "attachment; filename=agentskillbench_leaderboard.csv"},
    )


@app.post("/api/evaluate-all")
async def api_evaluate_all(body: dict, background_tasks: BackgroundTasks):
    """
    Queue the top-N skills (sorted by stars from clawhub_skills_meta.json)
    for evaluation with the selected model and backend.
    N is provided by the caller via the 'top_n' field (default: 100).
    Skips any skill already evaluated with the same model.
    The hf_local model is loaded once and reused across all jobs (via _llm_cache).
    """
    from clawhub_fetch import list_slugs_from_meta

    model    = body.get("model",    llm_config.get("model", ""))
    api_type = body.get("api_type", llm_config.get("api_type", "anthropic"))
    api_key  = (body.get("api_key") or body.get("hf_token")
                or llm_config.get("api_key", ""))
    top_n    = max(1, int(body.get("top_n", 100)))

    skills = list_slugs_from_meta(top_n=top_n)
    if not skills:
        raise HTTPException(400, "No skills found in clawhub_skills_meta.json")

    effective_model = model or _default_model(api_type)
    batch_id    = str(uuid.uuid4())[:8]
    queued_jobs = []
    skipped     = []

    for skill in skills:
        slug     = skill["slug"]
        filename = skill["filename"]

        if storage.already_evaluated(filename, effective_model):
            skipped.append(slug)
            continue

        job_id = str(uuid.uuid4())[:8]
        jobs[job_id] = {
            "id":         job_id,
            "batch_id":   batch_id,
            "filename":   filename,
            "slug":       slug,
            "model":      model,
            "api_type":   api_type,
            "status":     "queued",
            "queued_at":  datetime.now().isoformat(),
            "started_at": None,
            "done_at":    None,
            "error":      None,
            "result_key": None,
            "source":     "clawhub_download",
        }
        background_tasks.add_task(
            _run_evaluation, job_id, None, model, api_type, api_key, filename, slug
        )
        queued_jobs.append(job_id)

    logger.info(
        f"[Batch {batch_id}] top_n={top_n}  queued={len(queued_jobs)}  "
        f"skipped={len(skipped)} (already-evaluated)"
    )
    return {
        "batch_id":     batch_id,
        "top_n":        top_n,
        "queued":       len(queued_jobs),
        "skipped":      len(skipped),
        "job_ids":      queued_jobs,
        "total_skills": len(skills),
    }


@app.post("/api/hf-validate")
async def api_hf_validate(body: dict):
    """Validate a HuggingFace token + model before running evaluation."""
    import asyncio
    api_key = (body.get("api_key") or body.get("hf_token")
               or llm_config.get("api_key") or os.getenv("HF_TOKEN", ""))
    model   = body.get("model") or llm_config.get("model") or ""

    logger.info(f"HF validate: model={model!r} token={'set' if api_key else 'MISSING'}")

    if not api_key:
        return {"ok": False, "status": "no_token",
                "detail": "No HuggingFace token provided. Add it in the API Key field.",
                "model": model}
    if not api_key.startswith("hf_"):
        return {"ok": False, "status": "bad_token_format",
                "detail": f"Token should start with 'hf_'. Got: '{api_key[:6]}...'",
                "model": model}
    if not model:
        return {"ok": False, "status": "no_model",
                "detail": "No model selected.", "model": model}

    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: _hf_test_call(api_key, model)),
            timeout=45,
        )
        return result
    except asyncio.TimeoutError:
        return {"ok": False, "status": "timeout",
                "detail": "No response in 45 s — model may be loading. Retry in ~60 s.",
                "model": model}
    except Exception as exc:
        return {"ok": False, "status": "error", "detail": str(exc), "model": model}


def _hf_test_call(api_key: str, model: str) -> dict:
    try:
        from huggingface_hub import InferenceClient
    except ImportError:
        return {"ok": False, "status": "missing_package",
                "detail": "Run: pip install huggingface_hub>=0.24", "model": model}

    client = InferenceClient(token=api_key)
    try:
        resp  = client.chat_completion(
            model=model,
            messages=[{"role": "user", "content": "Reply with one word: OK"}],
            max_tokens=8, temperature=0.01,
        )
        reply = resp.choices[0].message.content.strip()
        logger.info(f"  HF test OK: {reply!r}")
        return {"ok": True, "status": "ok",
                "detail": f"Token and model working. Response: '{reply}'", "model": model}
    except Exception as e:
        err = str(e)
        logger.error(f"  HF test failed: {err}")
        if "401" in err or "authorization" in err.lower():
            return {"ok": False, "status": "invalid_token",
                    "detail": "Token rejected (401). Check huggingface.co/settings/tokens.",
                    "model": model}
        if "403" in err or "forbidden" in err.lower():
            return {"ok": False, "status": "no_access",
                    "detail": f"Access denied (403) for '{model}'. Accept license or upgrade to PRO.",
                    "model": model}
        if "404" in err or "not found" in err.lower():
            return {"ok": False, "status": "model_not_found",
                    "detail": f"Model '{model}' not found. Check the model ID.", "model": model}
        if "429" in err or "rate" in err.lower():
            return {"ok": False, "status": "rate_limited",
                    "detail": "Rate limited. Upgrade to HF PRO or wait.", "model": model}
        if "503" in err or "loading" in err.lower():
            return {"ok": False, "status": "model_loading",
                    "detail": "Model loading (cold start ~30-60s). Retry shortly.", "model": model}
        return {"ok": False, "status": "api_error", "detail": f"HF error: {err}", "model": model}


@app.get("/api/skill-files")
def api_skill_files():
    from clawhub_fetch import list_slugs_from_meta

    logger.info("skills_dir: " + (str(skills_dir) if skills_dir else "None"))

    # ── Case 1: skills directory exists and has .md files → use directory ─
    if skills_dir != "clawhub" and skills_dir.exists():
        files = sorted(skills_dir.glob("**/*.md"))
        if files:
            result = []
            for f in files:
                models_done = [
                    m for m in storage.list_models()
                    if storage.already_evaluated(f.name, m)
                ]
                result.append({
                    "filename":    f.name,
                    "path":        str(f.relative_to(skills_dir)),
                    "size_kb":     round(f.stat().st_size / 1024, 1),
                    "models_done": models_done,
                    "source":      "local",
                })
            return result

    # ── Case 2: no skills directory (or empty) → load from clawhub_skills_meta.json ─
    logger.info("skills_dir empty or missing — loading skill list from clawhub_skills_meta.json")
    slugs = list_slugs_from_meta()
    for entry in slugs:
        entry["models_done"] = [
            m for m in storage.list_models()
            if storage.already_evaluated(entry["filename"], m)
        ]
        entry["source"] = "clawhub_meta"
    return slugs[:20]


@app.post("/api/evaluate")
async def api_evaluate(body: dict, background_tasks: BackgroundTasks):
    filename = body.get("filename", "")
    slug     = body.get("slug", "")          # passed when source is clawhub_meta
    model    = body.get("model", llm_config.get("model", ""))
    api_type = body.get("api_type", llm_config.get("api_type", "anthropic"))
    api_key  = (body.get("api_key") or body.get("hf_token")
                or llm_config.get("api_key", ""))

    if not filename and not slug:
        raise HTTPException(400, "filename or slug is required")

    # Normalise: if slug given without filename, derive filename
    if slug and not filename:
        filename = f"{slug}.md"
    if not slug:
        slug = Path(filename).stem.replace("_SKILL", "")

    # ── Try to find the file on disk first ────────────────────────────────
    candidate = None
    if skills_dir and skills_dir.exists():
        candidate = skills_dir / filename
        if not candidate.exists():
            matches = list(skills_dir.glob(f"**/{filename}"))
            candidate = matches[0] if matches else None

    if candidate and candidate.exists():
        # File found on disk — evaluate from disk (original path)
        source = "local"
    else:
        # File not on disk — download from ClawHub zip API
        source = "clawhub_download"
        logger.info(f"File '{filename}' not on disk — will download from ClawHub (slug={slug})")
        candidate = None  # signals _run_evaluation to use zip download

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "id":         job_id,
        "filename":   filename,
        "slug":       slug,
        "model":      model,
        "api_type":   api_type,
        "status":     "queued",
        "queued_at":  datetime.now().isoformat(),
        "started_at": None,
        "done_at":    None,
        "error":      None,
        "result_key": None,
        "source":     source,
    }
    background_tasks.add_task(
        _run_evaluation, job_id, candidate, model, api_type, api_key, filename, slug
    )
    return {"job_id": job_id, "status": "queued", "source": source}


@app.get("/api/jobs")
def api_jobs():
    return list(jobs.values())


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str):
    if job_id not in jobs:
        raise HTTPException(404, f"Job not found: {job_id}")
    return jobs[job_id]


@app.get("/api/metrics")
def api_metrics():
    """Serve metrics.json for the metric popup definitions."""
    import json
    metrics_path = PROJECT_DIR / "metrics.json"
    if not metrics_path.exists():
        raise HTTPException(404, "metrics.json not found")
    with open(metrics_path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/clawhub-official/{slug:path}")
async def api_clawhub_official(slug: str):
    """
    Fetch the official ClawHub evaluation report for a skill slug or filename.
    Uses clawhub_fetch.py which looks up skill_id from clawhub_skills_meta.json
    and tries multiple API endpoints + HTML scraping as fallback.
    """
    import asyncio
    from clawhub_fetch import fetch_official_evaluation, get_skill_stats

    logger.info(f"ClawHub official evaluation requested: {slug}")

    loop = asyncio.get_event_loop()
    try:
        # Run in executor since clawhub_fetch uses synchronous requests
        result = await loop.run_in_executor(
            None, lambda: fetch_official_evaluation(slug)
        )
    except Exception as exc:
        logger.error(f"ClawHub fetch error for '{slug}': {exc}", exc_info=True)
        raise HTTPException(500, f"Error fetching ClawHub evaluation: {exc}")

    if not result:
        # Return skill stats from metadata even if no evaluation available
        stats = await loop.run_in_executor(None, lambda: get_skill_stats(slug))
        raise HTTPException(
            404,
            f"No official ClawHub evaluation found for '{slug}'. "
            + (f"Skill URL: https://clawhub.ai/{stats['owner_handle']}/{stats['slug']}" if stats else
               "Check that clawhub_skills_meta.json contains this slug.")
        )

    # Also attach skill stats (stars, downloads, etc.) if available
    stats = await loop.run_in_executor(None, lambda: get_skill_stats(slug))
    if stats:
        result["skill_stats"] = stats

    logger.info(f"ClawHub official: {slug} → verdict={result.get('verdict')} source={result.get('source')}")
    return result


@app.get("/api/sars-metrics")
def api_sars_metrics():
    """Serve SARS dimension definitions for the popup feature."""
    from skillvetbench_github.source_code.utils.sars import SARS_DIMENSIONS
    return {
        k: {
            "name":        v["name"],
            "short":       v["short"],
            "description": v["description"],
            "weight":      v["weight"],
            "levels":      {str(lk): lv for lk, lv in v["levels"].items()},
        }
        for k, v in SARS_DIMENSIONS.items()
    }


# ─────────────────────────────────────────────────────────────────────────────
# Background evaluation task
# ─────────────────────────────────────────────────────────────────────────────

async def _run_evaluation(
    job_id: str,
    path: Optional[Path],
    model: str,
    api_type: str,
    api_key: str,
    filename: str = "",
    slug: str = "",
):
    job = jobs[job_id]
    sem = _get_semaphore(api_type)

    # Acquire slot before starting.
    # hf_local: semaphore(1) — strictly sequential, one job at a time.
    #           Guarantees the GPU pipeline is never accessed concurrently.
    # API backends: semaphore(3) — up to 3 parallel jobs.
    display_name = (path.name if path else filename) or slug
    if api_type == "hf_local":
        logger.info(f"[Job {job_id}] ⏳ Queued (hf_local slot): {display_name}")

    async with sem:
        job["status"]     = "running"
        job["started_at"] = datetime.now().isoformat()

        logger.info(f"[Job {job_id}] ▶ Start  : {display_name}")
        logger.info(f"[Job {job_id}]   Source : {'disk' if path else 'ClawHub download ('+slug+')'}")
        logger.info(f"[Job {job_id}]   Backend: {api_type}  model={model or '(default)'}")

        try:
            loop = asyncio.get_event_loop()

            if path and path.exists():
                # ── Evaluate from disk ────────────────────────────────────
                report = await loop.run_in_executor(
                    None, lambda: _do_evaluate(path, model, api_type, api_key)
                )
                report_filename = path.name
            else:
                # ── Download zip from ClawHub, evaluate in memory ─────────
                logger.info(f"[Job {job_id}]   Downloading zip for slug='{slug}'")
                from clawhub_fetch import fetch_skill_from_zip
                content = await loop.run_in_executor(
                    None, lambda: fetch_skill_from_zip(slug)
                )
                if not content:
                    raise ValueError(
                        f"Could not download SKILL.md for slug '{slug}'. "
                        "Check the slug spelling and your internet connection."
                    )
                logger.info(f"[Job {job_id}]   SKILL.md: {len(content):,} chars")
                report = await loop.run_in_executor(
                    None, lambda: _do_evaluate_content(
                        content, filename or f"{slug}.md", model, api_type, api_key
                    )
                )
                report_filename = filename or f"{slug}.md"

            effective_model = model or _default_model(api_type)
            save_path = storage.save(report, model_name=effective_model)
            job["status"]     = "done"
            job["done_at"]    = datetime.now().isoformat()
            job["result_key"] = f"{_slug(report_filename)}::{_slug(effective_model)}"
            logger.info(f"[Job {job_id}] ✅ Done  : {save_path.name}")

        except Exception as exc:
            job["status"]  = "error"
            job["error"]   = str(exc)
            job["done_at"] = datetime.now().isoformat()
            logger.error(f"[Job {job_id}] ❌ Error : {exc}", exc_info=True)


def _do_evaluate_content(content: str, filename: str, model: str, api_type: str, api_key: str):
    """Evaluate skill content passed as a string (no file on disk needed)."""
    from skillvetbench_github.source_code.utils.evaluator import SkillEvaluator

    ENV_MAP = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "hf_api":    "HF_TOKEN",
        "hf_local":  "HF_TOKEN",
        "ollama":    "",
    }
    env_var = ENV_MAP.get(api_type or "anthropic", "")
    key = (
        api_key
        or (os.getenv(env_var, "") if env_var else "")
    )
    if not key and api_type in ("anthropic", "openai"):
        raise ValueError(
            f"No API key for backend '{api_type}'. "
            f"Set the {env_var} environment variable or enter it in the API Key field."
        )
    if not key and api_type in ("hf_api", "hf_local"):
        raise ValueError(
            "No HuggingFace token found. "
            "Set HF_TOKEN=hf_... in your environment or enter it in the API Key field."
        )
    logger.info(
        f"  Backend={api_type}  model={model or '(default)'}  "
        f"key={'set ('+api_key[:8]+'...)' if api_key else 'from env'}"
    )
    llm = _get_or_create_llm(api_type or "anthropic", model or "", key)
    ev  = SkillEvaluator(llm)
    return ev.evaluate_content(content, filename)


def _do_evaluate(path: Path, model: str, api_type: str, api_key: str):
    from skillvetbench_github.source_code.utils.evaluator import SkillEvaluator

    ENV_MAP = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "hf_api":    "HF_TOKEN",
        "hf_local":  "HF_TOKEN",
        "ollama":    "",
    }
    env_var = ENV_MAP.get(api_type or "anthropic", "")
    key = (
        api_key
        or (os.getenv(env_var, "") if env_var else "")
    )
    if not key and api_type in ("anthropic", "openai"):
        raise ValueError(
            f"No API key for backend '{api_type}'. "
            f"Set {env_var} or pass --key YOUR_KEY when starting the server."
        )
    if not key and api_type in ("hf_api", "hf_local"):
        raise ValueError(
            "No HuggingFace token. "
            "Export HF_TOKEN=hf_... or pass --key hf_... when starting the server."
        )
    llm = _get_or_create_llm(api_type or "anthropic", model or "", key)
    ev  = SkillEvaluator(llm)
    return ev.evaluate_file(path)


def _default_model(api_type: str) -> str:
    from skillvetbench_github.source_code.utils.llm_client import LLMClient
    return LLMClient.DEFAULTS.get(api_type, api_type)



# ─────────────────────────────────────────────────────────────────────────────
# Load HTML templates from templates.html
# ─────────────────────────────────────────────────────────────────────────────

_TEMPLATES_FILE = REPO_ROOT / "source_code" / "UI" / "templates.html"
_SEPARATOR      = "<!-- ==================== DETAIL_PAGE ==================== -->"

def _load_templates():
    logger.debug(f"Loading templates from: {_TEMPLATES_FILE}")
    if not _TEMPLATES_FILE.exists():
        raise FileNotFoundError(
            f"templates.html not found at {_TEMPLATES_FILE}\n"
            "Make sure templates.html is in the same directory as server.py"
        )
    content = _TEMPLATES_FILE.read_text(encoding="utf-8")
    parts   = content.split(_SEPARATOR, 1)
    if len(parts) != 2:
        raise ValueError("templates.html is missing the DETAIL_PAGE separator comment")
    lb, det = parts[0].strip(), parts[1].strip()
    logger.debug(f"Templates loaded — leaderboard: {len(lb):,} chars, detail: {len(det):,} chars")
    return lb, det

_LEADERBOARD_HTML, _DETAIL_HTML = _load_templates()


# ─────────────────────────────────────────────────────────────────────────────
# HTML page routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def page_leaderboard():
    logger.info("📄 Serving leaderboard page (GET /)")
    return HTMLResponse(_LEADERBOARD_HTML)


@app.get("/skill/{skill_slug}/{model_slug}", response_class=HTMLResponse)
def page_detail(skill_slug: str, model_slug: str):
    logger.info(f"📄 Serving detail page: {skill_slug} / {model_slug}")
    return HTMLResponse(_DETAIL_HTML)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    global storage, skills_dir, llm_config

    parser = argparse.ArgumentParser(description="Skill Security Evaluator — Web Server")
    parser.add_argument("--host",        default="0.0.0.0")
    parser.add_argument("--port",  "-p", default=8000, type=int)
    parser.add_argument("--reports-dir", default="reports",  metavar="DIR")
    parser.add_argument("--skills-dir",  default="clawhub",  metavar="DIR")
    parser.add_argument("--api",         default="hf_local",
                        choices=["anthropic","openai","hf_local","hf_api","ollama"])
    parser.add_argument("--model",  default=None)
    parser.add_argument("--key",    default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--quantize",   default="4bit", choices=["4bit","8bit"])
    parser.add_argument("--device",     default="cuda", choices=["cuda","mps","cpu"])
    parser.add_argument("--max-tokens", default=6000, type=int,
                        help="Max new tokens for LLM output (default: 6000). "
                             "The CVSS+SARS system prompt alone is ~3,636 tokens, "
                             "so 4096 is too small for hf_local models on medium skills. "
                             "Use 6000 for 8B models, 4096 is fine for API backends.")
    parser.add_argument("--log-file",   default="logs/server.log", metavar="FILE",
                        help="Log file path (default: logs/server.log).")
    args = parser.parse_args()

    _setup_logging(args.log_file)

    storage    = ReportStorage(args.reports_dir)
    skills_dir = Path(args.skills_dir)
    llm_config = {
        "api_type":     args.api,
        "model":        args.model,
        "api_key":      args.key or "",
        "base_url":     args.base_url,
        "load_in_4bit": args.quantize == "4bit",
        "load_in_8bit": args.quantize == "8bit",
        "device":       args.device,
        "max_tokens":   args.max_tokens,
    }

    logger.info(f"Skills dir  : {skills_dir}")
    logger.info(f"Reports dir : {args.reports_dir}")
    logger.info(f"LLM backend : {args.api}  model={args.model or '(default)'}  max_tokens={args.max_tokens}")
    logger.info(f"Web server  : http://localhost:{args.port}")
    logger.info(f"Open in browser → http://localhost:{args.port}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()