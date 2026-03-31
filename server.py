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

PROJECT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_DIR))

from storage import ReportStorage, _slug

logging.basicConfig(
    format  = "%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt = "%H:%M:%S",
    level   = logging.INFO,
)
logger = logging.getLogger("SkillEvalServer")

app          = FastAPI(title="Skill Security Evaluator", version="2.0")
storage: ReportStorage = None    # type: ignore
skills_dir:  Path      = None    # type: ignore
llm_config:  dict      = {}
jobs:        dict      = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/leaderboard")
def api_leaderboard(model: str = "", risk: str = "", sort: str = "cvss_base_score"):
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


@app.get("/api/skill-files")
def api_skill_files():
    if not skills_dir or not skills_dir.exists():
        return []
    files = sorted(skills_dir.glob("**/*.md"))
    result = []
    for f in files:
        models_done = []
        for m in storage.list_models():
            if storage.already_evaluated(f.name, m):
                models_done.append(m)
        result.append({
            "filename":    f.name,
            "path":        str(f.relative_to(skills_dir)),
            "size_kb":     round(f.stat().st_size / 1024, 1),
            "models_done": models_done,
        })
    return result


@app.post("/api/evaluate")
async def api_evaluate(body: dict, background_tasks: BackgroundTasks):
    filename = body.get("filename", "")
    model    = body.get("model", llm_config.get("model", ""))
    api_type = body.get("api_type", llm_config.get("api_type", "anthropic"))
    api_key  = (body.get("api_key") or body.get("hf_token")
                or llm_config.get("api_key", ""))

    if not filename:
        raise HTTPException(400, "filename is required")

    candidate = skills_dir / filename if skills_dir else Path(filename)
    if not candidate.exists():
        if skills_dir:
            matches = list(skills_dir.glob(f"**/{filename}"))
            if matches:
                candidate = matches[0]
            else:
                raise HTTPException(404, f"Skill file not found: {filename}")
        else:
            raise HTTPException(404, f"Skill file not found: {filename}")

    job_id = str(uuid.uuid4())[:8]
    jobs[job_id] = {
        "id":         job_id,
        "filename":   filename,
        "model":      model,
        "api_type":   api_type,
        "status":     "queued",
        "queued_at":  datetime.now().isoformat(),
        "started_at": None,
        "done_at":    None,
        "error":      None,
        "result_key": None,
    }
    background_tasks.add_task(_run_evaluation, job_id, candidate, model, api_type, api_key)
    return {"job_id": job_id, "status": "queued"}


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


# ─────────────────────────────────────────────────────────────────────────────
# Background evaluation task
# ─────────────────────────────────────────────────────────────────────────────

async def _run_evaluation(job_id: str, path: Path, model: str, api_type: str, api_key: str):
    job = jobs[job_id]
    job["status"]     = "running"
    job["started_at"] = datetime.now().isoformat()
    logger.info(f"[Job {job_id}] Evaluating: {path.name} with {model or api_type}")
    try:
        loop   = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            None, lambda: _do_evaluate(path, model, api_type, api_key)
        )
        effective_model = model or _default_model(api_type)
        save_path = storage.save(report, model_name=effective_model)
        job["status"]     = "done"
        job["done_at"]    = datetime.now().isoformat()
        job["result_key"] = f"{_slug(path.name)}::{_slug(effective_model)}"
        logger.info(f"[Job {job_id}] Done → {save_path}")
    except Exception as exc:
        job["status"]  = "error"
        job["error"]   = str(exc)
        job["done_at"] = datetime.now().isoformat()
        logger.error(f"[Job {job_id}] Error: {exc}")


def _do_evaluate(path: Path, model: str, api_type: str, api_key: str):
    from llm_client import LLMClient
    from evaluator  import SkillEvaluator

    ENV_MAP = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "hf_api":    "HF_TOKEN",
        "hf_local":  "HF_TOKEN",
        "ollama":    "",
    }
    # Resolve key specifically for this backend — never cross-contaminate
    env_var = ENV_MAP.get(api_type or "anthropic", "")
    key = (
        api_key                                          # 1. passed in UI field
        or (os.getenv(env_var, "") if env_var else "")   # 2. env var for this backend
    )
    if not key and api_type in ("anthropic", "openai"):
        raise ValueError(
            f"No API key for backend '{api_type}'.\n"
            f"  Option 1: Start server with --key YOUR_KEY\n"
            f"  Option 2: Set {env_var} environment variable\n"
            f"  Option 3: Pass api_key in the evaluate request body"
        )
    if not key and api_type in ("hf_api", "hf_local"):
        raise ValueError(
            f"No HuggingFace token for backend '{api_type}'.\n"
            f"  Option 1: Start server with --key hf_...\n"
            f"  Option 2: export HF_TOKEN=hf_...\n"
            f"  Get a token at: https://huggingface.co/settings/tokens"
        )
    llm = LLMClient(
        api_type=api_type or "anthropic",
        api_key=key,
        model=model or None,
        **{k: v for k, v in llm_config.items()
           if k in ("base_url", "load_in_4bit", "load_in_8bit", "device", "hf_cache_dir")},
    )
    ev = SkillEvaluator(llm)
    return ev.evaluate_file(path)


def _default_model(api_type: str) -> str:
    from llm_client import LLMClient
    return LLMClient.DEFAULTS.get(api_type, api_type)



# ─────────────────────────────────────────────────────────────────────────────
# Load HTML templates from templates.html
# ─────────────────────────────────────────────────────────────────────────────

_TEMPLATES_FILE = PROJECT_DIR / "templates.html"
_SEPARATOR      = "<!-- ==================== DETAIL_PAGE ==================== -->"

def _load_templates():
    if not _TEMPLATES_FILE.exists():
        raise FileNotFoundError(
            f"templates.html not found at {_TEMPLATES_FILE}\n"
            "Make sure templates.html is in the same directory as server.py"
        )
    content = _TEMPLATES_FILE.read_text(encoding="utf-8")
    parts   = content.split(_SEPARATOR, 1)
    if len(parts) != 2:
        raise ValueError("templates.html is missing the DETAIL_PAGE separator comment")
    return parts[0].strip(), parts[1].strip()

_LEADERBOARD_HTML, _DETAIL_HTML = _load_templates()


# ─────────────────────────────────────────────────────────────────────────────
# HTML page routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def page_leaderboard():
    return HTMLResponse(_LEADERBOARD_HTML)


@app.get("/skill/{skill_slug}/{model_slug}", response_class=HTMLResponse)
def page_detail(skill_slug: str, model_slug: str):
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
    parser.add_argument("--skills-dir",  default="skills",   metavar="DIR")
    parser.add_argument("--api",         default="hf_api",
                        choices=["anthropic","openai","hf_local","hf_api","ollama"])
    parser.add_argument("--model",  default=None)
    parser.add_argument("--key",    default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--quantize", default=None, choices=["4bit","8bit"])
    parser.add_argument("--device",   default="cuda", choices=["cuda","mps","cpu"])
    args = parser.parse_args()

    storage    = ReportStorage(args.reports_dir)
    skills_dir = Path(args.skills_dir)
    llm_config = {
        "api_type":    args.api,
        "model":       args.model,
        "api_key":     args.key or "",   # only store if explicitly passed via --key
        "base_url":    args.base_url,
        "load_in_4bit": args.quantize == "4bit",
        "load_in_8bit": args.quantize == "8bit",
        "device":      args.device,
    }

    logger.info(f"Skills dir  : {skills_dir}")
    logger.info(f"Reports dir : {args.reports_dir}")
    logger.info(f"LLM backend : {args.api}  model={args.model or '(default)'}")
    logger.info(f"Web server  : http://{args.host}:{args.port}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()