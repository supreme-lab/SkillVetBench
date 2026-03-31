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
    env_var = ENV_MAP.get(api_type or "anthropic", "")
    key = (
        api_key
        or llm_config.get("api_key", "")
        or (os.getenv(env_var, "") if env_var else "")
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
# Shared CSS
# ─────────────────────────────────────────────────────────────────────────────

_CSS_VARS = """
:root{
  --bg:#f8f9fc;--surface:#ffffff;--card:#f1f5f9;--border:#e2e8f0;--border2:#cbd5e1;
  --text:#1e293b;--text2:#475569;--text3:#94a3b8;
  --accent:#2563eb;--teal:#0d9488;--purple:#7c3aed;
  --c-crit:#dc2626;--c-high:#ea580c;--c-med:#b45309;--c-low:#16a34a;--c-none:#0d9488;
  --bg-crit:#fef2f2;--bg-high:#fff7ed;--bg-med:#fffbeb;--bg-low:#f0fdf4;--bg-none:#f0fdfa;
  --r:8px;--mono:'JetBrains Mono',monospace;--sans:'Plus Jakarta Sans',sans-serif;
  --shadow:0 1px 3px rgba(0,0,0,.07),0 1px 2px rgba(0,0,0,.04);
  --shadow-md:0 4px 16px rgba(0,0,0,.08),0 2px 6px rgba(0,0,0,.04);
}
"""

_CSS_BASE = _CSS_VARS + """
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;-webkit-font-smoothing:antialiased}
.wrap{position:relative;z-index:1;margin:0 auto;padding:32px 24px 80px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;border-bottom:1px solid var(--border);padding-bottom:20px;margin-bottom:28px;flex-wrap:wrap}
.logo{display:flex;align-items:center;gap:10px}
.logo-icon{width:38px;height:38px;background:linear-gradient(135deg,var(--accent),var(--teal));border-radius:var(--r);display:grid;place-items:center;font-size:18px;flex-shrink:0}
.logo h1{font-size:17px;font-weight:800;color:var(--text);letter-spacing:-.3px}
.logo p{font-size:10px;color:var(--text3);font-family:var(--mono)}
.nav a{color:var(--text3);text-decoration:none;font-size:12px;font-family:var(--mono);padding:6px 12px;border:1px solid var(--border);border-radius:var(--r);transition:all .15s}
.nav a:hover{color:var(--accent);border-color:var(--accent)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:100px;font-size:10px;font-weight:700;font-family:var(--mono);border:1px solid;white-space:nowrap}
.badge .dot{width:5px;height:5px;border-radius:50%;background:currentColor}
.b-crit{color:var(--c-crit);border-color:var(--c-crit);background:var(--bg-crit)}
.b-high{color:var(--c-high);border-color:var(--c-high);background:var(--bg-high)}
.b-med {color:var(--c-med); border-color:var(--c-med); background:var(--bg-med)}
.b-low {color:var(--c-low); border-color:var(--c-low); background:var(--bg-low)}
.b-none{color:var(--c-none);border-color:var(--c-none);background:var(--bg-none)}
.b-info{color:var(--text3);border-color:var(--border);background:var(--card)}
.c-crit{color:var(--c-crit)}.c-high{color:var(--c-high)}.c-med{color:var(--c-med)}.c-low{color:var(--c-low)}.c-none{color:var(--c-none)}
.tag{font-family:var(--mono);font-size:10px;background:var(--card);border:1px solid var(--border);padding:2px 8px;border-radius:4px;color:var(--text2)}
.btn{padding:7px 14px;border-radius:var(--r);font-size:12px;font-weight:600;font-family:var(--mono);border:1px solid;cursor:pointer;transition:all .15s;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.btn-primary:hover{opacity:.85}
.btn-ghost{background:var(--surface);color:var(--text2);border-color:var(--border)}
.btn-ghost:hover{color:var(--text);border-color:var(--border2)}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Leaderboard page
# ─────────────────────────────────────────────────────────────────────────────

_LEADERBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Skill Security Evaluator — Leaderboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
""" + _CSS_BASE + """
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.sc{background:var(--surface);border:1.5px solid var(--border);border-radius:12px;padding:16px 20px;min-width:120px;box-shadow:var(--shadow)}
.sc-num{font-size:28px;font-weight:800;line-height:1;font-family:var(--mono)}
.sc-lbl{font-size:10px;color:var(--text3);font-family:var(--mono);text-transform:uppercase;letter-spacing:.6px;margin-top:4px}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;align-items:center}
.controls select,.controls input{background:var(--surface);border:1.5px solid var(--border);color:var(--text);border-radius:var(--r);padding:8px 12px;font-family:var(--sans);font-size:13px;font-weight:500;box-shadow:var(--shadow)}
.controls select:focus,.controls input:focus{outline:none;border-color:var(--accent)}
.controls input{flex:1;min-width:180px}
.eval-panel{background:var(--surface);border:1.5px solid var(--border);border-radius:14px;padding:20px 22px;margin-bottom:24px;box-shadow:var(--shadow)}
.eval-panel h3{font-size:14px;font-weight:700;color:var(--accent);margin-bottom:14px}
.eval-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.eval-row select,.eval-row input{background:var(--card);border:1.5px solid var(--border);color:var(--text);border-radius:var(--r);padding:8px 12px;font-size:13px;font-family:var(--sans);font-weight:500;transition:border .15s}
.eval-row select:focus,.eval-row input:focus{outline:none;border-color:var(--accent)}
.eval-row input[type=text]{flex:1;min-width:200px}
.eval-label{font-size:11px;color:var(--text2);font-family:var(--sans);font-weight:600;margin-bottom:5px}
.eval-field{display:flex;flex-direction:column}
.jobs-panel{margin-top:14px}
.job-row{display:flex;gap:10px;align-items:center;padding:8px 12px;border-radius:var(--r);background:var(--card);margin-top:6px;font-size:12px;font-family:var(--mono);border:1.5px solid var(--border)}
.job-status{padding:2px 9px;border-radius:5px;font-size:10px;font-weight:700;letter-spacing:.3px}
.js-queued{background:#e2e8f0;color:var(--text3)}
.js-running{background:#dbeafe;color:var(--accent);animation:pulse 1.5s ease infinite}
.js-done{background:var(--bg-low);color:var(--c-low)}
.js-error{background:var(--bg-crit);color:var(--c-crit)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
/* ── Leaderboard table ── */
.lb-wrap{overflow-x:auto;border:1.5px solid var(--border);border-radius:14px;box-shadow:var(--shadow)}
table{width:100%;border-collapse:collapse;min-width:960px;background:var(--surface)}
thead{background:#f1f5f9;border-bottom:1.5px solid var(--border)}
th{padding:10px 12px;text-align:left;font-size:9px;font-weight:700;color:var(--text3);font-family:var(--mono);text-transform:uppercase;letter-spacing:.6px;white-space:nowrap;cursor:pointer;user-select:none}
th:hover{color:var(--text)} th.sorted{color:var(--accent)}
th .sa{font-size:9px;margin-left:2px;opacity:.5}
/* Group header row */
.th-group{background:#e8edf5;font-size:8px;font-weight:800;color:var(--text3);font-family:var(--mono);text-transform:uppercase;letter-spacing:1px;text-align:center;padding:5px 6px;border-bottom:1px solid var(--border);white-space:nowrap}
.th-group.tg-base{color:var(--accent)}
.th-group.tg-vuln{color:var(--teal)}
.th-group.tg-subseq{color:var(--purple)}
.th-group.tg-threat{color:var(--c-high)}
.th-group.tg-supp{color:var(--c-med)}
td{padding:9px 12px;font-size:12px;border-bottom:1px solid var(--border);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8faff}
.rank-num{font-family:var(--mono);font-size:11px;color:var(--text3);font-weight:700;background:var(--card);border:1px solid var(--border);padding:2px 7px;border-radius:5px}
.skill-link{color:var(--accent);text-decoration:none;font-weight:700;font-size:12px;display:flex;align-items:center;gap:5px}
.skill-link:hover{color:#1d4ed8;text-decoration:underline}
.skill-link .arrow{font-size:9px;opacity:.4}
.model-cell{max-width:160px}
.model-name{font-family:var(--mono);font-size:10px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.score-big{font-family:var(--mono);font-weight:800;font-size:15px}
.score-bar{height:3px;background:var(--border);border-radius:2px;margin-top:3px;overflow:hidden;min-width:48px}
.score-fill{height:100%;border-radius:2px}
.mv-badge{font-family:var(--mono);font-size:9px;background:rgba(124,58,237,.1);border:1px solid rgba(124,58,237,.3);color:var(--purple);padding:2px 6px;border-radius:4px}
.supp-cell{font-family:var(--mono);font-size:10px;color:var(--text3)}
.supp-val{display:inline-block;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:700;background:var(--card);border:1px solid var(--border);color:var(--text2)}
.supp-y{background:rgba(22,163,74,.1);border-color:rgba(22,163,74,.3);color:var(--c-low)}
.supp-n{background:rgba(148,163,184,.1);border-color:var(--border2);color:var(--text3)}
.supp-red{background:var(--bg-crit);border-color:var(--c-crit);color:var(--c-crit)}
.supp-amber{background:#fffbeb;border-color:#b45309;color:#b45309}
.supp-green{background:var(--bg-low);border-color:var(--c-low);color:var(--c-low)}
.cat-cell{font-size:10px;color:var(--text2);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono)}
.cat-pill{display:inline-block;padding:3px 10px;border-radius:100px;font-size:10px;font-weight:700;font-family:var(--mono);white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}
.no-data{text-align:center;padding:56px;color:var(--text3);font-size:14px}
.del-btn{background:none;border:none;cursor:pointer;color:var(--text3);font-size:13px;padding:4px 7px;border-radius:5px;transition:all .15s;opacity:.45}
.del-btn:hover{background:var(--bg-crit);color:var(--c-crit);opacity:1}
.row-deleting{animation:rowdel .28s ease forwards}
@keyframes rowdel{to{opacity:0;transform:translateX(18px)}}
/* HF picker */
.hf-tab{padding:9px 14px;font-size:11px;font-weight:600;font-family:var(--sans);cursor:pointer;white-space:nowrap;border-bottom:2px solid transparent;color:var(--text3);transition:all .15s;flex-shrink:0}
.hf-tab:hover{color:var(--text)} .hf-tab-active{color:var(--teal);border-bottom-color:var(--teal)}
.hf-model-row{display:flex;flex-direction:column;gap:3px;padding:10px 14px;cursor:pointer;border-bottom:1px solid var(--border);transition:background .12s}
.hf-model-row:hover{background:#f0f7ff} .hf-model-row:last-child{border-bottom:none}
.hf-model-id{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text)}
.hf-model-note{font-size:11px;color:var(--text3);padding-left:2px}
.hf-size-badge{font-family:var(--mono);font-size:10px;font-weight:700;background:rgba(13,148,136,.1);border:1px solid rgba(13,148,136,.3);color:var(--teal);padding:1px 6px;border-radius:4px;flex-shrink:0}
@keyframes fadein{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
tr{animation:fadein .22s ease both}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="logo">
    <div class="logo-icon">🔐</div>
    <div><h1>Skill Security Evaluator</h1><p>AgentAIBench · UTEP SUPREME Lab</p></div>
  </div>
  <div class="nav"><a href="/">Leaderboard</a></div>
</header>

<div class="stats" id="stats"></div>

<!-- Evaluate panel -->
<div class="eval-panel">
  <h3>⚡ Evaluate a Skill</h3>
  <div class="eval-row">
    <div class="eval-field">
      <div class="eval-label">Skill File</div>
      <select id="eval-file" style="min-width:220px"><option value="">Loading…</option></select>
    </div>
    <div class="eval-field" style="position:relative">
      <div class="eval-label">Model</div>
      <div style="display:flex;gap:6px;align-items:center">
        <input id="eval-model" type="text" placeholder="Model ID or pick from list →" style="min-width:240px">
        <div id="hf-pick-wrap" style="display:none;position:relative">
          <button class="btn btn-ghost" id="hf-pick-btn" onclick="toggleHFDropdown()">🤗 Popular models ▾</button>
          <div id="hf-dropdown" style="display:none;position:absolute;top:calc(100% + 6px);right:0;z-index:100;background:var(--surface);border:1.5px solid var(--border);border-radius:12px;min-width:520px;max-height:460px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.12)">
            <div style="padding:10px 12px;border-bottom:1px solid var(--border)">
              <input id="hf-search" type="text" placeholder="Filter models…" oninput="filterHF(this.value)" style="width:100%;background:var(--card);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 10px;font-family:var(--mono);font-size:12px">
            </div>
            <div id="hf-tabs" style="display:flex;padding:0 12px;border-bottom:1px solid var(--border);overflow-x:auto;scrollbar-width:none"></div>
            <div id="hf-list" style="overflow-y:auto;max-height:340px;padding:6px 0"></div>
          </div>
        </div>
      </div>
    </div>
    <div class="eval-field">
      <div class="eval-label">Backend</div>
      <select id="eval-api" onchange="onApiChange(this.value)">
        <option value="anthropic">Anthropic</option>
        <option value="openai">OpenAI / Compatible</option>
        <option value="hf_local">HuggingFace Local</option>
        <option value="hf_api">HuggingFace API</option>
        <option value="ollama">Ollama</option>
      </select>
    </div>
    <div class="eval-field" id="key-field" style="display:none">
      <div class="eval-label" id="key-label">API Key</div>
      <input id="eval-key" type="password" placeholder="hf_... or sk-..." style="min-width:180px">
    </div>
    <button class="btn btn-primary" onclick="submitEval()">▶ Evaluate</button>
  </div>
  <div id="key-hint" style="display:none;margin-top:8px;font-size:11px;font-family:var(--mono);color:var(--text3)"></div>
  <div class="jobs-panel" id="jobs-panel"></div>
</div>

<!-- Filter controls -->
<div class="controls">
  <input id="search" type="text" placeholder="Search skill or model…" oninput="render()">
  <select id="filter-model" onchange="render()"><option value="">All models</option></select>
  <select id="filter-risk" onchange="render()">
    <option value="">All risk levels</option>
    <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>NONE</option>
  </select>
  <span id="row-count" style="font-size:11px;color:var(--text3);font-family:var(--mono);margin-left:auto"></span>
</div>

<!-- Leaderboard table -->
<div class="lb-wrap">
<table id="lb">
<thead>
  <tr>
    <th onclick="sortBy('rank')"># <span class="sa">↕</span></th>
    <th onclick="sortBy('skill_name')">Skill <span class="sa">↕</span></th>
    <th onclick="sortBy('model_name')">Model <span class="sa">↕</span></th>
    <th onclick="sortBy('overall_risk')">Risk <span class="sa">↕</span></th>
    <th onclick="sortBy('cvss_base_score')" title="CVSS v4.0 Base Score">Score <span class="sa">↕</span></th>
    <th onclick="sortBy('cvss_severity')" title="Severity label">Severity <span class="sa">↕</span></th>
    <th onclick="sortBy('attack_vector')" title="Attack Vector (AV)">Attack Vector <span class="sa">↕</span></th>
    <th onclick="sortBy('attack_complexity')" title="Attack Complexity (AC)">Attack Complexity <span class="sa">↕</span></th>
    <th onclick="sortBy('privileges_required')" title="Privileges Required (PR)">Privileges Required <span class="sa">↕</span></th>
    <th onclick="sortBy('top_finding_category')">Attack Category <span class="sa">↕</span></th>
    <th onclick="sortBy('vulnerability_count')">Vulns <span class="sa">↕</span></th>
    <th onclick="sortBy('evaluated_at')">Evaluated <span class="sa">↕</span></th>
    <th style="width:38px"></th>
  </tr>
</thead>
<tbody id="lb-body"></tbody>
</table>
</div>
</div>

<script>
const RC={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',NONE:'none',INFO:'info',UNKNOWN:'info'};
const RW={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,NONE:1,UNKNOWN:0};
let rows=[],sortKey='cvss_base_score',sortDir=-1;

async function load(){
  const[lb,fs,ms]=await Promise.all([
    fetch('/api/leaderboard').then(r=>r.json()),
    fetch('/api/skill-files').then(r=>r.json()),
    fetch('/api/models').then(r=>r.json()),
  ]);
  rows=lb;
  buildStats(); buildModelFilter(ms);
  const sel=document.getElementById('eval-file');
  sel.innerHTML=fs.map(f=>`<option value="${f.filename}">${f.filename} (${f.size_kb}kb)</option>`).join('');
  render();
}

function buildStats(){
  const n=rows.length,nv=rows.filter(r=>r.is_vulnerable).length;
  const cnt={};rows.forEach(r=>{cnt[r.overall_risk]=(cnt[r.overall_risk]||0)+1});
  const cards=[
    {num:n,lbl:'Evaluations',color:'var(--accent)'},
    {num:nv,lbl:'Vulnerable',color:'var(--c-crit)'},
    ...[['CRITICAL','--c-crit'],['HIGH','--c-high'],['MEDIUM','--c-med'],['LOW','--c-low'],['NONE','--c-none']]
      .filter(([k])=>cnt[k]).map(([k,c])=>({num:cnt[k],lbl:k,color:`var(${c})`}))
  ];
  document.getElementById('stats').innerHTML=cards.map(c=>
    `<div class="sc"><div class="sc-num" style="color:${c.color}">${c.num}</div><div class="sc-lbl">${c.lbl}</div></div>`
  ).join('');
}

function buildModelFilter(ms){
  const sel=document.getElementById('filter-model');
  sel.innerHTML='<option value="">All models</option>'+ms.map(m=>`<option>${m}</option>`).join('');
}

function sortBy(key){
  if(sortKey===key)sortDir*=-1; else{sortKey=key;sortDir=-1;}
  render();
}

// Abbreviate long metric values for compact table cells
function abbrev(val){
  const MAP={
    'Network':'Net','Adjacent':'Adj','Local':'Loc','Physical':'Phy',
    'None':'None','Present':'Pres','Low':'Low','High':'High',
    'Passive':'Pass','Active':'Act',
    'Automatic':'Auto','User':'User','Irrecoverable':'Irrecov',
    'Diffuse':'Diff','Concentrated':'Conc',
    'Not Defined':'—','Attacked':'Atk','Proof-of-Concept':'PoC','Unreported':'Unrep',
    'Negligible':'Negl','Safety':'Safety',
    'Yes':'Yes','No':'No',
    'Clear':'Clear','Green':'Green','Amber':'Amber','Red':'Red',
  };
  return MAP[val]||val||'—';
}

// Style classes for supplemental metric values
function suppCls(metric,val){
  if(val==='Not Defined'||val==='—'||!val) return 'supp-n';
  if(metric==='AU'&&val==='Yes') return 'supp-y';
  if(metric==='U'){
    if(val==='Red')   return 'supp-red';
    if(val==='Amber') return 'supp-amber';
    if(val==='Green') return 'supp-green';
  }
  if(metric==='S'&&val==='Present') return 'supp-red';
  if(metric==='R'&&val==='Irrecoverable') return 'supp-red';
  return 'supp-n';
}

// Score → fill colour
function scoreColor(score){
  if(score>=9.0) return 'var(--c-crit)';
  if(score>=7.0) return 'var(--c-high)';
  if(score>=4.0) return 'var(--c-med)';
  if(score>0)    return 'var(--c-low)';
  return 'var(--c-none)';
}

function render(){
  const q =document.getElementById('search').value.toLowerCase();
  const fm=document.getElementById('filter-model').value;
  const fr=document.getElementById('filter-risk').value;
  let data=[...rows];
  if(q)  data=data.filter(r=>r.skill_name.toLowerCase().includes(q)||r.model_name.toLowerCase().includes(q));
  if(fm) data=data.filter(r=>r.model_name===fm);
  if(fr) data=data.filter(r=>r.overall_risk===fr);
  data.sort((a,b)=>{
    let av=a[sortKey]??'',bv=b[sortKey]??'';
    if(sortKey==='overall_risk'){av=RW[av]||0;bv=RW[bv]||0;}
    if(typeof av==='number') return sortDir*(av-bv);
    return sortDir*String(av).localeCompare(String(bv));
  });
  data.forEach((r,i)=>r._rank=i+1);
  document.getElementById('row-count').textContent=`${data.length} row${data.length!==1?'s':''}`;
  const body=document.getElementById('lb-body');
  if(!data.length){
    body.innerHTML=`<tr><td colspan="13" class="no-data">No evaluations yet. Submit a skill above to get started.</td></tr>`;
    return;
  }

  // Assign a stable colour to each unique attack category value
  const CAT_PALETTE=[
    '#2563eb','#0d9488','#7c3aed','#b45309','#dc2626',
    '#059669','#d97706','#6366f1','#db2777','#0891b2',
    '#65a30d','#9333ea','#ea580c','#0284c7','#be185d',
  ];
  const catColorMap={};
  let catIdx=0;
  function catColor(cat){
    if(!cat||cat==='—') return 'var(--text3)';
    if(!catColorMap[cat]) catColorMap[cat]=CAT_PALETTE[catIdx++%CAT_PALETTE.length];
    return catColorMap[cat];
  }
  // Pre-scan all visible rows so colours are consistent across re-renders
  data.forEach(r=>catColor(r.top_finding_category||'—'));

  body.innerHTML=data.map(r=>{
    const sc=RC[r.overall_risk]||'info';
    const scorePct=((r.cvss_base_score/10)*100).toFixed(0);
    const scoreCol=scoreColor(r.cvss_base_score);
    const dt=r.evaluated_at?new Date(r.evaluated_at).toLocaleString():'—';
    const detailUrl=`/skill/${r.skill_slug}/${r.model_slug}`;
    const cat=r.top_finding_category||'—';
    const catCol=catColor(cat);

    return `<tr>
      <td><span class="rank-num">${r._rank}</span></td>
      <td>
        <a class="skill-link" href="${detailUrl}">${esc(r.skill_name)}<span class="arrow">→</span></a>
        <div style="font-size:9px;color:var(--text3);font-family:var(--mono);margin-top:1px">${esc(r.filename)}</div>
      </td>
      <td class="model-cell"><div class="model-name" title="${esc(r.model_name)}">${esc(r.model_name)}</div></td>
      <td><span class="badge b-${sc}"><span class="dot"></span>${r.overall_risk}</span></td>
      <td>
        <div class="score-big" style="color:${scoreCol}">${r.cvss_base_score.toFixed(1)}</div>
        <div class="score-bar"><div class="score-fill" style="width:${scorePct}%;background:${scoreCol}"></div></div>
      </td>
      <td><span class="badge b-${sc}" style="font-size:9px">${r.cvss_severity||'—'}</span></td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text2)">${abbrev(r.attack_vector)||'—'}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text2)">${abbrev(r.attack_complexity)||'—'}</td>
      <td style="font-family:var(--mono);font-size:11px;color:var(--text2)">${abbrev(r.privileges_required)||'—'}</td>
      <td>
        <span class="cat-pill" title="${esc(cat)}"
          style="background:${catCol}18;border:1px solid ${catCol}55;color:${catCol}">
          ${esc(cat)}
        </span>
      </td>
      <td style="text-align:center;font-family:var(--mono);font-size:12px;font-weight:700;color:${r.vulnerability_count>0?'var(--c-crit)':'var(--c-low)'}">${r.vulnerability_count}</td>
      <td style="font-size:10px;color:var(--text3);font-family:var(--mono);white-space:nowrap">${dt}</td>
      <td><button class="del-btn" onclick="deleteRow(event,'${r.skill_slug}','${r.model_slug}')" title="Delete">✕</button></td>
    </tr>`;
  }).join('');
}

async function deleteRow(e, skillSlug, modelSlug){
  e.stopPropagation();
  const tr=e.target.closest('tr');
  if(!confirm('Delete evaluation for "'+skillSlug+'" ('+modelSlug+')?')) return;
  tr.classList.add('row-deleting');
  const r=await fetch('/api/report/'+skillSlug+'/'+modelSlug,{method:'DELETE'});
  if(r.ok){
    rows=rows.filter(x=>!(x.skill_slug===skillSlug&&x.model_slug===modelSlug));
    buildStats();
    setTimeout(()=>{tr.remove();render();},290);
  } else {
    tr.classList.remove('row-deleting');
    const d=await r.json().catch(()=>({}));
    alert('Delete failed: '+(d.detail||r.status));
  }
}

// ── HuggingFace model catalogue ───────────────────────────────────────
const HF_MODELS={
  'Llama 3.1/3.2':[
    {id:'meta-llama/Meta-Llama-3.1-8B-Instruct',  size:'8B',  note:'Best 8B instruction model'},
    {id:'meta-llama/Meta-Llama-3.1-70B-Instruct', size:'70B', note:'Top-tier open-source reasoning'},
    {id:'meta-llama/Llama-3.2-3B-Instruct',       size:'3B',  note:'Ultra-lightweight'},
    {id:'meta-llama/Llama-3.2-11B-Vision-Instruct',size:'11B',note:'Multimodal'},
  ],
  'Qwen 2.5':[
    {id:'Qwen/Qwen2.5-7B-Instruct',  size:'7B',  note:'Excellent JSON output'},
    {id:'Qwen/Qwen2.5-14B-Instruct', size:'14B', note:'Strong security reasoning'},
    {id:'Qwen/Qwen2.5-32B-Instruct', size:'32B', note:'Near-frontier quality'},
    {id:'Qwen/Qwen2.5-72B-Instruct', size:'72B', note:'Best Qwen flagship'},
    {id:'Qwen/QwQ-32B',              size:'32B', note:'Reasoning / chain-of-thought'},
  ],
  'Mistral':[
    {id:'mistralai/Mistral-7B-Instruct-v0.3',   size:'7B',   note:'Fast, reliable JSON'},
    {id:'mistralai/Mixtral-8x7B-Instruct-v0.1', size:'8×7B', note:'MoE strong reasoning'},
    {id:'mistralai/Mistral-Large-Instruct-2407', size:'123B', note:'Frontier quality'},
  ],
  'Phi / Gemma':[
    {id:'microsoft/Phi-3.5-mini-instruct', size:'3.8B',note:'CPU-friendly'},
    {id:'microsoft/phi-4',                 size:'14B', note:'Latest Phi'},
    {id:'google/gemma-2-9b-it',            size:'9B',  note:'Best Gemma 9B'},
    {id:'google/gemma-2-27b-it',           size:'27B', note:'Google flagship open'},
  ],
  'DeepSeek':[
    {id:'deepseek-ai/DeepSeek-R1-Distill-Qwen-14B', size:'14B', note:'R1 reasoning distilled'},
    {id:'deepseek-ai/DeepSeek-R1-Distill-Qwen-32B', size:'32B', note:'Best R1 distill'},
  ],
  'Other':[
    {id:'NousResearch/Hermes-3-Llama-3.1-8B', size:'8B', note:'Structured output & tool use'},
    {id:'CohereForAI/c4ai-command-r-plus',    size:'104B',note:'Retrieval-optimised'},
  ],
};
let hfActiveCat=Object.keys(HF_MODELS)[0],hfOpen=false;

function onApiChange(val){
  const wrap=document.getElementById('hf-pick-wrap');
  const keyFld=document.getElementById('key-field');
  const keyLbl=document.getElementById('key-label');
  const keyHnt=document.getElementById('key-hint');
  const modelInp=document.getElementById('eval-model');
  wrap.style.display=(val==='hf_api'||val==='hf_local')?'block':'none';
  if(val==='hf_api'||val==='hf_local'){buildHFTabs();buildHFList(hfActiveCat);}
  else closeHFDropdown();
  const META={
    anthropic:{show:true, label:'Anthropic API Key',hint:'Get key: console.anthropic.com',ph:'sk-ant-...'},
    openai:   {show:true, label:'OpenAI API Key',   hint:'Get key: platform.openai.com',  ph:'sk-...'},
    hf_api:   {show:true, label:'HuggingFace Token',hint:'🤗 huggingface.co/settings/tokens — or set HF_TOKEN env var',ph:'hf_...'},
    hf_local: {show:false,label:'',                 hint:'Gated models need HF_TOKEN env var',ph:''},
    ollama:   {show:false,label:'',                 hint:'Ollama runs locally — no key needed',ph:''},
  };
  const m=META[val]||{show:false,hint:''};
  keyFld.style.display=m.show?'flex':'none';
  keyLbl.textContent=m.label;
  document.getElementById('eval-key').placeholder=m.ph||'';
  keyHnt.style.display=m.hint?'block':'none';
  keyHnt.textContent=m.hint;
  const PH={anthropic:'claude-sonnet-4-6',openai:'gpt-4o-mini',ollama:'llama3.1:8b',hf_api:'Pick from 🤗 Popular models →',hf_local:'Pick from 🤗 Popular models →'};
  modelInp.placeholder=PH[val]||'Model ID';
  if(!['hf_api','hf_local'].includes(val)) modelInp.value='';
}

function buildHFTabs(){
  document.getElementById('hf-tabs').innerHTML=Object.keys(HF_MODELS).map(cat=>
    `<div class="hf-tab ${cat===hfActiveCat?'hf-tab-active':''}" onclick="switchHFCat('${cat}')">${cat}</div>`
  ).join('');
}
function buildHFList(cat,q=''){
  hfActiveCat=cat; buildHFTabs();
  const items=q?Object.values(HF_MODELS).flat().filter(m=>m.id.toLowerCase().includes(q.toLowerCase())||m.note.toLowerCase().includes(q.toLowerCase())):(HF_MODELS[cat]||[]);
  document.getElementById('hf-list').innerHTML=items.length
    ?items.map(m=>`<div class="hf-model-row" onclick="selectHFModel('${m.id}')"><div style="display:flex;align-items:center;gap:8px"><span class="hf-size-badge">${m.size}</span><span class="hf-model-id">${esc(m.id)}</span></div><div class="hf-model-note">${esc(m.note)}</div></div>`).join('')
    :'<div style="padding:20px;text-align:center;color:var(--text3);font-size:12px">No models match</div>';
}
function switchHFCat(cat){document.getElementById('hf-search').value='';buildHFList(cat,'');}
function filterHF(q){buildHFList(hfActiveCat,q);}
function selectHFModel(id){document.getElementById('eval-model').value=id;closeHFDropdown();}
function toggleHFDropdown(){hfOpen=!hfOpen;document.getElementById('hf-dropdown').style.display=hfOpen?'block':'none';if(hfOpen)setTimeout(()=>document.getElementById('hf-search').focus(),50);}
function closeHFDropdown(){hfOpen=false;const dd=document.getElementById('hf-dropdown');if(dd)dd.style.display='none';}
document.addEventListener('click',e=>{const w=document.getElementById('hf-pick-wrap');if(w&&!w.contains(e.target))closeHFDropdown();});

async function submitEval(){
  const file=document.getElementById('eval-file').value;
  const model=document.getElementById('eval-model').value.trim();
  const api=document.getElementById('eval-api').value;
  const key=document.getElementById('eval-key').value.trim();
  if(!file){alert('Select a skill file first.');return;}
  const body={filename:file,model,api_type:api};
  if(key) body.api_key=key;
  const r=await fetch('/api/evaluate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data=await r.json();
  if(r.ok&&data.job_id) pollJob(data.job_id);
  else alert('Error: '+(data.detail||JSON.stringify(data)));
}

function pollJob(jid){
  const panel=document.getElementById('jobs-panel');
  const id=`job-${jid}`;
  if(!document.getElementById(id)){
    panel.insertAdjacentHTML('afterbegin',`<div class="job-row" id="${id}"><span class="job-status js-queued" id="${id}-st">QUEUED</span><span id="${id}-txt" style="flex:1;color:var(--text2)">Job ${jid}</span><span id="${id}-ts" style="color:var(--text3)"></span></div>`);
  }
  const iv=setInterval(async()=>{
    const j=await fetch(`/api/jobs/${jid}`).then(r=>r.json());
    document.getElementById(`${id}-st`).className=`job-status js-${j.status}`;
    document.getElementById(`${id}-st`).textContent=j.status.toUpperCase();
    document.getElementById(`${id}-txt`).textContent=`${j.filename} → ${j.model||j.api_type}`;
    document.getElementById(`${id}-ts`).textContent=j.done_at?new Date(j.done_at).toLocaleTimeString():'';
    if(j.status==='done'){clearInterval(iv);setTimeout(()=>load(),500);}
    if(j.status==='error'){clearInterval(iv);document.getElementById(`${id}-txt`).textContent+=' ERROR: '+j.error;document.getElementById(`${id}-txt`).style.color='var(--c-crit)';}
  },1500);
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
load();
setInterval(load,15000);
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Detail page
# ─────────────────────────────────────────────────────────────────────────────

_DETAIL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Skill Detail — Security Evaluator</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
""" + _CSS_BASE + """
.back{display:inline-flex;align-items:center;gap:6px;color:var(--text3);text-decoration:none;font-size:12px;font-family:var(--mono);margin-bottom:24px;transition:color .15s}
.back:hover{color:var(--accent)}
.skill-title{font-size:28px;font-weight:800;color:var(--text);margin-bottom:6px;letter-spacing:-.4px}
.skill-meta-row{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
/* CVSS Hero */
.cvss-hero{display:flex;align-items:center;gap:24px;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:24px 28px;margin-bottom:24px;flex-wrap:wrap;box-shadow:var(--shadow)}
.cvss-num{font-size:56px;font-weight:800;line-height:1;font-family:var(--mono)}
.cvss-info h2{font-size:20px;font-weight:800;margin-bottom:4px}
.cvss-vec{font-family:var(--mono);font-size:11px;color:var(--text3);margin-top:6px;word-break:break-all}
.sbars{display:flex;gap:20px;flex-wrap:wrap}
.sbar{min-width:130px}
.sbar-lbl{font-size:10px;color:var(--text3);font-family:var(--mono);margin-bottom:5px}
.sbar-track{height:5px;background:var(--border);border-radius:3px;overflow:hidden}
.sbar-fill{height:100%;border-radius:3px}
.sbar-val{font-size:11px;font-family:var(--mono);color:var(--text2);margin-top:3px}
/* Metric sections */
.stitle{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--text3);font-family:var(--mono);margin:24px 0 10px;display:flex;align-items:center;gap:8px}
.stitle::after{content:'';flex:1;height:1px;background:var(--border)}
/* Metrics grid with group labels */
.mgroup{margin-bottom:20px}
.mgroup-lbl{font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:1px;font-family:var(--mono);margin-bottom:8px;padding:4px 10px;border-radius:5px;display:inline-block}
.mgl-base{color:var(--accent);background:rgba(37,99,235,.08)}
.mgl-vuln{color:var(--teal);background:rgba(13,148,136,.08)}
.mgl-subseq{color:var(--purple);background:rgba(124,58,237,.08)}
.mgl-threat{color:var(--c-high);background:rgba(234,88,12,.08)}
.mgl-env{color:var(--text2);background:var(--card)}
.mgl-supp{color:var(--c-med);background:rgba(180,83,9,.08)}
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
.mcell{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:10px 14px}
.mcell-k{font-size:9px;color:var(--text3);font-family:var(--mono);text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px}
.mcell-v{font-size:13px;font-weight:600;color:var(--text)}
.mcell-abbr{font-size:9px;color:var(--text3);font-family:var(--mono);margin-top:1px}
/* Summary */
.sumbox{font-size:13px;color:var(--text2);line-height:1.75;background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:16px 18px;border-left:3px solid var(--accent);margin-bottom:16px}
/* Vulnerability cards */
.vlist{display:flex;flex-direction:column;gap:10px;margin-bottom:24px}
.vcard{border:1px solid var(--border);border-radius:var(--r);overflow:hidden}
.vcard-hdr{display:flex;align-items:center;gap:10px;padding:13px 16px;cursor:pointer;transition:background .15s}
.vcard-hdr:hover{background:var(--card)}
.vid{font-family:var(--mono);font-size:10px;color:var(--text3);flex-shrink:0}
.vtitle{font-size:13px;font-weight:600;flex:1}
.stag{font-family:var(--mono);font-size:10px;font-weight:700;padding:3px 10px;border-radius:100px;flex-shrink:0;border:1px solid}
.vchev{font-size:10px;color:var(--text3);transition:transform .2s;flex-shrink:0}
.vcard.open .vchev{transform:rotate(180deg)}
.vbody{display:none;border-top:1px solid var(--border);padding:16px;background:var(--card)}
.vcard.open .vbody{display:block}
.vfield{margin-bottom:14px}
.vflbl{font-size:9px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;font-weight:700}
.vftxt{font-size:13px;color:var(--text2);line-height:1.65}
.codebox{display:block;background:#1e293b;border:1px solid #334155;border-left:3px solid var(--accent);border-radius:var(--r);padding:12px 14px;font-family:var(--mono);font-size:11px;color:#58a6ff;white-space:pre-wrap;word-break:break-all;line-height:1.6}
.steps{display:flex;flex-direction:column;gap:5px}
.step{display:flex;gap:10px}
.snum{font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:700;flex-shrink:0;min-width:18px}
.stxt{font-size:12px;color:var(--text2);line-height:1.5}
.rbox{background:var(--bg-low);border:1px solid var(--c-low);border-radius:var(--r);padding:12px 14px;font-size:13px;color:var(--c-low);line-height:1.6}
/* Patterns */
.pgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}
@media(max-width:600px){.pgrid{grid-template-columns:1fr}}
.pbox{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:14px 16px}
.pbox h4{font-size:10px;font-family:var(--mono);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px}
.pbox.dang h4{color:var(--c-crit)}.pbox.safe h4{color:var(--c-low)}
.pit{display:flex;gap:8px;align-items:flex-start;margin-bottom:5px}
.pdot{width:5px;height:5px;border-radius:50%;margin-top:5px;flex-shrink:0;background:currentColor}
.pbox.dang .pdot{color:var(--c-crit)}.pbox.safe .pdot{color:var(--c-low)}
.pit span{font-size:12px;color:var(--text2);line-height:1.5}
.prbox{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:16px 18px}
.prbox h4{font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px}
.prstep{display:flex;gap:10px;align-items:flex-start;margin-bottom:7px}
.prnum{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--teal);flex-shrink:0;min-width:20px}
.prtxt{font-size:13px;color:var(--text2);line-height:1.5}
.clean{text-align:center;padding:40px;color:var(--c-none)}
.clean-ico{font-size:48px;margin-bottom:12px}
.clean h3{font-size:18px;font-weight:700;margin-bottom:6px}
.clean p{font-size:13px;color:var(--text3)}
.loading{text-align:center;padding:60px;color:var(--text3);font-family:var(--mono)}
@keyframes fadein{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.vcard{animation:fadein .25s ease both}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="logo">
    <div class="logo-icon">🔐</div>
    <div><h1>Skill Security Evaluator</h1><p>AgentAIBench · UTEP SUPREME Lab</p></div>
  </div>
  <div class="nav"><a href="/">← Leaderboard</a></div>
</header>
<a class="back" href="/">← Back to Leaderboard</a>
<div id="content"><div class="loading">Loading evaluation…</div></div>
</div>

<script>
const RC={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',NONE:'none',INFO:'info',UNKNOWN:'info'};
const parts=location.pathname.split('/');
const skillSlug=parts[2],modelSlug=parts[3];

async function load(){
  const r=await fetch(`/api/report/${skillSlug}/${modelSlug}`);
  if(!r.ok){document.getElementById('content').innerHTML='<div class="loading">Report not found.</div>';return;}
  render(await r.json());
}

function scoreColor(s){
  if(s>=9.0) return 'var(--c-crit)';
  if(s>=7.0) return 'var(--c-high)';
  if(s>=4.0) return 'var(--c-med)';
  if(s>0)    return 'var(--c-low)';
  return 'var(--c-none)';
}

function render(d){
  const rc=RC[d.overall_risk]||'info';
  const cc=RC[(d.cvss_severity||'').toUpperCase()]||rc;
  const scoreCol=scoreColor(d.cvss_base_score||0);
  const scorePct=((d.cvss_base_score/10)*100).toFixed(0);
  const dt=d.evaluated_at?new Date(d.evaluated_at).toLocaleString():'';

  // ── CVSS v4.0 metric groups ─────────────────────────────────────────
  const G_BASE=[
    {k:'AV',lbl:'Attack Vector',        abbr:'AV', v:d.attack_vector},
    {k:'AC',lbl:'Attack Complexity',    abbr:'AC', v:d.attack_complexity},
    {k:'AT',lbl:'Attack Requirements',  abbr:'AT', v:d.attack_requirements},
    {k:'PR',lbl:'Privileges Required',  abbr:'PR', v:d.privileges_required},
    {k:'UI',lbl:'User Interaction',     abbr:'UI', v:d.user_interaction},
  ];
  const G_VULN=[
    {k:'VC',lbl:'Confidentiality Impact',abbr:'VC',v:d.confidentiality_vs},
    {k:'VI',lbl:'Integrity Impact',      abbr:'VI',v:d.integrity_vs},
    {k:'VA',lbl:'Availability Impact',   abbr:'VA',v:d.availability_vs},
  ];
  const G_SUBSEQ=[
    {k:'SC',lbl:'Confidentiality Impact',abbr:'SC',v:d.confidentiality_ss},
    {k:'SI',lbl:'Integrity Impact',      abbr:'SI',v:d.integrity_ss},
    {k:'SA',lbl:'Availability Impact',   abbr:'SA',v:d.availability_ss},
  ];
  const G_THREAT=[
    {k:'E', lbl:'Exploit Maturity',      abbr:'E', v:d.exploit_maturity},
  ];
  const G_ENV=[
    {k:'CR',lbl:'Conf. Requirement',     abbr:'CR',v:d.cr},
    {k:'IR',lbl:'Integ. Requirement',    abbr:'IR',v:d.ir},
    {k:'AR',lbl:'Avail. Requirement',    abbr:'AR',v:d.ar},
  ];
  const G_SUPP=[
    {k:'S', lbl:'Safety',                      abbr:'S',  v:d.safety},
    {k:'AU',lbl:'Automatable',                  abbr:'AU', v:d.automatable},
    {k:'U', lbl:'Provider Urgency',             abbr:'U',  v:d.provider_urgency},
    {k:'R', lbl:'Recovery',                     abbr:'R',  v:d.recovery},
    {k:'V', lbl:'Value Density',                abbr:'V',  v:d.value_density},
    {k:'RE',lbl:'Response Effort',              abbr:'RE', v:d.vulnerability_response_effort},
  ];

  function metricGroup(label,cls,items){
    const cells=items.map(m=>
      `<div class="mcell">
        <div class="mcell-abbr">${m.abbr}</div>
        <div class="mcell-k">${m.lbl}</div>
        <div class="mcell-v">${esc(m.v||'Not Defined')}</div>
      </div>`
    ).join('');
    return `<div class="mgroup">
      <div class="mgroup-lbl ${cls}">${label}</div>
      <div class="mgrid">${cells}</div>
    </div>`;
  }

  // ── Vulnerabilities ─────────────────────────────────────────────────
  let vulnsHtml='';
  if(d.vulnerabilities&&d.vulnerabilities.length){
    vulnsHtml=d.vulnerabilities.map((v,vi)=>{
      const vc=RC[v.severity]||'info';
      const steps=v.attack_scenario.split('\\n').filter(l=>l.trim()).map(l=>{
        const m=l.trim().match(/^(\\d+)\\.\\s*(.+)/);
        return m?`<div class="step"><span class="snum">${m[1]}.</span><span class="stxt">${esc(m[2])}</span></div>`
               :`<div class="step"><span class="snum">·</span><span class="stxt">${esc(l.trim())}</span></div>`;
      }).join('');
      return`<div class="vcard" id="v${vi}">
        <div class="vcard-hdr" style="border-top:2px solid var(--c-${vc})" onclick="togV(${vi})">
          <span class="vid">${esc(v.id)}</span>
          <span class="vtitle c-${vc}">${esc(v.title)}</span>
          <span class="stag c-${vc}" style="border-color:var(--c-${vc})">${v.severity}</span>
          <span class="vchev">▼</span>
        </div>
        <div class="vbody">
          <div class="vfield"><div class="vflbl c-${vc}">Category</div><div class="vftxt">${esc(v.category)}</div></div>
          <div class="vfield"><div class="vflbl" style="color:var(--c-high)">Affected Content</div><span class="codebox">${esc(v.affected_content)}</span></div>
          <div class="vfield"><div class="vflbl" style="color:var(--c-med)">Why It Is Dangerous</div><div class="vftxt">${esc(v.explanation)}</div></div>
          <div class="vfield"><div class="vflbl c-crit">Attack Scenario</div><div class="steps">${steps}</div></div>
          <div class="vfield"><div class="vflbl c-low">Remediation</div><div class="rbox">${esc(v.remediation)}</div></div>
        </div>
      </div>`;
    }).join('');
  } else {
    vulnsHtml=`<div class="clean"><div class="clean-ico">✅</div><h3>No Vulnerabilities Found</h3><p>This skill passed all 12 security checks.</p></div>`;
  }

  const dang=(d.dangerous_patterns||[]).map(p=>`<div class="pit"><span class="pdot"></span><span>${esc(p)}</span></div>`).join('')||'<div style="font-size:12px;color:var(--text3)">None detected</div>';
  const safe=(d.safe_patterns||[]).map(p=>`<div class="pit"><span class="pdot"></span><span>${esc(p)}</span></div>`).join('')||'<div style="font-size:12px;color:var(--text3)">None noted</div>';
  let prioHtml='';
  if(d.remediation_priority){
    const ps=d.remediation_priority.split('\\n').filter(l=>l.trim()).map(l=>{
      const m=l.trim().match(/^(\\d+)\\.\\s*(.+)/);
      return m?`<div class="prstep"><span class="prnum">${m[1]}.</span><span class="prtxt">${esc(m[2])}</span></div>`
             :`<div class="prstep"><span class="prnum">·</span><span class="prtxt">${esc(l.trim())}</span></div>`;
    }).join('');
    prioHtml=`<div class="prbox"><h4>🛠 Remediation Priority</h4>${ps}</div>`;
  }

  document.getElementById('content').innerHTML=`
    <div style="margin-bottom:28px">
      <div class="skill-title">${esc(d.skill_name)}</div>
      <div class="skill-meta-row">
        <span class="badge b-${rc}"><span class="dot"></span>${d.overall_risk}</span>
        <span class="tag">${esc(d.model_name||'')}</span>
        <span class="tag">${esc(d.filename||'')}</span>
        ${dt?`<span style="font-size:11px;color:var(--text3);font-family:var(--mono)">${dt}</span>`:''}
      </div>
    </div>

    <!-- CVSS v4.0 Hero -->
    <div class="cvss-hero">
      <div class="cvss-num" style="color:${scoreCol}">${(d.cvss_base_score||0).toFixed(1)}</div>
      <div class="cvss-info">
        <div style="font-size:10px;color:var(--text3);font-family:var(--mono);text-transform:uppercase;letter-spacing:.5px;margin-bottom:3px">CVSS v4.0 Base Score</div>
        <h2 style="color:${scoreCol}">${d.cvss_severity||'—'}</h2>
        <div style="font-family:var(--mono);font-size:9px;color:var(--text3);margin-top:4px">Nomenclature: ${d.cvss_nomenclature||'CVSS-B'}</div>
        <div class="cvss-vec">${esc(d.cvss_vector||'')}</div>
      </div>
      <div class="sbars">
        <div class="sbar">
          <div class="sbar-lbl">Base Score</div>
          <div class="sbar-track"><div class="sbar-fill" style="width:${scorePct}%;background:${scoreCol}"></div></div>
          <div class="sbar-val">${(d.cvss_base_score||0).toFixed(1)} / 10</div>
        </div>
        <div class="sbar">
          <div class="sbar-lbl">MacroVector Score</div>
          <div class="sbar-track"><div class="sbar-fill" style="width:${(((d.macro_vector_score||0)/10)*100).toFixed(0)}%;background:var(--purple)"></div></div>
          <div class="sbar-val">${(d.macro_vector_score||0).toFixed(1)} / 10</div>
        </div>
        <div class="sbar">
          <div class="sbar-lbl">Vuln Count</div>
          <div class="sbar-track"><div class="sbar-fill" style="width:${Math.min(100,(d.vulnerability_count||0)*10)}%;background:var(--c-high)"></div></div>
          <div class="sbar-val">${d.vulnerability_count||0} findings</div>
        </div>
      </div>
    </div>

    <!-- CVSS v4.0 Metrics — grouped -->
    <div class="stitle">CVSS v4.0 Metrics</div>
    ${metricGroup('Exploitability','mgl-base',G_BASE)}
    ${metricGroup('Vulnerable System Impact','mgl-vuln',G_VULN)}
    ${metricGroup('Subsequent System Impact','mgl-subseq',G_SUBSEQ)}
    ${metricGroup('Threat','mgl-threat',G_THREAT)}
    ${metricGroup('Environmental Requirements','mgl-env',G_ENV)}
    ${metricGroup('Supplemental (informational only)','mgl-supp',G_SUPP)}

    <!-- Summary -->
    <div class="stitle">Executive Summary</div>
    <div class="sumbox">${esc(d.executive_summary||'')}</div>
    ${d.skill_purpose_analysis?`<div class="stitle">Skill Purpose</div><div class="sumbox" style="border-left-color:var(--teal)">${esc(d.skill_purpose_analysis)}</div>`:''}

    <!-- Findings -->
    <div class="stitle">Vulnerability Findings (${d.vulnerability_count||0})</div>
    <div class="vlist">${vulnsHtml}</div>

    <!-- Patterns -->
    <div class="stitle">Security Patterns</div>
    <div class="pgrid">
      <div class="pbox dang"><h4>🚩 Dangerous Patterns</h4>${dang}</div>
      <div class="pbox safe"><h4>✅ Safe Practices</h4>${safe}</div>
    </div>
    ${prioHtml}`;
}

function togV(vi){document.getElementById('v'+vi).classList.toggle('open')}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
load();
</script>
</body>
</html>"""


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
    parser.add_argument("--api",         default="anthropic",
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
        "api_key":     os.getenv("HF_TOKEN") or os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY"),
        "base_url":    args.base_url,
        "load_in_4bit":args.quantize == "4bit",
        "load_in_8bit":args.quantize == "8bit",
        "device":      args.device,
    }

    logger.info(f"Skills dir  : {skills_dir}")
    logger.info(f"Reports dir : {args.reports_dir}")
    logger.info(f"LLM backend : {args.api}  model={args.model or '(default)'}")
    logger.info(f"Web server  : http://{args.host}:{args.port}")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()