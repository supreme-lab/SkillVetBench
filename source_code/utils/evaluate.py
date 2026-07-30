#!/usr/bin/env python3
"""
evaluate.py
===========
CLI batch evaluator — evaluates every .md skill file in a directory
directly via the SkillEvaluator pipeline, WITHOUT starting the web server.

All progress, API call details, and results are written to both the
terminal and a rotating log file.

Usage
-----
    python source_code/utils/evaluate.py --api anthropic --model claude-sonnet-4-6
    python source_code/utils/evaluate.py --api openai --model gpt-4o --skills-dir my_skills/
    python source_code/utils/evaluate.py --api hf_local --device cuda --quantize 4bit
    python source_code/utils/evaluate.py --top-n 50 --skip-existing --verbose
    python source_code/utils/evaluate.py --help

Log output format (example)
----------------------------
    2026-05-23 10:00:00  INFO  [Config]  Skills dir   : /abs/path/skills/
    2026-05-23 10:00:00  INFO  [Config]  Reports dir  : /abs/path/reports/
    2026-05-23 10:00:01  INFO  [ 1/10] ▶ START   SKILL1.md
    2026-05-23 10:00:01  INFO  [ 1/10]   Input  : /abs/path/skills/SKILL1.md
    2026-05-23 10:00:01  INFO  [ 1/10] → API call #1  [fn=evaluate_content  api=anthropic  model=claude-sonnet-4-6  prompt=4,821 chars]
    2026-05-23 10:00:35  INFO  [ 1/10] ✓ API call #1  responded in 34.2s  (1,842 chars)
    2026-05-23 10:00:35  INFO  [ 1/10] → API call #2  [fn=evaluate_content (clawhub)  api=anthropic  model=claude-sonnet-4-6  prompt=3,204 chars]
    2026-05-23 10:00:56  INFO  [ 1/10] ✓ API call #2  responded in 21.3s  (945 chars)
    2026-05-23 10:00:56  INFO  [ 1/10] ✔ DONE   SKILL1.md  SARS=7.4 HIGH  CVSS=7.8 HIGH  (55.2s)
    2026-05-23 10:00:56  INFO  [ 1/10]   Output : /abs/path/reports/claude-sonnet-4-6/SKILL1_md.json
    2026-05-23 10:00:56  INFO  [ 1/10]   Progress: 1/10 done  |  9 left  |  Elapsed: 55s  |  ETA ~8m 17s
"""

import argparse
import importlib
import logging
import os
import sys
import time
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# ── Repo-root path setup ──────────────────────────────────────────────────────
UTILS_DIR = Path(__file__).resolve().parent            # …/source_code/utils
REPO_ROOT = UTILS_DIR.parent.parent                    # …/skillvetbench_github
sys.path.insert(0, str(REPO_ROOT.parent))              # parent of skillvetbench_github — for skillvetbench_github.* imports
sys.path.insert(0, str(UTILS_DIR.parent / "clawhub"))  # …/source_code/clawhub — for clawhub_fetch imports

from skillvetbench_github.source_code.utils.evaluator import SkillEvaluator
from skillvetbench_github.source_code.utils.llm_client import LLMClient
from skillvetbench_github.source_code.utils.storage    import ReportStorage

# ── Module logger ─────────────────────────────────────────────────────────────
logger = logging.getLogger("BatchEval")


# ─────────────────────────────────────────────────────────────────────────────
# Timed LLM wrapper
# ─────────────────────────────────────────────────────────────────────────────

class _TimedLLMClient(LLMClient):
    """
    Drop-in replacement for LLMClient that logs every API call with:
      - call number within the current skill
      - function context (CVSS+SARS vs ClawHub)
      - prompt character count
      - wall-clock response time
      - response character count
    Call set_skill_label() before each new skill to reset the counter.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._call_n   = 0
        self._label    = "[?/?]"

    def set_skill_label(self, label: str) -> None:
        self._call_n = 0
        self._label  = label

    def complete(self, system_prompt: str, user_message: str, **kwargs) -> str:
        self._call_n += 1
        n        = self._call_n
        api      = getattr(self, "api_type", "?")
        model    = getattr(self, "model",    None) or "default"
        fn_ctx   = "CVSS+SARS evaluation" if n == 1 else "ClawHub evaluation"
        prompt_len = len(system_prompt) + len(user_message)

        logger.info(
            f"{self._label} → API call #{n}  "
            f"[fn={fn_ctx}  api={api}  model={model}  "
            f"prompt={prompt_len:,} chars]"
        )

        t0 = time.perf_counter()
        try:
            response  = super().complete(system_prompt, user_message, **kwargs)
            elapsed   = time.perf_counter() - t0
            logger.info(
                f"{self._label} ✓ API call #{n}  "
                f"responded in {elapsed:.1f}s  ({len(response):,} chars)"
            )
            return response

        except Exception as exc:
            elapsed = time.perf_counter() - t0
            logger.error(
                f"{self._label} ✗ API call #{n}  "
                f"FAILED after {elapsed:.1f}s  — {exc}"
            )
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_prompt_module(prompt_module: str):
    """
    Import a prompts_cvss4_0*.py module by short name (e.g. "prompts_cvss4_0",
    "prompts_cvss4_0_b") and return (SKILL_SECURITY_EVAL_SYSTEM_PROMPT,
    build_evaluation_prompt) from it. Lets the same evaluation pipeline run
    under differently-worded system prompts for inter-prompt variance /
    error-bar analysis.
    """
    mod = importlib.import_module(
        f"skillvetbench_github.source_code.utils.{prompt_module}"
    )
    return mod.SKILL_SECURITY_EVAL_SYSTEM_PROMPT, mod.build_evaluation_prompt


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    m, s = divmod(int(seconds), 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h {m:02d}m {s:02d}s"


def _setup_logging(log_file: str, verbose: bool) -> None:
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    fmt       = "%(asctime)s  %(levelname)-8s  %(name)-12s  %(message)s"
    formatter = logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)   # capture everything; handlers filter

    # Console: INFO by default, DEBUG with --verbose
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(formatter)

    # File: always DEBUG (full detail for post-mortem)
    file_h = RotatingFileHandler(
        log_path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_h.setLevel(logging.DEBUG)
    file_h.setFormatter(formatter)

    root.addHandler(console)
    root.addHandler(file_h)

    # Silence noisy third-party libraries
    for lib in ("httpx", "anthropic", "openai", "huggingface_hub",
                "transformers", "urllib3", "requests", "uvicorn"):
        logging.getLogger(lib).setLevel(logging.WARNING)

    logger.info(f"[Config]  Log file     : {log_path.resolve()}")


# ─────────────────────────────────────────────────────────────────────────────
# Core batch runner
# ─────────────────────────────────────────────────────────────────────────────

def run_batch(
    skills_dir:   Path,
    reports_dir:  Path,
    api_type:     str,
    model:        str,
    api_key:      str,
    device:       str,
    load_in_4bit: bool,
    load_in_8bit: bool,
    max_tokens:   int,
    skip_existing: bool,
    top_n:        int = 0,
    base_url:     str = "",
    trust_remote_code: bool = False,
    prompt_module: str = "prompts_cvss4_0",
    downloaded_skills_dir: Optional[Path] = None,
) -> int:
    """
    Evaluate skills from a local directory or ClawHub (skills_dir == 'clawhub').
    top_n > 0 limits the number of skills evaluated.
    prompt_module selects which prompts_cvss4_0*.py system prompt / user-message
    builder to use (see prompts_cvss4_0_b/c/d/e.py for paraphrased variants).
    downloaded_skills_dir (ClawHub only): local cache of raw SKILL.md content
    keyed by filename. A skill already present there is read from disk instead
    of re-downloaded — lets multiple prompt-variant runs against the same
    top-N skills reuse one download instead of hitting ClawHub every time.
    Returns 0 on full success, 1 if any skill failed.
    """
    from skillvetbench_github.source_code.utils.storage import _slug

    system_prompt, build_prompt_fn = _load_prompt_module(prompt_module)

    is_clawhub  = str(skills_dir) == "clawhub"
    dl_cache_dir = Path(downloaded_skills_dir) if downloaded_skills_dir else Path("downloaded_skills")
    if is_clawhub:
        dl_cache_dir.mkdir(parents=True, exist_ok=True)
    storage    = ReportStorage(str(reports_dir))
    model_name = model or "default"

    # ── Discover skills ───────────────────────────────────────────────────
    if is_clawhub:
        from clawhub_fetch import list_slugs_from_meta, fetch_skill_from_zip
        effective_n   = top_n if top_n > 0 else 99999
        skill_entries = list_slugs_from_meta(top_n=effective_n)
        if not skill_entries:
            logger.error("No skills found in clawhub_skills_meta.json")
            return 1
        if skip_existing:
            model_dir     = reports_dir / _slug(model_name)
            before        = len(skill_entries)
            skill_entries = [
                e for e in skill_entries
                if not (model_dir / f"{_slug(e['filename'])}.json").exists()
            ]
            skipped = before - len(skill_entries)
            if skipped:
                logger.info(f"[Config]  Skipped {skipped} already-evaluated skill(s)")
        total = len(skill_entries)
        source_label = "ClawHub"
    else:
        skill_files = sorted(skills_dir.glob("*.md"))
        if top_n > 0:
            skill_files = skill_files[:top_n]
        if not skill_files:
            logger.error(f"No .md files found in: {skills_dir.resolve()}")
            return 1
        if skip_existing:
            model_dir   = reports_dir / _slug(model_name)
            before      = len(skill_files)
            skill_files = [
                f for f in skill_files
                if not (model_dir / f"{_slug(f.name)}.json").exists()
            ]
            skipped = before - len(skill_files)
            if skipped:
                logger.info(f"[Config]  Skipped {skipped} already-evaluated skill(s)")
        total        = len(skill_files)
        source_label = str(skills_dir.resolve())

    if total == 0:
        logger.info("All skills already evaluated — nothing to do.")
        return 0

    # ── Config banner ─────────────────────────────────────────────────────
    SEP = "═" * 66
    logger.info(SEP)
    logger.info("  SkillVetBench — CLI Batch Evaluation")
    logger.info(SEP)
    logger.info(f"[Config]  Source       : {source_label}")
    logger.info(f"[Config]  Reports dir  : {reports_dir.resolve()}")
    logger.info(f"[Config]  LLM backend  : {api_type}")
    logger.info(f"[Config]  Model        : {model_name}")
    if base_url:
        logger.info(f"[Config]  Base URL     : {base_url}")
    logger.info(f"[Config]  Max tokens   : {max_tokens}")
    logger.info(f"[Config]  Top-N limit  : {top_n if top_n > 0 else 'all'}")
    logger.info(f"[Config]  Prompt module: {prompt_module}")
    if is_clawhub:
        logger.info(f"[Config]  Skill cache  : {dl_cache_dir.resolve()}")
    logger.info(f"[Config]  Skills total : {total}")
    logger.info(f"[Config]  Started at   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(SEP)

    # ── Build LLM client ──────────────────────────────────────────────────
    llm = _TimedLLMClient(
        api_type     = api_type,
        api_key      = api_key or "",
        model        = model or None,
        base_url     = base_url or None,
        device       = device,
        load_in_4bit = load_in_4bit,
        load_in_8bit = load_in_8bit,
        max_tokens   = max_tokens,
        trust_remote_code = trust_remote_code,
    )
    evaluator = SkillEvaluator(llm, system_prompt=system_prompt, build_prompt_fn=build_prompt_fn)

    # ── Evaluate each skill ───────────────────────────────────────────────
    succeeded    = 0
    failed       = 0
    skill_times: list[float] = []
    batch_start  = time.perf_counter()

    items = skill_entries if is_clawhub else skill_files

    for idx, item in enumerate(items, 1):
        if is_clawhub:
            slug     = item["slug"]
            filename = item["filename"]
            owner    = item.get("owner_handle")
        else:
            skill_path = item
            filename   = skill_path.name

        label = f"[{idx:>{len(str(total))}}/{total}]"

        if skill_times:
            avg_s   = sum(skill_times) / len(skill_times)
            eta_s   = avg_s * (total - idx + 1)
            eta_str = f"  ETA ~{_fmt_duration(eta_s)}"
        else:
            eta_str = ""

        logger.info("")
        logger.info(f"{label} ▶ START   {filename}{eta_str}")

        llm.set_skill_label(label)
        t_skill = time.perf_counter()

        try:
            if is_clawhub:
                cached_path = dl_cache_dir / filename
                if cached_path.exists():
                    content = cached_path.read_text(encoding="utf-8", errors="replace")
                    logger.info(
                        f"{label}   Using cached download ({len(content):,} chars): {cached_path}"
                    )
                else:
                    logger.info(f"{label}   Downloading '{slug}' from ClawHub ...")
                    content = fetch_skill_from_zip(slug, owner_handle=owner)
                    if not content:
                        raise ValueError(f"Could not download SKILL.md for slug '{slug}'")
                    logger.info(f"{label}   Downloaded {len(content):,} chars")
                    cached_path.write_text(content, encoding="utf-8")
                    logger.info(f"{label}   Cached to {cached_path}")
                report = evaluator.evaluate_content(content, filename)
            else:
                logger.info(f"{label}   Input  : {skill_path.resolve()}")
                report = evaluator.evaluate_file(skill_path)

            elapsed  = time.perf_counter() - t_skill
            out_path = storage.save(report, model_name)

            logger.info(
                f"{label} ✔ DONE   {filename}  "
                f"SARS={report.sars_score:.1f} {report.sars_severity}  "
                f"CVSS={report.cvss_base_score:.1f} {report.cvss_severity}  "
                f"({_fmt_duration(elapsed)})"
            )
            logger.info(f"{label}   Output : {Path(out_path).resolve()}")
            succeeded += 1
            skill_times.append(elapsed)

        except Exception as exc:
            elapsed = time.perf_counter() - t_skill
            logger.error(
                f"{label} ✘ FAILED  {filename}  "
                f"({_fmt_duration(elapsed)})  error={exc}",
                exc_info=True,
            )
            failed += 1
            skill_times.append(elapsed)

        done_so_far   = idx
        left          = total - idx
        total_elapsed = time.perf_counter() - batch_start
        logger.info(
            f"{label}   Progress: {done_so_far}/{total} done  |  "
            f"{left} left  |  "
            f"Elapsed: {_fmt_duration(total_elapsed)}"
        )

    # ── Final summary ─────────────────────────────────────────────────────
    total_elapsed = time.perf_counter() - batch_start
    avg_str = (
        f"  Avg per skill   : {_fmt_duration(sum(skill_times)/len(skill_times))}"
        if skill_times else ""
    )

    logger.info("")
    logger.info(SEP)
    logger.info("  Batch Evaluation Complete")
    logger.info(SEP)
    logger.info(f"  Total skills    : {total}")
    logger.info(f"  Succeeded       : {succeeded}")
    logger.info(f"  Failed          : {failed}")
    logger.info(f"  Total time      : {_fmt_duration(total_elapsed)}")
    if avg_str:
        logger.info(avg_str)
    logger.info(f"  Source          : {source_label}")
    logger.info(f"  Reports saved to: {reports_dir.resolve()}")
    logger.info(f"  Finished at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(SEP)

    return 1 if failed else 0


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SkillVetBench — CLI batch evaluator (no web server needed)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python source_code/utils/evaluate.py --api anthropic --model claude-sonnet-4-6\n"
            "  python source_code/utils/evaluate.py --api openai --model gpt-4o --skills-dir my_skills/\n"
            "  python source_code/utils/evaluate.py --api openrouter --model anthropic/claude-sonnet-4-6\n"
            "  python source_code/utils/evaluate.py --api hf_local --device cuda --quantize 4bit\n"
            "  python source_code/utils/evaluate.py --top-n 50 --skip-existing --verbose\n"
        ),
    )

    # Directories
    parser.add_argument(
        "--skills-dir", default="skills",
        metavar="DIR", help="Directory containing .md skill files to evaluate",
    )
    parser.add_argument(
        "--reports-dir", default="reports",
        metavar="DIR", help="Directory to save JSON evaluation reports",
    )
    parser.add_argument(
        "--downloaded-skills-dir", default="downloaded_skills",
        metavar="DIR",
        help="Local cache directory for skill files downloaded from ClawHub "
             "(ignored when --skills-dir is a local directory). A skill already "
             "cached here is read from disk instead of re-downloaded — reuse the "
             "same directory across multiple prompt-variant runs against the "
             "same top-N skills so only the first run hits the network.",
    )
    parser.add_argument(
        "--log-file", default="logs/eval.log",
        metavar="FILE", help="Rotating log file path",
    )

    # LLM backend
    parser.add_argument(
        "--api", default="anthropic",
        choices=["anthropic", "openai", "openrouter", "hf_local", "hf_api", "hf_router", "ollama"],
        help="LLM backend",
    )
    parser.add_argument(
        "--model", default=None,
        help="Model name — uses backend default when omitted",
    )
    parser.add_argument(
        "--key", default=None,
        metavar="KEY",
        help="API key — falls back to ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY / HF_TOKEN env vars",
    )
    parser.add_argument(
        "--base-url", default=None,
        metavar="URL",
        help="Override endpoint URL — for ollama, defaults to $OLLAMA_HOST or "
             "http://localhost:11434; for openai, points at an OpenAI-compatible "
             "endpoint (Together/Groq/vLLM/etc.)",
    )

    # Local inference options
    parser.add_argument(
        "--device", default="cuda", choices=["cuda", "mps", "cpu"],
        help="Compute device (hf_local only)",
    )
    parser.add_argument(
        "--quantize", default="4bit", choices=["4bit", "8bit", "none"],
        help="Weight quantization (hf_local only)",
    )
    parser.add_argument(
        "--trust-remote-code", action="store_true",
        help="Allow executing custom modeling code shipped in the HF repo "
             "(hf_local only). Required by some models (e.g. Kimi-K2.6). "
             "SECURITY: only enable for repos/publishers you trust — this "
             "runs arbitrary Python from the model repo.",
    )

    # Generation options
    parser.add_argument(
        "--max-tokens", default=6000, type=int,
        help="Max output tokens per LLM call",
    )

    # Scope limit
    parser.add_argument(
        "--top-n", default=0, type=int, metavar="N",
        help="Evaluate only the first N skill files (alphabetical order); 0 = evaluate all",
    )

    # Prompt variant (for inter-prompt variance / error-bar runs)
    parser.add_argument(
        "--prompt-module", default="prompts_cvss4_0",
        metavar="MODULE",
        help="Which prompts_cvss4_0*.py module to load the system prompt and "
             "user-message builder from, e.g. prompts_cvss4_0, prompts_cvss4_0_b, "
             "prompts_cvss4_0_c, prompts_cvss4_0_d, prompts_cvss4_0_e. All variants "
             "perform the identical evaluation task with the same JSON output "
             "contract — only the prompt wording/style differs.",
    )

    # Behaviour flags
    parser.add_argument(
        "--skip-existing", action="store_true",
        help="Skip skills that already have a saved report for this model",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show DEBUG-level log lines (raw LLM responses, etc.)",
    )

    args = parser.parse_args()

    # Resolve paths
    skills_dir_raw = args.skills_dir
    reports_dir    = Path(args.reports_dir).expanduser().resolve()

    if skills_dir_raw == "clawhub":
        skills_dir = Path(skills_dir_raw)   # kept as-is; actual fetching handled downstream
    else:
        skills_dir = Path(skills_dir_raw).expanduser().resolve()
        if not skills_dir.exists():
            print(f"ERROR: --skills-dir not found: {skills_dir}", file=sys.stderr)
            sys.exit(1)

    reports_dir.mkdir(parents=True, exist_ok=True)

    # Logging must be set up before anything else logs
    _setup_logging(args.log_file, verbose=args.verbose)

    # API key resolution
    ENV_MAP = {
        "anthropic":  "ANTHROPIC_API_KEY",
        "openai":     "OPENAI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "hf_api":     "HF_TOKEN",
        "hf_local":   "HF_TOKEN",
        "hf_router":  "HF_TOKEN",
        "ollama":     "",
    }
    env_var = ENV_MAP.get(args.api, "")
    api_key = args.key or (os.getenv(env_var, "") if env_var else "")

    if not api_key and args.api in ("anthropic", "openai", "openrouter"):
        logger.error(
            f"No API key found for backend '{args.api}'. "
            f"Set the {env_var} environment variable or pass --key YOUR_KEY."
        )
        sys.exit(1)
    if not api_key and args.api in ("hf_api", "hf_local", "hf_router"):
        logger.error(
            "No HuggingFace token. Set HF_TOKEN=hf_... or pass --key hf_..."
        )
        sys.exit(1)

    exit_code = run_batch(
        skills_dir   = skills_dir,
        reports_dir  = reports_dir,
        api_type     = args.api,
        model        = args.model or "",
        api_key      = api_key,
        device       = args.device,
        load_in_4bit = args.quantize == "4bit",
        load_in_8bit = args.quantize == "8bit",
        max_tokens   = args.max_tokens,
        skip_existing = args.skip_existing,
        top_n        = max(0, args.top_n),
        base_url     = args.base_url or "",
        trust_remote_code = args.trust_remote_code,
        prompt_module = args.prompt_module,
        downloaded_skills_dir = Path(args.downloaded_skills_dir).expanduser().resolve(),
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
