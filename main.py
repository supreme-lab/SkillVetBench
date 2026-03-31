"""
main.py — Skill Security Evaluator CLI
=======================================

OPEN-SOURCE (HuggingFace)
  # Run locally — model downloaded once and cached
  python main.py skills/ --api hf_local --model meta-llama/Meta-Llama-3.1-8B-Instruct

  # Run locally with 4-bit quantization (uses ~4 GB instead of ~16 GB)
  python main.py skills/ --api hf_local --model meta-llama/Meta-Llama-3.1-8B-Instruct --quantize 4bit

  # HuggingFace Inference API (serverless — needs HF_TOKEN)
  python main.py skills/ --api hf_api --model meta-llama/Meta-Llama-3.1-70B-Instruct --key hf_...

  # HuggingFace Dedicated Endpoint
  python main.py skills/ --api hf_api --key hf_... --base-url https://YOUR-ENDPOINT.hf.cloud

FRONTIER (API)
  # Anthropic Claude (default)
  python main.py skills/my_skill.md

  # OpenAI
  python main.py skills/ --api openai --key sk-...

  # Groq — very fast, OpenAI-compatible
  python main.py skills/ --api openai --key gsk_... \\
    --base-url https://api.groq.com/openai/v1 --model llama-3.1-70b-versatile

  # Together AI
  python main.py skills/ --api openai --key ... \\
    --base-url https://api.together.xyz/v1 --model mistralai/Mistral-7B-Instruct-v0.3

  # Ollama (local server)
  python main.py skills/ --api ollama --model llama3.1:8b

UTILITY
  python main.py --list-models          # show all supported models
  python main.py skills/ --output reports/   # save JSON report
"""

import argparse
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    format   = "%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt  = "%H:%M:%S",
    level    = logging.INFO,
    handlers = [logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("SkillEval")


def main():
    parser = argparse.ArgumentParser(
        description = "Evaluate OpenClaw / agent skill .md files for security vulnerabilities",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = __doc__,
    )

    # ── Positional (optional so --list-models works alone) ───────────────────
    parser.add_argument(
        "path", nargs="?", default=None,
        help="Path to a single .md file or a directory of .md files",
    )

    # ── Backend selection ─────────────────────────────────────────────────────
    parser.add_argument(
        "--api", default="anthropic",
        choices=["anthropic", "openai", "ollama", "hf_local", "hf_api"],
        help=(
            "LLM backend  (default: anthropic)\n"
            "  hf_local  — HuggingFace model running on your machine\n"
            "  hf_api    — HuggingFace Inference API (serverless or dedicated)\n"
            "  anthropic — Anthropic Claude API\n"
            "  openai    — OpenAI or any OpenAI-compatible endpoint\n"
            "  ollama    — local Ollama server"
        ),
    )
    parser.add_argument("--key",  default=None,
        help="API / HF token (falls back to ANTHROPIC_API_KEY / OPENAI_API_KEY / HF_TOKEN)")
    parser.add_argument("--model", default=None,
        help="Model name/ID (run --list-models to see options per backend)")
    parser.add_argument("--base-url", default=None,
        help="Custom endpoint URL (Groq, Together, HF dedicated endpoint, Ollama host, etc.)")

    # ── HuggingFace local options ─────────────────────────────────────────────
    hf_group = parser.add_argument_group("HuggingFace local options (--api hf_local)")
    hf_group.add_argument(
        "--quantize", default=None, choices=["4bit", "8bit"],
        help=(
            "Quantize model to reduce memory:\n"
            "  4bit — ~75%% memory reduction (needs bitsandbytes + CUDA)\n"
            "  8bit — ~50%% memory reduction (needs bitsandbytes + CUDA)"
        ),
    )
    hf_group.add_argument("--device", default=None,
        choices=["cuda", "mps", "cpu"],
        help="Force specific device (default: auto-detect GPU/MPS/CPU)")
    hf_group.add_argument("--hf-cache", default=None,
        metavar="DIR",
        help="Custom directory for downloaded model weights (default: ~/.cache/huggingface)")

    # ── Output / display ──────────────────────────────────────────────────────
    parser.add_argument("--output", "-o", default=None,
        help="Directory to save JSON report")
    parser.add_argument("--pdf", default=None, metavar="DIR",
        help=(
            "Directory to save PDF reports. "
            "Each model gets its own subdirectory: <DIR>/<model_name>/<skill>_security_report.pdf"
        ))
    parser.add_argument("--no-color", action="store_true",
        help="Disable Rich colored output")
    parser.add_argument("--list-models", action="store_true",
        help="List all recommended models for every backend and exit")

    args = parser.parse_args()

    # ── --list-models ─────────────────────────────────────────────────────────
    if args.list_models:
        sys.path.insert(0, str(Path(__file__).parent))
        from llm_client import list_recommended_models
        list_recommended_models()
        sys.exit(0)

    # ── Require path if not listing models ────────────────────────────────────
    if not args.path:
        parser.error("'path' argument is required unless --list-models is set")

    # ── Setup ─────────────────────────────────────────────────────────────────
    sys.path.insert(0, str(Path(__file__).parent))

    if args.no_color:
        import reporter as rep
        rep._has_rich = False

    from llm_client  import LLMClient
    from evaluator   import SkillEvaluator
    from pdf_reporter import PDFReporter
    import reporter as rep

    # ── Resolve API key ───────────────────────────────────────────────────────
    key = (
        args.key
        or os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("HF_TOKEN")
        or ""
    )

    # ── Build LLM client ──────────────────────────────────────────────────────
    try:
        llm = LLMClient(
            api_type     = args.api,
            api_key      = key,
            model        = args.model,
            base_url     = args.base_url,
            load_in_4bit = (args.quantize == "4bit"),
            load_in_8bit = (args.quantize == "8bit"),
            device       = args.device,
            hf_cache_dir = args.hf_cache,
        )
        logger.info(f"Backend : {llm}")
    except Exception as e:
        logger.error(f"Cannot initialise LLM client: {e}")
        sys.exit(1)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    target = Path(args.path)
    if not target.exists():
        logger.error(f"Path not found: {target}")
        sys.exit(1)

    evaluator = SkillEvaluator(llm)

    if target.is_file():
        reports = [evaluator.evaluate_file(target)]
    else:
        reports = evaluator.evaluate_directory(target)

    if not reports:
        logger.warning("No .md skill files found.")
        sys.exit(0)

    # ── Display results ───────────────────────────────────────────────────────
    for r in reports:
        rep.print_report(r)

    if len(reports) > 1:
        rep.print_summary(reports)

    # ── Save JSON ─────────────────────────────────────────────────────────────
    if args.output:
        out_path = rep.save_json_reports(reports, Path(args.output))
        logger.info(f"JSON report saved → {out_path}")

    # ── Save PDF reports (model-wise directories) ──────────────────────────
    if args.pdf:
        model_id = args.model or LLMClient.DEFAULTS.get(args.api, args.api)
        pdf_rep  = PDFReporter(output_dir=args.pdf, model_name=model_id)
        pdf_paths = pdf_rep.save_batch(reports)
        for p in pdf_paths:
            logger.info(f"PDF report saved  → {p}")

    # ── Exit code — non-zero if CRITICAL or HIGH findings ─────────────────────
    n_critical = sum(1 for r in reports if r.overall_risk in ("CRITICAL", "HIGH"))
    if n_critical:
        logger.warning(f"{n_critical} skill(s) with CRITICAL/HIGH risk.")
        sys.exit(2)


if __name__ == "__main__":
    main()