#!/usr/bin/env bash
# =============================================================================
# run_eval.sh — SkillVetBench CLI batch evaluator (multi-prompt-variant runner)
# =============================================================================
#
# Evaluates skills without starting the web UI.
# Runs as a background process (survives terminal close) so the terminal can
# be closed.  All progress and API call details are written to rotating
# .log files.
#
# MULTI-PROMPT-VARIANT BEHAVIOUR
# -------------------------------
#   A single invocation now runs the FULL evaluation (respecting --top-n)
#   once per system-prompt variant, one after another:
#
#       prompts_cvss4_0    (original)
#       prompts_cvss4_0_b  (paraphrase — red-team lead / terse checklist)
#       prompts_cvss4_0_c  (paraphrase — principal AppSec architect / formal)
#       prompts_cvss4_0_d  (paraphrase — incident-response analyst / narrative)
#       prompts_cvss4_0_e  (paraphrase — automated compliance auditor / rigid)
#
#   All five variants evaluate the SAME skills against the SAME 15-category
#   taxonomy and produce the SAME JSON schema — only the prompt wording
#   differs. This is intended to let you compute mean/error-bars across the
#   5 runs for each skill's CVSS/SARS scores.
#
#   Each variant writes its reports to its own subdirectory:
#       <reports-dir>/<prompt_module>/<model_slug>/<skill>.json
#   and its own log file:
#       <log-dir>/<log-base>__<prompt_module>.log
#
#   If one variant's run fails outright, the script logs the failure and
#   continues on to the next variant rather than aborting the whole batch.
#
# SKILL DOWNLOAD CACHE
# --------------------
#   When --skills-dir is 'clawhub', each skill's SKILL.md is downloaded once
#   and cached on disk under --downloaded-skills-dir (default:
#   downloaded_skills/). The SAME cache directory is reused across every
#   prompt variant in the loop above, so only the very first variant's run
#   actually hits the ClawHub network — the remaining variants (and any
#   later invocation of this script against the same top-N skills) read the
#   cached SKILL.md straight off disk instead of re-downloading it.
#
# QUICK START
# -----------
#   chmod +x run_eval.sh
#   export ANTHROPIC_API_KEY=sk-ant-...
#   ./run_eval.sh --top-n 50
#
# USAGE
# -----
#   ./run_eval.sh [OPTIONS]
#
# OPTIONS
# -------
#   --api             {anthropic|openai|openrouter|hf_api|hf_local|hf_router|ollama}  LLM backend
#   --model           Model name (e.g. claude-sonnet-4-6)          Use backend default if omitted
#   --key             API key                                       Falls back to env var
#   --base-url        Override endpoint URL                          ollama default: $OLLAMA_HOST or localhost:11434
#   --skills-dir      'clawhub' (ClawHub) or a local directory       default: clawhub
#   --reports-dir     Base directory for JSON output reports       default: reports/
#                     (each prompt variant gets its own subfolder under this)
#   --downloaded-skills-dir  Local cache of ClawHub SKILL.md        default: downloaded_skills/
#                     downloads, shared across all prompt variants (ClawHub only)
#   --log-file        Base path for rotating log files             default: logs/eval2.log
#                     (each prompt variant gets its own <base>__<module>.log)
#   --max-tokens      Max LLM output tokens per call               default: 6000
#   --top-n           Evaluate only the first N skills (0 = all)   default: 0 (all)
#   --prompt-modules  Comma-separated list of prompt modules to    default: all 5 variants
#                     run, in order (e.g. prompts_cvss4_0,prompts_cvss4_0_b)
#   --cuda-devices    CUDA_VISIBLE_DEVICES value (e.g. 0 or 0,1)  default: all GPUs
#   --device          {cuda|mps|cpu}  for hf_local                 default: cuda
#   --quantize        {4bit|8bit|none} for hf_local                default: 4bit
#   --trust-remote-code  Allow custom modeling code from the HF repo (hf_local
#                        only) — required by some models (e.g. Kimi-K2.6).
#                        SECURITY: only for publishers you trust.
#   --skip-existing   Skip skills with an existing report (per variant)
#   --verbose         Show DEBUG-level log lines
#   --help            Show this help message
#
# EXAMPLES
# --------
#   # Run all 5 prompt variants against the top 50 skills (recommended)
#   ./run_eval.sh --api anthropic --model claude-sonnet-4-6 --top-n 50
#
#   # Only run two of the five variants
#   ./run_eval.sh --prompt-modules prompts_cvss4_0,prompts_cvss4_0_c --top-n 50
#
#   # OpenRouter (routes to Anthropic/OpenAI/Meta/etc. via one API key)
#   export OPENROUTER_API_KEY=sk-or-v1-...
#   ./run_eval.sh --api openrouter --model anthropic/claude-sonnet-4-6 --top-n 50
#
#   # HuggingFace router (one HF_TOKEN, routes to the provider named in the
#   # model string — here Kimi-K3 served by Together AI) — runs this model
#   # through all 5 prompt variants, saving to
#   # reports/prompts_cvss4_0_X/moonshotai_Kimi-K3_together/ alongside the
#   # other evaluator models already there.
#   export HF_TOKEN=hf_...
#   ./run_eval.sh --api hf_router --model moonshotai/Kimi-K3:together --top-n 50
#
#   # Custom skill and report directories
#   ./run_eval.sh --skills-dir data/my_skills/ --reports-dir data/my_reports/
#
#   # Resume — skip skills already evaluated (checked per prompt variant)
#   ./run_eval.sh --skip-existing --verbose
#
# BACKGROUND PROCESS
# ------------------
#   The evaluator runs in the background — closing the terminal will NOT
#   stop it. PID is saved to logs/eval2.pid for easy management:
#       tail -f logs/eval2.log                      # monitor supervisor progress
#       tail -f logs/eval2__prompts_cvss4_0_b.log    # monitor one variant
#       kill $(cat logs/eval2.pid)                   # stop the entire batch
#                                                     # (current variant + any queued)
#
# LOG FILES
# ---------
#   The supervisor log (--log-file) records which variant is running and
#   overall progress. Each prompt variant additionally gets its own rotating
#   log (rotated at 10 MB, 5 backups) with full per-skill detail.
#
# =============================================================================

set -euo pipefail

# ── Locate repo root (directory containing this script) ──────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# =============================================================================
# DEFAULT CONFIGURATION
# Edit these values to change the defaults without passing flags every time.
# =============================================================================
API="anthropic"          # LLM backend: anthropic | openai | openrouter | hf_api | hf_local | ollama
MODEL=""                 # Model name — leave blank to use the backend's default
KEY=""                   # API key — leave blank to read from env var
                          # (ANTHROPIC_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY / HF_TOKEN)
BASE_URL=""              # Endpoint override — leave blank for backend default
                          # (ollama: reads $OLLAMA_HOST, else localhost:11434)
SKILLS_DIR="clawhub"     # 'clawhub' (fetch from ClawHub) or a local directory path
REPORTS_DIR="reports"    # Base directory to write JSON reports (one subfolder per prompt variant)
DOWNLOADED_SKILLS_DIR="downloaded_skills"  # Cache of ClawHub downloads, shared across all prompt variants
LOG_FILE="logs/eval4.log" # Supervisor log file (rotating); each variant also gets its own log
MAX_TOKENS=6000          # Max LLM output tokens per API call
TOP_N=0                  # Number of skills to evaluate; 0 = evaluate all
CUDA_DEVICES="3"          # CUDA_VISIBLE_DEVICES — blank = use all GPUs
DEVICE="cuda"            # Compute device for hf_local: cuda | mps | cpu
QUANTIZE="4bit"          # Quantisation for hf_local: 4bit | 8bit | none
TRUST_REMOTE_CODE=0      # Set to 1 to allow custom code from the HF repo
                          # (hf_local only) — only for publishers you trust
SKIP_EXISTING=0          # Set to 1 to skip already-evaluated skills
VERBOSE=0                # Set to 1 for DEBUG-level log output

# The 5 prompt variants to run, in order. Same task / same JSON schema for
# all of them — only the system-prompt wording differs (see
# source_code/utils/prompts_cvss4_0*.py). Override with --prompt-modules.
PROMPT_MODULES=(
    prompts_cvss4_0_a
    prompts_cvss4_0_b
    prompts_cvss4_0_c
    prompts_cvss4_0_d
    prompts_cvss4_0_e
)
# =============================================================================

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api)            API="$2";            shift 2 ;;
        --model)          MODEL="$2";          shift 2 ;;
        --key)            KEY="$2";            shift 2 ;;
        --base-url)       BASE_URL="$2";       shift 2 ;;
        --skills-dir)     SKILLS_DIR="$2";     shift 2 ;;
        --reports-dir)    REPORTS_DIR="$2";    shift 2 ;;
        --downloaded-skills-dir) DOWNLOADED_SKILLS_DIR="$2"; shift 2 ;;
        --log-file)       LOG_FILE="$2";       shift 2 ;;
        --max-tokens)     MAX_TOKENS="$2";     shift 2 ;;
        --top-n)          TOP_N="$2";          shift 2 ;;
        --prompt-modules)
            IFS=',' read -r -a PROMPT_MODULES <<< "$2"
            shift 2
            ;;
        --cuda-devices)   CUDA_DEVICES="$2";   shift 2 ;;
        --device)         DEVICE="$2";         shift 2 ;;
        --quantize)       QUANTIZE="$2";       shift 2 ;;
        --trust-remote-code) TRUST_REMOTE_CODE=1; shift ;;
        --skip-existing)  SKIP_EXISTING=1;     shift   ;;
        --verbose|-v)     VERBOSE=1;           shift   ;;
        --help|-h)
            sed -n '/^# USAGE/,/^# ===/p' "$0" | grep -v "^# ===" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Run $0 --help for usage." >&2
            exit 1
            ;;
    esac
done

if [[ "${#PROMPT_MODULES[@]}" -eq 0 ]]; then
    echo "ERROR: --prompt-modules resolved to an empty list." >&2
    exit 1
fi

# ── Build optional Python flags (shared across all prompt-variant runs) ──────
EXTRA_ARGS=()
[[ -n "$MODEL" ]]            && EXTRA_ARGS+=("--model"  "$MODEL")
[[ -n "$KEY" ]]              && EXTRA_ARGS+=("--key"    "$KEY")
[[ -n "$BASE_URL" ]]         && EXTRA_ARGS+=("--base-url" "$BASE_URL")
[[ "$TOP_N"        -gt 0 ]]  && EXTRA_ARGS+=("--top-n"  "$TOP_N")
[[ "$TRUST_REMOTE_CODE" -eq 1 ]] && EXTRA_ARGS+=("--trust-remote-code")
[[ "$SKIP_EXISTING" -eq 1 ]] && EXTRA_ARGS+=("--skip-existing")
[[ "$VERBOSE"       -eq 1 ]] && EXTRA_ARGS+=("--verbose")

# ── Verify Python is available ────────────────────────────────────────────────
if ! command -v python &>/dev/null && ! command -v python3 &>/dev/null; then
    echo "ERROR: python / python3 not found in PATH." >&2
    exit 1
fi
PYTHON=$(command -v python3 || command -v python)

# ── Validate skills-dir ───────────────────────────────────────────────────────
if [[ "$SKILLS_DIR" != "clawhub" ]] && [[ ! -d "$SKILLS_DIR" ]]; then
    echo "ERROR: --skills-dir '$SKILLS_DIR' is not a valid directory." >&2
    echo "       Pass 'clawhub' to fetch skills from ClawHub, or a valid local path." >&2
    exit 1
fi

# ── Ensure log and reports directories exist ──────────────────────────────────
LOG_DIR="$(dirname "$LOG_FILE")"
LOG_BASE="$(basename "$LOG_FILE" .log)"
mkdir -p "$LOG_DIR"
mkdir -p "$REPORTS_DIR"
mkdir -p "$DOWNLOADED_SKILLS_DIR"

# ── Set CUDA_VISIBLE_DEVICES ──────────────────────────────────────────────────
if [[ -n "$CUDA_DEVICES" ]]; then
    export CUDA_VISIBLE_DEVICES="$CUDA_DEVICES"
fi

# ── Launch banner ─────────────────────────────────────────────────────────────
PID_FILE="$LOG_DIR/eval4.pid"

echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  SkillVetBench — CLI Batch Evaluation (background, multi-prompt-variant)"
echo "══════════════════════════════════════════════════════════════════"
printf  "  %-16s : %s\n" "API backend"   "$API"
printf  "  %-16s : %s\n" "Model"         "${MODEL:-"(backend default)"}"
[[ -n "$BASE_URL" ]] && printf  "  %-16s : %s\n" "Base URL"      "$BASE_URL"
[[ "$TRUST_REMOTE_CODE" -eq 1 ]] && printf  "  %-16s : %s\n" "Trust remote code" "⚠  ENABLED"
printf  "  %-16s : %s\n" "Skills source" "$SKILLS_DIR"
printf  "  %-16s : %s\n" "Reports base"  "$SCRIPT_DIR/$REPORTS_DIR"
printf  "  %-16s : %s\n" "Skill cache"   "$SCRIPT_DIR/$DOWNLOADED_SKILLS_DIR"
printf  "  %-16s : %s\n" "Supervisor log" "$SCRIPT_DIR/$LOG_FILE"
printf  "  %-16s : %s\n" "Max tokens"    "$MAX_TOKENS"
printf  "  %-16s : %s\n" "Top-N skills"  "${TOP_N} (0 = all)"
printf  "  %-16s : %s\n" "CUDA devices"  "${CUDA_DEVICES:-"all"}"
printf  "  %-16s : %s\n" "Prompt variants" "${#PROMPT_MODULES[@]}"
for m in "${PROMPT_MODULES[@]}"; do
    printf  "  %-16s   - %s\n" "" "$m"
done
printf  "  %-16s : %s\n" "Started"       "$(date '+%Y-%m-%d %H:%M:%S')"
echo "══════════════════════════════════════════════════════════════════"
echo ""

# ── Launch the full multi-variant batch as a background process ─────────────
# Runs in a forked subshell (not a re-exec'd bash -c string) so it still has
# direct access to all arrays/variables above. SIGHUP is ignored so closing
# the terminal doesn't kill it (nohup-style); SIGTERM/SIGINT are forwarded to
# whichever python child is currently running so `kill $(cat eval2.pid)`
# cleanly stops the whole batch instead of orphaning the current variant.
(
    trap '' HUP
    child_pid=""
    trap 'echo "[Supervisor] Caught termination signal — stopping current variant and exiting."; [[ -n "$child_pid" ]] && kill -TERM "$child_pid" 2>/dev/null; exit 143' TERM INT

    total_variants="${#PROMPT_MODULES[@]}"
    variant_idx=0
    overall_rc=0

    for module in "${PROMPT_MODULES[@]}"; do
        variant_idx=$((variant_idx + 1))
        variant_reports_dir="$REPORTS_DIR/$module"
        variant_log_file="$LOG_DIR/${LOG_BASE}__${module}.log"
        mkdir -p "$variant_reports_dir"

        echo ""
        echo "══════════════════════════════════════════════════════════════════"
        echo "[Supervisor] Prompt variant ${variant_idx}/${total_variants}: $module"
        echo "[Supervisor] Reports dir : $SCRIPT_DIR/$variant_reports_dir"
        echo "[Supervisor] Variant log : $SCRIPT_DIR/$variant_log_file"
        echo "[Supervisor] Started at  : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "══════════════════════════════════════════════════════════════════"

        "$PYTHON" source_code/utils/evaluate.py \
            --api           "$API"               \
            --skills-dir    "$SKILLS_DIR"         \
            --reports-dir   "$variant_reports_dir" \
            --log-file      "$variant_log_file"   \
            --max-tokens    "$MAX_TOKENS"          \
            --device        "$DEVICE"              \
            --quantize      "$QUANTIZE"            \
            --prompt-module "$module"              \
            --downloaded-skills-dir "$DOWNLOADED_SKILLS_DIR" \
            "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"  &
        child_pid=$!
        # `if wait ...` (rather than a bare `wait; rc=$?`) so a non-zero exit
        # from this variant doesn't trip `set -e` and kill the whole
        # supervisor loop before the next variant gets a chance to run.
        if wait "$child_pid"; then
            rc=0
        else
            rc=$?
        fi
        child_pid=""

        if [[ "$rc" -eq 0 ]]; then
            echo "[Supervisor] ✔ Variant '$module' completed successfully at $(date '+%Y-%m-%d %H:%M:%S')"
        else
            echo "[Supervisor] ✘ Variant '$module' exited with code $rc at $(date '+%Y-%m-%d %H:%M:%S') — continuing to next variant"
            overall_rc=1
        fi
    done

    echo ""
    echo "══════════════════════════════════════════════════════════════════"
    echo "[Supervisor] All $total_variants prompt variant(s) finished at $(date '+%Y-%m-%d %H:%M:%S')"
    echo "[Supervisor] Reports written under: $SCRIPT_DIR/$REPORTS_DIR/<prompt_module>/"
    echo "══════════════════════════════════════════════════════════════════"
    exit "$overall_rc"
) >> "$LOG_FILE" 2>&1 &

disown
PID=$!
echo "$PID" > "$PID_FILE"

echo "  ✔  Multi-prompt-variant evaluation launched in background"
echo ""
printf  "  %-16s : %s\n" "Supervisor PID" "$PID"
printf  "  %-16s : %s\n" "PID file"       "$SCRIPT_DIR/$PID_FILE"
echo ""
echo "  Monitor overall progress:"
echo "       tail -f $SCRIPT_DIR/$LOG_FILE"
echo ""
echo "  Monitor a specific prompt variant:"
echo "       tail -f $SCRIPT_DIR/$LOG_DIR/${LOG_BASE}__<prompt_module>.log"
echo ""
echo "  Stop the entire batch (current + queued variants):"
echo "       kill \$(cat $SCRIPT_DIR/$PID_FILE)"
echo "══════════════════════════════════════════════════════════════════"
echo ""
