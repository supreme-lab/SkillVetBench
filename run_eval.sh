#!/usr/bin/env bash
# =============================================================================
# run_eval.sh — SkillVetBench CLI batch evaluator
# =============================================================================
#
# Evaluates skills without starting the web UI.
# Runs as a background process (nohup) so the terminal can be closed.
# All progress and API call details are written to a rotating .log file.
#
# QUICK START
# -----------
#   chmod +x run_eval.sh
#   export ANTHROPIC_API_KEY=sk-ant-...
#   ./run_eval.sh
#
# USAGE
# -----
#   ./run_eval.sh [OPTIONS]
#
# OPTIONS
# -------
#   --api           {anthropic|openai|hf_api|hf_local|ollama}   LLM backend
#   --model         Model name (e.g. claude-sonnet-4-6)          Use backend default if omitted
#   --key           API key                                       Falls back to env var
#   --skills-dir    'clawhub' (ClawHub) or a local directory       default: clawhub
#   --reports-dir   Directory for JSON output reports            default: reports/
#   --log-file      Path to rotating log file                    default: logs/eval.log
#   --max-tokens    Max LLM output tokens per call               default: 6000
#   --top-n         Evaluate only the first N skills (0 = all)   default: 0 (all)
#   --cuda-devices  CUDA_VISIBLE_DEVICES value (e.g. 0 or 0,1)  default: all GPUs
#   --device        {cuda|mps|cpu}  for hf_local                 default: cuda
#   --quantize      {4bit|8bit|none} for hf_local                default: 4bit
#   --skip-existing Skip skills with an existing report
#   --verbose       Show DEBUG-level log lines
#   --help          Show this help message
#
# EXAMPLES
# --------
#   # Anthropic Claude (recommended)
#   ./run_eval.sh --api anthropic --model claude-sonnet-4-6
#
#   # OpenAI GPT-4o
#   ./run_eval.sh --api openai --model gpt-4o
#
#   # HuggingFace Qwen via serverless API
#   ./run_eval.sh --api hf_api --model Qwen/Qwen2.5-14B-Instruct
#
#   # Local GPU inference (Mistral 7B, 4-bit) on GPU 0
#   ./run_eval.sh --api hf_local --model mistralai/Mistral-7B-Instruct-v0.3 \
#                 --device cuda --quantize 4bit --cuda-devices 0
#
#   # Custom skill and report directories
#   ./run_eval.sh --skills-dir data/my_skills/ --reports-dir data/my_reports/
#
#   # Evaluate only the top 50 skills
#   ./run_eval.sh --top-n 50
#
#   # Resume — skip skills already evaluated
#   ./run_eval.sh --skip-existing --verbose
#
#   # Full example — local GPU, ClawHub skills, top-50, skip already done
#   ./run_eval.sh --api hf_local --model mistralai/Mistral-7B-Instruct-v0.3 \
#                 --device cuda --quantize 4bit --cuda-devices 0 \
#                 --skills-dir clawhub --top-n 50 \
#                 --reports-dir reports/ --skip-existing --verbose
#
# BACKGROUND PROCESS
# ------------------
#   The evaluator runs via nohup — closing the terminal will NOT stop it.
#   PID is saved to logs/eval.pid for easy management:
#       tail -f logs/eval.log          # monitor live progress
#       kill $(cat logs/eval.pid)      # stop the evaluation
#
# LOG FILE
# --------
#   Real-time log is written to logs/eval.log (rotated at 10 MB, 5 backups).
#   Both stdout and stderr are captured in the log file.
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
API="anthropic"          # LLM backend: anthropic | openai | hf_api | hf_local | ollama
MODEL=""                 # Model name — leave blank to use the backend's default
KEY=""                   # API key — leave blank to read from env var
SKILLS_DIR="clawhub"     # 'clawhub' (fetch from ClawHub) or a local directory path
REPORTS_DIR="reports"    # Directory to write JSON reports
LOG_FILE="logs/eval.log" # Log file (rotating)
MAX_TOKENS=6000          # Max LLM output tokens per API call
TOP_N=0                  # Number of skills to evaluate; 0 = evaluate all
CUDA_DEVICES="3"          # CUDA_VISIBLE_DEVICES — blank = use all GPUs
DEVICE="cuda"            # Compute device for hf_local: cuda | mps | cpu
QUANTIZE="4bit"          # Quantisation for hf_local: 4bit | 8bit | none
SKIP_EXISTING=0          # Set to 1 to skip already-evaluated skills
VERBOSE=0                # Set to 1 for DEBUG-level log output
# =============================================================================

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api)            API="$2";            shift 2 ;;
        --model)          MODEL="$2";          shift 2 ;;
        --key)            KEY="$2";            shift 2 ;;
        --skills-dir)     SKILLS_DIR="$2";     shift 2 ;;
        --reports-dir)    REPORTS_DIR="$2";    shift 2 ;;
        --log-file)       LOG_FILE="$2";       shift 2 ;;
        --max-tokens)     MAX_TOKENS="$2";     shift 2 ;;
        --top-n)          TOP_N="$2";          shift 2 ;;
        --cuda-devices)   CUDA_DEVICES="$2";   shift 2 ;;
        --device)         DEVICE="$2";         shift 2 ;;
        --quantize)       QUANTIZE="$2";       shift 2 ;;
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

# ── Build optional Python flags ───────────────────────────────────────────────
EXTRA_ARGS=()
[[ -n "$MODEL" ]]            && EXTRA_ARGS+=("--model"  "$MODEL")
[[ -n "$KEY" ]]              && EXTRA_ARGS+=("--key"    "$KEY")
[[ "$TOP_N"        -gt 0 ]]  && EXTRA_ARGS+=("--top-n"  "$TOP_N")
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
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$REPORTS_DIR"

# ── Set CUDA_VISIBLE_DEVICES ──────────────────────────────────────────────────
if [[ -n "$CUDA_DEVICES" ]]; then
    export CUDA_VISIBLE_DEVICES="$CUDA_DEVICES"
fi

# ── Launch banner ─────────────────────────────────────────────────────────────
PID_FILE="$(dirname "$LOG_FILE")/eval.pid"

echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  SkillVetBench — CLI Batch Evaluation (background)"
echo "══════════════════════════════════════════════════════════════════"
printf  "  %-16s : %s\n" "API backend"   "$API"
printf  "  %-16s : %s\n" "Model"         "${MODEL:-"(backend default)"}"
printf  "  %-16s : %s\n" "Skills source" "$SKILLS_DIR"
printf  "  %-16s : %s\n" "Reports dir"   "$SCRIPT_DIR/$REPORTS_DIR"
printf  "  %-16s : %s\n" "Log file"      "$SCRIPT_DIR/$LOG_FILE"
printf  "  %-16s : %s\n" "Max tokens"    "$MAX_TOKENS"
printf  "  %-16s : %s\n" "Top-N skills"  "${TOP_N} (0 = all)"
printf  "  %-16s : %s\n" "CUDA devices"  "${CUDA_DEVICES:-"all"}"
printf  "  %-16s : %s\n" "Started"       "$(date '+%Y-%m-%d %H:%M:%S')"
echo "══════════════════════════════════════════════════════════════════"
echo ""

# ── Launch as background process via nohup ────────────────────────────────────
nohup "$PYTHON" source_code/utils/evaluate.py \
    --api          "$API"          \
    --skills-dir   "$SKILLS_DIR"   \
    --reports-dir  "$REPORTS_DIR"  \
    --log-file     "$LOG_FILE"     \
    --max-tokens   "$MAX_TOKENS"   \
    --device       "$DEVICE"       \
    --quantize     "$QUANTIZE"     \
    "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}" \
    >> "$LOG_FILE" 2>&1 &

PID=$!
echo "$PID" > "$PID_FILE"

echo "  ✔  Evaluation launched in background"
echo ""
printf  "  %-16s : %s\n" "PID"      "$PID"
printf  "  %-16s : %s\n" "PID file" "$SCRIPT_DIR/$PID_FILE"
echo ""
echo "  Monitor progress:"
echo "       tail -f $SCRIPT_DIR/$LOG_FILE"
echo ""
echo "  Stop evaluation:"
echo "       kill \$(cat $SCRIPT_DIR/$PID_FILE)"
echo "══════════════════════════════════════════════════════════════════"
echo ""
