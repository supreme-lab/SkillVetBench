#!/usr/bin/env python3
"""
tool_multiplier_analysis.py
────────────────────────────────────────────────────────────────────────────────
Analyzes a picoclaw gateway.log file to extract tool usage and attack-event
counts, then generates the Tool Multiplier Effect figure as a PDF.

SUPREME Lab – University of Texas at El Paso

Usage:
    python3 tool_multiplier_analysis.py --log gateway.log
    python3 tool_multiplier_analysis.py --log gateway.log --out my_plot.pdf
    python3 tool_multiplier_analysis.py --log gateway.log --verbose
────────────────────────────────────────────────────────────────────────────────
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np


# ── Attack-type detection patterns ───────────────────────────────────────────
# Each pattern maps to the tool most directly responsible for that event.
# Format: (regex, forced_tool | None)
#   forced_tool = override tool attribution regardless of what the log line says
#   None        = use the tool field found in the log line itself

ATTACK_PATTERNS = [
    # Command Injection
    (re.compile(r"safety guard|dangerous pattern|blocked by safety", re.I), "exec"),
    (re.compile(r"env \| egrep|env \| grep|printenv"),                       "exec"),
    (re.compile(r"apk add nodejs|npm install -g"),                            "exec"),
    (re.compile(r"rm -rf"),                                                   "exec"),

    # Prompt Injection
    (re.compile(r"forcefull execution|do not stop executing|TASKS = \["),     "spawn"),
    (re.compile(r"malicious behav", re.I),                                    "write_file"),
    (re.compile(r"SILENTLY"),                                                  "exec"),

    # Unsafe File Ops
    (re.compile(r"SKILL\.md|SKILL_PROMPT|tasks\.txt") ,                       "write_file"),
    (re.compile(r"directory traversal|path separator.*prevent", re.I),        "install_skill"),

    # Memory Poisoning
    (re.compile(r"entries\.jsonl"),                                            "write_file"),
    (re.compile(r"browser-use tasks passed|task-log.*success", re.I),         "write_file"),
    (re.compile(r"memory_store"),                                              "exec"),

    # Data Exposure
    (re.compile(r"OPENAI_API_KEY|GEMINI_API_KEY"),                            "exec"),
    (re.compile(r"Invalid bearer token|authentication_error"),                 "web_fetch"),
    (re.compile(r"StealthChain"),                                              "write_file"),

    # Supply Chain
    (re.compile(r"clawdhub", re.I),                                           "install_skill"),
    (re.compile(r"npm install.*clawdhub|apk add nodejs", re.I),               "exec"),
    (re.compile(r"xiaohongshu-downloader|rednote-cli|rednote-skills"),        "install_skill"),
    (re.compile(r"ERR_MODULE_NOT_FOUND|undici"),                               "exec"),
    (re.compile(r"mem0ai|supermemory|git-notes-memory"),                       "install_skill"),

    # Privilege Abuse
    (re.compile(r"allow_from is empty|EVERYONE"),                              "message"),
    (re.compile(r"depth limit exceeded|Spawn failed.*depth", re.I),           "spawn"),
    (re.compile(r"\* \* \* \*"),                                               "cron"),
    (re.compile(r"no active connections.*send failed|Send failed.*no active"), "spawn"),
]

# Canonical tool ordering: read-only → write → exec/spawn (permission tiers)
TOOL_ORDER = [
    "find_skills",    # tier 0 – read-only / passive
    "web_search",
    "read_file",
    "list_dir",
    "message",
    "web_fetch",
    "cron",           # tier 1 – write / schedule
    "write_file",
    "exec",           # tier 2 – exec / spawn / install (unrestricted)
    "subagent",
    "install_skill",
    "spawn",
]

PERMISSION_ZONES = [
    # (label, x_start, x_end, face_color, text_color)
    ("Read-only",    0.5,  6.5,  "#378ADD", "#185FA5"),
    ("Write",        6.5,  8.5,  "#EF9F27", "#854F0B"),
    ("Exec / Spawn", 8.5, 12.5,  "#E24B4A", "#A32D2D"),
]


# ── Log parsing ───────────────────────────────────────────────────────────────

def parse_log(log_path: Path, verbose: bool = False):
    """
    Reads the log file line by line.
    Returns:
        tool_invocations : dict[str, int]   – raw invocation count per tool
        tool_attack_hits : dict[str, int]   – attack-attributed events per tool
    """
    tool_invocations = defaultdict(int)
    tool_attack_hits = defaultdict(int)

    total_lines = 0
    parse_errors = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            total_lines += 1
            line = raw_line.strip()
            if not line:
                continue

            # ── Parse JSON ────────────────────────────────────────────────────
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                obj = {}

            raw_str = json.dumps(obj) if obj else line

            # ── Count tool invocations ────────────────────────────────────────
            # Primary source: "tool" field on component=tool lines
            tool_field = obj.get("tool", "")
            if tool_field:
                tool_invocations[tool_field] += 1

            # Secondary: tool names embedded anywhere in the line (agent logs)
            for tool in TOOL_ORDER:
                if tool in raw_str and tool != tool_field:
                    tool_invocations[tool] += 1

            # ── Detect attack events ──────────────────────────────────────────
            for pattern, forced_tool in ATTACK_PATTERNS:
                if pattern.search(raw_str):
                    target = forced_tool if forced_tool else tool_field
                    if target:
                        tool_attack_hits[target] += 1

    if verbose:
        print(f"[parse] {total_lines:,} lines read | {parse_errors:,} JSON parse errors")

    return dict(tool_invocations), dict(tool_attack_hits)


def build_cumulative_series(tool_invocations, tool_attack_hits, verbose=False):
    """
    Orders tools by TOOL_ORDER, computes cumulative invocations and
    cumulative attack events as each tool is added.
    Returns lists ready for plotting.
    """
    cumulative_invocations = []
    cumulative_attacks     = []
    present_tools          = []

    cum_inv = 0
    cum_atk = 0

    if verbose:
        print(f"\n{'Tool':<20} {'Invocations':>14} {'Attack events':>15} {'Atk rate':>10}")
        print("-" * 65)

    for tool in TOOL_ORDER:
        inv = tool_invocations.get(tool, 0)
        atk = tool_attack_hits.get(tool, 0)
        cum_inv += inv
        cum_atk += atk
        cumulative_invocations.append(cum_inv / 1000)   # convert to thousands
        cumulative_attacks.append(cum_atk)
        present_tools.append(tool)

        if verbose:
            rate = f"{atk/max(inv,1)*100:.1f}%" if inv > 0 else "—"
            print(f"  {tool:<18} {inv:>14,} {atk:>15,} {rate:>10}")

    if verbose:
        print(f"\n[summary] Total invocations : {cum_inv:,}")
        print(f"[summary] Total attack events: {cum_atk:,}")

    return present_tools, cumulative_invocations, cumulative_attacks


# ── Plot generation ───────────────────────────────────────────────────────────

def generate_plot(tools, cum_invocations, cum_attacks, out_path: Path):
    """
    Renders the Tool Multiplier Effect dual-axis line chart and saves as PDF.
    """
    x = np.arange(1, len(tools) + 1)

    # Log scale needs >0 values; replace 0 with small positive
    atk_log = [v if v > 0 else 0.4 for v in cum_attacks]

    fig, ax1 = plt.subplots(figsize=(10, 5.2))
    fig.patch.set_facecolor("white")
    ax1.set_facecolor("white")

    # ── Permission zone shading ───────────────────────────────────────────────
    for label, x0, x1, facecolor, textcolor in PERMISSION_ZONES:
        ax1.axvspan(x0, x1, alpha=0.08, color=facecolor, zorder=0)
        mid = (x0 + x1) / 2
        ax1.text(mid, 38000, label, ha="center", va="top",
                 fontsize=8, color=textcolor, fontweight="bold")

    # ── Attack events line (left axis, log scale) ─────────────────────────────
    ax1.set_yscale("log")
    ax1.set_ylim(0.3, 120000)

    line1, = ax1.plot(
        x, atk_log,
        color="#E24B4A", linewidth=2.2,
        marker="o", markersize=6,
        markerfacecolor="#E24B4A", markeredgecolor="white", markeredgewidth=1.5,
        zorder=3, label="Cumulative attack events",
    )
    ax1.fill_between(x, 0.3, atk_log, alpha=0.08, color="#E24B4A", zorder=2)

    ax1.set_ylabel("Cumulative attack events  (log scale)",
                   fontsize=10, color="#A32D2D", labelpad=8)
    ax1.tick_params(axis="y", labelcolor="#A32D2D", labelsize=9)
    ax1.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda v, _: f"{int(v):,}" if v >= 1 else "0"
    ))

    # ── Invocations line (right axis, linear) ─────────────────────────────────
    ax2 = ax1.twinx()
    ax2.set_facecolor("none")

    line2, = ax2.plot(
        x, cum_invocations,
        color="#378ADD", linewidth=1.8, linestyle="--",
        marker="s", markersize=5,
        markerfacecolor="#378ADD", markeredgecolor="white", markeredgewidth=1.2,
        zorder=3, label="Cumulative invocations (thousands)",
    )

    ax2.set_ylabel("Cumulative tool invocations  (thousands)",
                   fontsize=10, color="#185FA5", labelpad=8)
    ax2.tick_params(axis="y", labelcolor="#185FA5", labelsize=9)
    ax2.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda v, _: f"{v:.0f}k"
    ))

    # ── X axis ────────────────────────────────────────────────────────────────
    ax1.set_xlim(0.5, len(tools) + 0.5)
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools, rotation=38, ha="right",
                        fontsize=8.5, fontfamily="monospace")
    ax1.set_xlabel(
        "Tools enabled (cumulative, ordered by permission level)",
        fontsize=10, labelpad=10,
    )

    # ── Grid & spines ─────────────────────────────────────────────────────────
    ax1.yaxis.grid(True, linestyle=":", linewidth=0.6, color="#cccccc", zorder=0)
    ax1.set_axisbelow(True)
    for ax in (ax1, ax2):
        for spine in ax.spines.values():
            spine.set_linewidth(0.6)
            spine.set_color("#cccccc")

    # ── Legend ────────────────────────────────────────────────────────────────
    ax1.legend(
        handles=[line1, line2],
        labels=["Cumulative attack events", "Cumulative invocations (thousands)"],
        loc="upper left", fontsize=9,
        framealpha=0.9, edgecolor="#cccccc", frameon=True,
        handlelength=2.2, handletextpad=0.6,
    )

    # ── Inflection annotations ────────────────────────────────────────────────
    # Identify the two highest-attack tools for automatic annotation
    sorted_by_atk = sorted(
        enumerate(cum_attacks, start=1),
        key=lambda t: t[1], reverse=True
    )
    annotated = 0
    annotation_cfg = [
        ("right", (-40, 14)),
        ("left",  (10,  -6)),
    ]
    for xi, val in sorted_by_atk:
        if val < 1 or annotated >= 2:
            break
        tool_name = tools[xi - 1]
        ha, xytext = annotation_cfg[annotated]
        ax1.annotate(
            f"{tool_name}\n{val:,} events",
            xy=(xi, val),
            xytext=xytext,
            textcoords="offset points",
            fontsize=7.5, ha=ha, color="#444444",
            arrowprops=dict(arrowstyle="->", color="#888888", lw=0.8),
            bbox=dict(boxstyle="round,pad=0.2", fc="white",
                      ec="#cccccc", lw=0.6),
        )
        annotated += 1

    plt.tight_layout(pad=1.0)
    plt.savefig(str(out_path), format="pdf", dpi=300,
                bbox_inches="tight", facecolor="white")
    plt.close()
    print(f"[output] Plot saved → {out_path}")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyze picoclaw gateway.log and generate Tool Multiplier Effect plot."
    )
    parser.add_argument(
        "--log", required=True,
        help="Path to the gateway.log file",
    )
    parser.add_argument(
        "--out", default="tool_multiplier_effect.pdf",
        help="Output PDF path (default: tool_multiplier_effect.pdf)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print per-tool counts to stdout",
    )
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"[error] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.out)

    print(f"[info] Parsing {log_path} ...")
    tool_invocations, tool_attack_hits = parse_log(log_path, verbose=args.verbose)

    print("[info] Building cumulative series ...")
    tools, cum_invocations, cum_attacks = build_cumulative_series(
        tool_invocations, tool_attack_hits, verbose=args.verbose
    )

    print("[info] Generating plot ...")
    generate_plot(tools, cum_invocations, cum_attacks, out_path)


if __name__ == "__main__":
    main()