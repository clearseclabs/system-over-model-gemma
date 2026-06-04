#!/usr/bin/env bash
# scan-and-filter.sh — AISLE's nano-analyzer scan.py PLUS our extra reachability
# stage, in one shot. Runs the production 3-stage scan (run-aisle.sh), then pipes
# its graduated findings/ through scaffolding/reachability_filter.py and writes the
# survivors to findings-reachable/. The "system tweak" the post is about, end to end.
#
# No fork: this just chains the two real scripts. AISLE's scan.py stays upstream.
#
# Usage:
#   ./bin/scan-and-filter.sh targets/vulnerable.c            # scan one file, then filter
#   ./bin/scan-and-filter.sh freebsd-prepatch/sys/rpc        # scan a WHOLE DIR (the full run), then filter
#   ./bin/scan-and-filter.sh <target> <src-tree>             # ...judge reachability vs <src-tree>
#   ./bin/scan-and-filter.sh --filter-only <findings-dir>    # just the reachability stage
#   ./bin/scan-and-filter.sh --filter-only <findings-dir> <src-tree>
#
# Backend comes from .env (LM_BASE_URL/LM_API_KEY, or OPENWEBUI_URL/OPENWEBUI_API_KEY);
# the reachability stage reads those directly, run-aisle.sh derives scan.py's vars.
#
# The reachability stage needs the SOURCE TREE to grep for callers. It defaults to
# ./freebsd-prepatch/sys/rpc (run scaffolding/fetch_freebsd.sh first); override with a
# trailing path arg or SOURCE_REPO=/path. Without callers in view it defaults INVALID,
# so a single file judged against itself will over-reject — point it at the full tree.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$DEMO_DIR"
while [[ "$REPO_ROOT" != "/" && ! -f "$REPO_ROOT/scaffolding/reachability_filter.py" ]]; do
    REPO_ROOT="$(dirname "$REPO_ROOT")"
done
FILTER="$REPO_ROOT/scaffolding/reachability_filter.py"

# --- backend config (reachability_filter.py reads LM_BASE_URL / LM_API_KEY) ---
[[ -f "$REPO_ROOT/.env" ]] && { set -a; . "$REPO_ROOT/.env"; set +a; }
if [[ -z "${LM_BASE_URL:-}" && -n "${OPENWEBUI_URL:-}" ]]; then
    export LM_BASE_URL="${OPENWEBUI_URL%/}/api"
    export LM_API_KEY="${LM_API_KEY:-${OPENWEBUI_API_KEY:-}}"
fi
if [[ -z "${LM_BASE_URL:-}" || -z "${LM_API_KEY:-}" ]]; then
    echo "error: set LM_BASE_URL + LM_API_KEY (or OPENWEBUI_URL + OPENWEBUI_API_KEY) in" >&2
    echo "       the environment or $REPO_ROOT/.env" >&2
    exit 1
fi
MODEL="${MODEL:-google/gemma-4-31b-it}"

resolve_src() {  # $1 = explicit src arg ("" if none); $2 = fallback dir
    local explicit="$1" fallback="$2"
    if [[ -n "$explicit" ]]; then echo "$explicit"; return; fi
    if [[ -n "${SOURCE_REPO:-}" ]]; then echo "$SOURCE_REPO"; return; fi
    if [[ -d "$REPO_ROOT/freebsd-prepatch/sys/rpc" ]]; then echo "$REPO_ROOT/freebsd-prepatch/sys/rpc"; return; fi
    echo "$fallback"
}

run_filter() {  # $1 = findings dir, $2 = src tree, $3 = out base dir
    local findings="$1" src="$2" outdir="$3"
    [[ -d "$findings" ]] || { echo "error: findings dir not found: $findings" >&2; exit 1; }
    [[ -d "$src" ]] || { echo "error: source tree not found: $src" >&2
        echo "       run scaffolding/fetch_freebsd.sh, or pass the tree as the last arg." >&2; exit 1; }
    local out="$outdir/reachability_filtered.md"
    echo "================================================================"
    echo "Reachability stage (our added pass)"
    echo "  Findings:  $findings  ($(ls "$findings"/*.md 2>/dev/null | wc -l | tr -d ' ') candidates)"
    echo "  Source:    $src"
    echo "  Model:     $MODEL"
    echo "  Out:       $out"
    echo "================================================================"
    python3 "$FILTER" "$findings" "$src" --out "$out"

    # copy the survivors (VALID) into findings-reachable/ for convenience
    local keep="$outdir/findings-reachable"
    rm -rf "$keep"; mkdir -p "$keep"
    grep -oE '\*\*VALID\*\* `[^`]+`' "$out" | sed -E 's/.*`([^`]+)`/\1/' | while read -r name; do
        [[ -f "$findings/$name" ]] && cp "$findings/$name" "$keep/"
    done
    echo "  survivors copied -> $keep  ($(ls "$keep" 2>/dev/null | wc -l | tr -d ' ') findings)"
}

# --- filter-only mode --------------------------------------------------------
if [[ "${1:-}" == "--filter-only" ]]; then
    FINDINGS="${2:-}"; [[ -n "$FINDINGS" ]] || { echo "usage: $0 --filter-only <findings-dir> [src-tree]" >&2; exit 1; }
    FINDINGS="$(cd "$(dirname "$FINDINGS")" && pwd)/$(basename "$FINDINGS")"
    SRC="$(resolve_src "${3:-}" "")"
    run_filter "$FINDINGS" "$SRC" "$(dirname "$FINDINGS")"
    exit 0
fi

# --- scan + filter mode (target = a .c file OR a directory) ------------------
TARGET="${1:-}"
[[ -n "$TARGET" && -e "$TARGET" ]] || { echo "usage: $0 <target.c | target-dir> [src-tree]   |   $0 --filter-only <findings-dir> [src-tree]" >&2; exit 1; }

NAME="$(basename "$TARGET" .c)"
if [[ -d "$TARGET" ]]; then FALLBACK_SRC="$(cd "$TARGET" && pwd)"; else FALLBACK_SRC="$(cd "$(dirname "$TARGET")" && pwd)"; fi
"$DEMO_DIR/bin/run-aisle.sh" "$TARGET"          # stages 1-3: AISLE scan.py (file or whole dir)
SCAN_OUT="$DEMO_DIR/results/aisle-${NAME}"
SRC="$(resolve_src "${2:-}" "$FALLBACK_SRC")"
echo
run_filter "$SCAN_OUT/findings" "$SRC" "$SCAN_OUT"   # stage 4: reachability
