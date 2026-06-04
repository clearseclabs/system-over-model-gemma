#!/usr/bin/env bash
# Run AISLE's nano-analyzer scan.py (the production 3-stage with multi-round
# triage and grep-as-tool) on a single target file. Output goes to
# scan-demo/results/aisle-<target>/ with findings/VULN-NNN.md, triages/, and a summary.
#
# Usage:
#   ./bin/run-aisle.sh targets/vulnerable.c
#   ./bin/run-aisle.sh targets/patched.c
#
# Inference endpoint comes from .env (OPENWEBUI_URL/OPENWEBUI_API_KEY or
# LM_BASE_URL/LM_API_KEY); AISLE's scan.py reads CUSTOM_BASE_URL / CUSTOM_API_KEY,
# which this script derives from those for you.
#
# Triage runs 3 rounds + arbiter, so expect ~5-10 min for a single file.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target.c | target-dir>" >&2
    echo "Examples:" >&2
    echo "  $0 targets/vulnerable.c       # scan one file" >&2
    echo "  $0 freebsd-prepatch/sys/rpc   # scan a whole directory (the full sub-system run)" >&2
    exit 1
fi

TARGET="$1"
if [[ ! -e "$TARGET" ]]; then
    echo "error: $TARGET not found" >&2
    exit 1
fi

# --- locate repo root (dir containing scaffolding/reachability_filter.py) ---
DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$DEMO_DIR"
while [[ "$REPO_ROOT" != "/" && ! -f "$REPO_ROOT/scaffolding/reachability_filter.py" ]]; do
    REPO_ROOT="$(dirname "$REPO_ROOT")"
done

# --- backend config: AISLE's scan.py reads CUSTOM_BASE_URL / CUSTOM_API_KEY ---
[[ -f "$REPO_ROOT/.env" ]] && { set -a; . "$REPO_ROOT/.env"; set +a; }
: "${CUSTOM_BASE_URL:=${LM_BASE_URL:-${OPENWEBUI_URL:+${OPENWEBUI_URL%/}/api}}}"
: "${CUSTOM_API_KEY:=${LM_API_KEY:-${OPENWEBUI_API_KEY:-}}}"
export CUSTOM_BASE_URL CUSTOM_API_KEY
export DISABLE_JSON_MODE=1

if [[ -z "${CUSTOM_BASE_URL:-}" || -z "${CUSTOM_API_KEY:-}" ]]; then
    echo "error: set CUSTOM_BASE_URL and CUSTOM_API_KEY (or LM_BASE_URL/LM_API_KEY, or" >&2
    echo "       OPENWEBUI_URL/OPENWEBUI_API_KEY) in the environment or $REPO_ROOT/.env" >&2
    exit 1
fi

MODEL="${MODEL:-google/gemma-4-31b-it}"
NAME="$(basename "$TARGET" .c)"
OUT_DIR="$DEMO_DIR/results/aisle-${NAME}"
mkdir -p "$OUT_DIR"

# --- locate AISLE's upstream scan.py (not vendored here) ---
# Override with SCAN_PY=/path/to/scan.py, or clone it into the repo as ./nano-analyzer/.
SCAN="${SCAN_PY:-$REPO_ROOT/nano-analyzer/scan.py}"
if [[ ! -f "$SCAN" ]]; then
    echo "error: AISLE scan.py not found at $SCAN" >&2
    echo "       It's the upstream production scanner — clone it and point SCAN_PY at it:" >&2
    echo "         git clone https://github.com/weareaisle/nano-analyzer \"$REPO_ROOT/nano-analyzer\"" >&2
    echo "         SCAN_PY=\"$REPO_ROOT/nano-analyzer/scan.py\" $0 $TARGET" >&2
    exit 1
fi

# AISLE wants a "repo dir" (the grep/caller scope) and a target. A directory target
# scans every file in it; a single file scans just that file (callers limited to it).
if [[ -d "$TARGET" ]]; then
    REPO_DIR="$(cd "$TARGET" && pwd)"
    PARALLEL="${PARALLEL:-4}"
    TRIAGE_PARALLEL="${TRIAGE_PARALLEL:-4}"
else
    REPO_DIR="$(cd "$(dirname "$TARGET")" && pwd)"
    PARALLEL="${PARALLEL:-1}"
    TRIAGE_PARALLEL="${TRIAGE_PARALLEL:-1}"
fi

cat <<EOF
================================================================
AISLE scan.py — 3-stage with multi-round triage
  Target:    $TARGET
  Model:     $MODEL
  Triage rounds: 3 + arbiter
  Output:    results/aisle-${NAME}/

Stage 1 (context):  per-file briefing
Stage 2 (vuln_scan): broad vulnerability scan
Stage 3 (triage):   3 separate triage rounds, each with grep-as-tool
                    verification, then a different-model arbiter resolves.

Watch the funnel banner at the end. Look for:
  - Critical/High/Medium severity counts at scan stage
  - Per-round verdicts in the [N/M] triage progress (V/U/I)
  - Final survivors in 'Findings that survived triage'

A single file is ~5-10 minutes; a whole directory is one pass per file
(the full sys/rpc tree is ~50 files).

================================================================

EOF

AISLE_ARGS=(-u "$SCAN" "$TARGET"
    --model "$MODEL"
    --parallel "$PARALLEL"
    --triage-rounds 3
    --triage-parallel "$TRIAGE_PARALLEL"
    --repo-dir "$REPO_DIR"
    --output-dir "$OUT_DIR"
    --project "scan-demo-${NAME}")
if command -v uv >/dev/null 2>&1; then
    uv run --with openai --with python-dotenv python "${AISLE_ARGS[@]}"
else
    python3 "${AISLE_ARGS[@]}"
fi

cat <<EOF

----------------------------------------------------------------
Done. Inspect:

  Triage survivors:
    bat results/aisle-${NAME}/triage_survivors.md

  Per-finding multi-round triage:
    ls results/aisle-${NAME}/findings/
    bat results/aisle-${NAME}/findings/VULN-001*.md

  All triage rounds:
    ls results/aisle-${NAME}/triages/
----------------------------------------------------------------
EOF
