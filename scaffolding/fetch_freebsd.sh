#!/usr/bin/env bash
# fetch_freebsd.sh — fetch the FreeBSD sys/rpc tree at the PRE-PATCH (vulnerable)
# revision for CVE-2026-4747, into ./freebsd-prepatch/.
#
# CVE-2026-4747 (FreeBSD-SA-26:08) was fixed upstream in commit
#   143293c14f8d  "rpcsec_gss: Fix a stack overflow in svc_rpc_gss_validate()"
# so the last vulnerable tree is that commit's parent:
#   6b2d6ccad2552e46a5c9c3ba70b2d0ed27c70ca8
# We pin to the parent and sparse-checkout only sys/rpc (~50 files, ~19 MB) — the
# sub-system scope used in the post. Cloning current main would get the *patched*
# tree (the bounds check is already there) and would not reproduce the finding.
#
# Usage:
#   ./fetch_freebsd.sh                        # -> ./freebsd-prepatch  (pre-patch sys/rpc)
#   ./fetch_freebsd.sh /tmp/freebsd-prepatch  # custom destination
#   FREEBSD_SPARSE="sys" ./fetch_freebsd.sh   # widen scope to the whole kernel tree (large)
#   FREEBSD_COMMIT=main ./fetch_freebsd.sh    # fetch the PATCHED tree instead (for A/B)
#
# Requires: git >= 2.27 (partial clone + cone-mode sparse-checkout).

set -euo pipefail

DEST="${1:-./freebsd-prepatch}"
REMOTE="${FREEBSD_REMOTE:-https://github.com/freebsd/freebsd-src.git}"
# Parent of the CVE-2026-4747 fix commit = last vulnerable revision.
PREPATCH_COMMIT="6b2d6ccad2552e46a5c9c3ba70b2d0ed27c70ca8"
COMMIT="${FREEBSD_COMMIT:-$PREPATCH_COMMIT}"
SPARSE="${FREEBSD_SPARSE:-sys/rpc}"
VULN_FILE="sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"

if [[ -e "$DEST/.git" ]]; then
    echo "[info] $DEST already initialized; re-fetching $COMMIT"
else
    echo "[info] init partial clone of $REMOTE -> $DEST"
    git init -q "$DEST"
    git -C "$DEST" remote add origin "$REMOTE"
fi

git -C "$DEST" config extensions.partialClone origin
git -C "$DEST" sparse-checkout init --cone
# shellcheck disable=SC2086  # intentional word-split: SPARSE may list several paths
git -C "$DEST" sparse-checkout set $SPARSE

echo "[info] fetching $COMMIT (blobless, depth 1, sparse: $SPARSE)…"
git -C "$DEST" fetch -q --depth 1 --filter=blob:none origin "$COMMIT"
git -C "$DEST" checkout -q FETCH_HEAD

# --- verify we actually got the vulnerable tree ---
f="$DEST/$VULN_FILE"
if [[ "$COMMIT" == "$PREPATCH_COMMIT" && -f "$f" ]]; then
    if grep -q "oa->oa_length > sizeof(rpchdr)" "$f"; then
        echo "[WARN] bounds check present in $VULN_FILE — this looks PATCHED, not vulnerable." >&2
    elif grep -q "memcpy((caddr_t)buf, oa->oa_base, oa->oa_length)" "$f"; then
        echo "[ok] pre-patch confirmed: unchecked memcpy present, no upper-bound check on oa_length."
    else
        echo "[WARN] could not confirm the vulnerable pattern in $VULN_FILE" >&2
    fi
fi

n=$(find "$DEST/sys/rpc" \( -name '*.c' -o -name '*.h' \) 2>/dev/null | wc -l | tr -d ' ')
size=$(du -sh "$DEST" 2>/dev/null | cut -f1)
echo
echo "Done. $DEST ($size); sys/rpc has $n source files."
echo "Scopes for the scan:"
echo "  T1 (neighborhood):  $DEST/sys/rpc/rpcsec_gss/"
echo "  T2 (sub-system):    $DEST/sys/rpc/          <- the post's scope"
echo
echo "Run the analyzer, e.g.:"
echo "  python nano_analyzer_lite.py $DEST/sys/rpc --recursive --max-files 100 \\"
echo "      --models context=\$MODEL,vuln_scan=\$MODEL,triage=\$MODEL"
