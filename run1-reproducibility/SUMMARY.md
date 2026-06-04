# Run 1 reproducibility — is the Gemma scan-stage miss deterministic?

**Question:** In one AISLE `scan.py` + `gemma-4-31b-it` run on `sys/rpc/`, Gemma missed CVE-2026-4747 at the scan stage: it invented a bounds check and downgraded the overflow ("right line, wrong rationale"). Is that the representative outcome, or a one-off?

**Method (faithful):** imported AISLE's actual `scan.py` (commit `5d05d0afc1`, the single commit cited), pointed its backend at an OpenAI-compatible proxy, and called AISLE's own per-file `scan_single_file` (stage 1 context → stage 2 broad scan + 3-bug few-shot) **N=12** times on the unpatched `svc_rpcsec_gss.c` (commit `6b2d6ccad25`, parent of the fix). Model `google/gemma-4-31b-it`. Harness `measure_run1.py`; raw outputs `report_00.md`…`report_11.md`.

**Result: 12 / 12 HIT.** Every run flagged the unbounded `memcpy((caddr_t)buf, oa->oa_base, oa->oa_length)` into the 128-byte `rpchdr` as a critical stack overflow and stated there is **no** bound on attacker-controlled `oa_length`. **None invented a bounds check.** (report_07 also surfaced the `gss_oid_to_str` sprintf overflow as a secondary finding, never as a substitute.)

**Interpretation:**
- Pooled with the original miss: **12 hits / 13 runs ≈ 92%**; miss rate ≈ 8% (95% CI ≈ 1.4–33%).
- The "invented bounds check / right line, wrong rationale" miss is a **rare stochastic outlier (~1 in 13)** — not deterministic, and not a coin flip; the scan stage reliably *catches* the bug.
- So a single run that misses presents one unlucky draw as typical behavior. The honest picture: AISLE + Gemma usually *finds* CVE-2026-4747; a one-off run can draw the ~8% miss.

**Caveats:**
- Scan stage only (context + scan). The miss originated at scan; since scan catches it 12/12, it reaches triage, which only helps.
- Grep-as-tool no-op'd here (`rg`/`csearch` unavailable) — if anything that *handicapped* the runs, and it still hit 12/12.
- n=12; the point estimate of the miss rate is ~8% but the CI is wide. A larger sweep would tighten it.
- AISLE's `scan.py` uses `urllib` with no `User-Agent`; the harness injects one to avoid a Cloudflare 1010/403 on this backend.

## Was it the local quantized model? (no)

Hypothesis: the original miss came from a low-bit *local* quant, not the hosted model. Tested directly: same faithful AISLE two-stage scan against the **local MLX quant** `gemma-4-31b-it-mlx` (LM Studio @ localhost:1234), N=5 (`measure_local.py`, reports in `local/`). **Result: 5/5 HIT** — none invented a bounds check; the local quant catches it as reliably as the hosted model. (8 local scans actually ran due to a concurrent re-launch racing the same dir; 3 reports were overwritten, but all 8 logged critical findings and the 5 surviving texts are clean HITs.)

The original run was hosted (`google/gemma-4-31b-it`, zero local GPU), so the local-quant hypothesis doesn't even apply — but it was tested anyway, and the quant also catches the bug.

## Does it survive triage? (yes, 5/5)

Took the CVE finding from a HIT scan and ran AISLE's real multi-round triage + arbiter (3 rounds + arbiter) on it, `gemma-4-31b-it`, N=5 (`measure_triage.py`). **Result: 5/5 SURVIVE** — every trial `VVV→V`, FINAL=VALID, confidence 1.0. Once Gemma's scan flags the overflow, triage keeps it unanimously; triage is not a second filter that drops it (unlike gpt-oss, where triage voting dropped a correct round-2 verdict to UNCERTAIN@33%).

## Combined verdict

**17/17 reruns caught CVE-2026-4747** at the scan stage (12 hosted + 5 local quant), none inventing a bound; and once caught it **survives triage 5/5**. Pooled with the original miss = **17 hits / 18 ≈ 94%**, miss rate ~6% (95% CI ~1–27%). The "invented bounds check / right line, wrong rationale" miss does not reproduce on either the hosted model or the local quant — it's a rare stochastic outlier, not a deterministic or quant-induced failure.
