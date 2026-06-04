# Gemma-4-31b on the patched function — is the matrix false-positive deterministic?

The five-model matrix recorded one `gemma-4-31b` run that "confirmed" a bug on the **patched**
`svc_rpc_gss_validate` — a false positive. Representative, or a single unlucky draw?

**Method:** ran `gemma-4-31b` on the patched (post-fix) function `svc_rpc_gss_validate_CLEAN.c`
— the version where the bounds check exists — at three temperatures, two trials each (N=6).

**Result: 6 / 6 REJECTED.** Every run correctly cleared the patched code. The signed-`int` premise
for `oa_length` shows up in the reasoning each time, but it does not flip the verdict — Gemma still
concludes the patch is safe.

| temperature | trial 1 | trial 2 |
|---|---|---|
| 0.0 | REJECTED | REJECTED |
| 0.3 | REJECTED | REJECTED |
| 0.7 | REJECTED | REJECTED |

So the matrix's single CONFIRMED was a stochastic outlier, the same single-run noise the rest of
this work documents: Gemma discriminates the patch correctly far more often than not.

Raw per-run output: `gemma31-T{00,03,07}-trial{1,2}.json` (T00 = temp 0.0, T03 = 0.3, T07 = 0.7).
