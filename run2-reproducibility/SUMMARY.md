# Run 2 reproducibility — gpt-oss-20b (scan + triage), faithful AISLE scan.py via OpenRouter

Same protocol as Gemma's `run1-reproducibility`: AISLE's real `scan_single_file` /
`triage_finding` (commit `5d05d0afc1`), unpatched `svc_rpcsec_gss.c`, OpenRouter
`openai/gpt-oss-20b`. Harnesses: `measure_gptoss.py` (scan), `measure_gptoss_triage.py`.

## Scan: 4/8 HIT (~50%)

`scan/report_0[0-7].md`:
- **HIT** (correct critical `svc_rpc_gss_validate` rpchdr overflow, no invented bound): 00, 01, 05, 07.
- **MISS — echoed the few-shot example**: 02, 03. gpt-oss output a templated analysis of
  `example/net/parser.c` / `parse_packet` — *literally AISLE's `FEWSHOT_EXAMPLE` block* — instead
  of analyzing the FreeBSD file. A model-specific catastrophic failure Gemma never showed.
- **MISS — didn't flag the rpchdr overflow**: 04, 06.

Contrast: Gemma scanned this file **17/17** clean.

## Triage: 11/14 survive (~79%) — but every "drop" is an empty-output parse failure, not reasoning

Two runs, 3 rounds + arbiter each on a confirmed HIT finding (`measure_gptoss.py` Part B on
report_00, N=8; `measure_gptoss_triage.py` on report_01, N=6):
```
run A (report_00, 7/8): UUV→V, UUU(drop), UUU→V, UVU→V, UUU→V, UUV, UUV, UUV→V
run B (report_01, 4/6): UUU→V, VUU→(unparsed,drop), UUU→(unparsed,drop), UUU→V, UVU→V, UUU→V
```
Rounds are overwhelmingly `U`; the 3 DROPs are `UUU`/`(unparsed)` — empty/unparsed verdicts. **Confirmed root
cause:** a raw triage call returns **empty content** (`''`) with **981 reasoning tokens / 974
completion tokens** — the reasoning track consumes the whole output budget, leaving nothing for the
verdict, so `_extract_json` fails and the harness defaults to UNCERTAIN. So gpt-oss's "stochastic
UNCERTAIN votes" are **reasoning-budget-exhaustion / empty-output parse failures**, not the model
reasoning the bug is uncertain. When it emits content (the arbiter, 4/6), it says VALID. Matches
AISLE's published "2-of-3" and the cached Run-2 trace's "no rationale captured" UNCERTAIN rounds.

## Takeaway

gpt-oss's failures at **both** stages are **format/tooling fragility**, not security-reasoning
failures: few-shot echo at scan, empty-output (reasoning exhaustion) at triage. When gpt-oss
actually produces an answer, it is correct (HIT scans correct; arbiter VALID). The harness has to
handle the model's output format (reasoning-token budgets / harmony tokens) — that's the real
"system" gap, and it's model-specific.

## Combined (both models)

| | Gemma-4-31b-it | gpt-oss-20b |
|---|---|---|
| scan catches CVE | 17/17 (~100%) | 4/8 (~50%; 2 few-shot echoes) |
| triage survives (HIT finding) | 5/5 | 11/14 (~79%; every drop = empty-output parse fail) |
| original "miss" was… | a ~6% stochastic fluke | format fragility (echo + empty triage), not bad reasoning |

The post's "out of the box both missed; two tweaks fixed it" is unsupported. The data supports a
stronger thesis: **single-run detection is dominated by run-to-run variance and model-output-format
fragility, not model capability — measure the rate, fit the harness to the model's format, and
verify findings (the funnel was ~98% false-positive).**
