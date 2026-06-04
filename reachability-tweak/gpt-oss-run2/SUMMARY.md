# Reachability stage on gpt-oss-20b's Run-2 funnel (does the tweak generalize?)

The reachability filter was first shown on **Gemma's** Run-1 funnel (30 → 5, ~83% fewer false
positives, CVE kept 5/5). This is the second-model check: same `scaffolding/reachability_filter.py`,
**gpt-oss-20b as its own arbiter**, pointed at **gpt-oss's own 21 graduated Run-2 findings**
(`results-aisle-gpt-oss-sysrpc/findings/`).

## Result: 21 → 4 VALID, 17 INVALID, 0 uncertain/err (~81% fewer)

`result-gptoss-arbiter.md`, `run-gptoss-arbiter.log`. Same shape as Gemma's 30→5. The stage is not
Gemma-specific — one extra reachability pass cuts the false-positive pile on the second model too.

**gpt-oss did NOT empty out as an arbiter** (0 uncertain/err across all 21). Its reasoning-budget
fragility — the empty-output failures that sank the Run-2 *triage vote* (`run2-reproducibility/`) — is
specific to the multi-round triage stage, not to focused single-finding arbitration. When the task is
"judge this one finding," gpt-oss emits a parseable verdict every time.

Rejections are reachability-aware, not random:
- **Dead code (no callers):** `getnetconfig`, `rpcm_dissect` macro, `clnt_reconnect_create`, `svc_tp_create`
- **Kernel-set / not attacker-controlled:** `clnt_dg` svcaddr, `clnt_nl` args, `rpctlssd` privileged-daemon gid, server-generated response lengths
- **OOM-only NULL derefs:** `gd_principal` strdup, `authunix_destroy`

## Honest limits (same as the Gemma run)

1. **The 4 survivors are still false positives.** Run 2's 21 findings were hand-checked as **0 real
   attacker-reachable security bugs**, so there was no true positive to keep here — the 4 kept
   (`VULN-004/007/008/019`) are "reachable-looking but bounded/not-real" cases the pass doesn't catch.
   Precision booster, not verifier — you still read the 4.
2. **The 21→4 measures FP-cut only — the CVE wasn't in that funnel.** It died UNCERTAIN in Run 2's
   triage vote (an empty-output artifact, see `run2-reproducibility/`), so it never reached gpt-oss's
   `findings/`. Fed gpt-oss's *own* scan HIT of the CVE directly, though, the stage **keeps it 5/5**
   (`result-cve-gptoss.md`, gpt-oss as arbiter, 0 rejected) — every trial reconstructs the
   network → `svc_rpc_gss_validate` path. So precision *and* recall hold on the second model too.

## Both models, the tweak side by side

| Model (as its own arbiter) | Graduated funnel | After reachability stage | FP cut | CVE kept |
|---|---|---|---|---|
| gemma-4-31b-it (Run 1) | 30 VALID | 5 VALID | ~83% | 5/5 |
| gpt-oss-20b (Run 2) | 21 VALID | 4 VALID | ~81% | 5/5 |

One extra stage, same weights, both models: ~80% of the false-positive pile gone. The survivors still
need a human — the stage makes the list readable, it doesn't verify.
