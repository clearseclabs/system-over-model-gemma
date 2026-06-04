# RESULTS — System Over Model, Tested

The numbers behind the post. Every claim here has a directory you can open: raw context,
scan, triage, and graduated `findings/` for each run, plus the re-run harnesses and their logs.

**Target:** CVE-2026-4747 / FreeBSD-SA-26:08 — a stack overflow in `svc_rpc_gss_validate`
(`sys/rpc/rpcsec_gss/svc_rpcsec_gss.c`). A `memcpy(buf, oa->oa_base, oa->oa_length)` copies an
attacker-controlled GSS token into a fixed 128-byte `rpchdr` with no bounds check. Pre-patch tree:
commit `6b2d6ccad25` (parent of the fix, `143293c14f8d`); `scaffolding/fetch_freebsd.sh` checks it out.

**Pipeline:** AISLE's `scan.py` as published — per-file context briefing → broad vuln-scan with
few-shot → multi-round triage with a grep-backed cross-model arbiter. Each file scanned independently.

**Models:** `google/gemma-4-31b-it` (Run 1) and `openai/gpt-oss-20b` (Run 2), both open-weight,
served over an OpenAI-compatible endpoint (OpenRouter for the bulk; a local 4-bit quant for the
re-run controls). No fine-tuning, no fork of `scan.py`.

---

## Run 1 — AISLE + gemma-4-31b @ `sys/rpc/`

`results-aisle-gemma-sysrpc/`

| | |
|---|---|
| Graduated to **VALID** | **30** findings |
| CVE-2026-4747 | **dropped at the scan stage** — not graduated |
| Real, attacker-reachable security bugs among the 30 | **0** |

The CVE didn't reach triage: at the scan stage the model reported the copy as *bounded*, asserting
a check that isn't in the source — a confident, fabricated "it's fine." That single run is what the
post opens on. (It does not reproduce — see *The misses recover* below.)

## Run 2 — AISLE + gpt-oss-20b @ `sys/rpc/`

`results-aisle-gpt-oss-sysrpc/`

| | |
|---|---|
| Graduated to **VALID** | **21** findings |
| CVE-2026-4747 | found at scan, then **UNCERTAIN** (≈33% triage vote) |
| Real, attacker-reachable security bugs among the 21 | **0** |

gpt-oss *did* surface the overflow at the scan stage, but multi-round triage couldn't hold it: the
verdict landed UNCERTAIN. The scariest graduated finding (VULN-001, an "auth bypass") is a false
positive — it analyzed the client-side reply validator, not the server dispatcher, which rejects
unknown flavors with `AUTH_REJECTEDCRED`.

---

## The misses recover

Both "misses" are single-run artifacts. Measured as a rate, the bug is there.

| Check | Result | Reading |
|---|---|---|
| Gemma — scan stage, re-run | **17 / 17 HIT** (12 hosted + 5 local 4-bit quant) | The Run-1 miss is ~1 unlucky draw in 18 |
| Gemma — triage on a HIT | **5 / 5 survive** | Triage doesn't lose it |
| gpt-oss — scan stage, re-run | **4 / 8 HIT** (~50%) | 2 misses were gpt-oss *echoing AISLE's few-shot example* (`example/net/parser.c`) instead of scanning the target |
| gpt-oss — triage on a HIT | **11 / 14 survive** (~79%) | Every drop is an **empty output** (reasoning budget exhausted → `''` → parser defaults UNCERTAIN), not reasoned doubt |
| 5 local models — vuln vs. patched pair, no hints | **4 / 5 discriminate** | The capability is common, not special |

Harnesses and logs: `run1-reproducibility/`, `run2-reproducibility/`, `5-model-matrix/`. The
takeaway the data supports: single-run detection is dominated by run-to-run variance and
output-format fragility (few-shot echo, reasoning-budget exhaustion), **not** model capability.

## The false positives

This is the real problem. Both runs graduate a pile, and almost none of it is real.

- **Run 1 — 30 VALID → 0 attacker-reachable security bugs.** I read all thirty against the source.
  ~11 are "summary" documents the funnel mistook for findings; the rest are false positives:
  kernel-set `sa_len`, `MAX_AUTH_BYTES` (=400) caps, dead code, privilege-gated daemons,
  `alloc == copy` sizes. Exactly one was a *real* defect — and it wasn't the CVE (next section).
- **Run 2 — 21 VALID → 0 security bugs.**

The funnel *feels* productive and is mostly noise. The bug I came for never made either list, and
when present it was never flagged any louder than the false positives around it. Roughly a **98%
false-positive rate** across both runs.

## The reachability tweak

`reachability-tweak/`, productized as `scaffolding/reachability_filter.py`

One extra stage, **same weights**: a reachability-strict arbiter that takes each VALID finding,
traces it back to an external entry point, greps for callers and constants, asks whether the cited
length is attacker-controlled or kernel-set, and rejects dead code / bounded / privileged-only paths.

| | |
|---|---|
| Run 1's 30 VALID | **→ 5 VALID, 25 INVALID** (~83% fewer false positives, 0 errors) — `result-30-fixed.md` |
| Real CVE finding through the same stage | **5 / 5 kept** — `result-cve.md`, every trial reconstructs *Network packet → svc_rpc_gss → svc_rpc_gss_validate* |

And it generalizes past Gemma. Run the same stage with **gpt-oss-20b judging its own 21 Run-2
findings** (`reachability-tweak/gpt-oss-run2/`): **21 → 4** (~81% fewer, 0 uncertain), and it **keeps
the CVE 5/5** when fed gpt-oss's own scan HIT — precision and recall intact on the second model.

| Model (own arbiter) | Funnel | After stage | FP cut | CVE kept |
|---|---|---|---|---|
| gemma-4-31b (Run 1) | 30 | 5 | ~83% | 5/5 |
| gpt-oss-20b (Run 2) | 21 | 4 | ~81% | 5/5 |

**30 → 5 is the gain; 5 ≠ 0 is the truth.** The five survivors are still false positives — VULN-008/016
(network-reachable but socket-buffer-bounded DoS), VULN-013 (`rpc_callmsg` `oa_length` capped at
`MAX_AUTH_BYTES`), VULN-018 (`m_pullup` self-bounds), VULN-021 (`rpctls` privileged-daemon source).
The arbiter checks *reachability* well but is weak on *reachable-but-bounded* DoS-class findings. It's
a **precision booster, not a verifier**: it turns a 30-item pile into a 5-item list. You still read the 5.

**Method caution (a running-local-models lesson).** An earlier version reported a too-good **30 → 2**.
That was a harness bug: the source was head-truncated to 16 KB, so functions deep in large files
(including `svc_rpc_gss_validate` at line 1166) fell outside the window and the model rejected them as
"not present." The **CVE keep-test caught it** (0/5, "the function is not in the provided source").
Fixed with a function-centered window (`reachability_filter.py:window()`). A tweak that drops your
known true positive isn't a win — always sanity-check against one.

## The one real defect

The funnel did surface a genuine bug — by accident, and unrelated to the CVE. Run 1's VULN-004 is a
double `rw_wlock` (should be `rw_wunlock`) self-deadlock in `clnt_nl_destroy`
(`sys/rpc/clnt_nl.c:467`). Verified real and **still in FreeBSD `main`** (introduced 2025-02-01,
commit `fa1b961259bc`). Not a security issue — privileged teardown path only, CWE-667. Write-up and
the fix diff: `clnt_nl-double-lock.md`. A candidate for an ordinary upstream FreeBSD report.

---

## Reproduce it

```bash
cp .env.example .env                                   # LM_BASE_URL + LM_API_KEY
export MODEL=google/gemma-4-31b-it                     # or any model your endpoint serves
scaffolding/fetch_freebsd.sh                           # pre-patch sys/rpc (vulnerable), ~19 MB

# fastest path — run the tweak on the captured Run-1 findings:
python3 scaffolding/reachability_filter.py \
    results-aisle-gemma-sysrpc/findings freebsd-prepatch/sys/rpc
# -> ~5 of the 30 "VALID" survive; the rest were never attacker-reachable.
```

To start from scratch on your own model: clone AISLE's `scan.py`
([`weareaisle/nano-analyzer`](https://github.com/weareaisle/nano-analyzer)), run it over
`freebsd-prepatch/sys/rpc`, then point `reachability_filter.py` at its `findings/`.

**Cost:** all of it — both runs, every re-run, retries and dead ends included — was ~10.8M tokens and
about **$12 on OpenRouter**, and **$0 if you run the model locally**.

## Credit

The pipeline, the three-stage recipe, and `scan.py` are Stanislav Fort / AISLE's work:
[*System Over Model*](https://aisle.com/blog/system-over-model-zero-day-discovery-at-the-jagged-frontier)
and [`weareaisle/nano-analyzer`](https://github.com/weareaisle/nano-analyzer). This repo tests them on
open-weight models and adds one stage. Apache-2.0, matching upstream.
