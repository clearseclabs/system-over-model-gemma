# system-over-model-gemma

Companion repo for the post **[System Over Model, Tested](https://clearbluejar.github.io/posts/system-over-model-tested-mythos-freebsd-local-openweight/)** — run
AISLE's vulnerability-scan pipeline against a model *you* can run, on a real FreeBSD bug
(CVE-2026-4747, a stack overflow in `svc_rpc_gss_validate`), and see where the work actually lives.

AISLE's thesis is that the scaffolding does more than the model. Testing that on local open-weight
models (`gemma-4-31b-it`, `gpt-oss-20b`), two things held up:

- **The model isn't the bottleneck.** A scan that "misses" the bug usually finds it on the next run —
  the failure was variance, not capability (`run1-/run2-reproducibility/`).
- **The system is.** On these models the pipeline graduates a pile of *false positives* — 30 "VALID"
  findings in one run, of which one was a real (unrelated) defect, and the CVE was not among them
  (the scan had missed it).

So the lever is the system, not the model. Add one stage — a reachability check, **same weights** —
and the noise drops: **30 false positives → 5, and the real CVE still passes.** That's
[`scaffolding/reachability_filter.py`](scaffolding/reachability_filter.py), and you can point it at
your own model and findings. (30→5 is the gain; 5 isn't 0 — you still verify the 5.)

Full numbers and verbatim model output: [`reachability-tweak/`](reachability-tweak/),
[`run1-reproducibility/`](run1-reproducibility/), [`RESULTS.md`](RESULTS.md). AISLE upstream; Apache-2.0.

## Requirements

- An **OpenAI-compatible endpoint** for your model (LM Studio, Ollama, vLLM, OpenWebUI, OpenRouter).
- **Python 3.9+**, **`rg`** (ripgrep — the filter uses it to find callers), **git ≥ 2.27** (fetch).
- AISLE's `scan.py` is upstream ([`weareaisle/nano-analyzer`](https://github.com/weareaisle/nano-analyzer)),
  not vendored here.

## Backend config

```bash
cp .env.example .env        # LM_BASE_URL + LM_API_KEY (OpenWebUI: OPENWEBUI_URL + OPENWEBUI_API_KEY)
export MODEL=google/gemma-4-31b-it   # or any model your endpoint serves
```

## See the system tweak recover the signal (~5 min)

The fastest path uses the run already captured here — no need to re-scan:

```bash
scaffolding/fetch_freebsd.sh                                   # pre-patch sys/rpc (vulnerable), ~19 MB
python3 scaffolding/reachability_filter.py \
    results-aisle-gemma-sysrpc/findings freebsd-prepatch/sys/rpc
# -> ~5 of the 30 "VALID" findings survive; the rest were never attacker-reachable.
```

To confirm it keeps a real bug, run it on the CVE finding too (`reachability-tweak/result-cve.md`
shows 5/5 kept).

To **start from scratch on your own model**, [`scan-demo/bin/scan-and-filter.sh`](scan-demo/bin/scan-and-filter.sh)
runs AISLE's `scan.py` *and* the reachability stage in one shot, using your `.env` backend (it derives
AISLE's `CUSTOM_BASE_URL`/`CUSTOM_API_KEY` for you; clone `scan.py` first, see Requirements). The target
is a single file **or** a whole directory:

```bash
scan-demo/bin/scan-and-filter.sh scan-demo/targets/vulnerable.c   # one file: scan + reachability
scan-demo/bin/scan-and-filter.sh freebsd-prepatch/sys/rpc         # the whole tree: the full sub-system run
scan-demo/bin/scan-and-filter.sh --filter-only results-aisle-gemma-sysrpc/findings   # re-filter a run you already have
```

Survivors land in `findings-reachable/`. For the scan only (no reachability stage), use
[`scan-demo/bin/run-aisle.sh`](scan-demo/bin/run-aisle.sh) — same file-or-directory target.

## What you'll see

| Stage | What happens on local models |
|---|---|
| **AISLE scan + triage** | Finds the bug *most* runs (a "miss" recovers on re-run); but graduates ~30 "VALID" findings, almost all false positives |
| **+ reachability filter** | 30 "VALID" → ~5 (≈83% fewer false positives), and the real CVE survives — one extra stage, same model |

It's a precision filter, not an oracle: the survivors still need a look (they're "reachable but
*bounded*" cases). The point isn't this particular filter — it's that **the system is the lever you
control, and you can change it for your model.** Details and the honest limits: `reachability-tweak/SUMMARY.md`.

## A note on running these models

- **`max_tokens` is a ceiling, not a target** — these models stop on their own well under it; with a
  ~256k context window neither inputs nor budgets bind. (A *reasoning* model given too small a cap can
  return empty content — that's the one case to bump.)
- **Hosted endpoints behind a proxy can return HTTP 524** (origin timeout) — intermittent and
  retryable; re-run and it clears.
- **Sanity-check a "great" result against a known true positive.** An early version of the filter
  looked *better* (30→2) — it was a truncation bug hiding the target function. The CVE keep-test caught it.

## Repository layout

```
.
├── README.md
├── RESULTS.md                       ← run-by-run writeup + verbatim model output
├── .env.example                     ← backend config template
├── scaffolding/
│   ├── fetch_freebsd.sh             ← fetch the pre-patch (vulnerable) FreeBSD sys/rpc tree
│   └── reachability_filter.py       ← the system tweak: a reachability stage that prunes false positives
├── results-aisle-gemma-sysrpc/      ← Run 1: AISLE scan.py + gemma @ sys/rpc (30 "VALID" findings)
├── results-aisle-gpt-oss-sysrpc/    ← Run 2: AISLE scan.py + gpt-oss @ sys/rpc (21 "VALID")
├── run1-reproducibility/            ← Gemma: the "miss" recovers on re-run (17/17 scan, 5/5 triage)
├── run2-reproducibility/            ← gpt-oss: works but less reliable (format, not reasoning)
├── reachability-tweak/              ← the filter: 30→5, CVE kept 5/5, + honest limits
├── 5-model-matrix/                  ← 5 local models, vuln-vs-patched discrimination (4/5)
├── clnt_nl-double-lock.md           ← the one real defect the funnel surfaced (unrelated FreeBSD bug)
├── scan-demo/                       ← run-aisle.sh (scan) + scan-and-filter.sh (scan + reachability); file or whole dir
└── freebsd-prepatch/                ← created by fetch_freebsd.sh (not committed)
```

## Credit

The pipeline, the three-stage recipe, and `scan.py` are Stanislav Fort / AISLE's work:
[*System Over Model*](https://aisle.com/blog/system-over-model-zero-day-discovery-at-the-jagged-frontier)
and [`weareaisle/nano-analyzer`](https://github.com/weareaisle/nano-analyzer). This repo tests them on
open-weight models and adds one stage. Apache-2.0, matching upstream.
