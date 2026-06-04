# scan-demo

A tiny, self-contained way to watch AISLE's `scan.py` run on **one file** — the single-file
baseline the post opens with, where each model confirms the `svc_rpc_gss_validate` overflow in
isolation before the full `sys/rpc/` hunt.

## What's here

```
scan-demo/
├── targets/
│   ├── vulnerable.c   # svc_rpc_gss_validate, pre-patch (has CVE-2026-4747)
│   └── patched.c      # svc_rpc_gss_validate, post-patch (the FreeBSD-SA-26:08 bounds check)
├── bin/
│   └── run-aisle.sh   # run AISLE scan.py on a target file
└── results/           # cached single-file scans the post links
    ├── nano-vulnerable.json           # gemma-4-31b-it on vulnerable.c — confirms the overflow
    └── nano-gptoss20b-vulnerable.json # gpt-oss-20b on vulnerable.c — same
```

The two `results/*.json` are the cached single-file scans quoted in the post: hand either model
just `svc_rpc_gss_validate` and it sees the unbounded `memcpy` into the 128-byte `rpchdr`. That's
the baseline — both models nail the bug in isolation; the interesting part is what happens at full
`sys/rpc/` scope (see the top-level `RESULTS.md`).

## Run it yourself

Backend config — any OpenAI-compatible endpoint:

```bash
cp ../.env.example ../.env            # OPENWEBUI_URL + OPENWEBUI_API_KEY, or LM_BASE_URL + LM_API_KEY
export MODEL=google/gemma-4-31b-it    # or openai/gpt-oss-20b, or any model your endpoint serves
```

AISLE's `scan.py` is upstream (not vendored here) — clone it and point `SCAN_PY` at it:

```bash
git clone https://github.com/weareaisle/nano-analyzer ../nano-analyzer
SCAN_PY=../nano-analyzer/scan.py ./bin/run-aisle.sh targets/vulnerable.c
```

You'll watch the three stages — context briefing, broad scan, then three triage rounds plus a
grep-backed arbiter — and a funnel banner at the end. Output lands in `results/aisle-vulnerable/`.

Run it on `targets/patched.c` too: the arbiter should **REJECT** the would-be overflow, citing the
bounds check. Same source, same model, different verdict — that's the scanner reading the code, not
pattern-matching the function name.

## Cost

A single-file scan is tiny — a few thousand input tokens, the triage rounds maybe 5–10× that.
Pennies on OpenRouter, free on a local server.
