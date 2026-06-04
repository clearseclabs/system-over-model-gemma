# The reachability tweak — cutting the false-positive funnel (keeps the CVE)

**Problem:** AISLE's funnel graduated **30 "VALID" findings** on Run 1 (Gemma @ sys/rpc).
By hand, ~all were false positives and the actual CVE was dropped at scan. "Graduated" ≠ real.

**The tweak:** one extra **reachability-strict arbiter** stage on the *same* model
(`google/gemma-4-31b-it`) — trace from an external entry point, GREP for callers/constants, and
REJECT dead-code / kernel-set / upstream-bounded / privileged-only findings. Productized as a
self-contained, model-agnostic tool: `scaffolding/reachability_filter.py` (run it after AISLE's
`scan.py` on its `findings/`; no fork of scan.py). Raw outputs: `result-30-fixed.md`, `result-cve.md`
(earlier `result.txt` is the buggy run — see method note).

## Results

- **Keeps the real CVE: 5/5 VALID** (`result-cve.md`) — every trial reconstructs the correct path
  *"Network packet → svc_rpc_gss → svc_rpc_gss_validate."* **No recall loss on the true positive.**
- **Cuts the 30 false positives → 5** (`result-30-fixed.md`): 25 rejected, ~83% fewer FPs, 0 errors.
  Correctly killed every dead-code / kernel-set-`sa_len` / no-caller / privileged finding, and the
  real-but-not-attacker-reachable `clnt_nl.c` double-lock.

**Honest limit — the 5 survivors are still false positives** (verified by hand earlier):
`VULN-008`/`016` (DoS via record/`resid` — network-*reachable* but bounded by the socket buffer),
`VULN-013` (`rpc_callmsg` `oa_length` capped at `MAX_AUTH_BYTES`), `VULN-018` (`m_pullup` self-bounds),
`VULN-021` (`rpctls` privileged-daemon source). The arbiter checks **reachability** well but is weak on
**"reachable but *bounded*"** DoS-class findings. So it's a **precision booster, not a verifier** — it
turns a 30-item FP pile into a 5-item one, and you still check the 5.

## Method note (a "running local models" lesson)

The first run reported a too-good **30→2**. That was a harness bug: the source was head-truncated to
16 KB, so functions deep in large files (incl. `svc_rpc_gss_validate` at line 1166) weren't in the
window — the model said "function not present" and over-rejected. The **CVE keep-test caught it**
(0/5, with reasons like "the function is not in the provided source"). Fix: a **function-centered
window** (`reachability_filter.py:window()`) that guarantees the cited function is included. Re-run
gives the honest **30→5 / CVE 5/5** above. Lesson: a "great" local-model result can be a truncation
artifact — sanity-check with a known true positive.

## Second model: gpt-oss-20b (`gpt-oss-run2/`)

The same stage, gpt-oss judging its **own** 21 Run-2 findings: **21 → 4** (~81% fewer FPs, 0
uncertain), and it **keeps the CVE 5/5** when fed gpt-oss's own scan HIT (`gpt-oss-run2/result-cve-gptoss.md`).
The tweak isn't Gemma-specific — ~80% precision gain on both models, recall intact. (Bonus: as a
single-finding arbiter gpt-oss doesn't empty out the way its Run-2 triage *vote* did.) Details:
`gpt-oss-run2/SUMMARY.md`.
