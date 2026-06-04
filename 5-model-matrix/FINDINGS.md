# Findings — Local-model reproduction of CVE-2026-4747

Ten runs across five model configurations, two patch states each. Clean target files (no CVE hints, just the C with a BSD license header), local LM Studio, ~29 minutes wall clock.

## Headline

**Four of five local configurations correctly discriminated vulnerable from patched code with no CVE hint in the prompt.** Three cited the exact root cause: an unchecked `memcpy(buf, oa->oa_base, oa->oa_length)` into a 128-byte `rpchdr` stack buffer. On a single local-class workstation, that reproduces AISLE's "Jagged Frontier" claim — open-weight local models can find real bugs in system code when orchestrated correctly.

## Result table

| Config | Post-patch verdict | Pre-patch verdict | Discriminates | Wall clock (post/pre) |
|---|---|---|---|---|
| gpt-oss-20b × 3 | REJECTED | LIKELY_REAL | ✅ | 42 s / 46 s |
| qwen3.5-35b think-on + gpt-oss arbiter | REJECTED | CONFIRMED | ✅ | 174 s / 133 s |
| qwen3.5-35b `/no_think` + gpt-oss arbiter | REJECTED | CONFIRMED | ✅ | 128 s / 122 s |
| gemma-4-31b × 3 | **CONFIRMED (false positive)** | CONFIRMED | ❌ | 442 s / 417 s |
| gemma-4-26b-a4b abliterated + gpt-oss arbiter | REJECTED | CONFIRMED | ✅ | 82 s / 82 s |

Four right, one wrong — and the wrong one is identifiable by its hallucination pattern.

## What the three correct pre-patch verdicts said

All three cite the exact bug, an unchecked `memcpy` into a 128-byte stack buffer, with the CVE hint removed:

**gpt-oss-20b × 3:**
> The code copies `oa->oa_length` bytes into a 128-byte stack buffer (`rpchdr[32]`) without any bounds check. If the caller can supply a credential length > 128, `memcpy()` will write past the end of `rpchdr`, corrupting adjacent stack data.

**qwen3.5 think-on:**
> The function builds a 128-byte stack buffer (`rpchdr`). It writes 8 XDR fields (32 bytes) before copying the credential. No bounds check is performed on `oa->oa_length`. If an attacker sends a credential longer than 96 bytes, the subsequent `memcpy` overruns the stack buffer.

**gemma-4-26b abliterated:**
> The function builds a fixed-size 128-byte stack buffer (`rpchdr`). It writes a header that occupies ~32 bytes, then copies `oa->oa_length` bytes from the caller-supplied opaque credential into that buffer without any bounds check. If `oa->oa_length` exceeds the remaining space (≈96 bytes), `memcpy()` will overflow the stack buffer.

## The failure mode on gemma-4-31b

gemma-4-31b confirmed the bug on **both** arms. On the post-patch file (where the bounds check exists and is sufficient), its triage reasoning was:

> In FreeBSD's RPC implementation the `struct opaque_auth` defines `oa_length` as a signed `int`. [...] Because `oa_length` is a signed integer, any negative value will satisfy the condition `(negative_value > 96) == false`, thereby bypassing the security check.

**That type fact is wrong** — `oa_length` is `u_int` (unsigned) in the actual FreeBSD source. The model invented a premise that would make the code vulnerable, then concluded it was vulnerable. The lesson: cross-model disagreement is the signal. A finding only one model confirms, on reasoning that hinges on a specific claim about a type or constant, is a hallucination candidate.

## Notes

- **`/no_think` didn't hurt accuracy.** qwen3.5 with `/no_think` reached the same verdicts as with thinking on, marginally faster.
- **The smallest model was the fastest and correct.** gemma-4-26b-a4b (4B active in an MoE config) discriminated correctly in ~82 s using zero reasoning tokens.
- **Single-file scope.** This confirms a *known* bug (pre-patch) and confirms the *official fix* holds (post-patch) — both useful, but not the same as discovering new bugs at scale, which needs multi-file runs.
