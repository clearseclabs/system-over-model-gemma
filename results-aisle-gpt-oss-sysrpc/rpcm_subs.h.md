# Scan: rpcm_subs.h

```json
[
  {
    "severity": "high",
    "title": "Under‑write via negative size in rpcm_build()",
    "function": "rpcm_build",
    "description": "The macro accepts the length `s` directly from the caller. If an attacker supplies a negative value, the checks `if ((s) > M_TRAILINGSPACE(mb))` and `if ((s) > MLEN)` pass because a negative number cannot be greater than a positive space value. The code then updates `mb->m_len += s` (decreasing it) and blindly adjusts `bpos += s`, moving the data pointer backward into the buffer, potentially overwriting unrelated kernel memory and corrupting the mbuf chain. No bounds or sign checks are performed."
  },
  {
    "severity": "high",
    "title": "Signed overflow of mb->m_len in rpcm_build()",
    "function": "rpcm_build",
    "description": "The macro adds `s` to `mb->m_len` without validating that the result fits in the size type of `m_len`. A malicious user can supply a very large `s` (e.g. > INT_MAX – value of mb->m_len), causing signed overflow, which is undefined behavior. After overflow, the remaining space calculation can become incorrect, leading to subsequent writes past the end of the mbuf and possible memory corruption or arbitrary code execution."
  },
  {
    "severity": "medium",
    "title": "Assumed non‑NULL chain pointer in rpcm_dissect()",
    "function": "rpcm_dissect",
    "description": "The macro uses the global `md` and `dpos` directly, computing `mtod(md, caddr_t)+md->m_len-dpos`. If `md` is NULL or the current `md->m_next` is missing (e.g. because the incoming packet is truncated), the expression dereferences a NULL pointer or reads past the end of the mbuf chain. The caller usually performs sanity checks, but if they are bypassed or incorrectly implemented an attacker can cause a crash or memory corruption."
  },
  {
    "severity": "medium",
    "title": "Unvalidated pointer returned by rpcm_disct()",
    "function": "rpcm_dissect",
    "description": "When the requested size `s` does not fit in the current mbuf, the macro calls `rpcm_disct(&md, &dpos, (s), t1, &cp2)`. The helper may return a pointer `cp2` that lies outside the current mbuf chain (for example, past the end of the packet). The macro then casts this pointer to the desired type and assigns it to `a`. Subsequent code that interprets `a` as a pointer to a structured value can therefore read or write memory outside the intended bounds, leading to data leaks or memory corruption."
  },
  {
    "severity": "medium",
    "title": "Potential out‑of‑bounds advancement in rpcm_adv()",
    "function": "rpcm_adv",
    "description": "The macro advances the global read pointer `dpos` by `s` bytes. If the caller supplies a size `s` larger than the remaining bytes in the current mbuf and the helper `rpc_adv()` fails or returns 0, the macro will fall through to `dpos += (s)` regardless. If `dpos` points beyond the last mbuf, subsequent reads will dereference garbage, potentially causing a crash or information disclosure."
  }
]
```