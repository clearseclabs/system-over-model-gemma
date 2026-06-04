# Triage T0078: Under‑write via negative size in rpcm_build()

- **File**: `rpcm_subs.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Under‑write via negative size in rpcm_build()

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The macro `rpcm_build()` obtains the size argument `s` from the caller and applies it directly to buffer bookkeeping. A negative value would indeed under‑decrement `mb->m_len` and move the data pointer backward, potentially overwriting kernel memory. However, in the context of the RPC subsystem `s` originates from server-side code that knows how many bytes it will serialize (not from any untrusted client input). Consequently a remote attacker cannot supply a negative `s` value. The negative value would only arise from an internal coding error, not from external input, and so the flaw does not translate into a real exploit or a true security vulnerability.

