# Triage T0027: Potential integer overflow in retransmission timer calculation

- **File**: `clnt_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUU→I]

---

## Finding

Potential integer overflow in retransmission timer calculation

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** guarded retransmit_time < RPC_MAX_BACKOFF * hz keeps value < 60k, far below INT_MAX; retransmit_time is internal, no attacker influence

In clnt_dg_call the potential overflow of retransmit_time is guarded by a limit proportional to RPC_MAX_BACKOFF and hz. RPC_MAX_BACKOFF is a compile‑time constant set to 30 (or 1 in a special configuration). hz is the kernel tick frequency, which is a small integer (typical values are 100, 200, 1000). The product RPC_MAX_BACKOFF * hz is therefore at most 30 000 (or 1 000), far below 2^31. retransmit_time starts at tvtohz(&cu->cu_wait) (≈3 * hz), doubles each time only while < RPC_MAX_BACKOFF*hz, and stops after at most a few doublings. The maximum value it can reach is 2 * (RPC_MAX_BACKOFF*hz), e.g. 60 000, well within 32‑bit signed int range. Because retransmit_time is internally computed and not influenced by untrusted input, an attacker cannot trigger an overflow or exploit a negative value that would cause msleep to wake immediately. Consequently the integer overflow pattern does not pose a security risk.

The code has a defensive guard that effectively prevents overflow; therefore the scanner flag is a false positive.

Crux: the guard preserving retransmit_time < RPC_MAX_BACKOFF * hz bounds the value well below INT_MAX and retransmit_time is not derived from user data.



CRUX: guarded retransmit_time < RPC_MAX_BACKOFF * hz keeps value < 60k, far below INT_MAX; retransmit_time is internal, no attacker influence
GREP: RPC_MAX_BACKOFF

🔎 **Grep results:**

GREP `RPC_MAX_BACKOFF`:
```
sys/rpc/clnt_dg.c:64:#define	RPC_MAX_BACKOFF		1 /* second */
sys/rpc/clnt_dg.c:66:#define	RPC_MAX_BACKOFF		30 /* seconds */
lib/libc/rpc/clnt_dg.c:69:#define	RPC_MAX_BACKOFF		1 /* second */
lib/libc/rpc/clnt_dg.c:71:#define	RPC_MAX_BACKOFF		30 /* seconds */
sys/rpc/clnt_dg.c:670:			if (retransmit_time < RPC_MAX_BACKOFF * hz)
lib/libc/rpc/clnt_dg.c:504:			if (retransmit_time.tv_sec < RPC_MAX_BACKOFF)
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The code limits `retransmit_time` to `RPC_MAX_BACKOFF * hz` (30 × hz on most builds). Starting from 3 hz, it doubles only while less than this limit, so the maximum value it ever reaches is at most 30 hz (≈ 30 000 when hz ≈ 1000). Thus the signed 32‑bit `int` can never overflow in the doubling. The guard prevents the signed overflow that would otherwise produce a negative or zero value. Consequently the reported DoS scenario cannot occur as described. No other arithmetic in the retransmit logic can overflow in a way that would corrupt the sleep duration. Therefore the claim is not a real vulnerability.

