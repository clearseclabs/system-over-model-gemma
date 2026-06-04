# Triage T0112: String length assumption in svc_dg_destroy

- **File**: `svc_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

String length assumption in svc_dg_destroy

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The code frees `xprt->xp_netid` using `strlen(xprt->xp_netid)+1`, which only would be unsafe if `xp_netid` could ever be a non‑NULL‑terminated string. In the NetBSD RPC implementation `xp_netid` is created by allocating a length‐of‐string plus one byte and copying a standard NUL‑terminated identifier (e.g., "udp", "tcp") into it. No code path in `svc_dg.c` or the standard RPC stack assigns a non‑terminated string to this field. Therefore the assumption is always satisfied, and the deallocation logic does not introduce a memory‑corruption exploit. The vulnerability claim is unsupported by evidence, thus the verdict is INVALID. 

