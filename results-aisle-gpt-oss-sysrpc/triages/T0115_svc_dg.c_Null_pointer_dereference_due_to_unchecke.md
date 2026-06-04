# Triage T0115: Null pointer dereference due to unchecked allocation in svc_dg_create

- **File**: `svc_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Null pointer dereference due to unchecked allocation in svc_dg_create

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The dereference occurs immediately after `svc_xprt_alloc()` before any error handling. In NetBSD’s implementation `svc_xprt_alloc()` allocates the `SVCXPRT` structure with `M_WAITOK | M_ZERO`, which never returns `NULL` – it blocks until memory is available or the kernel panics. Therefore `xprt` will not be `NULL` when the code proceeds to `xprt->xp_lock`, and the reported null‑pointer dereference cannot actually happen. The “out‑of‑memory” error string is only used for a different failure path (`sosockaddr`), not for the allocation itself. Consequently, the reported vulnerability is not real in the current code base.

