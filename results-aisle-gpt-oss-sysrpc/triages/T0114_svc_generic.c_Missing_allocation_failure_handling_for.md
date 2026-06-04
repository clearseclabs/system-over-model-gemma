# Triage T0114: Missing allocation‑failure handling for strdup in svc_tli_create

- **File**: `svc_generic.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

Missing allocation‑failure handling for strdup in svc_tli_create

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] svc_tli_create calls `strdup(nconf->nc_netid, M_RPC)` and assigns the result to `xprt->xp_netid` without checking for NULL. If the allocation fails the kernel may still return a service handle whose `xp_netid` field is NULL. Subsequent RPC code that accesses `xp_netid` as a C‑string will dereference a NULL pointer, leading to a kernel fault. This is a non‑trivial allocation‑failure bug in the kernel that can be triggered under low‑memory conditions and therefore constitutes a real HIGH‑severity vulnerability.

