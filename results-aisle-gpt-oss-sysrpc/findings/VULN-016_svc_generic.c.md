# VULN-016: Missing allocation‑failure handling for strdup in svc_tli_create

- **File**: `svc_generic.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Missing allocation‑failure handling for strdup in svc_tli_create

The code duplicates the network ID string with `strdup(nconf->nc_netid, M_RPC)` and assigns the result to `xprt->xp_netid` without checking whether the allocation succeeded. If `strdup()` returns NULL, `xprt->xp_netid` becomes NULL; subsequent code that expects a valid pointer may dereference it, leading to a kernel fault. An attacker could force a memory‑pressure situation to trigger repeated allocation failures.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] svc_tli_create calls `strdup(nconf->nc_netid, M_RPC)` and assigns the result to `xprt->xp_netid` without checking for NULL. If the allocation fails the kernel may still return a service handle whose `xp_netid` field is NULL. Subsequent RPC code that accesses `xp_netid` as a C‑string will dereference a NULL pointer, leading to a kernel fault. This is a non‑trivial allocation‑failure bug in the kernel that can be triggered under low‑memory conditions and therefore constitutes a real HIGH‑severity vulnerability.

