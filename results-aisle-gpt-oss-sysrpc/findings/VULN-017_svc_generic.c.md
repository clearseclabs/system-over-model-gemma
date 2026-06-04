# VULN-017: Null pointer dereference caused by missing check on taddr in svc_tp_create

- **File**: `svc_generic.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Null pointer dereference caused by missing check on taddr in svc_tp_create

The function calls uaddr2taddr(nconf,uaddr) to obtain a pointer to a struct netbuf, but it does not verify that the returned pointer is non‑NULL. If uaddr2taddr() fails (e.g., due to allocation failure or malformed address string), the subsequent dereference `bind.addr = *taddr;` will trigger a kernel panic, causing denial‑of‑service. Because the function runs in kernel context, the crash can impair all RPC services.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] In svc_tp_create the code calls `taddr = uaddr2taddr(nconf, uaddr);` and immediately dereferences `taddr` with `bind.addr = *taddr;` without any NULL‑check.  The function `uaddr2taddr()` allocates a `struct netbuf` (via `M_RPC`) and returns NULL on failure (e.g., memory allocation failure or malformed address string).  If such a failure occurs, `taddr` becomes NULL and the dereference produces a null‑pointer bug in kernel context, causing a panic and a denial‑of‑service.  Because the dereference is unconditional, the code path is vulnerable whenever `uaddr2taddr()` can legitimately return NULL.  Therefore the evidence supports a real security flaw. 

