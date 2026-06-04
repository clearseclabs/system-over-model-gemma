# Triage T0118: Null pointer dereference caused by missing check on taddr in svc_tp_create

- **File**: `svc_generic.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

Null pointer dereference caused by missing check on taddr in svc_tp_create

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] In svc_tp_create the code calls `taddr = uaddr2taddr(nconf, uaddr);` and immediately dereferences `taddr` with `bind.addr = *taddr;` without any NULL‑check.  The function `uaddr2taddr()` allocates a `struct netbuf` (via `M_RPC`) and returns NULL on failure (e.g., memory allocation failure or malformed address string).  If such a failure occurs, `taddr` becomes NULL and the dereference produces a null‑pointer bug in kernel context, causing a panic and a denial‑of‑service.  Because the dereference is unconditional, the code path is vulnerable whenever `uaddr2taddr()` can legitimately return NULL.  Therefore the evidence supports a real security flaw. 

