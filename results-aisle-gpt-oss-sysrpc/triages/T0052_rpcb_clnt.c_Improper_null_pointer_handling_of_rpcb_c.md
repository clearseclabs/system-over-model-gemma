# Triage T0052: Improper null‑pointer handling of rpcb_clnt global

- **File**: `rpcb_clnt.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Improper null‑pointer handling of rpcb_clnt global

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The global pointer `rpcb_clnt` is initialized by the `local_rpcb()` function during kernel startup and registered with the `SYSINIT` macro (SI_SUB_VFS, SI_ORDER_SECOND). `local_rpcb()` immediately performs `KASSERT(rpcb_clnt, ...)`, which will trigger a kernel panic if `client_nl_create()` returns NULL. Therefore, a functional kernel will never have `rpcb_clnt == NULL` when any part of the kernel calls `rpcb_set()` or `rpcb_unset()`. No subsequent code frees or resets this pointer, and there is no early‑boot race where user space could execute these functions before the init routine runs. Hence the reported null‑pointer dereference cannot occur in a normally booted kernel, and the claim of a real vulnerability is unfounded.

