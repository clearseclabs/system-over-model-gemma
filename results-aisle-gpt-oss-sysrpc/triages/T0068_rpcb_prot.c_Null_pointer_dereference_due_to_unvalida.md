# Triage T0068: Null pointer dereference due to unvalidated rp argument

- **File**: `rpcb_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Null pointer dereference due to unvalidated rp argument

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] Both `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` are internal XDR helper functions that receive a pointer-to-pointer argument (`rpcblist_ptr *rp`, `rpcb_entry_list_ptr *rp`). In normal operation the caller allocates a local variable such as `rpcblist_ptr list = NULL;` and passes the address of that variable (`&list`). The code assumes that the address argument itself is never `NULL`. If an attacker could supply a NULL pointer for this argument, the dereference of `*rp` would indeed crash (e.g., the assignment `more_elements = (bool_t)(*rp != NULL);`). However, the XDR API is not intended to be called with a NULL pointer argument; all invocations in the NetBSD rpcbinder are performed by trusted internal code that always supplies a valid address. There is no publicly documented API surface that allows arbitrary callers to invoke `xdr_rpcblist_ptr` or `xdr_rpcb_entry_list_ptr` with a NULL pointer. Consequently, the observed null‑pointer dereference is not a realistic attack vector in the context of the rpcbinder and does not constitute a viable denial‑of‑service vulnerability.

The reviewers’ earlier “UNCERTAIN/INVALID” assessments are consistent with this conclusion: the code itself does not guard against a NULL `rp`, but legitimate callers never pass a NULL pointer. Therefore the claim of a real vulnerability is unsubstantiated.


