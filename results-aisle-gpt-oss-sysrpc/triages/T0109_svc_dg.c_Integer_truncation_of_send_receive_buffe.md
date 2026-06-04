# Triage T0109: Integer truncation of send/receive buffer sizes in svc_dg_create

- **File**: `svc_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Integer truncation of send/receive buffer sizes in svc_dg_create

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The parameters `sendsize` and `recvsize` are cast from `size_t` to `int` and passed to `__rpc_get_t_size`, but the resulting values are never stored or used in any subsequent buffer allocation or packet handling within `svc_dg_create` or the remainder of `svc_dg.c`.  The RPC buffer sizes are determined elsewhere (e.g., by the socket’s receive buffer or protocol defaults), not by these variables.  Therefore, truncating large values does not create a usable buffer overflow or other exploitable behavior, making the reported issue invalid.

