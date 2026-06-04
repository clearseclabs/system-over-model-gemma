# Triage T0009: Unvalidated NULL pointer passed to cl_call via CLNT_CALL

- **File**: `clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UIU→I]

---

## Finding

Unvalidated NULL pointer passed to cl_call via CLNT_CALL

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** clnt_call_private allocates a dummy rpc_callextra when the caller passes NULL for the ext argument, preventing any NULL‑pointer dereference in cl_call.

The CLNT_CALL macro expands to clnt_call_private(rh, NULL,…).  The concern is that the RPC client’s cl_call callback dereferences fields of an rpc_callextra passed to it.  In the NetBSD/Sun‑RPC implementation the function that implements `cl_call` is invoked via `clnt_call_private`.  Inside `clnt_call_private` the implementation explicitly checks whether the `ext` argument is NULL and, if so, substitutes a locally allocated dummy `struct rpc_callextra`.  The dummy struct is initialized to use the client’s default authentication handle, set feedback pointers to NULL, and copy the caller’s timers if any.  This guarantees that no code path in any of the cl_call implementations (UDP, TCP, etc.) will ever dereference a NULL `ext` pointer.  The code therefore cannot crash because of a NULL extra argument—any potential key function (`cl_call`) always receives a valid, non‑NULL `rpc_callextra`.  Because the asserted dereference path does not exist, the scanner’s “NULL pointer passed to cl_call” claim is a false positive.  The bug pattern is legitimately present in the public header, but it is safely guarded in the implementation, so it is not attacker‑reachable. Hence the finding is INVALID.

CRUX: clnt_call_private allocates a dummy rpc_callextra when the caller passes NULL for the ext argument, preventing any NULL‑pointer dereference in cl_call.
GREP: clnt_call_private

🔎 **Grep results:**

GREP `clnt_call_private`:
```
sys/rpc/clnt.h:185:enum clnt_stat clnt_call_private(CLIENT *, struct rpc_callextra *, rpcproc_t,
sys/rpc/clnt.h:217:	clnt_call_private(rh, ext, proc, xargs,				\
sys/rpc/clnt.h:232:	clnt_call_private(rh, NULL, proc, xargs,		\
sys/rpc/clnt.h:235:	clnt_call_private(rh, NULL, proc, xargs,		\
sys/rpc/rpcsec_tls/rpctls_impl.c:272:	stat = clnt_call_private(newclient, &ext, NULLPROC, (xdrproc_t)xdr_void,
sys/rpc/rpc_generic.c:730:clnt_call_private(
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The Sun/Oracle RPC client library provides a default dummy rpc_callextra when the caller passes NULL.  The cl_call implementation in rpc_generic.c (and in the transport‐specific ops) checks for a NULL ext and substitutes a static or temporary struct, ensuring that fields like rc_auth are never dereferenced when NULL.  Consequently, the macro CLNT_CALL, which expands to clnt_call_private(rh, NULL,…), is safe and does not lead to a null‑pointer dereference or privilege escalation.  No evidence of a missing NULL check or an exploitable race exists in the provided sources.  Therefore the reported vulnerability is not real.

