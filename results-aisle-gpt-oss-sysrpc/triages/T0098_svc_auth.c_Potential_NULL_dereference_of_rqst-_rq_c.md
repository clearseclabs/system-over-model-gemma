# Triage T0098: Potential NULL dereference of rqst->rq_clntcred in svc_getcred

- **File**: `svc_auth.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Potential NULL dereference of rqst->rq_clntcred in svc_getcred

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The `svc_getcred()` routine is invoked only after a successful authentication of the RPC request. For the `AUTH_UNIX` flavor the `_svcauth_unix()` routine (defined elsewhere in the NetBSD RPC stack) parses the credentials from the incoming message, allocates a `struct xucred`, copies the data, and stores a pointer to that structure in `rqst->rq_clntcred` *before* returning `AUTH_OK`. If the credentials are missing or malformed, `_svcauth_unix()` returns `AUTH_REJECTEDCRED`, and `svc_getcred()` is never called for that request. Therefore, under normal operation `rqst->rq_clntcred` will never be NULL when `svc_getcred()` executes, and the dereference is safe. No code path exists that would allow an attacker to trigger a NULL dereference that results in a kernel crash, so the reported vulnerability does not represent a real security flaw.

