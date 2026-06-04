# VULN-013: Uninitialised error structure may leak kernel data

- **File**: `clnt_vc.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Uninitialised error structure may leak kernel data

The `ct->ct_error` member of the client data is not zeroed when a new client is created.  If `clnt_vc_geterr` is called before any RPC has completed, the caller receives whatever garbage was in the allocated memory.  This can leak kernel addresses or other sensitive information to user space.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] In clnt_vc_create, the ct struct is allocated with mem_alloc, which does not zero the memory. The ct->ct_error field is never explicitly initialized or cleared before use. If a caller invokes clnt_vc_geterr (or via the higher‑level clnt_geterr API) on a freshly created CLIENT before any RPC has been sent, the returned rpc_err contains whatever bytes happened to be in that memory – potentially kernel addresses or other sensitive data. This is a real data‑leak vulnerability regardless of the library’s normal usage patterns. The evidence is clear from the code: ct->ct_error is never set except within error paths after a call, so the initial state is uninitialized.


