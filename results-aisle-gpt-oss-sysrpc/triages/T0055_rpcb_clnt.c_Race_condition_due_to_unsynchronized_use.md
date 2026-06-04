# Triage T0055: Race condition due to unsynchronized use of rpcb_clnt

- **File**: `rpcb_clnt.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Race condition due to unsynchronized use of rpcb_clnt

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The global CLIENT *rpcb_clnt is initialized once during system startup and never reassigned, so concurrent reads are safe. The CLNT_CALL macro expands to clnt_call(), which internally acquires a per‑CLIENT lock (or otherwise serializes access to the CLIENT structure) in NetBSD’s RPC implementation. Therefore concurrent invocations of rpcb_set() and rpcb_unset() do not corrupt the CLIENT state; the code is effectively thread‑safe. Because the claim of a race condition relies on the assumption that clnt_call has no locking, which is incorrect for NetBSD, the evidence does not demonstrate a real DoS or code‑execution vulnerability. Hence the finding is invalid.

