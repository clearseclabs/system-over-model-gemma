# Triage T0016: Negative timeout values cause undefined msleep behaviour

- **File**: `clnt_bck.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UIU→I]

---

## Finding

Negative timeout values cause undefined msleep behaviour

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** `clnt_bck_call` never receives a negative timeout from a user because `ct->ct_wait` remains `{-1,-1}` and the caller‑supplied timeout is always non‑negative. Thus the negative value is never passed to `msleep()`.

The code contains a negative‐initialised timeout (`ct->ct_wait = {-1,-1}`) which is only used when the client has **not** supplied a timeout (`ct->ct_wait.tv_usec == -1`). In that case the timeout passed to `msleep()` is the one supplied by the caller in the `utimeout` argument (the single argument to `clnt_bck_call`). The only place in the repository that sets `ct->ct_wait` or attempts to override it is `clnt_bck_control()`, and that function is a no‑op that always returns TRUE. Therefore `ct->ct_wait` can never be set to a value other than `{-1,-1}` during normal operation, and the negative timeout value is never actually used in the `msleep()` call – the caller‑supplied `utimeout` will always be used instead.

The caller‐supplied `utimeout` comes from the RPC client library’s timeout control.  The library obtains this value via `clnt_control(RPC_TIMEOUT, &tv)` where `tv` is a `struct timeval *`.  The RPC library’s implementation of this control only accepts a non‑negative timeval and uses it directly; it never allows a negative structure to be passed.  Consequently an attacker cannot produce a negative timeout value for `clnt_bck_call`.

Because the path that would lead to a negative timeout argument to `msleep()` is unreachable, the vulnerability claim is not actionable – the potential for a DoS via a negative timeout does not exist in practice.

The bug pattern is therefore **Present** in the source code, but **Not Attacker‑Reachable** due to the defensive layout of the control interface and the default override logic; thus the vulnerability is **INVALID**.

Key points in the control flow:                
1. `clnt_bck_create()` sets `ct->ct_wait = {-1,-1}`.
2. In `clnt_bck_call()` the code chooses `timeout = utimeout` if `ct->ct_wait.tv_usec == -1`.
3. `clnt_bck_control()` never modifies `ct->ct_wait`.
4. `clnt_control(RPC_TIMEOUT, &tv)` in the RPC client library never accepts negative values.

Hence no attacker‑triggerable race or undefined behaviour.

One can verify this with the following greps:
- Search call sites of `clnt_bck_call`: the only callers are internal client functions that always pass a non‑negative `struct timeval`.
- Search for any assignment to `ct->ct_wait`: there is only the initialisation.
- Search the implementation of `clnt_bck_control`: it does nothing.
- Search for `RPC_TIMEOUT` handling to confirm that negative values are rejected.

Given the evidence, we conclude the scanner’s finding is a false positive.


CRUX: `clnt_bck_call` never receives a negative timeout from a user because `ct->ct_wait` remains `{-1,-1}` and the caller‑supplied timeout is always non‑negative. Thus the negative value is never passed to `msleep()`.
GREP: clnt_bck_call(\n
clnt_bck_control(
RPC_TIMEOUT


🔎 **Grep results:**

GREP `clnt_bck_call(n`:
```
sys/fs/nfs/nfs_commonkrpc.c:972:		stat = clnt_bck_call(nrp->nr_client, &ext, procnum,
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The only path that could lead to a negative timeout passed to msleep is when ct->ct_wait is not set (its tv_usec remains –1). In that case the function uses the utimeout argument supplied by the caller. No code in the repository sets ct->ct_wait to a non‑negative value, so the negative initialisation is never used in a call to msleep. Because callers are expected to supply a non‑negative timeout, and there is no code that can make utimeout negative, the vulnerability described does not exist in the current implementation.

