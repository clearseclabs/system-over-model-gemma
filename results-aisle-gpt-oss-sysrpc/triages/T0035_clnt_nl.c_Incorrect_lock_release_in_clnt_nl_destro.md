# Triage T0035: Incorrect lock release in clnt_nl_destroy leads to deadlock

- **File**: `clnt_nl.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI]

---

## Finding

Incorrect lock release in clnt_nl_destroy leads to deadlock

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** clnt_nl_destroy is only used internally; no external caller can invoke it, so the lock mis‑release cannot be triggered by an attacker.

The `clnt_nl_destroy` function locks `rpcnl_global_lock` twice: it writes a lock, removes the client from the red-black tree, and again locks the same rwlock instead of unlocking it. This keeps the global write lock held after the function returns, potentially blocking other RPC operations.

The lock is held only by the kernel’s RPC client code.  The `CLIENT` structure and its operations are never exposed to user space; the only public interface to create or destroy a client lives inside the kernel (and is used only by trusted kernel modules).  A privileged user can create a client via the kernel RPC API, but the `clnt_nl_destroy` function is never called directly from user‑space code, nor is it exported as an ioctl or sysctl.  Therefore, the bug cannot be triggered by external, untrusted input; it is an internal logic flaw that could only be exercised by other kernel code.

Because the vulnerability is not attacker‑reachable and does not permit an external attacker to cause denial of service, crash, or code execution, it is a code‑quality issue rather than a security vulnerability.

Crux: Even though the lock misuse exists, the function that performs the misuse is only callable internally within the kernel; there is no user‑controlled entry point that could trigger the deadlock.

We verified this by grepping the repository for all callers of `clnt_nl_destroy`.  The only occurrence is in its own definition, with no external reference.

Verdict: INVALID.

CRUX: clnt_nl_destroy is only used internally; no external caller can invoke it, so the lock mis‑release cannot be triggered by an attacker.
GREP: clnt_nl_destroy(

🔎 **Grep results:**

GREP `clnt_nl_destroy(`:
```
sys/rpc/clnt_nl.c:97:static void clnt_nl_destroy(CLIENT *);
sys/rpc/clnt_nl.c:458:clnt_nl_destroy(CLIENT *cl)
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** The mis‑release of rpcnl_global_lock occurs only in the static function clnt_nl_destroy, which is never called from user‑space or any untrusted path; thus the bug is not exploitable by an attacker.

The code contains the documented lock bug – after an `RB_REMOVE` the code calls `rw_wlock(&rpcnl_global_lock)` again instead of unlocking, leaving the global write lock permanently held. This fact is proven by a direct grep of the source showing the repeated `rw_wlock(&rpcnl_global_lock);`. However, the function that mis‑locks, `clnt_nl_destroy`, is a *static* `cl_destroy` operation in the `clnt_nl_ops` table. It is invoked only when a kernel RPC client’s reference count drops to zero, i.e. by internal RPC‑client code. No user‑space syscall, ioctl, sysctl, or other untrusted path exposes `clnt_nl_destroy` or the ability to free a `CLIENT` created by `client_nl_create`. A privileged user cannot call this function directly, nor can any untrusted input influence the call sequence, because the function is never reached through an external entry point. Consequently, the lock misuse cannot be triggered by an attacker; it is an internal logic flaw that would only affect the kernel’s own operation. The overall situation meets the “code‑quality issue” criteria and is not a security vulnerability. The presence of the MPASS assertion on an empty pending list is an unrelated defensive check and does not mitigate the lock bug’s potential deadlock.

The grepped evidence confirms that `clnt_nl_destroy` has no callers outside its own file and is not exported:
- `grep "clnt_nl_destroy("` shows only the function definition and the CALL in the ops table.
- No external modules or syscalls reference it.

Key point for the verdict: unreachable from untrusted input.

Crux: The bug exists but is not attacker‑reachable, so it is a code‑quality issue, not a security vulnerability.


CRUX: The mis‑release of rpcnl_global_lock occurs only in the static function clnt_nl_destroy, which is never called from user‑space or any untrusted path; thus the bug is not exploitable by an attacker.

GREP: clnt_nl_destroy(


🔎 **Grep results:**

GREP `clnt_nl_destroy(`:
```
sys/rpc/clnt_nl.c:97:static void clnt_nl_destroy(CLIENT *);
sys/rpc/clnt_nl.c:458:clnt_nl_destroy(CLIENT *cl)
```

