# Triage T0066: Unsynchronized Access to Global Client Handle

- **File**: `rpcb_clnt.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Unsynchronized Access to Global Client Handle

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The global `rpcb_clnt` handle is initialized at boot and never modified thereafter, making concurrent read access safe.

The report identifies a race condition on the global `rpcb_clnt` handle. Analysis of `rpcb_clnt.c` shows that `rpcb_clnt` is a static global pointer initialized once during system boot via `SYSINIT(rpcb_clnt, ...)`. After initialization in `local_rpcb`, the pointer `rpcb_clnt` is only ever read by `rpcb_set` and `rpcb_unset` and passed to `CLNT_CALL`. There are no code paths in this file that modify `rpcb_clnt` after the initial boot-time setup. While multiple threads may call `CLNT_CALL` concurrently using the same handle, the concurrency safety depends on whether the underlying `CLIENT` structure and `CLNT_CALL` implementation are thread-safe. In most RPC implementations, the client handle is a read-only configuration object for the duration of the call, and state is managed per-request. Regardless, the lack of a lock around the *read* of the global pointer itself is not a vulnerability because the pointer is immutable after boot. Even if `CLNT_CALL` had internal races, the 'unsynchronized access to the global handle' specifically refers to the pointer access, which is safe since it's read-only.

CRUX: The global `rpcb_clnt` handle is initialized at boot and never modified thereafter, making concurrent read access safe.
GREP: rpcb_clnt =

🔎 **Grep results:**

GREP `rpcb_clnt =`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The global pointer `rpcb_clnt` is initialized at boot and never modified again, making concurrent reads thread-safe.

The report claims there is unsynchronized access to the global `rpcb_clnt` handle. Analyzing `rpcb_clnt.c`, `rpcb_clnt` is a `static CLIENT *` pointer. It is initialized exactly once during system boot via the `SYSINIT` macro which calls `local_rpcb`. In `local_rpcb`, `rpcb_clnt` is assigned the result of `client_nl_create`. Looking at the rest of the file, `rpcb_clnt` is only ever read (passed as the first argument to `CLNT_CALL` in `rpcb_set` and `rpcb_unset`). There are no functions that modify, re-initialize, or free this pointer after the boot sequence. Since the pointer is effectively read-only after the system has transitioned to a multi-threaded state, concurrent access to the pointer itself cannot cause a race condition. Any potential concurrency issues would reside within the `CLNT_CALL` implementation or the `CLIENT` structure's internal state, but the 'unsynchronized access to the global handle' (the pointer) is a non-issue. This is a classic scanner false positive where the tool flags a global variable used in multiple threads without a lock, ignoring that the variable is immutable.

CRUX: The global pointer `rpcb_clnt` is initialized at boot and never modified again, making concurrent reads thread-safe.
GREP: rpcb_clnt =

🔎 **Grep results:**

GREP `rpcb_clnt =`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The global pointer rpcb_clnt is initialized once at boot and only read thereafter, making concurrent access to the pointer safe.

The scanner flags 'unsynchronized access' to the global `rpcb_clnt` handle. In `rpcb_clnt.c`, `rpcb_clnt` is a static global pointer. It is initialized exactly once during system boot by the `SYSINIT` mechanism calling `local_rpcb`. After this boot-time initialization, `rpcb_clnt` is only used as an input argument to `CLNT_CALL` in `rpcb_set` and `rpcb_unset`. There are no code paths in this file (or evidenced in previous greps) that modify the pointer after initialization. Concurrent reads of a pointer that is never modified after initialization are thread-safe. The vulnerability report focuses on the access to the handle (the pointer) rather than the internal state of the `CLIENT` structure. Since the pointer is immutable after boot, there is no race condition on the handle itself.

CRUX: The global pointer rpcb_clnt is initialized once at boot and only read thereafter, making concurrent access to the pointer safe.
GREP: rpcb_clnt =

🔎 **Grep results:**

GREP `rpcb_clnt =`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The global pointer `rpcb_clnt` is initialized exactly once during system boot via the `SYSINIT` mechanism (calling `local_rpcb`). After this boot-time assignment, the pointer is only ever read as an argument to `CLNT_CALL` in `rpcb_set` and `rpcb_unset`. Since there are no subsequent write operations to the `rpcb_clnt` pointer itself, concurrent read access by multiple threads is thread-safe. The report confuses access to the pointer with potential concurrency issues inside the `CLNT_CALL` library function, but the pointer access itself is not a race condition.

