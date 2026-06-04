# VULN-002: NULL pointer dereference in getnetconfig()

- **File**: `getnetconfig.c`
- **Confidence**: 50% [UUV→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

NULL pointer dereference in getnetconfig()

The function casts the supplied handle to a struct netconfig ** and immediately dereferences it to obtain *nconfp. If the caller passes a NULL or otherwise invalid handle, the dereference causes a crash. Although the check `if (nconf->nc_netid == NULL)` protects against an uninitialized netconfig struct, it does not guard against a NULL *nconfp or a handle that does not point to a valid pointer-to-netconfig pointer returned by setnetconfig(). This is exploitable for a denial‑of‑service attack by causing a null‑pointer exception.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

The source shows that `getnetconfig(void *handle)` casts the supplied `handle` to `struct netconfig **` and immediately dereferences it (`nconf = *nconfp;`) without checking that `handle` is non-NULL or that it points to a valid allocator-backed pointer returned by `setnetconfig()`.  In the API, there is no defensive guard for a NULL or malformed handle.  Any userland code linking against this library can call `getnetconfig()` with an arbitrary or NULL value, causing a segmentation fault or a use‑after‑free if the caller previously freed the handle.

The function is part of the public RPC utility library (`setnetconfig()`, `getnetconfig()`, `endnetconfig()`).  The code that generates the handle (`setnetconfig()`) allocates memory with `M_WAITOK` and stores a pointer to a static `netconfigs` array. No further validation is performed when the handle is consumed.  Therefore, an attacker can trivially trigger the crash solely from userland input, i.e., by passing a NULL or garbage handle.

This is a classic denial‑of‑service (DoS) vulnerability: the attacker causes an invalid memory access that crashes the invoking process.  The vulnerability is externally reachable, real, and causes a crash, satisfying the criteria for a **VALID** vulnerability under the rules.

No defensive checks (e.g., `if (handle == NULL) ...)` exist in the implementation, and the only potential magic constant (`netconfigs` array) is statically defined; the bug is not mitigated by any size bounds or null checks.

Conclusion: The bug exists, is attacker‑reachable, and results in a crash – a meaningful security impact.  Hence the finding is **VALID**.

The crux is the absence of a null/garbage pointer check before dereferencing `handle` in `getnetconfig`.

The grep pattern "getnetconfig(" will locate the function definition and confirm the lack of defensive checks.

The result is a VALID vulnerability: attacker can supply a null or otherwise invalid handle to cause a crash.


CRUX: Null dereference in getnetconfig() caused by unvalidated handle, attacker can pass NULL or invalid handle to trigger a crash.
GREP: getnetconfig\(

### Round 4: ✅ VALID

[ARBITER] The implementation of `getnetconfig` blindly casts the supplied `void *handle` to `struct netconfig **` and immediately dereferences it (`nconf = *nconfp;`). There is no check that `handle` is non‑NULL or that it points to a valid heap‑allocated pointer returned by `setnetconfig`. Consequently, a caller can pass a NULL pointer or any arbitrary value, causing a segmentation fault when the function dereferences or accesses the `nc_netid` field of the resulting garbage pointer. This undefined‑behaviour path can be triggered by an attacker to cause a denial‑of‑service (crash) of any process that uses the library, and is therefore a real security vulnerability. No additional numeric data required to confirm the flaw—the source code itself demonstrates the unchecked dereference.}

