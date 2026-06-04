# Triage T0129: Thread‑local static allocation race in rpc_gss_get_mechanisms

- **File**: `rpcsec_gss/rpcsec_gss_conf.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IIU→I]

---

## Finding

Thread‑local static allocation race in rpc_gss_get_mechanisms

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** a data race on the uninitialized static pointer that cannot lead to memory corruption, data leakage, or denial of service, only a memory leak and possible stale data read – thus not a security vulnerability.

The code creates a static pointer `mech_names` that is lazily initialized without any locking. Two parallel callers could both see it as `NULL`, each allocate a new array, write the sentinel `NULL`, then write the pointer to the global variable – one allocation is leaked and the other wins. The race does not corrupt any memory or create an exploitable denial‑of‑service or data‑leak situation: the leaked allocation remains valid, each thread eventually obtains a stable list, and all subsequent accesses are read‑only. The loop that builds the array is self‑contained and does not write outside the bounds allocated. No attacker‑controllable input is used to influence any bounds or indices; the input is merely enumerated from the `kgss_mechs` list, which is internal. Therefore, while a true data race exists, it is a concurrency quality issue rather than a security vulnerability that an attacker can trigger for crash, code execution, or data corruption.

The only defense that could matter is the check `if (mech_names) return(mech_names);`. It merely prevents re‑initialization but does not guard against concurrent writes. No additional locking or bounds checks are used, so the race is unprotected, but it does not lead to a security‑relevant failure.

Hence the scanner’s flag is an FALSE POSITIVE in the security sense.

The core fact (crux) is that the race does not compromise correctness or security – it merely leaks memory and may temporarily expose stale data, but not a meaningful attack vector.

We confirmed the existence of the function and its callers, and there are no defensive checks that would change the assessment.

Conclusion: The vulnerability report is INVALID for security purposes.


CRUX: a data race on the uninitialized static pointer that cannot lead to memory corruption, data leakage, or denial of service, only a memory leak and possible stale data read – thus not a security vulnerability.
GREP: rpc_gss_get_mechanisms

🔎 **Grep results:**

GREP `rpc_gss_get_mechanisms`:
```
include/rpc/rpcsec_gss.h:154:const char **rpc_gss_get_mechanisms(void);
sys/rpc/rpcsec_gss.h:169:typedef const char **rpc_gss_get_mechanisms_ftype(void);
sys/rpc/rpcsec_gss.h:200:	rpc_gss_get_mechanisms_ftype	*rpc_gss_get_mechanisms;
sys/rpc/rpcsec_gss.h:313:rpc_gss_get_mechanisms_call(void)
sys/rpc/rpcsec_gss.h:317:	if (rpc_gss_entries.rpc_gss_get_mechanisms != NULL)
sys/rpc/rpcsec_gss.h:318:		ret = (*rpc_gss_entries.rpc_gss_get_mechanisms)();
sys/rpc/rpcsec_gss.h:458:const char **rpc_gss_get_mechanisms(void);
tools/regression/rpcsec_gss/rpctest.c:113:	mechs = rpc_gss_get_mechanisms();
tools/regression/rpcsec_gss/rpctest.c:299:	mechs = rpc_gss_get_mechanisms();
lib/librpcsec_gss/rpcsec_gss_conf.c:364:rpc_gss_get_mechanisms(void)
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:90:rpc_gss_get_mechanisms(void)
sys/kgssapi/gss_impl.c:284:		rpc_gss_entries.rpc_gss_get_mechanisms = rpc_gss_get_mechanisms;
```

### Round 2: ❌ INVALID

**🎯 Crux:** A data race that only causes a memory leak and possible brief stale reads; no attacker‑controlled input can influence the allocation or array contents, so no security impact exists.

The function rpc_gss_get_mechanisms lazily initializes a static pointer mech_names without any locking. Two threads can both observe mech_names == NULL, each allocate a fresh array, set the global pointer, leak the first allocation, and return the array of the winning writer. This is a classic data‑race that can cause a memory leak and, at worst, a stale pointer at a very narrow window. The array contents are built solely from the internal kgss_mechs list; no attacker‑controlled input influences the allocation size or the array indices.

The bug is a concurrency quality issue, not a security vulnerability. It does not lead to a denial‑of‑service, buffer overflow, information disclosure, or code execution. The libc‑provided memory allocator guarantees that a second allocation will not corrupt the first, and the array is never accessed before being fully constructed. Thus the race cannot be exploited to harm the system.

There is no defensive mechanism that could mitigate it; the code simply lacks a lock. Because the vulnerability cannot be triggered by untrusted input to achieve a security‑relevant outcome, it is considered an INVALID finding in a security sense.

To support this, we confirm the pointer is defined only inside the function and is only used there, and the function is called solely from internal or testing code.


CRUX: A data race that only causes a memory leak and possible brief stale reads; no attacker‑controlled input can influence the allocation or array contents, so no security impact exists.
GREP: static const char \*\*mech_names

🔎 **Grep results:**

GREP `static const char **mech_names (simplified to: mech_names)`:
```
lib/librpcsec_gss/rpcsec_gss_conf.c:59:static const char **mech_names;
lib/librpcsec_gss/rpcsec_gss_conf.c:225:	mech_names = malloc((count + 1) * sizeof(char*));
lib/librpcsec_gss/rpcsec_gss_conf.c:226:	pp = mech_names;
lib/librpcsec_gss/rpcsec_gss_conf.c:368:	return (mech_names);
crypto/krb5/src/appl/gss-sample/gss-client.c:418:    gss_OID_set mech_names;
crypto/krb5/src/appl/gss-sample/gss-client.c:477:                                              mechanism, &mech_names);
crypto/krb5/src/appl/gss-sample/gss-client.c:490:               (int) mech_names->count);
crypto/krb5/src/appl/gss-sample/gss-client.c:493:        for (i = 0; i < mech_names->count; i++) {
crypto/krb5/src/appl/gss-sample/gss-client.c:495:                                      &mech_names->elements[i], &oid_name);
crypto/krb5/src/appl/gss-sample/gss-client.c:505:        (void) gss_release_oid_set(&min_stat, &mech_names);
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:92:	static const char **mech_names = NULL;
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:96:	if (mech_names)
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:97:		return (mech_names);
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:105:	mech_names = malloc(count * sizeof(const char *), M_RPC, M_WAITOK);
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:108:		mech_names[count++] = km->km_mech_name;
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:110:	mech_names[count++] = NULL;
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:112:	return (mech_names);
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The race in rpc_gss_get_mechanisms merely causes two parallel callers to each allocate a separate array and overwrite the static pointer. One allocation is leaked, and the caller that returns the older allocation gets a valid pointer it owns; the global pointer ends up pointing to the newer array, which is otherwise constant. There is no memory corruption, no use‑after‑free, and attacker supplied data cannot influence the content or size of the arrays. The only effect is a memory leak and a very narrow window of stale global data that is not used by any code. Therefore, it is not a security vulnerability but simply a race that yields a leak/reliability issue.

