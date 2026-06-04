# Triage T0130: Race condition and memory leak in mechanism caching

- **File**: `rpcsec_gss/rpcsec_gss_conf.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Race condition and memory leak in mechanism caching

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The race condition occurs during the one-time initialization of a static cache, leading to a memory leak, but lacks a viable path to a security-relevant crash or use-after-free in a typical kernel environment.

The function `rpc_gss_get_mechanisms` uses a static pointer `mech_names` and initializes it without any synchronization (locking). In a multi-threaded environment, concurrent calls to this function during the first invocation can lead to a race condition where `malloc` is called multiple times, causing a memory leak of the previously allocated pointers. However, the report claims this could lead to 'potential crashes' and 'use-after-free' if the `kgss_mechs` list changes. In most kernel GSS implementations (like FreeBSD's kgss), the list of available mechanisms is populated during boot or module load and is effectively static/read-only during the operational phase of the RPC service. Even if it were dynamic, the race condition on the initialization of a static cache is a classic 'benign' race or a code quality issue (small memory leak) rather than a security vulnerability, unless it can be leveraged for a crash or exploit. Given the context of RPCSEC_GSS, this function typically provides a list of supported mechanisms to the caller; a duplicate allocation here does not grant an attacker primitive for execution or privilege escalation.

CRUX: The race condition occurs during the one-time initialization of a static cache, leading to a memory leak, but lacks a viable path to a security-relevant crash or use-after-free in a typical kernel environment.
GREP: kgss_mechs

🔎 **Grep results:**

GREP `kgss_mechs`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The race condition on the static cache initialization causes a one-time memory leak, which is a code quality issue rather than a security vulnerability, and there is no evidence that the underlying mechanism list is dynamic enough to cause a UAF.

The function `rpc_gss_get_mechanisms` implements a lazy-initialization pattern for a static cache (`mech_names`) without synchronization. In a concurrent environment, multiple threads could enter the `if (!mech_names)` block, resulting in multiple calls to `malloc` and overwriting the static pointer, which causes a memory leak. However, for this to be a security vulnerability, it must lead to a crash or exploitable state. The report suggests a Use-After-Free (UAF) if `kgss_mechs` changes. 

First, the provided grep for `kgss_mechs` returned no results in the current repository context, but the code provided explicitly uses `LIST_FOREACH(km, &kgss_mechs, km_link)`. This suggests `kgss_mechs` is likely defined in an external header or the `kgss` framework. In kernel GSS implementations, the mechanism list is typically populated at boot or module load and remains static. Even if it were dynamic, the `mech_names` cache is never freed or updated; it is allocated once and persisted. If the underlying `km->km_mech_name` were freed, that would be a vulnerability in the `kgss` framework's lifecycle management, not in this caching function. 

Regardless, a race condition that causes a small, one-time memory leak during initialization (essentially a few pointers) is a code quality issue (a 'benign race'), not a security vulnerability. There is no path here to arbitrary code execution or a denial-of-service crash that an external attacker could reliably trigger to compromise the system.

CRUX: The race condition on the static cache initialization causes a one-time memory leak, which is a code quality issue rather than a security vulnerability, and there is no evidence that the underlying mechanism list is dynamic enough to cause a UAF.
GREP: kgss_mechs

🔎 **Grep results:**

GREP `kgss_mechs`:
```
sys/kgssapi/gssapi_impl.h:56:extern struct kgss_mech_list kgss_mechs;
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:100:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:107:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:51:struct kgss_mech_list kgss_mechs;
sys/kgssapi/gss_impl.c:61:	LIST_INIT(&kgss_mechs);
sys/kgssapi/gss_impl.c:121:	LIST_INSERT_HEAD(&kgss_mechs, km, km_link);
sys/kgssapi/gss_impl.c:129:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:143:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:156:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:170:	LIST_FOREACH(km, &kgss_mechs, km_link) {
```

### Round 3: ❌ INVALID

**🎯 Crux:** The race condition is a one-time initialization leak of a static cache, which is a code quality issue, and there is no evidence that the GSS mechanism list is dynamic enough to trigger a security-relevant UAF.

The reported vulnerability identifies a race condition in the lazy initialization of the `mech_names` static pointer in `rpc_gss_get_mechanisms`. If two threads enter the function simultaneously when `mech_names` is NULL, both may execute `malloc` and assign the result to `mech_names`, leading to a memory leak of the first allocation. In the context of a kernel, a one-time memory leak of a few pointers during early initialization is a code quality issue, not a security vulnerability. Regarding the potential for Use-After-Free (UAF), the `mech_names` array stores pointers to `km->km_mech_name`. The grep results show `kgss_mechs` is managed in `sys/kgssapi/gss_impl.c`. Typically, GSS mechanisms are registered at boot or module load and are not dynamically removed during runtime. Even if they were, the vulnerability would lie in the lifecycle management of the `kgss` framework, not the caching logic here. Because the 'crash' or 'UAF' claims are speculative and the only concrete bug is a trivial initialization race causing a small memory leak, this is marked as INVALID.

CRUX: The race condition is a one-time initialization leak of a static cache, which is a code quality issue, and there is no evidence that the GSS mechanism list is dynamic enough to trigger a security-relevant UAF.
GREP: kgss_mechs

🔎 **Grep results:**

GREP `kgss_mechs`:
```
sys/kgssapi/gssapi_impl.h:56:extern struct kgss_mech_list kgss_mechs;
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:100:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:107:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:51:struct kgss_mech_list kgss_mechs;
sys/kgssapi/gss_impl.c:61:	LIST_INIT(&kgss_mechs);
sys/kgssapi/gss_impl.c:121:	LIST_INSERT_HEAD(&kgss_mechs, km, km_link);
sys/kgssapi/gss_impl.c:129:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:143:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:156:	LIST_FOREACH(km, &kgss_mechs, km_link) {
sys/kgssapi/gss_impl.c:170:	LIST_FOREACH(km, &kgss_mechs, km_link) {
```

### Round 4: ❌ INVALID

[ARBITER] The race condition occurs during the lazy initialization of a static cache (`mech_names`). If multiple threads enter the `if (!mech_names)` block simultaneously, multiple calls to `malloc` will occur, and the static pointer will be overwritten, causing a one-time memory leak. In a kernel context, a small, one-time memory leak during initialization is a code quality issue, not a security vulnerability. Furthermore, there is no evidence that the `kgss_mechs` list is modified dynamically in a way that would lead to a use-after-free (UAF), as the cache stores pointers to names typically associated with static or long-lived mechanism structures.

