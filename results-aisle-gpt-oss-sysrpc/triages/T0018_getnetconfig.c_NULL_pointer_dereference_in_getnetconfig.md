# Triage T0018: NULL pointer dereference in getnetconfig()

- **File**: `getnetconfig.c`
- **Verdict**: VALID
- **Confidence**: 50% [UUV→V]

---

## Finding

NULL pointer dereference in getnetconfig()

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

**🎯 Crux:** Null dereference in getnetconfig() caused by unvalidated handle, attacker can pass NULL or invalid handle to trigger a crash.

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

🔎 **Grep results:**

GREP `getnetconfig(`:
```
include/netconfig.h:112:struct netconfig *getnetconfig(void *);
sys/rpc/netconfig.h:82:struct netconfig *getnetconfig(void *);
usr.sbin/ypserv/yp_main.c:533:	while((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:650:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:722:		while ((nconf = getnetconfig(nc_handle))) {
contrib/tcp_wrappers/tli.c:206:    while (config = getnetconfig(handlep)) {
contrib/tcp_wrappers/tli.c:226:     * Something else may clobber our getnetconfig() result, so we'd better
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:290:	while ((nconf = getnetconfig(localhandle)) != NULL) {
usr.sbin/rpcbind/rpcbind.c:218:	while ((nconf = getnetconfig(nc_handle))) {
lib/libc/rpc/crypt_client.c:56:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/getnetconfig.c:140: * getnetconfig() to parse the file.  Each call to getnetconfig() using the
lib/libc/rpc/getnetconfig.c:142: * setnetconfig() must be called before the first call to getnetconfig().
lib/libc/rpc/getnetconfig.c:193: * When first called, getnetconfig() returns a pointer to the first entry in
lib/libc/rpc/getnetconfig.c:195: * call, getnetconfig() returns a pointer to the next entry in the database.
lib/libc/rpc/getnetconfig.c:196: * getnetconfig() can thus be used to search the entire netconfig file.
lib/libc/rpc/getnetconfig.c:197: * getnetconfig() returns NULL at end of file.
lib/libc/rpc/getnetconfig.c:201:getnetconfig(void *handlep)
lib/libc/rpc/getnetconfig.c:418:     * getnetconfig(), then copy this entry into a buffer and return it.
lib/libc/rpc/rpc_soc.c:462:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/rpcb_clnt.c:471:		while ((nconf = getnetconfig(nc_handle)) != NULL) {
lib/libc/rpc/rpcb_clnt.c:653:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/key_call.c:367:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/getnetpath.c:158:	    if ((ncp = getnetconfig(np_sessionp->nc_handlep)) == NULL) {
lib/libc/rpc/rpc_generic.c:240:		while ((nconf = getnetconfig(confighandle)) != NULL) {
lib/libc/rpc/rpc_generic.c:339:			nconf = getnetconfig(handle->nhandle);
usr.sbin/rpc.lockd/lockd.c:307:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:326:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:398:		while ((nconf = getnetconfig(nc_handle))) {
lib/libypclnt/ypclnt_passwd.c:85:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:168:	while ((nc = getnetconfig(localhandle)) != NULL) {
```

### Round 4: ✅ VALID

[ARBITER] The implementation of `getnetconfig` blindly casts the supplied `void *handle` to `struct netconfig **` and immediately dereferences it (`nconf = *nconfp;`). There is no check that `handle` is non‑NULL or that it points to a valid heap‑allocated pointer returned by `setnetconfig`. Consequently, a caller can pass a NULL pointer or any arbitrary value, causing a segmentation fault when the function dereferences or accesses the `nc_netid` field of the resulting garbage pointer. This undefined‑behaviour path can be triggered by an attacker to cause a denial‑of‑service (crash) of any process that uses the library, and is therefore a real security vulnerability. No additional numeric data required to confirm the flaw—the source code itself demonstrates the unchecked dereference.}

