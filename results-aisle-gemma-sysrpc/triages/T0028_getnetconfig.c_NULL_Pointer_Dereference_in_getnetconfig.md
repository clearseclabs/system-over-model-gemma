# Triage T0028: NULL Pointer Dereference in getnetconfig

- **File**: `getnetconfig.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

NULL Pointer Dereference in getnetconfig

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** Whether the `handle` parameter in `getnetconfig` can be controlled by an external attacker or is only managed by trusted internal kernel code.

The function `getnetconfig(void *handle)` indeed dereferences `handle` without a NULL check. However, we must determine if an external attacker can control the `handle` passed to this function. According to the provided security context, the only untrusted input reaching this file is via `getnetconfigent(const char *netid)`. The `getnetconfig`, `setnetconfig`, and `endnetconfig` functions implement a stateful iterator pattern (Open -> GetNext -> Close). In kernel-space RPC implementations, such handles are typically managed internally by the kernel's RPC state machine or passed between internal kernel functions. There is no evidence that the `handle` is derived from a user-supplied value (like a file descriptor or a session ID) that can be set to NULL by an attacker. If the handle is only managed by trusted internal callers, a missing NULL check is a code quality issue, not a security vulnerability.

CRUX: Whether the `handle` parameter in `getnetconfig` can be controlled by an external attacker or is only managed by trusted internal kernel code.
GREP: getnetconfig(

🔎 **Grep results:**

GREP `getnetconfig(`:
```
include/netconfig.h:112:struct netconfig *getnetconfig(void *);
sys/rpc/netconfig.h:82:struct netconfig *getnetconfig(void *);
usr.sbin/ypserv/yp_main.c:533:	while((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:290:	while ((nconf = getnetconfig(localhandle)) != NULL) {
usr.sbin/mountd/mountd.c:650:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:722:		while ((nconf = getnetconfig(nc_handle))) {
contrib/tcp_wrappers/tli.c:206:    while (config = getnetconfig(handlep)) {
contrib/tcp_wrappers/tli.c:226:     * Something else may clobber our getnetconfig() result, so we'd better
usr.sbin/rpc.lockd/lockd.c:307:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:326:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:398:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.statd/statd.c:201:  while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.statd/statd.c:265:  while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpcbind/rpcbind.c:218:	while ((nconf = getnetconfig(nc_handle))) {
sys/rpc/getnetconfig.c:97:getnetconfig(void *handle)
sys/rpc/rpc_generic.c:526:		while ((nconf = getnetconfig(confighandle)) != NULL) {
sys/rpc/rpc_generic.c:615:			nconf = getnetconfig(handle->nhandle);
sys/rpc/rpc_generic.c:619:			nconf = getnetconfig(handle->nhandle);
lib/libypclnt/ypclnt_passwd.c:85:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:168:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/getnetpath.c:158:	    if ((ncp = getnetconfig(np_sessionp->nc_handlep)) == NULL) {
lib/libc/rpc/crypt_client.c:56:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/key_call.c:367:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/getnetconfig.c:140: * getnetconfig() to parse the file.  Each call to getnetconfig() using the
lib/libc/rpc/getnetconfig.c:142: * setnetconfig() must be called before the first call to getnetconfig().
lib/libc/rpc/getnetconfig.c:193: * When first called, getnetconfig() returns a pointer to the first entry in
lib/libc/rpc/getnetconfig.c:195: * call, getnetconfig() returns a pointer to the next entry in the database.
lib/libc/rpc/getnetconfig.c:196: * getnetconfig() can thus be used to search the entire netconfig file.
lib/libc/rpc/getnetconfig.c:197: * getnetconfig() returns NULL at end of file.
lib/libc/rpc/getnetconfig.c:201:getnetconfig(void *handlep)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The 'handle' parameter is managed internally by the RPC subsystem and is not derived from untrusted network input; thus, an external attacker cannot trigger the NULL dereference.

The vulnerability report identifies a missing NULL check for the `handle` parameter in `getnetconfig()`. I analyzed the provided code and the grep results to determine if an external attacker can trigger this. 

1. **Bug Pattern**: The bug is real. `getnetconfig` casts `handle` to `struct netconfig **` and immediately dereferences it (`nconf = *nconfp`), which will cause a crash if `handle` is NULL.

2. **Reachability**: The grep results show `getnetconfig()` is called in various places: userspace daemons (e.g., `rpcbind`, `mountd`, `statd`), a libc implementation, and kernel-space RPC code (`sys/rpc/rpc_generic.c`). 

In the kernel context (`sys/rpc/getnetconfig.c`), the `handle` is created by `setnetconfig()`, which calls `malloc(..., M_WAITOK)`. `M_WAITOK` ensures that the allocation will sleep until memory is available, meaning `malloc` will not return NULL under normal kernel operation. The `handle` is then passed internally through the RPC state machine.

In the userspace contexts, the `handle` is typically returned by `setnetconfig()` and stored in a local variable (e.g., `nc_handle`). An attacker cannot directly pass a value to these internal function calls; they can only send RPC packets. The RPC dispatcher uses these functions to look up network configurations to handle those packets, but it does not take a 'handle' from the network packet and pass it into `getnetconfig()`.

3. **Security Relevance**: Since the `handle` is managed internally (created by `setnetconfig` and passed to `getnetconfig` and `endnetconfig` by the kernel or the daemon), there is no path for an untrusted external user to provide a NULL value to this function. A NULL handle would only occur if `setnetconfig` failed (which is prevented by `M_WAITOK` in kernel or is a fatal startup error in userspace) or if there was a logic error in the internal state management. This is a code quality issue (missing defensive check), not a security vulnerability reachable by an attacker.

CRUX: The 'handle' parameter is managed internally by the RPC subsystem and is not derived from untrusted network input; thus, an external attacker cannot trigger the NULL dereference.
GREP: setnetconfig

🔎 **Grep results:**

GREP `setnetconfig`:
```
lib/libc/rpc/getnetconfig.c:65:#define NC_NOTINIT	EINVAL	    /* setnetconfig was not called first */
sys/rpc/netconfig.h:81:void *setnetconfig(void);
include/netconfig.h:111:void *setnetconfig(void);
usr.sbin/ypserv/yp_main.c:502:	nc_handle = setnetconfig();
usr.sbin/mountd/mountd.c:649:		nc_handle = setnetconfig();
usr.sbin/mountd/mountd.c:690:						nc_handle = setnetconfig();
usr.sbin/mountd/mountd.c:721:		nc_handle = setnetconfig();
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:289:	localhandle = setnetconfig();
usr.sbin/rpc.lockd/lockd.c:306:		nc_handle = setnetconfig();
usr.sbin/rpc.lockd/lockd.c:325:		nc_handle = setnetconfig();
usr.sbin/rpc.lockd/lockd.c:366:						nc_handle = setnetconfig();
usr.sbin/rpc.lockd/lockd.c:397:		nc_handle = setnetconfig();
usr.sbin/rpc.statd/statd.c:200:  nc_handle = setnetconfig();
usr.sbin/rpc.statd/statd.c:236:				nc_handle = setnetconfig();
usr.sbin/rpc.statd/statd.c:264:  nc_handle = setnetconfig();
contrib/tcp_wrappers/tli.c:202:    if ((handlep = setnetconfig()) == 0) {
contrib/tcp_wrappers/tli.c:203:	tcpd_warn("setnetconfig: %m");
usr.sbin/rpcbind/rpcbind.c:196:	nc_handle = setnetconfig();	/* open netconfig file */
sys/rpc/getnetconfig.c:86:setnetconfig(void)
sys/rpc/rpc_generic.c:522:		if (!(confighandle = setnetconfig())) {
sys/rpc/rpc_generic.c:573:		if (!(handle->nhandle = setnetconfig()))
sys/rpc/rpc_generic.c:582:		if (!(handle->nhandle = setnetconfig())) {
lib/libypclnt/ypclnt_passwd.c:84:	localhandle = setnetconfig();
lib/libypclnt/ypclnt_passwd.c:167:	localhandle = setnetconfig();
lib/libc/rpc/rpc_generic.c:236:		if (!(confighandle = setnetconfig())) {
lib/libc/rpc/rpc_generic.c:304:		if (!(handle->nhandle = setnetconfig())) {
lib/libc/rpc/crypt_client.c:55:	localhandle = setnetconfig();
lib/libc/rpc/getnetconfig.c:99:    int		ref;	/* # of times setnetconfig() has been called */
lib/libc/rpc/getnetconfig.c:136: * A call to setnetconfig() establishes a /etc/netconfig "session".  A session
lib/libc/rpc/getnetconfig.c:138: * a call to setnetconfig()) searches through the /etc/netconfig database will
```

### Round 3: ❌ INVALID

**🎯 Crux:** The `handle` parameter is an internal state pointer created by `setnetconfig` and is not reachable or controllable by external untrusted input.

The vulnerability report correctly identifies a NULL pointer dereference in `getnetconfig(void *handle)`. However, for this to be a security vulnerability, the `handle` must be controllable by an external attacker. Analysis of the code and the grep results shows that `getnetconfig` is part of a stateful iterator API (`setnetconfig` -> `getnetconfig` -> `endnetconfig`). In the kernel implementation (`sys/rpc/getnetconfig.c`), `setnetconfig` uses `malloc(..., M_WAITOK)`, which ensures the handle is allocated or the thread sleeps; it does not return NULL. The `handle` is then passed between internal kernel functions. The grep results for `getnetconfig` show it is used in userspace daemons and kernel-space RPC generic code, but in all cases, the handle is an internal pointer returned by `setnetconfig`. There is no evidence of any RPC dispatcher or interface that takes a handle from a network packet and passes it to `getnetconfig`. Because the handle is managed internally and not derived from untrusted input, this is a code quality issue (lack of defensive programming) rather than a reachable security vulnerability.

CRUX: The `handle` parameter is an internal state pointer created by `setnetconfig` and is not reachable or controllable by external untrusted input.
GREP: getnetconfig(

🔎 **Grep results:**

GREP `getnetconfig(`:
```
sys/rpc/netconfig.h:82:struct netconfig *getnetconfig(void *);
include/netconfig.h:112:struct netconfig *getnetconfig(void *);
usr.sbin/ypserv/yp_main.c:533:	while((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:650:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:722:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:290:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:85:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:168:	while ((nc = getnetconfig(localhandle)) != NULL) {
usr.sbin/rpc.lockd/lockd.c:307:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:326:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:398:		while ((nconf = getnetconfig(nc_handle))) {
contrib/tcp_wrappers/tli.c:206:    while (config = getnetconfig(handlep)) {
contrib/tcp_wrappers/tli.c:226:     * Something else may clobber our getnetconfig() result, so we'd better
usr.sbin/rpc.statd/statd.c:201:  while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.statd/statd.c:265:  while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpcbind/rpcbind.c:218:	while ((nconf = getnetconfig(nc_handle))) {
sys/rpc/getnetconfig.c:97:getnetconfig(void *handle)
sys/rpc/rpc_generic.c:526:		while ((nconf = getnetconfig(confighandle)) != NULL) {
sys/rpc/rpc_generic.c:615:			nconf = getnetconfig(handle->nhandle);
sys/rpc/rpc_generic.c:619:			nconf = getnetconfig(handle->nhandle);
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
```

### Round 4: ❌ INVALID

[ARBITER] While there is a technical NULL pointer dereference in `getnetconfig` if `handle` is NULL, the evidence shows that `handle` is exclusively managed internally by the system. It is created by `setnetconfig` and passed to `getnetconfig` by internal kernel or system callers. There is no path for an external, untrusted user to provide or control the `handle` parameter, making this a bug in API usage/robustness rather than a security vulnerability.

