# Triage T0030: Type Confusion/Invalid Memory Access via handle

- **File**: `getnetconfig.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Type Confusion/Invalid Memory Access via handle

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** Whether the 'void *handle' parameter in 'getnetconfig' and 'endnetconfig' can be influenced by untrusted external input.

The reported vulnerability focuses on the 'void *handle' passed to 'getnetconfig' and 'endnetconfig'. In this implementation, 'setnetconfig' allocates a pointer to the static 'netconfigs' array and returns it as the handle. 'getnetconfig' then dereferences this handle to iterate through the array. To determine if this is security-relevant, we must establish if an attacker can control the 'handle' argument. According to the provided Security Context Briefing, the 'Untrusted Input Path' only involves the 'netid' parameter in 'getnetconfigent()'. There is no mention of the 'handle' being exposed to external RPC requests. In standard RPC/libc-style APIs, 'setnetconfig' creates a session handle that is managed by the caller (typically the kernel or a trusted internal process) and passed back to 'getnetconfig'. If the 'handle' is only managed and passed by trusted internal kernel code, an attacker cannot trigger an arbitrary memory read or heap corruption. The provided context explicitly states that 'Untrusted input reaches this code via the netid parameter in getnetconfigent()', implying other entry points are not attacker-controlled.

CRUX: Whether the 'void *handle' parameter in 'getnetconfig' and 'endnetconfig' can be influenced by untrusted external input.
GREP: getnetconfig(

🔎 **Grep results:**

GREP `getnetconfig(`:
```
include/netconfig.h:112:struct netconfig *getnetconfig(void *);
sys/rpc/netconfig.h:82:struct netconfig *getnetconfig(void *);
usr.sbin/ypserv/yp_main.c:533:	while((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:650:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:722:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:290:	while ((nconf = getnetconfig(localhandle)) != NULL) {
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
lib/libypclnt/ypclnt_passwd.c:85:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:168:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/crypt_client.c:56:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/getnetconfig.c:140: * getnetconfig() to parse the file.  Each call to getnetconfig() using the
lib/libc/rpc/getnetconfig.c:142: * setnetconfig() must be called before the first call to getnetconfig().
lib/libc/rpc/getnetconfig.c:193: * When first called, getnetconfig() returns a pointer to the first entry in
lib/libc/rpc/getnetconfig.c:195: * call, getnetconfig() returns a pointer to the next entry in the database.
lib/libc/rpc/getnetconfig.c:196: * getnetconfig() can thus be used to search the entire netconfig file.
lib/libc/rpc/getnetconfig.c:197: * getnetconfig() returns NULL at end of file.
lib/libc/rpc/getnetconfig.c:201:getnetconfig(void *handlep)
lib/libc/rpc/getnetconfig.c:418:     * getnetconfig(), then copy this entry into a buffer and return it.
lib/libc/rpc/key_call.c:367:	while ((nconf = getnetconfig(localhandle)) != NULL) {
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `handle` passed to `getnetconfig` and `endnetconfig` is managed internally by the kernel/daemons and is not reachable or controllable by an external attacker.

The reported vulnerability describes a type confusion/invalid memory access where an attacker provides an invalid `void *handle` to `getnetconfig` or `endnetconfig`. I analyzed the provided code and the grep results for callers of `getnetconfig`. The code implementation in `sys/rpc/getnetconfig.c` is a kernel-space implementation. The grep results show that `getnetconfig` is called by various system daemons (like `rpcbind`, `mountd`, `lockd`) and internal kernel functions (like `rpc_generic.c`). In all these cases, the `handle` passed to `getnetconfig` is the result of a previous call to `setnetconfig()`. `setnetconfig` allocates memory for the handle using `malloc` and initializes it to point to a static internal array (`netconfigs`). There is no evidence in the code or the caller list that this handle is ever derived from, or influenced by, untrusted network input. The handle is a session-like state maintained internally by the caller. An external attacker cannot inject a pointer value into the `handle` argument of these functions. The 'Security Context Briefing' also explicitly states that untrusted input only reaches `getnetconfigent()` via the `netid` parameter, not via the handle in `getnetconfig`.

CRUX: The `handle` passed to `getnetconfig` and `endnetconfig` is managed internally by the kernel/daemons and is not reachable or controllable by an external attacker.
GREP: setnetconfig

🔎 **Grep results:**

GREP `setnetconfig`:
```
lib/libc/rpc/getnetconfig.c:65:#define NC_NOTINIT	EINVAL	    /* setnetconfig was not called first */
sys/rpc/netconfig.h:81:void *setnetconfig(void);
include/netconfig.h:111:void *setnetconfig(void);
lib/libypclnt/ypclnt_passwd.c:84:	localhandle = setnetconfig();
lib/libypclnt/ypclnt_passwd.c:167:	localhandle = setnetconfig();
usr.sbin/ypserv/yp_main.c:502:	nc_handle = setnetconfig();
usr.sbin/mountd/mountd.c:649:		nc_handle = setnetconfig();
usr.sbin/mountd/mountd.c:690:						nc_handle = setnetconfig();
usr.sbin/mountd/mountd.c:721:		nc_handle = setnetconfig();
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:289:	localhandle = setnetconfig();
lib/libc/rpc/crypt_client.c:55:	localhandle = setnetconfig();
lib/libc/rpc/key_call.c:348:	if (!(localhandle = setnetconfig())) {
lib/libc/rpc/getnetpath.c:95:    if ((np_sessionp->nc_handlep = setnetconfig()) == NULL) {
lib/libc/rpc/getnetpath.c:154:		np_sessionp->nc_handlep = setnetconfig();
lib/libc/rpc/getnetconfig.c:99:    int		ref;	/* # of times setnetconfig() has been called */
lib/libc/rpc/getnetconfig.c:136: * A call to setnetconfig() establishes a /etc/netconfig "session".  A session
lib/libc/rpc/getnetconfig.c:138: * a call to setnetconfig()) searches through the /etc/netconfig database will
lib/libc/rpc/getnetconfig.c:142: * setnetconfig() must be called before the first call to getnetconfig().
lib/libc/rpc/getnetconfig.c:145: * A new session is established with each call to setnetconfig(), with a new
lib/libc/rpc/getnetconfig.c:150: * setnetconfig() need *not* be called before a call to getnetconfigent().
lib/libc/rpc/getnetconfig.c:151: * setnetconfig() returns a NULL pointer on failure (for example, if
lib/libc/rpc/getnetconfig.c:155:setnetconfig(void)
lib/libc/rpc/getnetconfig.c:333: * may not be called before setnetconfig().  endnetconfig() returns 0 on
lib/libc/rpc/getnetconfig.c:334: * success and -1 on failure (for example, if setnetconfig() was not called
lib/libc/rpc/rpc_generic.c:236:		if (!(confighandle = setnetconfig())) {
lib/libc/rpc/rpc_generic.c:304:		if (!(handle->nhandle = setnetconfig())) {
lib/libc/rpc/rpc_soc.c:461:	localhandle = setnetconfig();
lib/libc/rpc/rpcb_clnt.c:463:		nc_handle = setnetconfig();
lib/libc/rpc/rpcb_clnt.c:652:	localhandle = setnetconfig();
usr.sbin/rpc.lockd/lockd.c:306:		nc_handle = setnetconfig();
```

### Round 3: ❌ INVALID

**🎯 Crux:** The `handle` parameter is an internal kernel pointer generated by `setnetconfig` and is not exposed to or controllable by external RPC input.

The vulnerability report alleges that an attacker can provide an invalid pointer as a `handle` to `getnetconfig` or `endnetconfig`, leading to arbitrary memory read or heap corruption. However, the provided code is a kernel-space implementation (indicated by the use of `M_RPC` and `M_WAITOK` in `malloc`, which are FreeBSD kernel memory allocator flags). In this implementation, the `handle` is created by `setnetconfig()`, which allocates memory for a pointer and initializes it to a static array (`netconfigs`). The `handle` is an internal pointer managed by the kernel or trusted system daemons (as seen in the grep results for `rpcbind`, `mountd`, `lockd`, etc.). There is no mechanism in the RPC dispatcher or the provided code that allows an external network packet to specify a memory address that is then passed as the `handle` argument to these functions. Since the `handle` is not attacker-controllable, the bug is not reachable by an external attacker.

CRUX: The `handle` parameter is an internal kernel pointer generated by `setnetconfig` and is not exposed to or controllable by external RPC input.
GREP: getnetconfig(

🔎 **Grep results:**

GREP `getnetconfig(`:
```
sys/rpc/netconfig.h:82:struct netconfig *getnetconfig(void *);
include/netconfig.h:112:struct netconfig *getnetconfig(void *);
lib/libypclnt/ypclnt_passwd.c:85:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:168:	while ((nc = getnetconfig(localhandle)) != NULL) {
usr.sbin/ypserv/yp_main.c:533:	while((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:650:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:722:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:290:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/crypt_client.c:56:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/key_call.c:367:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/getnetpath.c:158:	    if ((ncp = getnetconfig(np_sessionp->nc_handlep)) == NULL) {
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
lib/libc/rpc/rpc_generic.c:240:		while ((nconf = getnetconfig(confighandle)) != NULL) {
lib/libc/rpc/rpc_generic.c:339:			nconf = getnetconfig(handle->nhandle);
contrib/tcp_wrappers/tli.c:206:    while (config = getnetconfig(handlep)) {
contrib/tcp_wrappers/tli.c:226:     * Something else may clobber our getnetconfig() result, so we'd better
usr.sbin/rpc.lockd/lockd.c:307:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:326:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:398:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.statd/statd.c:201:  while ((nconf = getnetconfig(nc_handle))) {
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability requires an attacker to control the 'void *handle' argument passed to getnetconfig() or endnetconfig(). Analysis of the codebase shows that these functions are used internally by the kernel and system daemons. The handle is exclusively created by setnetconfig(), which allocates memory internally and returns a pointer. There is no evidence of any RPC interface or untrusted input path that allows an external user to pass an arbitrary pointer into these functions. Therefore, the 'invalid pointer' scenario is not reachable by an attacker.

