# Triage T0020: Out‑of‑bounds memory read after sentinel in getnetconfig()

- **File**: `getnetconfig.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Out‑of‑bounds memory read after sentinel in getnetconfig()

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** getnetconfig() never dereferences an index beyond the sentinel; the pointer stops at the end of the static array.

The only alleged out‑of‑bounds read is performed in getnetconfig() after dereferencing the pointer returned by setnetconfig(). On the first call, nconf points to the first element of netconfigs, which is valid. The function returns this element and then increments the pointer. After this increment, the pointer is positioned at the sentinel element (nc_netid == NULL). The next call returns NULL without incrementing further. The pointer **never moves past** the sentinel: the increment happens only when the current element is not the sentinel, and the sentinel itself is part of the static array, so dereferencing it is perfectly safe. No read from memory beyond the array occurs. Therefore the reported out‑of‑bounds read does not exist. Since no attacker‑controllable path can trigger a memory read beyond the sentinel, the issue is a false positive. The pattern does not pose a security risk.


CRUX: getnetconfig() never dereferences an index beyond the sentinel; the pointer stops at the end of the static array.

GREP: getnetconfig(void *handle)\n\n.*\*nconfp\++;

🔎 **Grep results:**

GREP `getnetconfig(void *handle)nn.**nconfp++; (simplified to: getnetconfig)`:
```
include/netconfig.h:112:struct netconfig *getnetconfig(void *);
include/netconfig.h:113:struct netconfig *getnetconfigent(const char *);
sys/rpc/netconfig.h:82:struct netconfig *getnetconfig(void *);
sys/rpc/netconfig.h:83:struct netconfig *getnetconfigent(const char *);
sbin/mount_nfs/mount_nfs.c:1074: * Otherwise it behaves just like getnetconfigent(), so nc_*error()
sbin/mount_nfs/mount_nfs.c:1091:	if ((nconf = getnetconfigent(netid)) == NULL)
usr.sbin/ypserv/yp_main.c:533:	while((nconf = getnetconfig(nc_handle))) {
usr.bin/rpcinfo/rpcinfo.c:312:	while ((nconf = getnetconfig(localhandle)) != NULL) {
usr.bin/rpcinfo/rpcinfo.c:318:		warnx("getnetconfig: %s", nc_sperror());
usr.bin/rpcinfo/rpcinfo.c:695:			nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:891:		nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:920:		nconf = getnetconfigent(client->cl_netid);
usr.bin/rpcinfo/rpcinfo.c:1209:		nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:1270:	nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:1382:		nconf = getnetconfigent(netid);
usr.sbin/mountd/mountd.c:650:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/mountd/mountd.c:722:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:290:	while ((nconf = getnetconfig(localhandle)) != NULL) {
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:296:		yp_error("getnetconfigent unix: %s", nc_sperror());
usr.sbin/rpc.lockd/lock_proc.c:259:	nconf = getnetconfigent(netid);
usr.sbin/rpc.lockd/lockd.c:307:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:326:		while ((nconf = getnetconfig(nc_handle))) {
usr.sbin/rpc.lockd/lockd.c:398:		while ((nconf = getnetconfig(nc_handle))) {
usr.bin/rpcgen/rpc_svcout.c:184:	f_print(fout, "%s\tnconf = getnetconfigent(\"%s\");\n", sp, transp);
usr.bin/rpcgen/rpc_svcout.c:801:	f_print(fout, "\t\t\tif ((nconf = getnetconfigent(netid)) == NULL)\n");
usr.sbin/nfsd/nfsd.c:290:	} else if (getnetconfigent("udp6") == NULL ||
usr.sbin/nfsd/nfsd.c:291:		getnetconfigent("tcp6") == NULL) {
usr.sbin/nfsd/nfsd.c:336:			nconf_udp = getnetconfigent("udp");
usr.sbin/nfsd/nfsd.c:338:				err(1, "getnetconfigent udp failed");
usr.sbin/nfsd/nfsd.c:360:			nconf_udp6 = getnetconfigent("udp6");
```

### Round 2: ❌ INVALID

**🎯 Crux:** The pointer in getnetconfig() is advanced only when the current element’s nc_netid field is non‑NULL, so it can never dereference past the sentinel element.

The static array "netconfigs" contains a sentinel element whose ".nc_netid" field is NULL.  In "getnetconfig()" the current element is read, and if it is the sentinel an early return occurs before the pointer is advanced.  The pointer is only incremented when the current element is *not* the sentinel, so the pointer never moves past the sentinel element.  Dereferencing the pointer therefore always accesses a valid array entry.  Attacker‑controlled input is limited to the handle obtained from "setnetconfig()"; that handle is allocated by the kernel and cannot be manipulated by a user process to change the pointer contents.  Thus there is no out‑of‑bounds read that can be triggered by untrusted input.  The code shows no additional bounds checks, but the logic itself guarantees safety.

The proof is that the only way to move the pointer beyond the sentinel is to increment it while the current element is not NULL, which the code prevents.  Consequently the alleged OOB read cannot occur, making the claim a false positive.

This is a code‑quality/style concern (the function relies on the hidden sentinel) but not a security vulnerability.



CRUX: The pointer in getnetconfig() is advanced only when the current element’s nc_netid field is non‑NULL, so it can never dereference past the sentinel element.

GREP: getnetconfig(void *handle)\n.*\*nconfp\++|\.nc_netid\s*=\s*NULL

🔎 **Grep results:**

GREP `getnetconfig(void *handle)n.**nconfp++ (simplified to: getnetconfig)`:
```
include/netconfig.h:112:struct netconfig *getnetconfig(void *);
include/netconfig.h:113:struct netconfig *getnetconfigent(const char *);
sys/rpc/netconfig.h:82:struct netconfig *getnetconfig(void *);
sys/rpc/netconfig.h:83:struct netconfig *getnetconfigent(const char *);
sbin/mount_nfs/mount_nfs.c:1074: * Otherwise it behaves just like getnetconfigent(), so nc_*error()
sbin/mount_nfs/mount_nfs.c:1091:	if ((nconf = getnetconfigent(netid)) == NULL)
sys/rpc/getnetconfig.c:97:getnetconfig(void *handle)
sys/rpc/getnetconfig.c:112:getnetconfigent(const char *netid)
sys/rpc/rpc_generic.c:526:		while ((nconf = getnetconfig(confighandle)) != NULL) {
sys/rpc/rpc_generic.c:550:	dummy = getnetconfigent(netid);
sys/rpc/rpc_generic.c:615:			nconf = getnetconfig(handle->nhandle);
sys/rpc/rpc_generic.c:619:			nconf = getnetconfig(handle->nhandle);
lib/libypclnt/ypclnt_passwd.c:85:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:92:		    "getnetconfig: %s", nc_sperror());
lib/libypclnt/ypclnt_passwd.c:168:	while ((nc = getnetconfig(localhandle)) != NULL) {
lib/libypclnt/ypclnt_passwd.c:175:		    "getnetconfig: %s", nc_sperror());
sys/fs/nfs/nfs_commonkrpc.c:294:			nconf = getnetconfigent("udp");
sys/fs/nfs/nfs_commonkrpc.c:296:			nconf = getnetconfigent("tcp");
sys/fs/nfs/nfs_commonkrpc.c:299:			nconf = getnetconfigent("udp6");
sys/fs/nfs/nfs_commonkrpc.c:301:			nconf = getnetconfigent("tcp6");
lib/libc/rpc/svc_dg.c:622:	if (nconf = getnetconfigent(xprt->xp_netid)) {
lib/libc/rpc/svc_dg.c:680:			if (nconf = getnetconfigent(xprt->xp_netid)) {
lib/libc/rpc/crypt_client.c:56:	while ((nconf = getnetconfig(localhandle)) != NULL) {
lib/libc/rpc/crypt_client.c:62:		warnx("getnetconfig: %s", nc_sperror());
lib/libc/rpc/getnetconfig.c:1:/*	$NetBSD: getnetconfig.c,v 1.3 2000/07/06 03:10:34 christos Exp $	*/
lib/libc/rpc/getnetconfig.c:140: * getnetconfig() to parse the file.  Each call to getnetconfig() using the
lib/libc/rpc/getnetconfig.c:142: * setnetconfig() must be called before the first call to getnetconfig().
lib/libc/rpc/getnetconfig.c:150: * setnetconfig() need *not* be called before a call to getnetconfigent().
lib/libc/rpc/getnetconfig.c:193: * When first called, getnetconfig() returns a pointer to the first entry in
lib/libc/rpc/getnetconfig.c:195: * call, getnetconfig() returns a pointer to the next entry in the database.
```

GREP `.nc_netid*=*NULL`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** `getnetconfig()` only increments the pointer when the current element’s `nc_netid` field is non‑NULL; the sentinel element (`nc_netid == NULL`) blocks any advancement past the static array.

The data‑flow in getnetconfig() is simple:  \n- `setnetconfig()` allocates a pointer to a `struct netconfig*` and initializes it to point at the first element of the static array `netconfigs`.  \n- Each call to `getnetconfig()` dereferences this pointer to obtain `nconf`.  If `nconf->nc_netid == NULL` the function returns `NULL` and **does not** increment the pointer.  \n- Only when `nc_netid` is non‑NULL does the code execute `(*nconfp)++;`.  The last element of `netconfigs` is the sentinel whose `nc_netid` field is `NULL`.  Therefore after the final valid entry has been returned, the next call will see the sentinel, return `NULL`, and the pointer will remain pointing at the sentinel.  It is never advanced past the array’s last element, so no out‑of‑bounds read can occur.  \n- The handle passed to `getnetconfig()` is created by `setnetconfig()`.  The code does not provide any other source of an untrusted handle that could make `*nconfp` point at a location outside the static array.  Thus, an attacker cannot influence the pointer math to read arbitrary memory; the only reachable value that could be read is the sentinel element, which contains only a `NULL` pointer.  \n- Consequently the reported out‑of‑bounds read does not exist, and there is no security impact.

CRUX: `getnetconfig()` only increments the pointer when the current element’s `nc_netid` field is non‑NULL; the sentinel element (`nc_netid == NULL`) blocks any advancement past the static array.
GREP: nc_netid\s*=\s*NULL

🔎 **Grep results:**

GREP `nc_netid*=*NULL`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The `getnetconfig()` logic only increments the internal pointer when the current entry's `nc_netid` is non‑NULL. The array ends with a sentinel whose `nc_netid` is NULL. Thus after returning the last valid entry, the pointer moves to the sentinel, a subsequent call detects the sentinel and returns `NULL` without further increment. The pointer never advances past the sentinel element, so no out‑of‑bounds read of arbitrary memory can occur. The claim that an OOB read is possible is incorrect based on the source code. Hence the vulnerability is not real. 

