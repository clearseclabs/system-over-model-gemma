# Context: netconfig.h

**Security Context Brief – `<netconfig.h>`**

1. **What it does / where it sits**  
   This header defines the public API for the *netconfig* subsystem in NetBSD.  
   The subsystem reads the system configuration file `"/etc/netconfig"` (or
   files listed in the environment variable `NETPATH`) to map a network
   identifier (e.g. “tcp”, “udp”) to a concrete network stack implementation.
   The header is included by any module that needs to enumerate or lookup a
   configuration entry – e.g. the *rpc* stack, *inet* protocols, or user‑level
   utilities such as `getnetconf / nfs*.  The implementation lives in
   `netconfig.c` (or equivalent) which parses the file line‑by‑line and
   populates `struct netconfig`.  The header is part of the system library
   collected under `/usr/lib/libc.a`.

2. **Untrusted input**  
   * **File input** – `/etc/netconfig` and any files referred to by the
     `NETPATH` environment variable.  These files are world‑readable and
     may be edited by privileged users.  The content is treated as
     untrusted.  No network socket or API is involved directly; the
     information can be injected into the process only through the
     file system.

3. **Attacker‑controlled data**  
   The following fields in `struct netconfig` are populated from the file:
   * `nc_netid`, `nc_protofmly`, `nc_proto`, `nc_device`, `nc_lookups`,  
     and each string in `nc_lookups`.  These are plain C‑strings that
     are dereferenced later when the API is used to open sockets,
     load lookup libraries, or match protocol families.

4. **Fixed‑size buffers / constants**  
   No buffers are defined in this header.  The only size constants are
   flag masks and enumeration values – e.g.
   ```
   #define NC_TPI_CLTS 1
   #define NC_TPI_COTS 2
   #define NC_TPI_COTS_ORD 3
   #define NC_TPI_RAW 4
   ```

5. **Dangerous data flows (attacker → fixed buffer)**  
   Not applicable – this header declares no buffers.  If the implementation
   copies any of the above strings into a fixed buffer (e.g. `char buf[16]`) it
   could become a vector, but that would be visible in `netconfig.c`, not in
   this header.

6. **NULL dereferences**  
   The API does not expose any unvalidated pointer parameters that could be
   NULL in the header.  The implementation may check returned pointers, but
   it must guard against `NULL` `nc_lookups` array entries.

7. **Tagged unions / variant access**  
   No unions or variant types appear in this header.

8. **Public vs static API**  
   *Public* functions: `setnetconfig()`, `getnetconfig()`, `getnetconfigent()`,
   `freenetconfigent()`, `endnetconfig()`, plus the NETPATH equivalents
   when `_KERNEL` is not defined.  
   *Static helpers* – not declared here; the implementation may mark
   functions as `static`.  Their safety depends on the implementation.

9. **Likelihood of bug classes**  
   * **File‑parsing errors** – malformed lines could cause memory corruption,
     if the parser fails to null‑terminate strings or overrun buffers.  
   * **Buffer overflows** – if implementation copies fields into
     fixed‑size buffers.  
   * **Improper NULL checks** – if the implementation blindly uses
     pointers returned from `getnetconfigent()` without validating
     `nc_lookups`.  
   * **Race conditions** – concurrent reads of `/etc/netconfig`
     or changes to `NETPATH` may lead to inconsistent state if not
     protected with locks.

**GREP results (for reference)**  

```
GREP: '#define NC_TPI_CLTS'
#  define NC_TPI_CLTS    1

GREP: 'setnetconfig('
# 1   : static void *setnetconfig(void);
GREP: 'getnetconfigent('
# 1   : struct netconfig *getnetconfigent(const char *);
```

The file `/etc/netconfig` is the sole external source of untrusted data that
harnesses the public API defined here.  All other interactions are
internally controlled by the library.

[GREP RESULTS from codebase]:
GREP `#define NC_TPI_CLTS`:
```
include/netconfig.h:62:#define NC_TPI_CLTS	1	/* Connectionless transport */
lib/libc/rpc/getnetconfig.c:72:#define NC_TPI_CLTS_S	    "tpi_clts"
sys/rpc/netconfig.h:32:#define NC_TPI_CLTS	1
```

GREP `setnetconfig(`:
```
include/netconfig.h:111:void *setnetconfig(void);
sys/rpc/netconfig.h:81:void *setnetconfig(void);
lib/libypclnt/ypclnt_passwd.c:84:	localhandle = setnetconfig();
lib/libypclnt/ypclnt_passwd.c:167:	localhandle = setnetconfig();
sys/rpc/getnetconfig.c:86:setnetconfig(void)
sys/rpc/rpc_generic.c:522:		if (!(confighandle = setnetconfig())) {
sys/rpc/rpc_generic.c:573:		if (!(handle->nhandle = setnetconfig()))
sys/rpc/rpc_generic.c:582:		if (!(handle->nhandle = setnetconfig())) {
lib/libc/rpc/crypt_client.c:55:	localhandle = setnetconfig();
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
lib/libc/rpc/rpc_soc.c:461:	localhandle = setnetconfig();
lib/libc/rpc/rpcb_clnt.c:463:		nc_handle = setnetconfig();
lib/libc/rpc/rpcb_clnt.c:652:	localhandle = setnetconfig();
lib/libc/rpc/key_call.c:348:	if (!(localhandle = setnetconfig())) {
lib/libc/rpc/getnetpath.c:95:    if ((np_sessionp->nc_handlep = setnetconfig()) == NULL) {
lib/libc/rpc/getnetpath.c:154:		np_sessionp->nc_handlep = setnetconfig();
lib/libc/rpc/rpc_generic.c:236:		if (!(confighandle = setnetconfig())) {
lib/libc/rpc/rpc_generic.c:304:		if (!(handle->nhandle = setnetconfig())) {
usr.bin/rpcinfo/rpcinfo.c:311:	localhandle = setnetconfig();
contrib/tcp_wrappers/tli.c:202:    if ((handlep = setnetconfig()) == 0) {
usr.sbin/ypserv/yp_main.c:502:	nc_handle = setnetconfig();
```

GREP `getnetconfigent(`:
```
include/netconfig.h:113:struct netconfig *getnetconfigent(const char *);
sys/rpc/netconfig.h:83:struct netconfig *getnetconfigent(const char *);
lib/libc/rpc/svc_dg.c:622:	if (nconf = getnetconfigent(xprt->xp_netid)) {
lib/libc/rpc/svc_dg.c:680:			if (nconf = getnetconfigent(xprt->xp_netid)) {
lib/libc/rpc/getnetconfig.c:150: * setnetconfig() need *not* be called before a call to getnetconfigent().
lib/libc/rpc/getnetconfig.c:395: * getnetconfigent(netid) returns a pointer to the struct netconfig structure
lib/libc/rpc/getnetconfig.c:403:getnetconfigent(const char *netid)
lib/libc/rpc/getnetconfig.c:490: * netconfigp (previously returned by getnetconfigent()).
lib/libc/rpc/rpcb_clnt.c:501:		loopnconf = getnetconfigent(tmpnconf->nc_netid);
lib/libc/rpc/rpcb_clnt.c:752:			if ((newnconf = getnetconfigent("udp")) == NULL) {
lib/libc/rpc/getnetpath.c:172:	if ((ncp = getnetconfigent(npp)) != NULL) {
lib/libc/rpc/rpc_generic.c:274:	dummy = getnetconfigent(netid);
lib/libc/rpc/rpc_generic.c:451:	return getnetconfigent((char *)netid);
lib/libc/rpc/rpc_generic.c:530:	nconf = getnetconfigent("local");
usr.bin/rpcinfo/rpcinfo.c:695:			nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:891:		nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:920:		nconf = getnetconfigent(client->cl_netid);
usr.bin/rpcinfo/rpcinfo.c:1209:		nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:1270:	nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:1382:		nconf = getnetconfigent(netid);
sbin/mount_nfs/mount_nfs.c:1074: * Otherwise it behaves just like getnetconfigent(), so nc_*error()
sbin/mount_nfs/mount_nfs.c:1091:	if ((nconf = getnetconfigent(netid)) == NULL)
sys/fs/nfs/nfs_commonkrpc.c:294:			nconf = getnetconfigent("udp");
sys/fs/nfs/nfs_commonkrpc.c:296:			nconf = getnetconfigent("tcp");
sys/fs/nfs/nfs_commonkrpc.c:299:			nconf = getnetconfigent("udp6");
sys/fs/nfs/nfs_commonkrpc.c:301:			nconf = getnetconfigent("tcp6");
usr.bin/rpcgen/rpc_svcout.c:184:	f_print(fout, "%s\tnconf = getnetconfigent(\"%s\");\n", sp, transp);
usr.bin/rpcgen/rpc_svcout.c:801:	f_print(fout, "\t\t\tif ((nconf = getnetconfigent(netid)) == NULL)\n");
sys/rpc/getnetconfig.c:112:getnetconfigent(const char *netid)
sys/rpc/rpc_generic.c:550:	dummy = getnetconfigent(netid);
```